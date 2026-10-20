package fileops

import (
	"Picocrypt-NG/internal/secret"
	"Picocrypt-NG/internal/util"
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ProgressFunc is called during file operations to report progress.
// Parameters: progress (0.0-1.0 completion fraction), info (human-readable status).
type ProgressFunc func(progress float32, info string)

// StatusFunc is called to report status messages (e.g., "Compressing...", "Splitting...").
type StatusFunc func(status string)

// CancelFunc is called periodically to check if the user requested cancellation.
// Return true to abort the operation.
type CancelFunc func() bool

// ZIPSequentialSource supplies logical metadata and a sequential plaintext
// reader for one identity-pinned ciphertext input in a temporary ZIP.
type ZIPSequentialSource struct {
	Info os.FileInfo
	Open func() (io.ReadCloser, error)
}

// ZipOptions configures zip file creation
type ZipOptions struct {
	Files           []string           // Files to include
	InputIdentities []ZIPInputIdentity // Optional immutable discovery snapshots
	RootDir         string             // Root directory for relative paths
	EntryNames      map[string]string
	OutputPath      string   // Output archive path
	OutputFile      *os.File // Optional caller-owned, exclusively created output
	Compress        bool     // Use Deflate compression
	Progress        ProgressFunc
	Status          StatusFunc
	Cancel          CancelFunc
	Budget          *ZIPResourceBudget
	singleSource    *ZIPSequentialSource
}

func entryNameForPath(opts ZipOptions, path string) (string, error) {
	if name, ok := opts.EntryNames[path]; ok {
		clean := filepath.Clean(filepath.FromSlash(name))
		if !filepath.IsLocal(clean) {
			return "", fmt.Errorf("zip entry %q is not local", name)
		}
		return filepath.ToSlash(clean), nil
	}

	rel, err := filepath.Rel(opts.RootDir, path)
	if err != nil {
		return "", err
	}
	rel = filepath.Clean(rel)
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("zip entry %q is not local", rel)
	}
	return filepath.ToSlash(rel), nil
}

// CreateZip creates a zip archive from the given files.
// Returns the path to the created archive.
// On error or cancellation, the partial output file is removed.
func CreateZip(opts ZipOptions) (retErr error) {
	budget := opts.Budget
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	charge, err := zipWriterWorkingBytes(opts)
	if err != nil {
		return err
	}
	if err := budget.Reserve(charge); err != nil {
		return err
	}
	defer budget.Release(charge)
	opts.InputIdentities, err = CaptureZIPInputs(opts.Files, opts.InputIdentities)
	if err != nil {
		return err
	}
	file := opts.OutputFile
	ownsFile := false
	var ownedOutput ownedFilePath
	if file == nil {
		var err error
		file, err = CreateExclusiveNoSymlink(opts.OutputPath)
		if err != nil {
			return fmt.Errorf("create zip file: %w", err)
		}
		ownsFile = true
		ownedOutput, err = newOwnedFilePath(opts.OutputPath, file)
		if err != nil {
			_ = file.Close()
			return fmt.Errorf("inspect zip file: %w", err)
		}
	}

	fileClosed := false
	keepOutput := false
	defer func() {
		if ownsFile && !keepOutput {
			if !fileClosed {
				retErr = errors.Join(retErr, file.Close())
			}
			retErr = errors.Join(retErr, ownedOutput.remove())
		}
	}()
	if err := emitZIP(file, opts); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync zip file: %w", err)
	}
	if ownsFile {
		err := file.Close()
		fileClosed = true
		if err != nil {
			return fmt.Errorf("close zip file: %w", err)
		}
		current, err := os.Lstat(opts.OutputPath)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(ownedOutput.info, current) {
			if err != nil {
				return fmt.Errorf("inspect completed zip: %w", err)
			}
			return errors.New("zip output path changed during creation")
		}
		keepOutput = true
	}

	return nil
}

// emitZIP emits one archive under a caller-held ZIP workspace reservation.
// On failure it never closes the ZIP writer: Close would emit a central
// directory after cancellation or an aborted authenticated record.
func emitZIP(dst io.Writer, opts ZipOptions) error {
	if opts.singleSource != nil && (len(opts.Files) != 1 || opts.singleSource.Info == nil || !opts.singleSource.Info.Mode().IsRegular() || opts.singleSource.Info.Size() < 0 || opts.singleSource.Open == nil) {
		return errors.New("invalid sequential archive source")
	}
	writer := zip.NewWriter(&zipCancelWriter{Writer: dst, cancel: opts.Cancel})
	// Calculate total size for progress
	var totalSize int64
	for _, identity := range opts.InputIdentities {
		totalSize += identity.info.Size()
	}

	if opts.singleSource != nil {
		totalSize = opts.singleSource.Info.Size()
	}
	buf := make([]byte, util.MiB)
	defer secret.SecureZero(buf)
	var done int64
	startTime := time.Now()

	// report drives the progress bar and the speed/ETA status line, mirroring
	// split.go/recombine.go so the compression pass shows an ETA like the others.
	report := func(fileIndex int) {
		if opts.Progress == nil {
			return
		}
		progress, speed, eta := util.Statify(done, totalSize, startTime)
		opts.Progress(progress, fmt.Sprintf("%d/%d", fileIndex+1, len(opts.Files)))
		if opts.Status != nil {
			opts.Status(fmt.Sprintf("Compressing at %.2f MiB/s (ETA: %s)", speed, eta))
		}
	}

	for i, path := range opts.Files {
		if opts.Cancel != nil && opts.Cancel() {
			return errZIPCancelled
		}

		report(i)

		var fin io.ReadCloser
		var stat os.FileInfo
		var err error
		if opts.singleSource != nil {
			stat = opts.singleSource.Info
			fin, err = opts.singleSource.Open()
		} else {
			var file *os.File
			file, err = opts.InputIdentities[i].Open()
			if err == nil {
				stat, err = file.Stat()
				fin = file
			}
			if err != nil && file != nil {
				err = errors.Join(err, file.Close())
			}
		}
		if err != nil {
			return fmt.Errorf("open selected input %s: %w", path, err)
		}
		err = func() (retErr error) {
			defer func() { retErr = errors.Join(retErr, fin.Close()) }()

			header, err := zip.FileInfoHeader(stat)
			if err != nil {
				return fmt.Errorf("create header for %s: %w", path, err)
			}

			name, err := entryNameForPath(opts, path)
			if err != nil {
				return err
			}
			header.Name = name

			if opts.Compress {
				header.Method = zip.Deflate
			} else {
				header.Method = zip.Store
			}

			entry, err := writer.CreateHeader(header)
			if err != nil {
				return fmt.Errorf("create entry for %s: %w", path, err)
			}

			for {
				if opts.Cancel != nil && opts.Cancel() {
					return errZIPCancelled
				}

				n, readErr := fin.Read(buf)
				if n > 0 {
					if _, err := entry.Write(buf[:n]); err != nil {
						return fmt.Errorf("write to zip: %w", err)
					}
					done += int64(n)
					report(i)
				}

				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					return fmt.Errorf("read %s: %w", path, readErr)
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}

	// Close writer and file on success
	err := writer.Close()
	if err != nil {
		return fmt.Errorf("close zip writer: %w", err)
	}
	return nil
}
