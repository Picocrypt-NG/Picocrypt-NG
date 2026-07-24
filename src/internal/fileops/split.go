// Package fileops provides file operations for Picocrypt volumes:
// zip archive creation, file splitting, chunk recombining, and zip extraction.
//
// These operations are used during encryption (zipping multiple files, splitting output)
// and decryption (recombining chunks, extracting zips).
package fileops

import (
	"Picocrypt-NG/internal/util"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func isSplitArtifact(baseName, candidateName string) bool {
	prefix := baseName + "."
	if !strings.HasPrefix(candidateName, prefix) {
		return false
	}

	suffix := strings.TrimPrefix(candidateName, prefix)
	suffix = strings.TrimSuffix(suffix, ".incomplete")
	_, ok := parseUnsignedChunkIndex(suffix)
	return ok
}

func existingSplitArtifact(basePath string) (string, error) {
	dir := filepath.Dir(basePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read split output directory: %w", err)
	}
	baseName := filepath.Base(basePath)
	for _, entry := range entries {
		if isSplitArtifact(baseName, entry.Name()) {
			return filepath.Join(dir, entry.Name()), nil
		}
	}
	return "", nil
}

type ownedFilePath struct {
	path string
	info os.FileInfo
}

func newOwnedFilePath(path string, file *os.File) (ownedFilePath, error) {
	info, err := file.Stat()
	if err != nil {
		return ownedFilePath{}, err
	}
	return ownedFilePath{path: path, info: info}, nil
}

func (owned ownedFilePath) remove() error {
	current, err := os.Lstat(owned.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect owned output %s during cleanup: %w", owned.path, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(owned.info, current) {
		return nil
	}
	if err := os.Remove(owned.path); err != nil {
		return fmt.Errorf("remove owned output %s: %w", owned.path, err)
	}
	return nil
}

func (owned ownedFilePath) matches() (bool, error) {
	current, err := os.Lstat(owned.path)
	if err != nil {
		return false, err
	}
	return current.Mode().IsRegular() && os.SameFile(owned.info, current), nil
}

// SplitUnit represents the unit of measurement for chunk sizes when splitting files.
type SplitUnit int

const (
	SplitUnitKiB   SplitUnit = iota // Kibibytes (1024 bytes)
	SplitUnitMiB                    // Mebibytes (1024^2 bytes)
	SplitUnitGiB                    // Gibibytes (1024^3 bytes)
	SplitUnitTiB                    // Tebibytes (1024^4 bytes)
	SplitUnitTotal                  // Special: divide file into N equal parts
)

// SplitOptions configures how a file should be split into chunks.
type SplitOptions struct {
	InputPath     string       // Path to file to split
	ExpectedInput os.FileInfo  // Optional identity that InputPath must still name
	ChunkSize     int          // Size of each chunk in Unit (or number of parts if Unit=Total)
	Unit          SplitUnit    // Unit of ChunkSize
	Progress      ProgressFunc // Progress callback (optional)
	Status        StatusFunc   // Status message callback (optional)
	Cancel        CancelFunc   // Cancellation check callback (optional)
}

// ChunkSizeToBytes converts a chunk size expressed in unit to a byte count,
// rejecting values that overflow int64. It is defined for the fixed-size units
// (KiB/MiB/GiB/TiB); SplitUnitTotal and any unknown unit are size-relative and
// returned unscaled (they cannot overflow here). Callers must reject the error:
// an unchecked overflow wraps negative, making Split a silent no-op.
func ChunkSizeToBytes(chunkSize int, unit SplitUnit) (int64, error) {
	size := int64(chunkSize)
	var unitBytes int64
	switch unit {
	case SplitUnitKiB:
		unitBytes = util.KiB
	case SplitUnitMiB:
		unitBytes = util.MiB
	case SplitUnitGiB:
		unitBytes = util.GiB
	case SplitUnitTiB:
		unitBytes = util.TiB
	default:
		return size, nil
	}
	if size > math.MaxInt64/unitBytes {
		return 0, fmt.Errorf("chunk size too large: %d would overflow when converted to bytes", chunkSize)
	}
	return size * unitBytes, nil
}

// cleanupSplitOnError removes the random stage and every final chunk still
// backed by a file this Split invocation created.
func cleanupSplitOnError(stage *StagedFile, chunks []ownedFilePath) error {
	var cleanupErrs []error
	if stage != nil {
		if err := stage.Cleanup(); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	for _, chunk := range chunks {
		if err := chunk.remove(); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	return errors.Join(cleanupErrs...)
}

// Split divides a file into multiple sequential chunks for easier storage/transfer.
//
// Output files are named with numeric suffixes: inputPath.0, inputPath.1, inputPath.2, etc.
// Existing chunks cause Split to fail without changing them.
//
// Use cases:
//   - Storing large encrypted volumes on FAT32 (4 GiB file size limit)
//   - Uploading to cloud services with file size restrictions
//   - Splitting for distribution across multiple storage media
//
// To reassemble, use Recombine() or concatenate files in order: cat file.pcv.* > file.pcv
func Split(opts SplitOptions) (chunks []string, retErr error) {
	if opts.ChunkSize <= 0 {
		return nil, errors.New("chunk size must be greater than zero")
	}

	fin, err := os.Open(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = fin.Close() }()

	stat, err := fin.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	if opts.ExpectedInput != nil && !os.SameFile(opts.ExpectedInput, stat) {
		return nil, errors.New("input path changed before splitting")
	}
	totalSize := stat.Size()

	// Calculate actual chunk size in bytes
	var chunkSize int64
	if opts.Unit == SplitUnitTotal {
		// Divide into N equal parts
		chunkSize = int64(math.Ceil(float64(totalSize) / float64(opts.ChunkSize)))
	} else {
		chunkSize, err = ChunkSizeToBytes(opts.ChunkSize, opts.Unit)
		if err != nil {
			return nil, err
		}
	}

	numChunks := int(math.Ceil(float64(totalSize) / float64(chunkSize)))

	existing, err := existingSplitArtifact(opts.InputPath)
	if err != nil {
		return nil, err
	}
	if existing != "" {
		return nil, fmt.Errorf("split artifact already exists: %s: %w", existing, os.ErrExist)
	}

	var ownedChunks []ownedFilePath
	var activeStage *StagedFile
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, cleanupSplitOnError(activeStage, ownedChunks))
		}
	}()
	var totalDone int64
	startTime := time.Now()

	for i := range numChunks {
		if opts.Cancel != nil && opts.Cancel() {
			return nil, errors.New("operation cancelled")
		}

		finalPath := fmt.Sprintf("%s.%d", opts.InputPath, i)
		stage, err := CreateSiblingTemp(finalPath)
		if err != nil {
			return nil, fmt.Errorf("create chunk stage %d: %w", i, err)
		}
		activeStage = stage
		fout := stage.File()

		var chunkDone int64
		buf := make([]byte, util.MiB)

		for chunkDone < chunkSize {
			if opts.Cancel != nil && opts.Cancel() {
				return nil, errors.New("operation cancelled")
			}

			// Adjust buffer size if near end of chunk
			remaining := chunkSize - chunkDone
			if remaining < int64(len(buf)) {
				buf = make([]byte, remaining)
			}

			n, readErr := fin.Read(buf)
			if n > 0 {
				if _, err := fout.Write(buf[:n]); err != nil {
					return nil, fmt.Errorf("write chunk %d: %w", i, err)
				}
				chunkDone += int64(n)
				totalDone += int64(n)

				if opts.Progress != nil {
					progress, speed, eta := util.Statify(totalDone, totalSize, startTime)
					opts.Progress(progress, fmt.Sprintf("%d/%d", i+1, numChunks))
					if opts.Status != nil {
						opts.Status(fmt.Sprintf("Splitting at %.2f MiB/s (ETA: %s)", speed, eta))
					}
				}
			}

			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return nil, fmt.Errorf("read for chunk %d: %w", i, readErr)
			}
		}

		if err := fout.Sync(); err != nil {
			return nil, fmt.Errorf("sync chunk stage %d: %w", i, err)
		}
		if _, err := fout.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("rewind chunk stage %d: %w", i, err)
		}

		finalFile, err := CreateExclusiveNoSymlink(finalPath)
		if err != nil {
			return nil, fmt.Errorf("create chunk %d: %w", i, err)
		}
		ownedChunk, err := newOwnedFilePath(finalPath, finalFile)
		if err != nil {
			_ = finalFile.Close()
			return nil, fmt.Errorf("inspect chunk %d: %w", i, err)
		}
		ownedChunks = append(ownedChunks, ownedChunk)
		copied, err := io.Copy(finalFile, fout)
		if err != nil {
			_ = finalFile.Close()
			return nil, fmt.Errorf("publish chunk %d: %w", i, err)
		}
		if copied != chunkDone {
			_ = finalFile.Close()
			return nil, fmt.Errorf("publish chunk %d: copied %d bytes, want %d", i, copied, chunkDone)
		}
		if err := finalFile.Sync(); err != nil {
			_ = finalFile.Close()
			return nil, fmt.Errorf("sync chunk %d: %w", i, err)
		}
		if err := finalFile.Close(); err != nil {
			return nil, fmt.Errorf("close chunk %d: %w", i, err)
		}
		matches, err := ownedChunk.matches()
		if err != nil || !matches {
			if err != nil {
				return nil, fmt.Errorf("inspect completed chunk %d: %w", i, err)
			}
			return nil, fmt.Errorf("chunk %d path changed during splitting", i)
		}

		if err := stage.Cleanup(); err != nil {
			return nil, err
		}
		activeStage = nil
		chunks = append(chunks, finalPath)
	}

	for i, chunk := range ownedChunks {
		matches, err := chunk.matches()
		if err != nil || !matches {
			if err != nil {
				return nil, fmt.Errorf("inspect completed chunk %d: %w", i, err)
			}
			return nil, fmt.Errorf("chunk %d path changed during splitting", i)
		}
	}

	return chunks, nil
}
