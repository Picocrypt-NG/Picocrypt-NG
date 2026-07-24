package fileops

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/util"
	"archive/zip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/chacha20"
)

// ProgressFunc is called during file operations to report progress.
// Parameters: progress (0.0-1.0 completion fraction), info (human-readable status).
type ProgressFunc func(progress float32, info string)

// StatusFunc is called to report status messages (e.g., "Compressing...", "Splitting...").
type StatusFunc func(status string)

// CancelFunc is called periodically to check if the user requested cancellation.
// Return true to abort the operation.
type CancelFunc func() bool

// encryptedWriter wraps an io.Writer to encrypt data on-the-fly using ChaCha20.
// Used for temporary zip files to protect plaintext on disk during compression.
type encryptedWriter struct {
	w      io.Writer
	cipher *chacha20.Cipher
}

func (ew *encryptedWriter) Write(data []byte) (int, error) {
	dst := make([]byte, len(data))
	ew.cipher.XORKeyStream(dst, data)
	return ew.w.Write(dst)
}

// encryptedReader wraps an io.Reader to decrypt data on-the-fly using ChaCha20.
// Used to read the encrypted temporary zip during encryption phase.
type encryptedReader struct {
	r      io.Reader
	cipher *chacha20.Cipher
}

func (er *encryptedReader) Read(data []byte) (int, error) {
	src := make([]byte, len(data))
	n, err := er.r.Read(src)
	if n > 0 {
		dst := make([]byte, n)
		er.cipher.XORKeyStream(dst, src[:n])
		copy(data, dst)
	}
	return n, err
}

// TempZipCiphers holds paired ChaCha20 ciphers for encrypting temporary files.
// This protects plaintext from being written to disk during multi-file encryption.
//
// Security note: The temporary zip file is encrypted with a random ephemeral key
// that exists only in memory. Even if the temp file is recovered, it cannot be
// decrypted without this key.
//
// SECURITY: Call Close() when done to zero the ephemeral key material.
type TempZipCiphers struct {
	Writer *chacha20.Cipher // Used when writing the zip archive
	Reader *chacha20.Cipher // Used when reading back for encryption
	key    *crypto.Secret   // Ephemeral key (owned for secure zeroing)
	nonce  *crypto.Secret   // Nonce (owned for secure zeroing)
	closed bool
}

// NewTempZipCiphers creates synchronized ChaCha20 cipher pair for temp file protection.
//
// Both ciphers share the same random key and nonce, so data encrypted by Writer
// can be decrypted by Reader. The key is generated fresh and never written to disk.
//
// Returns error if crypto/rand fails (indicates serious system problem).
func NewTempZipCiphers() (*TempZipCiphers, error) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)

	if n, err := rand.Read(key); err != nil || n != 32 {
		return nil, errors.New("fatal crypto/rand error")
	}
	if n, err := rand.Read(nonce); err != nil || n != 12 {
		return nil, errors.New("fatal crypto/rand error")
	}

	// Sanity check
	zeroKey := make([]byte, 32)
	zeroNonce := make([]byte, 12)
	if string(key) == string(zeroKey) || string(nonce) == string(zeroNonce) {
		return nil, errors.New("fatal crypto/rand error: produced zero values")
	}

	writer, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}

	reader, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}

	return &TempZipCiphers{
		Writer: writer,
		Reader: reader,
		key:    crypto.SecretFrom(key),
		nonce:  crypto.SecretFrom(nonce),
	}, nil
}

// Close securely zeros the ephemeral key material and clears cipher references.
// This should be called when the temporary zip is no longer needed.
//
// SECURITY: Always call Close() to minimize the window during which
// the ephemeral key is recoverable from memory.
func (t *TempZipCiphers) Close() {
	if t == nil || t.closed {
		return
	}
	t.key.Close()
	t.nonce.Close()
	t.key = nil
	t.nonce = nil
	t.Writer = nil
	t.Reader = nil
	t.closed = true
}

// ZipOptions configures zip file creation
type ZipOptions struct {
	Files      []string // Files to include
	RootDir    string   // Root directory for relative paths
	EntryNames map[string]string
	OutputPath string          // Output archive path
	OutputFile *os.File        // Optional caller-owned, exclusively created output
	Compress   bool            // Use Deflate compression
	Cipher     *TempZipCiphers // Optional encryption for temp file
	Progress   ProgressFunc
	Status     StatusFunc
	Cancel     CancelFunc
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

	var w io.Writer = file
	if opts.Cipher != nil {
		w = &encryptedWriter{w: file, cipher: opts.Cipher.Writer}
	}

	writer := zip.NewWriter(w)
	writerClosed := false
	fileClosed := false
	keepOutput := false
	defer func() {
		if !writerClosed {
			if err := writer.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close zip writer during cleanup: %w", err))
			}
		}
		if ownsFile && !keepOutput {
			if !fileClosed {
				if err := file.Close(); err != nil {
					retErr = errors.Join(retErr, fmt.Errorf("close zip file during cleanup: %w", err))
				}
			}
			retErr = errors.Join(retErr, ownedOutput.remove())
		}
	}()

	// Calculate total size for progress
	var totalSize int64
	for _, path := range opts.Files {
		stat, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		totalSize += stat.Size()
	}

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
			return errors.New("operation cancelled")
		}

		report(i)

		stat, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

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

		// #nosec G304 -- input paths from user-provided file list
		fin, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}

		buf := make([]byte, util.MiB)
		for {
			if opts.Cancel != nil && opts.Cancel() {
				_ = fin.Close()
				return errors.New("operation cancelled")
			}

			n, readErr := fin.Read(buf)
			if n > 0 {
				if _, err := entry.Write(buf[:n]); err != nil {
					_ = fin.Close()
					return fmt.Errorf("write to zip: %w", err)
				}
				done += int64(n)
				report(i)
			}

			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = fin.Close()
				return fmt.Errorf("read %s: %w", path, readErr)
			}
		}
		_ = fin.Close()
	}

	// Close writer and file on success
	err := writer.Close()
	writerClosed = true
	if err != nil {
		return fmt.Errorf("close zip writer: %w", err)
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

// WrapReaderWithCipher wraps a reader with the temp zip decryption cipher
func WrapReaderWithCipher(r io.Reader, cipher *TempZipCiphers) io.Reader {
	if cipher == nil {
		return r
	}
	return &encryptedReader{r: r, cipher: cipher.Reader}
}
