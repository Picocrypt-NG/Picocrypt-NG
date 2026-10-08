package cli

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
)

var activeStdinTempPath atomic.Pointer[string]

// cleanupTempFiles removes every stdin/stdout staging temp. It attempts all
// paths and reports a generic error without disclosing temporary pathnames.
func cleanupTempFiles(paths ...string) error {
	failed := false
	for _, p := range paths {
		if p != "" {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				failed = true
				continue
			}
			if active := activeStdinTempPath.Load(); active != nil && *active == p {
				activeStdinTempPath.CompareAndSwap(active, nil)
			}
		}
	}
	if failed {
		return errors.New("temporary file cleanup failed")
	}
	return nil
}

func cleanupActiveStdinTemp() error {
	active := activeStdinTempPath.Swap(nil)
	if active == nil {
		return nil
	}
	return cleanupTempFiles(*active)
}

// IsStdin returns true if the path indicates stdin ("-")
func IsStdin(path string) bool {
	return path == "-"
}

// IsStdout returns true if the path indicates stdout ("-")
func IsStdout(path string) bool {
	return path == "-"
}

// BufferStdinToTemp copies stdin to a temp file and returns the path.
// outputPath is used to determine fallback temp directories.
// Caller is responsible for removing the temp file.
func BufferStdinToTemp(outputPath string) (string, error) {
	// Choose temp directory with space checking
	tempDir, err := ChooseTempDir(0, outputPath) // 0 = unknown size, use default estimate
	if err != nil {
		return "", fmt.Errorf("selecting temp directory: %w", err)
	}

	tmp, err := os.CreateTemp(tempDir, "picocrypt-stdin-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if !activeStdinTempPath.CompareAndSwap(nil, &tmpPath) {
		_ = tmp.Close()
		return "", errors.Join(
			errors.New("another stdin temporary file is already active"),
			cleanupTempFiles(tmpPath),
		)
	}

	// Set restrictive permissions
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", errors.Join(
			fmt.Errorf("setting temp file permissions: %w", err),
			cleanupTempFiles(tmpPath),
		)
	}

	_, err = io.Copy(tmp, os.Stdin)
	if err != nil {
		_ = tmp.Close()
		return "", errors.Join(
			fmt.Errorf("buffering stdin: %w", err),
			cleanupTempFiles(tmpPath),
		)
	}

	if err := tmp.Close(); err != nil {
		return "", errors.Join(
			fmt.Errorf("closing temp file: %w", err),
			cleanupTempFiles(tmpPath),
		)
	}

	return tmpPath, nil
}

// StreamFileToStdout consumes a temporary file while copying it to stdout.
// Unix unlinks it before the first write, so an interrupted process cannot
// leave plaintext at the temporary pathname. Windows removes it after close.
func StreamFileToStdout(ctx context.Context, path string) (retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	absolutePath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolving file for stdout: %w", err)
	}
	root, err := fileops.OpenRootNoSymlink(filepath.Dir(absolutePath))
	if err != nil {
		return fmt.Errorf("opening directory for stdout: %w", err)
	}
	name := filepath.Base(absolutePath)
	f, err := root.Open(name)
	if err != nil {
		return errors.Join(fmt.Errorf("opening file for stdout: %w", err), root.Close())
	}
	identity, statErr := f.Stat()
	current, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || identity == nil || current == nil ||
		!identity.Mode().IsRegular() || !current.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !os.SameFile(identity, current) {
		return errors.Join(
			errors.New("temporary stdout file identity changed"),
			statErr,
			pathErr,
			f.Close(),
			root.Close(),
		)
	}
	unlinked := false
	if runtime.GOOS != "windows" {
		current, err := root.Lstat(name)
		if err != nil || current == nil || !current.Mode().IsRegular() ||
			!os.SameFile(identity, current) || root.Remove(name) != nil {
			return errors.Join(
				errors.New("temporary stdout file cleanup failed"),
				err,
				f.Close(),
				root.Close(),
			)
		}
		unlinked = true
	}
	defer func() {
		if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			retErr = errors.Join(retErr, err)
		}
		if !unlinked {
			current, err := root.Lstat(name)
			if err != nil || current == nil || !current.Mode().IsRegular() ||
				!os.SameFile(identity, current) || root.Remove(name) != nil {
				retErr = errors.Join(retErr, errors.New("temporary stdout file cleanup failed"), err)
			}
		}
		retErr = errors.Join(retErr, root.Close())
	}()

	done := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(os.Stdout, f)
		done <- copyErr
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("streaming to stdout: %w", err)
		}
	case <-ctx.Done():
		_ = f.Close()
		_ = os.Stdout.Close()
		return ctx.Err()
	}

	return nil
}

// CreateTempOutput creates a temp file for output.
// estimatedSize is the expected output size (0 for unknown).
// Caller is responsible for removing the temp file.
func CreateTempOutput(estimatedSize int64) (string, error) {
	// Choose temp directory with space checking
	tempDir, err := ChooseTempDir(estimatedSize, "")
	if err != nil {
		return "", fmt.Errorf("selecting temp directory: %w", err)
	}

	tmp, err := os.CreateTemp(tempDir, "picocrypt-out-*")
	if err != nil {
		return "", fmt.Errorf("creating temp output file: %w", err)
	}
	tmpPath := tmp.Name()

	// Set restrictive permissions
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", errors.Join(
			fmt.Errorf("setting temp file permissions: %w", err),
			cleanupTempFiles(tmpPath),
		)
	}

	// Close immediately - volume package will reopen
	if err := tmp.Close(); err != nil {
		return "", errors.Join(
			fmt.Errorf("closing temp file: %w", err),
			cleanupTempFiles(tmpPath),
		)
	}

	return tmpPath, nil
}
