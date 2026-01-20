package fileops

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"Picocrypt-NG/internal/util"
)

// RecombineOptions configures chunk recombination
type RecombineOptions struct {
	InputBase  string // Base path without .N suffix
	OutputPath string // Output .pcv file path
	Progress   ProgressFunc
	Status     StatusFunc
	Cancel     CancelFunc
}

// CountChunks returns the number of split chunks for a given base path
func CountChunks(basePath string) (int, int64, error) {
	count := 0
	var totalSize int64

	for {
		stat, err := os.Stat(fmt.Sprintf("%s.%d", basePath, count))
		if err != nil {
			break
		}
		count++
		totalSize += stat.Size()
	}

	if count == 0 {
		return 0, 0, errors.New("no chunks found")
	}

	return count, totalSize, nil
}

// Recombine merges split chunks back into a single file.
// Chunks are expected to be named: basePath.0, basePath.1, etc.
func Recombine(opts RecombineOptions) error {
	numChunks, totalSize, err := CountChunks(opts.InputBase)
	if err != nil {
		return err
	}

	// Check if output already exists
	if _, err := os.Stat(opts.OutputPath); err == nil {
		return fmt.Errorf("output file already exists: %s", opts.OutputPath)
	}

	fout, err := os.Create(opts.OutputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() { _ = fout.Close() }()

	var totalDone int64
	startTime := time.Now()

	for i := range numChunks {
		if opts.Cancel != nil && opts.Cancel() {
			_ = fout.Close()
			_ = os.Remove(opts.OutputPath)
			return errors.New("operation cancelled")
		}

		chunkPath := fmt.Sprintf("%s.%d", opts.InputBase, i)
		fin, err := os.Open(chunkPath)
		if err != nil {
			_ = fout.Close()
			_ = os.Remove(opts.OutputPath)
			return fmt.Errorf("open chunk %d: %w", i, err)
		}

		buf := make([]byte, util.MiB)
		for {
			if opts.Cancel != nil && opts.Cancel() {
				_ = fin.Close()
				_ = fout.Close()
				_ = os.Remove(opts.OutputPath)
				return errors.New("operation cancelled")
			}

			n, readErr := fin.Read(buf)
			if n > 0 {
				if _, err := fout.Write(buf[:n]); err != nil {
					_ = fin.Close()
					_ = fout.Close()
					_ = os.Remove(opts.OutputPath)
					return fmt.Errorf("write from chunk %d: %w", i, err)
				}
				totalDone += int64(n)

				if opts.Progress != nil {
					progress, speed, eta := util.Statify(totalDone, totalSize, startTime)
					opts.Progress(progress, fmt.Sprintf("%d/%d", i+1, numChunks))
					if opts.Status != nil {
						opts.Status(fmt.Sprintf("Recombining at %.2f MiB/s (ETA: %s)", speed, eta))
					}
				}
			}

			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = fin.Close()
				_ = fout.Close()
				_ = os.Remove(opts.OutputPath)
				return fmt.Errorf("read chunk %d: %w", i, readErr)
			}
		}

		if err := fin.Close(); err != nil {
			return fmt.Errorf("close chunk %d: %w", i, err)
		}
	}

	// Sync to ensure all data is flushed to disk before caller reads the file
	if err := fout.Sync(); err != nil {
		return fmt.Errorf("sync output file: %w", err)
	}

	return nil
}
