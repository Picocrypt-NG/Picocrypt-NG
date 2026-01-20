// Package fileops provides file operations for Picocrypt volumes:
// zip archive creation, file splitting, chunk recombining, and zip extraction.
//
// These operations are used during encryption (zipping multiple files, splitting output)
// and decryption (recombining chunks, extracting zips).
package fileops

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"Picocrypt-NG/internal/util"
)

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
	InputPath string       // Path to file to split
	ChunkSize int          // Size of each chunk in Unit (or number of parts if Unit=Total)
	Unit      SplitUnit    // Unit of ChunkSize
	Progress  ProgressFunc // Progress callback (optional)
	Status    StatusFunc   // Status message callback (optional)
	Cancel    CancelFunc   // Cancellation check callback (optional)
}

// Split divides a file into multiple sequential chunks for easier storage/transfer.
//
// Output files are named with numeric suffixes: inputPath.0, inputPath.1, inputPath.2, etc.
// Existing chunks with matching names are deleted before splitting begins.
//
// Use cases:
//   - Storing large encrypted volumes on FAT32 (4 GiB file size limit)
//   - Uploading to cloud services with file size restrictions
//   - Splitting for distribution across multiple storage media
//
// To reassemble, use Recombine() or concatenate files in order: cat file.pcv.* > file.pcv
func Split(opts SplitOptions) ([]string, error) {
	stat, err := os.Stat(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	totalSize := stat.Size()

	// Calculate actual chunk size in bytes
	chunkSize := int64(opts.ChunkSize)
	switch opts.Unit {
	case SplitUnitKiB:
		chunkSize *= util.KiB
	case SplitUnitMiB:
		chunkSize *= util.MiB
	case SplitUnitGiB:
		chunkSize *= util.GiB
	case SplitUnitTiB:
		chunkSize *= util.TiB
	case SplitUnitTotal:
		// Divide into N equal parts
		chunkSize = int64(math.Ceil(float64(totalSize) / float64(opts.ChunkSize)))
	}

	numChunks := int(math.Ceil(float64(totalSize) / float64(chunkSize)))

	fin, err := os.Open(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = fin.Close() }()

	// Delete existing chunks first
	existingChunks, _ := filepath.Glob(opts.InputPath + ".*")
	for _, chunk := range existingChunks {
		_ = os.Remove(chunk)
	}

	var chunks []string
	var totalDone int64
	startTime := time.Now()

	for i := range numChunks {
		if opts.Cancel != nil && opts.Cancel() {
			// Clean up partial chunks
			for _, chunk := range chunks {
				_ = os.Remove(chunk)
			}
			return nil, errors.New("operation cancelled")
		}

		chunkPath := fmt.Sprintf("%s.%d.incomplete", opts.InputPath, i)
		fout, err := os.Create(chunkPath)
		if err != nil {
			// Clean up partial chunks
			for _, chunk := range chunks {
				_ = os.Remove(chunk)
			}
			return nil, fmt.Errorf("create chunk %d: %w", i, err)
		}

		var chunkDone int64
		buf := make([]byte, util.MiB)

		for chunkDone < chunkSize {
			if opts.Cancel != nil && opts.Cancel() {
				_ = fout.Close()
				_ = os.Remove(chunkPath)
				for _, chunk := range chunks {
					_ = os.Remove(chunk)
				}
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
					_ = fout.Close()
					_ = os.Remove(chunkPath)
					for _, chunk := range chunks {
						_ = os.Remove(chunk)
					}
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
				_ = fout.Close()
				_ = os.Remove(chunkPath)
				for _, chunk := range chunks {
					_ = os.Remove(chunk)
				}
				return nil, fmt.Errorf("read for chunk %d: %w", i, readErr)
			}
		}

		// Sync to ensure data is flushed before renaming
		if err := fout.Sync(); err != nil {
			return nil, fmt.Errorf("sync chunk %d: %w", i, err)
		}

		if err := fout.Close(); err != nil {
			return nil, fmt.Errorf("close chunk %d: %w", i, err)
		}

		// Rename to final name
		finalPath := fmt.Sprintf("%s.%d", opts.InputPath, i)
		if err := os.Rename(chunkPath, finalPath); err != nil {
			return nil, fmt.Errorf("rename chunk %d: %w", i, err)
		}

		chunks = append(chunks, finalPath)
	}

	return chunks, nil
}
