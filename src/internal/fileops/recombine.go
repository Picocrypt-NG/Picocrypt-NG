package fileops

import (
	"Picocrypt-NG/internal/util"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// recombineCloseFn is the function used to close a source chunk file.
// Overridable in tests to simulate close failures.
var recombineCloseFn = (*os.File).Close

// recombineSyncFn is the function used to sync the output file.
// Overridable in tests to simulate sync failures.
var recombineSyncFn = (*os.File).Sync

func parseUnsignedChunkIndex(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	index, err := strconv.Atoi(s)
	if err != nil || index < 0 {
		return 0, false
	}
	return index, true
}

// RecombineOptions configures chunk recombination
type RecombineOptions struct {
	InputBase          string               // Base path without .N suffix
	OutputPath         string               // Output .pcv file path
	Output             *os.File             // Optional borrowed output descriptor
	OutputInfo         *os.FileInfo         // Optional exact identity of the completed output
	InputInfos         *[]os.FileInfo       // Optional identities of the exact consumed chunk descriptors
	ExpectedInputs     []os.FileInfo        // Optional pinned identities and sizes for every chunk
	FirstChunk         *os.File             // Optional borrowed, pre-routed chunk-zero descriptor
	ValidateFirstChunk func(*os.File) error // Optional validation before output creation
	Progress           ProgressFunc
	Status             StatusFunc
	Cancel             CancelFunc
}

// CountChunks returns the number of split chunks for a given base path
func CountChunks(basePath string) (int, int64, error) {
	return countChunks(basePath, nil)
}

func countChunks(basePath string, firstChunkInfo os.FileInfo) (int, int64, error) {
	dir := filepath.Dir(basePath)
	if dir == "" {
		dir = "."
	}
	prefix := filepath.Base(basePath) + "."

	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("read chunk dir: %w", err)
	}

	indexes := make([]int, 0, len(entries))
	var totalSize int64

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}

		suffix := strings.TrimPrefix(name, prefix)
		index, ok := parseUnsignedChunkIndex(suffix)
		if !ok {
			continue
		}

		if index == 0 && firstChunkInfo != nil {
			totalSize += firstChunkInfo.Size()
		} else {
			stat, err := entry.Info()
			if err != nil {
				return 0, 0, fmt.Errorf("stat chunk %s: %w", filepath.Join(dir, name), err)
			}
			totalSize += stat.Size()
		}

		indexes = append(indexes, index)
	}

	if len(indexes) == 0 {
		return 0, 0, errors.New("no chunks found")
	}

	sort.Ints(indexes)
	for expected, actual := range indexes {
		if actual != expected {
			return 0, 0, fmt.Errorf("missing chunk %d", expected)
		}
	}

	return len(indexes), totalSize, nil
}

// Recombine merges split chunks back into a single file.
// Chunks are expected to be named: basePath.0, basePath.1, etc.
func Recombine(opts RecombineOptions) (retErr error) {
	firstChunk := opts.FirstChunk
	borrowedFirstChunk := firstChunk != nil
	var firstChunkInfo os.FileInfo
	if firstChunk == nil && opts.ValidateFirstChunk != nil {
		firstChunkPath := opts.InputBase + ".0"
		// #nosec G304 -- chunk path derived from user-provided base path
		firstChunk, retErr = os.Open(firstChunkPath)
		if retErr != nil {
			return fmt.Errorf("open chunk 0: %w", retErr)
		}
		defer func() {
			if firstChunk != nil && !borrowedFirstChunk {
				retErr = errors.Join(retErr, firstChunk.Close())
			}
		}()
	}
	if firstChunk != nil {
		if opts.ExpectedInputs != nil {
			var err error
			firstChunkInfo, err = firstChunk.Stat()
			if err != nil {
				return fmt.Errorf("stat chunk 0: %w", err)
			}
			if len(opts.ExpectedInputs) == 0 || !sameRegularFileAndSize(opts.ExpectedInputs[0], firstChunkInfo) {
				return errors.New("chunk 0 changed before recombination")
			}
		}
		if opts.ValidateFirstChunk != nil {
			if err := opts.ValidateFirstChunk(firstChunk); err != nil {
				return err
			}
		}
		if _, err := firstChunk.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind chunk 0 after validation: %w", err)
		}
		if firstChunkInfo == nil {
			var err error
			firstChunkInfo, err = firstChunk.Stat()
			if err != nil {
				return fmt.Errorf("stat chunk 0: %w", err)
			}
		}
	}

	numChunks, totalSize, err := countChunks(opts.InputBase, firstChunkInfo)
	if err != nil {
		return err
	}
	if opts.ExpectedInputs != nil && len(opts.ExpectedInputs) != numChunks {
		return fmt.Errorf("expected %d chunk identities, found %d chunks", len(opts.ExpectedInputs), numChunks)
	}

	fout := opts.Output
	borrowedOutput := fout != nil
	var ownedOutput ownedFilePath
	if borrowedOutput {
		info, err := fout.Stat()
		if err != nil {
			return fmt.Errorf("inspect borrowed output: %w", err)
		}
		if !info.Mode().IsRegular() {
			return errors.New("borrowed output is not a regular file")
		}
	} else {
		fout, err = CreateExclusiveNoSymlink(opts.OutputPath)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("output file already exists: %s: %w", opts.OutputPath, err)
			}
			return fmt.Errorf("create output: %w", err)
		}
		ownedOutput, err = newOwnedFilePath(opts.OutputPath, fout)
		if err != nil {
			_ = fout.Close()
			return fmt.Errorf("inspect output: %w", err)
		}
	}
	keepOutput := false
	if !borrowedOutput {
		defer func() {
			if err := fout.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close output: %w", err))
				keepOutput = false
			}
			if !keepOutput {
				retErr = errors.Join(retErr, ownedOutput.remove())
			}
		}()
	}

	var totalDone int64
	inputInfos := make([]os.FileInfo, 0, numChunks)
	startTime := time.Now()

	for i := range numChunks {
		if opts.Cancel != nil && opts.Cancel() {
			return errors.New("operation cancelled")
		}

		var (
			fin      *os.File
			closeFin bool
		)
		if i == 0 && firstChunk != nil {
			fin = firstChunk
			closeFin = !borrowedFirstChunk
			firstChunk = nil
		} else {
			chunkPath := fmt.Sprintf("%s.%d", opts.InputBase, i)
			if opts.ExpectedInputs != nil && i > 0 {
				fin, err = OpenExistingNoSymlink(chunkPath, os.O_RDONLY)
			} else {
				// #nosec G304 -- chunk paths derived from user-provided base path
				fin, err = os.Open(chunkPath)
			}
			if err != nil {
				return fmt.Errorf("open chunk %d: %w", i, err)
			}
			closeFin = true
		}
		finInfo, err := fin.Stat()
		if err != nil {
			if closeFin {
				_ = fin.Close()
			}
			return fmt.Errorf("stat chunk %d: %w", i, err)
		}
		if opts.ExpectedInputs != nil && !sameRegularFileAndSize(opts.ExpectedInputs[i], finInfo) {
			if closeFin {
				_ = fin.Close()
			}
			return fmt.Errorf("chunk %d changed before recombination", i)
		}
		inputInfos = append(inputInfos, finInfo)

		buf := make([]byte, util.MiB)
		for {
			if opts.Cancel != nil && opts.Cancel() {
				if closeFin {
					_ = fin.Close()
				}
				return errors.New("operation cancelled")
			}

			n, readErr := fin.Read(buf)
			if n > 0 {
				if _, err := fout.Write(buf[:n]); err != nil {
					if closeFin {
						_ = fin.Close()
					}
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
				if closeFin {
					_ = fin.Close()
				}
				return fmt.Errorf("read chunk %d: %w", i, readErr)
			}
		}

		if closeFin {
			if err := recombineCloseFn(fin); err != nil {
				return fmt.Errorf("close chunk %d: %w", i, err)
			}
		}
	}

	// Sync to ensure all data is flushed to disk before caller reads the file
	if err := recombineSyncFn(fout); err != nil {
		return fmt.Errorf("sync output file: %w", err)
	}
	if borrowedOutput {
		if _, err := fout.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind borrowed output: %w", err)
		}
		if opts.OutputInfo != nil {
			info, err := fout.Stat()
			if err != nil {
				return fmt.Errorf("inspect completed borrowed output: %w", err)
			}
			*opts.OutputInfo = info
		}
	} else {
		current, err := os.Lstat(opts.OutputPath)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(ownedOutput.info, current) {
			if err != nil {
				return fmt.Errorf("inspect completed output: %w", err)
			}
			return errors.New("output path changed during recombination")
		}
		if opts.OutputInfo != nil {
			*opts.OutputInfo = ownedOutput.info
		}
		keepOutput = true
	}
	if opts.InputInfos != nil {
		*opts.InputInfos = append([]os.FileInfo(nil), inputInfos...)
	}

	return nil
}

func sameRegularFileAndSize(expected, actual os.FileInfo) bool {
	return expected != nil && actual != nil &&
		expected.Mode().IsRegular() && actual.Mode().IsRegular() &&
		expected.Size() == actual.Size() && os.SameFile(expected, actual)
}
