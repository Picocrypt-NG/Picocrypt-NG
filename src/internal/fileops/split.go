// Package fileops provides file operations for Picocrypt volumes:
// zip archive creation, file splitting, chunk recombining, and zip extraction.
//
// These operations are used during encryption (zipping multiple files, splitting output)
// and decryption (recombining chunks, extracting zips).
package fileops

import (
	"Picocrypt-NG/internal/util"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var splitDirectorySyncFn = SyncDirectory

var ErrSplitCleanupIncomplete = errors.New("split cleanup incomplete")

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
	name string
	info os.FileInfo
	root *os.Root
}

func newOwnedFilePath(path string, file *os.File) (ownedFilePath, error) {
	return newOwnedFileInRoot(path, "", nil, file)
}

func newOwnedFileInRoot(path, name string, root *os.Root, file *os.File) (ownedFilePath, error) {
	info, err := file.Stat()
	if err != nil {
		return ownedFilePath{}, err
	}
	return ownedFilePath{path: path, name: name, info: info, root: root}, nil
}

func (owned ownedFilePath) lstat() (os.FileInfo, error) {
	if owned.root != nil {
		return owned.root.Lstat(owned.name)
	}
	return os.Lstat(owned.path)
}

func (owned ownedFilePath) remove() error {
	current, err := owned.lstat()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect owned output %s during cleanup: %w", owned.path, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(owned.info, current) {
		return nil
	}
	if owned.root != nil {
		err = owned.root.Remove(owned.name)
	} else {
		err = os.Remove(owned.path)
	}
	if err != nil {
		return fmt.Errorf("remove owned output %s: %w", owned.path, err)
	}
	return nil
}

func (owned ownedFilePath) matches() (bool, error) {
	current, err := owned.lstat()
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
	InputPath            string             // Path to file to split
	ExpectedInput        os.FileInfo        // Optional identity that InputPath must still name
	ExpectedDirectory    os.FileInfo        // Optional identity that the output directory must retain
	ExpectedSHA256       *[sha256.Size]byte // Optional digest frozen before splitting starts
	ChunkSize            int                // Size of each chunk in Unit (or number of parts if Unit=Total)
	Unit                 SplitUnit          // Unit of ChunkSize
	MinimumChunkSize     int64              // Optional minimum bytes required in every non-final chunk
	RequireDirectorySync bool               // Require durable chunk creation and rollback removal
	Progress             ProgressFunc       // Progress callback (optional)
	Status               StatusFunc         // Status message callback (optional)
	Cancel               CancelFunc         // Cancellation check callback (optional)
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

func openSplitDirectory(path string) (*os.Root, *os.File, os.FileInfo, error) {
	root, err := OpenRootNoSymlink(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open split output directory: %w", err)
	}
	identity, err := root.Stat(".")
	if err != nil {
		return nil, nil, nil, errors.Join(
			fmt.Errorf("inspect split output directory: %w", err),
			root.Close(),
		)
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, nil, nil, errors.Join(
			fmt.Errorf("retain split output directory: %w", err),
			root.Close(),
		)
	}
	opened, statErr := directory.Stat()
	if statErr != nil || opened == nil || !os.SameFile(identity, opened) {
		return nil, nil, nil, errors.Join(
			errors.New("split output directory identity changed while opening"),
			statErr,
			directory.Close(),
			root.Close(),
		)
	}
	return root, directory, identity, nil
}

func existingSplitArtifactInRoot(root *os.Root, basePath string) (string, error) {
	directory, err := root.Open(".")
	if err != nil {
		return "", fmt.Errorf("open split output directory: %w", err)
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return "", errors.Join(fmt.Errorf("read split output directory: %w", readErr), closeErr)
	}
	baseName := filepath.Base(basePath)
	for _, entry := range entries {
		if isSplitArtifact(baseName, entry.Name()) {
			return filepath.Join(filepath.Dir(basePath), entry.Name()), nil
		}
	}
	return "", nil
}

func validateSplitDirectory(directory *os.File, path string, identity os.FileInfo) error {
	if directory == nil || identity == nil {
		return errors.New("split output directory is unavailable")
	}
	pinned, err := directory.Stat()
	if err != nil || pinned == nil || !os.SameFile(identity, pinned) {
		return errors.Join(errors.New("split output directory identity changed"), err)
	}
	current, err := os.Lstat(path)
	if err != nil || current == nil || !current.IsDir() ||
		current.Mode()&os.ModeSymlink != 0 || !os.SameFile(identity, current) {
		return errors.Join(errors.New("split output directory path changed"), err)
	}
	return nil
}

func syncSplitDirectory(directory *os.File, path string, identity os.FileInfo) error {
	if err := validateSplitDirectory(directory, path, identity); err != nil {
		return err
	}
	if err := splitDirectorySyncFn(directory); err != nil {
		return fmt.Errorf("sync split output directory: %w", err)
	}
	return nil
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
	return split(opts, nil, nil, nil, nil, splitDirectorySyncFn)
}

// SplitPinned is Split with borrowed input and output-directory handles. All
// chunk names are resolved through root; the handles remain owned by the caller.
func SplitPinned(
	opts SplitOptions,
	input *os.File,
	root *os.Root,
	directory *os.File,
) (chunks []string, retErr error) {
	if input == nil || root == nil || directory == nil {
		return nil, os.ErrInvalid
	}
	opts.RequireDirectorySync = true
	return split(opts, input, root, directory, nil, splitDirectorySyncFn)
}

// SplitState describes verified chunk completion, independently of any full-file removal.
type SplitState uint8

const (
	SplitFailed SplitState = iota
	SplitCompleteDurable
	SplitCompleteDurabilityUncertain
)

// SplitResult preserves a complete chunk set when only its final directory
// barrier failed. A non-nil returned error instead means split failure/rollback.
type SplitResult struct {
	State           SplitState
	Chunks          []string
	DurabilityError error
}

// SplitPinnedWithResult borrows the pinned handles and directory barrier policy.
// The barrier runs only after internal directory identity and content checks;
// uncertainty never relaxes file flush, close, cancellation or identity checks.
func SplitPinnedWithResult(opts SplitOptions, input *os.File, root *os.Root, directory *os.File, barrier func(*os.File) error) (result SplitResult, err error) {
	if input == nil || root == nil || directory == nil || barrier == nil {
		return result, os.ErrInvalid
	}
	opts.RequireDirectorySync = true
	result.Chunks, err = split(opts, input, root, directory, &result, barrier)
	if err == nil && result.State != SplitCompleteDurabilityUncertain {
		result.State = SplitCompleteDurable
	}
	return result, err
}

func split(
	opts SplitOptions,
	pinnedInput *os.File,
	pinnedRoot *os.Root,
	pinnedDirectory *os.File,
	completion *SplitResult,
	barrier func(*os.File) error,
) (chunks []string, retErr error) {
	if opts.ChunkSize <= 0 {
		return nil, errors.New("chunk size must be greater than zero")
	}

	fin := pinnedInput
	closeInput := false
	var err error
	if fin == nil {
		fin, err = os.Open(opts.InputPath)
		if err != nil {
			return nil, fmt.Errorf("open input: %w", err)
		}
		closeInput = true
	}
	if closeInput {
		defer func() { _ = fin.Close() }()
	}

	stat, err := fin.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	if opts.ExpectedInput != nil &&
		(!opts.ExpectedInput.Mode().IsRegular() || !stat.Mode().IsRegular() ||
			opts.ExpectedInput.Size() != stat.Size() || !os.SameFile(opts.ExpectedInput, stat)) {
		return nil, errors.New("input path changed before splitting (identity or size mismatch)")
	}
	totalSize := stat.Size()
	if _, err := fin.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind input: %w", err)
	}

	splitRoot := pinnedRoot
	splitDirectory := pinnedDirectory
	var splitDirectoryIdentity os.FileInfo
	splitDirectoryPath := filepath.Dir(opts.InputPath)
	if opts.RequireDirectorySync {
		closeDirectory := false
		if splitRoot == nil || splitDirectory == nil {
			splitRoot, splitDirectory, splitDirectoryIdentity, err = openSplitDirectory(splitDirectoryPath)
			if err != nil {
				return nil, err
			}
			closeDirectory = true
		} else {
			rootInfo, rootErr := splitRoot.Stat(".")
			directoryInfo, directoryErr := splitDirectory.Stat()
			if rootErr != nil || directoryErr != nil || rootInfo == nil || directoryInfo == nil ||
				!rootInfo.IsDir() || !directoryInfo.IsDir() || !os.SameFile(rootInfo, directoryInfo) {
				return nil, errors.Join(errors.New("pinned split output directory is invalid"), rootErr, directoryErr)
			}
			splitDirectoryIdentity = rootInfo
		}
		if closeDirectory {
			defer func() {
				_ = splitDirectory.Close()
				_ = splitRoot.Close()
			}()
		}
		if opts.ExpectedDirectory != nil && !os.SameFile(opts.ExpectedDirectory, splitDirectoryIdentity) {
			return nil, errors.New("split output directory changed before splitting")
		}
	}

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
	if opts.MinimumChunkSize > 0 && chunkSize < opts.MinimumChunkSize {
		return nil, fmt.Errorf("chunk size %d is below required minimum %d", chunkSize, opts.MinimumChunkSize)
	}

	numChunks := int(math.Ceil(float64(totalSize) / float64(chunkSize)))

	var existing string
	if splitRoot != nil {
		existing, err = existingSplitArtifactInRoot(splitRoot, opts.InputPath)
	} else {
		existing, err = existingSplitArtifact(opts.InputPath)
	}
	if err != nil {
		return nil, err
	}
	if existing != "" {
		return nil, fmt.Errorf("split artifact already exists: %s: %w", existing, os.ErrExist)
	}

	var ownedChunks []ownedFilePath
	var activeStage *StagedFile
	directoryModified := false
	defer func() {
		if retErr != nil {
			cleanupErr := cleanupSplitOnError(activeStage, ownedChunks)
			if opts.RequireDirectorySync && directoryModified {
				cleanupErr = errors.Join(
					cleanupErr,
					syncSplitDirectory(splitDirectory, splitDirectoryPath, splitDirectoryIdentity),
				)
			}
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()
	var totalDone int64
	firstPassDigest := sha256.New()
	startTime := time.Now()

	for i := range numChunks {
		if opts.Cancel != nil && opts.Cancel() {
			return nil, context.Canceled
		}

		finalPath := fmt.Sprintf("%s.%d", opts.InputPath, i)
		finalName := filepath.Base(finalPath)
		var stage *StagedFile
		if splitRoot != nil {
			stage, err = createSiblingTempInRoot(splitRoot, splitDirectoryIdentity, finalName, finalPath)
		} else {
			stage, err = CreateSiblingTemp(finalPath)
		}
		if err != nil {
			return nil, fmt.Errorf("create chunk stage %d: %w", i, err)
		}
		directoryModified = true
		activeStage = stage
		fout := stage.File()

		var chunkDone int64
		buf := make([]byte, util.MiB)

		for chunkDone < chunkSize {
			if opts.Cancel != nil && opts.Cancel() {
				return nil, context.Canceled
			}

			// Adjust buffer size if near end of chunk
			remaining := chunkSize - chunkDone
			if remaining < int64(len(buf)) {
				buf = make([]byte, remaining)
			}

			n, readErr := fin.Read(buf)
			if n > 0 {
				if opts.RequireDirectorySync || opts.ExpectedSHA256 != nil {
					_, _ = firstPassDigest.Write(buf[:n])
				}
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

		var finalFile *os.File
		if splitRoot != nil {
			finalFile, err = splitRoot.OpenFile(finalName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		} else {
			finalFile, err = CreateExclusiveNoSymlink(finalPath)
		}
		if err != nil {
			return nil, fmt.Errorf("create chunk %d: %w", i, err)
		}
		ownedChunk, err := newOwnedFileInRoot(finalPath, finalName, splitRoot, finalFile)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("inspect chunk %d: %w", i, err),
				finalFile.Close(),
				ErrSplitCleanupIncomplete,
			)
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
	if totalDone != totalSize {
		return nil, fmt.Errorf("split source changed size while reading: copied %d of %d bytes", totalDone, totalSize)
	}
	if opts.ExpectedSHA256 != nil && !bytes.Equal(firstPassDigest.Sum(nil), opts.ExpectedSHA256[:]) {
		return nil, errors.New("split source does not match its prepublication digest")
	}
	if opts.RequireDirectorySync {
		current, err := fin.Stat()
		if err != nil || current == nil || !current.Mode().IsRegular() ||
			current.Size() != totalSize || !os.SameFile(stat, current) {
			return nil, errors.Join(errors.New("split source changed before verification"), err)
		}
		if _, err := fin.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("rewind split source for verification: %w", err)
		}
		secondPassDigest := sha256.New()
		remaining := totalSize
		buffer := make([]byte, util.MiB)
		for remaining > 0 {
			if opts.Cancel != nil && opts.Cancel() {
				return nil, context.Canceled
			}
			want := int64(len(buffer))
			if remaining < want {
				want = remaining
			}
			count, readErr := io.ReadFull(fin, buffer[:want])
			if count > 0 {
				_, _ = secondPassDigest.Write(buffer[:count])
				remaining -= int64(count)
			}
			if readErr != nil {
				return nil, fmt.Errorf("verify split source: %w", readErr)
			}
		}
		verified, err := fin.Stat()
		if err != nil || verified == nil || !verified.Mode().IsRegular() ||
			verified.Size() != totalSize || !os.SameFile(stat, verified) ||
			!bytes.Equal(firstPassDigest.Sum(nil), secondPassDigest.Sum(nil)) ||
			(opts.ExpectedSHA256 != nil && !bytes.Equal(secondPassDigest.Sum(nil), opts.ExpectedSHA256[:])) {
			return nil, errors.Join(errors.New("split source changed while creating chunks"), err)
		}
	}
	if completion != nil {
		// Verify the published chunk bytes, not just the source read passes.
		chunkDigest := sha256.New()
		var verifiedBytes int64
		buffer := make([]byte, util.MiB)
		for i, chunk := range ownedChunks {
			file, err := splitRoot.Open(chunk.name)
			if err != nil {
				return nil, fmt.Errorf("open completed chunk %d: %w", i, err)
			}
			info, statErr := file.Stat()
			if statErr != nil || info == nil || !info.Mode().IsRegular() || !os.SameFile(chunk.info, info) {
				return nil, errors.Join(errors.New("completed chunk identity changed"), statErr, file.Close())
			}
			for {
				if opts.Cancel != nil && opts.Cancel() {
					return nil, errors.Join(context.Canceled, file.Close())
				}
				n, readErr := file.Read(buffer)
				if n > 0 {
					_, _ = chunkDigest.Write(buffer[:n])
					verifiedBytes += int64(n)
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					return nil, errors.Join(readErr, file.Close())
				}
			}
			if err := file.Close(); err != nil {
				return nil, err
			}
			matches, err := chunk.matches()
			if err != nil || !matches {
				return nil, errors.Join(errors.New("completed chunk path changed"), err)
			}
		}
		if verifiedBytes != totalSize || !bytes.Equal(chunkDigest.Sum(nil), firstPassDigest.Sum(nil)) {
			return nil, errors.New("completed chunk content does not match split source")
		}
	}
	if opts.Cancel != nil && opts.Cancel() {
		return nil, context.Canceled
	}
	if opts.RequireDirectorySync {
		if err := validateSplitDirectory(splitDirectory, splitDirectoryPath, splitDirectoryIdentity); err != nil {
			return nil, err
		}
		sourcePath := ownedFilePath{path: opts.InputPath, name: filepath.Base(opts.InputPath), root: splitRoot, info: stat}
		if completion != nil {
			matches, err := sourcePath.matches()
			if err != nil || !matches {
				return nil, errors.Join(errors.New("split source path changed"), err)
			}
		}
		barrierErr := barrier(splitDirectory)
		// Revalidate after the syscall too: a lost/replaced directory is a
		// failed split, never merely unconfirmed durability.
		if identityErr := validateSplitDirectory(splitDirectory, splitDirectoryPath, splitDirectoryIdentity); identityErr != nil {
			return nil, errors.Join(barrierErr, identityErr)
		}
		if completion != nil {
			matches, err := sourcePath.matches()
			if err != nil || !matches {
				return nil, errors.Join(errors.New("split source path changed"), err)
			}
		}
		if opts.Cancel != nil && opts.Cancel() {
			return nil, context.Canceled
		}
		if err := barrierErr; err != nil {
			if completion == nil {
				return nil, fmt.Errorf("sync split output directory: %w", err)
			}
			completion.State = SplitCompleteDurabilityUncertain
			completion.DurabilityError = err
		}
	}

	return chunks, nil
}
