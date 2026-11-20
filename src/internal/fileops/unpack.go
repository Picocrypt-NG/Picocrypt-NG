package fileops

import (
	"Picocrypt-NG/internal/diskspace"
	"Picocrypt-NG/internal/secret"
	"Picocrypt-NG/internal/util"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// UnpackOptions configures archive extraction
type UnpackOptions struct {
	ZipPath             string // Path to .zip file
	ZipFile             *os.File
	Prepared            *PreparedZIPUnpack // Optional pre-publication metadata/workspace owner
	ExtractDir          string             // Directory to extract to (empty = same as zip, minus .zip)
	ExtractRoot         *os.Root
	ExpectedExtractRoot os.FileInfo
	SameLevel           bool // Extract to same directory as zip (not a subdirectory)
	Progress            ProgressFunc
	Status              StatusFunc
	Cancel              CancelFunc                  // Cancellation check callback (optional)
	Budget              *ZIPResourceBudget          // Shared operation-local archive working budget
	AvailableSpace      func(string) (int64, error) // Override free-space probe (optional, mainly for tests)
	Review              func(ZIPSummary) error      // Optional approval of the declared budget instead of the default ratio limit
}

// UnpackState is the closed publication truth for one typed extraction.
type UnpackState uint8

const (
	UnpackStateNotPublished UnpackState = iota + 1
	UnpackStatePublishedDurable
	UnpackStatePublishedDurabilityUncertain
	UnpackStatePublicationIndeterminate
)

// ErrUnpackCleanupIncomplete reports that absence of operation-owned unpack
// residue was not proven. It does not assert that residue is present.
var ErrUnpackCleanupIncomplete = errors.New("fileops: unpack cleanup incomplete")

// UnpackResult is the sealed terminal view returned by UnpackWithResult.
// Publication state and cleanup uncertainty remain orthogonal.
type UnpackResult interface {
	error
	State() UnpackState
	isUnpackResult()
}

type unpackResult struct {
	state UnpackState
	err   error
}

func (result *unpackResult) State() UnpackState {
	if result == nil {
		return 0
	}
	return result.state
}

func (result *unpackResult) Error() string {
	if result == nil {
		return "fileops: unpack result unavailable"
	}
	return "fileops: unpack " + result.state.String()
}

func (result *unpackResult) Unwrap() error {
	if result == nil {
		return nil
	}
	return result.err
}

func (*unpackResult) isUnpackResult() {}

func (state UnpackState) String() string {
	switch state {
	case UnpackStateNotPublished:
		return "not-published"
	case UnpackStatePublishedDurable:
		return "published-durable"
	case UnpackStatePublishedDurabilityUncertain:
		return "published-durability-uncertain"
	case UnpackStatePublicationIndeterminate:
		return "publication-indeterminate"
	default:
		return "unknown-state"
	}
}

type stagedUnpackEntry struct {
	file       *os.File
	stageName  string
	targetName string
	outPath    string
	info       os.FileInfo
}

func (entry *stagedUnpackEntry) cleanup(root *os.Root) (bool, error) {
	if entry == nil {
		return true, nil
	}
	var closeErr error
	if entry.file != nil {
		if err := entry.file.Close(); err != nil {
			closeErr = fmt.Errorf("close staged extraction output %s: %w", entry.outPath, err)
		}
		entry.file = nil
	}
	if entry.stageName == "" {
		return true, closeErr
	}
	if root == nil || entry.info == nil {
		return false, errors.Join(closeErr, ErrUnpackCleanupIncomplete)
	}
	current, err := root.Lstat(entry.stageName)
	if errors.Is(err, os.ErrNotExist) {
		return false, errors.Join(closeErr, fmt.Errorf("%w: staged extraction output missing during cleanup: %s", ErrUnpackCleanupIncomplete, entry.outPath))
	}
	if err != nil {
		return false, errors.Join(closeErr, fmt.Errorf("inspect staged extraction output %s during cleanup: %w", entry.outPath, err))
	}
	if !current.Mode().IsRegular() || !os.SameFile(entry.info, current) {
		return false, errors.Join(closeErr, fmt.Errorf("%w: staged extraction output changed during cleanup: %s", ErrUnpackCleanupIncomplete, entry.outPath))
	}
	if err := root.Remove(entry.stageName); err != nil {
		return false, errors.Join(closeErr, fmt.Errorf("remove staged extraction output %s: %w", entry.outPath, err))
	}
	entry.stageName = ""
	return true, closeErr
}

var (
	unpackStageSyncFn       = (*os.File).Sync
	unpackDirectorySyncFn   = SyncDirectory
	unpackDirectoryCloseFn  = (*os.File).Close
	unpackCloseRootFn       = (*os.Root).Close
	unpackStageStatFn       = (*os.File).Stat
	unpackCreatedDirLstatFn = (*os.Root).Lstat
)

// normalizeZipPath normalizes a path from a zip file by converting all separators
// to the platform-appropriate separator. This handles cross-platform zip files.
func normalizeZipPath(zipPath string) string {
	// Replace all backslashes with forward slashes first
	normalized := strings.ReplaceAll(zipPath, "\\", "/")
	// Then convert to platform-specific separators
	return filepath.FromSlash(normalized)
}

// hasUnsafeWindowsTrimTraversalComponent rejects path segments that Windows can
// canonicalize into "." or ".." by trimming trailing spaces or periods.
func hasUnsafeWindowsTrimTraversalComponent(path string) bool {
	return slices.ContainsFunc(strings.Split(strings.ReplaceAll(path, "\\", "/"), "/"), becomesDotTraversalAfterWindowsTrim)
}

func becomesDotTraversalAfterWindowsTrim(segment string) bool {
	current := segment
	for {
		if current == "." || current == ".." {
			return true
		}
		if current == "" {
			return false
		}

		last := current[len(current)-1]
		if last != ' ' && last != '.' {
			return false
		}
		current = current[:len(current)-1]
	}
}

// isValidExtractionPath checks if the output path is within the extraction directory.
// This prevents zip slip attacks where malicious archives contain paths like ../../etc/passwd
// while allowing legitimate filenames with double dots like "file..txt".
func isValidExtractionPath(outPath, extractDir string) bool {
	// Clean both paths to resolve any .. segments
	cleanOut := filepath.Clean(outPath)
	cleanBase := filepath.Clean(extractDir)

	// Get the relative path from extractDir to outPath
	rel, err := filepath.Rel(cleanBase, cleanOut)
	if err != nil {
		return false
	}

	// If the relative path starts with "..", it's trying to escape
	// the extraction directory (path traversal attack)
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

func pathWalkStart(path string) (string, []string) {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)

	start := volume
	if strings.HasPrefix(rest, string(filepath.Separator)) {
		start += string(filepath.Separator)
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
	}
	if start == "" {
		start = "."
	}
	if rest == "" || rest == "." {
		return start, nil
	}

	return start, strings.Split(rest, string(filepath.Separator))
}

func walkExtractionRoot(current string, parts []string, create bool, allowLeadingSymlink bool) (string, error) {
	for i, part := range parts {
		next := filepath.Join(current, part)
		isLast := i == len(parts)-1

		info, err := os.Lstat(next)
		switch {
		case os.IsNotExist(err):
			if !create {
				return "", fmt.Errorf("extraction directory does not exist: %s", filepath.Join(current, filepath.Join(parts[i:]...)))
			}
			if err := os.Mkdir(next, 0o700); err != nil {
				return "", fmt.Errorf("create extraction directory %s: %w", next, err)
			}
		case err != nil:
			return "", fmt.Errorf("stat extraction directory %s: %w", next, err)
		case info.Mode()&os.ModeSymlink != 0:
			if !allowLeadingSymlink || i != 0 {
				return "", fmt.Errorf("cannot extract to %s: path contains symlink %s", filepath.Join(current, filepath.Join(parts[i:]...)), next)
			}

			resolved, err := filepath.EvalSymlinks(next)
			if err != nil {
				return "", fmt.Errorf("resolve symlinked extraction directory %s: %w", next, err)
			}

			resolvedInfo, err := os.Stat(resolved)
			if err != nil {
				return "", fmt.Errorf("stat resolved extraction directory %s: %w", resolved, err)
			}
			if !resolvedInfo.IsDir() {
				return "", fmt.Errorf("cannot extract to %s: path resolves to a non-directory: %s", resolved, next)
			}

			current = resolved
			continue
		case !info.IsDir() && isLast:
			return "", fmt.Errorf("cannot extract to %s: path exists as a file (not a directory). Enable 'Same level' option or move/rename the existing file", filepath.Join(current, filepath.Join(parts[i:]...)))
		case !info.IsDir():
			return "", fmt.Errorf("cannot extract to %s: parent path is not a directory: %s", filepath.Join(current, filepath.Join(parts[i:]...)), next)
		}

		current = next
	}

	return current, nil
}

func allowLeadingExtractionRootSymlink(absDir, tempDir string) bool {
	cleanPath := filepath.Clean(absDir)
	cleanTemp := filepath.Clean(tempDir)
	if cleanTemp == "" {
		return false
	}
	if cleanPath == cleanTemp {
		return true
	}
	return strings.HasPrefix(cleanPath, cleanTemp+string(filepath.Separator))
}

func prepareExtractionRoot(extractDir string, create bool) (string, error) {
	absDir, err := filepath.Abs(extractDir)
	if err != nil {
		return "", fmt.Errorf("resolve extraction directory %s: %w", extractDir, err)
	}

	current, parts := pathWalkStart(absDir)
	resolved, err := walkExtractionRoot(current, parts, create, allowLeadingExtractionRootSymlink(absDir, os.TempDir()))
	if err != nil {
		return "", err
	}

	return resolved, nil
}

func verifyExtractionRootPath(extractDir string, expected os.FileInfo) error {
	current, err := os.Stat(extractDir)
	if err != nil {
		return fmt.Errorf("inspect extraction directory before write: %w", err)
	}
	if !os.SameFile(expected, current) {
		return errors.New("extraction directory changed before write")
	}
	return nil
}

// Unpack extracts a zip archive to the specified directory.
func Unpack(opts UnpackOptions) error {
	state := UnpackStateNotPublished
	err := unpack(opts, false, &state)
	if state == UnpackStatePublicationIndeterminate {
		return fmt.Errorf("%w: %w", &unpackResult{state: state}, err)
	}
	return err
}

// UnpackWithResult extracts through the same engine as Unpack and additionally
// classifies publication and directory durability for the PCV3 operation path.
// Its extraction root must already exist: creating the root here would also
// require proving durability of the root's entry in its parent directory.
func UnpackWithResult(opts UnpackOptions) UnpackResult {
	state := UnpackStateNotPublished
	err := unpack(opts, true, &state)
	return &unpackResult{state: state, err: err}
}

func unpack(opts UnpackOptions, classifyPublication bool, state *UnpackState) (retErr error) {
	*state = UnpackStateNotPublished
	var closeReader func() error
	file := opts.ZipFile
	if file == nil {
		var err error
		file, err = os.Open(opts.ZipPath)
		if err != nil {
			return fmt.Errorf("open zip: %w", err)
		}
		closeReader = file.Close
	}
	defer func() {
		if closeReader != nil {
			if err := closeReader(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close zip reader: %w", err))
			}
		}
	}()
	// Determine extraction directory
	extractDir := opts.ExtractDir
	if extractDir == "" {
		if opts.SameLevel {
			extractDir = filepath.Dir(opts.ZipPath)
		} else {
			extractDir = filepath.Join(
				filepath.Dir(opts.ZipPath),
				strings.TrimSuffix(filepath.Base(opts.ZipPath), ".zip"),
			)
		}
	}

	prepared := opts.Prepared
	if prepared == nil {
		var err error
		prepared, err = PrepareZIPUnpack(file, extractDir, ZIPReadOptions{Cancel: opts.Cancel, Budget: opts.Budget})
		if err != nil {
			if errors.Is(err, errZIPCancelled) {
				return errZIPCancelled
			}
			return fmt.Errorf("open zip: %w", err)
		}
		opts.Budget = prepared.state.reader.Budget()
	}
	defer prepared.Close()
	reader, err := prepared.use(file, extractDir, opts.Budget)
	if err != nil {
		return err
	}

	// Calculate total uncompressed size with overflow protection
	var totalSize int64
	var summary ZIPSummary
	for _, f := range reader.File {
		if opts.Cancel != nil && opts.Cancel() {
			return errors.New("operation cancelled")
		}
		size, ok := util.SafeUint64ToInt64(f.UncompressedSize64)
		if !ok {
			return fmt.Errorf("file %s: uncompressed size exceeds int64 max", f.Name)
		}
		if totalSize > math.MaxInt64-size {
			return errors.New("total uncompressed size exceeds int64 max")
		}
		totalSize += size
		if f.FileInfo().IsDir() {
			summary.Directories++
		} else {
			summary.Files++
		}
	}
	summary.UnpackedBytes = totalSize
	reviewed := false
	if opts.Review != nil {
		if opts.Cancel != nil && opts.Cancel() {
			return errors.New("operation cancelled")
		}
		reviewErr := func() (err error) {
			defer func() {
				if recover() != nil {
					err = errors.New("archive review callback panicked")
				}
			}()
			return opts.Review(summary)
		}()
		if opts.Cancel != nil && opts.Cancel() {
			return errors.New("operation cancelled")
		}
		if reviewErr != nil {
			return fmt.Errorf("archive review: %w", reviewErr)
		}
		reviewed = true
	}

	var extractRoot *os.Root
	closeExtractRoot := false
	if opts.ExtractRoot != nil {
		extractDir, err = filepath.Abs(filepath.Clean(extractDir))
		if err != nil {
			return fmt.Errorf("resolve extraction directory %s: %w", extractDir, err)
		}
		extractRoot = opts.ExtractRoot
	} else {
		createExtractRoot := !classifyPublication && !opts.SameLevel && opts.ExpectedExtractRoot == nil
		extractDir, err = prepareExtractionRoot(extractDir, createExtractRoot)
		if err != nil {
			return err
		}
		extractRoot, err = os.OpenRoot(extractDir)
		if err != nil {
			return fmt.Errorf("open extraction root %s: %w", extractDir, err)
		}
		closeExtractRoot = true
	}
	var extractRootInfo os.FileInfo
	defer func() {
		if closeExtractRoot {
			if err := unpackCloseRootFn(extractRoot); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close extraction root: %w", err))
				retErr = errors.Join(retErr, ErrUnpackCleanupIncomplete)
			}
		}
		if *state == UnpackStatePublishedDurable || *state == UnpackStatePublishedDurabilityUncertain {
			// Keep the published files when their pinned directory has moved;
			// the selected destination no longer proves ordinary completion.
			if err := verifyExtractionRootPath(extractDir, extractRootInfo); err != nil {
				*state = UnpackStatePublicationIndeterminate
				retErr = errors.Join(retErr, ErrUnpackCleanupIncomplete, fmt.Errorf("verify extraction directory after publication: %w", err))
			}
		}
	}()
	extractRootInfo, err = extractRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect extraction root %s: %w", extractDir, err)
	}
	if opts.ExpectedExtractRoot != nil && !os.SameFile(opts.ExpectedExtractRoot, extractRootInfo) {
		return errors.New("extraction root does not match the reserved output directory")
	}
	if err := verifyExtractionRootPath(extractDir, extractRootInfo); err != nil {
		return err
	}
	dirs := unpackDirectories{root: extractRoot, path: extractDir, info: extractRootInfo, first: make(map[string]*zipDirectoryIdentity)}
	publicEffect := false
	completed := false
	defer func() {
		if publicEffect && !completed {
			// Public names may no longer refer to our outputs. Keep them and
			// preserve the unresolved publication/cleanup state for both callers.
			*state = UnpackStatePublicationIndeterminate
			retErr = errors.Join(retErr, ErrUnpackCleanupIncomplete)
		}
	}()

	// Record each directory's first identity (or absence) and check existing
	// destinations before staging. Create missing directories after CRC checks.
	stagedEntries := make([]stagedUnpackEntry, 0, len(reader.File))
	seenTargets := make(map[string]struct{})
	for _, f := range reader.File {
		if opts.Cancel != nil && opts.Cancel() {
			return errors.New("operation cancelled")
		}
		isDir := f.FileInfo().IsDir()
		name, err := ParseZIPEntryPath(f.Name, isDir, ZIPPathExtractionCompatible)
		if err != nil {
			return errors.New("potentially malicious zip item path")
		}
		targetName := filepath.Clean(filepath.FromSlash(name))
		outPath := filepath.Join(extractDir, targetName)
		if !filepath.IsLocal(targetName) || !isValidExtractionPath(outPath, extractDir) {
			return errors.New("potentially malicious zip item path")
		}
		if err := dirs.preflight(targetName, isDir); err != nil {
			return err
		}
		if isDir {
			continue
		}
		if _, exists := seenTargets[targetName]; exists {
			return fmt.Errorf("duplicate extraction destination in archive: %s", outPath)
		}
		seenTargets[targetName] = struct{}{}
		stagedEntries = append(stagedEntries, stagedUnpackEntry{targetName: targetName, outPath: outPath})
	}
	for _, entry := range stagedEntries {
		if dirs.first[entry.targetName] != nil {
			return fmt.Errorf("archive declares a file and directory at the same destination: %s", entry.outPath)
		}
	}

	probe := opts.AvailableSpace
	if probe == nil {
		probe = diskspace.Available
	}
	available, err := probe(extractDir)
	if err != nil {
		return fmt.Errorf("check available disk space for extraction: %w", err)
	}
	if totalSize > available {
		return fmt.Errorf("insufficient disk space for extraction: need %d bytes, have %d", totalSize, available)
	}
	if err := verifyExtractionRootPath(extractDir, extractRootInfo); err != nil {
		return err
	}

	// Second pass: extract files
	// Note: File handles are closed manually at the end of each iteration (not using defer)
	// to prevent file descriptor exhaustion when extracting large archives with many files.
	// Using defer here would accumulate all file handles until function exit.
	buf := make([]byte, util.MiB)
	defer secret.SecureZero(buf)
	var done int64
	startTime := time.Now()
	defer func() {
		var cleanupErrors zipCleanupErrors
		cleanupIncomplete := false
		for i := range stagedEntries {
			cleanupProven, cleanupErr := stagedEntries[i].cleanup(extractRoot)
			if cleanupErr != nil {
				cleanupErrors.add(cleanupErr)
			}
			if !cleanupProven || cleanupErr != nil {
				cleanupIncomplete = true
				if !cleanupProven && *state == UnpackStateNotPublished {
					*state = UnpackStatePublicationIndeterminate
				}
			}
		}
		retErr = errors.Join(retErr, cleanupErrors.err())
		if cleanupIncomplete {
			retErr = errors.Join(retErr, ErrUnpackCleanupIncomplete)
		}
	}()

	nextStage := 0
	for i, f := range reader.File {
		// Check for cancellation between files
		if opts.Cancel != nil && opts.Cancel() {
			return errors.New("operation cancelled")
		}

		if f.FileInfo().IsDir() {
			continue
		}

		stagedEntry := &stagedEntries[nextStage]
		nextStage++
		outPath := stagedEntry.outPath

		fileInArchive, err := f.Open()
		if err != nil {
			return fmt.Errorf("open %s in archive: %w", f.Name, err)
		}

		stageName := ".picocrypt-unpack-" + rand.Text()
		stageFile, err := extractRoot.OpenFile(stageName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = fileInArchive.Close()
			return fmt.Errorf("create stage for %s: %w", outPath, err)
		}
		stagedEntry.file = stageFile
		stagedEntry.stageName = stageName
		stageInfo, err := unpackStageStatFn(stageFile)
		if err != nil {
			_ = fileInArchive.Close()
			return fmt.Errorf("inspect stage for %s: %w", outPath, err)
		}
		stagedEntry.info = stageInfo

		// Reviewed entries cannot exceed their declared size. The conversion
		// was checked while computing the approved summary before any output.
		maxBytes := int64(f.UncompressedSize64)
		if !reviewed {
			var ok bool
			maxBytes, ok = ZIPDecompressionLimit(f.CompressedSize64)
			if !ok {
				_ = fileInArchive.Close()
				return fmt.Errorf("file %s: compressed size exceeds int64 max", f.Name)
			}
		}

		var written int64
		for {
			// Check for cancellation during file extraction
			if opts.Cancel != nil && opts.Cancel() {
				_ = fileInArchive.Close()
				return errors.New("operation cancelled")
			}

			n, readErr := fileInArchive.Read(buf)
			if n > 0 {
				count := int64(n)
				if count > maxBytes-written {
					_ = fileInArchive.Close()
					if reviewed {
						return fmt.Errorf("declared ZIP entry size exceeded: %s", f.Name)
					}
					return fmt.Errorf("decompression limit exceeded: %s (ratio >%d:1)",
						f.Name, util.MaxDecompressRatio)
				}
				if reviewed && count > totalSize-done {
					_ = fileInArchive.Close()
					return errors.New("approved ZIP extraction budget exceeded")
				}
				written += count

				if _, err := stageFile.Write(buf[:n]); err != nil {
					_ = fileInArchive.Close()
					return fmt.Errorf("write %s: %w", outPath, err)
				}

				done += count
				if opts.Progress != nil {
					progress, speed, eta := util.Statify(done, totalSize, startTime)
					opts.Progress(progress, fmt.Sprintf("%d/%d", i+1, len(reader.File)))
					if opts.Status != nil {
						opts.Status(fmt.Sprintf("Unpacking at %.2f MiB/s (ETA: %s)", speed, eta))
					}
				}
			}

			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = fileInArchive.Close()
				return fmt.Errorf("read %s: %w", f.Name, readErr)
			}
		}

		_ = fileInArchive.Close()
		if err := unpackStageSyncFn(stageFile); err != nil {
			return fmt.Errorf("sync %s: %w", outPath, err)
		}
		if err := stageFile.Close(); err != nil {
			return fmt.Errorf("close %s: %w", outPath, err)
		}
		stagedEntry.file = nil
		if err := stagedEntry.checkStage(extractRoot); err != nil {
			return err
		}
	}

	// Surface archive-close errors before publishing any staged entry.
	if closeReader != nil {
		if err := closeReader(); err != nil {
			closeReader = nil
			return fmt.Errorf("close zip reader: %w", err)
		}
		closeReader = nil
	}

	// Do not publish a destination before every file has passed its CRC check.
	if err := dirs.verifyExisting(); err != nil {
		return err
	}
	for i := range stagedEntries {
		if err := stagedEntries[i].checkStage(extractRoot); err != nil {
			return err
		}
	}
	if opts.Cancel != nil && opts.Cancel() {
		return errZIPCancelled
	}
	stageDirectory, err := extractRoot.Open(".")
	if err != nil {
		return fmt.Errorf("open staging directory: %w", err)
	}
	defer func() {
		if err := stageDirectory.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close staging directory: %w", err), ErrUnpackCleanupIncomplete)
		}
	}()

	for _, path := range dirs.missing {
		if opts.Cancel != nil && opts.Cancel() {
			return errZIPCancelled
		}
		created, err := dirs.create(path)
		publicEffect = publicEffect || created
		if err != nil {
			return err
		}
	}

	var durabilityErrors zipCleanupErrors
	for i := range stagedEntries {
		if opts.Cancel != nil && opts.Cancel() {
			return errors.Join(errZIPCancelled, durabilityErrors.err())
		}
		published, durabilityErr, err := publishStagedUnpackEntry(extractRoot, stageDirectory, &dirs, &stagedEntries[i], opts.Cancel)
		publicEffect = publicEffect || published
		durabilityErrors.add(durabilityErr)
		if err != nil {
			return errors.Join(err, durabilityErrors.err())
		}
	}

	if opts.Cancel != nil && opts.Cancel() {
		return errors.Join(errZIPCancelled, durabilityErrors.err())
	}
	if classifyPublication {
		bindingErr, durabilityErr, cleanupErr := dirs.sync(stagedEntries)
		durabilityErrors.add(durabilityErr)
		if cleanupErr != nil {
			retErr = errors.Join(cleanupErr, ErrUnpackCleanupIncomplete)
		}
		if bindingErr != nil {
			return errors.Join(bindingErr, durabilityErrors.err(), retErr)
		}
	}
	if err := dirs.verifyExisting(); err != nil {
		return errors.Join(err, durabilityErrors.err(), retErr)
	}

	if opts.Cancel != nil && opts.Cancel() {
		return errors.Join(errZIPCancelled, durabilityErrors.err(), retErr)
	}
	completed = true
	if durabilityErr := durabilityErrors.err(); durabilityErr != nil {
		*state = UnpackStatePublishedDurabilityUncertain
		retErr = errors.Join(retErr, durabilityErr)
	} else {
		*state = UnpackStatePublishedDurable
	}
	return retErr
}
