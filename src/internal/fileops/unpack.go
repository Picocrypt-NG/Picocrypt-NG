package fileops

import (
	"Picocrypt-NG/internal/diskspace"
	"Picocrypt-NG/internal/util"
	"archive/zip"
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
	ExtractDir          string // Directory to extract to (empty = same as zip, minus .zip)
	ExtractRoot         *os.Root
	ExpectedExtractRoot os.FileInfo
	SameLevel           bool // Extract to same directory as zip (not a subdirectory)
	Progress            ProgressFunc
	Status              StatusFunc
	Cancel              CancelFunc                  // Cancellation check callback (optional)
	AvailableSpace      func(string) (int64, error) // Override free-space probe (optional, mainly for tests)
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
	if entry == nil || root == nil || entry.stageName == "" {
		return true, nil
	}
	var closeErr error
	if entry.file != nil {
		if err := entry.file.Close(); err != nil {
			closeErr = fmt.Errorf("close staged extraction output %s: %w", entry.outPath, err)
		}
		entry.file = nil
	}
	current, err := root.Lstat(entry.stageName)
	if errors.Is(err, os.ErrNotExist) {
		return false, closeErr
	}
	if err != nil {
		return false, errors.Join(closeErr, fmt.Errorf("inspect staged extraction output %s during cleanup: %w", entry.outPath, err))
	}
	if !current.Mode().IsRegular() || !os.SameFile(entry.info, current) {
		return false, closeErr
	}
	if err := root.Remove(entry.stageName); err != nil {
		return false, errors.Join(closeErr, fmt.Errorf("remove staged extraction output %s: %w", entry.outPath, err))
	}
	entry.stageName = ""
	return true, closeErr
}

type ownedUnpackFile struct {
	targetName string
	outPath    string
	info       os.FileInfo
}

func (owned ownedUnpackFile) remove(root *os.Root) error {
	current, err := root.Lstat(owned.targetName)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("published extraction output missing before rollback: %s", owned.outPath)
	}
	if err != nil {
		return fmt.Errorf("inspect published extraction output %s during rollback: %w", owned.outPath, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(owned.info, current) {
		return fmt.Errorf("published extraction output changed before rollback: %s", owned.outPath)
	}
	if err := root.Remove(owned.targetName); err != nil {
		return fmt.Errorf("remove published extraction output %s during rollback: %w", owned.outPath, err)
	}
	return nil
}

type ownedUnpackDir struct {
	targetName string
	outPath    string
	info       os.FileInfo
}

type ownedUnpackDirs struct {
	entries []ownedUnpackDir
	indexes map[string]int
}

func (dirs *ownedUnpackDirs) record(dir ownedUnpackDir) {
	if dirs.indexes == nil {
		dirs.indexes = make(map[string]int)
	}
	if index, ok := dirs.indexes[dir.targetName]; ok {
		dirs.entries[index] = dir
		return
	}
	dirs.indexes[dir.targetName] = len(dirs.entries)
	dirs.entries = append(dirs.entries, dir)
}

func (dirs *ownedUnpackDirs) cleanup(root *os.Root) error {
	var cleanupErrs []error
	for i := len(dirs.entries) - 1; i >= 0; i-- {
		dir := dirs.entries[i]
		current, err := root.Lstat(dir.targetName)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			cleanupErrs = append(
				cleanupErrs,
				fmt.Errorf("inspect extraction directory %s during rollback: %w", dir.outPath, err),
			)
		case !current.IsDir() || !os.SameFile(dir.info, current):
			cleanupErrs = append(
				cleanupErrs,
				fmt.Errorf("extraction directory changed before rollback: %s", dir.outPath),
			)
		default:
			if err := root.Remove(dir.targetName); err != nil {
				cleanupErrs = append(
					cleanupErrs,
					fmt.Errorf("remove extraction directory %s during rollback: %w", dir.outPath, err),
				)
			}
		}
	}
	return errors.Join(cleanupErrs...)
}

var (
	unpackLinkFn           = (*os.Root).Link
	unpackCopyFn           = io.Copy
	unpackStageSyncFn      = (*os.File).Sync
	unpackDirectorySyncFn  = (*os.File).Sync
	unpackDirectoryCloseFn = (*os.File).Close
	unpackCloseRootFn      = (*os.Root).Close
	unpackRemoveOwnedFn    = ownedUnpackFile.remove
)

func publishStagedUnpackEntry(
	root *os.Root,
	entry *stagedUnpackEntry,
) (published ownedUnpackFile, cleanupProven bool, retErr error) {
	cleanupProven = true
	currentStage, err := root.Lstat(entry.stageName)
	if err != nil {
		return ownedUnpackFile{}, true, fmt.Errorf("inspect stage for %s before publish: %w", entry.outPath, err)
	}
	if !currentStage.Mode().IsRegular() || !os.SameFile(entry.info, currentStage) {
		return ownedUnpackFile{}, true, fmt.Errorf("stage path changed before publishing %s", entry.outPath)
	}

	// A hard link publishes the complete staged inode atomically and fails if
	// the destination exists. Filesystems without hard-link support fall back
	// to an exclusive copy, which retains the same no-clobber contract.
	if err := unpackLinkFn(root, entry.stageName, entry.targetName); err == nil {
		owned := ownedUnpackFile{targetName: entry.targetName, outPath: entry.outPath, info: entry.info}
		targetInfo, statErr := root.Lstat(entry.targetName)
		if statErr != nil {
			rollbackErr := unpackRemoveOwnedFn(owned, root)
			return ownedUnpackFile{}, rollbackErr == nil, errors.Join(
				fmt.Errorf("inspect published %s: %w", entry.outPath, statErr),
				rollbackErr,
			)
		}
		if !targetInfo.Mode().IsRegular() || !os.SameFile(entry.info, targetInfo) {
			rollbackErr := unpackRemoveOwnedFn(owned, root)
			return ownedUnpackFile{}, rollbackErr == nil, errors.Join(
				fmt.Errorf("published path changed for %s", entry.outPath),
				rollbackErr,
			)
		}
		owned.info = targetInfo
		if err := root.Remove(entry.stageName); err != nil {
			rollbackErr := unpackRemoveOwnedFn(owned, root)
			return ownedUnpackFile{}, rollbackErr == nil, errors.Join(
				fmt.Errorf("remove stage for %s: %w", entry.outPath, err),
				rollbackErr,
			)
		}
		entry.stageName = ""
		return owned, true, nil
	}

	if _, err := root.Lstat(entry.targetName); err == nil {
		return ownedUnpackFile{}, true, fmt.Errorf("extraction destination already exists: %s: %w", entry.outPath, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ownedUnpackFile{}, true, fmt.Errorf("inspect extraction destination %s: %w", entry.outPath, err)
	}

	target, err := root.OpenFile(entry.targetName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ownedUnpackFile{}, true, fmt.Errorf("create extraction destination %s: %w", entry.outPath, err)
	}
	cleanupProven = false
	targetOpen := true
	keepTarget := false
	owned := ownedUnpackFile{targetName: entry.targetName, outPath: entry.outPath}
	defer func() {
		if keepTarget {
			return
		}
		if targetOpen {
			if err := target.Close(); err != nil {
				retErr = errors.Join(
					retErr,
					fmt.Errorf("close extraction destination %s during rollback: %w", entry.outPath, err),
				)
			}
			targetOpen = false
		}
		if owned.info == nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("could not safely roll back extraction destination with unavailable identity: %s", entry.outPath),
			)
			return
		}
		removeErr := unpackRemoveOwnedFn(owned, root)
		retErr = errors.Join(retErr, removeErr)
		cleanupProven = removeErr == nil
	}()

	targetInfo, err := target.Stat()
	if err != nil {
		return ownedUnpackFile{}, cleanupProven, fmt.Errorf("inspect extraction destination %s: %w", entry.outPath, err)
	}
	owned.info = targetInfo

	stage, err := root.Open(entry.stageName)
	if err != nil {
		return ownedUnpackFile{}, cleanupProven, fmt.Errorf("open stage for %s: %w", entry.outPath, err)
	}
	stageInfo, err := stage.Stat()
	if err != nil || !os.SameFile(entry.info, stageInfo) {
		var stageCloseErr error
		if closeErr := stage.Close(); closeErr != nil {
			stageCloseErr = fmt.Errorf("close stage for %s after inspect failure: %w", entry.outPath, closeErr)
		}
		if err != nil {
			return ownedUnpackFile{}, cleanupProven, errors.Join(
				fmt.Errorf("inspect stage for %s: %w", entry.outPath, err),
				stageCloseErr,
			)
		}
		return ownedUnpackFile{}, cleanupProven, errors.Join(
			fmt.Errorf("stage path changed before publishing %s", entry.outPath),
			stageCloseErr,
		)
	}
	if _, err := unpackCopyFn(target, stage); err != nil {
		var stageCloseErr error
		if closeErr := stage.Close(); closeErr != nil {
			stageCloseErr = fmt.Errorf("close stage for %s after copy failure: %w", entry.outPath, closeErr)
		}
		return ownedUnpackFile{}, cleanupProven, errors.Join(
			fmt.Errorf("copy staged output %s: %w", entry.outPath, err),
			stageCloseErr,
		)
	}
	if err := stage.Close(); err != nil {
		return ownedUnpackFile{}, cleanupProven, fmt.Errorf("close stage for %s: %w", entry.outPath, err)
	}
	if err := target.Sync(); err != nil {
		return ownedUnpackFile{}, cleanupProven, fmt.Errorf("sync extraction destination %s: %w", entry.outPath, err)
	}
	if err := target.Close(); err != nil {
		targetOpen = false
		return ownedUnpackFile{}, cleanupProven, fmt.Errorf("close extraction destination %s: %w", entry.outPath, err)
	}
	targetOpen = false
	currentTarget, err := root.Lstat(entry.targetName)
	if err != nil || !currentTarget.Mode().IsRegular() || !os.SameFile(owned.info, currentTarget) {
		if err != nil {
			return ownedUnpackFile{}, cleanupProven, fmt.Errorf("inspect completed extraction destination %s: %w", entry.outPath, err)
		}
		return ownedUnpackFile{}, cleanupProven, fmt.Errorf("extraction destination changed for %s", entry.outPath)
	}
	if err := root.Remove(entry.stageName); err != nil {
		return ownedUnpackFile{}, cleanupProven, fmt.Errorf("remove stage for %s: %w", entry.outPath, err)
	}
	entry.stageName = ""
	keepTarget = true
	cleanupProven = true
	return owned, cleanupProven, nil
}

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

func prepareExtractionPath(
	root *os.Root,
	extractDir, normalizedName string,
	isDir bool,
	createdDirs *ownedUnpackDirs,
) (string, string, error) {
	relPath := filepath.Clean(normalizedName)
	if !filepath.IsLocal(relPath) {
		return "", "", errors.New("potentially malicious zip item path")
	}

	outPath := filepath.Join(extractDir, relPath)
	if !isValidExtractionPath(outPath, extractDir) {
		return "", "", errors.New("potentially malicious zip item path")
	}

	current := ""
	parts := strings.Split(relPath, string(filepath.Separator))
	for i, part := range parts {
		next := filepath.Join(current, part)
		isLast := i == len(parts)-1

		info, err := root.Lstat(next)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if !isLast || isDir {
				if err := root.Mkdir(next, 0o700); err != nil {
					return "", "", fmt.Errorf("create directory %s: %w", filepath.Join(extractDir, next), err)
				}
				info, err := root.Lstat(next)
				if err != nil {
					return "", "", fmt.Errorf(
						"inspect created directory %s: %w",
						filepath.Join(extractDir, next),
						err,
					)
				}
				if !info.IsDir() {
					return "", "", fmt.Errorf(
						"created extraction path is not a directory: %s",
						filepath.Join(extractDir, next),
					)
				}
				createdDirs.record(ownedUnpackDir{
					targetName: next,
					outPath:    filepath.Join(extractDir, next),
					info:       info,
				})
			}
		case err != nil:
			return "", "", err
		case info.Mode()&os.ModeSymlink != 0:
			// SEC-03 invariant (pinned by TestUnpackSymlinkEscape): every path
			// component is Lstat'd and any symlink rejected before a write, so a
			// symlinked intermediate dir cannot be followed out of the extraction
			// root. In-archive symlink entries never reach here as symlinks — they
			// are materialized as regular files (target string = body).
			return "", "", fmt.Errorf("refusing to follow symlink during extraction: %s", filepath.Join(extractDir, next))
		case !info.IsDir() && (!isLast || isDir):
			return "", "", fmt.Errorf("path exists as file: %s", filepath.Join(extractDir, next))
		case isLast && !isDir && info.IsDir():
			return "", "", fmt.Errorf("path exists as directory: %s", filepath.Join(extractDir, next))
		}

		current = next
	}

	return relPath, outPath, nil
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

func syncModifiedUnpackDirectories(
	root *os.Root,
	stagedEntries []stagedUnpackEntry,
	createdDirs *ownedUnpackDirs,
) (error, error) {
	modified := map[string]struct{}{filepath.Clean("."): {}}
	for _, entry := range stagedEntries {
		modified[filepath.Clean(filepath.Dir(entry.targetName))] = struct{}{}
	}
	if createdDirs != nil {
		for _, directory := range createdDirs.entries {
			modified[filepath.Clean(filepath.Dir(directory.targetName))] = struct{}{}
		}
	}

	directories := make([]string, 0, len(modified))
	for directory := range modified {
		directories = append(directories, directory)
	}
	slices.SortFunc(directories, func(left, right string) int {
		leftDepth := strings.Count(left, string(filepath.Separator))
		rightDepth := strings.Count(right, string(filepath.Separator))
		if left == "." {
			leftDepth = -1
		}
		if right == "." {
			rightDepth = -1
		}
		if leftDepth > rightDepth {
			return -1
		}
		if leftDepth < rightDepth {
			return 1
		}
		return strings.Compare(left, right)
	})

	var durabilityErrs, cleanupErrs []error
	for _, directory := range directories {
		handle, err := root.Open(directory)
		if err != nil {
			durabilityErrs = append(durabilityErrs, fmt.Errorf("open modified extraction directory: %w", err))
			continue
		}
		info, statErr := handle.Stat()
		if statErr != nil {
			durabilityErrs = append(durabilityErrs, fmt.Errorf("inspect modified extraction directory: %w", statErr))
		} else if !info.IsDir() {
			durabilityErrs = append(durabilityErrs, errors.New("modified extraction directory changed before sync"))
		} else if syncErr := unpackDirectorySyncFn(handle); syncErr != nil {
			durabilityErrs = append(durabilityErrs, fmt.Errorf("sync modified extraction directory: %w", syncErr))
		}
		if closeErr := unpackDirectoryCloseFn(handle); closeErr != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("close modified extraction directory: %w", closeErr))
		}
	}
	return errors.Join(durabilityErrs...), errors.Join(cleanupErrs...)
}

// Unpack extracts a zip archive to the specified directory.
func Unpack(opts UnpackOptions) error {
	state := UnpackStateNotPublished
	err := unpack(opts, false, &state)
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
	var reader *zip.Reader
	var closeReader func() error
	var err error
	if opts.ZipFile != nil {
		info, err := opts.ZipFile.Stat()
		if err != nil {
			return fmt.Errorf("inspect zip: %w", err)
		}
		reader, err = zip.NewReader(opts.ZipFile, info.Size())
		if err != nil {
			return fmt.Errorf("open zip: %w", err)
		}
	} else {
		readCloser, err := zip.OpenReader(opts.ZipPath)
		if err != nil {
			return fmt.Errorf("open zip: %w", err)
		}
		reader = &readCloser.Reader
		closeReader = readCloser.Close
	}
	defer func() {
		if closeReader != nil {
			if err := closeReader(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close zip reader: %w", err))
			}
		}
	}()

	// Calculate total uncompressed size with overflow protection
	var totalSize int64
	for _, f := range reader.File {
		size, ok := util.SafeUint64ToInt64(f.UncompressedSize64)
		if !ok {
			return fmt.Errorf("file %s: uncompressed size exceeds int64 max", f.Name)
		}
		if totalSize > math.MaxInt64-size {
			return errors.New("total uncompressed size exceeds int64 max")
		}
		totalSize += size
	}

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
	defer func() {
		if closeExtractRoot {
			if err := unpackCloseRootFn(extractRoot); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close extraction root: %w", err))
				if classifyPublication {
					retErr = errors.Join(retErr, ErrUnpackCleanupIncomplete)
				}
			}
		}
	}()
	extractRootInfo, err := extractRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect extraction root %s: %w", extractDir, err)
	}
	if opts.ExpectedExtractRoot != nil && !os.SameFile(opts.ExpectedExtractRoot, extractRootInfo) {
		return errors.New("extraction root does not match the reserved output directory")
	}
	if err := verifyExtractionRootPath(extractDir, extractRootInfo); err != nil {
		return err
	}
	createdDirs := &ownedUnpackDirs{}
	keepCreatedDirs := false
	defer func() {
		if !keepCreatedDirs {
			if cleanupErr := createdDirs.cleanup(extractRoot); cleanupErr != nil {
				retErr = errors.Join(retErr, cleanupErr)
				if classifyPublication {
					retErr = errors.Join(retErr, ErrUnpackCleanupIncomplete)
				}
			}
		}
	}()

	// First pass: create all directories and reject duplicate or existing
	// destinations before extracting any data.
	seenTargets := make(map[string]struct{})
	for _, f := range reader.File {
		// Normalize and validate path to prevent zip slip attacks
		canonicalName, pathErr := ParseZIPEntryPath(
			f.Name,
			f.FileInfo().IsDir(),
			ZIPPathExtractionCompatible,
		)
		if pathErr != nil {
			return errors.New("potentially malicious zip item path")
		}
		normalizedName := filepath.FromSlash(canonicalName)
		targetName, outPath, err := prepareExtractionPath(
			extractRoot,
			extractDir,
			normalizedName,
			f.FileInfo().IsDir(),
			createdDirs,
		)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			continue
		}
		if _, exists := seenTargets[targetName]; exists {
			return fmt.Errorf("duplicate extraction destination in archive: %s", outPath)
		}
		seenTargets[targetName] = struct{}{}
		if _, err := extractRoot.Lstat(targetName); err == nil {
			return fmt.Errorf("extraction destination already exists: %s: %w", outPath, os.ErrExist)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect extraction destination %s: %w", outPath, err)
		}
	}

	probe := opts.AvailableSpace
	if probe == nil {
		probe = diskspace.Available
	}
	if available, err := probe(extractDir); err == nil && totalSize > available {
		return fmt.Errorf("insufficient disk space for extraction: need %d bytes, have %d", totalSize, available)
	}
	if err := verifyExtractionRootPath(extractDir, extractRootInfo); err != nil {
		return err
	}

	// Second pass: extract files
	// Note: File handles are closed manually at the end of each iteration (not using defer)
	// to prevent file descriptor exhaustion when extracting large archives with many files.
	// Using defer here would accumulate all file handles until function exit.
	var done int64
	startTime := time.Now()
	stagedEntries := make([]stagedUnpackEntry, 0, len(reader.File))
	defer func() {
		for i := range stagedEntries {
			cleanupProven, cleanupErr := stagedEntries[i].cleanup(extractRoot)
			if cleanupErr != nil {
				retErr = errors.Join(retErr, cleanupErr)
			}
			if classifyPublication && (!cleanupProven || cleanupErr != nil) {
				retErr = errors.Join(retErr, ErrUnpackCleanupIncomplete)
				if !cleanupProven && *state == UnpackStateNotPublished {
					*state = UnpackStatePublicationIndeterminate
				}
			}
		}
	}()

	for i, f := range reader.File {
		// Check for cancellation between files
		if opts.Cancel != nil && opts.Cancel() {
			return errors.New("operation cancelled")
		}

		if f.FileInfo().IsDir() {
			continue
		}

		// Revalidate before staging. The first pass creates directories and
		// sizes the extraction; the stage and final rename both go through
		// os.Root so their paths remain root-confined.
		canonicalName, pathErr := ParseZIPEntryPath(
			f.Name,
			false,
			ZIPPathExtractionCompatible,
		)
		if pathErr != nil {
			return errors.New("potentially malicious zip item path")
		}
		normalizedName := filepath.FromSlash(canonicalName)
		targetName, outPath, err := prepareExtractionPath(
			extractRoot,
			extractDir,
			normalizedName,
			false,
			createdDirs,
		)
		if err != nil {
			return err
		}
		if err := verifyExtractionRootPath(extractDir, extractRootInfo); err != nil {
			return err
		}

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
		stageInfo, err := stageFile.Stat()
		if err != nil {
			_ = fileInArchive.Close()
			_ = stageFile.Close()
			return fmt.Errorf("inspect stage for %s: %w", outPath, err)
		}
		stagedEntries = append(stagedEntries, stagedUnpackEntry{
			file:       stageFile,
			stageName:  stageName,
			targetName: targetName,
			outPath:    outPath,
			info:       stageInfo,
		})
		stagedEntry := &stagedEntries[len(stagedEntries)-1]

		// Decompression bomb protection
		maxBytes, ok := ZIPDecompressionLimit(f.CompressedSize64)
		if !ok {
			_ = fileInArchive.Close()
			return fmt.Errorf("file %s: compressed size exceeds int64 max", f.Name)
		}

		var written int64
		buf := make([]byte, util.MiB)
		for {
			// Check for cancellation during file extraction
			if opts.Cancel != nil && opts.Cancel() {
				_ = fileInArchive.Close()
				return errors.New("operation cancelled")
			}

			n, readErr := fileInArchive.Read(buf)
			if n > 0 {
				written += int64(n)
				if written > maxBytes {
					_ = fileInArchive.Close()
					return fmt.Errorf("decompression limit exceeded: %s (ratio >%d:1)",
						f.Name, util.MaxDecompressRatio)
				}

				if _, err := stageFile.Write(buf[:n]); err != nil {
					_ = fileInArchive.Close()
					return fmt.Errorf("write %s: %w", outPath, err)
				}

				done += int64(n)
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
		currentStage, err := extractRoot.Lstat(stageName)
		if err != nil {
			return fmt.Errorf("inspect stage for %s before publish: %w", outPath, err)
		}
		if !currentStage.Mode().IsRegular() || !os.SameFile(stageInfo, currentStage) {
			return fmt.Errorf("stage path changed before publishing %s", outPath)
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

	// Do not publish any destination until every archive entry has been fully
	// decompressed and checksum-verified. Existing destinations are never
	// replaced: a collision is an error, including a race after preflight.
	if err := verifyExtractionRootPath(extractDir, extractRootInfo); err != nil {
		return err
	}
	for i := range stagedEntries {
		entry := &stagedEntries[i]
		current, err := extractRoot.Lstat(entry.stageName)
		if err != nil {
			return fmt.Errorf("inspect stage for %s before publish: %w", entry.outPath, err)
		}
		if !current.Mode().IsRegular() || !os.SameFile(entry.info, current) {
			return fmt.Errorf("stage path changed before publishing %s", entry.outPath)
		}
	}
	published := make([]ownedUnpackFile, 0, len(stagedEntries))
	for i := range stagedEntries {
		entry := &stagedEntries[i]
		owned, cleanupProven, err := publishStagedUnpackEntry(extractRoot, entry)
		if err != nil {
			rollbackErrors := []error{err}
			cleanupIncomplete := !cleanupProven
			for _, output := range published {
				if rollbackErr := unpackRemoveOwnedFn(output, extractRoot); rollbackErr != nil {
					rollbackErrors = append(rollbackErrors, rollbackErr)
					cleanupIncomplete = true
				}
			}
			if classifyPublication && cleanupIncomplete {
				*state = UnpackStatePublicationIndeterminate
				rollbackErrors = append(rollbackErrors, ErrUnpackCleanupIncomplete)
			}
			return errors.Join(rollbackErrors...)
		}
		published = append(published, owned)
	}

	keepCreatedDirs = true
	if !classifyPublication {
		return nil
	}

	*state = UnpackStatePublishedDurabilityUncertain
	durabilityErr, cleanupErr := syncModifiedUnpackDirectories(extractRoot, stagedEntries, createdDirs)
	if durabilityErr == nil {
		*state = UnpackStatePublishedDurable
	} else {
		retErr = errors.Join(retErr, durabilityErr)
	}
	if cleanupErr != nil {
		retErr = errors.Join(retErr, cleanupErr, ErrUnpackCleanupIncomplete)
	}
	return
}
