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

type stagedUnpackEntry struct {
	file       *os.File
	stageName  string
	targetName string
	outPath    string
	info       os.FileInfo
}

func (entry *stagedUnpackEntry) cleanup(root *os.Root) error {
	if entry == nil || root == nil || entry.stageName == "" {
		return nil
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
		entry.stageName = ""
		return closeErr
	}
	if err != nil {
		return errors.Join(closeErr, fmt.Errorf("inspect staged extraction output %s during cleanup: %w", entry.outPath, err))
	}
	if !current.Mode().IsRegular() || !os.SameFile(entry.info, current) {
		entry.stageName = ""
		return closeErr
	}
	if err := root.Remove(entry.stageName); err != nil {
		return errors.Join(closeErr, fmt.Errorf("remove staged extraction output %s: %w", entry.outPath, err))
	}
	entry.stageName = ""
	return closeErr
}

type ownedUnpackFile struct {
	targetName string
	outPath    string
	info       os.FileInfo
}

func (owned ownedUnpackFile) remove(root *os.Root) error {
	current, err := root.Lstat(owned.targetName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
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
	unpackLinkFn        = (*os.Root).Link
	unpackCopyFn        = io.Copy
	unpackStageSyncFn   = (*os.File).Sync
	unpackRemoveOwnedFn = ownedUnpackFile.remove
)

func publishStagedUnpackEntry(root *os.Root, entry *stagedUnpackEntry) (published ownedUnpackFile, retErr error) {
	currentStage, err := root.Lstat(entry.stageName)
	if err != nil {
		return ownedUnpackFile{}, fmt.Errorf("inspect stage for %s before publish: %w", entry.outPath, err)
	}
	if !currentStage.Mode().IsRegular() || !os.SameFile(entry.info, currentStage) {
		return ownedUnpackFile{}, fmt.Errorf("stage path changed before publishing %s", entry.outPath)
	}

	// A hard link publishes the complete staged inode atomically and fails if
	// the destination exists. Filesystems without hard-link support fall back
	// to an exclusive copy, which retains the same no-clobber contract.
	if err := unpackLinkFn(root, entry.stageName, entry.targetName); err == nil {
		owned := ownedUnpackFile{targetName: entry.targetName, outPath: entry.outPath, info: entry.info}
		targetInfo, statErr := root.Lstat(entry.targetName)
		if statErr != nil {
			return ownedUnpackFile{}, errors.Join(
				fmt.Errorf("inspect published %s: %w", entry.outPath, statErr),
				unpackRemoveOwnedFn(owned, root),
			)
		}
		if !targetInfo.Mode().IsRegular() || !os.SameFile(entry.info, targetInfo) {
			return ownedUnpackFile{}, errors.Join(
				fmt.Errorf("published path changed for %s", entry.outPath),
				unpackRemoveOwnedFn(owned, root),
			)
		}
		owned.info = targetInfo
		if err := root.Remove(entry.stageName); err != nil {
			return ownedUnpackFile{}, errors.Join(
				fmt.Errorf("remove stage for %s: %w", entry.outPath, err),
				unpackRemoveOwnedFn(owned, root),
			)
		}
		entry.stageName = ""
		return owned, nil
	}

	if _, err := root.Lstat(entry.targetName); err == nil {
		return ownedUnpackFile{}, fmt.Errorf("extraction destination already exists: %s: %w", entry.outPath, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ownedUnpackFile{}, fmt.Errorf("inspect extraction destination %s: %w", entry.outPath, err)
	}

	target, err := root.OpenFile(entry.targetName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ownedUnpackFile{}, fmt.Errorf("create extraction destination %s: %w", entry.outPath, err)
	}
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
		retErr = errors.Join(retErr, unpackRemoveOwnedFn(owned, root))
	}()

	targetInfo, err := target.Stat()
	if err != nil {
		return ownedUnpackFile{}, fmt.Errorf("inspect extraction destination %s: %w", entry.outPath, err)
	}
	owned.info = targetInfo

	stage, err := root.Open(entry.stageName)
	if err != nil {
		return ownedUnpackFile{}, fmt.Errorf("open stage for %s: %w", entry.outPath, err)
	}
	stageInfo, err := stage.Stat()
	if err != nil || !os.SameFile(entry.info, stageInfo) {
		var stageCloseErr error
		if closeErr := stage.Close(); closeErr != nil {
			stageCloseErr = fmt.Errorf("close stage for %s after inspect failure: %w", entry.outPath, closeErr)
		}
		if err != nil {
			return ownedUnpackFile{}, errors.Join(
				fmt.Errorf("inspect stage for %s: %w", entry.outPath, err),
				stageCloseErr,
			)
		}
		return ownedUnpackFile{}, errors.Join(
			fmt.Errorf("stage path changed before publishing %s", entry.outPath),
			stageCloseErr,
		)
	}
	if _, err := unpackCopyFn(target, stage); err != nil {
		var stageCloseErr error
		if closeErr := stage.Close(); closeErr != nil {
			stageCloseErr = fmt.Errorf("close stage for %s after copy failure: %w", entry.outPath, closeErr)
		}
		return ownedUnpackFile{}, errors.Join(
			fmt.Errorf("copy staged output %s: %w", entry.outPath, err),
			stageCloseErr,
		)
	}
	if err := stage.Close(); err != nil {
		return ownedUnpackFile{}, fmt.Errorf("close stage for %s: %w", entry.outPath, err)
	}
	if err := target.Sync(); err != nil {
		return ownedUnpackFile{}, fmt.Errorf("sync extraction destination %s: %w", entry.outPath, err)
	}
	if err := target.Close(); err != nil {
		targetOpen = false
		return ownedUnpackFile{}, fmt.Errorf("close extraction destination %s: %w", entry.outPath, err)
	}
	targetOpen = false
	currentTarget, err := root.Lstat(entry.targetName)
	if err != nil || !currentTarget.Mode().IsRegular() || !os.SameFile(owned.info, currentTarget) {
		if err != nil {
			return ownedUnpackFile{}, fmt.Errorf("inspect completed extraction destination %s: %w", entry.outPath, err)
		}
		return ownedUnpackFile{}, fmt.Errorf("extraction destination changed for %s", entry.outPath)
	}
	if err := root.Remove(entry.stageName); err != nil {
		return ownedUnpackFile{}, fmt.Errorf("remove stage for %s: %w", entry.outPath, err)
	}
	entry.stageName = ""
	keepTarget = true
	return owned, nil
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

// Unpack extracts a zip archive to the specified directory.
func Unpack(opts UnpackOptions) (retErr error) {
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
		createExtractRoot := !opts.SameLevel && opts.ExpectedExtractRoot == nil
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
			if err := extractRoot.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close extraction root: %w", err))
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
			retErr = errors.Join(retErr, createdDirs.cleanup(extractRoot))
		}
	}()

	// First pass: create all directories and reject duplicate or existing
	// destinations before extracting any data.
	seenTargets := make(map[string]struct{})
	for _, f := range reader.File {
		// Normalize and validate path to prevent zip slip attacks
		if hasUnsafeWindowsTrimTraversalComponent(f.Name) {
			return errors.New("potentially malicious zip item path")
		}
		normalizedName := normalizeZipPath(f.Name)
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
			if err := stagedEntries[i].cleanup(extractRoot); err != nil {
				retErr = errors.Join(retErr, err)
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
		if hasUnsafeWindowsTrimTraversalComponent(f.Name) {
			return errors.New("potentially malicious zip item path")
		}
		normalizedName := normalizeZipPath(f.Name)
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
		compressedSize, ok := util.SafeUint64ToInt64(f.CompressedSize64)
		if !ok {
			_ = fileInArchive.Close()
			return fmt.Errorf("file %s: compressed size exceeds int64 max", f.Name)
		}
		// Overflow-safe ratio calculation: check before multiply
		var maxBytes int64
		if compressedSize > math.MaxInt64/util.MaxDecompressRatio {
			maxBytes = math.MaxInt64 // allow: ratio can't overflow, trust content
		} else {
			maxBytes = compressedSize * util.MaxDecompressRatio
		}
		// Floor for small compressed files to avoid false positives
		if maxBytes < util.MiB {
			maxBytes = util.MiB
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
		owned, err := publishStagedUnpackEntry(extractRoot, entry)
		if err != nil {
			rollbackErrors := []error{err}
			for _, output := range published {
				if rollbackErr := output.remove(extractRoot); rollbackErr != nil {
					rollbackErrors = append(rollbackErrors, rollbackErr)
				}
			}
			return errors.Join(rollbackErrors...)
		}
		published = append(published, owned)
	}

	keepCreatedDirs = true
	return nil
}
