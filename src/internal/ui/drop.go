package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
)

const (
	dropScanBatchSize     = 128
	dropScanFlushInterval = 50 * time.Millisecond
)

type scannedFile struct {
	path string
	size int64
}

type scannedFileBatch func(context.Context, []scannedFile) error

type folderScanJob struct {
	roots       []string
	fileCount   int
	folderCount int
	generation  uint64
}

var errFolderScanSuperseded = errors.New("folder scan superseded")

var startupPathStat = os.Stat

var (
	previewDroppedHeader    = previewHeader
	openDroppedPCVInput     = volume.OpenLegacyPCVInput
	isDroppedVolumeDeniable = volume.IsDeniableFile
)

func isPCV3UnavailableError(err error) bool {
	if errors.Is(err, pcv3.ErrReaderUnavailable) {
		return true
	}
	var failure pcv3.Failure
	return errors.As(err, &failure) && failure.Outcome() != pcv3.OutcomeOperationFailed
}

func dropPromptLabel() string {
	return tr("drop.prompt", "Drop files and folders into this window")
}

func startupPathAccessStatus() string {
	return tr("startup_path.access_failed", "Failed to access startup path")
}

func startupPathPartialAccessStatus() string {
	return tr("startup_path.partial_access_failed", "Some startup paths could not be accessed")
}

func selectionScanningLabel(size int64) string {
	return tr("selection.scanning_files", "Scanning files... ({{.Size}})", map[string]any{
		"Size": util.Sizeify(size),
	})
}

func selectionWithSize(label string, size int64) string {
	return tr("selection.with_size", "{{.Label}} ({{.Size}})", map[string]any{
		"Label": label,
		"Size":  util.Sizeify(size),
	})
}

func selectedFilesLabel(count int) string {
	fallback := "{{.Count}} files"
	if count == 1 {
		fallback = "{{.Count}} file"
	}
	return trn("selection.files", fallback, count, map[string]any{
		"Count": count,
	})
}

func selectedFoldersLabel(count int) string {
	fallback := "{{.Count}} folders"
	if count == 1 {
		fallback = "{{.Count}} folder"
	}
	return trn("selection.folders", fallback, count, map[string]any{
		"Count": count,
	})
}

func selectionSummary(files, folders int) string {
	switch {
	case folders == 0:
		return selectedFilesLabel(files)
	case files == 0:
		return selectedFoldersLabel(folders)
	default:
		return tr("selection.mixed", "{{.Files}} and {{.Folders}}", map[string]any{
			"Files":   selectedFilesLabel(files),
			"Folders": selectedFoldersLabel(folders),
		})
	}
}

func isIgnoredStartupArg(path string) bool {
	return path == "" || strings.HasPrefix(path, "-psn_")
}

func isDecryptVolumePath(path string) bool {
	if fileops.IsSplitChunkPath(path) {
		return true
	}

	return strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".pcv")
}

func trimPCVSuffix(path string) string {
	if !strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".pcv") {
		return path
	}

	return path[:len(path)-4]
}

func collectStartupPaths(paths []string, statFn func(string) (os.FileInfo, error)) ([]string, error) {
	validPaths := make([]string, 0, len(paths))
	var firstErr error

	for _, path := range paths {
		if isIgnoredStartupArg(path) {
			continue
		}

		if _, err := statFn(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("startup path %q: %w", path, err)
			}
			continue
		}

		validPaths = append(validPaths, path)
	}

	return validPaths, firstErr
}

// applyStartupPaths reuses drag-and-drop handling for files passed at GUI startup.
func (a *App) applyStartupPaths(paths []string) {
	validPaths, err := collectStartupPaths(paths, startupPathStat)
	if len(validPaths) == 0 {
		if err != nil {
			a.State.SetStatusMessage(app.StatusStartupPathAccessFailed, util.RED, app.StatusArgs{})
			a.refreshUI()
		}
		return
	}

	a.onDrop(validPaths)
	if err != nil {
		a.State.SetStatusMessage(app.StatusStartupPathPartialAccessFailed, util.YELLOW, app.StatusArgs{})
		a.refreshUI()
	}
}

func (a *App) applyFolderWalkError() {
	a.State.SetScanning(false)
	a.resetUI()
	a.State.SetStatusMessage(app.StatusDropFailedWalk, util.RED, app.StatusArgs{})
	a.refreshUI()
}

func (a *App) appendScannedFiles(files []scannedFile) {
	if len(files) == 0 {
		return
	}

	for _, file := range files {
		a.State.AllFiles = append(a.State.AllFiles, file.path)
		a.State.CompressTotal += file.size
		a.State.RequiredFreeSpace += file.size
	}
	a.State.SetInputScanning(a.State.CompressTotal)
	a.refreshUI()
}

func scanFolders(ctx context.Context, roots []string, emit scannedFileBatch) error {
	pendingFiles := make([]scannedFile, 0, dropScanBatchSize)
	lastFlush := time.Now()

	flushPendingFiles := func() error {
		if len(pendingFiles) == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		batch := append([]scannedFile(nil), pendingFiles...)
		if err := emit(ctx, batch); err != nil {
			return err
		}
		pendingFiles = pendingFiles[:0]
		lastFlush = time.Now()
		return nil
	}

	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				return walkErr
			}
			if !info.Mode().IsRegular() {
				return nil
			}

			pendingFiles = append(pendingFiles, scannedFile{path: path, size: info.Size()})
			if len(pendingFiles) >= dropScanBatchSize || time.Since(lastFlush) >= dropScanFlushInterval {
				return flushPendingFiles()
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return flushPendingFiles()
}

func (a *App) folderScanCanApply(ctx context.Context, generation uint64) bool {
	return ctx.Err() == nil && !a.workers.isStopping() && a.folderScanGeneration == generation
}

func (a *App) scannedFileEmitter(generation uint64) scannedFileBatch {
	return func(ctx context.Context, batch []scannedFile) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		applied := false
		fyne.DoAndWait(func() {
			if !a.folderScanCanApply(ctx, generation) {
				return
			}
			a.appendScannedFiles(batch)
			applied = true
		})
		if applied {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return errFolderScanSuperseded
	}
}

func (a *App) runFolderScan(ctx context.Context, job folderScanJob, emit scannedFileBatch) {
	err := scanFolders(ctx, job.roots, emit)
	fyne.DoAndWait(func() {
		if !a.folderScanCanApply(ctx, job.generation) {
			return
		}

		switch {
		case err == nil:
			a.State.SetInputSelection(job.fileCount, job.folderCount, a.State.CompressTotal, true)
			a.State.SetScanning(false)
			a.refreshUI()
			a.refreshAdvanced()
		case errors.Is(err, context.Canceled), errors.Is(err, errFolderScanSuperseded):
			return
		default:
			a.applyFolderWalkError()
		}
	})
}

// onDrop handles files and folders dropped onto the window.
func (a *App) onDrop(names []string) {
	if a.mobileImportActive {
		return
	}

	// If keyfile modal is open, handle as keyfiles
	if a.State.ShowKeyfile {
		a.handleKeyfileDrop(names)
		return
	}

	// Prevent race condition: ignore new drops while scanning or working
	// This prevents multiple goroutines from simultaneously modifying AllFiles
	if a.State.IsScanning() || a.State.IsWorking() {
		return
	}

	a.applyDropSelection(names)
}

// applyDropSelection applies one already-accepted UI selection. It is UI-only.
// Recursive processing uses it inside its DoAndWait transaction so it bypasses
// only onDrop's user-input busy guard and never re-enters the public handler.
func (a *App) applyDropSelection(names []string) bool {
	reservation, ok := a.workers.reserve()
	if !ok {
		return false
	}
	workerLaunched := false
	defer func() {
		if !workerLaunched {
			reservation.release()
		}
	}()

	a.folderScanGeneration++
	generation := a.folderScanGeneration
	a.State.SetScanning(true)
	a.State.CompressDone = 0
	a.State.CompressTotal = 0
	// Reset UI synchronously - onDrop runs on UI thread, so fyne.Do() is not needed
	// Using fyne.Do() here would cause a race condition where Mode gets cleared
	// AFTER it's set below, because fyne.Do() queues the call for later execution
	a.resetUI()

	// One item dropped
	if len(names) == 1 {
		stat, err := os.Stat(names[0])
		if err != nil {
			a.State.SetStatusMessage(app.StatusDropFailedStatItem, util.RED, app.StatusArgs{})
			a.State.SetScanning(false)
			a.refreshUI()
			return false
		}

		// A folder was dropped
		if stat.IsDir() {
			a.State.Mode = "encrypt"
			a.State.SetInputSelection(0, 1, a.State.CompressTotal, false)
			a.State.SetStartAction(app.StartActionZipAndEncrypt)
			a.State.OnlyFolders = append(a.State.OnlyFolders, names[0])
			a.State.InputFile = filepath.Join(filepath.Dir(names[0]),
				"encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
			a.State.OutputFile = a.State.InputFile + ".pcv"
		} else {
			// A file was dropped
			a.State.RequiredFreeSpace = stat.Size()
			if !stat.Mode().IsRegular() {
				a.State.SetScanning(false)
				a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
				a.refreshAdvanced()
				return false
			}

			// Is the file a part of a split volume?
			isSplit := fileops.IsSplitChunkPath(names[0])
			routedInput, err := openDroppedPCVInput(names[0], isSplit)
			if err != nil {
				if isPCV3UnavailableError(err) {
					a.State.SetPCVUnavailable(names[0], stat.Size())
					a.refreshAdvanced()
					a.refreshUI()
					return true
				}
				a.State.SetScanning(false)
				a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
				a.refreshAdvanced()
				return false
			}
			defer func() { _ = routedInput.Close() }()

			// Decide if encrypting or decrypting
			if isDecryptVolumePath(names[0]) {
				a.handleDecryptDrop(names[0], isSplit, routedInput)
				// For decrypt, no folder scanning needed
				a.State.SetScanning(false)
				a.refreshUI()
				a.refreshAdvanced()
				return true
			} else {
				// Encrypting a single file
				a.State.Mode = "encrypt"
				a.State.InputFile = names[0]
				a.State.SetInputSelection(1, 0, a.State.CompressTotal, false)
				a.State.SetStartAction(app.StartActionEncrypt)
				// Set output file based on compress state
				if a.State.Compress {
					a.State.OutputFile = names[0] + ".zip.pcv"
				} else {
					a.State.OutputFile = names[0] + ".pcv"
				}
				a.State.OnlyFiles = append(a.State.OnlyFiles, names[0])
				a.State.AllFiles = append(a.State.AllFiles, names[0])
				// Add to compressTotal for size display (like original line 1077)
				a.State.CompressTotal += stat.Size()
			}
		}
	} else if !a.handleMultipleDrop(names) {
		return false
	}

	if len(a.State.OnlyFolders) == 0 {
		a.State.SetInputSelection(len(a.State.OnlyFiles), len(a.State.OnlyFolders), a.State.CompressTotal, true)
		a.State.SetScanning(false)
		a.refreshUI()
		a.refreshAdvanced()
		return true
	}

	job := folderScanJob{
		roots:       append([]string(nil), a.State.OnlyFolders...),
		fileCount:   len(a.State.OnlyFiles),
		folderCount: len(a.State.OnlyFolders),
		generation:  generation,
	}
	emit := a.scannedFileEmitter(generation)
	workerLaunched = true
	reservation.launch(func(ctx context.Context) {
		a.runFolderScan(ctx, job, emit)
	})
	return true
}

func (a *App) applyDropError(status string, closeKeyfileModal bool) {
	if closeKeyfileModal && a.keyfileModal != nil {
		a.keyfileModal.Hide()
	}
	a.resetUI()
	a.State.SetStatus(status, util.RED)
	a.refreshUI()
}

func (a *App) applyDropStatusMessage(kind app.StatusKind, closeKeyfileModal bool) {
	if closeKeyfileModal && a.keyfileModal != nil {
		a.keyfileModal.Hide()
	}
	a.resetUI()
	a.State.SetStatusMessage(kind, util.RED, app.StatusArgs{})
	a.refreshUI()
}

// handleDecryptDrop handles a .pcv file being dropped for decryption.
func (a *App) handleDecryptDrop(name string, isSplit bool, fin *os.File) {
	a.State.Mode = "decrypt"
	a.State.SetInputDecryptVolume()
	a.State.SetStartAction(app.StartActionDecrypt)
	a.State.CommentsPreviewState = app.CommentsPreviewUnavailable

	// Add the file to onlyFiles (required for UI enable/disable logic)
	a.State.OnlyFiles = append(a.State.OnlyFiles, name)

	// Get the correct input and output filenames
	if isSplit {
		basePath, ok := fileops.SplitChunkBase(name)
		if !ok {
			a.applyDropStatusMessage(app.StatusDropFailedSplitPath, false)
			return
		}
		name = basePath
		a.State.InputFile = name
		a.State.OutputFile = trimPCVSuffix(name)
		a.State.Recombine = true

		// Find out the number of split chunks
		totalFiles := 0
		for {
			stat, err := os.Stat(fmt.Sprintf("%s.%d", a.State.InputFile, totalFiles))
			if err != nil {
				break
			}
			totalFiles++
			a.State.CompressTotal += stat.Size()
		}
		a.State.RequiredFreeSpace = a.State.CompressTotal
	} else {
		a.State.InputFile = name
		a.State.OutputFile = trimPCVSuffix(name)
	}

	if fin == nil {
		a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
		return
	}

	// Parse the header through the single validated parser (SEC-01/UI-01/D-01).
	// previewHeader is pure + UI-free; it shares the ^\d{5}$ comment-length
	// guard (+ D-02 bound) and the anchored version regex used at decrypt time,
	// so a crafted comment-length field can never drive an over-allocation here.
	res, err := previewDroppedHeader(fin, a.rsCodecs)
	if err != nil {
		switch {
		case errors.Is(err, header.ErrInvalidVersion):
			// Version field does not match ^v\d\.\d{2}$ — the volume may have a
			// plausible-deniability wrapper (its leading bytes are random).
			a.State.Deniability = true
			a.State.SetStatusMessage(app.StatusDropHeaderMayBeDeniable, util.WHITE, app.StatusArgs{})
			return
		case errors.Is(err, header.ErrInvalidCommentLength):
			// Malformed comment length is a non-comment header-field failure:
			// it must not leave the volume looking startable.
			a.State.SetStatusMessage(app.StatusDropHeaderDamaged, util.RED, app.StatusArgs{})
			return
		default:
			a.State.SetStatusMessage(app.StatusDropHeaderDamaged, util.RED, app.StatusArgs{})
			return
		}
	} else if res.DecodeError != nil && res.NonCommentDecodeError {
		a.State.SetStatusMessage(app.StatusDropHeaderDamaged, util.RED, app.StatusArgs{})
		return
	} else if res.DecodeError != nil && res.CommentDecodeError {
		a.State.Comments = ""
		a.State.CommentsPreviewState = app.CommentsPreviewCorrupted
	} else if res.DecodeError != nil {
		a.State.SetStatusMessage(app.StatusDropHeaderDamaged, util.RED, app.StatusArgs{})
		return
	} else {
		a.State.Comments = res.Header.Comments
		if a.State.Comments == "" {
			a.State.CommentsPreviewState = app.CommentsPreviewUnavailable
		} else {
			a.State.CommentsPreviewState = app.CommentsPreviewNormal
		}
	}

	// Update comments entry if it exists
	if a.commentsEntry != nil {
		snap := a.State.UISnapshot()
		a.commentsEntry.SetText(commentsDisplayText(snap.Mode, snap.Comments, snap.CommentsPreviewState))
	}

	// Parse flags from the decoded header (only when ReadHeader produced one).
	if res != nil {
		flagsStruct := res.Header.Flags
		if flagsStruct.UseKeyfiles {
			a.State.Keyfile = true
		} else {
			a.State.Keyfile = false
		}
		if flagsStruct.KeyfileOrdered {
			a.State.KeyfileOrdered = true
		}
	}

	// Check for deniability
	if isDroppedVolumeDeniable(fin, a.rsCodecs) {
		a.State.Deniability = true
	}
}

// handleMultipleDrop handles multiple files/folders being dropped.
func (a *App) handleMultipleDrop(names []string) bool {
	a.State.Mode = "encrypt"
	a.State.SetStartAction(app.StartActionZipAndEncrypt)
	files, folders := 0, 0

	// Go through each dropped item and add to corresponding slices
	for _, name := range names {
		stat, err := os.Stat(name)
		if err != nil {
			a.State.SetScanning(false)
			a.resetUI()
			a.State.SetStatusMessage(app.StatusDropFailedStatItems, util.RED, app.StatusArgs{})
			a.refreshUI()
			return false
		}
		if stat.IsDir() {
			folders++
			a.State.OnlyFolders = append(a.State.OnlyFolders, name)
		} else {
			files++
			a.State.OnlyFiles = append(a.State.OnlyFiles, name)
			a.State.AllFiles = append(a.State.AllFiles, name)

			a.State.CompressTotal += stat.Size()
			a.State.RequiredFreeSpace += stat.Size()
			a.State.SetInputScanning(a.State.CompressTotal)
		}
	}

	// Update UI with the number of files and folders selected (matches original lines 1111-1125)
	a.State.SetInputSelection(files, folders, a.State.CompressTotal, false)

	// Set the input and output paths (matches original lines 1127-1129)
	a.State.InputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
	a.State.OutputFile = a.State.InputFile + ".pcv"
	return true
}

// handleKeyfileDrop processes dropped keyfiles when the modal is open.
func (a *App) handleKeyfileDrop(paths []string) bool {
	if !a.State.ShowKeyfile {
		return false
	}

	// Add keyfiles, checking for duplicates and access
	for _, path := range paths {
		// Check if duplicate
		duplicate := slices.Contains(a.State.Keyfiles, path)

		// Check if accessible and not a directory
		stat, err := os.Stat(path)
		if err != nil {
			a.State.ShowKeyfile = false
			a.applyDropStatusMessage(app.StatusKeyfileReadAccessDenied, true)
			return true
		}

		if !duplicate && !stat.IsDir() {
			a.State.Keyfiles = append(a.State.Keyfiles, path)
		}
	}

	// Update the keyfile list in the modal and increment modalId like original
	a.State.ModalID++
	a.updateKeyfileList()
	a.refreshUI()
	return true
}
