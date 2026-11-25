package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"
	"context"
	"errors"
	"fmt"
	"io"
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
	path     string
	size     int64
	identity fileops.ZIPInputIdentity
}

type scannedFileBatch func(context.Context, []scannedFile) error

type folderScanJob struct {
	roots       []fileops.ZIPInputCandidate
	fileCount   int
	folderCount int
	generation  uint64
	budget      *fileops.ZIPResourceBudget
	metadata    *fileops.ZIPInputMetadataReservation
}

var errFolderScanSuperseded = errors.New("folder scan superseded")

var startupPathStat = os.Stat

var (
	previewDroppedHeader    = previewHeader
	openDroppedPCVInput     = openDroppedInput
	probeDroppedPCVInput    = pcv3operation.Probe
	isDroppedVolumeDeniable = volume.IsDeniableFile
)

type droppedRouteResult struct {
	preview       pcv3operation.NormalPreview
	source        *os.File
	size          int64
	route         pcv3operation.Route
	err           error
	explicitD1    bool
	encryptOnly   bool
	inputIdentity fileops.ZIPInputIdentity
}

func openDroppedInput(ctx context.Context, path string, recombine bool) (*os.File, error) {
	if !recombine {
		return fileops.OpenExistingNoSymlink(path, os.O_RDONLY)
	}
	base, ok := fileops.SplitChunkBase(path)
	if !ok {
		return nil, errors.New("invalid split input")
	}

	source, err := fileops.OpenRegularReadNoSymlink(base + ".0")
	if !errors.Is(err, os.ErrNotExist) {
		return source, err
	}
	suffix := strings.TrimPrefix(path, base+".")
	index, parseErr := strconv.Atoi(suffix)
	if parseErr == nil && index > 0 && strconv.Itoa(index) == suffix {
		selected, selectedErr := fileops.OpenRegularReadNoSymlink(path)
		if selectedErr != nil {
			return nil, selectedErr
		}
		if closeErr := selected.Close(); closeErr != nil {
			return nil, closeErr
		}
		if _, scanErr := droppedSplitSize(ctx, path); scanErr != nil {
			return nil, scanErr
		}
	}
	return nil, err
}

func defaultPCV3Output(path string) string {
	if trimmed := trimPCVSuffix(path); trimmed != path {
		return trimmed
	}
	return path + ".decrypted"
}

func isPCV3UnavailableError(err error) bool {
	if errors.Is(err, pcv3operation.ErrReaderUnavailable) {
		return true
	}
	var failure pcv3operation.Failure
	return errors.As(err, &failure) && failure.Outcome() != pcv3operation.OutcomeOperationFailed
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
func (a *App) applyStartupPaths(paths []string) []string {
	validPaths, err := collectStartupPaths(paths, startupPathStat)
	if len(validPaths) == 0 {
		if err != nil {
			a.State.SetStatusMessage(app.StatusStartupPathAccessFailed, util.RED, app.StatusArgs{})
			a.refreshUI()
		}
		return nil
	}

	accepted := a.onDrop(validPaths)
	if err != nil {
		a.State.SetStatusMessage(app.StatusStartupPathPartialAccessFailed, util.YELLOW, app.StatusArgs{})
		a.refreshUI()
	}
	if accepted {
		return validPaths
	}
	return nil
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
		a.State.InputIdentities = append(a.State.InputIdentities, file.identity)
		a.State.CompressTotal += file.size
		a.State.RequiredFreeSpace += file.size
	}
	a.State.SetInputScanning(a.State.CompressTotal)
	a.refreshUI()
}

func scanFolders(ctx context.Context, roots []string, emit scannedFileBatch) error {
	return scanFoldersWithBudget(ctx, roots, fileops.NewZIPResourceBudget(), emit)
}

func scanFoldersWithBudget(ctx context.Context, roots []string, budget *fileops.ZIPResourceBudget, emit scannedFileBatch) error {
	var metadata fileops.ZIPInputMetadataReservation
	defer metadata.Release()
	var retained uint64
	defer func() { budget.Release(retained) }()
	var candidates []fileops.ZIPInputCandidate
	for _, path := range roots {
		if err := ctx.Err(); err != nil {
			return err
		}
		charge, err := fileops.ReserveZIPInputPath(budget, len(path))
		if err != nil {
			return err
		}
		retained += charge
		candidate, err := metadata.Inspect(budget, path)
		if err != nil {
			return err
		}
		if err := metadata.RetainCandidate(budget, candidate); err != nil {
			return err
		}
		candidates = append(candidates, candidate)
	}
	return scanFolderCandidatesWithBudget(ctx, candidates, budget, emit, &metadata)
}

func scanFolderCandidatesWithBudget(ctx context.Context, roots []fileops.ZIPInputCandidate, budget *fileops.ZIPResourceBudget, emit scannedFileBatch, metadata *fileops.ZIPInputMetadataReservation) error {
	if err := pcv3operation.AdmitZIPWorkingMemory(ctx, budget); err != nil {
		return err
	}
	const batchWorkspace = 8 << 10
	if err := budget.Reserve(batchWorkspace); err != nil {
		return err
	}
	defer budget.Release(batchWorkspace)
	var retained uint64
	defer func() { budget.Release(retained) }()
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

		if err := metadata.RetainCandidate(budget, root); err != nil {
			return err
		}
		err := root.Walk(ctx, budget, func(candidate fileops.ZIPInputCandidate, walkErr error) error {
			path, info := candidate.Path, candidate.Info
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				return walkErr
			}
			if !info.Mode().IsRegular() {
				return nil
			}

			cost, err := fileops.ReserveZIPInputPath(budget, len(path))
			if err != nil {
				return err
			}
			retained += cost
			identity, err := metadata.Capture(budget, candidate, false)
			if err != nil {
				return err
			}
			pendingFiles = append(pendingFiles, scannedFile{path: path, size: info.Size(), identity: identity})
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
	budget := job.budget
	if budget == nil {
		budget = fileops.NewZIPResourceBudget()
	}
	metadata := job.metadata
	if metadata == nil {
		metadata = &fileops.ZIPInputMetadataReservation{}
	}
	defer metadata.Release()
	err := scanFolderCandidatesWithBudget(ctx, job.roots, budget, emit, metadata)
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
		case errors.Is(err, fileops.ErrZIPMetadataLimit):
			a.applyFolderWalkError()
			a.State.SetStatus(resourceLimitCopy().Title, util.RED)
			a.refreshUI()
		default:
			a.applyFolderWalkError()
		}
	})
}

// onDrop handles files and folders dropped onto the window.
func (a *App) onDrop(names []string) bool {
	return a.selectDroppedInput(names, StartupAuto)
}

func (a *App) selectDroppedInput(names []string, intent StartupIntent) bool {
	if a.mobileImportActive {
		return false
	}

	// If keyfile modal is open, handle as keyfiles
	if a.State.ShowKeyfile {
		if intent == StartupAuto {
			a.handleKeyfileDrop(names)
		}
		return false
	}

	// Prevent race condition: ignore new drops while scanning or working
	// This prevents multiple goroutines from simultaneously modifying AllFiles
	if a.State.IsScanning() || a.State.IsWorking() {
		return false
	}

	return a.applyDropSelection(names, intent)
}

// applyDropSelection applies one already-accepted UI selection. It is UI-only.
// Recursive processing uses it inside its DoAndWait transaction so it bypasses
// only onDrop's user-input busy guard and never re-enters the public handler.
func (a *App) applyDropSelection(names []string, intent StartupIntent) bool {
	budget := fileops.NewZIPResourceBudget()
	var metadata fileops.ZIPInputMetadataReservation
	var roots []fileops.ZIPInputCandidate
	if len(names) > 1 {
		if err := pcv3operation.AdmitZIPWorkingMemory(context.Background(), budget); err != nil {
			a.applyFolderWalkError()
			a.State.SetStatus(resourceLimitCopy().Title, util.RED)
			a.refreshUI()
			return false
		}
	}
	for _, name := range names {
		if _, err := fileops.ReserveZIPInputPath(budget, len(name)); err != nil {
			a.applyFolderWalkError()
			a.State.SetStatus(resourceLimitCopy().Title, util.RED)
			a.refreshUI()
			return false
		}
	}
	reservation, ok := a.workers.reserve()
	if !ok {
		return false
	}
	workerLaunched := false
	defer func() {
		if !workerLaunched {
			reservation.release()
			metadata.Release()
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
	if intent == StartupEncrypt {
		a.State.SetEncryptSelectionOnly()
	}

	// One item dropped
	if len(names) == 1 {
		candidate, err := metadata.Inspect(budget, names[0])
		stat := candidate.Info
		if err != nil {
			if errors.Is(err, fileops.ErrZIPMetadataLimit) {
				a.applyFolderWalkError()
				a.State.SetStatus(resourceLimitCopy().Title, util.RED)
				a.refreshUI()
				return false
			}
			a.State.SetStatusMessage(app.StatusDropFailedStatItem, util.RED, app.StatusArgs{})
			a.State.SetScanning(false)
			a.refreshUI()
			return false
		}
		if stat.Mode()&os.ModeSymlink != 0 {
			if intent == StartupEncrypt || !isDecryptVolumePath(names[0]) {
				a.State.SetScanning(false)
				a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
				return false
			}
			stat, err = os.Stat(names[0])
			if err != nil {
				a.State.SetScanning(false)
				a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
				return false
			}
		}

		// A folder was dropped
		if stat.IsDir() {
			if err := metadata.RetainCandidate(budget, candidate); err != nil {
				a.applyFolderWalkError()
				a.State.SetStatus(resourceLimitCopy().Title, util.RED)
				a.refreshUI()
				return false
			}
			roots = append(roots, candidate)
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

			path := names[0]
			isSplit := intent == StartupAuto && fileops.IsSplitChunkPath(path)
			leaf, err := os.Lstat(path)
			if err != nil {
				a.State.SetScanning(false)
				a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
				a.refreshAdvanced()
				return false
			}
			if leaf.Mode()&os.ModeSymlink != 0 {
				if intent == StartupEncrypt {
					a.State.SetScanning(false)
					a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
					return false
				}
				routedInput, routeErr := volume.OpenLegacyPCVInput(path, isSplit)
				if routeErr != nil {
					if isPCV3UnavailableError(routeErr) {
						a.State.SetPCVUnavailable(path, stat.Size())
						a.refreshAdvanced()
						a.refreshUI()
						return true
					}
					a.State.SetScanning(false)
					a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
					a.refreshAdvanced()
					return false
				}
				size := stat.Size()
				if isSplit {
					size, routeErr = droppedSplitSize(context.Background(), path)
					if routeErr != nil {
						_ = routedInput.Close()
						a.setDroppedRouteFailed(routeErr)
						a.refreshAdvanced()
						a.refreshUI()
						return false
					}
				}
				accepted := a.applyLegacyDroppedFileRoute(path, isSplit, droppedRouteResult{
					source: routedInput,
					size:   size,
					route:  pcv3operation.RouteLegacyEligible,
				})
				// Leaf symlinks remain a legacy compatibility path only. Do not
				// retain their descriptor as later explicit D1 authority.
				a.State.ClosePCV3Source()
				a.refreshAdvanced()
				a.refreshUI()
				return accepted
			}
			a.State.SetPCV3RoutingChecking(path, stat.Size())
			identity, err := metadata.Capture(budget, candidate, false)
			if err != nil {
				a.State.SetScanning(false)
				a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
				return false
			}
			a.refreshAdvanced()
			a.refreshUI()
			workerLaunched = true
			reservation.launch(func(ctx context.Context) {
				defer metadata.Release()
				result := routeDroppedFile(ctx, path, isSplit, intent == StartupEncrypt)
				if result.err == nil && (result.encryptOnly || (!isSplit && !isDecryptVolumePath(path))) {
					result.err = identity.CheckFile(result.source)
					result.inputIdentity = identity
				}
				fyne.DoAndWait(func() {
					a.applyDroppedFileRoute(ctx, generation, path, isSplit, result)
				})
			})
			return true
		}
	} else {
		var accepted bool
		roots, accepted = a.handleMultipleDrop(names, budget, &metadata)
		if !accepted {
			return false
		}
	}

	if len(a.State.OnlyFolders) == 0 {
		a.State.SetInputSelection(len(a.State.OnlyFiles), len(a.State.OnlyFolders), a.State.CompressTotal, true)
		a.State.SetScanning(false)
		a.refreshUI()
		a.refreshAdvanced()
		return true
	}

	job := folderScanJob{
		roots:       roots,
		fileCount:   len(a.State.OnlyFiles),
		folderCount: len(a.State.OnlyFolders),
		generation:  generation,
		budget:      budget,
		metadata:    &metadata,
	}
	emit := a.scannedFileEmitter(generation)
	workerLaunched = true
	reservation.launch(func(ctx context.Context) {
		a.runFolderScan(ctx, job, emit)
	})
	return true
}

func routeDroppedFile(ctx context.Context, path string, split, encryptOnly bool) droppedRouteResult {
	var source *os.File
	var err error
	if encryptOnly {
		source, err = fileops.OpenRegularReadNoSymlink(path)
	} else {
		source, err = openDroppedPCVInput(ctx, path, split)
	}
	if err != nil {
		return droppedRouteResult{err: err}
	}
	info, err := source.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		_ = source.Close()
		return droppedRouteResult{err: errors.New("selected input is not a regular file")}
	}
	if encryptOnly {
		return droppedRouteResult{
			source: source, size: info.Size(), route: pcv3operation.RouteLegacyEligible, encryptOnly: true,
		}
	}
	if split {
		totalSize, err := droppedSplitSize(ctx, path)
		if err != nil {
			return droppedRouteResult{source: source, err: err}
		}
		var prefix [4]byte
		count, readErr := io.ReadFull(source, prefix[:])
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			_ = source.Close()
			return droppedRouteResult{err: readErr}
		}
		if _, err := source.Seek(0, io.SeekStart); err != nil {
			_ = source.Close()
			return droppedRouteResult{err: err}
		}
		route := pcv3operation.DetectPrefix(prefix[:count])
		result := previewDroppedNormal(ctx, source, info.Size(), route, nil)
		result.size = totalSize
		return result
	}
	route, err := probeDroppedPCVInput(source, info.Size())
	return previewDroppedNormal(ctx, source, info.Size(), route, err)
}

func droppedSplitSize(ctx context.Context, path string) (int64, error) {
	base, ok := fileops.SplitChunkBase(path)
	if !ok {
		return 0, errors.New("invalid split input")
	}
	_, size, err := fileops.CountChunksWithCancel(base, func() bool { return ctx.Err() != nil })
	return size, err
}

func previewDroppedNormal(ctx context.Context, source *os.File, size int64, route pcv3operation.Route, err error) droppedRouteResult {
	result := droppedRouteResult{source: source, size: size, route: route, err: err}
	if route == pcv3operation.RouteNormalPCV && err == nil {
		result.preview, _ = pcv3operation.PreviewNormal(ctx, source, size)
	}
	return result
}

func (a *App) applyNormalPreview(result droppedRouteResult) {
	if ticket, _, ok := a.State.PCV3ReadyOutputSelection(); ok {
		a.State.SetPCV3NormalPreviewForReady(ticket, result.source, result.preview)
	}
}

// prepareRecursiveDropSelection replaces only the per-file selection state.
// The recursive operation itself remains live: this must not call resetUI,
// cancel the operation session, or change its generation.
func (a *App) prepareRecursiveDropSelection() {
	a.pcv3ArchiveSummary = nil
	a.State.ClosePCV3Source()
	a.State.PCVUnavailable = false
	a.State.Mode = ""
	a.State.InputFile = ""
	a.State.OutputFile = ""
	a.State.OutputChosenViaSaveDialog = false
	a.State.OnlyFiles = nil
	a.State.OnlyFolders = nil
	a.State.AllFiles = nil
	a.State.InputIdentities = nil
	a.State.Recombine = false
	a.State.CompressTotal = 0
	a.State.RequiredFreeSpace = 0
	a.State.Keyfile = false
	a.State.KeyfileOrdered = false
	a.State.Comments = ""
	a.State.CommentsPreviewState = app.CommentsPreviewNormal
	a.State.Deniability = false
	a.State.SetPCV3LegacyEligible()
	a.State.SetInputPrompt()
	a.State.SetStartAction(app.StartActionStart)
}

// applyLegacyDroppedFileRoute applies a legacy-eligible result after routing
// has completed. The caller owns result.source until RetainPCV3D1Candidate
// succeeds or this function closes it.
func (a *App) applyLegacyDroppedFileRoute(path string, isSplit bool, result droppedRouteResult) bool {
	if result.source == nil {
		return false
	}
	a.State.SetPCV3LegacyEligible()
	if !result.encryptOnly && isDecryptVolumePath(path) {
		a.handleDecryptDrop(path, isSplit, result.source, result.size)
	} else {
		if result.inputIdentity.ReadPath() == "" {
			info, err := result.source.Stat()
			if err == nil {
				result.inputIdentity, err = fileops.ZIPInputFromFileInfo(path, info)
			}
			if err != nil {
				_ = result.source.Close()
				return false
			}
		}
		a.State.Mode = "encrypt"
		a.State.InputFile = path
		a.State.SetInputSelection(1, 0, result.size, true)
		a.State.SetStartAction(app.StartActionEncrypt)
		a.State.OutputFile = path + ".pcv"
		a.State.OnlyFiles = []string{path}
		a.State.AllFiles = []string{path}
		a.State.InputIdentities = []fileops.ZIPInputIdentity{result.inputIdentity}
		a.State.CompressTotal = result.size
	}
	accepted := a.State.Mode != ""
	if result.encryptOnly || !accepted || !a.State.RetainPCV3D1Candidate(result.source) {
		_ = result.source.Close()
	}
	a.State.SetScanning(false)
	return accepted
}

// routeRecursiveD1File opens the exact selected file under explicit D1 intent.
// Prefixes cannot change that intent, even when random D1 bytes resemble PCV.
func routeRecursiveD1File(path string) droppedRouteResult {
	source, err := openPCV3InputFile(path)
	if err != nil {
		return droppedRouteResult{err: err}
	}
	info, err := source.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		_ = source.Close()
		return droppedRouteResult{err: errors.New("selected D1 input is not a regular file")}
	}
	return droppedRouteResult{source: source, size: info.Size(), explicitD1: true}
}

// applyRecursiveDroppedFileRoute consumes one synchronously routed result on
// the Fyne thread. PCV3 transfers only to the selected typed batch reader;
// malformed or unsupported PCV input never falls through to legacy.
func (a *App) applyRecursiveDroppedFileRoute(path string, isSplit bool, result droppedRouteResult) bool {
	a.prepareRecursiveDropSelection()
	if result.err == nil && (result.explicitD1 || result.route == pcv3operation.RouteNormalPCV) && !isSplit {
		format := app.PCV3FormatNormal
		if result.explicitD1 {
			format = app.PCV3FormatD1
		}
		if a.State.SetPCV3Ready(result.source, format, path, defaultPCV3Output(path), result.size) {
			if !result.explicitD1 {
				a.applyNormalPreview(result)
			}
			return true
		}
	}
	if result.err != nil || result.explicitD1 || result.route != pcv3operation.RouteLegacyEligible {
		if result.source != nil {
			_ = result.source.Close()
		}
		return false
	}
	return a.applyLegacyDroppedFileRoute(path, isSplit, result)
}

func (a *App) applyDroppedFileRoute(
	ctx context.Context,
	generation uint64,
	path string,
	isSplit bool,
	result droppedRouteResult,
) {
	if !a.folderScanCanApply(ctx, generation) {
		if result.source != nil {
			_ = result.source.Close()
		}
		return
	}
	// Structural probe failures still belong to the Normal family. Keep the
	// held source so the user can explicitly choose recovery or D1; the
	// selected reader will validate it again. Actual input I/O failures remain
	// terminal and no claimed PCV source may fall back to the legacy reader.
	var failure pcv3operation.Failure
	structuralFailure := result.route == pcv3operation.RouteNormalPCV &&
		errors.As(result.err, &failure) &&
		(failure.Outcome() == pcv3operation.OutcomeInvalidStructurePreKDF ||
			failure.Outcome() == pcv3operation.OutcomeUnsupportedRoutingPreKDF)
	if result.err != nil && !structuralFailure {
		if result.source != nil {
			_ = result.source.Close()
		}
		a.setDroppedRouteFailed(result.err)
		a.refreshAdvanced()
		a.refreshUI()
		return
	}
	if result.route == pcv3operation.RouteNormalPCV {
		if isSplit {
			base, ok := fileops.SplitChunkBase(path)
			if !ok {
				_ = result.source.Close()
				a.State.SetPCV3RoutingFailed()
				a.refreshAdvanced()
				a.refreshUI()
				return
			}
			if !a.State.SetPCV3Ready(
				result.source, app.PCV3FormatNormal, base, defaultPCV3Output(base), result.size,
			) {
				_ = result.source.Close()
				a.State.SetPCV3RoutingFailed()
			} else {
				a.State.Recombine = true
				a.applyNormalPreview(result)
				a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyUnset, app.PCV3KeyfileOrderUnset)
			}
			a.refreshAdvanced()
			a.refreshUI()
			return
		}
		if !a.State.SetPCV3Ready(
			result.source, app.PCV3FormatNormal, path, defaultPCV3Output(path), result.size,
		) {
			_ = result.source.Close()
			a.State.SetPCV3RoutingFailed()
		} else {
			a.applyNormalPreview(result)
			a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyUnset, app.PCV3KeyfileOrderUnset)
		}
		a.refreshAdvanced()
		a.refreshUI()
		return
	}

	a.applyLegacyDroppedFileRoute(path, isSplit, result)
	a.refreshAdvanced()
	a.refreshUI()
}

func (a *App) setDroppedRouteFailed(err error) {
	a.State.SetPCV3RoutingFailed()
	var missing *fileops.MissingChunkError
	if errors.As(err, &missing) {
		a.State.SetStatusMessage(app.StatusDropMissingSplitPart, util.RED, app.StatusArgs{Index: missing.Index})
	}
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
func (a *App) handleDecryptDrop(name string, isSplit bool, fin *os.File, inputSize int64) {
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

		a.State.CompressTotal = inputSize
		a.State.RequiredFreeSpace = inputSize
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
			a.State.CommentsPreviewState = app.CommentsPreviewUnverified
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
func (a *App) handleMultipleDrop(names []string, budget *fileops.ZIPResourceBudget, metadata *fileops.ZIPInputMetadataReservation) ([]fileops.ZIPInputCandidate, bool) {
	a.State.Mode = "encrypt"
	a.State.SetStartAction(app.StartActionZipAndEncrypt)
	files, folders := 0, 0
	var roots []fileops.ZIPInputCandidate

	// Go through each dropped item and add to corresponding slices
	for _, name := range names {
		candidate, err := metadata.Inspect(budget, name)
		if err != nil {
			if errors.Is(err, fileops.ErrZIPMetadataLimit) {
				a.applyFolderWalkError()
				a.State.SetStatus(resourceLimitCopy().Title, util.RED)
				a.refreshUI()
				return nil, false
			}
			a.State.SetScanning(false)
			a.resetUI()
			a.State.SetStatusMessage(app.StatusDropFailedStatItems, util.RED, app.StatusArgs{})
			a.refreshUI()
			return nil, false
		}
		stat := candidate.Info
		if stat.IsDir() {
			if err := metadata.RetainCandidate(budget, candidate); err != nil {
				a.applyFolderWalkError()
				a.State.SetStatus(resourceLimitCopy().Title, util.RED)
				a.refreshUI()
				return nil, false
			}
			folders++
			roots = append(roots, candidate)
			a.State.OnlyFolders = append(a.State.OnlyFolders, name)
		} else {
			identity, err := metadata.Capture(budget, candidate, false)
			if err != nil {
				a.State.SetScanning(false)
				a.applyDropStatusMessage(app.StatusDropReadAccessDenied, false)
				return nil, false
			}
			files++
			a.State.OnlyFiles = append(a.State.OnlyFiles, name)
			a.State.AllFiles = append(a.State.AllFiles, name)
			a.State.InputIdentities = append(a.State.InputIdentities, identity)

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
	return roots, true
}

// handleKeyfileDrop processes dropped keyfiles when the modal is open.
func (a *App) handleKeyfileDrop(paths []string) bool {
	if !a.State.ShowKeyfile {
		return false
	}

	// Add keyfiles, checking for duplicates and access
	for _, path := range paths {
		// Check if accessible and not a directory
		stat, err := os.Stat(path)
		if err != nil {
			a.State.ShowKeyfile = false
			a.applyDropStatusMessage(app.StatusKeyfileReadAccessDenied, true)
			return true
		}

		if !stat.IsDir() && (a.State.UISnapshot().PCV3Route == app.PCV3RouteReady ||
			!slices.Contains(a.State.Keyfiles, path)) {
			a.State.Keyfiles = append(a.State.Keyfiles, path)
		}
	}

	// Update the keyfile list in the modal and increment modalId like original
	a.State.ModalID++
	a.updateKeyfileList()
	a.refreshUI()
	return true
}
