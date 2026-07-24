// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/log"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
)

type operationInput struct {
	mode string

	inputFile   string
	inputFiles  []string
	onlyFiles   []string
	onlyFolders []string
	outputFile  string

	password       []byte
	keyfiles       []string
	keyfileOrdered bool
	comments       string

	paranoid    bool
	reedSolomon bool
	deniability bool
	compress    bool

	split     bool
	chunkSize int
	chunkUnit fileops.SplitUnit

	forceDecrypt bool
	verifyFirst  bool
	autoUnzip    bool
	sameLevel    bool
	recombine    bool
	delete       bool

	rsCodecs *encoding.RSCodecs
}

type operationResult struct {
	err          error
	cancelled    bool
	completed    bool
	kept         bool
	deleteFailed bool
	succeeded    int
	failed       int
}

type operationExecutor func(
	context.Context,
	operationInput,
	volume.ProgressReporter,
) operationResult

type operationSourceRemover func(context.Context, string) error

func removeOperationSource(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Remove(path)
}

type deletionSource struct {
	path string
	info os.FileInfo
}

type operationDeletionManifest struct {
	files       []deletionSource
	directories []deletionSource
}

func captureDeletionSource(path string, wantDirectory bool) (deletionSource, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return deletionSource{}, fmt.Errorf("resolve deletion source %q: %w", path, err)
	}

	var info os.FileInfo
	if wantDirectory {
		root, err := os.OpenRoot(absolute)
		if err != nil {
			return deletionSource{}, fmt.Errorf("open deletion source directory %q: %w", absolute, err)
		}
		info, err = root.Stat(".")
		closeErr := root.Close()
		if err != nil {
			return deletionSource{}, errors.Join(
				fmt.Errorf("inspect deletion source directory %q: %w", absolute, err),
				closeErr,
			)
		}
		if closeErr != nil {
			return deletionSource{}, fmt.Errorf("close deletion source directory %q: %w", absolute, closeErr)
		}
		if !info.IsDir() {
			return deletionSource{}, fmt.Errorf("deletion source is no longer a directory: %s", absolute)
		}
	} else {
		file, err := fileops.OpenExistingNoSymlink(absolute, os.O_RDONLY)
		if err != nil {
			return deletionSource{}, fmt.Errorf("open deletion source file %q: %w", absolute, err)
		}
		info, err = file.Stat()
		closeErr := file.Close()
		if err != nil {
			return deletionSource{}, errors.Join(
				fmt.Errorf("inspect deletion source file %q: %w", absolute, err),
				closeErr,
			)
		}
		if closeErr != nil {
			return deletionSource{}, fmt.Errorf("close deletion source file %q: %w", absolute, closeErr)
		}
		if !info.Mode().IsRegular() {
			return deletionSource{}, fmt.Errorf("deletion source is no longer a regular file: %s", absolute)
		}
	}
	return deletionSource{path: absolute, info: info}, nil
}

func captureOperationDeletionManifest(input operationInput) (*operationDeletionManifest, error) {
	if !input.delete {
		return nil, nil
	}

	var filePaths []string
	var folderPaths []string
	switch {
	case input.mode == "encrypt" && len(input.inputFiles) > 0:
		filePaths = append(filePaths, input.inputFiles...)
		folderPaths = append(folderPaths, input.onlyFolders...)
	case input.mode == "encrypt":
		filePaths = append(filePaths, input.inputFile)
	case input.recombine:
		inputBase := input.inputFile
		if base, ok := fileops.SplitChunkBase(inputBase); ok {
			inputBase = base
		}
		numChunks, _, err := fileops.CountChunks(inputBase)
		if err != nil {
			return nil, fmt.Errorf("enumerate split sources: %w", err)
		}
		for i := range numChunks {
			filePaths = append(filePaths, inputBase+"."+strconv.Itoa(i))
		}
	default:
		filePaths = append(filePaths, input.inputFile)
	}

	manifest := &operationDeletionManifest{}
	seenFiles := make(map[string]struct{}, len(filePaths))
	for _, path := range filePaths {
		source, err := captureDeletionSource(path, false)
		if err != nil {
			return nil, err
		}
		if _, exists := seenFiles[source.path]; exists {
			continue
		}
		seenFiles[source.path] = struct{}{}
		manifest.files = append(manifest.files, source)
	}

	seenDirectories := make(map[string]deletionSource)
	for _, rootPath := range folderPaths {
		root, err := filepath.Abs(filepath.Clean(rootPath))
		if err != nil {
			return nil, fmt.Errorf("resolve source folder %q: %w", rootPath, err)
		}
		err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				return nil
			}
			source, err := captureDeletionSource(path, true)
			if err != nil {
				return err
			}
			seenDirectories[source.path] = source
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("capture source folder %q: %w", root, err)
		}
	}
	for _, source := range seenDirectories {
		manifest.directories = append(manifest.directories, source)
	}
	sort.Slice(manifest.directories, func(i, j int) bool {
		left := strings.Count(filepath.Clean(manifest.directories[i].path), string(filepath.Separator))
		right := strings.Count(filepath.Clean(manifest.directories[j].path), string(filepath.Separator))
		if left == right {
			return manifest.directories[i].path > manifest.directories[j].path
		}
		return left > right
	})
	return manifest, nil
}

type deletionSourceState int

const (
	deletionSourceMissing deletionSourceState = iota
	deletionSourceUnchanged
	deletionSourceChanged
)

func inspectDeletionSource(source deletionSource, directory bool) (deletionSourceState, error) {
	current, err := os.Lstat(source.path)
	if errors.Is(err, os.ErrNotExist) {
		return deletionSourceMissing, nil
	}
	if err != nil {
		return deletionSourceChanged, err
	}
	if !os.SameFile(source.info, current) || current.Mode().Type() != source.info.Mode().Type() {
		return deletionSourceChanged, nil
	}
	if directory {
		if !current.IsDir() || current.Mode().Perm() != source.info.Mode().Perm() {
			return deletionSourceChanged, nil
		}
		return deletionSourceUnchanged, nil
	}
	if !current.Mode().IsRegular() ||
		current.Mode() != source.info.Mode() ||
		current.Size() != source.info.Size() ||
		!current.ModTime().Equal(source.info.ModTime()) {
		return deletionSourceChanged, nil
	}
	return deletionSourceUnchanged, nil
}

type operationReporterGate struct {
	mu         sync.Mutex
	open       bool
	ctx        context.Context
	generation uint64
	current    func() uint64
	stopping   func() bool
}

func newOperationReporterGate(
	ctx context.Context,
	generation uint64,
	current func() uint64,
	stopping func() bool,
) *operationReporterGate {
	return &operationReporterGate{
		open:       true,
		ctx:        ctx,
		generation: generation,
		current:    current,
		stopping:   stopping,
	}
}

func (g *operationReporterGate) validLocked() bool {
	return g.open && g.ctx.Err() == nil && !g.stopping() && g.current() == g.generation
}

func (g *operationReporterGate) accept(fn func()) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.validLocked() {
		return false
	}
	fn()
	return true
}

func (g *operationReporterGate) canApply() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.validLocked()
}

func (g *operationReporterGate) cancel(cancel context.CancelFunc) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.open {
		return false
	}
	g.open = false
	cancel()
	return true
}

// finish closes callback acceptance and reports whether cancellation won the
// terminal race. The context is cancelled before releasing the gate lock so a
// concurrent cancel callback cannot be accepted after completion wins.
func (g *operationReporterGate) finish(cancel context.CancelFunc) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	cancelled := g.ctx.Err() != nil
	g.open = false
	cancel()
	return cancelled
}

type operationSession struct {
	ctx        context.Context
	cancel     context.CancelFunc
	generation uint64
	gate       *operationReporterGate
}

type recursiveSelectionOutcome int

const (
	recursiveSelectionUnapplied recursiveSelectionOutcome = iota
	recursiveSelectionFailed
	recursiveSelectionApplied
)

func showOverwriteModalForOutput(outputExists, recursively, chosenViaDialog bool) bool {
	return outputExists && !recursively && !chosenViaDialog
}

func recursiveStatusCompleted(count int) string {
	fallback := "Completed ({{.Count}} files)"
	if count == 1 {
		fallback = "Completed ({{.Count}} file)"
	}
	return trn("status.recursive_completed", fallback, count, map[string]any{
		"Count": count,
	})
}

func recursiveStatusFailedAll(count int) string {
	fallback := "Failed (all {{.Count}} files)"
	if count == 1 {
		fallback = "Failed (all {{.Count}} file)"
	}
	return trn("status.recursive_failed_all", fallback, count, map[string]any{
		"Count": count,
	})
}

func recursiveStatusCompletedFailed(successCount, failedCount int) string {
	return tr("status.recursive_completed_failed", "Completed ({{.OK}} ok, {{.Failed}} failed)", map[string]any{
		"OK":     successCount,
		"Failed": failedCount,
	})
}

func recursiveProcessingStatus(index, total int) string {
	return tr("status.processing_file", "Processing file {{.Index}}/{{.Total}}...", map[string]any{
		"Index": index,
		"Total": total,
	})
}

func cancelledOperationStatus() string {
	return tr("status.cancelled_by_user", "Operation cancelled by user")
}

func splitSizeReady(snap app.UISnapshot) bool {
	if !snap.Split {
		return true
	}
	size, err := strconv.ParseInt(strings.TrimSpace(snap.SplitSize), 10, 64)
	return err == nil && size > 0
}

// onClickStart handles the Start button click.
func (a *App) onClickStart() {
	if a.mobileImportActive {
		return
	}
	a.cancelOpenedPathReadiness()

	if a.State.Mode == "" || a.startDisabled(a.State.UISnapshot()) {
		return
	}

	if !a.State.Recursively {
		input, err := a.captureOperationInput(a.State.Snapshot())
		if err != nil {
			a.State.SetStatusMessage(app.StatusInvalidSplitSize, util.RED, app.StatusArgs{})
			a.updateUIState()
			return
		}
		defer crypto.SecureZero(input.password)
		if err := validateOperationInputSafety(input); err != nil {
			a.State.SetStatus(err.Error(), util.RED)
			a.updateUIState()
			return
		}
	}

	_, outputExists := os.Stat(a.State.OutputFile)
	if showOverwriteModalForOutput(outputExists == nil, a.State.Recursively, a.State.OutputChosenViaSaveDialog) {
		a.showOverwriteModal()
		return
	}

	a.startWork()
}

func parseSplitSize(value string) (int, error) {
	chunkSize := 1
	if value == "" {
		return chunkSize, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return 0, errors.New("invalid split size")
	}
	return n, nil
}

func validateOperationInputSafety(input operationInput) error {
	var err error
	if input.mode == "encrypt" {
		err = (&volume.EncryptRequest{
			InputFile:   input.inputFile,
			InputFiles:  input.inputFiles,
			OnlyFiles:   input.onlyFiles,
			OnlyFolders: input.onlyFolders,
			OutputFile:  input.outputFile,
			Keyfiles:    input.keyfiles,
		}).ValidateOutputSafety()
	} else {
		err = (&volume.DecryptRequest{
			InputFile:  input.inputFile,
			OutputFile: input.outputFile,
			Keyfiles:   input.keyfiles,
			Recombine:  input.recombine,
		}).ValidateOutputSafety()
	}
	if err != nil {
		return err
	}
	return validateDeletionSafety(input)
}

func validateDeletionSafety(input operationInput) error {
	if !input.delete {
		return nil
	}

	deleteFiles := make([]string, 0, len(input.inputFiles)+1)
	deleteFolders := make([]string, 0, len(input.onlyFolders))
	if input.mode == "encrypt" {
		if len(input.inputFiles) > 0 {
			deleteFiles = append(deleteFiles, input.inputFiles...)
			deleteFolders = append(deleteFolders, input.onlyFolders...)
		} else if input.inputFile != "" {
			deleteFiles = append(deleteFiles, input.inputFile)
		}

		for _, folder := range deleteFolders {
			inside, err := operationPathInside(folder, input.outputFile)
			if err != nil {
				return err
			}
			if inside {
				return fmt.Errorf("output %q is inside source folder %q scheduled for deletion", input.outputFile, folder)
			}
		}
	} else if input.recombine {
		inputBase := input.inputFile
		if base, ok := fileops.SplitChunkBase(inputBase); ok {
			inputBase = base
		}
		numChunks, _, err := fileops.CountChunks(inputBase)
		if err == nil {
			for i := range numChunks {
				deleteFiles = append(deleteFiles, fmt.Sprintf("%s.%d", inputBase, i))
			}
		}
	} else if input.inputFile != "" {
		deleteFiles = append(deleteFiles, input.inputFile)
	}

	for _, keyfile := range input.keyfiles {
		for _, source := range deleteFiles {
			same, err := fileops.SamePathOrFile(keyfile, source)
			if err != nil {
				return err
			}
			if same {
				return fmt.Errorf("keyfile %q aliases source %q scheduled for deletion", keyfile, source)
			}
		}
		for _, folder := range deleteFolders {
			inside, err := operationPathInside(folder, keyfile)
			if err != nil {
				return err
			}
			if inside {
				return fmt.Errorf("keyfile %q is inside source folder %q scheduled for deletion", keyfile, folder)
			}
		}
	}

	return nil
}

func operationPathInside(rootPath, candidatePath string) (bool, error) {
	root, err := resolveOperationPath(rootPath)
	if err != nil {
		return false, err
	}
	candidate, err := resolveOperationPath(candidatePath)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false, fmt.Errorf("compare %q with %q: %w", rootPath, candidatePath, err)
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

func resolveOperationPath(path string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return filepath.Clean(resolved), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}

	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err == nil {
		return filepath.Join(parent, filepath.Base(absolute)), nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return absolute, nil
	}
	return "", fmt.Errorf("resolve parent of %q: %w", path, err)
}

func (a *App) captureOperationInput(snap app.Snapshot) (operationInput, error) {
	chunkSize := 1
	if snap.Mode == "encrypt" {
		var err error
		chunkSize, err = parseSplitSize(snap.SplitSize)
		if err != nil {
			return operationInput{}, err
		}
	}

	return operationInput{
		mode:           snap.Mode,
		inputFile:      snap.InputFile,
		inputFiles:     append([]string(nil), snap.InputFiles...),
		onlyFiles:      append([]string(nil), snap.OnlyFiles...),
		onlyFolders:    append([]string(nil), snap.OnlyFolders...),
		outputFile:     snap.OutputFile,
		password:       []byte(snap.Password),
		keyfiles:       append([]string(nil), snap.Keyfiles...),
		keyfileOrdered: snap.KeyfileOrdered,
		comments:       snap.Comments,
		paranoid:       snap.Paranoid,
		reedSolomon:    snap.ReedSolomon,
		deniability:    snap.Deniability,
		compress:       snap.Compress,
		split:          snap.Split,
		chunkSize:      chunkSize,
		chunkUnit:      splitUnitFromIndex(snap.SplitSelected),
		forceDecrypt:   snap.Keep,
		verifyFirst:    snap.VerifyFirst,
		autoUnzip:      snap.AutoUnzip,
		sameLevel:      snap.SameLevel,
		recombine:      snap.Recombine,
		delete:         snap.Delete,
		rsCodecs:       a.rsCodecs,
	}, nil
}

func (a *App) newOperationSession() *operationSession {
	ctx, cancel := context.WithCancel(a.workers.ctx)
	generation := a.operationGeneration.Add(1)
	session := &operationSession{
		ctx:        ctx,
		cancel:     cancel,
		generation: generation,
	}
	session.gate = newOperationReporterGate(
		ctx,
		generation,
		a.operationGeneration.Load,
		a.workers.isStopping,
	)
	return session
}

func (a *App) setOperationSession(session *operationSession) {
	a.operationMu.Lock()
	a.operationSession = session
	a.operationMu.Unlock()
}

func (a *App) isCurrentOperation(session *operationSession) bool {
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	return a.operationSession == session && a.operationGeneration.Load() == session.generation
}

func (a *App) clearOperationSession(session *operationSession) {
	a.operationMu.Lock()
	if a.operationSession == session {
		a.operationSession = nil
	}
	a.operationMu.Unlock()
}

func (a *App) stopCurrentOperation() {
	a.operationMu.Lock()
	session := a.operationSession
	a.operationMu.Unlock()
	if session == nil {
		return
	}
	session.gate.cancel(session.cancel)
}

func (a *App) operationCanApply(session *operationSession) bool {
	return !a.workers.isStopping() && session.ctx.Err() == nil && a.isCurrentOperation(session)
}

// startWork begins the encryption/decryption operation. It is called only from
// Fyne callbacks and captures every worker input before launching the worker.
func (a *App) startWork() {
	snap := a.State.Snapshot()
	uiSnap := a.State.UISnapshot()
	mobile := isMobile()

	if uiSnap.Recursively && snap.Mode == "encrypt" {
		if _, err := parseSplitSize(snap.SplitSize); err != nil {
			a.State.SetStatusMessage(app.StatusInvalidSplitSize, util.RED, app.StatusArgs{})
			a.updateUIState()
			return
		}
	}

	var input operationInput
	var err error
	if !uiSnap.Recursively {
		input, err = a.captureOperationInput(snap)
		if err != nil {
			a.State.SetStatusMessage(app.StatusInvalidSplitSize, util.RED, app.StatusArgs{})
			a.updateUIState()
			return
		}
		if err := validateDeletionSafety(input); err != nil {
			crypto.SecureZero(input.password)
			a.State.SetStatus(err.Error(), util.RED)
			a.updateUIState()
			return
		}
	} else if len(snap.InputFiles) == 0 {
		a.State.SetStatusMessage(app.StatusNoFilesToProcess, util.YELLOW, app.StatusArgs{})
		a.State.SetWorking(false)
		a.State.SetShowProgress(false)
		a.updateUIState()
		return
	}

	reservation, ok := a.workers.reserve()
	if !ok {
		crypto.SecureZero(input.password)
		return
	}
	launched := false
	defer func() {
		if !launched {
			reservation.release()
		}
	}()

	session := a.newOperationSession()
	if a.workers.isStopping() || session.ctx.Err() != nil {
		session.gate.cancel(session.cancel)
		crypto.SecureZero(input.password)
		return
	}
	a.setOperationSession(session)
	a.State.OutputChosenViaSaveDialog = false
	a.State.SetWorking(true)
	a.State.SetShowProgress(true)
	a.State.FastDecode = true
	a.State.SetCanCancel(true)
	a.State.ModalID++
	a.showProgressModal(session)

	executor := a.operationExecutor
	if executor == nil {
		executor = executeVolumeOperation
	}
	reporter := a.CreateReporter(session)

	launched = true
	if uiSnap.Recursively {
		files := append([]string(nil), snap.InputFiles...)
		saved := a.State.RecursiveSnapshot()
		reservation.launch(func(context.Context) {
			lastInput, result := a.runRecursiveOperation(session, executor, reporter, files, saved)
			if mobile {
				a.CleanupMobileTempFiles()
			}
			a.finishOperationWorker(session, lastInput, result, true)
		})
		return
	}

	reservation.launch(func(context.Context) {
		result := a.runCapturedOperation(session.ctx, executor, reporter, input)
		if mobile {
			a.CleanupMobileTempFiles()
		}
		a.finishOperationWorker(session, input, result, false)
	})
}

func (a *App) runCapturedOperation(
	ctx context.Context,
	executor operationExecutor,
	reporter volume.ProgressReporter,
	input operationInput,
) operationResult {
	defer crypto.SecureZero(input.password)

	if err := validateDeletionSafety(input); err != nil {
		return operationResult{
			err:    fmt.Errorf("prepare source deletion: %w", err),
			failed: 1,
		}
	}
	deletionManifest, err := captureOperationDeletionManifest(input)
	if err != nil {
		return operationResult{
			err:    fmt.Errorf("prepare source deletion: %w", err),
			failed: 1,
		}
	}
	result := executor(ctx, input, reporter)
	if ctx.Err() != nil {
		result.cancelled = true
	}
	result = a.cleanupOperationSources(ctx, input, deletionManifest, result)
	if ctx.Err() != nil {
		result.cancelled = true
	}
	if result.cancelled {
		return result
	}
	if result.completed && result.err == nil {
		result.succeeded = 1
	} else {
		result.failed = 1
	}
	return result
}

func executeVolumeOperation(
	ctx context.Context,
	input operationInput,
	reporter volume.ProgressReporter,
) operationResult {
	if input.mode == "encrypt" {
		req := &volume.EncryptRequest{
			InputFile:      input.inputFile,
			InputFiles:     input.inputFiles,
			OnlyFolders:    input.onlyFolders,
			OnlyFiles:      input.onlyFiles,
			OutputFile:     input.outputFile,
			Password:       input.password,
			Keyfiles:       input.keyfiles,
			KeyfileOrdered: input.keyfileOrdered,
			Comments:       input.comments,
			Paranoid:       input.paranoid,
			ReedSolomon:    input.reedSolomon,
			Deniability:    input.deniability,
			Compress:       input.compress,
			Split:          input.split,
			ChunkSize:      input.chunkSize,
			ChunkUnit:      input.chunkUnit,
			Reporter:       reporter,
			RSCodecs:       input.rsCodecs,
		}
		err := volume.Encrypt(ctx, req)
		return operationResult{err: err, completed: err == nil, cancelled: errors.Is(err, context.Canceled)}
	}

	kept := false
	req := &volume.DecryptRequest{
		InputFile:    input.inputFile,
		OutputFile:   input.outputFile,
		Password:     input.password,
		Keyfiles:     input.keyfiles,
		ForceDecrypt: input.forceDecrypt,
		VerifyFirst:  input.verifyFirst,
		AutoUnzip:    input.autoUnzip,
		SameLevel:    input.sameLevel,
		Recombine:    input.recombine,
		Deniability:  input.deniability,
		Reporter:     reporter,
		RSCodecs:     input.rsCodecs,
		Kept:         &kept,
	}
	err := volume.Decrypt(ctx, req)
	return operationResult{err: err, completed: err == nil, kept: kept, cancelled: errors.Is(err, context.Canceled)}
}

func (a *App) cleanupOperationSources(
	ctx context.Context,
	input operationInput,
	manifest *operationDeletionManifest,
	result operationResult,
) operationResult {
	if result.err != nil || !result.completed || result.cancelled || !input.delete || (input.mode == "decrypt" && result.kept) {
		return result
	}
	if manifest == nil {
		result.deleteFailed = true
		return result
	}
	remove := func(source deletionSource, directory bool) bool {
		state, err := inspectDeletionSource(source, directory)
		if err != nil {
			result.deleteFailed = true
			return true
		}
		if state == deletionSourceMissing {
			return true
		}
		if state == deletionSourceChanged {
			result.deleteFailed = true
			return true
		}
		remover := a.operationSourceRemover
		if remover == nil {
			remover = removeOperationSource
		}
		err = remover(ctx, source.path)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			result.cancelled = true
			return false
		}
		if errors.Is(err, os.ErrNotExist) {
			return true
		}
		if err != nil {
			result.deleteFailed = true
		}
		return true
	}

	for _, source := range manifest.files {
		if !remove(source, false) {
			return result
		}
	}
	for _, source := range manifest.directories {
		if !remove(source, true) {
			return result
		}
	}
	return result
}

func (a *App) runRecursiveOperation(
	session *operationSession,
	executor operationExecutor,
	reporter volume.ProgressReporter,
	files []string,
	saved app.RecursiveSnapshot,
) (operationInput, operationResult) {
	var aggregate operationResult
	var lastInput operationInput

	for i, file := range files {
		input, selection := a.captureRecursiveOperationInput(session, file, saved, i+1, len(files))
		if selection == recursiveSelectionFailed {
			aggregate.err = errors.New("recursive selection failed")
			aggregate.completed = false
			aggregate.failed++
			continue
		}
		if selection != recursiveSelectionApplied || session.ctx.Err() != nil || a.operationGeneration.Load() != session.generation {
			crypto.SecureZero(input.password)
			aggregate.cancelled = session.ctx.Err() != nil
			return lastInput, aggregate
		}

		result := a.runCapturedOperation(session.ctx, executor, reporter, input)
		lastInput = input
		aggregate.err = result.err
		aggregate.cancelled = result.cancelled
		aggregate.completed = result.completed
		aggregate.kept = result.kept
		aggregate.deleteFailed = aggregate.deleteFailed || result.deleteFailed
		if result.completed && result.err == nil && !result.cancelled {
			aggregate.succeeded++
		} else if !result.cancelled {
			aggregate.failed++
		}
		if result.cancelled {
			return lastInput, aggregate
		}
	}

	return lastInput, aggregate
}

func (a *App) captureRecursiveOperationInput(
	session *operationSession,
	file string,
	saved app.RecursiveSnapshot,
	index, total int,
) (operationInput, recursiveSelectionOutcome) {
	var input operationInput
	applied := false
	selectionFailed := false
	fyne.DoAndWait(func() {
		if !a.operationCanApply(session) {
			return
		}
		if !a.applyDropSelection([]string{file}) {
			selectionFailed = true
			return
		}
		a.State.ApplyRecursiveSelection(saved)
		status := recursiveProcessingStatus(index, total)
		a.State.SetPopupStatusText(status)
		if err := a.boundStatus.Set(status); err != nil {
			log.Error("set recursive operation status binding", log.Err(err))
		}
		captured, err := a.captureOperationInput(a.State.Snapshot())
		if err != nil {
			a.State.SetStatusMessage(app.StatusInvalidSplitSize, util.RED, app.StatusArgs{})
			selectionFailed = true
			return
		}
		input = captured
		applied = true
	})

	if !applied || session.ctx.Err() != nil || a.operationGeneration.Load() != session.generation {
		crypto.SecureZero(input.password)
		if selectionFailed && session.ctx.Err() == nil && a.operationGeneration.Load() == session.generation {
			return operationInput{}, recursiveSelectionFailed
		}
		return operationInput{}, recursiveSelectionUnapplied
	}
	return input, recursiveSelectionApplied
}

func (a *App) finishOperationWorker(
	session *operationSession,
	lastInput operationInput,
	result operationResult,
	recursive bool,
) {
	if session.gate.finish(session.cancel) {
		result.cancelled = true
	}
	if a.workers.isStopping() || a.operationGeneration.Load() != session.generation {
		a.clearOperationSession(session)
		return
	}
	fyne.Do(func() {
		if a.workers.isStopping() || a.operationGeneration.Load() != session.generation {
			a.clearOperationSession(session)
			return
		}
		a.finalizeOperation(session, lastInput, result, recursive)
	})
}

func (a *App) applyCompletedOperation(input operationInput, result operationResult) {
	a.State.ResetUI()
	a.State.SetInputPrompt()
	a.State.SetStartAction(app.StartActionStart)
	if result.kept {
		a.State.SetKept(true)
		a.State.SetStatusMessage(app.StatusKeptOutputUnverified, util.YELLOW, app.StatusArgs{})
		return
	}
	if result.deleteFailed {
		if input.mode == "encrypt" {
			a.State.SetStatusMessage(app.StatusCompletedSomeDeleteFailed, util.YELLOW, app.StatusArgs{})
		} else {
			a.State.SetStatusMessage(app.StatusCompletedVolumeDeleteFailed, util.YELLOW, app.StatusArgs{})
		}
		return
	}
	a.State.SetStatusMessage(app.StatusCompleted, util.GREEN, app.StatusArgs{})
}

func (a *App) finalizeOperation(
	session *operationSession,
	lastInput operationInput,
	result operationResult,
	recursive bool,
) {
	if a.workers.isStopping() || !a.isCurrentOperation(session) {
		return
	}
	a.clearOperationSession(session)

	clearCredentials := false
	switch {
	case result.cancelled:
		a.State.SetStatusMessage(app.StatusCancelledByUser, util.WHITE, app.StatusArgs{})
	case recursive:
		if result.completed && result.err == nil {
			a.applyCompletedOperation(lastInput, result)
			clearCredentials = true
		}
		switch {
		case result.failed == 0 && result.deleteFailed:
			if lastInput.mode == "encrypt" {
				a.State.SetStatusMessage(app.StatusCompletedSomeDeleteFailed, util.YELLOW, app.StatusArgs{})
			} else {
				a.State.SetStatusMessage(app.StatusCompletedVolumeDeleteFailed, util.YELLOW, app.StatusArgs{})
			}
		case result.failed == 0:
			a.State.SetStatusMessage(app.StatusRecursiveCompleted, util.GREEN, app.StatusArgs{Count: result.succeeded})
		case result.succeeded == 0:
			a.State.SetStatusMessage(app.StatusRecursiveFailedAll, util.RED, app.StatusArgs{Count: result.failed})
		default:
			a.State.SetStatusMessage(app.StatusRecursiveCompletedFailed, util.YELLOW, app.StatusArgs{OK: result.succeeded, Failed: result.failed})
		}
	case result.err != nil:
		a.State.SetStatus(result.err.Error(), util.RED)
	case result.completed:
		a.applyCompletedOperation(lastInput, result)
		clearCredentials = true
	}

	a.State.SetCanCancel(false)
	a.State.SetWorking(false)
	a.State.SetShowProgress(false)
	if a.progressModal != nil {
		a.progressModal.Hide()
	}
	if clearCredentials {
		a.clearCredentialEntries()
	}
	a.updateAdvancedSection()
	a.updateUIState()
}

func (a *App) cancelOperation(session *operationSession) {
	if session == nil || !a.isCurrentOperation(session) {
		return
	}
	if !session.gate.cancel(session.cancel) {
		return
	}
	a.State.SetCanCancel(false)
	a.State.SetStatusMessage(app.StatusCancelledByUser, util.WHITE, app.StatusArgs{})
	if err := a.boundStatus.Set(cancelledOperationStatus()); err != nil {
		log.Error("set cancelled operation status binding", log.Err(err))
	}
	if a.cancelButton != nil {
		a.cancelButton.Disable()
	}
	// Working remains true until the tracked worker exits and the single
	// finalizer has hidden the modal and applied the result.
}

// clearCredentialEntries resets the password, confirm-password, and comments
// widgets to match a cleared State. It is UI-only.
func (a *App) clearCredentialEntries() {
	if a.passwordEntry != nil {
		a.passwordEntry.SetText("")
	}
	if a.cPasswordEntry != nil {
		a.cPasswordEntry.SetText("")
	}
	if a.commentsEntry != nil {
		a.commentsEntry.SetText("")
	}
	a.updatePasswordStrength()
	a.updateValidation()
}

func splitUnitFromIndex(index int32) fileops.SplitUnit {
	switch index {
	case 0:
		return fileops.SplitUnitKiB
	case 1:
		return fileops.SplitUnitMiB
	case 2:
		return fileops.SplitUnitGiB
	case 3:
		return fileops.SplitUnitTiB
	case 4:
		return fileops.SplitUnitTotal
	default:
		return fileops.SplitUnitKiB
	}
}

// CreateReporter creates the complete volume-to-UI adapter for one operation
// session. All callbacks cross the session gate before changing state or UI.
func (a *App) CreateReporter(session *operationSession) *app.UIReporter {
	return app.NewUIReporter(
		func(text string) {
			session.gate.accept(func() {
				a.State.SetPopupStatusText(text)
				if err := a.boundStatus.Set(text); err != nil {
					log.Error("set operation status binding", log.Err(err))
				}
			})
		},
		func(fraction float32, info string) {
			session.gate.accept(func() {
				a.State.SetProgress(fraction, info)
				if err := a.boundProgress.Set(float64(fraction)); err != nil {
					log.Error("set operation progress binding", log.Err(err))
				}
			})
		},
		func(can bool) {
			if !session.gate.accept(func() {
				a.State.SetCanCancel(can)
			}) {
				return
			}
			fyne.Do(func() {
				if !session.gate.canApply() || a.cancelButton == nil {
					return
				}
				if can {
					a.cancelButton.Enable()
				} else {
					a.cancelButton.Disable()
				}
			})
		},
		func() bool {
			return session.ctx.Err() != nil
		},
	)
}
