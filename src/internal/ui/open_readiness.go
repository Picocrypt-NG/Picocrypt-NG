package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"
	"context"
	"errors"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const (
	openedPathReadyTimeout = 45 * time.Second
)

var (
	openedPathPollInterval             = 200 * time.Millisecond
	openedPathCloudSettleDelay         = 1500 * time.Millisecond
	openedPathCloudCancelSuppressDelay = 1500 * time.Millisecond
	openedPathCloudPostApplyMergeDelay = 5 * time.Second
	beforeOpenedPathReadyApply         = func() {}
)

func openedPathsPreparingStatus() string {
	return tr("opened_paths.preparing", "Preparing iCloud files")
}

func openedPathsTimeoutStatus() string {
	return tr("opened_paths.timeout", "Some iCloud files are not downloaded")
}

type openedPathReadinessState int

const (
	openedPathReady openedPathReadinessState = iota
	openedPathPending
	openedPathMissing
	openedPathError
)

type openedPathReadiness struct {
	Path         string
	State        openedPathReadinessState
	Err          error
	IsUbiquitous bool
	IsDir        bool
}

type openedPathReadinessResult []openedPathReadiness

type openedPathReadinessCheck func(context.Context, []string) openedPathReadinessResult

var checkOpenedPathReadiness openedPathReadinessCheck = defaultOpenedPathReadiness

func normalizeOpenedPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if isIgnoredStartupArg(path) {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func (r openedPathReadinessResult) allReady() bool {
	if len(r) == 0 {
		return false
	}
	for _, item := range r {
		if item.State != openedPathReady {
			return false
		}
	}
	return true
}

func (r openedPathReadinessResult) terminalError() error {
	for _, item := range r {
		if item.State != openedPathMissing && item.State != openedPathError {
			continue
		}
		if item.Err != nil {
			return item.Err
		}
		return errors.New("opened path is not available")
	}
	return nil
}

func (r openedPathReadinessResult) hasUbiquitousFile() bool {
	for _, item := range r {
		if item.IsUbiquitous && !item.IsDir {
			return true
		}
	}
	return false
}

// hasUbiquitousItem reports whether any opened item lives in iCloud. Finder
// may split its delivery, so a later batch needs an explicit selection choice.
func (r openedPathReadinessResult) hasUbiquitousItem() bool {
	for _, item := range r {
		if item.IsUbiquitous {
			return true
		}
	}
	return false
}

func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}

func (a *App) cancelOpenedPathReadiness() {
	a.openReadinessMu.Lock()
	cancel := a.openReadinessCancel
	activePaths := len(a.openReadinessPaths) > 0
	freshCloudApply := a.cloudApplyMergeableLocked()
	appliedAt := a.openReadinessAppliedAt
	a.openReadinessGeneration++
	a.openReadinessCancel = nil
	a.openReadinessPaths = nil
	a.openReadinessCollectLate = false
	a.openReadinessLastAppend = time.Time{}
	a.openReadinessChoicePaths = nil
	a.clearCloudApplyRecordLocked()
	if (cancel != nil && activePaths) || freshCloudApply {
		until := time.Now().Add(openedPathCloudCancelSuppressDelay)
		if freshCloudApply {
			// Stragglers of the cancelled gesture may keep arriving for the
			// rest of the post-apply merge window; suppress them for that long
			// so they cannot stomp the selection the user just made.
			if cloudUntil := appliedAt.Add(openedPathCloudPostApplyMergeDelay); cloudUntil.After(until) {
				until = cloudUntil
			}
		}
		a.openReadinessSuppressUntil = until
	}
	a.openReadinessMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (a *App) beginOpenedPathReadiness(paths []string) (context.Context, uint64, *workerReservation, bool) {
	ctx, cancel := context.WithCancel(a.workers.ctx)
	reservation, ok := a.workers.reserve()
	if !ok {
		cancel()
		return nil, 0, nil, false
	}

	a.openReadinessMu.Lock()
	if a.workers.isStopping() {
		a.openReadinessMu.Unlock()
		cancel()
		reservation.release()
		return nil, 0, nil, false
	}
	previousCancel := a.openReadinessCancel
	a.openReadinessGeneration++
	generation := a.openReadinessGeneration
	a.openReadinessCancel = cancel
	a.openReadinessPaths = append([]string(nil), paths...)
	a.openReadinessCollectLate = false
	a.openReadinessLastAppend = time.Now()
	a.openReadinessMu.Unlock()

	if previousCancel != nil {
		previousCancel()
	}
	return ctx, generation, reservation, true
}

func (a *App) isOpenedPathReadinessCurrent(generation uint64) bool {
	if a.workers.isStopping() {
		return false
	}
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	return !a.workers.isStopping() && a.openReadinessGeneration == generation && a.openReadinessCancel != nil
}

func (a *App) finishOpenedPathReadiness(generation uint64) {
	a.openReadinessMu.Lock()
	cancel := a.openReadinessCancel
	current := a.openReadinessGeneration == generation
	if current {
		a.openReadinessCancel = nil
		a.openReadinessPaths = nil
		a.openReadinessCollectLate = false
		a.openReadinessLastAppend = time.Time{}
		a.openReadinessChoicePaths = nil
	} else {
		cancel = nil
	}
	a.openReadinessMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if current {
		a.hideOpenedPathSelectionChoice()
	}
}

// openedPathReadinessUIGuard reports whether the readiness session may touch
// the UI right now. Working always finishes the session: the user started an
// operation and opened paths must not interfere. Scanning finishes it too,
// unless a recent cloud selection is still scanning — then the session stays
// alive so it can present the incoming selection after the scan settles.
// A manual drop, Clear, or Start clears that
// record via cancelOpenedPathReadiness, so foreign scans always finish the
// session, preserving the user's selection.
func (a *App) openedPathReadinessUIGuard(generation uint64) bool {
	if !a.isOpenedPathReadinessCurrent(generation) {
		return false
	}
	snap := a.State.UISnapshot()
	if snap.Working {
		a.finishOpenedPathReadiness(generation)
		return false
	}
	if snap.Scanning {
		if !a.hasRecentCloudApply() {
			a.finishOpenedPathReadiness(generation)
		}
		return false
	}
	return true
}

func (a *App) openedPathReadinessCanUpdateUI(generation uint64) bool {
	if !a.isOpenedPathReadinessCurrent(generation) {
		return false
	}

	snap := a.State.UISnapshot()
	if snap.Working || snap.Scanning {
		a.finishOpenedPathReadiness(generation)
		return false
	}
	return true
}

func (a *App) openedPathReadinessSnapshot(generation uint64) ([]string, bool) {
	if a.workers.isStopping() {
		return nil, false
	}
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.workers.isStopping() || a.openReadinessGeneration != generation || a.openReadinessCancel == nil {
		return nil, false
	}
	return append([]string(nil), a.openReadinessPaths...), true
}

// enableLateOpenedPathCollection marks the session as cloud-backed so that
// openedPathCloudSettleRemaining holds the apply open for trailing batches.
// It does NOT gate merging: mergeLateOpenedPaths extends any active session.
func (a *App) enableLateOpenedPathCollection(generation uint64) {
	if a.workers.isStopping() {
		return
	}
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.workers.isStopping() || a.openReadinessGeneration != generation || a.openReadinessCancel == nil {
		return
	}
	a.openReadinessCollectLate = true
}

// mergeLateOpenedPaths extends the active readiness session with paths from a
// later openURLs: batch of the same gesture. Merging before apply is always
// safe: the session re-checks readiness for the combined set before applying.
func (a *App) mergeLateOpenedPaths(paths []string) bool {
	if a.workers.isStopping() {
		return false
	}
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.workers.isStopping() || a.openReadinessCancel == nil {
		return false
	}

	seen := make(map[string]struct{}, len(a.openReadinessPaths)+len(paths))
	for _, path := range a.openReadinessPaths {
		seen[path] = struct{}{}
	}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		a.openReadinessPaths = append(a.openReadinessPaths, path)
	}
	a.openReadinessLastAppend = time.Now()
	return true
}

// cloudApplyMergeableLocked reports whether a later batch could belong to the
// applied cloud selection. It does not establish that they are the same gesture.
// Callers must hold openReadinessMu.
func (a *App) cloudApplyMergeableLocked() bool {
	if len(a.openReadinessAppliedPaths) == 0 {
		return false
	}
	return len(a.openReadinessChoicePaths) > 0 ||
		time.Since(a.openReadinessAppliedAt) <= openedPathCloudPostApplyMergeDelay
}

// clearCloudApplyRecordLocked drops the post-apply merge record. Callers must
// hold openReadinessMu.
func (a *App) clearCloudApplyRecordLocked() {
	a.openReadinessAppliedPaths = nil
	a.openReadinessAppliedAt = time.Time{}
}

// hasRecentCloudApply is the lock-acquiring form of cloudApplyMergeableLocked.
func (a *App) hasRecentCloudApply() bool {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	return a.cloudApplyMergeableLocked()
}

// retainPendingOpenedPaths keeps every incoming URL while an explicit choice
// is pending. The applied selection stays separate until the user chooses Add.
func (a *App) retainPendingOpenedPaths(paths []string) []string {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if !a.cloudApplyMergeableLocked() {
		a.clearCloudApplyRecordLocked()
		return paths
	}
	return normalizeOpenedPaths(append(append([]string(nil), a.openReadinessChoicePaths...), paths...))
}

func (a *App) finishOpenedPathReadinessIfPathsCurrent(generation uint64, paths []string, hadCloudItem bool) (bool, []string) {
	if a.workers.isStopping() {
		return false, nil
	}
	a.openReadinessMu.Lock()
	if a.workers.isStopping() || a.openReadinessGeneration != generation || a.openReadinessCancel == nil {
		a.openReadinessMu.Unlock()
		return false, nil
	}
	if !sameStringSlices(a.openReadinessPaths, paths) {
		a.openReadinessMu.Unlock()
		return false, nil
	}
	var previous []string
	if a.cloudApplyMergeableLocked() {
		previous = append([]string(nil), a.openReadinessAppliedPaths...)
	}
	cancel := a.openReadinessCancel
	a.openReadinessCancel = nil
	a.openReadinessPaths = nil
	a.openReadinessCollectLate = false
	a.openReadinessLastAppend = time.Time{}
	if len(previous) > 0 {
		a.openReadinessChoicePaths = append([]string(nil), paths...)
	} else if hadCloudItem {
		a.openReadinessAppliedPaths = append([]string(nil), paths...)
		a.openReadinessAppliedAt = time.Now()
	} else {
		a.clearCloudApplyRecordLocked()
	}
	a.openReadinessMu.Unlock()

	if cancel != nil {
		cancel()
	}
	return true, previous
}

func (a *App) suppressesOpenedPaths() bool {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.openReadinessSuppressUntil.IsZero() {
		return false
	}
	now := time.Now()
	if now.Before(a.openReadinessSuppressUntil) {
		// A straggler stream keeps the window alive, but re-arming must only
		// ever EXTEND it: cancelOpenedPathReadiness may have armed a longer
		// window covering the rest of the post-apply merge period.
		if until := now.Add(openedPathCloudCancelSuppressDelay); until.After(a.openReadinessSuppressUntil) {
			a.openReadinessSuppressUntil = until
		}
		return true
	}
	a.openReadinessSuppressUntil = time.Time{}
	return false
}

func (a *App) openedPathCloudSettleRemaining(generation uint64) time.Duration {
	if a.workers.isStopping() {
		return 0
	}
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.workers.isStopping() || a.openReadinessGeneration != generation || a.openReadinessCancel == nil || !a.openReadinessCollectLate {
		return 0
	}
	if openedPathCloudSettleDelay <= 0 {
		return 0
	}
	remaining := openedPathCloudSettleDelay - time.Since(a.openReadinessLastAppend)
	if remaining <= 0 {
		return 0
	}
	return remaining
}

func applyOpenedPathPreparingStatus(a *App, generation uint64) {
	if !a.isOpenedPathReadinessCurrent(generation) {
		return
	}
	fyne.Do(func() {
		if !a.openedPathReadinessUIGuard(generation) {
			return
		}
		a.State.SetStatusMessage(app.StatusOpenedPathsPreparing, util.YELLOW, app.StatusArgs{})
		a.refreshUI()
	})
}

func (a *App) applyOpenedPaths(paths []string) {
	if a.workers.isStopping() {
		return
	}
	normalized := normalizeOpenedPaths(paths)
	if len(normalized) == 0 {
		return
	}
	if a.suppressesOpenedPaths() {
		return
	}
	if a.mergeLateOpenedPaths(normalized) {
		return
	}
	normalized = a.retainPendingOpenedPaths(normalized)

	ctx, generation, reservation, ok := a.beginOpenedPathReadiness(normalized)
	if !ok {
		return
	}
	reservation.launch(func(context.Context) {
		a.waitForOpenedPathsAndApply(ctx, generation)
	})
}

func (a *App) waitForOpenedPathsAndApply(ctx context.Context, generation uint64) {
	ctx, cancel := context.WithTimeout(ctx, openedPathReadyTimeout)
	defer cancel()

	for {
		if !a.isOpenedPathReadinessCurrent(generation) {
			return
		}
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				a.applyOpenedPathReadinessTimeout(generation)
			}
			return
		}

		if a.State.IsScanning() && a.hasRecentCloudApply() {
			// A folder scan from the earlier cloud selection is
			// running; skip the readiness checks (cgo per-path queries on
			// darwin) and the UI round-trip until it settles.
			if sleepOrCancel(ctx, openedPathPollInterval) {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					a.applyOpenedPathReadinessTimeout(generation)
				}
				return
			}
			continue
		}

		paths, ok := a.openedPathReadinessSnapshot(generation)
		if !ok {
			return
		}
		result := checkOpenedPathReadiness(ctx, paths)

		if !a.isOpenedPathReadinessCurrent(generation) {
			return
		}
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				a.applyOpenedPathReadinessTimeout(generation)
			}
			return
		}
		if err := result.terminalError(); err != nil {
			a.applyOpenedPathReadinessError(generation)
			return
		}
		if result.hasUbiquitousFile() {
			a.enableLateOpenedPathCollection(generation)
		}
		if result.allReady() {
			if remaining := a.openedPathCloudSettleRemaining(generation); remaining > 0 {
				applyOpenedPathPreparingStatus(a, generation)
				if sleepOrCancel(ctx, minDuration(openedPathPollInterval, remaining)) {
					if errors.Is(ctx.Err(), context.DeadlineExceeded) {
						a.applyOpenedPathReadinessTimeout(generation)
					}
					return
				}
				continue
			}
			if a.applyReadyOpenedPaths(generation, paths, result.hasUbiquitousItem()) {
				return
			}
			if !a.isOpenedPathReadinessCurrent(generation) {
				return
			}
			if sleepOrCancel(ctx, openedPathPollInterval) {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					a.applyOpenedPathReadinessTimeout(generation)
				}
				return
			}
			continue
		}

		applyOpenedPathPreparingStatus(a, generation)

		if sleepOrCancel(ctx, openedPathPollInterval) {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				a.applyOpenedPathReadinessTimeout(generation)
			}
			return
		}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func sameStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (a *App) applyReadyOpenedPaths(generation uint64, paths []string, hadCloudItem bool) bool {
	applied := false
	beforeOpenedPathReadyApply()
	if !a.isOpenedPathReadinessCurrent(generation) {
		return false
	}
	fyne.DoAndWait(func() {
		if !a.openedPathReadinessUIGuard(generation) {
			return
		}
		finished, previous := a.finishOpenedPathReadinessIfPathsCurrent(generation, paths, hadCloudItem)
		if !finished {
			return
		}
		if len(previous) > 0 {
			a.showOpenedPathSelectionChoice(generation, previous, paths, hadCloudItem)
		} else {
			a.applyStartupPaths(paths)
		}
		applied = true
	})
	return applied
}

func (a *App) showOpenedPathSelectionChoice(generation uint64, previous, incoming []string, incomingHadCloud bool) {
	a.hideOpenedPathSelectionChoice()
	selectionGeneration := a.operationGeneration.Load()
	takeChoice := func(consume bool) bool {
		current := a.State.UISnapshot()
		if a.workers.isStopping() || a.operationGeneration.Load() != selectionGeneration || current.Working || current.Scanning {
			return false
		}
		a.openReadinessMu.Lock()
		defer a.openReadinessMu.Unlock()
		if a.openReadinessGeneration != generation ||
			!sameStringSlices(a.openReadinessChoicePaths, incoming) {
			return false
		}
		if consume {
			a.openReadinessChoicePaths = nil
			a.clearCloudApplyRecordLocked()
		}
		return true
	}
	var choice dialog.Dialog
	selectPaths := func(add bool) {
		if !takeChoice(true) {
			return
		}
		paths := incoming
		if add {
			paths = normalizeOpenedPaths(append(append([]string(nil), previous...), incoming...))
		}
		choice.Hide()
		applied := a.applyStartupPaths(paths)
		if (add || incomingHadCloud) && len(applied) > 0 {
			a.openReadinessMu.Lock()
			if !a.workers.isStopping() && a.openReadinessGeneration == generation && len(applied) > 0 {
				a.openReadinessAppliedPaths = applied
				a.openReadinessAppliedAt = time.Now()
			}
			a.openReadinessMu.Unlock()
		}
	}
	previousList := strings.Join(previous, "\n")
	incomingList := strings.Join(incoming, "\n")
	message := widget.NewLabel(tr("opened_paths.choice_message", "Replace the current selection or add the new files?"))
	message.Wrapping = fyne.TextWrapWord
	previousLabel := widget.NewLabel(previousList)
	previousLabel.Wrapping = fyne.TextWrapBreak
	previousLabel.Selectable = true
	incomingLabel := widget.NewLabel(incomingList)
	incomingLabel.Wrapping = fyne.TextWrapBreak
	incomingLabel.Selectable = true
	content := container.NewVBox(
		message,
		widget.NewLabel(tr("opened_paths.current_selection", "Current selection:")),
		previousLabel,
		widget.NewLabel(tr("opened_paths.incoming_selection", "New files:")),
		incomingLabel,
	)
	actions := container.NewVBox(
		container.NewGridWithColumns(2,
			widget.NewButton(tr("opened_paths.replace_selection", "Replace selection"), func() { selectPaths(false) }),
			widget.NewButton(tr("opened_paths.add_files", "Add files"), func() { selectPaths(true) }),
		),
		widget.NewButton(tr("action.cancel", "Cancel"), func() { choice.Hide() }),
	)
	choice = dialog.NewCustomWithoutButtons(tr("opened_paths.choice_title", "New files opened"), container.NewBorder(nil, actions, nil, nil, container.NewVScroll(content)), a.Window)
	choice.SetOnClosed(func() {
		if takeChoice(false) {
			a.cancelOpenedPathReadiness()
		}
		if a.openedPathChoice == choice {
			a.openedPathChoice = nil
		}
	})
	a.openedPathChoice = choice
	size := a.Window.Canvas().Size()
	choice.Resize(fyne.NewSize(min(size.Width*0.9, 600), min(size.Height*0.8, 400)))
	choice.Show()
}

// hideOpenedPathSelectionChoice is called only on the Fyne thread. The caller
// first invalidates or consumes the choice so dismissal cannot authorize it.
func (a *App) hideOpenedPathSelectionChoice() {
	choice := a.openedPathChoice
	a.openedPathChoice = nil
	if choice != nil {
		choice.Hide()
	}
}

func (a *App) applyOpenedPathReadinessError(generation uint64) {
	if !a.isOpenedPathReadinessCurrent(generation) {
		return
	}
	fyne.Do(func() {
		if !a.openedPathReadinessCanUpdateUI(generation) {
			return
		}

		a.finishOpenedPathReadiness(generation)
		a.State.SetStatusMessage(app.StatusStartupPathAccessFailed, util.RED, app.StatusArgs{})
		a.refreshUI()
	})
}

func (a *App) applyOpenedPathReadinessTimeout(generation uint64) {
	if !a.isOpenedPathReadinessCurrent(generation) {
		return
	}
	fyne.Do(func() {
		if !a.openedPathReadinessCanUpdateUI(generation) {
			return
		}

		a.finishOpenedPathReadiness(generation)
		a.State.SetStatusMessage(app.StatusOpenedPathsTimeout, util.YELLOW, app.StatusArgs{})
		a.refreshUI()
	})
}
