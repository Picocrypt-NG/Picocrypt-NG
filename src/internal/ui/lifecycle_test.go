package ui

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/util"
	"context"
	"image/color"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"fyne.io/fyne/v2"
)

func TestWorkerGroupStopWaitsForReservedWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		workers := newWorkerLifecycle()
		reservation, ok := workers.reserve()
		if !ok {
			t.Fatal("initial worker reservation was rejected")
		}

		if !workers.beginStop() {
			t.Fatal("first stop request was rejected")
		}
		if _, ok := workers.reserve(); ok {
			t.Fatal("worker reservation succeeded after shutdown began")
		}

		waitReturned := make(chan struct{})
		go func() {
			workers.wait()
			close(waitReturned)
		}()
		synctest.Wait()

		select {
		case <-waitReturned:
			t.Fatal("worker wait returned before the accepted reservation was completed")
		default:
		}

		workerSawCancellation := make(chan bool, 1)
		reservation.launch(func(ctx context.Context) {
			workerSawCancellation <- ctx.Err() != nil
		})
		synctest.Wait()

		if !<-workerSawCancellation {
			t.Fatal("worker launched after stop did not inherit the cancelled lifecycle context")
		}
		select {
		case <-waitReturned:
		default:
			t.Fatal("worker wait did not return after the accepted reservation completed")
		}
	})
}

func TestOrderlyShutdownWaitsForAcceptedOpenedPathCallback(t *testing.T) {
	resetOpenedPathsForTest(t)
	fyneApp := newTestFyneApp(t)

	a, err := NewApp("test")
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	a.fyneApp = fyneApp
	a.Window = fyneApp.NewWindow("shutdown-test")

	closed := make(chan struct{})
	a.Window.SetOnClosed(func() {
		close(closed)
	})

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	setOpenedPathsNotify(func() {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
	})

	openedPathsMu.Lock()
	generation := openedPathsGeneration
	openedPathsMu.Unlock()
	notifyReturned := make(chan struct{})
	go func() {
		notifyOpenedPaths(generation)
		close(notifyReturned)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the opened-path callback to start")
	}

	fyne.DoAndWait(a.beginOrderlyShutdown)
	workersDone := a.workersDone
	fyne.DoAndWait(a.shutdownSentinelTick)
	select {
	case <-closed:
		t.Fatal("window closed while an accepted opened-path callback was still running")
	default:
	}

	close(release)
	select {
	case <-notifyReturned:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the opened-path callback to return")
	}
	select {
	case <-workersDone:
	case <-time.After(time.Second):
		t.Fatal("orderly shutdown did not finish after the accepted callback returned")
	}

	setOpenedPathsNotify(func() {
		calls.Add(1)
	})
	appendOpenedPath("/tmp/post-stop.txt")
	flushOpenedPaths()
	openedPathsMu.Lock()
	postStopGeneration := openedPathsGeneration
	openedPathsMu.Unlock()
	notifyOpenedPaths(postStopGeneration)
	if got := calls.Load(); got != 1 {
		t.Fatalf("opened-path handler calls after shutdown = %d; want no call after the accepted callback", got-1)
	}

	fyne.DoAndWait(a.shutdownSentinelTick)
	select {
	case <-closed:
	default:
		t.Fatal("window remained open after all accepted callbacks and workers completed")
	}
}

func TestOrderlyShutdownCancelsAndJoinsFolderScan(t *testing.T) {
	t.Run("StoppingSuppressesAcceptedScanResults", func(t *testing.T) {
		resetOpenedPathsForTest(t)
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)

		root := t.TempDir()
		payload := filepath.Join(root, "payload.txt")
		if err := os.WriteFile(payload, []byte("payload"), 0o600); err != nil {
			t.Fatalf("create payload: %v", err)
		}

		reservation, ok := a.workers.reserve()
		if !ok {
			t.Fatal("folder scan reservation was rejected before shutdown")
		}

		const baselineStatus = "waiting for folder scan"
		var generation uint64
		var baselineInput string
		var baselineSummaryKind int
		fyne.DoAndWait(func() {
			a.folderScanGeneration++
			generation = a.folderScanGeneration
			a.State.SetScanning(true)
			a.State.SetInputScanning(0)
			a.State.SetStatus(baselineStatus, color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff})
			a.refreshUI()
			baselineInput = a.inputLabel.Text
			baselineSummaryKind = int(a.State.UISnapshot().InputSummary.Kind)
		})

		candidate, err := fileops.InspectZIPInput(root)
		if err != nil {
			t.Fatal(err)
		}
		job := folderScanJob{
			roots:       []fileops.ZIPInputCandidate{candidate},
			folderCount: 1,
			generation:  generation,
		}
		realEmitter := a.scannedFileEmitter(generation)
		entered := make(chan context.Context, 1)
		release := make(chan struct{})
		emit := func(ctx context.Context, batch []scannedFile) error {
			entered <- ctx
			<-release
			return realEmitter(ctx, batch)
		}
		reservation.launch(func(ctx context.Context) {
			a.runFolderScan(ctx, job, emit)
		})

		var scanCtx context.Context
		select {
		case scanCtx = <-entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for the real scanner batch callback")
		}

		fyne.DoAndWait(a.beginOrderlyShutdown)
		workersDone := a.workersDone
		select {
		case <-scanCtx.Done():
		case <-time.After(time.Second):
			t.Fatal("folder scanner context was not cancelled by shutdown")
		}
		select {
		case <-workersDone:
			t.Fatal("shutdown completed before the accepted scanner callback returned")
		default:
		}

		close(release)
		select {
		case <-workersDone:
		case <-time.After(time.Second):
			t.Fatal("shutdown did not complete after the accepted scanner returned")
		}

		var inputText string
		var summaryKind int
		var statusText string
		fyne.DoAndWait(func() {
			snap := a.State.UISnapshot()
			inputText = a.inputLabel.Text
			summaryKind = int(snap.InputSummary.Kind)
			statusText = snap.Status.Text
		})
		state := snapshotDropState(t, a)
		if len(state.AllFiles) != 0 {
			t.Fatalf("files applied after shutdown = %#v; want none", state.AllFiles)
		}
		if inputText != baselineInput || summaryKind != baselineSummaryKind {
			t.Fatalf("final selection/refresh applied after shutdown: input=%q kind=%d; want %q scanning", inputText, summaryKind, baselineInput)
		}
		if statusText != baselineStatus {
			t.Fatalf("status after cancelled scan = %q; want unchanged %q", statusText, baselineStatus)
		}

		fyne.DoAndWait(a.shutdownSentinelTick)
	})

	t.Run("NormalCompletionClearsScanning", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		root := t.TempDir()
		want := filepath.Join(root, "payload.txt")
		if err := os.WriteFile(want, []byte("payload"), 0o600); err != nil {
			t.Fatalf("create payload: %v", err)
		}

		fyne.DoAndWait(func() {
			a.onDrop([]string{root})
		})
		waitForDropProcessing(t, a)
		if a.State.IsScanning() {
			t.Fatal("Scanning remained true after a normal folder scan")
		}
		if got := snapshotDropState(t, a).AllFiles; !reflect.DeepEqual(got, []string{want}) {
			t.Fatalf("normal scan files = %#v; want %#v", got, []string{want})
		}
	})
}

type closeInterceptCaptureWindow struct {
	fyne.Window
	closeIntercept func()
}

func (w *closeInterceptCaptureWindow) SetCloseIntercept(fn func()) {
	w.closeIntercept = fn
}

func TestOrderlyShutdownCancelsAndJoinsOpenedPathReadiness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		resetOpenedPathsForTest(t)
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		window := &closeInterceptCaptureWindow{Window: a.Window}
		a.Window = window
		a.Window.SetCloseIntercept(a.handleCloseRequest)

		tempDir := t.TempDir()
		baselinePath := filepath.Join(tempDir, "baseline.txt")
		latePath := filepath.Join(tempDir, "late.txt")
		for _, path := range []string{baselinePath, latePath} {
			if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
				t.Fatalf("create test input %q: %v", path, err)
			}
		}

		const baselineStatus = "selection before shutdown"
		fyne.DoAndWait(func() {
			a.onDrop([]string{baselinePath})
			a.State.SetCustomStatus(baselineStatus, util.WHITE)
			a.refreshUI()
		})
		baseline := snapshotDropState(t, a)

		oldCheck := checkOpenedPathReadiness
		t.Cleanup(func() {
			checkOpenedPathReadiness = oldCheck
		})
		checkerEntered := make(chan context.Context, 1)
		checkerCancelled := make(chan struct{})
		releaseChecker := make(chan struct{})
		var releaseOnce sync.Once
		t.Cleanup(func() {
			releaseOnce.Do(func() { close(releaseChecker) })
		})
		checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
			checkerEntered <- ctx
			<-ctx.Done()
			close(checkerCancelled)
			<-releaseChecker
			return openedPathReadinessResult{{Path: paths[0], State: openedPathReady}}
		}

		setOpenedPathsNotify(func() {})
		fyne.DoAndWait(func() {
			a.applyOpenedPaths([]string{latePath})
		})
		readinessCtx := <-checkerEntered

		fyne.DoAndWait(window.closeIntercept)
		workersDone := a.workersDone
		synctest.Wait()

		select {
		case <-readinessCtx.Done():
		default:
			t.Fatal("readiness context was not cancelled by shutdown")
		}
		select {
		case <-checkerCancelled:
		default:
			t.Fatal("readiness checker did not observe shutdown cancellation")
		}
		openedPathsMu.Lock()
		notifyCleared := openedPathsNotify == nil
		openedPathsMu.Unlock()
		if !notifyCleared {
			t.Fatal("opened-path notification source remained registered during shutdown")
		}
		select {
		case <-workersDone:
			t.Fatal("shutdown completed before the accepted readiness checker returned")
		default:
		}

		releaseOnce.Do(func() { close(releaseChecker) })
		synctest.Wait()
		select {
		case <-workersDone:
		default:
			t.Fatal("shutdown did not complete after the accepted readiness checker returned")
		}

		if got := snapshotDropState(t, a); !reflect.DeepEqual(got, baseline) {
			t.Fatalf("late readiness result changed selection/status after shutdown: got %#v; want %#v", got, baseline)
		}
		fyne.DoAndWait(a.shutdownSentinelTick)
	})
}
