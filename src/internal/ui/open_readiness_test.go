package ui

import (
	"Picocrypt-NG/internal/app"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func TestNormalizeOpenedPathsFiltersProcessSerialAndDedupesInOrder(t *testing.T) {
	got := normalizeOpenedPaths([]string{
		"-psn_0_12345",
		"/tmp/a.txt",
		"",
		"/tmp/b.txt",
		"/tmp/a.txt",
	})
	want := []string{"/tmp/a.txt", "/tmp/b.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeOpenedPaths() = %#v; want %#v", got, want)
	}
}

func TestOpenedPathReadinessResultRequiresAllCurrent(t *testing.T) {
	ready := openedPathReadinessResult{
		{Path: "/tmp/current.txt", State: openedPathReady},
		{Path: "/tmp/stale.txt", State: openedPathPending},
	}
	if ready.allReady() {
		t.Fatal("allReady() = true with a pending path; want false")
	}
}

func TestOpenedPathReadinessResultReportsTerminalErrors(t *testing.T) {
	errAccess := errors.New("permission denied")
	result := openedPathReadinessResult{
		{Path: "/tmp/a.txt", State: openedPathReady},
		{Path: "/tmp/blocked.txt", State: openedPathError, Err: errAccess},
	}
	if result.terminalError() == nil {
		t.Fatal("terminalError() = nil; want access error")
	}
}

func cloudFollowupTestApp(t *testing.T) (*App, []string) {
	t.Helper()
	resetOpenedPathsForTest(t)
	oldCheck, oldPoll, oldSettle := checkOpenedPathReadiness, openedPathPollInterval, openedPathCloudSettleDelay
	t.Cleanup(func() {
		checkOpenedPathReadiness, openedPathPollInterval, openedPathCloudSettleDelay = oldCheck, oldPoll, oldSettle
	})
	openedPathPollInterval, openedPathCloudSettleDelay = 5*time.Millisecond, 0
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "cloud-first.txt"), filepath.Join(dir, "local-second.txt"), filepath.Join(dir, "local-third.txt")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checkOpenedPathReadiness = func(ctx context.Context, opened []string) openedPathReadinessResult {
		result := defaultOpenedPathReadiness(ctx, opened)
		for i := range result {
			result[i].IsUbiquitous = result[i].Path == paths[0]
		}
		return result
	}
	a.applyOpenedPaths(paths[:1])
	waitForAllFiles(t, a, paths[:1])
	return a, paths
}

func waitForOpenedPathReadinessIdle(t *testing.T, a *App) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.openReadinessMu.Lock()
		active := a.openReadinessCancel != nil
		a.openReadinessMu.Unlock()
		if !active && !a.State.IsScanning() {
			fyne.DoAndWait(func() {})
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("opened-path readiness did not finish")
}

func chooseCloudFollowup(t *testing.T, a *App, action string) {
	t.Helper()
	waitForOpenedPathReadinessIdle(t, a)
	_, buttons := outputPickerControls(t, a)
	if buttons[action] == nil {
		t.Fatalf("opened-path choice has no %q action", action)
	}
	test.Tap(buttons[action])
}

func TestCloudFollowupRequiresExplicitSelectionDecision(t *testing.T) {
	for _, action := range []string{"Add files", "Replace selection", "Cancel"} {
		t.Run(action, func(t *testing.T) {
			a, paths := cloudFollowupTestApp(t)
			a.applyOpenedPaths(paths[1:2])
			waitForOpenedPathReadinessIdle(t, a)
			if got := snapshotDropState(t, a).AllFiles; !reflect.DeepEqual(got, paths[:1]) {
				t.Fatalf("separate open silently changed selection before consent: %v", got)
			}
			var displayed []string
			for _, object := range test.LaidOutObjects(a.Window.Canvas().Overlays().Top()) {
				if label, ok := object.(*widget.Label); ok {
					displayed = append(displayed, label.Text)
				}
			}
			text := strings.Join(displayed, "\n")
			for _, path := range paths[:2] {
				if !strings.Contains(text, path) {
					t.Fatalf("choice omitted selected/incoming path %q: %q", path, text)
				}
			}
			chooseCloudFollowup(t, a, action)
			want := paths[:1]
			if action == "Add files" {
				want = paths[:2]
			} else if action == "Replace selection" {
				want = paths[1:2]
			}
			waitForAllFiles(t, a, want)
			for _, path := range paths {
				if data, err := os.ReadFile(path); err != nil || string(data) != filepath.Base(path) {
					t.Fatalf("selection decision modified %q: %q, %v", path, data, err)
				}
			}
		})
	}
}

func TestCloudFollowupStaleAnswerPreservesManualSelection(t *testing.T) {
	a, paths := cloudFollowupTestApp(t)
	a.applyOpenedPaths(paths[1:2])
	waitForOpenedPathReadinessIdle(t, a)
	_, buttons := outputPickerControls(t, a)
	add := buttons["Add files"]
	if add == nil {
		t.Fatal("ambiguous followup did not offer an explicit choice")
	}
	fyne.DoAndWait(func() {
		a.cancelOpenedPathReadiness()
		a.onDrop(paths[2:])
	})
	waitForAllFiles(t, a, paths[2:])
	test.Tap(add)
	if got := snapshotDropState(t, a).AllFiles; !reflect.DeepEqual(got, paths[2:]) {
		t.Fatalf("stale answer replaced a manual selection: %v", got)
	}
}

func TestCloudFollowupNewArrivalRequiresUpdatedConsentWithoutLosingPaths(t *testing.T) {
	a, paths := cloudFollowupTestApp(t)
	a.applyOpenedPaths(paths[1:2])
	waitForOpenedPathReadinessIdle(t, a)
	_, buttons := outputPickerControls(t, a)
	oldAdd := buttons["Add files"]
	if oldAdd == nil {
		t.Fatal("ambiguous followup did not offer an explicit choice")
	}
	a.applyOpenedPaths(paths[2:])
	waitForOpenedPathReadinessIdle(t, a)
	test.Tap(oldAdd)
	if got := snapshotDropState(t, a).AllFiles; !reflect.DeepEqual(got, paths[:1]) {
		t.Fatalf("old consent authorized a later arrival: %v", got)
	}
	chooseCloudFollowup(t, a, "Add files")
	waitForAllFiles(t, a, paths)
}

func TestCloudFollowupMissingArrivalRejectsPendingBatchAndPreservesSelection(t *testing.T) {
	a, paths := cloudFollowupTestApp(t)
	a.applyOpenedPaths(paths[1:2])
	waitForOpenedPathReadinessIdle(t, a)
	a.applyOpenedPaths([]string{filepath.Join(filepath.Dir(paths[0]), "missing.txt")})
	waitForOpenedPathReadinessIdle(t, a)
	if got := snapshotDropState(t, a).AllFiles; !reflect.DeepEqual(got, paths[:1]) {
		t.Fatalf("failed incoming batch changed current selection: %v", got)
	}
	if status := a.State.UISnapshot().Status.Kind; status != app.StatusStartupPathAccessFailed {
		t.Fatalf("unreadable incoming batch was not reported: %v", status)
	}
	if a.Window.Canvas().Overlays().Top() != nil {
		t.Fatal("failed incoming batch left an obsolete selection decision open")
	}
}

func TestCloudFollowupAcceptedSelectionStillRequiresConsentForLaterArrival(t *testing.T) {
	for _, action := range []string{"Add files", "Replace selection"} {
		t.Run(action, func(t *testing.T) {
			a, paths := cloudFollowupTestApp(t)
			if action == "Replace selection" {
				checkOpenedPathReadiness = func(ctx context.Context, opened []string) openedPathReadinessResult {
					result := defaultOpenedPathReadiness(ctx, opened)
					for i := range result {
						result[i].IsUbiquitous = result[i].Path != paths[2]
					}
					return result
				}
			}
			a.applyOpenedPaths(paths[1:2])
			chooseCloudFollowup(t, a, action)
			want := paths[:2]
			if action == "Replace selection" {
				want = paths[1:2]
			}
			waitForAllFiles(t, a, want)
			a.applyOpenedPaths(paths[2:])
			waitForOpenedPathReadinessIdle(t, a)
			if got := snapshotDropState(t, a).AllFiles; !reflect.DeepEqual(got, want) {
				t.Fatalf("later arrival silently replaced an accepted cloud selection: %v", got)
			}
			chooseCloudFollowup(t, a, "Add files")
			waitForAllFiles(t, a, append(append([]string(nil), want...), paths[2:]...))
		})
	}
}

func TestCloudFollowupLocalReplacementEndsCloudAmbiguity(t *testing.T) {
	a, paths := cloudFollowupTestApp(t)
	a.applyOpenedPaths(paths[1:2])
	chooseCloudFollowup(t, a, "Replace selection")
	waitForAllFiles(t, a, paths[1:2])
	a.applyOpenedPaths(paths[2:])
	waitForAllFiles(t, a, paths[2:])
	if a.Window.Canvas().Overlays().Top() != nil {
		t.Fatal("ordinary local replacement retained a cloud selection prompt")
	}
}
