package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

// The injected executor supplies legacy trust outcomes; actual Fyne selection,
// source-deletion manifests, batch aggregation and terminal rendering run here.
// Cryptographic authentication is covered by the volume/golden lanes.
func TestRecursiveLegacyUnverifiedResultsSurviveLaterItemsAndFinalization(t *testing.T) {
	failure := errors.New("payload authentication refused")
	for _, tc := range []struct {
		name             string
		items            []operationResult
		verified, failed int
		cancelled        bool
	}{
		{"kept_then_clean", []operationResult{{completed: true, kept: true}, {completed: true}}, 1, 0, false},
		{"clean_then_kept", []operationResult{{completed: true}, {completed: true, kept: true}}, 1, 0, false},
		{"all_kept", []operationResult{{completed: true, kept: true}, {completed: true, kept: true}}, 0, 0, false},
		{"failure_kept_clean", []operationResult{{err: failure}, {completed: true, kept: true}, {completed: true}}, 1, 1, false},
		{"kept_then_cancelled", []operationResult{{completed: true, kept: true}, {cancelled: true}}, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetLocalizationForTest(t)
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)
			dir := t.TempDir()
			fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
			if err != nil {
				t.Fatal(err)
			}
			files := make([]string, len(tc.items))
			for i := range files {
				files[i] = filepath.Join(dir, fmt.Sprintf("input-%d.txt.pcv", i))
				if err := os.WriteFile(files[i], fixture, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var session *operationSession
			var saved app.RecursiveSnapshot
			fyne.DoAndWait(func() {
				a.State.Mode = "decrypt"
				a.State.Recursively = true
				a.State.Password = "test"
				a.State.Keep = true
				a.State.Delete = true
				a.State.SetWorking(true)
				saved = a.State.RecursiveSnapshot()
				session = a.newOperationSession()
				a.setOperationSession(session)
			})
			defer session.cancel()
			index := 0
			executor := func(context.Context, operationInput, volume.ProgressReporter) operationResult {
				result := tc.items[index]
				index++
				return result
			}
			lastInput, result := a.runRecursiveOperation(session, executor, nil, files, saved)
			unverified := 0
			for _, item := range tc.items {
				if item.completed && item.kept && item.err == nil && !item.cancelled {
					unverified++
				}
			}
			if !result.kept || result.unverified != unverified || result.succeeded != tc.verified || result.failed != tc.failed || result.cancelled != tc.cancelled {
				t.Errorf("batch lost trust/counts: %+v", result)
			}
			if tc.failed != 0 && !errors.Is(result.err, failure) {
				t.Errorf("later result erased earlier failure: %v", result.err)
			}
			for i, item := range tc.items {
				_, err := os.Lstat(files[i])
				if item.kept || item.err != nil || item.cancelled {
					if err != nil {
						t.Errorf("unsafe source deletion for item %d: %v", i, err)
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("clean source deletion did not run for item %d: %v", i, err)
				}
			}
			fyne.DoAndWait(func() { a.finalizeOperation(session, lastInput, result, true) })
			snap := a.State.UISnapshot()
			text := renderStatus(snap.Status, snap)
			if !a.State.WasKept() || snap.Status.Color != util.YELLOW || !strings.Contains(text, "unverified") {
				t.Errorf("terminal UI erased recovery warning: kept=%t status=%+v text=%q", a.State.WasKept(), snap.Status, text)
			}
			if tc.cancelled && !strings.Contains(text, "cancelled") {
				t.Errorf("terminal UI erased cancellation: %q", text)
			}
			if tc.failed != 0 && !strings.Contains(text, "1 failed") {
				t.Errorf("terminal UI erased failures: %q", text)
			}
			if snap.Working {
				t.Error("terminal UI remained working")
			}
		})
	}
}

func TestRecursiveLegacyWarningRemainsVisibleWithTransferredPCV3Result(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("published batch member"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := executePublicationTestEncryption(t, context.Background(), operationInput{mode: "encrypt", inputFile: source, outputFile: source + ".pcv"}, nil)
	result.completed = false
	result.err = errors.New("another batch member failed")
	result.failed = 1
	result.kept = true
	result.unverified = 1
	result.succeeded = 1
	fyne.DoAndWait(func() {
		a.State.Mode = "decrypt"
		a.State.Recursively = true
		a.State.PCV3Route = app.PCV3RouteTransferred
		a.State.SetWorking(true)
		session := a.newOperationSession()
		defer session.cancel()
		a.setOperationSession(session)
		a.finalizeOperation(session, operationInput{mode: "decrypt"}, result, true)
		if a.operationFooter.Visible() || !a.pcv3Container.Visible() {
			t.Fatal("expected sole transferred result surface")
		}
		text := pcv3RenderedText(a.pcv3Container)
		if !strings.Contains(text, "1 unverified") || !strings.Contains(text, "kept output is unverified") {
			t.Fatalf("transferred result hid earlier legacy recovery: %q", text)
		}
	})
}
