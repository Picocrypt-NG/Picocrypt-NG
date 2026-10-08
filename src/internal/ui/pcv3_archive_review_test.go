package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func newPCV3ArchiveReviewUI(t *testing.T) (*App, *operationSession) {
	t.Helper()
	a := newPCV3ReadUI(t, app.PCV3FormatNormal)
	var session *operationSession
	fyne.DoAndWait(func() {
		session = a.newOperationSession()
		a.setOperationSession(session)
		a.State.SetWorking(true)
		a.State.SetCanCancel(true)
		a.State.SetPCV3Progress(pcv3operation.StatusDerivingKey)
		a.updateUIState()
	})
	t.Cleanup(func() { session.cancel() })
	return a, session
}

func startPCV3ArchiveReviewForTest(t *testing.T, a *App, session *operationSession, ctx context.Context, summary pcv3operation.ArchiveSummary) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		result <- a.pcv3ArchiveReview(session)(ctx, summary)
		close(finished)
	}()
	t.Cleanup(func() {
		session.cancel()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("archive review did not stop with its operation")
		}
		fyne.DoAndWait(func() {})
	})
	return result
}

func requirePCV3ArchiveReviewResult(t *testing.T, result <-chan error, cancelled bool) {
	t.Helper()
	select {
	case err := <-result:
		if cancelled && !errors.Is(err, context.Canceled) || !cancelled && err != nil {
			t.Fatalf("archive review error = %v; cancellation expected %v", err, cancelled)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("archive review did not return after its decision")
	}
}

func pcv3ArchiveReviewButton(t *testing.T, a *App, label string) *widget.Button {
	t.Helper()
	for _, object := range test.LaidOutObjects(a.Window.Canvas().Overlays().Top()) {
		if button, ok := object.(*widget.Button); ok && button.Text == label {
			return button
		}
	}
	t.Fatalf("archive review has no %q button", label)
	return nil
}

func TestPCV3ArchiveReviewSmallArchiveShowsSummaryWithoutPrompt(t *testing.T) {
	resetLocalizationForTest(t)
	a, session := newPCV3ArchiveReviewUI(t)
	result := startPCV3ArchiveReviewForTest(t, a, session, session.ctx, pcv3operation.ArchiveSummary{
		Files: 9998, Directories: 1, UnpackedBytes: 1<<30 - 1,
	})
	requirePCV3ArchiveReviewResult(t, result, false)
	fyne.DoAndWait(func() {
		if a.Window.Canvas().Overlays().Top() != nil {
			t.Fatal("archive below both review thresholds opened a confirmation")
		}
		requirePCV3Text(t, a.pcv3Container, "Files: 9998", "Folders: 1", "Size after extraction: 1024.00 MiB")
		if strings.Contains(pcv3RenderedText(a.pcv3Container), "Deriving key") {
			t.Error("archive review still reports the completed key derivation phase")
		}
		a.resetUI()
		if strings.Contains(pcv3RenderedText(a.pcv3Container), "Files: 9998") {
			t.Fatal("reset retained the previous archive's size and count")
		}
	})
}

func TestPCV3ArchiveReviewLargeArchiveWaitsForWidgetDecision(t *testing.T) {
	resetLocalizationForTest(t)
	for _, tc := range []struct {
		name    string
		summary pcv3operation.ArchiveSummary
		accept  bool
		want    []string
	}{
		{"size boundary accepted", pcv3operation.ArchiveSummary{Files: 1, UnpackedBytes: 1 << 30}, true, []string{"1.00 GiB", "Files: 1", "Folders: 0"}},
		{"entry boundary refused", pcv3operation.ArchiveSummary{Files: 9999, Directories: 1, UnpackedBytes: 1024}, false, []string{"1.00 KiB", "Files: 9999", "Folders: 1"}},
		{"directory entries require review", pcv3operation.ArchiveSummary{Directories: 10000}, true, []string{"0.00 KiB", "Files: 0", "Folders: 10000"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, session := newPCV3ArchiveReviewUI(t)
			result := startPCV3ArchiveReviewForTest(t, a, session, session.ctx, tc.summary)
			waitForPCV3UI(t, func() bool { return a.Window.Canvas().Overlays().Top() != nil }, "large archive did not request confirmation")
			select {
			case err := <-result:
				t.Fatalf("large archive continued without a user decision: %v", err)
			default:
			}
			fyne.DoAndWait(func() {
				var rendered strings.Builder
				for _, object := range test.LaidOutObjects(a.Window.Canvas().Overlays().Top()) {
					if label, ok := object.(*widget.Label); ok {
						rendered.WriteString(label.Text)
					}
				}
				for _, want := range tc.want {
					if !strings.Contains(rendered.String(), want) {
						t.Errorf("archive confirmation omits %q: %s", want, rendered.String())
					}
				}
				cancel := pcv3ArchiveReviewButton(t, a, tr("action.cancel", "Cancel"))
				if a.Window.Canvas().Focused() != cancel {
					t.Error("archive confirmation did not focus the safe Cancel action")
				}
				if tc.accept {
					test.Tap(pcv3ArchiveReviewButton(t, a, tr("pcv3.archive.extract", "Extract archive")))
				} else {
					test.Tap(cancel)
				}
			})
			requirePCV3ArchiveReviewResult(t, result, !tc.accept)
			fyne.DoAndWait(func() {
				if a.Window.Canvas().Overlays().Top() != nil {
					t.Fatal("archive review remained open after the decision")
				}
			})
		})
	}
}

func TestPCV3ArchiveReviewCloseOrCancellationRefusesExtraction(t *testing.T) {
	resetLocalizationForTest(t)
	for _, action := range []string{"close", "context cancellation", "operation cancellation", "stale confirmation"} {
		t.Run(action, func(t *testing.T) {
			a, session := newPCV3ArchiveReviewUI(t)
			ctx, cancel := context.WithCancel(session.ctx)
			defer cancel()
			result := startPCV3ArchiveReviewForTest(t, a, session, ctx, pcv3operation.ArchiveSummary{Files: 1, UnpackedBytes: 1 << 30})
			waitForPCV3UI(t, func() bool { return a.Window.Canvas().Overlays().Top() != nil }, "archive confirmation did not open")
			fyne.DoAndWait(func() {
				switch action {
				case "close":
					a.pcv3ArchiveReviewModal.Hide()
				case "context cancellation":
					cancel()
				case "operation cancellation":
					a.cancelOperation(session)
				case "stale confirmation":
					confirm := pcv3ArchiveReviewButton(t, a, tr("pcv3.archive.extract", "Extract archive"))
					newer := a.newOperationSession()
					a.setOperationSession(newer)
					t.Cleanup(newer.cancel)
					test.Tap(confirm)
				}
			})
			requirePCV3ArchiveReviewResult(t, result, true)
			waitForPCV3UI(t, func() bool { return a.Window.Canvas().Overlays().Top() == nil }, "cancelled archive review remained visible")
		})
	}
}

func TestPCV3ArchiveReviewStaleSessionCannotOpenPrompt(t *testing.T) {
	resetLocalizationForTest(t)
	a, session := newPCV3ArchiveReviewUI(t)
	fyne.DoAndWait(func() {
		newer := a.newOperationSession()
		a.setOperationSession(newer)
		t.Cleanup(newer.cancel)
	})
	result := startPCV3ArchiveReviewForTest(t, a, session, session.ctx, pcv3operation.ArchiveSummary{Files: 1, UnpackedBytes: 1 << 30})
	requirePCV3ArchiveReviewResult(t, result, true)
	fyne.DoAndWait(func() {
		if a.Window.Canvas().Overlays().Top() != nil || strings.Contains(pcv3RenderedText(a.pcv3Container), "Size after extraction:") {
			t.Fatal("stale archive review changed the current operation's UI")
		}
	})
}
