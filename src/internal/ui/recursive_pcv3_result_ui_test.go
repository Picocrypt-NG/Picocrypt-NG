package ui

import (
	"Picocrypt-NG/internal/app"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

// Batch reads finish with a transferred source even when a later member fails.
// The only visible result must retain the batch outcome, not an earlier file's
// clean success, while cleanup warnings remain authoritative.
func TestRecursivePCV3TransferredResultSurfacePreservesBatchOutcome(t *testing.T) {
	resetLocalizationForTest(t)
	for _, test := range []struct {
		name       string
		cancelled  bool
		warning    bool
		wantStatus app.StatusKind
		want       string
	}{
		{"later credential refusal", false, false, app.StatusRecursiveCompletedFailed, "Completed (1 ok, 1 failed)"},
		{"later cancellation", true, false, app.StatusCancelledByUser, "Operation cancelled by user"},
		{"cleanup warning retains priority", false, true, app.StatusCustom, "Cleanup could not be confirmed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)
			source := filepath.Join(t.TempDir(), "source.txt")
			if err := os.WriteFile(source, []byte("published batch member"), 0o600); err != nil {
				t.Fatal(err)
			}
			input := operationInput{mode: "encrypt", inputFile: source, outputFile: source + ".pcv"}
			// A real keyfile-only publication supplies the earlier clean result.
			result := executeDeletionTestEncryption(t, context.Background(), input, nil)
			result.completed = false
			result.succeeded, result.failed = 1, 1
			result.err = errors.New("later batch member refused")
			result.cancelled = test.cancelled
			if test.cancelled {
				result.failed = 0
				result.err = context.Canceled
			}
			if test.warning {
				result.pcv3.WithCleanupWarning()
			}
			fyne.DoAndWait(func() {
				a.State.Mode = "decrypt"
				a.State.Recursively = true
				a.State.RecursiveD1 = true
				a.State.PCV3Route = app.PCV3RouteTransferred
				a.State.SetWorking(true)
				session := a.newOperationSession()
				defer session.cancel()
				a.setOperationSession(session)
				a.finalizeOperation(session, operationInput{mode: "decrypt"}, result, true)
				snap := a.State.UISnapshot()
				if snap.Status.Kind != test.wantStatus {
					t.Errorf("finalized batch status=%v want=%v", snap.Status.Kind, test.wantStatus)
				}
				if !test.cancelled && !test.warning && (snap.Status.Args.OK != 1 || snap.Status.Args.Failed != 1) {
					t.Errorf("batch counts=%+v want one success and one failure", snap.Status.Args)
				}
				if a.operationFooter.Visible() || !a.pcv3Container.Visible() {
					t.Fatal("test must inspect the sole visible result surface")
				}
				text := pcv3RenderedText(a.pcv3Container)
				if !strings.Contains(text, test.want) {
					t.Errorf("visible result lost batch outcome %q: %q", test.want, text)
				}
				if !test.warning && strings.Contains(text, "Operation complete") {
					t.Errorf("visible result still claims earlier file success for the batch: %q", text)
				}
				if test.cancelled && !strings.Contains(text, "File saved.") {
					t.Errorf("cancellation erased already-published output evidence: %q", text)
				}
			})
		})
	}
}
