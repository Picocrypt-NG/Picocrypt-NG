package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

type cancelAfterLegacyAuthenticationReporter struct {
	started bool
	ctx     context.Context
	cancel  context.CancelFunc
}

func (*cancelAfterLegacyAuthenticationReporter) SetProgress(float32, string) {}
func (*cancelAfterLegacyAuthenticationReporter) Update()                     {}
func (r *cancelAfterLegacyAuthenticationReporter) SetStatus(text string) {
	if text == "Calculating values..." {
		r.started = true
	}
}

func (r *cancelAfterLegacyAuthenticationReporter) SetCanCancel(can bool) {
	if can && r.started {
		r.cancel()
	}
}
func (r *cancelAfterLegacyAuthenticationReporter) IsCancelled() bool { return r.ctx.Err() != nil }

func TestFailedForcedReadCannotClaimRetainedOutputInRecursiveCompletion(t *testing.T) {
	resetLocalizationForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "output")
	input := operationInput{mode: "decrypt", inputFile: filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"), outputFile: output, password: []byte("wrong"), forceDecrypt: true, rsCodecs: rs}
	result := executeVolumeOperation(ctx, input, &cancelAfterLegacyAuthenticationReporter{ctx: ctx, cancel: cancel})
	if !result.kept || result.completed || !result.cancelled || !errors.Is(result.err, context.Canceled) {
		t.Fatalf("forced bypass without publication not reached: %+v", result)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("cancelled operation published output: %v", err)
	}
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	fyne.DoAndWait(func() {
		a.State.Mode = "decrypt"
		a.State.Recursively = true
		a.State.SetWorking(true)
		session := a.newOperationSession()
		defer session.cancel()
		a.setOperationSession(session)
		a.finalizeOperation(session, input, result, true)
		s := a.State.UISnapshot()
		if !a.State.WasKept() {
			t.Fatal("failed forced operation lost deletion-safety latch")
		}
		if s.Status.Kind != app.StatusCancelledByUser || strings.Contains(renderStatus(s.Status, s), "kept output") {
			t.Fatalf("cancelled no-output operation claimed recovery output: %+v %q", s.Status, renderStatus(s.Status, s))
		}
		if !strings.Contains(renderStatus(s.Status, s), "Authentication was bypassed; any retained output is unverified") {
			t.Fatalf("cancelled authentication bypass lost conditional trust warning: %q", renderStatus(s.Status, s))
		}
	})
}

func TestRecursiveFailedForceWithoutRetainedOutputKeepsFailureStatus(t *testing.T) {
	status := recursiveOperationStatus(operationInput{mode: "decrypt"}, operationResult{kept: true, failed: 1})
	if status.Kind != app.StatusRecursiveFailedAll || status.Color != util.RED {
		t.Fatalf("no-output failure was converted into retained recovery warning: %+v", status)
	}
}
