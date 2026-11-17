package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

func TestLegacyV1ActualReadCarriesFormatWarningToVisibleCompletion(t *testing.T) {
	resetLocalizationForTest(t)
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	input := operationInput{mode: "decrypt", inputFile: filepath.Join("..", "..", "testdata", "golden", "pico_test_v1.txt.pcv"), outputFile: filepath.Join(t.TempDir(), "output"), password: []byte("test"), rsCodecs: rs}
	result := executeVolumeOperation(context.Background(), input, nil)
	if result.err != nil || !result.completed || result.kept {
		t.Fatalf("legacy compatibility failed: %+v", result)
	}
	if !result.legacyHeaderUnverified {
		t.Fatal("actual v1 read lost missing-header-authentication warning")
	}
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() {
		a.State.Mode = "decrypt"
		a.State.SetWorking(true)
		session := a.newOperationSession()
		defer session.cancel()
		a.setOperationSession(session)
		a.finalizeOperation(session, input, result, false)
		s := a.State.UISnapshot()
		if s.Status.Kind != app.StatusCompleted || s.Status.Color != util.YELLOW || a.State.WasKept() {
			t.Fatalf("format limit changed completion/Force semantics: %+v", s.Status)
		}
		if text := renderStatus(s.Status, s); !strings.Contains(text, "Legacy v1 does not authenticate the header") {
			t.Fatalf("visible completion lost format warning: %q", text)
		}
	})
}

func TestLegacyFormatWarningsPreserveForceAndRecursiveOutcome(t *testing.T) {
	for _, test := range []struct {
		name      string
		result    operationResult
		recursive bool
		kind      app.StatusKind
	}{
		{"force", operationResult{completed: true, kept: true, legacyHeaderUnverified: true}, false, app.StatusKeptOutputUnverified},
		{"mixed cancelled", operationResult{cancelled: true, kept: true, unverified: 1, succeeded: 1, legacyHeaderUnverified: true, legacyKeyfilePasswordOnly: true}, true, app.StatusRecursiveUnverified},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetLocalizationForTest(t)
			a := createUIReadyDropTestApp(t, newTestFyneApp(t))
			fyne.DoAndWait(func() {
				a.State.Mode = "decrypt"
				a.State.SetWorking(true)
				session := a.newOperationSession()
				defer session.cancel()
				a.setOperationSession(session)
				a.finalizeOperation(session, operationInput{mode: "decrypt"}, test.result, test.recursive)
				s := a.State.UISnapshot()
				text := renderStatus(s.Status, s)
				if s.Status.Kind != test.kind || !a.State.WasKept() || !strings.Contains(text, "Legacy v1 does not authenticate the header") || !strings.Contains(text, "unverified") {
					t.Fatalf("lost result trust: %+v %q", s.Status, text)
				}
				if test.result.legacyKeyfilePasswordOnly && !strings.Contains(text, "keyfile does not contribute to legacy v2 authentication") {
					t.Fatalf("lost second batch limitation: %q", text)
				}
			})
		})
	}
}
