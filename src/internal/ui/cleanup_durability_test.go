package ui

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

func TestPCV3CleanupDurabilityHasPreciseTerminalCopy(t *testing.T) {
	resetLocalizationForTest(t)
	newTestFyneApp(t)
	presentation := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome: pcv3operation.OutcomeSuccess, Code: pcv3operation.CodeSuccess,
		PublicationAttempted: true, PublicationState: pcv3publication.StatePublishedDurable,
		PublicationCode: pcv3publication.CodePublishedDurable,
		Warnings:        []pcv3operation.Warning{pcv3operation.WarningCleanupDurabilityUncertain},
	})
	view := (&App{}).buildPCV3ResultView(presentation, nil)
	requirePCV3Text(t, view, "Cleanup may not persist after a power loss",
		"The app could not confirm that deleted temporary files will stay deleted after a power loss. Keep the source files.")
	if findPCV3Button(view, "Close cleanup durability warning") == nil {
		t.Fatal("terminal result has no precise cleanup-durability close action")
	}
	if strings.Contains(pcv3RenderedText(view), "The application could not confirm removal of all temporary files") {
		t.Fatal("known-absent cleanup was described as unconfirmed live removal")
	}
}

func TestPCV3CleanupDurabilitySurvivesReleaseSelectionAndLateWorker(t *testing.T) {
	for _, kind := range []string{"released", "clean disposer hook", "failed disposer hook", "late worker"} {
		t.Run(kind, func(t *testing.T) {
			resetLocalizationForTest(t)
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)
			result := pcv3operation.Run(context.Background(), &pcv3operation.Request{})
			result.WithCleanupDurabilityWarning()
			if kind == "clean disposer hook" || kind == "failed disposer hook" {
				a.pcv3ResultDisposer = func(*pcv3operation.Result) bool { return kind == "failed disposer hook" }
			}
			if kind == "late worker" {
				session := a.newOperationSession()
				a.operationGeneration.Add(1)
				a.finishPCV3Worker(session, result, pcv3operation.DiagnosticCoreFailure)
			} else {
				fyne.DoAndWait(func() {
					a.pcv3Result = result
					a.releasePCV3Result()
				})
			}
			fyne.DoAndWait(func() {
				a.State.Reset()
				a.State.SetPCV3RoutingChecking("replacement.bin", 12)
				a.State.SetPCV3LegacyEligible()
				a.State.ResetUI()
				a.updateUIState()
			})
			if snapshot := a.State.UISnapshot(); snapshot.PCV3CleanupIncomplete != (kind == "failed disposer hook") || !snapshot.PCV3CleanupDurabilityUncertain {
				t.Fatal("disposal lost or conflated independent cleanup observations")
			}
			requirePCV3Text(t, a.pcv3Container, "Cleanup may not persist after a power loss")
			if a.pcv3Container.Hidden {
				t.Fatal("replacement selection hid the process-lifetime durability warning")
			}
			fyne.DoAndWait(a.handleCloseRequest)
			if !a.State.UISnapshot().PCV3CleanupDurabilityUncertain {
				t.Fatal("shutdown erased deletion-durability truth")
			}
		})
	}
}
