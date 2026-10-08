package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3publication"
	"runtime"
	"slices"
	"testing"
)

// The native Windows publisher deliberately cannot prove directory durability.
// A published payload must keep that warning and never grant source deletion.
func requireNativeOperationPublication(t *testing.T, result *Result) {
	t.Helper()
	wantState, wantClass := pcv3publication.StatePublishedDurable, CompletionClean
	wantStage, wantCode := StageNone, pcv3publication.CodePublishedDurable
	var wantWarnings []Warning
	if runtime.GOOS == "windows" {
		wantState, wantClass = pcv3publication.StatePublishedDurabilityUncertain, CompletionDurabilityUncertain
		wantStage, wantCode = StageDirectorySync, pcv3publication.CodeDurabilityUncertain
		wantWarnings = []Warning{WarningDurabilityUncertain}
	}
	if result == nil || result.Outcome() != OutcomeSuccess || result.Diagnostic() != DiagnosticNone || result.Code() != CodeSuccess ||
		result.Stage() != StageNone || !result.PublicationAttempted() || result.PublicationState() != wantState ||
		result.PublicationStage() != wantStage || result.PublicationCode() != wantCode ||
		result.CompletionClass() != wantClass || !slices.Equal(result.Warnings(), wantWarnings) ||
		(runtime.GOOS == "windows" && result.SourceDeletionAllowed()) {
		if result != nil {
			t.Logf("actual native publication stage=%v diagnostic=%d", result.Stage(), result.Diagnostic())
		}
		t.Fatalf("native publication = %v; want state=%v class=%v warnings=%v", result, wantState, wantClass, wantWarnings)
	}
}
