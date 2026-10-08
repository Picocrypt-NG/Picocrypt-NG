package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"testing"
)

func TestResourceMapRefusalHasDedicatedStablePresentation(t *testing.T) {
	result := newResult(resultData{outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageResourceBudget, code: pcv3.CodeOperationFailed, diagnostic: DiagnosticResourceLimit})
	if !result.Presentation().valid() || result.Diagnostic() != DiagnosticResourceLimit || result.Presentation().CompletionClass() != CompletionNoOutput {
		t.Fatalf("resource refusal lost: %#v", result.Presentation())
	}
	for _, outcome := range []pcv3.Outcome{pcv3.OutcomeForcePartial, pcv3.OutcomeCredentialsOrDamage} {
		p := result.Presentation()
		p.outcome = outcome
		if p.valid() {
			t.Fatalf("invalid resource refusal accepted: %v", outcome)
		}
	}
}

func TestResourceDiagnosticAppendsWithoutRenumberingExistingRegistry(t *testing.T) {
	// Numeric values cross the mobile/frontend presentation boundary.
	values := []Diagnostic{DiagnosticNone, DiagnosticInvalidRequest, DiagnosticRoutingRefusal, DiagnosticCredentialPolicy, DiagnosticCancellation, DiagnosticCoreFailure, DiagnosticCallbackFailure, DiagnosticCallbackPanic, diagnosticReserved, DiagnosticResourceBusy, DiagnosticResourceInsufficient, DiagnosticResourceUnknown, DiagnosticResourceLimit}
	for expected, value := range values {
		if int(value) != expected {
			t.Fatalf("diagnostic registry %d became %d", expected, value)
		}
	}
	if StageDirectorySync != 24 || StageResourceBudget != 25 {
		t.Fatalf("stage registry changed: %d %d", StageDirectorySync, StageResourceBudget)
	}
}
