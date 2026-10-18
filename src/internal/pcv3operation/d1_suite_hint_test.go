package pcv3operation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestD1SuiteHintRefusedOutsideExplicitUnverifiedD1(t *testing.T) {
	for _, mode := range []Mode{
		ModeReadNormal, ModeReadD1, ModeRecoverNormal, ModeRecoverD1,
		ModeForceNormal, ModeForceD1, ModeForceUnverifiedNormal, ModeForceUnverifiedD1,
	} {
		t.Run(fmt.Sprintf("mode-%d", mode), func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "source")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			hint := SuiteStandard
			if mode == ModeForceUnverifiedD1 {
				hint = Suite(255)
			}
			request := &Request{
				Mode: mode, D1SuiteHint: hint, Source: file,
				Factors: operationPasswordFactors([]byte("password")), Target: filepath.Join(t.TempDir(), "output"),
			}
			if mode == ModeForceUnverifiedNormal || mode == ModeForceUnverifiedD1 {
				request.Consent = func(_ ConsentRequest, action ConsentAction) error { return action(RoleD1Front) }
			}
			admitter := &operationTestAdmitter{}
			result := runWithSeams(context.Background(), request, operationSeams{admitter: admitter})
			if result.Diagnostic() != DiagnosticInvalidRequest || admitter.calls != 0 || result.PublicationAttempted() {
				t.Fatalf("suite hint escaped its closed raw-D1 boundary: diagnostic=%v calls=%d publication=%v", result.Diagnostic(), admitter.calls, result.PublicationAttempted())
			}
			if request.D1SuiteHint != 0 {
				t.Fatal("suite hint remained on the transferred request")
			}
		})
	}
}

func TestD1ProfileRequiredPresentationStaysClosedNoOutput(t *testing.T) {
	spec := PresentationSpec{
		Outcome: OutcomeOperationFailed, Stage: StageD1Bootstrap,
		Code: CodeOperationFailed, Diagnostic: DiagnosticD1ProfileRequired,
	}
	presentation, err := NewPresentation(spec)
	if err != nil || presentation.CompletionClass() != CompletionNoOutput {
		t.Fatalf("profile choice refusal lost its bounded no-output presentation: %v", err)
	}
	spec.Outcome, spec.Stage, spec.Code = OutcomeSuccess, StageNone, CodeSuccess
	if _, err := NewPresentation(spec); err == nil {
		t.Fatal("profile choice diagnostic accepted a success tuple")
	}
}
