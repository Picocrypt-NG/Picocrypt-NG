package pcv3operation

import "testing"

// skipOnPCV3ResourceAdmissionDenial skips when a closed result carries a
// resource-admission diagnostic: a real delegated platform admitter
// legitimately refuses the fixed 1 GiB KDF profile on loaded or constrained
// test hosts. The scripted-admission refusal cases in the privacy matrix pin
// the fail-closed behavior, so this skip covers only the
// environment-dependent grant expectation.
func skipOnPCV3ResourceAdmissionDenial(t *testing.T, result *Result) {
	t.Helper()
	switch result.Diagnostic() {
	case DiagnosticResourceBusy, DiagnosticResourceInsufficient, DiagnosticResourceUnknown:
		t.Skipf(
			"resource-admission environment skip: platform admitter refused the fixed 1 GiB KDF profile (diagnostic %v)",
			result.Diagnostic(),
		)
	}
}
