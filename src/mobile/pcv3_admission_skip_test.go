package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
	"testing"
)

// skipOnPCV3ResourceAdmissionDenial skips when a completed bridge snapshot
// carries a resource-admission diagnostic: the real platform admitter behind
// the mobile bridge legitimately refuses the fixed 1 GiB KDF profile on
// loaded or constrained test hosts. The skip fires only on the resource
// diagnostics, which no asserted outcome uses, so every other result stays a
// test failure.
func skipOnPCV3ResourceAdmissionDenial(t *testing.T, snapshot *PCV3Snapshot) {
	t.Helper()
	switch snapshot.Diagnostic() {
	case pcv3DiagnosticCode(pcv3operation.DiagnosticResourceBusy),
		pcv3DiagnosticCode(pcv3operation.DiagnosticResourceInsufficient),
		pcv3DiagnosticCode(pcv3operation.DiagnosticResourceUnknown):
		t.Skipf(
			"resource-admission environment skip: platform admitter refused the fixed 1 GiB KDF profile (diagnostic %s)",
			snapshot.Diagnostic(),
		)
	}
}
