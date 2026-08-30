package ui

import (
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation"
	"errors"
	"testing"
)

// skipOnPCV3ResourceAdmissionDenial skips when err is a typed platform
// resource-admission refusal of the fixed 1 GiB KDF profile: loaded or
// constrained test hosts legitimately deny it. Admission policy itself is
// covered in internal/pcv3resource and internal/pcv3credential, so this skip
// loses no coverage; every other error stays a test failure.
func skipOnPCV3ResourceAdmissionDenial(t *testing.T, err error) {
	t.Helper()
	var kdfErr *pcv3credential.KDFError
	if errors.As(err, &kdfErr) && kdfErr.Code == pcv3credential.KDFErrorAdmission {
		t.Skipf(
			"resource-admission environment skip: PCV3 operation was refused the fixed 1 GiB KDF profile (%v)",
			err,
		)
	}
	var pipelineErr *pcv3credential.PipelineError
	if errors.As(err, &pipelineErr) && pipelineErr.Code == pcv3credential.PipelineErrorAdmission {
		t.Skipf(
			"resource-admission environment skip: PCV3 operation was refused the fixed 1 GiB KDF profile (%v)",
			err,
		)
	}
}

// skipOnPCV3ResourceAdmissionResult skips when a closed operation result from
// the real platform admitter carries a resource-admission diagnostic.
func skipOnPCV3ResourceAdmissionResult(t *testing.T, result *pcv3operation.Result) {
	t.Helper()
	switch result.Diagnostic() {
	case pcv3operation.DiagnosticResourceBusy,
		pcv3operation.DiagnosticResourceInsufficient,
		pcv3operation.DiagnosticResourceUnknown:
		t.Skipf(
			"resource-admission environment skip: PCV3 operation was refused the fixed 1 GiB KDF profile (diagnostic %v)",
			result.Diagnostic(),
		)
	}
}
