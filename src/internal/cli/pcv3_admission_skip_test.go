package cli

import (
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3resource"
	"context"
	"strings"
	"testing"
)

// pcv3AdmissionDenialStderrMarkers are the stable, bounded stderr shapes a
// real PCV3 subprocess produces when platform resource admission refuses the
// fixed 1 GiB Argon2id profile. The D1 writer surfaces the typed KDF error
// verbatim; the Normal writer and the operation renderer redact the cause, so
// those markers are only denial-consistent, never denial-proof.
var pcv3AdmissionDenialStderrMarkers = []string{
	"KDF runtime admission failed",
	"pcv3: normal serialization failed",
	"Outcome: operation-failed",
}

// pcv3PlatformAdmissionCurrentlyDenied probes the real platform admitter with
// the frozen fixed KDF profile (the same literal pcv3credential tests pin) so
// a redacted subprocess failure can be attributed to the environment instead
// of the implementation. Admission policy itself is covered in
// internal/pcv3resource.
func pcv3PlatformAdmissionCurrentlyDenied() bool {
	decision, err := pcv3resource.NewPlatformAdmitter().AdmitKDF(
		context.Background(),
		pcv3credential.KDFProfile{
			ID:            0x01,
			Argon2Version: 0x13,
			Time:          4,
			MemoryKiB:     1048576,
			Parallelism:   4,
			SaltBytes:     16,
			OutputBytes:   32,
		},
	)
	return err != nil || decision != pcv3credential.KDFAdmissionGranted
}

// skipOnPCV3ResourceAdmissionDenial converts a genuine platform
// resource-admission denial of a real PCV3 subprocess into a skip: the fixed
// 1 GiB KDF profile is legitimately refused on loaded or constrained test
// hosts. A failure without a denial-shaped stderr, or any failure while the
// fresh probe grants admission, stays a test failure.
func skipOnPCV3ResourceAdmissionDenial(t *testing.T, result cliTestResult) {
	t.Helper()
	if result.exitCode == 0 {
		return
	}
	for _, marker := range pcv3AdmissionDenialStderrMarkers {
		if strings.Contains(result.stderr, marker) && pcv3PlatformAdmissionCurrentlyDenied() {
			t.Skipf(
				"resource-admission environment skip: PCV3 subprocess was refused the fixed 1 GiB KDF profile (exit %d, stderr %q)",
				result.exitCode, result.stderr,
			)
		}
	}
}
