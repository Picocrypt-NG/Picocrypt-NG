package mobile

import (
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation"
	"errors"

	perrors "Picocrypt-NG/internal/errors"
)

func pcv3DiagnosticCode(diagnostic pcv3operation.Diagnostic) string {
	switch diagnostic {
	case pcv3operation.DiagnosticNone:
		return "none"
	case pcv3operation.DiagnosticInvalidRequest:
		return "invalid-request"
	case pcv3operation.DiagnosticRoutingRefusal:
		return "routing-refusal"
	case pcv3operation.DiagnosticCredentialPolicy:
		return "credential-policy"
	case pcv3operation.DiagnosticCancellation:
		return "cancellation"
	case pcv3operation.DiagnosticCoreFailure:
		return "core-failure"
	case pcv3operation.DiagnosticCallbackFailure:
		return "callback-failure"
	case pcv3operation.DiagnosticCallbackPanic:
		return "callback-panic"
	case pcv3operation.DiagnosticGovernanceRefusal:
		return "governance-refusal"
	case pcv3operation.DiagnosticResourceBusy:
		return "resource-busy"
	case pcv3operation.DiagnosticResourceInsufficient:
		return "resource-insufficient"
	case pcv3operation.DiagnosticResourceUnknown:
		return "resource-unknown"
	default:
		return "unknown"
	}
}

func pcv3WarningCode(warning pcv3operation.Warning) string {
	switch warning {
	case pcv3operation.WarningAuthenticatedDegraded:
		return "authenticated-degraded"
	case pcv3operation.WarningForcePartial:
		return "force-partial"
	case pcv3operation.WarningForceUnverified:
		return "force-unverified"
	case pcv3operation.WarningDurabilityUncertain:
		return "durability-uncertain"
	case pcv3operation.WarningPublicationIndeterminate:
		return "publication-indeterminate"
	case pcv3operation.WarningCleanupIncomplete:
		return "cleanup-incomplete"
	case pcv3operation.WarningCallbackFailure:
		return "callback-failure"
	default:
		return "unknown"
	}
}

func pcv3CompletionCode(completion pcv3operation.CompletionClass) string {
	switch completion {
	case pcv3operation.CompletionRefused:
		return "refused"
	case pcv3operation.CompletionNoOutput:
		return "no-output"
	case pcv3operation.CompletionClean:
		return "clean"
	case pcv3operation.CompletionWarning:
		return "warning"
	case pcv3operation.CompletionArchivePending:
		return "archive-pending"
	case pcv3operation.CompletionDurabilityUncertain:
		return "durability-uncertain"
	case pcv3operation.CompletionPublicationIndeterminate:
		return "publication-indeterminate"
	default:
		return "unknown"
	}
}

func pcv3ForceProvenance(provenance pcv3.ForceProvenance) string {
	switch provenance {
	case pcv3.ForceProvenanceNone:
		return "none"
	case pcv3.ForceProvenanceVerified:
		return "verified"
	case pcv3.ForceProvenancePartial:
		return "partial"
	case pcv3.ForceProvenanceUnverified:
		return "unverified"
	default:
		return "unknown"
	}
}

func pcv3D1Provenance(provenance pcv3.D1BootstrapProvenance) string {
	switch provenance {
	case pcv3.D1BootstrapProvenanceNone:
		return "none"
	case pcv3.D1BootstrapProvenanceFront:
		return "front"
	case pcv3.D1BootstrapProvenanceTail:
		return "tail"
	case pcv3.D1BootstrapProvenanceMatching:
		return "matching"
	default:
		return "unknown"
	}
}

// errorCode maps a pipeline error to a stable, locale-independent code for the
// Android layer. Empty string means no error.
//
// This replaces the prior English-substring matching in Kotlin's
// AppError.fromGoError, which was fragile (locale/wording-coupled) and tightly
// bound to Go error text — an interop hazard given the project's byte-for-byte
// compatibility mandate. The classification is SECURITY-RELEVANT: the Android
// layer gates force-decrypt (which BYPASSES integrity/RS checks) on
// DATA_CORRUPTED and password-retry on AUTH_FAILED, so the mapping below must
// preserve the OLD semantics exactly:
//
//   - A wrong password / failed authentication -> AUTH_FAILED (PasswordAuth;
//     password-retry, NOT force-decrypt).
//   - Payload corruption RS cannot recover -> DATA_CORRUPTED (force-decrypt).
//   - Header corruption -> CORRUPT_HEADER, which the Kotlin side maps to a
//     generic error so it is NOT force-decryptable (the old logic explicitly
//     excluded header errors from DataCorruption).
//
// IMPORTANT — why errors.Is(ErrAuthFailed) alone is insufficient:
// On the normal (non-verify-first) decrypt path, a wrong password/keyfile
// surfaces as *header.AuthError (volume/decrypt.go:273,283,335,345). That type
// has no Unwrap and does NOT wrap perrors.ErrAuthFailed, so errors.Is would
// return false and the most security-critical case would fall through to
// GENERIC, dropping the password-retry affordance. We therefore detect it with
// errors.As(&*header.AuthError) in addition to the bare sentinel that the
// verify-first path returns (volume/decrypt.go:572).
//
// Auth is checked BEFORE corruption so that an error chain carrying both
// classifies as AUTH_FAILED, mirroring the old substring logic (which favored
// the auth check and required corruption AND-NOT-auth).
func errorCode(err error) string {
	if err == nil {
		return ""
	}
	if code, ok := pcv3ErrorCode(err); ok {
		return code
	}

	// Auth failure: bare sentinel (verify-first path) OR the typed
	// *header.AuthError returned on the normal decrypt path.
	var authErr *header.AuthError
	if errors.Is(err, perrors.ErrAuthFailed) || errors.As(err, &authErr) {
		return "AUTH_FAILED"
	}

	switch {
	case errors.Is(err, perrors.ErrCorruptData):
		return "DATA_CORRUPTED"
	// Header corruption surfaces as header.ErrCorruptedHeader (wrapped by
	// "header damaged: %w" in decrypt.go); perrors.ErrCorruptHeader is also
	// matched defensively in case the pipeline ever returns it directly.
	case errors.Is(err, header.ErrCorruptedHeader), errors.Is(err, perrors.ErrCorruptHeader):
		return "CORRUPT_HEADER" // NOT force-decryptable
	case errors.Is(err, perrors.ErrFileNotFound):
		return "FILE_NOT_FOUND"
	case errors.Is(err, perrors.ErrCancelled):
		return "CANCELLED"
	default:
		return "GENERIC"
	}
}

func pcv3ErrorCode(err error) (string, bool) {
	if errors.Is(err, pcv3.ErrReaderUnavailable) {
		return pcv3.CodeUnsupported.String(), true
	}

	var failure pcv3.Failure
	if !errors.As(err, &failure) {
		return "", false
	}
	switch failure.Code() {
	case pcv3.CodeUnsupported:
		return pcv3.CodeUnsupported.String(), true
	case pcv3.CodeInvalidStructure:
		return pcv3.CodeInvalidStructure.String(), true
	default:
		return "", false
	}
}
