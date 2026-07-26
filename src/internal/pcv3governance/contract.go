// Package pcv3governance enforces the local PCV3 review-candidate promotion
// boundary. It deliberately does not implement a PCV3 reader or writer.
package pcv3governance

// WriterState reports the only current global PCV3 writer state.
type WriterState string

const (
	// WriterDisabled is permanent for the embedded review candidate. A future
	// final promotion can yield an authorization capability, but cannot mutate
	// this package's candidate state at runtime.
	WriterDisabled WriterState = "disabled"
)

// Reason identifies the failed governance condition without exposing a record
// value or an owner approval reference.
type Reason string

const (
	ReasonAuthorizationMissing         Reason = "authorization-missing"
	ReasonBaselineInvalid              Reason = "baseline-invalid"
	ReasonBaselineNotFinal             Reason = "baseline-not-final"
	ReasonConstraintMismatch           Reason = "constraint-mismatch"
	ReasonDuplicateField               Reason = "duplicate-field"
	ReasonGateUnsatisfied              Reason = "gate-unsatisfied"
	ReasonImplementationCommitMismatch Reason = "implementation-commit-mismatch"
	ReasonInvalidField                 Reason = "invalid-field"
	ReasonInvalidJSON                  Reason = "invalid-json"
	ReasonMissingField                 Reason = "missing-field"
	ReasonOwnerApprovalInvalid         Reason = "owner-approval-invalid"
	ReasonOwnerApprovalMissing         Reason = "owner-approval-missing"
	ReasonOwnerApprovalMismatch        Reason = "owner-approval-mismatch"
	ReasonSchemaMismatch               Reason = "schema-mismatch"
	ReasonSpecHashMismatch             Reason = "spec-hash-mismatch"
	ReasonSpecRevisionMismatch         Reason = "spec-revision-mismatch"
	ReasonStatusNotFinal               Reason = "status-not-final"
	ReasonToolchainMismatch            Reason = "toolchain-mismatch"
	ReasonUnknownField                 Reason = "unknown-field"
)

// RefusalError is a typed, non-secret explanation of why a record or
// capability was refused. Field contains only a fixed schema field or gate
// name, never an input value.
type RefusalError struct {
	Reason Reason
	Field  string
}

func (e *RefusalError) Error() string {
	if e == nil {
		return "pcv3 governance: refused"
	}
	if e.Field == "" {
		return "pcv3 governance: " + string(e.Reason)
	}
	return "pcv3 governance: " + string(e.Reason) + " (" + e.Field + ")"
}

// EmissionAuthorization is an opaque capability reserved for a future PCV3
// writer seam. Its zero value is invalid and no public constructor or setter
// can activate it. It is not an owner credential or cryptographic signature.
type EmissionAuthorization struct {
	marker *emissionMarker
}

type emissionMarker struct {
	nonzero byte
}

var validatedAuthorizationMarker = &emissionMarker{nonzero: 1}

func newEmissionAuthorization() *EmissionAuthorization {
	return &EmissionAuthorization{marker: validatedAuthorizationMarker}
}

// RequireEmissionAuthorization is the future writer seam. A Phase 5 writer
// must call it before emitting a PCV3 volume; Phase 1 intentionally has no
// writer to consume the capability.
func RequireEmissionAuthorization(authorization *EmissionAuthorization) error {
	if authorization == nil || authorization.marker != validatedAuthorizationMarker {
		return &RefusalError{Reason: ReasonAuthorizationMissing}
	}
	return nil
}
