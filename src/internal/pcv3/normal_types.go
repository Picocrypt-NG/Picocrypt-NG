package pcv3

import (
	"Picocrypt-NG/internal/pcv3credential"
	"fmt"
)

// normalAuthResult owns the authenticated capsule selection and, on the real
// credential path, the only published key owner. It exposes no unauthenticated
// candidate fields or raw key bytes.
type normalAuthResult struct {
	outcome       Outcome
	stage         Stage
	authenticated uint8
	candidate     Candidate
	geometry      Geometry
	owner         *pcv3credential.Owner
}

func newNormalAuthResult(
	outcome Outcome,
	stage Stage,
	authenticated int,
) *normalAuthResult {
	return &normalAuthResult{
		outcome:       outcome,
		stage:         stage,
		authenticated: uint8(authenticated), //nolint:gosec // Closed capsule count is at most two.
	}
}

func (result *normalAuthResult) Outcome() Outcome {
	if result == nil {
		return 0
	}
	return result.outcome
}

func (result *normalAuthResult) Stage() Stage {
	if result == nil {
		return 0
	}
	return result.stage
}

func (result *normalAuthResult) Code() Code {
	if result == nil {
		return 0
	}
	code, _ := codeFor(result.outcome, result.stage)
	return code
}

func (result *normalAuthResult) AuthenticatedCapsules() int {
	if result == nil {
		return 0
	}
	return int(result.authenticated)
}

func (result *normalAuthResult) Error() string {
	if result == nil {
		return "pcv3: capsule authentication failure"
	}
	switch result.outcome {
	case OutcomeSuccess:
		return "pcv3: capsule authentication succeeded"
	case OutcomeInvalidStructurePreKDF:
		return "pcv3: invalid structure before KDF"
	case OutcomeCredentialsOrDamage:
		return "pcv3: credentials incorrect or volume damaged"
	case OutcomeAuthenticatedDegraded:
		return "pcv3: capsule authentication succeeded with degraded redundancy"
	case OutcomeAmbiguousVolume:
		return "pcv3: ambiguous authenticated volume"
	case OutcomeOperationFailed:
		return "pcv3: capsule authentication operation failed"
	default:
		return "pcv3: capsule authentication failure"
	}
}

func (result *normalAuthResult) String() string {
	return result.Error()
}

func (result *normalAuthResult) GoString() string {
	return result.Error()
}

func (result *normalAuthResult) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, result.Error())
}

func (result *normalAuthResult) Close() {
	if result == nil {
		return
	}
	if result.owner != nil {
		result.owner.Close()
		result.owner = nil
	}
	result.candidate = Candidate{}
	result.geometry = Geometry{}
}
