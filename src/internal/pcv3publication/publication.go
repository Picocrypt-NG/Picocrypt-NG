// Package pcv3publication owns PCV3 staging and atomic filesystem publication.
// It contains no format, cryptographic, archive, or source-deletion authority.
package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3"
	"fmt"
	"strconv"
)

// Policy selects one closed publication policy. Its zero value is the safe
// no-replace policy.
type Policy uint8

const (
	PolicyNoReplace Policy = iota
	PolicySafeReplace
)

// State is the closed terminal publication state.
type State uint8

const (
	StateNotPublished State = iota + 1
	StatePublishedDurable
	StatePublishedDurabilityUncertain
	StatePublicationIndeterminate
)

// Code is a stable, non-disclosing publication diagnostic.
type Code uint8

const (
	CodeInvalidRequest Code = iota + 1
	CodePolicyUnsupported
	CodeDestinationExists
	CodeStageFailure
	CodeIdentityChanged
	CodeCancelled
	CodeAtomicFailed
	CodePublishedDurable
	CodeDurabilityUncertain
	CodePublicationIndeterminate
)

// Result is the sealed terminal view of a publication attempt. It never
// exposes filesystem paths or raw platform errors through formatting.
type Result interface {
	error
	fmt.Stringer
	fmt.GoStringer
	State() State
	Outcome() pcv3.Outcome
	Stage() pcv3.Stage
	Code() Code
	isPublicationResult()
}

type publicationResult struct {
	state   State
	outcome pcv3.Outcome
	stage   pcv3.Stage
	code    Code
}

func newResult(state State, stage pcv3.Stage, code Code) Result {
	outcome := pcv3.OutcomeOperationFailed
	switch state {
	case StatePublishedDurable:
		outcome = pcv3.OutcomeSuccess
		stage = pcv3.StageNone
		code = CodePublishedDurable
	case StatePublishedDurabilityUncertain:
		outcome = pcv3.OutcomeCommittedDurabilityUncertain
		stage = pcv3.StageDirectorySync
		code = CodeDurabilityUncertain
	case StatePublicationIndeterminate:
		outcome = pcv3.OutcomePublicationIndeterminate
		stage = pcv3.StageOutputPublication
		code = CodePublicationIndeterminate
	}
	return &publicationResult{state: state, outcome: outcome, stage: stage, code: code}
}

func (result *publicationResult) State() State {
	if result == nil {
		return 0
	}
	return result.state
}

func (result *publicationResult) Outcome() pcv3.Outcome {
	if result == nil {
		return 0
	}
	return result.outcome
}

func (result *publicationResult) Stage() pcv3.Stage {
	if result == nil {
		return 0
	}
	return result.stage
}

func (result *publicationResult) Code() Code {
	if result == nil {
		return 0
	}
	return result.code
}

func (result *publicationResult) Error() string {
	if result == nil {
		return "pcv3 publication: unavailable"
	}
	switch result.code {
	case CodeInvalidRequest:
		return "pcv3 publication: invalid request"
	case CodePolicyUnsupported:
		return "pcv3 publication: policy unsupported"
	case CodeDestinationExists:
		return "pcv3 publication: destination exists"
	case CodeStageFailure:
		return "pcv3 publication: staging failed"
	case CodeIdentityChanged:
		return "pcv3 publication: identity changed before commit"
	case CodeCancelled:
		return "pcv3 publication: cancelled before commit"
	case CodeAtomicFailed:
		return "pcv3 publication: not published"
	case CodePublishedDurable:
		return "pcv3 publication: published durable"
	case CodeDurabilityUncertain:
		return "pcv3 publication: published with uncertain durability"
	case CodePublicationIndeterminate:
		return "pcv3 publication: commit state indeterminate"
	default:
		return "pcv3 publication: unavailable"
	}
}

func (result *publicationResult) String() string {
	return result.Error()
}

func (result *publicationResult) GoString() string {
	return result.Error()
}

func (result *publicationResult) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, result.Error())
}

func (*publicationResult) isPublicationResult() {}

func (policy Policy) String() string {
	switch policy {
	case PolicyNoReplace:
		return "no-replace"
	case PolicySafeReplace:
		return "safe-replace"
	default:
		return "unknown-policy"
	}
}

func (policy Policy) GoString() string {
	return policy.String()
}

func (policy Policy) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, policy.String())
}

func (state State) String() string {
	switch state {
	case StateNotPublished:
		return "not-published"
	case StatePublishedDurable:
		return "published-durable"
	case StatePublishedDurabilityUncertain:
		return "published-durability-uncertain"
	case StatePublicationIndeterminate:
		return "publication-indeterminate"
	default:
		return "unknown-state"
	}
}

func (state State) GoString() string {
	return state.String()
}

func (state State) Format(output fmt.State, verb rune) {
	writeFixedFormat(output, verb, state.String())
}

func (code Code) String() string {
	switch code {
	case CodeInvalidRequest:
		return "PCV3_PUBLICATION_INVALID_REQUEST"
	case CodePolicyUnsupported:
		return "PCV3_PUBLICATION_POLICY_UNSUPPORTED"
	case CodeDestinationExists:
		return "PCV3_PUBLICATION_DESTINATION_EXISTS"
	case CodeStageFailure:
		return "PCV3_PUBLICATION_STAGE_FAILURE"
	case CodeIdentityChanged:
		return "PCV3_PUBLICATION_IDENTITY_CHANGED"
	case CodeCancelled:
		return "PCV3_PUBLICATION_CANCELLED"
	case CodeAtomicFailed:
		return "PCV3_PUBLICATION_NOT_PUBLISHED"
	case CodePublishedDurable:
		return "PCV3_PUBLICATION_PUBLISHED_DURABLE"
	case CodeDurabilityUncertain:
		return "PCV3_PUBLICATION_DURABILITY_UNCERTAIN"
	case CodePublicationIndeterminate:
		return "PCV3_PUBLICATION_INDETERMINATE"
	default:
		return "PCV3_PUBLICATION_UNKNOWN"
	}
}

func (code Code) GoString() string {
	return code.String()
}

func (code Code) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, code.String())
}

func writeFixedFormat(state fmt.State, verb rune, value string) {
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = state.Write([]byte(value))
}
