package pcv3

import (
	"errors"
	"fmt"
)

var (
	errInvalidRecoveryResult  = errors.New("pcv3: invalid recovery result")
	errInvalidRecoveryRequest = errors.New("pcv3: invalid recovery request")
)

// RecoveryMode separates explicit normal-v3 recovery from the two Force
// policies. Ordinary normal routing is intentionally not represented here.
type RecoveryMode uint8

const (
	RecoveryModeNormalV3 RecoveryMode = iota + 1
	RecoveryModeForce
	RecoveryModeForceUnverified
)

// ForceProvenance records how Force evidence relates to the semantic outcome.
// A fully Force-verified result remains OutcomeAuthenticatedDegraded.
type ForceProvenance uint8

const (
	ForceProvenanceNone ForceProvenance = iota
	ForceProvenanceVerified
	ForceProvenancePartial
	ForceProvenanceUnverified
)

// RecoveryRangeState identifies the authentication state of one canonical
// plaintext-record interval.
type RecoveryRangeState uint8

const (
	RecoveryRangeVerified RecoveryRangeState = iota + 1
	RecoveryRangeUnverified
	RecoveryRangeMissing
)

// RecoveryFinalState identifies the authentication state of the zero-length
// final record, which has no plaintext interval.
type RecoveryFinalState uint8

const (
	RecoveryFinalVerified RecoveryFinalState = iota + 1
	RecoveryFinalUnverified
	RecoveryFinalMissing
)

// RecoveryRange is immutable canonical evidence for one data-record interval.
// Its fields are private so callers cannot mutate or forge a returned value.
type RecoveryRange struct {
	recordIndex uint64
	start       uint64
	end         uint64
	state       RecoveryRangeState
}

func (recoveryRange RecoveryRange) RecordIndex() uint64 { return recoveryRange.recordIndex }

func (recoveryRange RecoveryRange) Start() uint64 { return recoveryRange.start }

func (recoveryRange RecoveryRange) End() uint64 { return recoveryRange.end }

func (recoveryRange RecoveryRange) State() RecoveryRangeState { return recoveryRange.state }

func (RecoveryRange) String() string { return "pcv3: recovery range evidence" }

func (recoveryRange RecoveryRange) GoString() string { return recoveryRange.String() }

func (recoveryRange RecoveryRange) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, recoveryRange.String())
}

// RecoveryResult is the immutable semantic recovery state. It contains no raw
// errors, identities, comments, keys, credentials, or recovered bytes.
type RecoveryResult struct {
	outcome         Outcome
	provenance      ForceProvenance
	stage           Stage
	plaintextLength uint64
	ranges          []RecoveryRange
	final           RecoveryFinalState
}

func newRecoveryResult(
	outcome Outcome,
	provenance ForceProvenance,
	stage Stage,
	plaintextLength uint64,
	ranges []RecoveryRange,
	final RecoveryFinalState,
) (*RecoveryResult, error) {
	if _, ok := codeFor(outcome, stage); !ok ||
		!validRecoveryEvidence(outcome, provenance, plaintextLength, ranges, final) {
		return nil, errInvalidRecoveryResult
	}

	result := &RecoveryResult{
		outcome:         outcome,
		provenance:      provenance,
		stage:           stage,
		plaintextLength: plaintextLength,
		final:           final,
	}
	if ranges != nil {
		result.ranges = append([]RecoveryRange(nil), ranges...)
	}
	return result, nil
}

func newRecoveryResultFromNormal(result *normalReadResult) (*RecoveryResult, error) {
	if result == nil {
		return nil, errInvalidRecoveryResult
	}
	return newRecoveryResult(
		result.Outcome(),
		ForceProvenanceNone,
		result.Stage(),
		0,
		nil,
		0,
	)
}

func validRecoveryEvidence(
	outcome Outcome,
	provenance ForceProvenance,
	plaintextLength uint64,
	ranges []RecoveryRange,
	final RecoveryFinalState,
) bool {
	if provenance == ForceProvenanceNone {
		return outcome != OutcomeForcePartial && outcome != OutcomeForceUnverified &&
			plaintextLength == 0 && len(ranges) == 0 && final == 0
	}
	if !validCanonicalRecoveryRanges(plaintextLength, ranges) || !validRecoveryFinalState(final) {
		return false
	}

	hasVerified := final == RecoveryFinalVerified
	hasUnverified := final == RecoveryFinalUnverified
	hasDamage := final != RecoveryFinalVerified
	for _, recoveryRange := range ranges {
		switch recoveryRange.state {
		case RecoveryRangeVerified:
			hasVerified = true
		case RecoveryRangeUnverified:
			hasUnverified = true
			hasDamage = true
		case RecoveryRangeMissing:
			hasDamage = true
		}
	}

	switch provenance {
	case ForceProvenanceVerified:
		return outcome == OutcomeAuthenticatedDegraded && !hasDamage
	case ForceProvenancePartial:
		return outcome == OutcomeForcePartial && hasVerified && hasDamage
	case ForceProvenanceUnverified:
		return outcome == OutcomeForceUnverified && !hasVerified && hasUnverified
	default:
		return false
	}
}

func validCanonicalRecoveryRanges(plaintextLength uint64, ranges []RecoveryRange) bool {
	recordCount, ok := checkedCeilDiv64(plaintextLength, recordPlaintextMax)
	if !ok || uint64(len(ranges)) != recordCount {
		return false
	}
	for index, recoveryRange := range ranges {
		recordIndex := uint64(index)
		start, ok := checkedMul64(recordIndex, recordPlaintextMax)
		if !ok {
			return false
		}
		end, ok := checkedAdd64(start, recordPlaintextMax)
		if !ok || end > plaintextLength {
			end = plaintextLength
		}
		if recoveryRange.recordIndex != recordIndex || recoveryRange.start != start ||
			recoveryRange.end != end || start >= end || !validRecoveryRangeState(recoveryRange.state) {
			return false
		}
	}
	return true
}

func validRecoveryRangeState(state RecoveryRangeState) bool {
	return state == RecoveryRangeVerified || state == RecoveryRangeUnverified ||
		state == RecoveryRangeMissing
}

func validRecoveryFinalState(state RecoveryFinalState) bool {
	return state == RecoveryFinalVerified || state == RecoveryFinalUnverified ||
		state == RecoveryFinalMissing
}

func (result *RecoveryResult) Outcome() Outcome {
	if result == nil {
		return 0
	}
	return result.outcome
}

func (result *RecoveryResult) ForceProvenance() ForceProvenance {
	if result == nil {
		return 0
	}
	return result.provenance
}

func (result *RecoveryResult) Stage() Stage {
	if result == nil {
		return 0
	}
	return result.stage
}

func (result *RecoveryResult) Code() Code {
	if result == nil {
		return 0
	}
	code, _ := codeFor(result.outcome, result.stage)
	return code
}

func (result *RecoveryResult) PlaintextLength() uint64 {
	if result == nil {
		return 0
	}
	return result.plaintextLength
}

func (result *RecoveryResult) Ranges() []RecoveryRange {
	if result == nil || result.ranges == nil {
		return nil
	}
	return append([]RecoveryRange(nil), result.ranges...)
}

func (result *RecoveryResult) FinalRecordState() RecoveryFinalState {
	if result == nil {
		return 0
	}
	return result.final
}

func (result *RecoveryResult) Error() string {
	if result == nil {
		return "pcv3: recovery result unavailable"
	}
	switch result.outcome {
	case OutcomeSuccess:
		return "pcv3: recovery authenticated"
	case OutcomeAuthenticatedDegraded:
		return "pcv3: recovery authenticated with degraded provenance"
	case OutcomeForcePartial:
		return "pcv3: recovery partially verified"
	case OutcomeForceUnverified:
		return "pcv3: recovery unverified"
	default:
		return "pcv3: recovery failed"
	}
}

func (result *RecoveryResult) String() string { return result.Error() }

func (result *RecoveryResult) GoString() string { return result.Error() }

func (result *RecoveryResult) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, result.Error())
}

func (result *RecoveryResult) Close() {
	if result == nil {
		return
	}
	for index := range result.ranges {
		result.ranges[index] = RecoveryRange{}
	}
	result.ranges = nil
	result.outcome = 0
	result.provenance = 0
	result.stage = 0
	result.plaintextLength = 0
	result.final = 0
}

type unverifiedConsentState struct {
	active bool
	role   CapsuleRole
}

// recoveryRequest is private policy authority. Its unverified capability can
// exist only during withUnverifiedRecoveryRequest's callback.
type recoveryRequest struct {
	mode    RecoveryMode
	consent *unverifiedConsentState
}

func newRecoveryRequest(mode RecoveryMode) (recoveryRequest, error) {
	if mode != RecoveryModeNormalV3 && mode != RecoveryModeForce {
		return recoveryRequest{}, errInvalidRecoveryRequest
	}
	return recoveryRequest{mode: mode}, nil
}

func withUnverifiedRecoveryRequest(
	role CapsuleRole,
	callback func(recoveryRequest) error,
) error {
	if !isSupportedCapsuleRole(role) || callback == nil {
		return errInvalidRecoveryRequest
	}
	state := &unverifiedConsentState{active: true, role: role}
	defer func() {
		state.active = false
		state.role = 0
	}()
	return callback(recoveryRequest{mode: RecoveryModeForceUnverified, consent: state})
}

func (request recoveryRequest) valid() bool {
	switch request.mode {
	case RecoveryModeNormalV3, RecoveryModeForce:
		return request.consent == nil
	case RecoveryModeForceUnverified:
		return request.consent != nil && request.consent.active &&
			isSupportedCapsuleRole(request.consent.role)
	default:
		return false
	}
}

func (request recoveryRequest) Mode() RecoveryMode {
	if !request.valid() {
		return 0
	}
	return request.mode
}

func (request recoveryRequest) authorizesUnverified(role CapsuleRole) bool {
	return request.valid() && request.mode == RecoveryModeForceUnverified &&
		isSupportedCapsuleRole(role) && request.consent.role == role
}

func (recoveryRequest) String() string { return "pcv3: recovery request" }

func (request recoveryRequest) GoString() string { return request.String() }

func (request recoveryRequest) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, request.String())
}
