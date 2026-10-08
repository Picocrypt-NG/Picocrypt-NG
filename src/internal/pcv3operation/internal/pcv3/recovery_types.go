package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
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
// A fully Force-verified result remains OutcomeAuthenticatedDegraded unless
// explicitly selected raw D1 outer provenance keeps the operation untrusted.
type ForceProvenance uint8

const (
	ForceProvenanceNone ForceProvenance = iota
	ForceProvenanceVerified
	ForceProvenancePartial
	ForceProvenanceUnverified
)

// D1BootstrapProvenance records the exact physical bootstrap evidence used to
// select one D1 OuterSecret. It is semantic provenance, never authorization.
type D1BootstrapProvenance uint8

const (
	D1BootstrapProvenanceNone D1BootstrapProvenance = iota
	D1BootstrapProvenanceFront
	D1BootstrapProvenanceTail
	D1BootstrapProvenanceMatching
)

// D1OuterProvenance records an explicitly selected, unanchored outer context.
// Inner record authentication cannot remove this operational trust boundary.
type D1OuterProvenance uint8

const (
	D1OuterProvenanceNone D1OuterProvenance = iota
	D1OuterProvenanceRawSelected
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
	outcome               Outcome
	provenance            ForceProvenance
	stage                 Stage
	d1BootstrapProvenance D1BootstrapProvenance
	d1OuterProvenance     D1OuterProvenance
	detailStage           Stage
	plaintextLength       uint64
	ranges                *pcv3ranges.Map
	final                 RecoveryFinalState
}

func newD1RawSelectedRecoveryResult(
	stage Stage,
	d1Provenance D1BootstrapProvenance,
	detailStage Stage,
	ranges *pcv3ranges.Map,
	final RecoveryFinalState,
) (*RecoveryResult, error) {
	if (stage != StageD1Bootstrap && stage != StageD1Body) ||
		!isPhysicalD1BootstrapProvenance(d1Provenance) || ranges == nil ||
		!validRecoveryFinalState(final) {
		return nil, errInvalidRecoveryResult
	}
	if _, ok := d1RecoveryCodeFor(OutcomeForceUnverified, stage, d1Provenance, detailStage); !ok {
		return nil, errInvalidRecoveryResult
	}
	summary := ranges.Summary()
	if summary.Verified == 0 && summary.Unverified == 0 &&
		final != RecoveryFinalVerified && final != RecoveryFinalUnverified {
		return nil, errInvalidRecoveryResult
	}
	return &RecoveryResult{
		outcome: OutcomeForceUnverified, provenance: ForceProvenanceUnverified,
		stage: stage, d1BootstrapProvenance: d1Provenance,
		d1OuterProvenance: D1OuterProvenanceRawSelected, detailStage: detailStage,
		plaintextLength: ranges.PlaintextLength(), ranges: ranges, final: final,
	}, nil
}

func newD1RecoveryResult(
	outcome Outcome,
	provenance ForceProvenance,
	stage Stage,
	d1Provenance D1BootstrapProvenance,
	detailStage Stage,
	plaintextLength uint64,
	ranges *pcv3ranges.Map,
	final RecoveryFinalState,
) (*RecoveryResult, error) {
	if _, ok := d1RecoveryCodeFor(outcome, stage, d1Provenance, detailStage); !ok ||
		!validRecoveryEvidence(outcome, provenance, plaintextLength, ranges, final) {
		return nil, errInvalidRecoveryResult
	}
	result := &RecoveryResult{
		outcome:               outcome,
		provenance:            provenance,
		stage:                 stage,
		d1BootstrapProvenance: d1Provenance,
		detailStage:           detailStage,
		plaintextLength:       plaintextLength,
		final:                 final,
	}
	if ranges != nil {
		result.ranges = ranges
	}
	return result, nil
}

func d1RecoveryCodeFor(
	outcome Outcome,
	stage Stage,
	provenance D1BootstrapProvenance,
	detailStage Stage,
) (Code, bool) {
	switch stage {
	case StageNone:
		return CodeSuccess, outcome == OutcomeSuccess &&
			(provenance == D1BootstrapProvenanceFront ||
				provenance == D1BootstrapProvenanceMatching) &&
			detailStage == StageNone
	case StageD1Bootstrap:
		if detailStage != StageNone {
			code, ok := codeFor(outcome, detailStage)
			return code, ok && validD1ProvenanceForOutcome(outcome, provenance)
		}
		switch outcome {
		case OutcomeAuthenticatedDegraded:
			return CodeAuthenticatedDegraded, isSelectedD1BootstrapProvenance(provenance)
		case OutcomeForcePartial:
			return CodeForcePartial, isSelectedD1BootstrapProvenance(provenance)
		case OutcomeForceUnverified:
			return CodeForceUnverified, isPhysicalD1BootstrapProvenance(provenance)
		case OutcomeCredentialsOrDamage:
			return CodeCredentialsOrDamage, provenance == D1BootstrapProvenanceNone
		case OutcomeAmbiguousVolume:
			return CodeAmbiguousVolume, provenance == D1BootstrapProvenanceNone
		default:
			return 0, false
		}
	case StageD1Body:
		if detailStage != StageNone {
			code, ok := codeFor(outcome, detailStage)
			return code, ok && validD1ProvenanceForOutcome(outcome, provenance)
		}
		switch outcome {
		case OutcomeAuthenticatedDegraded:
			return CodeAuthenticatedDegraded, isSelectedD1BootstrapProvenance(provenance)
		case OutcomeForcePartial:
			return CodeForcePartial, isSelectedD1BootstrapProvenance(provenance)
		case OutcomeForceUnverified:
			return CodeForceUnverified, isPhysicalD1BootstrapProvenance(provenance)
		case OutcomeAuthenticationFailed:
			return CodeAuthenticationFailed, isSelectedD1BootstrapProvenance(provenance)
		case OutcomeCredentialsOrDamage:
			return CodeCredentialsOrDamage, isSelectedD1BootstrapProvenance(provenance)
		case OutcomeAmbiguousVolume:
			return CodeAmbiguousVolume, provenance == D1BootstrapProvenanceNone
		default:
			return 0, false
		}
	case StageInnerVolume:
		if !validD1ProvenanceForOutcome(outcome, provenance) || detailStage == StageNone {
			return 0, false
		}
		return codeFor(outcome, detailStage)
	default:
		return 0, false
	}
}

func validD1ProvenanceForOutcome(
	outcome Outcome,
	provenance D1BootstrapProvenance,
) bool {
	if outcome == OutcomeForceUnverified {
		return isPhysicalD1BootstrapProvenance(provenance)
	}
	return isSelectedD1BootstrapProvenance(provenance)
}

func isSelectedD1BootstrapProvenance(provenance D1BootstrapProvenance) bool {
	return isPhysicalD1BootstrapProvenance(provenance) ||
		provenance == D1BootstrapProvenanceMatching
}

func isPhysicalD1BootstrapProvenance(provenance D1BootstrapProvenance) bool {
	return provenance == D1BootstrapProvenanceFront ||
		provenance == D1BootstrapProvenanceTail
}

func newRecoveryResult(
	outcome Outcome,
	provenance ForceProvenance,
	stage Stage,
	plaintextLength uint64,
	ranges *pcv3ranges.Map,
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
		result.ranges = ranges
	}
	return result, nil
}

func validRecoveryEvidence(
	outcome Outcome,
	provenance ForceProvenance,
	plaintextLength uint64,
	ranges *pcv3ranges.Map,
	final RecoveryFinalState,
) bool {
	if provenance == ForceProvenanceNone {
		return outcome != OutcomeForcePartial && outcome != OutcomeForceUnverified &&
			plaintextLength == 0 && ranges == nil && final == 0
	}
	if !validCanonicalRecoveryRanges(plaintextLength, ranges) || !validRecoveryFinalState(final) {
		return false
	}

	hasVerified := final == RecoveryFinalVerified
	hasUnverified := final == RecoveryFinalUnverified
	hasDamage := final != RecoveryFinalVerified
	summary := ranges.Summary()
	hasVerified = hasVerified || summary.Verified != 0
	hasUnverified = hasUnverified || summary.Unverified != 0
	hasDamage = hasDamage || summary.Missing != 0 || summary.Unverified != 0

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

func validCanonicalRecoveryRanges(plaintextLength uint64, ranges *pcv3ranges.Map) bool {
	return ranges != nil && ranges.PlaintextLength() == plaintextLength
}

func recoveryRangeFromMap(r pcv3ranges.Range) RecoveryRange {
	return RecoveryRange{recordIndex: r.Index, start: r.Start, end: r.End, state: RecoveryRangeState(r.State)}
}

func recoveryRangeAt(m *pcv3ranges.Map, index uint64) (RecoveryRange, bool) {
	r, ok := m.At(index)
	return recoveryRangeFromMap(r), ok
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

// D1BootstrapProvenance returns the selected physical D1 bootstrap evidence.
func (result *RecoveryResult) D1BootstrapProvenance() D1BootstrapProvenance {
	if result == nil {
		return D1BootstrapProvenanceNone
	}
	return result.d1BootstrapProvenance
}

func (result *RecoveryResult) D1OuterProvenance() D1OuterProvenance {
	if result == nil {
		return D1OuterProvenanceNone
	}
	return result.d1OuterProvenance
}

// DetailStage returns the closed inner normal stage reached through D1. When
// outer damage is also present, Stage retains that earlier D1 boundary.
func (result *RecoveryResult) DetailStage() Stage {
	if result == nil {
		return StageNone
	}
	return result.detailStage
}

func (result *RecoveryResult) Code() Code {
	if result == nil {
		return 0
	}
	if code, ok := d1RecoveryCodeFor(
		result.outcome,
		result.stage,
		result.d1BootstrapProvenance,
		result.detailStage,
	); ok {
		return code
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

func (result *RecoveryResult) Ranges() *pcv3ranges.Map {
	if result == nil || result.ranges == nil {
		return nil
	}
	// Copy only the fixed header: callers cannot overwrite the shared map
	// object itself. Its private immutable pages and index remain shared.
	snapshot := *result.ranges
	return &snapshot
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
	return result.fixedMessage()
}

func (result RecoveryResult) fixedMessage() string {
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

func (result RecoveryResult) String() string { return result.fixedMessage() }

func (result RecoveryResult) GoString() string { return result.fixedMessage() }

func (result RecoveryResult) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, result.fixedMessage())
}

func (result *RecoveryResult) Close() {
	if result == nil {
		return
	}
	result.ranges = nil
	result.outcome = 0
	result.provenance = 0
	result.stage = 0
	result.d1BootstrapProvenance = 0
	result.d1OuterProvenance = 0
	result.detailStage = 0
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
	budget  *pcv3ranges.Budget
	mode    RecoveryMode
	consent *unverifiedConsentState
}

func newRecoveryRequest(mode RecoveryMode) (recoveryRequest, error) {
	if mode != RecoveryModeNormalV3 && mode != RecoveryModeForce {
		return recoveryRequest{}, errInvalidRecoveryRequest
	}
	return recoveryRequest{mode: mode, budget: pcv3ranges.NewBudget(pcv3ranges.DefaultBudgetBytes)}, nil
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
	return callback(recoveryRequest{mode: RecoveryModeForceUnverified, consent: state, budget: pcv3ranges.NewBudget(pcv3ranges.DefaultBudgetBytes)})
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
