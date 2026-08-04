package pcv3

import (
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Outcome identifies one name in the closed PCV3 conformance registry.
type Outcome uint8

const (
	// OutcomeUnsupportedRoutingPreKDF rejects an unknown claimed PCV route.
	OutcomeUnsupportedRoutingPreKDF Outcome = iota + 1
	// OutcomeInvalidStructurePreKDF rejects malformed claimed PCV structure.
	OutcomeInvalidStructurePreKDF
	// OutcomeOperationFailed reports a non-structural input operation failure.
	OutcomeOperationFailed
	// OutcomeCredentialsOrDamage collapses wrong credentials and capsule damage.
	OutcomeCredentialsOrDamage
	// OutcomeAuthenticatedDegraded retains one authenticated recovery path.
	OutcomeAuthenticatedDegraded
	// OutcomeAmbiguousVolume rejects conflicting authenticated replicas.
	OutcomeAmbiguousVolume
	// OutcomeSuccess reports a fully authenticated, non-degraded result.
	OutcomeSuccess
	// OutcomeAuthenticationFailed rejects a confirmed volume with failed payload authentication.
	OutcomeAuthenticationFailed
	// OutcomeForcePartial reports verified anchors with missing or damaged payload records.
	OutcomeForcePartial
	// OutcomeForceUnverified reports explicit unverified recovery without a payload anchor.
	OutcomeForceUnverified
	// OutcomeCommittedDurabilityUncertain reports publication without confirmed directory durability.
	OutcomeCommittedDurabilityUncertain
)

// Stage identifies one boundary in the closed PCV3 conformance registry.
type Stage uint8

const StageNone Stage = 0

const (
	StageRouting Stage = iota + 1
	StagePreamble
	StageCapsuleRS
	StageCapsuleStructure
	StageTailGeometry
	StageInputIO
	StageCredentialPolicy
	StageWrapAuth
	StageUnwrap
	StageReplicaAuth
	StageKDFRuntime
	StageCancellation
	StageMetadata
	StageDescriptor
	StageRecordBodyRS
	StageRecordAuth
	StageFinalRecord
	StageOutputPublication
	StageD1Bootstrap
	StageD1Body
	StageInnerVolume
	StageRNG
	StageOutputWrite
	StageDirectorySync
)

// Code is the stable coarse code exposed by platform adapters.
type Code uint8

const (
	CodeUnsupported Code = iota + 1
	CodeInvalidStructure
	CodeOperationFailed
	CodeCredentialsOrDamage
	CodeAuthenticatedDegraded
	CodeAmbiguousVolume
	CodeSuccess
	CodeAuthenticationFailed
)

// ErrInvalidFailureMapping reports a caller attempt to create a non-normative
// outcome/stage pairing.
var ErrInvalidFailureMapping = errors.New("pcv3: invalid failure mapping")

// Failure is the sealed typed view of a legal Phase-3 failure. Callers can use
// errors.As for inspection but cannot implement or construct this interface.
type Failure interface {
	error
	fmt.Stringer
	fmt.GoStringer
	Outcome() Outcome
	Stage() Stage
	Code() Code
	isPCV3Failure()
}

type failureError struct {
	outcome Outcome
	stage   Stage
	cause   error
}

// Outcome returns the conformance outcome.
func (failure *failureError) Outcome() Outcome {
	if failure == nil {
		return 0
	}
	return failure.outcome
}

// Stage returns the earliest applicable conformance stage.
func (failure *failureError) Stage() Stage {
	if failure == nil {
		return 0
	}
	return failure.stage
}

// Code returns the stable adapter code for this legal mapping.
func (failure *failureError) Code() Code {
	if failure == nil {
		return 0
	}
	code, _ := codeFor(failure.outcome, failure.stage)
	return code
}

// Error returns a fixed message and never formats the underlying input cause.
func (failure *failureError) Error() string {
	if failure == nil {
		return "pcv3: failure"
	}
	switch failure.outcome {
	case OutcomeUnsupportedRoutingPreKDF:
		return "pcv3: unsupported routing before KDF"
	case OutcomeInvalidStructurePreKDF:
		return "pcv3: invalid structure before KDF"
	case OutcomeOperationFailed:
		return "pcv3: input operation failed"
	case OutcomeCredentialsOrDamage:
		return "pcv3: credentials incorrect or volume damaged"
	case OutcomeAuthenticatedDegraded:
		return "pcv3: authenticated with degraded recovery redundancy"
	case OutcomeAmbiguousVolume:
		return "pcv3: ambiguous authenticated volume"
	case OutcomeSuccess:
		return "pcv3: authentication succeeded"
	default:
		return "pcv3: failure"
	}
}

// String returns the same fixed, redacted representation as Error.
func (failure *failureError) String() string {
	return failure.Error()
}

// GoString prevents debug formatting from exposing private fields or causes.
func (failure *failureError) GoString() string {
	return failure.Error()
}

// Format keeps every fmt verb on the fixed, redacted representation.
func (failure *failureError) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, failure.Error())
}

// Unwrap preserves programmatic source-error inspection without formatting it.
func (failure *failureError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (*failureError) isPCV3Failure() {}

// NewUnsupportedRoutingError returns the only legal unsupported-routing
// mapping. Claimed PCV ownership remains terminal to callers.
func NewUnsupportedRoutingError() error {
	return newError(OutcomeUnsupportedRoutingPreKDF, StageRouting, nil)
}

// NewInvalidStructureError returns a structural failure at a legal pre-KDF
// stage, or ErrInvalidFailureMapping when the stage belongs to another class.
func NewInvalidStructureError(stage Stage) error {
	return newError(OutcomeInvalidStructurePreKDF, stage, nil)
}

// NewInputError returns the only Phase-3 operational failure. EOF-like causes
// are structural truncation and are rejected to prevent classification drift.
func NewInputError(cause error) error {
	if errors.Is(cause, io.EOF) || errors.Is(cause, io.ErrUnexpectedEOF) {
		return ErrInvalidFailureMapping
	}
	return newError(OutcomeOperationFailed, StageInputIO, cause)
}

func newError(outcome Outcome, stage Stage, cause error) error {
	if _, ok := codeFor(outcome, stage); !ok {
		return ErrInvalidFailureMapping
	}
	return &failureError{outcome: outcome, stage: stage, cause: cause}
}

func codeFor(outcome Outcome, stage Stage) (Code, bool) {
	switch outcome {
	case OutcomeUnsupportedRoutingPreKDF:
		return CodeUnsupported, stage == StageRouting
	case OutcomeInvalidStructurePreKDF:
		switch stage {
		case StagePreamble, StageCapsuleRS, StageCapsuleStructure, StageTailGeometry:
			return CodeInvalidStructure, true
		default:
			return 0, false
		}
	case OutcomeOperationFailed:
		switch stage {
		case StageInputIO, StageCredentialPolicy, StageUnwrap,
			StageKDFRuntime, StageCancellation, StageOutputWrite:
			return CodeOperationFailed, true
		default:
			return 0, false
		}
	case OutcomeCredentialsOrDamage:
		return CodeCredentialsOrDamage, stage == StageWrapAuth
	case OutcomeAuthenticatedDegraded:
		switch stage {
		case StagePreamble, StageCapsuleRS, StageCapsuleStructure,
			StageTailGeometry, StageWrapAuth, StageReplicaAuth, StageMetadata:
			return CodeAuthenticatedDegraded, true
		default:
			return 0, false
		}
	case OutcomeAmbiguousVolume:
		return CodeAmbiguousVolume, stage == StageCapsuleStructure
	case OutcomeSuccess:
		return CodeSuccess, stage == StageNone
	case OutcomeAuthenticationFailed:
		switch stage {
		case StageDescriptor, StageRecordBodyRS, StageRecordAuth, StageFinalRecord, StageTailGeometry:
			return CodeAuthenticationFailed, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

// String returns the exact conformance outcome name.
func (outcome Outcome) String() string {
	switch outcome {
	case OutcomeUnsupportedRoutingPreKDF:
		return "unsupported-routing-pre-kdf"
	case OutcomeInvalidStructurePreKDF:
		return "invalid-structure-pre-kdf"
	case OutcomeOperationFailed:
		return "operation-failed"
	case OutcomeCredentialsOrDamage:
		return "credentials-or-damage"
	case OutcomeAuthenticatedDegraded:
		return "authenticated-degraded"
	case OutcomeAmbiguousVolume:
		return "ambiguous-volume"
	case OutcomeSuccess:
		return "success"
	case OutcomeAuthenticationFailed:
		return "authentication-failed"
	case OutcomeForcePartial:
		return "force-partial"
	case OutcomeForceUnverified:
		return "force-unverified"
	case OutcomeCommittedDurabilityUncertain:
		return "committed-durability-uncertain"
	default:
		return "unknown-outcome"
	}
}

// GoString returns a fixed, non-numeric outcome name.
func (outcome Outcome) GoString() string {
	return outcome.String()
}

// Format keeps unknown outcomes from rendering their numeric value.
func (outcome Outcome) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, outcome.String())
}

// String returns the exact conformance stage name.
func (stage Stage) String() string {
	switch stage {
	case StageNone:
		return "none"
	case StageRouting:
		return "routing"
	case StagePreamble:
		return "preamble"
	case StageCapsuleRS:
		return "capsule-rs"
	case StageCapsuleStructure:
		return "capsule-structure"
	case StageTailGeometry:
		return "tail-geometry"
	case StageInputIO:
		return "input-io"
	case StageCredentialPolicy:
		return "credential-policy"
	case StageWrapAuth:
		return "wrap-auth"
	case StageUnwrap:
		return "unwrap"
	case StageReplicaAuth:
		return "replica-auth"
	case StageKDFRuntime:
		return "kdf-runtime"
	case StageCancellation:
		return "cancellation"
	case StageMetadata:
		return "metadata"
	case StageDescriptor:
		return "descriptor"
	case StageRecordBodyRS:
		return "record-body-rs"
	case StageRecordAuth:
		return "record-auth"
	case StageFinalRecord:
		return "final-record"
	case StageOutputPublication:
		return "output-publication"
	case StageD1Bootstrap:
		return "d1-bootstrap"
	case StageD1Body:
		return "d1-body"
	case StageInnerVolume:
		return "inner-volume"
	case StageRNG:
		return "rng"
	case StageOutputWrite:
		return "output-write"
	case StageDirectorySync:
		return "directory-sync"
	default:
		return "unknown-stage"
	}
}

// GoString returns a fixed, non-numeric stage name.
func (stage Stage) GoString() string {
	return stage.String()
}

// Format keeps unknown stages from rendering their numeric value.
func (stage Stage) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, stage.String())
}

// String returns the stable adapter code.
func (code Code) String() string {
	switch code {
	case CodeUnsupported:
		return "PCV3_UNSUPPORTED"
	case CodeInvalidStructure:
		return "PCV3_INVALID_STRUCTURE"
	case CodeOperationFailed:
		return "PCV3_OPERATION_FAILED"
	case CodeCredentialsOrDamage:
		return "PCV3_CREDENTIALS_OR_DAMAGE"
	case CodeAuthenticatedDegraded:
		return "PCV3_AUTHENTICATED_DEGRADED"
	case CodeAmbiguousVolume:
		return "PCV3_AMBIGUOUS_VOLUME"
	case CodeSuccess:
		return "PCV3_SUCCESS"
	case CodeAuthenticationFailed:
		return "PCV3_AUTHENTICATION_FAILED"
	default:
		return "PCV3_UNKNOWN"
	}
}

// GoString returns a fixed, non-numeric adapter code.
func (code Code) GoString() string {
	return code.String()
}

// Format keeps unknown adapter codes from rendering their numeric value.
func (code Code) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, code.String())
}

// ReaderUnavailableError distinguishes structural admission from a supported
// read/decrypt operation, success, or authentication.
type ReaderUnavailableError struct{}

// Error returns the fixed reader-unavailable message.
func (ReaderUnavailableError) Error() string {
	return "pcv3: reader unavailable after structural admission"
}

// String returns the fixed reader-unavailable message.
func (failure ReaderUnavailableError) String() string {
	return failure.Error()
}

// GoString prevents debug formatting from inventing internal state.
func (failure ReaderUnavailableError) GoString() string {
	return failure.Error()
}

// Format keeps every fmt verb on the fixed reader-unavailable message.
func (failure ReaderUnavailableError) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, failure.Error())
}

// ErrReaderUnavailable is the typed structural-admission sentinel.
var ErrReaderUnavailable = ReaderUnavailableError{}

func writeFixedFormat(state fmt.State, verb rune, value string) {
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = state.Write([]byte(value))
}
