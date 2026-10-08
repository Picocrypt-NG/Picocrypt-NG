package pcv3

import (
	"Picocrypt-NG/internal/pcv3result"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Outcome and Stage remain source-compatible aliases of the dependency-leaf
// result registry used by both format and publication packages.
type Outcome = pcv3result.Outcome

const (
	OutcomeUnsupportedRoutingPreKDF     = pcv3result.OutcomeUnsupportedRoutingPreKDF
	OutcomeInvalidStructurePreKDF       = pcv3result.OutcomeInvalidStructurePreKDF
	OutcomeOperationFailed              = pcv3result.OutcomeOperationFailed
	OutcomeCredentialsOrDamage          = pcv3result.OutcomeCredentialsOrDamage
	OutcomeAuthenticatedDegraded        = pcv3result.OutcomeAuthenticatedDegraded
	OutcomeAmbiguousVolume              = pcv3result.OutcomeAmbiguousVolume
	OutcomeSuccess                      = pcv3result.OutcomeSuccess
	OutcomeAuthenticationFailed         = pcv3result.OutcomeAuthenticationFailed
	OutcomeForcePartial                 = pcv3result.OutcomeForcePartial
	OutcomeForceUnverified              = pcv3result.OutcomeForceUnverified
	OutcomeCommittedDurabilityUncertain = pcv3result.OutcomeCommittedDurabilityUncertain
	OutcomePublicationIndeterminate     = pcv3result.OutcomePublicationIndeterminate
)

type Stage = pcv3result.Stage

const (
	StageNone              = pcv3result.StageNone
	StageRouting           = pcv3result.StageRouting
	StagePreamble          = pcv3result.StagePreamble
	StageCapsuleRS         = pcv3result.StageCapsuleRS
	StageCapsuleStructure  = pcv3result.StageCapsuleStructure
	StageTailGeometry      = pcv3result.StageTailGeometry
	StageInputIO           = pcv3result.StageInputIO
	StageResourceBudget    = pcv3result.StageResourceBudget
	StageCredentialPolicy  = pcv3result.StageCredentialPolicy
	StageWrapAuth          = pcv3result.StageWrapAuth
	StageUnwrap            = pcv3result.StageUnwrap
	StageReplicaAuth       = pcv3result.StageReplicaAuth
	StageKDFRuntime        = pcv3result.StageKDFRuntime
	StageCancellation      = pcv3result.StageCancellation
	StageMetadata          = pcv3result.StageMetadata
	StageDescriptor        = pcv3result.StageDescriptor
	StageRecordBodyRS      = pcv3result.StageRecordBodyRS
	StageRecordAuth        = pcv3result.StageRecordAuth
	StageFinalRecord       = pcv3result.StageFinalRecord
	StageOutputPublication = pcv3result.StageOutputPublication
	StageD1Bootstrap       = pcv3result.StageD1Bootstrap
	StageD1Body            = pcv3result.StageD1Body
	StageInnerVolume       = pcv3result.StageInnerVolume
	StageRNG               = pcv3result.StageRNG
	StageOutputWrite       = pcv3result.StageOutputWrite
	StageDirectorySync     = pcv3result.StageDirectorySync
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
	CodeForcePartial
	CodeForceUnverified
)

// ErrInvalidFailureMapping reports a caller attempt to create a non-normative
// outcome/stage pairing.
var ErrInvalidFailureMapping = errors.New("pcv3: invalid failure mapping")

// Failure is the sealed typed view of a legal PCV3 failure. Callers can use
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
	case OutcomeAuthenticationFailed:
		return "pcv3: authentication failed"
	case OutcomeForcePartial:
		return "pcv3: Force recovery is partially verified"
	case OutcomeForceUnverified:
		return "pcv3: Force recovery is unverified"
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

// NewInputError returns an input-operation failure. EOF-like causes
// are structural truncation and are rejected to prevent classification drift.
func NewInputError(cause error) error {
	if errors.Is(cause, io.EOF) || errors.Is(cause, io.ErrUnexpectedEOF) {
		return ErrInvalidFailureMapping
	}
	return newError(OutcomeOperationFailed, StageInputIO, cause)
}

// NewOutputWriteError returns an output-write operation failure while
// preserving the underlying destination error for programmatic inspection.
func NewOutputWriteError(cause error) error {
	return newError(OutcomeOperationFailed, StageOutputWrite, cause)
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
			StageKDFRuntime, StageCancellation, StageOutputWrite, StageResourceBudget:
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
	case OutcomeForcePartial:
		return CodeForcePartial, isForceDamageStage(stage)
	case OutcomeForceUnverified:
		return CodeForceUnverified, isForceDamageStage(stage)
	default:
		return 0, false
	}
}

func isForceDamageStage(stage Stage) bool {
	switch stage {
	case StagePreamble, StageCapsuleRS, StageCapsuleStructure,
		StageTailGeometry, StageWrapAuth, StageReplicaAuth, StageMetadata,
		StageDescriptor, StageRecordBodyRS, StageRecordAuth, StageFinalRecord:
		return true
	default:
		return false
	}
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
	case CodeForcePartial:
		return "PCV3_FORCE_PARTIAL"
	case CodeForceUnverified:
		return "PCV3_FORCE_UNVERIFIED"
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
