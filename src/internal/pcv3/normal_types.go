package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"fmt"
)

// normalVolumeSink is operation-owned staging. The reader can only complete
// after the sink has retained every verified record and final closure succeeds.
type normalVolumeSink interface {
	normalRecordSink
	abortUncommitted()
}

type normalCompletion struct{}

// normalReadResult exposes only coarse conformance state and an authenticated
// public comment copy. It intentionally contains no source or key material.
type normalReadResult struct {
	outcome       Outcome
	stage         Stage
	authenticated uint8
	comment       []byte
}

func newNormalReadResult(outcome Outcome, stage Stage, authenticated int, comment []byte) *normalReadResult {
	// The closed capsule engine can authenticate only the primary and backup
	// slots. Guard the uint8 conversion against accidental future widening.
	if authenticated < 0 || authenticated > 2 {
		authenticated = 0
	}
	result := &normalReadResult{outcome: outcome, stage: stage, authenticated: uint8(authenticated)}
	if comment != nil {
		result.comment = append([]byte(nil), comment...)
	}
	return result
}

func (result *normalReadResult) Outcome() Outcome {
	if result == nil {
		return 0
	}
	return result.outcome
}

func (result *normalReadResult) Stage() Stage {
	if result == nil {
		return 0
	}
	return result.stage
}

func (result *normalReadResult) AuthenticatedCapsules() int {
	if result == nil {
		return 0
	}
	return int(result.authenticated)
}

func (result *normalReadResult) Code() Code {
	if result == nil {
		return 0
	}
	code, _ := codeFor(result.outcome, result.stage)
	return code
}

func (result *normalReadResult) Error() string {
	if result == nil {
		return "pcv3: normal volume operation failed"
	}
	switch result.outcome {
	case OutcomeSuccess:
		return "pcv3: normal volume authenticated"
	case OutcomeAuthenticatedDegraded:
		return "pcv3: normal volume authenticated with degraded recovery"
	case OutcomeCredentialsOrDamage, OutcomeAuthenticationFailed:
		return "pcv3: credentials incorrect or volume damaged"
	default:
		return "pcv3: normal volume operation failed"
	}
}

func (result *normalReadResult) String() string { return result.Error() }

func (result *normalReadResult) GoString() string { return result.Error() }

func (result *normalReadResult) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, result.Error())
}

func (result *normalReadResult) commentBytes() []byte {
	if result == nil || result.comment == nil {
		return nil
	}
	return append([]byte(nil), result.comment...)
}

func (result *normalReadResult) Close() {
	if result != nil {
		pcv3crypto.SecureZero(result.comment)
		result.comment = nil
		result.outcome = 0
		result.stage = 0
		result.authenticated = 0
	}
}

type normalKeyBorrower interface {
	withKey(
		context.Context,
		pcv3credential.KeyRequest,
		func([]byte) error,
	) error
}

type metadataResultState uint8

const (
	metadataDamaged metadataResultState = iota + 1
	metadataAuthenticatedPublic
)

// metadataResult owns only an authenticated copy of the public comment.
// Damage remains a package-private, nonterminal warning for the final reader.
type metadataResult struct {
	state   metadataResultState
	comment []byte
}

func (result *metadataResult) Error() string {
	if result == nil {
		return "pcv3: metadata result unavailable"
	}
	switch result.state {
	case metadataAuthenticatedPublic:
		return "pcv3: authenticated public metadata"
	case metadataDamaged:
		return "pcv3: metadata damaged"
	default:
		return "pcv3: metadata result unavailable"
	}
}

func (result *metadataResult) String() string {
	return result.Error()
}

func (result *metadataResult) GoString() string {
	return result.Error()
}

func (result *metadataResult) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, result.Error())
}

func (result *metadataResult) commentBytes() []byte {
	if result == nil || result.state != metadataAuthenticatedPublic {
		return nil
	}
	comment := make([]byte, len(result.comment))
	copy(comment, result.comment)
	return comment
}

func (result *metadataResult) close() {
	if result == nil {
		return
	}
	pcv3crypto.SecureZero(result.comment)
	result.comment = nil
	result.state = 0
}

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
	keyBorrower   normalKeyBorrower
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

func (result *normalAuthResult) withKey(
	ctx context.Context,
	request pcv3credential.KeyRequest,
	callback func([]byte) error,
) error {
	if result == nil || ctx == nil || callback == nil {
		return errInvalidMetadataRequest
	}
	if result.keyBorrower != nil {
		return result.keyBorrower.withKey(ctx, request, callback)
	}
	if result.owner == nil {
		return errInvalidMetadataRequest
	}

	var key [32]byte
	defer pcv3crypto.SecureZero(key[:])
	var callbackErr error
	err := result.owner.WithKeys(ctx, func(keys *pcv3credential.BorrowedKeys) error {
		if err := keys.CopyKey(request, key[:]); err != nil {
			callbackErr = err
			return err
		}
		callbackErr = callback(key[:])
		return callbackErr
	})
	if callbackErr != nil {
		return callbackErr
	}
	return err
}

func (result *normalAuthResult) Close() {
	if result == nil {
		return
	}
	if result.owner != nil {
		result.owner.Close()
		result.owner = nil
	}
	result.keyBorrower = nil
	result.candidate = Candidate{}
	result.geometry = Geometry{}
}
