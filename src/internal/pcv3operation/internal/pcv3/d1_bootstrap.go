package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	pcv3stream "Picocrypt-NG/internal/pcv3operation/internal/pcv3crypto"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	d1BootstrapLength           = 224
	d1BootstrapPrefixLength     = 96
	d1BootstrapReplicaTagOffset = 96
	d1BootstrapWrapTagOffset    = 160
	d1OuterSecretLength         = 40
	d1OuterReplicaDomain        = "Picocrypt-NG/PCV3/outer/replica\x00"
	d1OuterWrapDomain           = "Picocrypt-NG/PCV3/outer/wrap\x00"
)

var errInvalidD1Bootstrap = errors.New("pcv3: invalid outer bootstrap request")

// D1BootstrapRole identifies the physical front or tail outer bootstrap.
type D1BootstrapRole uint8

const (
	D1BootstrapFront D1BootstrapRole = iota
	D1BootstrapTail
)

type d1BootstrapCandidate struct {
	role          D1BootstrapRole
	argonSalt     [16]byte
	wrapNonce     [24]byte
	wrapSerpentIV [16]byte
	wrappedSecret [d1OuterSecretLength]byte
	replicaTag    [64]byte
	wrapTag       [64]byte
}

func (d1BootstrapCandidate) String() string {
	return "pcv3: unauthenticated outer bootstrap"
}

func (candidate d1BootstrapCandidate) GoString() string {
	return candidate.String()
}

func (candidate d1BootstrapCandidate) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, candidate.String())
}

func parseD1Bootstrap(
	raw []byte,
	role D1BootstrapRole,
) (d1BootstrapCandidate, error) {
	if len(raw) != d1BootstrapLength || !validD1BootstrapRole(role) {
		return d1BootstrapCandidate{}, errInvalidD1Bootstrap
	}
	var candidate d1BootstrapCandidate
	candidate.role = role
	copy(candidate.argonSalt[:], raw[0:16])
	copy(candidate.wrapNonce[:], raw[16:40])
	copy(candidate.wrapSerpentIV[:], raw[40:56])
	copy(candidate.wrappedSecret[:], raw[56:96])
	copy(candidate.replicaTag[:], raw[96:160])
	copy(candidate.wrapTag[:], raw[160:224])
	return candidate, nil
}

func (candidate d1BootstrapCandidate) prefix() [d1BootstrapPrefixLength]byte {
	var prefix [d1BootstrapPrefixLength]byte
	copy(prefix[0:16], candidate.argonSalt[:])
	copy(prefix[16:40], candidate.wrapNonce[:])
	copy(prefix[40:56], candidate.wrapSerpentIV[:])
	copy(prefix[56:96], candidate.wrappedSecret[:])
	return prefix
}

type d1BootstrapWrapKeys struct {
	xChaCha20 [32]byte
	serpent   [32]byte
	mac       [32]byte
}

func (keys *d1BootstrapWrapKeys) close() {
	if keys == nil {
		return
	}
	pcv3crypto.SecureZero(keys.xChaCha20[:])
	pcv3crypto.SecureZero(keys.serpent[:])
	pcv3crypto.SecureZero(keys.mac[:])
}

type d1BootstrapCredentialAccess interface {
	role() D1BootstrapRole
	withWrapKeys(context.Context, func(*d1BootstrapWrapKeys) error) error
}

type d1BootstrapOwnerAccess struct {
	owner *pcv3credential.D1OuterCredentialOwner
}

func (access *d1BootstrapOwnerAccess) role() D1BootstrapRole {
	if access == nil || access.owner == nil {
		return D1BootstrapRole(0xff)
	}
	role, ok := d1BootstrapRoleForKeyRole(access.owner.Role())
	if !ok {
		return D1BootstrapRole(0xff)
	}
	return role
}

func (access *d1BootstrapOwnerAccess) withWrapKeys(
	ctx context.Context,
	callback func(*d1BootstrapWrapKeys) error,
) error {
	if access == nil || access.owner == nil || ctx == nil || callback == nil {
		return errInvalidD1Bootstrap
	}
	var callbackErr error
	err := access.owner.WithKeys(
		ctx,
		func(borrowed *pcv3credential.BorrowedD1OuterCredentialKeys) error {
			var keys d1BootstrapWrapKeys
			defer keys.close()
			for _, request := range []struct {
				label       pcv3credential.D1OuterCredentialLabel
				destination []byte
			}{
				{pcv3credential.D1OuterCredentialWrapXChaCha20, keys.xChaCha20[:]},
				{pcv3credential.D1OuterCredentialWrapSerpent, keys.serpent[:]},
				{pcv3credential.D1OuterCredentialWrapMAC, keys.mac[:]},
			} {
				if err := borrowed.CopyKey(request.label, request.destination); err != nil {
					callbackErr = err
					return err
				}
			}
			callbackErr = callback(&keys)
			return callbackErr
		},
	)
	if callbackErr != nil {
		return callbackErr
	}
	return err
}

type d1BootstrapAuthSeams struct {
	unwrapParanoid func([]byte, []byte, []byte, []byte, []byte, []byte) error
}

func defaultD1BootstrapAuthSeams() d1BootstrapAuthSeams {
	return d1BootstrapAuthSeams{
		unwrapParanoid: pcv3stream.PCV3UnwrapParanoid1,
	}
}

type d1BootstrapEvaluationPolicy uint8

const (
	d1BootstrapVerifyBeforeUnwrap d1BootstrapEvaluationPolicy = iota
	d1BootstrapAllowRawUnwrap
)

type d1OuterSecretOwner struct {
	bodyLength uint64
	keys       *pcv3credential.D1OuterKeyOwner
}

func (*d1OuterSecretOwner) String() string {
	return "pcv3.d1OuterSecretOwner([REDACTED])"
}

func (*d1OuterSecretOwner) GoString() string {
	return "pcv3.d1OuterSecretOwner([REDACTED])"
}

func (owner *d1OuterSecretOwner) withOuterKeys(
	ctx context.Context,
	callback func(*pcv3credential.BorrowedD1OuterKeys) error,
) error {
	if owner == nil || owner.keys == nil || ctx == nil || callback == nil {
		return errInvalidD1Bootstrap
	}
	var callbackErr error
	err := owner.keys.WithKeys(
		ctx,
		func(keys *pcv3credential.BorrowedD1OuterKeys) error {
			callbackErr = callback(keys)
			return callbackErr
		},
	)
	if callbackErr != nil {
		return callbackErr
	}
	return err
}

func (owner *d1OuterSecretOwner) Close() {
	if owner == nil {
		return
	}
	if owner.keys != nil {
		owner.keys.Close()
		owner.keys = nil
	}
	owner.bodyLength = 0
}

type d1AuthenticatedBootstrap struct {
	candidate d1BootstrapCandidate
	secret    *d1OuterSecretOwner
}

func (*d1AuthenticatedBootstrap) String() string {
	return "pcv3.d1AuthenticatedBootstrap([REDACTED])"
}

func (*d1AuthenticatedBootstrap) GoString() string {
	return "pcv3.d1AuthenticatedBootstrap([REDACTED])"
}

func (bootstrap *d1AuthenticatedBootstrap) Close() {
	if bootstrap == nil {
		return
	}
	if bootstrap.secret != nil {
		bootstrap.secret.Close()
		bootstrap.secret = nil
	}
	bootstrap.candidate = d1BootstrapCandidate{}
}

func (bootstrap *d1AuthenticatedBootstrap) takeSecret() *d1OuterSecretOwner {
	if bootstrap == nil {
		return nil
	}
	secret := bootstrap.secret
	bootstrap.secret = nil
	return secret
}

type d1BootstrapAttempt struct {
	outcome       Outcome
	stage         Stage
	authenticated *d1AuthenticatedBootstrap
}

func newD1BootstrapAttempt(
	outcome Outcome,
	stage Stage,
	authenticated *d1AuthenticatedBootstrap,
) *d1BootstrapAttempt {
	return &d1BootstrapAttempt{
		outcome:       outcome,
		stage:         stage,
		authenticated: authenticated,
	}
}

func (attempt *d1BootstrapAttempt) Outcome() Outcome {
	if attempt == nil {
		return 0
	}
	return attempt.outcome
}

func (attempt *d1BootstrapAttempt) Stage() Stage {
	if attempt == nil {
		return 0
	}
	return attempt.stage
}

func (attempt *d1BootstrapAttempt) Error() string {
	if attempt == nil {
		return "pcv3: bootstrap authentication operation failed"
	}
	switch attempt.outcome {
	case OutcomeSuccess:
		return "pcv3: bootstrap authentication succeeded"
	case OutcomeCredentialsOrDamage:
		return "pcv3: credentials incorrect or volume damaged"
	case OutcomeOperationFailed:
		return "pcv3: bootstrap authentication operation failed"
	default:
		return "pcv3: bootstrap authentication failed"
	}
}

func (attempt *d1BootstrapAttempt) String() string { return attempt.Error() }

func (attempt *d1BootstrapAttempt) GoString() string { return attempt.Error() }

func (attempt *d1BootstrapAttempt) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, attempt.Error())
}

func (attempt *d1BootstrapAttempt) Close() {
	if attempt == nil {
		return
	}
	if attempt.authenticated != nil {
		attempt.authenticated.Close()
		attempt.authenticated = nil
	}
	attempt.outcome = 0
	attempt.stage = 0
}

type d1BootstrapEvaluation struct {
	secret          *d1OuterSecretOwner
	wrapVerified    bool
	replicaVerified bool
}

func (evaluation *d1BootstrapEvaluation) Close() {
	if evaluation == nil {
		return
	}
	if evaluation.secret != nil {
		evaluation.secret.Close()
		evaluation.secret = nil
	}
	evaluation.wrapVerified = false
	evaluation.replicaVerified = false
}

func (evaluation *d1BootstrapEvaluation) takeSecret() *d1OuterSecretOwner {
	if evaluation == nil {
		return nil
	}
	secret := evaluation.secret
	evaluation.secret = nil
	return secret
}

type d1BootstrapBinding struct {
	bodyLength      uint64
	wrapVerified    bool
	replicaVerified bool
	borrowOuterKeys func(
		context.Context,
		func(*pcv3credential.BorrowedD1OuterKeys) error,
	) error
}

func (binding *d1BootstrapBinding) withOuterKeys(
	ctx context.Context,
	callback func(*pcv3credential.BorrowedD1OuterKeys) error,
) error {
	if binding == nil || ctx == nil || callback == nil || binding.borrowOuterKeys == nil {
		return errInvalidD1Bootstrap
	}
	return binding.borrowOuterKeys(ctx, callback)
}

func (binding *d1BootstrapBinding) expire() {
	if binding == nil {
		return
	}
	binding.bodyLength = 0
	binding.wrapVerified = false
	binding.replicaVerified = false
}

func authenticateD1Bootstrap(
	ctx context.Context,
	candidate d1BootstrapCandidate,
	owner *pcv3credential.D1OuterCredentialOwner,
) *d1BootstrapAttempt {
	return authenticateD1BootstrapWithAccess(
		ctx,
		candidate,
		&d1BootstrapOwnerAccess{owner: owner},
		defaultD1BootstrapAuthSeams(),
	)
}

func authenticateD1BootstrapWithAccess(
	ctx context.Context,
	candidate d1BootstrapCandidate,
	access d1BootstrapCredentialAccess,
	seams d1BootstrapAuthSeams,
) *d1BootstrapAttempt {
	evaluation, stage, err := evaluateD1BootstrapWithAccess(
		ctx,
		candidate,
		access,
		seams,
		d1BootstrapVerifyBeforeUnwrap,
	)
	if err != nil {
		return newD1BootstrapAttempt(OutcomeOperationFailed, stage, nil)
	}
	defer evaluation.Close()
	if !evaluation.wrapVerified {
		return newD1BootstrapAttempt(
			OutcomeCredentialsOrDamage,
			StageWrapAuth,
			nil,
		)
	}
	if !evaluation.replicaVerified {
		return newD1BootstrapAttempt(
			OutcomeCredentialsOrDamage,
			StageReplicaAuth,
			nil,
		)
	}
	return newD1BootstrapAttempt(
		OutcomeSuccess,
		StageNone,
		&d1AuthenticatedBootstrap{
			candidate: candidate,
			secret:    evaluation.takeSecret(),
		},
	)
}

func bindD1BootstrapWithAccess(
	ctx context.Context,
	candidate d1BootstrapCandidate,
	access d1BootstrapCredentialAccess,
	seams d1BootstrapAuthSeams,
	callback func(*d1BootstrapBinding) error,
) error {
	if callback == nil {
		return errInvalidD1Bootstrap
	}
	evaluation, _, err := evaluateD1BootstrapWithAccess(
		ctx,
		candidate,
		access,
		seams,
		d1BootstrapAllowRawUnwrap,
	)
	if err != nil {
		return err
	}
	defer evaluation.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if evaluation.secret == nil || evaluation.secret.keys == nil {
		return errInvalidD1Bootstrap
	}
	keyOwner := evaluation.secret.keys
	binding := &d1BootstrapBinding{
		bodyLength:      evaluation.secret.bodyLength,
		wrapVerified:    evaluation.wrapVerified,
		replicaVerified: evaluation.replicaVerified,
		borrowOuterKeys: func(
			ctx context.Context,
			callback func(*pcv3credential.BorrowedD1OuterKeys) error,
		) error {
			return keyOwner.WithKeys(ctx, callback)
		},
	}
	defer binding.expire()
	if err := callback(binding); err != nil {
		return err
	}
	return ctx.Err()
}

func evaluateD1BootstrapWithAccess(
	ctx context.Context,
	candidate d1BootstrapCandidate,
	access d1BootstrapCredentialAccess,
	seams d1BootstrapAuthSeams,
	policy d1BootstrapEvaluationPolicy,
) (*d1BootstrapEvaluation, Stage, error) {
	if ctx == nil || access == nil || seams.unwrapParanoid == nil ||
		!validD1BootstrapRole(candidate.role) || access.role() != candidate.role ||
		(policy != d1BootstrapVerifyBeforeUnwrap && policy != d1BootstrapAllowRawUnwrap) {
		return nil, StageCredentialPolicy, errInvalidD1Bootstrap
	}
	if ctx.Err() != nil {
		return nil, StageCancellation, ctx.Err()
	}

	evaluation := &d1BootstrapEvaluation{}
	complete := false
	defer func() {
		if !complete {
			evaluation.Close()
		}
	}()
	var unwrapped [d1OuterSecretLength]byte
	defer pcv3crypto.SecureZero(unwrapped[:])
	unwrapAttempted := false
	err := access.withWrapKeys(ctx, func(keys *d1BootstrapWrapKeys) error {
		message := d1BootstrapWrapMessage(candidate)
		defer pcv3crypto.SecureZero(message)
		valid, err := verifySuiteMAC(
			SuiteParanoid,
			keys.mac[:],
			message,
			candidate.wrapTag[:],
		)
		if err != nil {
			return err
		}
		evaluation.wrapVerified = valid
		if !valid && policy == d1BootstrapVerifyBeforeUnwrap {
			return nil
		}
		unwrapAttempted = true
		return seams.unwrapParanoid(
			unwrapped[:],
			candidate.wrappedSecret[:],
			keys.xChaCha20[:],
			candidate.wrapNonce[:],
			keys.serpent[:],
			candidate.wrapSerpentIV[:],
		)
	})
	if err != nil {
		stage := StageCredentialPolicy
		if ctx.Err() != nil {
			stage = StageCancellation
		} else if unwrapAttempted {
			stage = StageUnwrap
		}
		return nil, stage, err
	}
	if !unwrapAttempted {
		complete = true
		return evaluation, StageWrapAuth, nil
	}

	outerKey := make([]byte, 32)
	copy(outerKey, unwrapped[0:32])
	keyOwner, err := pcv3credential.NewD1OuterKeyOwner(outerKey)
	if err != nil {
		return nil, StageUnwrap, err
	}
	evaluation.secret = &d1OuterSecretOwner{
		bodyLength: binary.BigEndian.Uint64(unwrapped[32:40]),
		keys:       keyOwner,
	}
	err = evaluation.secret.withOuterKeys(
		ctx,
		func(keys *pcv3credential.BorrowedD1OuterKeys) error {
			var replicaKey [32]byte
			defer pcv3crypto.SecureZero(replicaKey[:])
			if err := keys.CopyKey(
				pcv3credential.D1OuterReplicaMAC,
				keyRoleForD1Bootstrap(candidate.role),
				replicaKey[:],
			); err != nil {
				return err
			}
			message := d1BootstrapReplicaMessage(candidate)
			defer pcv3crypto.SecureZero(message)
			valid, err := verifySuiteMAC(
				SuiteParanoid,
				replicaKey[:],
				message,
				candidate.replicaTag[:],
			)
			evaluation.replicaVerified = valid
			return err
		},
	)
	if err != nil {
		stage := StageCredentialPolicy
		if ctx.Err() != nil {
			stage = StageCancellation
		}
		return nil, stage, err
	}
	complete = true
	return evaluation, StageNone, nil
}

func d1BootstrapReplicaMessage(candidate d1BootstrapCandidate) []byte {
	prefix := candidate.prefix()
	message := make([]byte, 0, len(d1OuterReplicaDomain)+1+len(prefix))
	message = append(message, d1OuterReplicaDomain...)
	message = append(message, byte(candidate.role))
	message = append(message, prefix[:]...)
	return message
}

func d1BootstrapWrapMessage(candidate d1BootstrapCandidate) []byte {
	prefix := candidate.prefix()
	message := make(
		[]byte,
		0,
		len(d1OuterWrapDomain)+1+len(prefix)+len(candidate.replicaTag),
	)
	message = append(message, d1OuterWrapDomain...)
	message = append(message, byte(candidate.role))
	message = append(message, prefix[:]...)
	message = append(message, candidate.replicaTag[:]...)
	return message
}

func sameD1OuterSecretAccess(
	ctx context.Context,
	leftLength uint64,
	left d1OuterKeyAccess,
	rightLength uint64,
	right d1OuterKeyAccess,
) (bool, error) {
	if ctx == nil || left == nil || right == nil {
		return false, errInvalidD1Bootstrap
	}
	if leftLength != rightLength {
		return false, nil
	}
	var leftSecret, rightSecret [d1OuterSecretLength]byte
	defer pcv3crypto.SecureZero(leftSecret[:])
	defer pcv3crypto.SecureZero(rightSecret[:])
	copyOuterKey := func(access d1OuterKeyAccess, destination []byte) error {
		return access.withOuterKeys(
			ctx,
			func(keys *pcv3credential.BorrowedD1OuterKeys) error {
				return keys.CopyOuterKey(destination)
			},
		)
	}
	if err := copyOuterKey(left, leftSecret[:32]); err != nil {
		return false, err
	}
	if err := copyOuterKey(right, rightSecret[:32]); err != nil {
		return false, err
	}
	binary.BigEndian.PutUint64(leftSecret[32:], leftLength)
	binary.BigEndian.PutUint64(rightSecret[32:], rightLength)
	return subtle.ConstantTimeCompare(leftSecret[:], rightSecret[:]) == 1, nil
}

func independentD1BootstrapParameters(
	front, tail d1BootstrapCandidate,
) bool {
	return front.argonSalt != tail.argonSalt &&
		front.wrapNonce != tail.wrapNonce &&
		front.wrapSerpentIV != tail.wrapSerpentIV
}

func validD1BootstrapRole(role D1BootstrapRole) bool {
	return role == D1BootstrapFront || role == D1BootstrapTail
}

func keyRoleForD1Bootstrap(role D1BootstrapRole) pcv3credential.KeyRole {
	if role == D1BootstrapTail {
		return pcv3credential.KeyRoleBackup
	}
	return pcv3credential.KeyRolePrimary
}

func d1BootstrapRoleForKeyRole(
	role pcv3credential.KeyRole,
) (D1BootstrapRole, bool) {
	switch role {
	case pcv3credential.KeyRolePrimary:
		return D1BootstrapFront, true
	case pcv3credential.KeyRoleBackup:
		return D1BootstrapTail, true
	default:
		return 0, false
	}
}
