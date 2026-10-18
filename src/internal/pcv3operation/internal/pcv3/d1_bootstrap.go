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
	d1BootstrapLength             = 320
	d1BootstrapPrefixLength       = 128
	d1BootstrapReplicaTagOffset   = 128
	d1BootstrapWrapTagOffset      = 192
	d1BootstrapInnerWrapTagOffset = 256
	d1OuterSecretLength           = 40
	d1OuterReplicaDomain          = "Picocrypt-NG/PCV3/D1C/replica\x00"
	d1OuterWrapDomain             = "Picocrypt-NG/PCV3/D1C/outer/wrap\x00"
	d1InnerWrapDomain             = "Picocrypt-NG/PCV3/D1C/inner/wrap\x00"
)

var errInvalidD1Bootstrap = errors.New("pcv3: invalid outer bootstrap request")

// ErrD1ProfileRequired is a closed refusal: selected raw D1 data has no
// authenticated hidden profile and requires an explicit payload suite choice.
var ErrD1ProfileRequired = errors.New("pcv3: raw D1 recovery requires an explicit Standard or Paranoid suite")

var errD1ProfileMismatch = errors.New("pcv3: D1 suite choice contradicts authenticated profile")

// D1BootstrapRole identifies the physical front or tail outer bootstrap.
type D1BootstrapRole uint8

const (
	D1BootstrapFront D1BootstrapRole = iota
	D1BootstrapTail
)

type d1BootstrapCandidate struct {
	role             D1BootstrapRole
	argonSalt        [16]byte
	wrapNonce        [24]byte
	wrapSerpentIV    [16]byte
	wrappedSecret    [d1OuterSecretLength]byte
	wrappedInnerRoot [32]byte
	replicaTag       [64]byte
	wrapTag          [64]byte
	innerWrapTag     [64]byte
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
	copy(candidate.wrappedInnerRoot[:], raw[96:128])
	copy(candidate.replicaTag[:], raw[128:192])
	copy(candidate.wrapTag[:], raw[192:256])
	copy(candidate.innerWrapTag[:], raw[256:320])
	return candidate, nil
}

func (candidate d1BootstrapCandidate) prefix() [d1BootstrapPrefixLength]byte {
	var prefix [d1BootstrapPrefixLength]byte
	copy(prefix[0:16], candidate.argonSalt[:])
	copy(prefix[16:40], candidate.wrapNonce[:])
	copy(prefix[40:56], candidate.wrapSerpentIV[:])
	copy(prefix[56:96], candidate.wrappedSecret[:])
	copy(prefix[96:128], candidate.wrappedInnerRoot[:])
	return prefix
}

type d1BootstrapWrapKeys struct {
	xChaCha20      [32]byte
	serpent        [32]byte
	mac            [32]byte
	innerXChaCha20 [32]byte
	innerSerpent   [32]byte
	innerMAC       [32]byte
}

func (keys *d1BootstrapWrapKeys) close() {
	if keys == nil {
		return
	}
	pcv3crypto.SecureZero(keys.xChaCha20[:])
	pcv3crypto.SecureZero(keys.serpent[:])
	pcv3crypto.SecureZero(keys.mac[:])
	pcv3crypto.SecureZero(keys.innerXChaCha20[:])
	pcv3crypto.SecureZero(keys.innerSerpent[:])
	pcv3crypto.SecureZero(keys.innerMAC[:])
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
	return access.withProfileWrapKeys(ctx, pcv3credential.D1ProfileParanoid, callback)
}

func (access *d1BootstrapOwnerAccess) withProfileWrapKeys(ctx context.Context, profile pcv3credential.D1Profile, callback func(*d1BootstrapWrapKeys) error) error {
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
				{pcv3credential.D1InnerCredentialWrapXChaCha20, keys.innerXChaCha20[:]},
				{pcv3credential.D1InnerCredentialWrapSerpent, keys.innerSerpent[:]},
				{pcv3credential.D1InnerCredentialWrapMAC, keys.innerMAC[:]},
			} {
				if err := borrowed.CopyKeyForProfile(profile, request.label, request.destination); err != nil {
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
	secret               *d1OuterSecretOwner
	wrapVerified         bool
	replicaVerified      bool
	profileHinted        bool
	profileAuthenticated bool
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
	evaluation.profileHinted = false
	evaluation.profileAuthenticated = false
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
	bodyLength           uint64
	wrapVerified         bool
	replicaVerified      bool
	profileHinted        bool
	profileAuthenticated bool
	borrowOuterKeys      func(
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
	binding.profileHinted = false
	binding.profileAuthenticated = false
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
	return bindD1BootstrapWithHint(ctx, candidate, access, seams, 0, false, callback)
}

func bindD1BootstrapWithHint(ctx context.Context, candidate d1BootstrapCandidate, access d1BootstrapCredentialAccess, seams d1BootstrapAuthSeams, hint Suite, requireProfile bool, callback func(*d1BootstrapBinding) error) error {
	if callback == nil {
		return errInvalidD1Bootstrap
	}
	evaluation, _, err := evaluateD1BootstrapWithHint(
		ctx,
		candidate,
		access,
		seams,
		d1BootstrapAllowRawUnwrap,
		hint,
		requireProfile,
	)
	if err != nil {
		return err
	}
	defer evaluation.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if evaluation.secret == nil || evaluation.secret.keys == nil {
		return callback(nil)
	}
	keyOwner := evaluation.secret.keys
	binding := &d1BootstrapBinding{
		bodyLength:           evaluation.secret.bodyLength,
		profileHinted:        evaluation.profileHinted,
		profileAuthenticated: evaluation.profileAuthenticated,
		wrapVerified:         evaluation.wrapVerified,
		replicaVerified:      evaluation.replicaVerified,
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
	return evaluateD1BootstrapWithHint(ctx, candidate, access, seams, policy, 0, false)
}

func evaluateD1BootstrapWithHint(ctx context.Context, candidate d1BootstrapCandidate, access d1BootstrapCredentialAccess, seams d1BootstrapAuthSeams, policy d1BootstrapEvaluationPolicy, hint Suite, requireProfile bool) (*d1BootstrapEvaluation, Stage, error) {
	if ctx == nil || access == nil || seams.unwrapParanoid == nil ||
		!validD1BootstrapRole(candidate.role) || access.role() != candidate.role ||
		(policy != d1BootstrapVerifyBeforeUnwrap && policy != d1BootstrapAllowRawUnwrap) ||
		(hint != 0 && (!isSupportedSuite(hint) || policy != d1BootstrapAllowRawUnwrap || !requireProfile)) {
		return nil, StageCredentialPolicy, errInvalidD1Bootstrap
	}
	if ctx.Err() != nil {
		return nil, StageCancellation, ctx.Err()
	}

	profiles := []pcv3credential.D1Profile{pcv3credential.D1ProfileParanoid}
	profileAccess, bothProfiles := access.(interface {
		withProfileWrapKeys(context.Context, pcv3credential.D1Profile, func(*d1BootstrapWrapKeys) error) error
	})
	if bothProfiles {
		profiles = []pcv3credential.D1Profile{pcv3credential.D1ProfileStandard, pcv3credential.D1ProfileParanoid}
	}
	var selected *d1BootstrapEvaluation
	var hinted *d1BootstrapEvaluation
	var selectedProfile pcv3credential.D1Profile
	defer func() {
		if selected != nil {
			selected.Close()
		}
		if hinted != nil {
			hinted.Close()
		}
	}()
	for _, profile := range profiles {
		evaluation := &d1BootstrapEvaluation{}
		unwrapAttempted := false
		profileAuthenticated := false
		var unwrapped [d1OuterSecretLength]byte
		var innerRoot [32]byte
		withKeys := func(callback func(*d1BootstrapWrapKeys) error) error {
			if bothProfiles {
				return profileAccess.withProfileWrapKeys(ctx, profile, callback)
			}
			return access.withWrapKeys(ctx, callback)
		}
		err := func() error {
			defer pcv3crypto.SecureZero(unwrapped[:])
			defer pcv3crypto.SecureZero(innerRoot[:])
			err := withKeys(func(keys *d1BootstrapWrapKeys) error {
				outerMessage := d1BootstrapProfileWrapMessage(candidate, profile, false)
				innerMessage := d1BootstrapProfileWrapMessage(candidate, profile, true)
				defer pcv3crypto.SecureZero(outerMessage)
				defer pcv3crypto.SecureZero(innerMessage)
				outerValid, err := verifySuiteMAC(Suite(profile.Suite()), keys.mac[:], outerMessage, candidate.wrapTag[:])
				if err != nil {
					return err
				}
				innerValid, err := verifySuiteMAC(Suite(profile.Suite()), keys.innerMAC[:], innerMessage, candidate.innerWrapTag[:])
				if err != nil {
					return err
				}
				profileAuthenticated = outerValid || innerValid
				evaluation.profileAuthenticated = profileAuthenticated
				evaluation.wrapVerified = outerValid && innerValid
				if !evaluation.wrapVerified && policy == d1BootstrapVerifyBeforeUnwrap {
					return nil
				}
				unwrapAttempted = true
				if err := unwrapD1BootstrapBranch(profile, seams, unwrapped[:], candidate.wrappedSecret[:], keys.xChaCha20[:], candidate.wrapNonce[:], keys.serpent[:], candidate.wrapSerpentIV[:]); err != nil {
					return err
				}
				return unwrapD1BootstrapBranch(profile, seams, innerRoot[:], candidate.wrappedInnerRoot[:], keys.innerXChaCha20[:], candidate.wrapNonce[:], keys.innerSerpent[:], candidate.wrapSerpentIV[:])
			})
			if err != nil || !unwrapAttempted {
				return err
			}
			keyOwner, err := pcv3credential.NewD1RootsOwner(append([]byte(nil), unwrapped[:32]...), append([]byte(nil), innerRoot[:]...), profile)
			if err != nil {
				return err
			}
			evaluation.secret = &d1OuterSecretOwner{bodyLength: binary.BigEndian.Uint64(unwrapped[32:40]), keys: keyOwner}
			return evaluation.secret.withOuterKeys(ctx, func(keys *pcv3credential.BorrowedD1OuterKeys) error {
				var replicaKey [32]byte
				defer pcv3crypto.SecureZero(replicaKey[:])
				if err := keys.CopyKey(pcv3credential.D1OuterReplicaMAC, keyRoleForD1Bootstrap(candidate.role), replicaKey[:]); err != nil {
					return err
				}
				message := d1BootstrapProfileReplicaMessage(candidate, profile)
				defer pcv3crypto.SecureZero(message)
				valid, err := verifySuiteMAC(Suite(profile.Suite()), replicaKey[:], message, candidate.replicaTag[:])
				evaluation.replicaVerified = valid
				evaluation.profileAuthenticated = evaluation.profileAuthenticated || valid
				return err
			})
		}()
		if err != nil {
			evaluation.Close()
			stage := StageCredentialPolicy
			if ctx.Err() != nil {
				stage = StageCancellation
			} else if unwrapAttempted {
				stage = StageUnwrap
			}
			return nil, stage, err
		}
		// A valid wrap pair or replica MAC authenticates the hidden profile.
		// Raw Force can therefore recover two damaged wrap tags when the
		// independently derived replica tag still authenticates the roots.
		if evaluation.wrapVerified || evaluation.replicaVerified || (policy == d1BootstrapAllowRawUnwrap && (profileAuthenticated || !bothProfiles)) {
			if selected != nil {
				evaluation.Close()
				return nil, StageCredentialPolicy, errInvalidD1Bootstrap
			}
			selected = evaluation
			selectedProfile = profile
		} else if policy == d1BootstrapAllowRawUnwrap && hint != 0 && Suite(profile.Suite()) == hint {
			evaluation.profileHinted = true
			hinted = evaluation
		} else {
			evaluation.Close()
		}
	}
	if selected == nil {
		if hinted != nil {
			result := hinted
			hinted = nil
			return result, StageNone, nil
		}
		if requireProfile {
			return nil, StageCredentialPolicy, ErrD1ProfileRequired
		}
		return &d1BootstrapEvaluation{}, StageWrapAuth, nil
	}
	if hint != 0 && Suite(selectedProfile.Suite()) != hint {
		return nil, StageCredentialPolicy, errD1ProfileMismatch
	}
	result := selected
	selected = nil
	return result, StageNone, nil
}

func unwrapD1BootstrapBranch(profile pcv3credential.D1Profile, seams d1BootstrapAuthSeams, destination, source, xkey, nonce, serpent, iv []byte) error {
	if profile == pcv3credential.D1ProfileStandard {
		return pcv3stream.PCV3UnwrapStandard1(destination, source, xkey, nonce)
	}
	return seams.unwrapParanoid(destination, source, xkey, nonce, serpent, iv)
}

func d1BootstrapProfileReplicaMessage(candidate d1BootstrapCandidate, profile pcv3credential.D1Profile) []byte {
	prefix := candidate.prefix()
	message := binary.BigEndian.AppendUint16([]byte(d1OuterReplicaDomain), uint16(profile))
	message = append(message, byte(candidate.role))
	return append(message, prefix[:]...)
}

func d1BootstrapProfileWrapMessage(candidate d1BootstrapCandidate, profile pcv3credential.D1Profile, inner bool) []byte {
	domain := d1OuterWrapDomain
	if inner {
		domain = d1InnerWrapDomain
	}
	prefix := candidate.prefix()
	message := binary.BigEndian.AppendUint16([]byte(domain), uint16(profile))
	message = append(message, byte(candidate.role))
	message = append(message, prefix[:]...)
	return append(message, candidate.replicaTag[:]...)
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
	var leftSecret, rightSecret [74]byte
	defer pcv3crypto.SecureZero(leftSecret[:])
	defer pcv3crypto.SecureZero(rightSecret[:])
	copyOuterKey := func(access d1OuterKeyAccess, destination []byte) error {
		return access.withOuterKeys(
			ctx,
			func(keys *pcv3credential.BorrowedD1OuterKeys) error {
				if err := keys.CopyOuterKey(destination[:32]); err != nil {
					return err
				}
				if err := keys.CopyInnerRoot(destination[32:64]); err != nil {
					return err
				}
				binary.BigEndian.PutUint16(destination[64:66], uint16(keys.Profile()))
				return nil
			},
		)
	}
	if err := copyOuterKey(left, leftSecret[:]); err != nil {
		return false, err
	}
	if err := copyOuterKey(right, rightSecret[:]); err != nil {
		return false, err
	}
	binary.BigEndian.PutUint64(leftSecret[66:], leftLength)
	binary.BigEndian.PutUint64(rightSecret[66:], rightLength)
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
