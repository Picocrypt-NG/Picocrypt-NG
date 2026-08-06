package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"testing"
)

func TestD1BootstrapRejectsDecryptBeforeWrapTag(t *testing.T) {
	outerKey := bytes.Repeat([]byte{0x61}, 32)
	raw, access := newD1BootstrapTestFixture(
		t,
		D1BootstrapFront,
		0x10,
		outerKey,
		4096,
	)
	raw[d1BootstrapWrapTagOffset] ^= 0x80
	candidate, err := parseD1Bootstrap(raw, D1BootstrapFront)
	if err != nil {
		t.Fatalf("parse wrap-tag fixture: %v", err)
	}
	decryptCalls := 0
	seams := defaultD1BootstrapAuthSeams()
	seams.unwrapParanoid = func(_, _, _, _, _, _ []byte) error {
		decryptCalls++
		return nil
	}
	wrapFailure := authenticateD1BootstrapWithAccess(
		context.Background(),
		candidate,
		access,
		seams,
	)
	defer wrapFailure.Close()
	if wrapFailure.Outcome() != OutcomeCredentialsOrDamage ||
		wrapFailure.Stage() != StageWrapAuth ||
		wrapFailure.authenticated != nil {
		t.Fatalf("wrap failure = outcome %d stage %d authenticated=%v", wrapFailure.Outcome(), wrapFailure.Stage(), wrapFailure.authenticated != nil)
	}
	if decryptCalls != 0 {
		t.Fatalf("failed wrap tag invoked decrypt %d times", decryptCalls)
	}

	replicaRaw, replicaAccess := newD1BootstrapTestFixture(
		t,
		D1BootstrapFront,
		0x20,
		outerKey,
		4096,
	)
	replicaRaw[d1BootstrapReplicaTagOffset] ^= 0x01
	recomputeD1BootstrapWrapTag(t, replicaRaw, D1BootstrapFront, replicaAccess.keys.mac[:])
	replicaCandidate, err := parseD1Bootstrap(replicaRaw, D1BootstrapFront)
	if err != nil {
		t.Fatalf("parse replica-tag fixture: %v", err)
	}
	var decryptedAlias []byte
	seams = defaultD1BootstrapAuthSeams()
	productionUnwrap := seams.unwrapParanoid
	seams.unwrapParanoid = func(destination, source, xKey, nonce, serpentKey, iv []byte) error {
		decryptCalls++
		decryptedAlias = destination
		return productionUnwrap(destination, source, xKey, nonce, serpentKey, iv)
	}
	replicaFailure := authenticateD1BootstrapWithAccess(
		context.Background(),
		replicaCandidate,
		replicaAccess,
		seams,
	)
	defer replicaFailure.Close()
	if replicaFailure.Outcome() != OutcomeCredentialsOrDamage ||
		replicaFailure.Stage() != StageReplicaAuth ||
		replicaFailure.authenticated != nil {
		t.Fatalf("replica failure = outcome %d stage %d authenticated=%v", replicaFailure.Outcome(), replicaFailure.Stage(), replicaFailure.authenticated != nil)
	}
	if decryptCalls != 1 {
		t.Fatalf("authenticated wrap invoked decrypt count %d, want 1", decryptCalls)
	}
	if len(decryptedAlias) != d1OuterSecretLength || !allZero(decryptedAlias) {
		t.Fatal("failed replica authentication retained decrypted OuterSecret scratch")
	}
	const wantOrdinaryFailure = "pcv3: credentials incorrect or volume damaged"
	if wrapFailure.Error() != wantOrdinaryFailure || replicaFailure.Error() != wantOrdinaryFailure {
		t.Fatalf("ordinary bootstrap failures were distinguishable: %q versus %q", wrapFailure.Error(), replicaFailure.Error())
	}
}

func TestD1ForceBootstrapBinderRetainsCompleteSecretAndExactValidity(t *testing.T) {
	const bodyLength = uint64(4096)
	outerKey := bytes.Repeat([]byte{0x6d}, 32)
	tests := []struct {
		name                string
		mutate              func(*testing.T, []byte, *d1TestBootstrapCredentialAccess)
		wantWrapVerified    bool
		wantReplicaVerified bool
		wantStrictOutcome   Outcome
		wantStrictStage     Stage
	}{
		{
			name:                "valid",
			mutate:              func(*testing.T, []byte, *d1TestBootstrapCredentialAccess) {},
			wantWrapVerified:    true,
			wantReplicaVerified: true,
			wantStrictOutcome:   OutcomeSuccess,
			wantStrictStage:     StageNone,
		},
		{
			name: "wrap damage",
			mutate: func(_ *testing.T, raw []byte, _ *d1TestBootstrapCredentialAccess) {
				raw[d1BootstrapWrapTagOffset] ^= 0x01
			},
			wantWrapVerified:    false,
			wantReplicaVerified: true,
			wantStrictOutcome:   OutcomeCredentialsOrDamage,
			wantStrictStage:     StageWrapAuth,
		},
		{
			name: "replica damage",
			mutate: func(t *testing.T, raw []byte, access *d1TestBootstrapCredentialAccess) {
				raw[d1BootstrapReplicaTagOffset] ^= 0x01
				recomputeD1BootstrapWrapTag(t, raw, D1BootstrapFront, access.keys.mac[:])
			},
			wantWrapVerified:    true,
			wantReplicaVerified: false,
			wantStrictOutcome:   OutcomeCredentialsOrDamage,
			wantStrictStage:     StageReplicaAuth,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, access := newD1BootstrapTestFixture(
				t,
				D1BootstrapFront,
				0x28,
				outerKey,
				bodyLength,
			)
			test.mutate(t, raw, access)
			candidate, err := parseD1Bootstrap(raw, D1BootstrapFront)
			if err != nil {
				t.Fatalf("parse Force bootstrap fixture: %v", err)
			}

			seams := defaultD1BootstrapAuthSeams()
			realUnwrap := seams.unwrapParanoid
			var unwrapAlias []byte
			seams.unwrapParanoid = func(destination, source, xKey, nonce, serpentKey, iv []byte) error {
				unwrapAlias = destination
				return realUnwrap(destination, source, xKey, nonce, serpentKey, iv)
			}
			var retained *d1BootstrapBinding
			var retainedSecret *d1OuterSecretOwner
			var retainedKeys *pcv3credential.D1OuterKeyOwner
			callbackCalls := 0
			err = bindD1BootstrapWithAccess(
				context.Background(),
				candidate,
				access,
				seams,
				func(binding *d1BootstrapBinding) error {
					callbackCalls++
					retained = binding
					if binding == nil || binding.secret == nil || binding.secret.keys == nil ||
						binding.wrapVerified != test.wantWrapVerified ||
						binding.replicaVerified != test.wantReplicaVerified ||
						binding.secret.bodyLength != bodyLength {
						t.Fatalf(
							"Force binding = %#v; want complete secret and validity %t/%t",
							binding,
							test.wantWrapVerified,
							test.wantReplicaVerified,
						)
					}
					retainedSecret = binding.secret
					retainedKeys = binding.secret.keys
					var gotOuterKey [32]byte
					if err := binding.secret.withOuterKeys(
						context.Background(),
						func(keys *pcv3credential.BorrowedD1OuterKeys) error {
							return keys.CopyOuterKey(gotOuterKey[:])
						},
					); err != nil || !bytes.Equal(gotOuterKey[:], outerKey) {
						t.Fatal("Force binding did not expose the complete OuterSecret")
					}
					return nil
				},
			)
			if err != nil || callbackCalls != 1 {
				t.Fatalf("bind Force bootstrap = error %v, callbacks %d; want nil/1", err, callbackCalls)
			}
			assertD1ForceBootstrapBindingClosed(
				t,
				retained,
				retainedSecret,
				retainedKeys,
				unwrapAlias,
			)

			strict := authenticateD1BootstrapWithAccess(
				context.Background(),
				candidate,
				access,
				defaultD1BootstrapAuthSeams(),
			)
			defer strict.Close()
			if strict.Outcome() != test.wantStrictOutcome || strict.Stage() != test.wantStrictStage ||
				(strict.authenticated != nil) != (test.wantStrictOutcome == OutcomeSuccess) {
				t.Fatalf(
					"strict bootstrap = %v/%v authenticated=%t; want %v/%v authenticated=%t",
					strict.Outcome(),
					strict.Stage(),
					strict.authenticated != nil,
					test.wantStrictOutcome,
					test.wantStrictStage,
					test.wantStrictOutcome == OutcomeSuccess,
				)
			}
		})
	}
}

func TestD1ForceBootstrapBinderClosesEveryCallbackExit(t *testing.T) {
	callbackErr := errors.New("TEST ONLY D1 Force binder callback failure")
	tests := []struct {
		name    string
		exit    func(context.CancelFunc) error
		wantErr error
	}{
		{name: "success", exit: func(context.CancelFunc) error { return nil }},
		{name: "callback error", exit: func(context.CancelFunc) error { return callbackErr }, wantErr: callbackErr},
		{
			name: "cancellation",
			exit: func(cancel context.CancelFunc) error {
				cancel()
				return context.Canceled
			},
			wantErr: context.Canceled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, access := newD1BootstrapTestFixture(
				t,
				D1BootstrapTail,
				0x39,
				bytes.Repeat([]byte{0x8e}, 32),
				8192,
			)
			candidate, err := parseD1Bootstrap(raw, D1BootstrapTail)
			if err != nil {
				t.Fatalf("parse lifecycle bootstrap fixture: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			seams := defaultD1BootstrapAuthSeams()
			realUnwrap := seams.unwrapParanoid
			var unwrapAlias []byte
			seams.unwrapParanoid = func(destination, source, xKey, nonce, serpentKey, iv []byte) error {
				unwrapAlias = destination
				return realUnwrap(destination, source, xKey, nonce, serpentKey, iv)
			}
			var retained *d1BootstrapBinding
			var retainedSecret *d1OuterSecretOwner
			var retainedKeys *pcv3credential.D1OuterKeyOwner
			err = bindD1BootstrapWithAccess(
				ctx,
				candidate,
				access,
				seams,
				func(binding *d1BootstrapBinding) error {
					retained = binding
					retainedSecret = binding.secret
					retainedKeys = binding.secret.keys
					return test.exit(cancel)
				},
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("binder exit error = %v; want %v", err, test.wantErr)
			}
			assertD1ForceBootstrapBindingClosed(
				t,
				retained,
				retainedSecret,
				retainedKeys,
				unwrapAlias,
			)
		})
	}
}

func TestD1BootstrapBindsPhysicalRole(t *testing.T) {
	outerKey := bytes.Repeat([]byte{0x72}, 32)
	raw, frontAccess := newD1BootstrapTestFixture(
		t,
		D1BootstrapFront,
		0x31,
		outerKey,
		2048,
	)
	front, err := parseD1Bootstrap(raw, D1BootstrapFront)
	if err != nil {
		t.Fatalf("parse front bootstrap: %v", err)
	}
	tailAccess := *frontAccess
	tailAccess.bootstrapRole = D1BootstrapTail
	decryptCalls := 0
	seams := defaultD1BootstrapAuthSeams()
	seams.unwrapParanoid = func(_, _, _, _, _, _ []byte) error {
		decryptCalls++
		return nil
	}
	wrongOwner := authenticateD1BootstrapWithAccess(
		context.Background(),
		front,
		&tailAccess,
		seams,
	)
	defer wrongOwner.Close()
	if wrongOwner.Outcome() != OutcomeOperationFailed ||
		wrongOwner.Stage() != StageCredentialPolicy || decryptCalls != 0 {
		t.Fatalf("wrong physical owner = outcome %d stage %d decrypts %d", wrongOwner.Outcome(), wrongOwner.Stage(), decryptCalls)
	}

	copiedToTail, err := parseD1Bootstrap(raw, D1BootstrapTail)
	if err != nil {
		t.Fatalf("parse copied tail bootstrap: %v", err)
	}
	copied := authenticateD1BootstrapWithAccess(
		context.Background(),
		copiedToTail,
		&tailAccess,
		seams,
	)
	defer copied.Close()
	if copied.Outcome() != OutcomeCredentialsOrDamage ||
		copied.Stage() != StageWrapAuth || decryptCalls != 0 {
		t.Fatalf("role-copied bootstrap = outcome %d stage %d decrypts %d", copied.Outcome(), copied.Stage(), decryptCalls)
	}
}

func TestD1BootstrapReconcilesEqualReplicasAndEitherRecovery(t *testing.T) {
	const bodyLength = uint64(8192)
	outerKey := bytes.Repeat([]byte{0x83}, 32)
	frontRaw, frontAccess := newD1BootstrapTestFixture(
		t,
		D1BootstrapFront,
		0x41,
		outerKey,
		bodyLength,
	)
	tailRaw, tailAccess := newD1BootstrapTestFixture(
		t,
		D1BootstrapTail,
		0x91,
		outerKey,
		bodyLength,
	)
	front := authenticateD1BootstrapTestFixture(t, frontRaw, D1BootstrapFront, frontAccess)
	tail := authenticateD1BootstrapTestFixture(t, tailRaw, D1BootstrapTail, tailAccess)
	tailOwner := tail.authenticated.secret.keys
	canonicalSize := bodyLength + 2*d1BootstrapLength
	result := reconcileD1BootstrapAttempts(canonicalSize, front, tail)
	if result.Outcome() != OutcomeSuccess || result.Stage() != StageNone ||
		result.AuthenticatedBootstraps() != 2 || result.BodyLength() != bodyLength {
		result.Close()
		t.Fatalf("equal bootstrap result = outcome %d stage %d authenticated %d body %d", result.Outcome(), result.Stage(), result.AuthenticatedBootstraps(), result.BodyLength())
	}
	if err := tailOwner.WithKeys(context.Background(), func(*pcv3credential.BorrowedD1OuterKeys) error {
		return nil
	}); !ownerErrorHasCode(err, pcv3credential.OwnerErrorClosed) {
		result.Close()
		t.Fatalf("discarded equal tail owner error = %T %v", err, err)
	}
	var expired *pcv3credential.BorrowedD1OuterKeys
	err := result.withOuterKeys(context.Background(), func(keys *pcv3credential.BorrowedD1OuterKeys) error {
		expired = keys
		key := make([]byte, 32)
		return keys.CopyKey(
			pcv3credential.D1OuterPayloadMAC,
			pcv3credential.KeyRoleNotReplica,
			key,
		)
	})
	if err != nil {
		result.Close()
		t.Fatalf("borrow reconciled outer keys: %v", err)
	}
	if err := expired.CopyKey(
		pcv3credential.D1OuterPayloadMAC,
		pcv3credential.KeyRoleNotReplica,
		make([]byte, 32),
	); err == nil {
		result.Close()
		t.Fatal("expired reconciled outer-key borrow remained usable")
	}
	result.Close()
	if err := result.withOuterKeys(context.Background(), func(*pcv3credential.BorrowedD1OuterKeys) error {
		return nil
	}); err == nil {
		t.Fatal("closed reconciled OuterSecret remained usable")
	}

	for _, test := range []struct {
		name   string
		role   D1BootstrapRole
		raw    []byte
		access *d1TestBootstrapCredentialAccess
	}{
		{name: "front only", role: D1BootstrapFront, raw: frontRaw, access: frontAccess},
		{name: "tail only", role: D1BootstrapTail, raw: tailRaw, access: tailAccess},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempt := authenticateD1BootstrapTestFixture(t, test.raw, test.role, test.access)
			var frontAttempt, tailAttempt *d1BootstrapAttempt
			if test.role == D1BootstrapFront {
				frontAttempt = attempt
			} else {
				tailAttempt = attempt
			}
			degraded := reconcileD1BootstrapAttempts(
				bodyLength+d1BootstrapLength,
				frontAttempt,
				tailAttempt,
			)
			defer degraded.Close()
			if degraded.Outcome() != OutcomeAuthenticatedDegraded ||
				degraded.Stage() != StageD1Bootstrap ||
				degraded.AuthenticatedBootstraps() != 1 ||
				degraded.BodyLength() != bodyLength {
				t.Fatalf("single %d result = outcome %d stage %d authenticated %d body %d", test.role, degraded.Outcome(), degraded.Stage(), degraded.AuthenticatedBootstraps(), degraded.BodyLength())
			}
		})
	}
}

func TestD1BootstrapConflictIsAmbiguity(t *testing.T) {
	const bodyLength = uint64(16384)
	frontRaw, frontAccess := newD1BootstrapTestFixture(
		t,
		D1BootstrapFront,
		0x51,
		bytes.Repeat([]byte{0xa1}, 32),
		bodyLength,
	)
	tailRaw, tailAccess := newD1BootstrapTestFixture(
		t,
		D1BootstrapTail,
		0xb1,
		bytes.Repeat([]byte{0xb2}, 32),
		bodyLength,
	)
	front := authenticateD1BootstrapTestFixture(t, frontRaw, D1BootstrapFront, frontAccess)
	tail := authenticateD1BootstrapTestFixture(t, tailRaw, D1BootstrapTail, tailAccess)
	frontOwner := front.authenticated.secret.keys
	tailOwner := tail.authenticated.secret.keys
	result := reconcileD1BootstrapAttempts(
		bodyLength+2*d1BootstrapLength,
		front,
		tail,
	)
	defer result.Close()
	if result.Outcome() != OutcomeAmbiguousVolume ||
		result.Stage() != StageD1Bootstrap ||
		result.AuthenticatedBootstraps() != 2 || result.secret != nil {
		t.Fatalf("conflicting bootstrap result = outcome %d stage %d authenticated %d secret=%v", result.Outcome(), result.Stage(), result.AuthenticatedBootstraps(), result.secret != nil)
	}
	for index, owner := range []*pcv3credential.D1OuterKeyOwner{frontOwner, tailOwner} {
		err := owner.WithKeys(context.Background(), func(*pcv3credential.BorrowedD1OuterKeys) error {
			return nil
		})
		if !ownerErrorHasCode(err, pcv3credential.OwnerErrorClosed) {
			t.Fatalf("conflicting owner %d error = %T %v", index, err, err)
		}
	}

	t.Run("repeated physical parameters", func(t *testing.T) {
		outerKey := bytes.Repeat([]byte{0xc4}, 32)
		frontRaw, frontAccess := newD1BootstrapTestFixture(
			t,
			D1BootstrapFront,
			0x37,
			outerKey,
			bodyLength,
		)
		tailRaw, tailAccess := newD1BootstrapTestFixture(
			t,
			D1BootstrapTail,
			0x37,
			outerKey,
			bodyLength,
		)
		front := authenticateD1BootstrapTestFixture(t, frontRaw, D1BootstrapFront, frontAccess)
		tail := authenticateD1BootstrapTestFixture(t, tailRaw, D1BootstrapTail, tailAccess)
		result := reconcileD1BootstrapAttempts(
			bodyLength+2*d1BootstrapLength,
			front,
			tail,
		)
		defer result.Close()
		if result.Outcome() != OutcomeAmbiguousVolume || result.secret != nil {
			t.Fatalf("repeated physical parameters = outcome %d secret=%v", result.Outcome(), result.secret != nil)
		}
	})
}

func TestD1BootstrapGeometryRejectsOverflow(t *testing.T) {
	raw, access := newD1BootstrapTestFixture(
		t,
		D1BootstrapFront,
		0x61,
		bytes.Repeat([]byte{0xc3}, 32),
		math.MaxUint64,
	)
	attempt := authenticateD1BootstrapTestFixture(t, raw, D1BootstrapFront, access)
	owner := attempt.authenticated.secret.keys
	result := reconcileD1BootstrapAttempts(math.MaxUint64, attempt, nil)
	defer result.Close()
	if result.Outcome() != OutcomeCredentialsOrDamage || result.secret != nil {
		t.Fatalf("overflow geometry result = outcome %d secret=%v", result.Outcome(), result.secret != nil)
	}
	if err := owner.WithKeys(context.Background(), func(*pcv3credential.BorrowedD1OuterKeys) error {
		return nil
	}); !ownerErrorHasCode(err, pcv3credential.OwnerErrorClosed) {
		t.Fatalf("overflow geometry owner error = %T %v", err, err)
	}
}

type d1TestBootstrapCredentialAccess struct {
	bootstrapRole D1BootstrapRole
	keys          d1BootstrapWrapKeys
}

func (access *d1TestBootstrapCredentialAccess) role() D1BootstrapRole {
	if access == nil {
		return D1BootstrapRole(0xff)
	}
	return access.bootstrapRole
}

func (access *d1TestBootstrapCredentialAccess) withWrapKeys(
	ctx context.Context,
	callback func(*d1BootstrapWrapKeys) error,
) error {
	if access == nil || ctx == nil || callback == nil || ctx.Err() != nil {
		return errors.New("TEST ONLY invalid D1 credential access")
	}
	keys := access.keys
	defer keys.close()
	return callback(&keys)
}

func newD1BootstrapTestFixture(
	t *testing.T,
	role D1BootstrapRole,
	seed byte,
	outerKey []byte,
	bodyLength uint64,
) ([]byte, *d1TestBootstrapCredentialAccess) {
	t.Helper()
	if len(outerKey) != 32 {
		t.Fatal("TEST ONLY OuterKey must be 32 bytes")
	}
	raw := make([]byte, d1BootstrapLength)
	fillD1TestBytes(raw[0:16], seed)
	fillD1TestBytes(raw[16:40], seed+0x20)
	fillD1TestBytes(raw[40:56], seed+0x40)
	access := &d1TestBootstrapCredentialAccess{bootstrapRole: role}
	fillD1TestBytes(access.keys.xChaCha20[:], seed+0x60)
	fillD1TestBytes(access.keys.serpent[:], seed+0x80)
	fillD1TestBytes(access.keys.mac[:], seed+0xa0)

	var plaintext [d1OuterSecretLength]byte
	defer pcv3crypto.SecureZero(plaintext[:])
	copy(plaintext[0:32], outerKey)
	binary.BigEndian.PutUint64(plaintext[32:40], bodyLength)
	if err := pcv3crypto.PCV3WrapParanoid1(
		raw[56:96],
		plaintext[:],
		access.keys.xChaCha20[:],
		raw[16:40],
		access.keys.serpent[:],
		raw[40:56],
	); err != nil {
		t.Fatalf("wrap TEST ONLY OuterSecret: %v", err)
	}

	replicaKey := independentD1OuterReplicaKey(t, outerKey, role)
	defer pcv3crypto.SecureZero(replicaKey[:])
	replicaTag := independentD1HMAC(
		replicaKey[:],
		[]byte("Picocrypt-NG/PCV3/outer/replica\x00"),
		[]byte{byte(role)},
		raw[:d1BootstrapPrefixLength],
	)
	copy(raw[d1BootstrapReplicaTagOffset:d1BootstrapWrapTagOffset], replicaTag[:])
	pcv3crypto.SecureZero(replicaTag[:])
	recomputeD1BootstrapWrapTag(t, raw, role, access.keys.mac[:])
	return raw, access
}

func recomputeD1BootstrapWrapTag(
	t *testing.T,
	raw []byte,
	role D1BootstrapRole,
	wrapMAC []byte,
) {
	t.Helper()
	if len(raw) != d1BootstrapLength {
		t.Fatal("TEST ONLY bootstrap has wrong length")
	}
	tag := independentD1HMAC(
		wrapMAC,
		[]byte("Picocrypt-NG/PCV3/outer/wrap\x00"),
		[]byte{byte(role)},
		raw[:d1BootstrapPrefixLength],
		raw[d1BootstrapReplicaTagOffset:d1BootstrapWrapTagOffset],
	)
	copy(raw[d1BootstrapWrapTagOffset:], tag[:])
	pcv3crypto.SecureZero(tag[:])
}

func independentD1OuterReplicaKey(
	t *testing.T,
	outerKey []byte,
	role D1BootstrapRole,
) [32]byte {
	t.Helper()
	rootSalt := sha3.Sum256([]byte("Picocrypt-NG/PCV3/outer/root\x00"))
	prk, err := hkdf.Extract(sha3.New256, outerKey, rootSalt[:])
	if err != nil {
		t.Fatalf("extract TEST ONLY OuterPRK: %v", err)
	}
	defer pcv3crypto.SecureZero(prk)
	info := independentD1ScheduleInfo("outer/replica/mac", role)
	key, err := hkdf.Expand(sha3.New256, prk, info, 32)
	if err != nil {
		t.Fatalf("expand TEST ONLY replica key: %v", err)
	}
	defer pcv3crypto.SecureZero(key)
	var result [32]byte
	copy(result[:], key)
	return result
}

func independentD1ScheduleInfo(label string, role D1BootstrapRole) string {
	const domain = "Picocrypt-NG/PCV3/HKDF\x00"
	info := make([]byte, 0, len(domain)+9+len(label))
	info = append(info, domain...)
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], 0x0003)
	info = append(info, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], 0x0001)
	info = append(info, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], uint16(SuiteParanoid))
	info = append(info, encoded[:]...)
	info = append(info, byte(role))
	binary.BigEndian.PutUint16(encoded[:], uint16(len(label)))
	info = append(info, encoded[:]...)
	info = append(info, label...)
	return string(info)
}

func independentD1HMAC(key []byte, parts ...[]byte) [64]byte {
	mac := hmac.New(func() hash.Hash { return sha3.New512() }, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	var tag [64]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func fillD1TestBytes(destination []byte, seed byte) {
	for index := range destination {
		destination[index] = seed + byte(index)
	}
}

func authenticateD1BootstrapTestFixture(
	t *testing.T,
	raw []byte,
	role D1BootstrapRole,
	access *d1TestBootstrapCredentialAccess,
) *d1BootstrapAttempt {
	t.Helper()
	candidate, err := parseD1Bootstrap(raw, role)
	if err != nil {
		t.Fatalf("parse TEST ONLY bootstrap: %v", err)
	}
	attempt := authenticateD1BootstrapWithAccess(
		context.Background(),
		candidate,
		access,
		defaultD1BootstrapAuthSeams(),
	)
	if attempt.Outcome() != OutcomeSuccess || attempt.authenticated == nil {
		attempt.Close()
		t.Fatalf("authenticate TEST ONLY bootstrap: outcome %d stage %d", attempt.Outcome(), attempt.Stage())
	}
	return attempt
}

func assertD1ForceBootstrapBindingClosed(
	t *testing.T,
	binding *d1BootstrapBinding,
	secret *d1OuterSecretOwner,
	keys *pcv3credential.D1OuterKeyOwner,
	unwrapAlias []byte,
) {
	t.Helper()
	if binding == nil || secret == nil || keys == nil {
		t.Fatal("Force bootstrap callback did not expose its owned binding")
	}
	if binding.secret != nil || binding.wrapVerified || binding.replicaVerified {
		t.Fatalf("expired Force bootstrap binding retained state: %#v", binding)
	}
	if secret.bodyLength != 0 || secret.keys != nil {
		t.Fatalf("expired Force bootstrap secret retained state: %#v", secret)
	}
	if err := keys.WithKeys(
		context.Background(),
		func(*pcv3credential.BorrowedD1OuterKeys) error { return nil },
	); !ownerErrorHasCode(err, pcv3credential.OwnerErrorClosed) {
		t.Fatalf("expired Force bootstrap key owner error = %T %v", err, err)
	}
	if len(unwrapAlias) != d1OuterSecretLength || !allZero(unwrapAlias) {
		t.Fatal("Force bootstrap binder retained unwrapped OuterSecret scratch")
	}
}

func ownerErrorHasCode(err error, code pcv3credential.OwnerErrorCode) bool {
	var ownerErr *pcv3credential.OwnerError
	return errors.As(err, &ownerErr) && ownerErr.Code == code
}

func TestD1BootstrapFormattingIsRedacted(t *testing.T) {
	raw, _ := newD1BootstrapTestFixture(
		t,
		D1BootstrapFront,
		0x71,
		bytes.Repeat([]byte{0xd4}, 32),
		1024,
	)
	candidate, err := parseD1Bootstrap(raw, D1BootstrapFront)
	if err != nil {
		t.Fatalf("parse formatting fixture: %v", err)
	}
	formatted := fmt.Sprintf("%v|%+v|%#v", candidate, candidate, candidate)
	const want = "pcv3: unauthenticated outer bootstrap|pcv3: unauthenticated outer bootstrap|pcv3: unauthenticated outer bootstrap"
	if formatted != want {
		t.Fatalf("bootstrap formatting was not fixed and redacted: %q", formatted)
	}
}
