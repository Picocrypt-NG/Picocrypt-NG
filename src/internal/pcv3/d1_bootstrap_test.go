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
	if err := (*d1BootstrapBinding)(nil).withOuterKeys(
		context.Background(),
		func(*pcv3credential.BorrowedD1OuterKeys) error { return nil },
	); err == nil {
		t.Fatal("nil Force bootstrap view accepted an outer-key borrow")
	}

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
			var retainedBorrowed *pcv3credential.BorrowedD1OuterKeys
			var retainedWithOuterKeys func(
				context.Context,
				func(*pcv3credential.BorrowedD1OuterKeys) error,
			) error
			callbackCalls := 0
			err = bindD1BootstrapWithAccess(
				context.Background(),
				candidate,
				access,
				seams,
				func(binding *d1BootstrapBinding) error {
					callbackCalls++
					retained = binding
					if binding == nil ||
						binding.wrapVerified != test.wantWrapVerified ||
						binding.replicaVerified != test.wantReplicaVerified ||
						binding.bodyLength != bodyLength {
						t.Fatalf(
							"Force binding = %#v; want complete secret and validity %t/%t",
							binding,
							test.wantWrapVerified,
							test.wantReplicaVerified,
						)
					}
					retainedWithOuterKeys = binding.withOuterKeys
					var gotOuterKey [32]byte
					if err := binding.withOuterKeys(
						context.Background(),
						func(keys *pcv3credential.BorrowedD1OuterKeys) error {
							retainedBorrowed = keys
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
				retainedBorrowed,
				retainedWithOuterKeys,
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
			if strict.authenticated != nil {
				var strictOuterKey [32]byte
				if err := strict.authenticated.secret.withOuterKeys(
					context.Background(),
					func(keys *pcv3credential.BorrowedD1OuterKeys) error {
						return keys.CopyOuterKey(strictOuterKey[:])
					},
				); err != nil || !bytes.Equal(strictOuterKey[:], outerKey) {
					t.Fatal("strict success did not take ownership of the evaluated OuterSecret")
				}
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
		{
			name: "cancellation after nil callback result",
			exit: func(cancel context.CancelFunc) error {
				cancel()
				return nil
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
			var retainedBorrowed *pcv3credential.BorrowedD1OuterKeys
			var retainedWithOuterKeys func(
				context.Context,
				func(*pcv3credential.BorrowedD1OuterKeys) error,
			) error
			err = bindD1BootstrapWithAccess(
				ctx,
				candidate,
				access,
				seams,
				func(binding *d1BootstrapBinding) error {
					retained = binding
					retainedWithOuterKeys = binding.withOuterKeys
					if borrowErr := binding.withOuterKeys(
						context.Background(),
						func(keys *pcv3credential.BorrowedD1OuterKeys) error {
							retainedBorrowed = keys
							return nil
						},
					); borrowErr != nil {
						return borrowErr
					}
					return test.exit(cancel)
				},
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("binder exit error = %v; want %v", err, test.wantErr)
			}
			assertD1ForceBootstrapBindingClosed(
				t,
				retained,
				retainedBorrowed,
				retainedWithOuterKeys,
				unwrapAlias,
			)
		})
	}
}

func TestD1ForceBootstrapBinderClosesPanicExit(t *testing.T) {
	raw, access := newD1BootstrapTestFixture(
		t,
		D1BootstrapFront,
		0x4a,
		bytes.Repeat([]byte{0x9f}, 32),
		12_288,
	)
	candidate, err := parseD1Bootstrap(raw, D1BootstrapFront)
	if err != nil {
		t.Fatalf("parse panic lifecycle bootstrap fixture: %v", err)
	}
	seams := defaultD1BootstrapAuthSeams()
	realUnwrap := seams.unwrapParanoid
	var unwrapAlias []byte
	seams.unwrapParanoid = func(destination, source, xKey, nonce, serpentKey, iv []byte) error {
		unwrapAlias = destination
		return realUnwrap(destination, source, xKey, nonce, serpentKey, iv)
	}
	panicValue := &struct{ label string }{label: "TEST ONLY D1 Force binder panic"}
	var recovered any
	var retained *d1BootstrapBinding
	var retainedBorrowed *pcv3credential.BorrowedD1OuterKeys
	var retainedWithOuterKeys func(
		context.Context,
		func(*pcv3credential.BorrowedD1OuterKeys) error,
	) error
	func() {
		defer func() {
			recovered = recover()
		}()
		_ = bindD1BootstrapWithAccess(
			context.Background(),
			candidate,
			access,
			seams,
			func(binding *d1BootstrapBinding) error {
				retained = binding
				retainedWithOuterKeys = binding.withOuterKeys
				if borrowErr := binding.withOuterKeys(
					context.Background(),
					func(keys *pcv3credential.BorrowedD1OuterKeys) error {
						retainedBorrowed = keys
						return nil
					},
				); borrowErr != nil {
					t.Fatalf("borrow before panic: %v", borrowErr)
				}
				panic(panicValue)
			},
		)
	}()
	if recovered != panicValue {
		t.Fatalf("binder panic = %v; want exact callback panic", recovered)
	}
	assertD1ForceBootstrapBindingClosed(
		t,
		retained,
		retainedBorrowed,
		retainedWithOuterKeys,
		unwrapAlias,
	)
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
	borrowed *pcv3credential.BorrowedD1OuterKeys,
	withOuterKeys func(
		context.Context,
		func(*pcv3credential.BorrowedD1OuterKeys) error,
	) error,
	unwrapAlias []byte,
) {
	t.Helper()
	if binding == nil || borrowed == nil || withOuterKeys == nil {
		t.Fatal("Force bootstrap callback did not expose its borrowed view")
	}
	if binding.bodyLength != 0 || binding.wrapVerified || binding.replicaVerified {
		t.Fatalf("expired Force bootstrap binding retained state: %#v", binding)
	}
	var copied [32]byte
	if err := borrowed.CopyOuterKey(copied[:]); !ownerErrorHasCode(err, pcv3credential.OwnerErrorBorrowExpired) {
		t.Fatalf("retained Force bootstrap borrow error = %T %v", err, err)
	}
	callbackCalls := 0
	if err := withOuterKeys(
		context.Background(),
		func(*pcv3credential.BorrowedD1OuterKeys) error {
			callbackCalls++
			return nil
		},
	); err == nil || callbackCalls != 0 {
		t.Fatalf(
			"retained Force bootstrap method = error %v callbacks %d; want expired without callback",
			err,
			callbackCalls,
		)
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
