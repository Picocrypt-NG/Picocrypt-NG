package pcv3credential

import (
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestD1TranscriptConsumesFactorsOnceAndSeparatesDomains(t *testing.T) {
	tests := []struct {
		name        string
		mode        CredentialMode
		keyfileMode KeyfileMode
		policy      FactorPolicy
		password    []byte
		keyfiles    [][]byte
	}{
		{
			name: "password only", mode: CredentialModePasswordOnly,
			keyfileMode: KeyfileModeNone, policy: FactorPolicyPasswordOnly,
			password: []byte("D1 Cafe\u0301"),
		},
		{
			name: "keyfiles only ordered", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyKeyfilesOnly,
			keyfiles: [][]byte{[]byte("TEST ONLY D1 keyfile alpha")},
		},
		{
			name: "keyfiles only unordered", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeUnordered, policy: FactorPolicyKeyfilesOnly,
			keyfiles: [][]byte{
				[]byte("TEST ONLY D1 keyfile alpha"),
				[]byte("TEST ONLY D1 keyfile beta"),
			},
		},
		{
			name: "combined ordered", mode: CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyPasswordAndKeyfiles,
			password: []byte("D1 Cafe\u0301"),
			keyfiles: [][]byte{[]byte("TEST ONLY D1 keyfile alpha")},
		},
		{
			name: "combined unordered", mode: CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeUnordered, policy: FactorPolicyPasswordAndKeyfiles,
			password: []byte("D1 Cafe\u0301"),
			keyfiles: [][]byte{
				[]byte("TEST ONLY D1 keyfile beta"),
				[]byte("TEST ONLY D1 keyfile alpha"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, passwordAlias, readers := newRealTranscriptRequest(
				test.mode,
				test.keyfileMode,
				test.policy,
				test.password,
				test.keyfiles...,
			)
			var normal *CredentialInputNormal
			var outer *CredentialInputOuter
			var wantNormal, wantOuter [64]byte
			err := WithValidatedFactors(context.Background(), request, func(factors *ValidatedFactors) error {
				transcript, err := NewCanonicalTranscript(factors)
				if err != nil {
					return err
				}
				serialized := append([]byte(nil), transcript.secret.Bytes()...)
				defer func() {
					for index := range serialized {
						serialized[index] = 0
					}
				}()
				wantNormal = d1TestInputDigest("Picocrypt-NG/PCV3/credential/normal\x00", serialized)
				wantOuter = d1TestInputDigest("Picocrypt-NG/PCV3/credential/outer\x00", serialized)
				normal, outer, err = NewD1CredentialInputs(transcript)
				return err
			})
			if err != nil {
				t.Fatalf("build D1 credential inputs: %v", err)
			}
			requireRealInputsReleased(t, request, passwordAlias, readers)
			for index, reader := range readers {
				if reader.bytesRead != len(test.keyfiles[index]) {
					t.Fatalf("keyfile %d bytes read = %d, want %d", index, reader.bytesRead, len(test.keyfiles[index]))
				}
			}
			if normal == nil || normal.secret == nil || outer == nil || outer.secret == nil {
				t.Fatal("D1 transcript fan-out did not publish both typed owners")
			}
			defer normal.Close()
			defer outer.Close()
			normalAlias := normal.secret.Bytes()
			outerAlias := outer.secret.Bytes()
			if !bytes.Equal(normalAlias, wantNormal[:]) || !bytes.Equal(outerAlias, wantOuter[:]) {
				t.Fatal("D1 transcript fan-out did not use the two literal protocol domains")
			}
			if bytes.Equal(normalAlias, outerAlias) {
				t.Fatal("normal and outer credential inputs were interchangeable")
			}
			formatted := fmt.Sprintf("%v|%+v|%#v|%v|%+v|%#v", normal, normal, normal, outer, outer, outer)
			const wantFormatted = "pcv3credential.CredentialInputNormal([REDACTED])|pcv3credential.CredentialInputNormal([REDACTED])|pcv3credential.CredentialInputNormal([REDACTED])|pcv3credential.CredentialInputOuter([REDACTED])|pcv3credential.CredentialInputOuter([REDACTED])|pcv3credential.CredentialInputOuter([REDACTED])"
			if formatted != wantFormatted {
				t.Fatalf("D1 credential input formatting was not fixed and redacted: %q", formatted)
			}
			normal.Close()
			outer.Close()
			if !allZero(normalAlias) || !allZero(outerAlias) {
				t.Fatal("D1 credential input owners retained bytes after Close")
			}
		})
	}
}

func TestD1OuterDerivationIsSequentialAndBounded(t *testing.T) {
	normal, outer := newD1TestInputs(t)
	var salts D1CreationSalts
	for index := range salts.Front {
		salts.Front[index] = byte(0x10 + index)
		salts.Tail[index] = byte(0x80 + index)
	}
	innerSalt := bytes.Repeat([]byte{0xe1}, kdfSaltBytes)
	ctx := context.Background()
	active := 0
	maxActive := 0
	var order []string
	var returnedAliases [][]byte
	var hkdfAliases [][]byte
	var ownedAliases [][]byte
	var credentialInfos []string
	var expiredOwner *D1OuterCredentialOwner
	current := ""
	derive := func(input, salt []byte, profile KDFProfile) ([]byte, error) {
		active++
		defer func() { active-- }()
		if active > maxActive {
			maxActive = active
		}
		if profile != mustD1TestProfile(t) {
			t.Fatal("D1 derivation did not use the fixed Paranoid-1 profile")
		}
		switch {
		case bytes.Equal(salt, salts.Front[:]):
			current = "front-outer"
		case bytes.Equal(salt, salts.Tail[:]):
			current = "tail-outer"
		case bytes.Equal(salt, innerSalt):
			current = "inner-normal"
		default:
			t.Fatal("D1 derivation used an unexpected salt")
		}
		order = append(order, current)
		returned := bytes.Repeat([]byte{byte(0xa0 + len(order))}, credentialRootBytes)
		returnedAliases = append(returnedAliases, returned)
		return returned, nil
	}
	extract := func(root, salt []byte) ([]byte, error) {
		if len(root) != credentialRootBytes ||
			(!bytes.Equal(salt, salts.Front[:]) && !bytes.Equal(salt, salts.Tail[:])) {
			t.Fatal("D1 outer credential extraction used the wrong root or salt")
		}
		returned := bytes.Repeat([]byte{byte(0x30 + len(hkdfAliases))}, derivedKeyBytes)
		hkdfAliases = append(hkdfAliases, returned)
		return returned, nil
	}
	expand := func(_ []byte, info string, size int) ([]byte, error) {
		credentialInfos = append(credentialInfos, info)
		returned := bytes.Repeat([]byte{byte(0x50 + len(hkdfAliases))}, size)
		hkdfAliases = append(hkdfAliases, returned)
		return returned, nil
	}

	err := withD1CreationCredentialRoots(
		ctx,
		normal,
		outer,
		salts,
		grantKDFAdmission(),
		d1OuterDerivationSeams{
			derive:  derive,
			extract: extract,
			expand:  expand,
		},
		func(front, tail *D1OuterCredentialOwner, inner *CredentialInputNormal) error {
			if front.Role() != KeyRolePrimary || tail.Role() != KeyRoleBackup {
				t.Fatal("D1 creation roots lost physical bootstrap roles")
			}
			for _, owner := range []*D1OuterCredentialOwner{front, tail} {
				if expiredOwner == nil {
					expiredOwner = owner
				}
				ownedAliases = append(ownedAliases, d1OuterCredentialOwnerAliases(owner)...)
				if err := owner.WithKeys(ctx, func(keys *BorrowedD1OuterCredentialKeys) error {
					for _, label := range []D1OuterCredentialLabel{
						D1OuterCredentialWrapXChaCha20,
						D1OuterCredentialWrapSerpent,
						D1OuterCredentialWrapMAC,
					} {
						destination := make([]byte, derivedKeyBytes)
						if err := keys.CopyKey(label, destination); err != nil {
							return err
						}
						if allZero(destination) {
							t.Fatal("D1 outer credential schedule produced an empty key")
						}
					}
					return nil
				}); err != nil {
					return err
				}
			}
			root, err := runCredentialKDF(
				ctx,
				inner,
				innerSalt,
				SuiteParanoid1,
				grantKDFAdmission(),
				derive,
			)
			if root != nil {
				defer root.close()
			}
			return err
		},
	)
	if err != nil {
		t.Fatalf("derive D1 creation credentials: %v", err)
	}
	if !slices.Equal(order, []string{"front-outer", "tail-outer", "inner-normal"}) {
		t.Fatalf("D1 derivation order = %v", order)
	}
	if maxActive != 1 {
		t.Fatalf("maximum overlapping D1 derivations = %d, want 1", maxActive)
	}
	wantCredentialInfos := []string{
		d1TestScheduleInfo("outer/wrap/xchacha20", KeyRolePrimary),
		d1TestScheduleInfo("outer/wrap/serpent", KeyRolePrimary),
		d1TestScheduleInfo("outer/wrap/mac", KeyRolePrimary),
		d1TestScheduleInfo("outer/wrap/xchacha20", KeyRoleBackup),
		d1TestScheduleInfo("outer/wrap/serpent", KeyRoleBackup),
		d1TestScheduleInfo("outer/wrap/mac", KeyRoleBackup),
	}
	if !slices.Equal(credentialInfos, wantCredentialInfos) {
		t.Fatalf("D1 outer credential schedule infos = %q, want %q", credentialInfos, wantCredentialInfos)
	}
	for _, alias := range returnedAliases {
		if !allZero(alias) {
			t.Fatal("D1 KDF provider return survived derivation")
		}
	}
	for _, alias := range ownedAliases {
		if !allZero(alias) {
			t.Fatal("D1 outer credential owner retained secret material after callback unwind")
		}
	}
	for _, alias := range hkdfAliases {
		if !allZero(alias) {
			t.Fatal("D1 outer credential HKDF provider return survived derivation")
		}
	}
	var ownerErr *OwnerError
	err = expiredOwner.WithKeys(ctx, func(*BorrowedD1OuterCredentialKeys) error {
		return nil
	})
	if !errors.As(err, &ownerErr) || ownerErr.Code != OwnerErrorClosed {
		t.Fatalf("closed D1 outer credential owner error = %T %v", err, err)
	}
}

func TestD1OuterKeyOwnerUsesClosedScheduleAndZeroes(t *testing.T) {
	keyAlias := bytes.Repeat([]byte{0x5c}, derivedKeyBytes)
	var infos []string
	var providerAliases [][]byte
	wantRootSalt := sha3.Sum256([]byte("Picocrypt-NG/PCV3/outer/root\x00"))
	owner, err := newD1OuterKeyOwnerWith(
		keyAlias,
		func(key, salt []byte) ([]byte, error) {
			if !bytes.Equal(key, keyAlias) || !bytes.Equal(salt, wantRootSalt[:]) {
				t.Fatal("D1 OuterKey extraction used the wrong key or literal root domain")
			}
			returned := bytes.Repeat([]byte{0x31}, derivedKeyBytes)
			providerAliases = append(providerAliases, returned)
			return returned, nil
		},
		func(prk []byte, info string, size int) ([]byte, error) {
			infos = append(infos, info)
			returned := bytes.Repeat([]byte{byte(0x40 + len(infos))}, size)
			providerAliases = append(providerAliases, returned)
			return returned, nil
		},
	)
	if err != nil {
		t.Fatalf("derive D1 OuterKey schedule: %v", err)
	}
	defer owner.Close()
	aliases := d1OuterKeyOwnerAliases(owner)
	wantInfos := []string{
		d1TestScheduleInfo("outer/replica/mac", KeyRolePrimary),
		d1TestScheduleInfo("outer/replica/mac", KeyRoleBackup),
		d1TestScheduleInfo("outer/payload/xchacha20", KeyRoleNotReplica),
		d1TestScheduleInfo("outer/payload/serpent", KeyRoleNotReplica),
		d1TestScheduleInfo("outer/payload/mac", KeyRoleNotReplica),
		d1TestScheduleInfo("outer/payload/xnonce-prefix", KeyRoleNotReplica),
		d1TestScheduleInfo("outer/payload/serpent-prefix", KeyRoleNotReplica),
	}
	if !slices.Equal(infos, wantInfos) {
		t.Fatalf("D1 OuterKey schedule infos = %q, want %q", infos, wantInfos)
	}
	for index, alias := range providerAliases {
		if !allZero(alias) {
			owner.Close()
			t.Fatalf("D1 OuterKey provider return %d was not cleared", index)
		}
	}
	var expired *BorrowedD1OuterKeys
	err = owner.WithKeys(context.Background(), func(keys *BorrowedD1OuterKeys) error {
		expired = keys
		outerKey := make([]byte, derivedKeyBytes)
		if err := keys.CopyOuterKey(outerKey); err != nil {
			return err
		}
		if !bytes.Equal(outerKey, bytes.Repeat([]byte{0x5c}, derivedKeyBytes)) {
			t.Fatal("D1 OuterKey owner did not lend the transferred key")
		}
		for _, request := range fixedD1OuterKeyRequests() {
			destination := make([]byte, request.outputBytes)
			if err := keys.CopyKey(request.label, request.role, destination); err != nil {
				return err
			}
			if allZero(destination) {
				t.Fatal("D1 OuterKey schedule produced an empty key")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("borrow D1 OuterKey schedule: %v", err)
	}
	if err := expired.CopyKey(D1OuterPayloadMAC, KeyRoleNotReplica, make([]byte, derivedKeyBytes)); err == nil {
		t.Fatal("expired D1 OuterKey borrow remained usable")
	}
	owner.Close()
	for _, alias := range aliases {
		if !allZero(alias) {
			t.Fatal("D1 OuterKey owner retained secret material after Close")
		}
	}
	var ownerErr *OwnerError
	err = owner.WithKeys(context.Background(), func(*BorrowedD1OuterKeys) error {
		return nil
	})
	if !errors.As(err, &ownerErr) || ownerErr.Code != OwnerErrorClosed {
		t.Fatalf("closed D1 OuterKey owner error = %T %v", err, err)
	}
}

func TestD1OuterCancellationAndClosedOwnersFailBeforeNextDerivation(t *testing.T) {
	normal, outer := newD1TestInputs(t)
	normalAlias := normal.secret.Bytes()
	outerAlias := outer.secret.Bytes()
	var salts D1CreationSalts
	for index := range salts.Front {
		salts.Front[index] = byte(index + 1)
		salts.Tail[index] = byte(index + 33)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	var returnedAlias []byte
	err := withD1CreationCredentialRoots(
		ctx,
		normal,
		outer,
		salts,
		grantKDFAdmission(),
		d1OuterDerivationSeams{
			derive: func([]byte, []byte, KDFProfile) ([]byte, error) {
				calls++
				returnedAlias = bytes.Repeat([]byte{0x77}, credentialRootBytes)
				cancel()
				return returnedAlias, nil
			},
			extract: defaultHKDFExtract,
			expand:  defaultHKDFExpand,
		},
		func(*D1OuterCredentialOwner, *D1OuterCredentialOwner, *CredentialInputNormal) error {
			t.Fatal("cancelled D1 derivation invoked the creation callback")
			return nil
		},
	)
	var kdfErr *KDFError
	if !errors.As(err, &kdfErr) || kdfErr.Code != KDFErrorCancelled {
		t.Fatalf("cancelled D1 derivation error = %T %v", err, err)
	}
	if calls != 1 {
		t.Fatalf("cancelled D1 derivation calls = %d, want 1", calls)
	}
	for _, alias := range [][]byte{normalAlias, outerAlias, returnedAlias} {
		if !allZero(alias) {
			t.Fatal("cancelled D1 derivation retained secret bytes")
		}
	}

	unusedNormal, closedOuter := newD1TestInputs(t)
	unusedNormal.Close()
	closedOuter.Close()
	called := false
	err = closedOuter.withInput(func([]byte) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("closed outer credential input was borrowed")
	}
}

func newD1TestInputs(t *testing.T) (*CredentialInputNormal, *CredentialInputOuter) {
	t.Helper()
	request, passwordAlias, readers := newRealTranscriptRequest(
		CredentialModePasswordOnly,
		KeyfileModeNone,
		FactorPolicyPasswordOnly,
		[]byte("TEST ONLY D1 password"),
	)
	transcript, err := canonicalTranscriptFromRequest(request)
	if err != nil {
		t.Fatalf("build D1 test transcript: %v", err)
	}
	requireRealInputsReleased(t, request, passwordAlias, readers)
	normal, outer, err := NewD1CredentialInputs(transcript)
	if err != nil {
		t.Fatalf("fan out D1 test transcript: %v", err)
	}
	return normal, outer
}

func d1TestInputDigest(domain string, transcript []byte) [64]byte {
	hasher := sha3.New512()
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write(transcript)
	var digest [64]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

func mustD1TestProfile(t *testing.T) KDFProfile {
	t.Helper()
	profile, err := fixedProfileForSuite(SuiteParanoid1)
	if err != nil {
		t.Fatalf("load Paranoid-1 profile: %v", err)
	}
	return profile
}

func d1TestScheduleInfo(label string, role KeyRole) string {
	const domain = "Picocrypt-NG/PCV3/HKDF\x00"
	info := make([]byte, 0, len(domain)+9+len(label))
	info = append(info, domain...)
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], 0x0003)
	info = append(info, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], 0x0001)
	info = append(info, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], uint16(SuiteParanoid1))
	info = append(info, encoded[:]...)
	info = append(info, byte(role))
	binary.BigEndian.PutUint16(encoded[:], uint16(len(label)))
	info = append(info, encoded[:]...)
	info = append(info, label...)
	return string(info)
}

func d1OuterCredentialOwnerAliases(owner *D1OuterCredentialOwner) [][]byte {
	if owner == nil || owner.state == nil {
		return nil
	}
	owner.state.mu.RLock()
	defer owner.state.mu.RUnlock()
	material := owner.state.material
	if material == nil {
		return nil
	}
	aliases := make([][]byte, 0, 2+len(material.keys))
	if material.root != nil && material.root.secret != nil {
		aliases = append(aliases, material.root.secret.Bytes())
	}
	if material.prk != nil && material.prk.secret != nil {
		aliases = append(aliases, material.prk.secret.Bytes())
	}
	for index := range material.keys {
		if material.keys[index].secret != nil {
			aliases = append(aliases, material.keys[index].secret.Bytes())
		}
	}
	return aliases
}

func d1OuterKeyOwnerAliases(owner *D1OuterKeyOwner) [][]byte {
	if owner == nil || owner.state == nil {
		return nil
	}
	owner.state.mu.RLock()
	defer owner.state.mu.RUnlock()
	material := owner.state.material
	if material == nil {
		return nil
	}
	aliases := make([][]byte, 0, 2+len(material.keys))
	if material.key != nil && material.key.secret != nil {
		aliases = append(aliases, material.key.secret.Bytes())
	}
	if material.prk != nil && material.prk.secret != nil {
		aliases = append(aliases, material.prk.secret.Bytes())
	}
	for index := range material.keys {
		if material.keys[index].secret != nil {
			aliases = append(aliases, material.keys[index].secret.Bytes())
		}
	}
	return aliases
}
