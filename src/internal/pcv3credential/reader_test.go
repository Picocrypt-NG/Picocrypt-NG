package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"context"
	"errors"
	"testing"
)

type readerCredentialProbe struct {
	admit *pipelineAdmission

	kdfCalls     int
	extractCalls int
	expandCalls  int
	providerData [][]byte
	ownedAliases [][]byte
}

func newReaderCredentialProbe() *readerCredentialProbe {
	return &readerCredentialProbe{
		admit: &pipelineAdmission{result: KDFAdmissionGranted},
	}
}

func (probe *readerCredentialProbe) seams() readerCredentialSeams {
	observe := func(material *keyMaterial) {
		if material == nil {
			return
		}
		for _, secret := range []*crypto.Secret{
			func() *crypto.Secret {
				if material.credentialRoot == nil {
					return nil
				}
				return material.credentialRoot.secret
			}(),
			func() *crypto.Secret {
				if material.volumeKey == nil {
					return nil
				}
				return material.volumeKey.secret
			}(),
			func() *crypto.Secret {
				if material.credentialPRK == nil {
					return nil
				}
				return material.credentialPRK.secret
			}(),
			func() *crypto.Secret {
				if material.volumePRK == nil {
					return nil
				}
				return material.volumePRK.secret
			}(),
		} {
			if secret != nil {
				probe.ownedAliases = append(probe.ownedAliases, secret.Bytes())
			}
		}
		for i := range material.keys {
			if material.keys[i].secret != nil {
				probe.ownedAliases = append(
					probe.ownedAliases,
					material.keys[i].secret.Bytes(),
				)
			}
		}
	}
	return readerCredentialSeams{
		derive: func([]byte, []byte, KDFProfile) ([]byte, error) {
			probe.kdfCalls++
			returned := bytes.Repeat([]byte{0x91}, credentialRootBytes)
			probe.providerData = append(probe.providerData, returned)
			return returned, nil
		},
		extract: func([]byte, []byte) ([]byte, error) {
			probe.extractCalls++
			returned := bytes.Repeat(
				[]byte{byte(0xa0 + probe.extractCalls)},
				derivedKeyBytes,
			)
			probe.providerData = append(probe.providerData, returned)
			return returned, nil
		},
		expand: func([]byte, string, int) ([]byte, error) {
			probe.expandCalls++
			returned := bytes.Repeat(
				[]byte{byte(0xc0 + probe.expandCalls)},
				derivedKeyBytes,
			)
			probe.providerData = append(probe.providerData, returned)
			return returned, nil
		},
		observeCredentialMaterial: observe,
		observeReplicaMaterial:    observe,
		observeOwnerMaterial:      observe,
	}
}

func readerCredentialRequest(t *testing.T, suite Suite) *ReaderCredentialRequest {
	t.Helper()
	writerRequest := pipelineRequest(t, suite)
	profile, err := fixedProfileForSuite(suite)
	if err != nil {
		t.Fatalf("fixedProfileForSuite(%#04x): %v", suite, err)
	}
	return &ReaderCredentialRequest{
		Suite:         suite,
		ProfileID:     profile.ID,
		Factors:       writerRequest.Factors,
		ClaimedPolicy: writerRequest.Factors.ExpectedPolicy,
		ArgonSalt:     bytes.Repeat([]byte{0x31}, kdfSaltBytes),
		VolumeID:      bytes.Repeat([]byte{0x42}, scheduleVolumeIDBytes),
	}
}

func TestReaderCredentialRejectsBeforeKDF(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ReaderCredentialRequest)
		ctx  func() context.Context
	}{
		{
			name: "invalid factor shape",
			edit: func(request *ReaderCredentialRequest) {
				request.Factors.Mode = CredentialModeKeyfilesOnly
			},
		},
		{
			name: "invalid claimed policy",
			edit: func(request *ReaderCredentialRequest) {
				request.ClaimedPolicy = FactorPolicy(0xff)
			},
		},
		{
			name: "caller policy contradicts capsule claim",
			edit: func(request *ReaderCredentialRequest) {
				request.ClaimedPolicy = FactorPolicyKeyfilesOnly
			},
		},
		{
			name: "invalid suite",
			edit: func(request *ReaderCredentialRequest) {
				request.Suite = Suite(0xffff)
			},
		},
		{
			name: "mismatched profile",
			edit: func(request *ReaderCredentialRequest) {
				request.ProfileID ^= 0xff
			},
		},
		{
			name: "short salt",
			edit: func(request *ReaderCredentialRequest) {
				request.ArgonSalt = request.ArgonSalt[:kdfSaltBytes-1]
			},
		},
		{
			name: "short volume ID",
			edit: func(request *ReaderCredentialRequest) {
				request.VolumeID = request.VolumeID[:scheduleVolumeIDBytes-1]
			},
		},
		{
			name: "cancelled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := readerCredentialRequest(t, SuiteStandard1)
			if test.edit != nil {
				test.edit(request)
			}
			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx()
			}
			passwordAlias := request.Factors.Password
			probe := newReaderCredentialProbe()
			callbackCalls := 0
			owner, err := newReaderCredential(
				ctx,
				request,
				probe.admit,
				func(*ReaderCredential) error {
					callbackCalls++
					return nil
				},
				probe.seams(),
			)
			if err == nil {
				if owner != nil {
					owner.Close()
				}
				t.Fatal("invalid reader request succeeded")
			}
			if owner != nil || probe.kdfCalls != 0 || callbackCalls != 0 {
				if owner != nil {
					owner.Close()
				}
				t.Fatalf(
					"rejection owner/KDF/callback = %v/%d/%d; want nil/0/0",
					owner,
					probe.kdfCalls,
					callbackCalls,
				)
			}
			if !allZero(passwordAlias) {
				t.Fatal("rejected reader request retained transferred password")
			}
			if request.Factors != nil {
				t.Fatal("rejected reader request retained transferred factors")
			}
		})
	}
}

func TestReaderCredentialExactlyOneKDFAndScopedKeys(t *testing.T) {
	request := readerCredentialRequest(t, SuiteStandard1)
	passwordAlias := request.Factors.Password
	wantMetadata := OwnerMetadata{
		Suite:          request.Suite,
		ExpectedPolicy: request.Factors.ExpectedPolicy,
	}
	copy(wantMetadata.ArgonSalt[:], request.ArgonSalt)
	copy(wantMetadata.VolumeID[:], request.VolumeID)
	probe := newReaderCredentialProbe()
	selected := bytes.Repeat([]byte{0x5a}, derivedKeyBytes)
	wantVolumeKey := append([]byte(nil), selected...)
	defer crypto.SecureZero(wantVolumeKey)
	second := bytes.Repeat([]byte{0x6b}, derivedKeyBytes)
	var expiredWrap, expiredReplica *ReaderKeys

	owner, err := newReaderCredential(
		context.Background(),
		request,
		probe.admit,
		func(reader *ReaderCredential) error {
			if err := reader.WithKeys(
				context.Background(),
				KeyRolePrimary,
				func(keys *ReaderKeys) error {
					expiredWrap = keys
					destination := make([]byte, derivedKeyBytes)
					defer crypto.SecureZero(destination)
					if err := keys.CopyKey(KeyRequest{
						Label:       KeyLabelCredentialWrapMAC,
						Role:        KeyRolePrimary,
						OutputBytes: derivedKeyBytes,
					}, destination); err != nil {
						return err
					}
					err := keys.CopyKey(KeyRequest{
						Label:       KeyLabelCredentialWrapMAC,
						Role:        KeyRoleBackup,
						OutputBytes: derivedKeyBytes,
					}, destination)
					requireOwnerCode(t, err, OwnerErrorUnknownKey)
					return nil
				},
			); err != nil {
				return err
			}

			candidate := append([]byte(nil), selected...)
			defer crypto.SecureZero(candidate)
			if err := reader.WithReplicaKey(
				context.Background(),
				KeyRolePrimary,
				candidate,
				func(keys *ReaderKeys) error {
					expiredReplica = keys
					destination := make([]byte, derivedKeyBytes)
					defer crypto.SecureZero(destination)
					return keys.CopyKey(KeyRequest{
						Label:       KeyLabelVolumeReplicaMAC,
						Role:        KeyRolePrimary,
						OutputBytes: derivedKeyBytes,
					}, destination)
				},
			); err != nil {
				return err
			}
			if !bytes.Equal(candidate, selected) {
				t.Fatal("replica-key derivation mutated its read-only candidate")
			}

			if err := reader.AdoptVolumeKey(selected); err != nil {
				return err
			}
			if !allZero(selected) {
				t.Fatal("VolumeKey adoption did not clear the transfer buffer")
			}
			err := reader.AdoptVolumeKey(second)
			requireOwnerCode(t, err, OwnerErrorInvalidRequest)
			if !allZero(second) {
				t.Fatal("second adoption rejection retained the transfer buffer")
			}
			return nil
		},
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("newReaderCredential: %v", err)
	}
	if owner == nil {
		t.Fatal("reader credential published no final owner")
	}
	if owner.Metadata() != wantMetadata {
		owner.Close()
		t.Fatalf("owner metadata = %+v; want %+v", owner.Metadata(), wantMetadata)
	}
	if probe.admit.calls != 1 || probe.kdfCalls != 1 {
		owner.Close()
		t.Fatalf(
			"admission/KDF calls = %d/%d; want 1/1",
			probe.admit.calls,
			probe.kdfCalls,
		)
	}
	if !allZero(passwordAlias) {
		owner.Close()
		t.Fatal("successful reader retained transferred password")
	}
	for i, returned := range probe.providerData {
		if !allZero(returned) {
			owner.Close()
			t.Fatalf("provider return %d was not cleared", i)
		}
	}
	destination := make([]byte, derivedKeyBytes)
	defer crypto.SecureZero(destination)
	requireOwnerCode(
		t,
		expiredWrap.CopyKey(KeyRequest{}, destination),
		OwnerErrorBorrowExpired,
	)
	requireOwnerCode(
		t,
		expiredReplica.CopyKey(KeyRequest{}, destination),
		OwnerErrorBorrowExpired,
	)
	if err := owner.WithKeys(
		context.Background(),
		func(keys *BorrowedKeys) error {
			return keys.CopyVolumeKey(destination)
		},
	); err != nil {
		owner.Close()
		t.Fatalf("copy adopted VolumeKey: %v", err)
	}
	if !bytes.Equal(destination, wantVolumeKey) {
		owner.Close()
		t.Fatal("final owner did not retain the selected VolumeKey")
	}
	owner.Close()
	for i, alias := range probe.ownedAliases {
		if !allZero(alias) {
			t.Fatalf("owner-controlled alias %d survived close", i)
		}
	}
}

func TestReaderCredentialCleanupOnCallbackExit(t *testing.T) {
	tests := []struct {
		name      string
		callback  func(*ReaderCredential, []byte) error
		wantPanic bool
	}{
		{
			name: "missing adoption",
			callback: func(*ReaderCredential, []byte) error {
				return nil
			},
		},
		{
			name: "callback error after adoption",
			callback: func(reader *ReaderCredential, key []byte) error {
				if err := reader.AdoptVolumeKey(key); err != nil {
					return err
				}
				return errors.New("private-reader-callback-sentinel")
			},
		},
		{
			name: "callback panic after adoption",
			callback: func(reader *ReaderCredential, key []byte) error {
				if err := reader.AdoptVolumeKey(key); err != nil {
					return err
				}
				panic("reader callback panic sentinel")
			},
			wantPanic: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := readerCredentialRequest(t, SuiteStandard1)
			probe := newReaderCredentialProbe()
			transfer := bytes.Repeat([]byte{0x77}, derivedKeyBytes)
			var owner *Owner
			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				owner, err = newReaderCredential(
					context.Background(),
					request,
					probe.admit,
					func(reader *ReaderCredential) error {
						return test.callback(reader, transfer)
					},
					probe.seams(),
				)
			}()
			if test.wantPanic {
				if recovered != "reader callback panic sentinel" {
					t.Fatalf("panic = %v; want reader callback marker", recovered)
				}
			} else if recovered != nil {
				t.Fatalf("unexpected panic: %v", recovered)
			}
			if owner != nil || (!test.wantPanic && err == nil) {
				if owner != nil {
					owner.Close()
				}
				t.Fatalf("callback exit owner/error = %v/%v; want nil/error", owner, err)
			}
			if test.name != "missing adoption" && !allZero(transfer) {
				t.Fatal("callback exit retained adopted transfer bytes")
			}
			for i, alias := range probe.ownedAliases {
				if !allZero(alias) {
					t.Fatalf("callback exit retained owned alias %d", i)
				}
			}
		})
	}
}
