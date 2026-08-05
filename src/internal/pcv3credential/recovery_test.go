package pcv3credential

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type recoveryCredentialProbe struct {
	reader *readerCredentialProbe

	activeKDF     int
	maxActiveKDF  int
	kdfInputs     [][]byte
	kdfSnapshots  [][]byte
	kdfSalts      [][]byte
	callbackOrder []int
}

func newRecoveryCredentialProbe() *recoveryCredentialProbe {
	return &recoveryCredentialProbe{reader: newReaderCredentialProbe()}
}

func (probe *recoveryCredentialProbe) seams() readerCredentialSeams {
	seams := probe.reader.seams()
	seams.derive = func(input, salt []byte, _ KDFProfile) ([]byte, error) {
		probe.activeKDF++
		probe.maxActiveKDF = max(probe.maxActiveKDF, probe.activeKDF)
		defer func() { probe.activeKDF-- }()

		probe.reader.kdfCalls++
		probe.kdfInputs = append(probe.kdfInputs, input)
		probe.kdfSnapshots = append(
			probe.kdfSnapshots,
			append([]byte(nil), input...),
		)
		probe.kdfSalts = append(probe.kdfSalts, append([]byte(nil), salt...))
		returned := bytes.Repeat(
			[]byte{byte(0x90 + probe.reader.kdfCalls)},
			credentialRootBytes,
		)
		probe.reader.providerData = append(probe.reader.providerData, returned)
		return returned, nil
	}
	return seams
}

func recoveryCredentialTuple(
	t *testing.T,
	suite Suite,
	factors *FactorRequest,
	marker byte,
) RecoveryCredentialTuple {
	t.Helper()
	profile, err := fixedProfileForSuite(suite)
	if err != nil {
		t.Fatalf("fixedProfileForSuite(%#04x): %v", suite, err)
	}
	return RecoveryCredentialTuple{
		Suite:          suite,
		ProfileID:      profile.ID,
		CredentialMode: factors.Mode,
		KeyfileMode:    factors.KeyfileMode,
		KeyfileCount:   uint16(len(factors.Keyfiles)), //nolint:gosec // Test inputs are bounded to two keyfiles.
		ArgonSalt:      bytes.Repeat([]byte{marker}, kdfSaltBytes),
		VolumeID:       bytes.Repeat([]byte{marker + 0x20}, scheduleVolumeIDBytes),
	}
}

func recoveryFactors(
	test ownerMetadataFactorCase,
) (*FactorRequest, []*trackedReadCloser) {
	readers := make([]*trackedReadCloser, len(test.keyfiles))
	keyfiles := make([]*KeyfileReader, len(test.keyfiles))
	for i := range test.keyfiles {
		readers[i] = newChunkedReadCloser(test.keyfiles[i], 3)
		keyfiles[i] = OwnKeyfileReader(readers[i])
	}
	return &FactorRequest{
		Mode:           test.mode,
		KeyfileMode:    test.keyfileMode,
		ExpectedPolicy: test.policy,
		Password:       append([]byte(nil), test.password...),
		Keyfiles:       keyfiles,
	}, readers
}

func TestRecoveryCredentialConsumesFactorsOnceAcrossTwoTuples(t *testing.T) {
	for _, test := range ownerMetadataFactorCases() {
		t.Run(test.name, func(t *testing.T) {
			factors, readers := recoveryFactors(test)
			passwordAlias := factors.Password
			first := recoveryCredentialTuple(t, SuiteStandard1, factors, 0x31)
			second := recoveryCredentialTuple(t, SuiteParanoid1, factors, 0x42)
			probe := newRecoveryCredentialProbe()
			transfer := bytes.Repeat([]byte{0x5a}, derivedKeyBytes)

			owner, err := newRecoveryCredential(
				context.Background(),
				&RecoveryCredentialRequest{
					Factors: factors,
					Tuples:  []RecoveryCredentialTuple{first, second},
				},
				probe.reader.admit,
				func(index int, candidate *ReaderCredential) error {
					probe.callbackOrder = append(probe.callbackOrder, index)
					if index == 0 {
						return candidate.AdoptVolumeKey(transfer)
					}
					return candidate.WithKeys(
						context.Background(),
						KeyRolePrimary,
						func(*ReaderKeys) error { return nil },
					)
				},
				probe.seams(),
			)
			if err != nil {
				t.Fatalf("newRecoveryCredential: %v", err)
			}
			if owner == nil {
				t.Fatal("selected recovery candidate published no owner")
			}
			if !allZero(transfer) {
				owner.Close()
				t.Fatal("selected VolumeKey transfer was not cleared")
			}
			metadata := owner.Metadata()
			if metadata.Suite != first.Suite ||
				metadata.CredentialMode != test.mode ||
				metadata.KeyfileMode != test.keyfileMode ||
				metadata.KeyfileCount != uint16(len(test.keyfiles)) {
				owner.Close()
				t.Fatalf("selected owner metadata = %+v", metadata)
			}
			if probe.reader.admit.calls != 2 ||
				probe.reader.kdfCalls != 2 ||
				probe.maxActiveKDF != 1 ||
				!slicesEqual(probe.callbackOrder, []int{0, 1}) {
				owner.Close()
				t.Fatalf(
					"admission/KDF/max-active/order = %d/%d/%d/%v; want 2/2/1/[0 1]",
					probe.reader.admit.calls,
					probe.reader.kdfCalls,
					probe.maxActiveKDF,
					probe.callbackOrder,
				)
			}
			if len(probe.kdfInputs) != 2 ||
				len(probe.kdfSnapshots) != 2 ||
				!bytes.Equal(probe.kdfSnapshots[0], probe.kdfSnapshots[1]) ||
				&probe.kdfInputs[0][0] != &probe.kdfInputs[1][0] {
				owner.Close()
				t.Fatal("two candidates did not borrow the same canonical input")
			}
			if bytes.Equal(probe.kdfSalts[0], probe.kdfSalts[1]) {
				owner.Close()
				t.Fatal("two candidate derivations did not preserve distinct salts")
			}
			if !allZero(passwordAlias) {
				owner.Close()
				t.Fatal("recovery session retained the transferred password")
			}
			for i, reader := range readers {
				if reader.readCalls == 0 || reader.closeCalls != 1 {
					owner.Close()
					t.Fatalf(
						"keyfile %d read/close calls = %d/%d; want >0/1",
						i,
						reader.readCalls,
						reader.closeCalls,
					)
				}
			}
			for i, alias := range probe.kdfInputs {
				if !allZero(alias) {
					owner.Close()
					t.Fatalf("borrowed input alias %d survived the session", i)
				}
			}
			owner.Close()
			for i, alias := range probe.reader.ownedAliases {
				if !allZero(alias) {
					t.Fatalf("candidate-owned alias %d survived owner close", i)
				}
			}
		})
	}
}

func TestRecoveryCredentialRejectsTupleSetBeforeKDF(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RecoveryCredentialRequest)
	}{
		{name: "zero tuples", edit: func(request *RecoveryCredentialRequest) { request.Tuples = nil }},
		{name: "third tuple", edit: func(request *RecoveryCredentialRequest) {
			request.Tuples = append(request.Tuples, recoveryCredentialTuple(t, SuiteStandard1, request.Factors, 0x53))
		}},
		{name: "duplicate tuple", edit: func(request *RecoveryCredentialRequest) {
			duplicate := request.Tuples[0]
			duplicate.ArgonSalt = append([]byte(nil), duplicate.ArgonSalt...)
			duplicate.VolumeID = append([]byte(nil), duplicate.VolumeID...)
			request.Tuples = []RecoveryCredentialTuple{request.Tuples[0], duplicate}
		}},
		{name: "unsupported suite", edit: func(request *RecoveryCredentialRequest) {
			request.Tuples[0].Suite = Suite(0xffff)
		}},
		{name: "wrong profile", edit: func(request *RecoveryCredentialRequest) {
			request.Tuples[0].ProfileID ^= 0xff
		}},
		{name: "short salt", edit: func(request *RecoveryCredentialRequest) {
			request.Tuples[0].ArgonSalt = request.Tuples[0].ArgonSalt[:kdfSaltBytes-1]
		}},
		{name: "short volume ID", edit: func(request *RecoveryCredentialRequest) {
			request.Tuples[0].VolumeID = request.Tuples[0].VolumeID[:scheduleVolumeIDBytes-1]
		}},
		{name: "factor tuple mismatch", edit: func(request *RecoveryCredentialRequest) {
			request.Tuples[0].CredentialMode = CredentialModeKeyfilesOnly
			request.Tuples[0].KeyfileMode = KeyfileModeOrdered
			request.Tuples[0].KeyfileCount = 1
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factors := pipelineRequest(t, SuiteStandard1).Factors
			passwordAlias := factors.Password
			request := &RecoveryCredentialRequest{
				Factors: factors,
				Tuples: []RecoveryCredentialTuple{
					recoveryCredentialTuple(t, SuiteStandard1, factors, 0x31),
				},
			}
			test.edit(request)
			probe := newRecoveryCredentialProbe()
			callbackCalls := 0
			owner, err := newRecoveryCredential(
				context.Background(),
				request,
				probe.reader.admit,
				func(int, *ReaderCredential) error {
					callbackCalls++
					return nil
				},
				probe.seams(),
			)
			if err == nil {
				if owner != nil {
					owner.Close()
				}
				t.Fatal("invalid recovery tuple set succeeded")
			}
			if owner != nil || callbackCalls != 0 ||
				probe.reader.admit.calls != 0 || probe.reader.kdfCalls != 0 {
				if owner != nil {
					owner.Close()
				}
				t.Fatalf(
					"rejection owner/callback/admission/KDF = %v/%d/%d/%d; want nil/0/0/0",
					owner,
					callbackCalls,
					probe.reader.admit.calls,
					probe.reader.kdfCalls,
				)
			}
			if request.Factors != nil || request.Tuples != nil || !allZero(passwordAlias) {
				t.Fatal("rejected recovery request retained transferred input")
			}
		})
	}
}

func TestCredentialInputBorrowRejectsNestedAndExpiredUse(t *testing.T) {
	factors := pipelineRequest(t, SuiteStandard1).Factors
	var retained *credentialInputBorrow
	var alias []byte
	err := WithValidatedFactors(
		context.Background(),
		factors,
		func(validated *ValidatedFactors) error {
			transcript, err := NewCanonicalTranscript(validated)
			if err != nil {
				return err
			}
			defer transcript.Close()
			return withCredentialInputBorrow(
				transcript,
				func(borrow *credentialInputBorrow) error {
					retained = borrow
					return borrow.withInput(func(input []byte) error {
						alias = input
						nestedCalls := 0
						nestedErr := borrow.withInput(func([]byte) error {
							nestedCalls++
							return nil
						})
						if nestedErr == nil || nestedCalls != 0 {
							t.Fatal("nested borrow was not rejected before callback")
						}
						return nil
					})
				},
			)
		},
	)
	if err != nil {
		t.Fatalf("withCredentialInputBorrow: %v", err)
	}
	if retained == nil || len(alias) != credentialInputNormalBytes || !allZero(alias) {
		t.Fatal("borrow did not expire and clear its owned canonical input")
	}
	expiredCalls := 0
	if err := retained.withInput(func([]byte) error {
		expiredCalls++
		return nil
	}); err == nil || expiredCalls != 0 {
		t.Fatal("expired borrow invoked its callback")
	}
}

func TestRecoveryCredentialCallbackExitClearsCandidateState(t *testing.T) {
	tests := []struct {
		name      string
		callback  func(context.CancelFunc) error
		wantPanic any
	}{
		{
			name: "callback error",
			callback: func(context.CancelFunc) error {
				return errors.New("private recovery callback marker")
			},
		},
		{
			name: "callback cancellation",
			callback: func(cancel context.CancelFunc) error {
				cancel()
				return nil
			},
		},
		{
			name: "callback panic",
			callback: func(context.CancelFunc) error {
				panic("recovery callback panic marker")
			},
			wantPanic: "recovery callback panic marker",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			factors := pipelineRequest(t, SuiteStandard1).Factors
			passwordAlias := factors.Password
			probe := newRecoveryCredentialProbe()
			transfer := bytes.Repeat([]byte{0x5a}, derivedKeyBytes)
			var owner *Owner
			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				owner, err = newRecoveryCredential(
					ctx,
					&RecoveryCredentialRequest{
						Factors: factors,
						Tuples: []RecoveryCredentialTuple{
							recoveryCredentialTuple(t, SuiteStandard1, factors, 0x31),
						},
					},
					probe.reader.admit,
					func(_ int, candidate *ReaderCredential) error {
						if adoptErr := candidate.AdoptVolumeKey(transfer); adoptErr != nil {
							return adoptErr
						}
						return test.callback(cancel)
					},
					probe.seams(),
				)
			}()
			if recovered != test.wantPanic {
				t.Fatalf("recovered panic = %#v; want %#v", recovered, test.wantPanic)
			}
			if owner != nil || (test.wantPanic == nil && err == nil) {
				if owner != nil {
					owner.Close()
				}
				t.Fatalf("callback exit owner/error = %v/%v; want nil/failure", owner, err)
			}
			if !allZero(passwordAlias) || !allZero(transfer) {
				t.Fatal("callback exit retained factor or adopted transfer")
			}
			for i, alias := range probe.kdfInputs {
				if !allZero(alias) {
					t.Fatalf("callback exit retained input alias %d", i)
				}
			}
			for i, alias := range probe.reader.ownedAliases {
				if !allZero(alias) {
					t.Fatalf("callback exit retained candidate alias %d", i)
				}
			}
		})
	}
}

func slicesEqual(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
