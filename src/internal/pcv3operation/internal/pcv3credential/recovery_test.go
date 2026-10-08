package pcv3credential

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"testing/synctest"
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
	seams.observeVolumeMaterial = seams.observeReplicaMaterial
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

func TestRecoveryCredentialSessionAnalysesBoundCandidatesBeforeSelection(t *testing.T) {
	factors := pipelineRequest(t, SuiteStandard1).Factors
	passwordAlias := factors.Password
	first := recoveryCredentialTuple(t, SuiteStandard1, factors, 0x31)
	second := recoveryCredentialTuple(t, SuiteParanoid1, factors, 0x42)
	probe := newRecoveryCredentialProbe()
	firstTransfer := bytes.Repeat([]byte{0x5a}, derivedKeyBytes)
	secondTransfer := bytes.Repeat([]byte{0x5a}, derivedKeyBytes)
	var retained *RecoverySession
	var selected *RecoveryVolumeCandidate
	allTuplesDerivedBeforeCallback := false

	owner, err := newRecoveryCredentialSession(
		context.Background(),
		&RecoveryCredentialRequest{
			Factors: factors,
			Tuples:  []RecoveryCredentialTuple{first, second},
		},
		probe.reader.admit,
		func(session *RecoverySession) error {
			retained = session
			allTuplesDerivedBeforeCallback = probe.reader.kdfCalls == 2 &&
				probe.reader.admit.calls == 2

			for index := range 2 {
				var wrapMAC [derivedKeyBytes]byte
				err := session.WithTupleKeys(
					context.Background(),
					index,
					KeyRolePrimary,
					func(keys *ReaderKeys) error {
						return keys.CopyKey(KeyRequest{
							Label:       KeyLabelCredentialWrapMAC,
							Role:        KeyRolePrimary,
							OutputBytes: derivedKeyBytes,
						}, wrapMAC[:])
					},
				)
				if err != nil || allZero(wrapMAC[:]) {
					return errors.New("retained tuple credential borrow failed")
				}
			}

			firstCandidate, err := session.BindCandidate(
				context.Background(),
				0,
				firstTransfer,
			)
			if err != nil {
				return err
			}
			secondCandidate, err := session.BindCandidate(
				context.Background(),
				1,
				secondTransfer,
			)
			if err != nil {
				return err
			}
			selected = firstCandidate
			same, err := session.SameVolumeKey(firstCandidate, secondCandidate)
			if err != nil || !same {
				return errors.New("constant-time candidate reconciliation failed")
			}

			var replicaMAC [derivedKeyBytes]byte
			if err := session.WithReplicaKey(
				context.Background(),
				firstCandidate,
				KeyRolePrimary,
				func(keys *ReaderKeys) error {
					return keys.CopyKey(KeyRequest{
						Label:       KeyLabelVolumeReplicaMAC,
						Role:        KeyRolePrimary,
						OutputBytes: derivedKeyBytes,
					}, replicaMAC[:])
				},
			); err != nil || allZero(replicaMAC[:]) {
				return errors.New("candidate replica-key borrow failed")
			}

			var payloadMAC [derivedKeyBytes]byte
			if err := session.WithVolumeKeys(
				context.Background(),
				firstCandidate,
				func(keys *ReaderKeys) error {
					return keys.CopyKey(KeyRequest{
						Label:       KeyLabelVolumePayloadMAC,
						Role:        KeyRoleNotReplica,
						OutputBytes: derivedKeyBytes,
					}, payloadMAC[:])
				},
			); err != nil || allZero(payloadMAC[:]) {
				return errors.New("candidate volume-key borrow failed")
			}

			if err := session.Select(&RecoveryVolumeCandidate{}); err == nil {
				return errors.New("fabricated recovery candidate was selected")
			}
			if err := session.Select(firstCandidate); err != nil {
				return err
			}
			if err := session.Select(secondCandidate); err == nil {
				return errors.New("recovery selection was not single-use")
			}
			return nil
		},
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("newRecoveryCredentialSession: %v", err)
	}
	if owner == nil || !allTuplesDerivedBeforeCallback {
		if owner != nil {
			owner.Close()
		}
		t.Fatal("session callback ran before both sequential derivations or published no owner")
	}
	if !allZero(firstTransfer) || !allZero(secondTransfer) || !allZero(passwordAlias) {
		owner.Close()
		t.Fatal("recovery session retained transferred candidate or factor bytes")
	}
	if owner.Metadata().Suite != first.Suite {
		owner.Close()
		t.Fatalf("selected owner suite = %#04x; want %#04x", owner.Metadata().Suite, first.Suite)
	}
	var selectedKey [derivedKeyBytes]byte
	if err := owner.WithKeys(context.Background(), func(keys *BorrowedKeys) error {
		return keys.CopyVolumeKey(selectedKey[:])
	}); err != nil || !bytes.Equal(selectedKey[:], bytes.Repeat([]byte{0x5a}, derivedKeyBytes)) {
		owner.Close()
		t.Fatal("selected owner did not retain the exact bound candidate key")
	}
	owner.Close()
	if retained == nil || selected == nil {
		t.Fatal("session callback did not expose its bounded handles")
	}
	expiredCalls := 0
	if err := retained.WithTupleKeys(
		context.Background(),
		0,
		KeyRolePrimary,
		func(*ReaderKeys) error {
			expiredCalls++
			return nil
		},
	); err == nil || expiredCalls != 0 {
		t.Fatal("expired recovery session invoked a tuple callback")
	}
	if _, err := retained.SameVolumeKey(selected, selected); err == nil {
		t.Fatal("expired recovery candidate remained comparable")
	}
	for i, alias := range probe.reader.ownedAliases {
		if !allZero(alias) {
			t.Fatalf("recovery session material alias %d survived owner close", i)
		}
	}
}

func TestRecoveryCredentialSessionClearsBoundCandidatesOnEveryExit(t *testing.T) {
	tests := []struct {
		name      string
		exit      func(context.CancelFunc) error
		wantPanic any
		wantOwner bool
	}{
		{name: "success", exit: func(context.CancelFunc) error { return nil }, wantOwner: true},
		{name: "callback error", exit: func(context.CancelFunc) error {
			return errors.New("recovery session callback marker")
		}},
		{name: "cancellation", exit: func(cancel context.CancelFunc) error {
			cancel()
			return nil
		}},
		{name: "panic", exit: func(context.CancelFunc) error {
			panic("recovery session panic marker")
		}, wantPanic: "recovery session panic marker"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			factors := pipelineRequest(t, SuiteStandard1).Factors
			passwordAlias := factors.Password
			probe := newRecoveryCredentialProbe()
			transfer := bytes.Repeat([]byte{0x6b}, derivedKeyBytes)
			var candidateAlias []byte
			var retained *RecoverySession
			var candidate *RecoveryVolumeCandidate
			var owner *Owner
			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				owner, err = newRecoveryCredentialSession(
					ctx,
					&RecoveryCredentialRequest{
						Factors: factors,
						Tuples: []RecoveryCredentialTuple{
							recoveryCredentialTuple(t, SuiteStandard1, factors, 0x31),
						},
					},
					probe.reader.admit,
					func(session *RecoverySession) error {
						retained = session
						var bindErr error
						candidate, bindErr = session.BindCandidate(ctx, 0, transfer)
						if bindErr != nil {
							return bindErr
						}
						candidateAlias = candidate.state.volumeKey.secret.Bytes()
						if selectErr := session.Select(candidate); selectErr != nil {
							return selectErr
						}
						return test.exit(cancel)
					},
					probe.seams(),
				)
			}()
			if recovered != test.wantPanic {
				if owner != nil {
					owner.Close()
				}
				t.Fatalf("recovered panic = %#v; want %#v", recovered, test.wantPanic)
			}
			if (owner != nil) != test.wantOwner ||
				(test.wantPanic == nil && test.wantOwner == (err != nil)) {
				if owner != nil {
					owner.Close()
				}
				t.Fatalf("owner/error = %v/%v; want owner=%t", owner, err, test.wantOwner)
			}
			if owner != nil {
				owner.Close()
			}
			if !allZero(passwordAlias) || !allZero(transfer) || !allZero(candidateAlias) {
				t.Fatal("session exit retained factor, transfer, or bound candidate bytes")
			}
			if retained == nil || candidate == nil {
				t.Fatal("session callback did not bind a candidate")
			}
			if _, compareErr := retained.SameVolumeKey(candidate, candidate); compareErr == nil {
				t.Fatal("session exit left the candidate handle live")
			}
			for i, alias := range probe.reader.ownedAliases {
				if !allZero(alias) {
					t.Fatalf("session exit retained derived alias %d", i)
				}
			}
		})
	}
}

func TestRecoverySessionTeardownWaitsForActiveReaderCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		factors := pipelineRequest(t, SuiteStandard1).Factors
		tuple := recoveryCredentialTuple(t, SuiteStandard1, factors, 0x31)
		probe := newRecoveryCredentialProbe()
		request := KeyRequest{
			Label:       KeyLabelCredentialWrapMAC,
			Role:        KeyRolePrimary,
			OutputBytes: derivedKeyBytes,
		}
		borrowEntered := make(chan struct{})
		releaseBorrow := make(chan struct{})
		borrowReleased := false
		release := func() {
			if !borrowReleased {
				close(releaseBorrow)
				borrowReleased = true
			}
		}
		defer release()
		borrowObservation := make(chan struct {
			key [derivedKeyBytes]byte
			err error
		}, 1)
		borrowDone := make(chan error, 1)
		sessionReady := make(chan *RecoverySession, 1)
		operationDone := make(chan struct {
			owner *Owner
			err   error
		}, 1)
		var beforeClose [derivedKeyBytes]byte
		var retainedKeys *ReaderKeys

		go func() {
			owner, err := newRecoveryCredentialSession(
				context.Background(),
				&RecoveryCredentialRequest{
					Factors: factors,
					Tuples:  []RecoveryCredentialTuple{tuple},
				},
				probe.reader.admit,
				func(session *RecoverySession) error {
					sessionReady <- session
					go func() {
						borrowDone <- session.WithTupleKeys(
							context.Background(),
							0,
							KeyRolePrimary,
							func(keys *ReaderKeys) error {
								retainedKeys = keys
								initialErr := keys.CopyKey(request, beforeClose[:])
								close(borrowEntered)
								<-releaseBorrow

								observation := struct {
									key [derivedKeyBytes]byte
									err error
								}{err: initialErr}
								if observation.err == nil {
									observation.err = keys.CopyKey(request, observation.key[:])
								}
								borrowObservation <- observation
								return observation.err
							},
						)
					}()
					<-borrowEntered
					return errors.New("TEST ONLY recovery callback failure")
				},
				probe.seams(),
			)
			operationDone <- struct {
				owner *Owner
				err   error
			}{owner: owner, err: err}
		}()

		session := <-sessionReady
		<-borrowEntered
		if allZero(beforeClose[:]) {
			t.Fatal("active recovery callback received an empty credential key")
		}

		// Wait until teardown and the active callback are both durably blocked.
		// A correct teardown cannot complete while the callback still owns its
		// scoped ReaderKeys borrow.
		synctest.Wait()
		select {
		case <-operationDone:
			t.Fatal("recovery teardown completed while a reader callback was active")
		default:
		}

		lateCallbackCalls := 0
		err := session.WithTupleKeys(
			context.Background(),
			0,
			KeyRolePrimary,
			func(*ReaderKeys) error {
				lateCallbackCalls++
				return nil
			},
		)
		requireOwnerCode(t, err, OwnerErrorClosed)
		if lateCallbackCalls != 0 {
			t.Fatal("recovery teardown admitted a new reader callback")
		}

		release()
		observation := <-borrowObservation
		if observation.err != nil {
			t.Fatalf("active recovery callback lost its key during teardown: %v", observation.err)
		}
		if !bytes.Equal(observation.key[:], beforeClose[:]) {
			t.Fatal("active recovery callback observed changed key material during teardown")
		}
		if err := <-borrowDone; err != nil {
			t.Fatalf("active recovery borrow failed after release: %v", err)
		}
		result := <-operationDone
		if result.owner != nil {
			result.owner.Close()
			t.Fatal("callback failure published a recovery owner")
		}
		requirePipelineCode(t, result.err, PipelineErrorCallback, PipelineStageCallback)
		requireOwnerCode(
			t,
			retainedKeys.CopyKey(request, make([]byte, derivedKeyBytes)),
			OwnerErrorBorrowExpired,
		)
		for index, alias := range probe.reader.ownedAliases {
			if !allZero(alias) {
				t.Fatalf("recovery teardown retained derived alias %d", index)
			}
		}
	})
}

func TestD1RecoveryCredentialSessionConsumesOwnedInputSequentially(t *testing.T) {
	probe := newRecoveryCredentialProbe()
	var retainedInput *CredentialInputNormal
	var retainedSession *RecoverySession
	var inputAlias []byte
	allTuplesReady := false

	err := withD1NormalTestInput(t, func(
		normal *CredentialInputNormal,
		factors *ValidatedFactors,
	) error {
		retainedInput = normal
		inputAlias = normal.secret.Bytes()
		tuples := []RecoveryCredentialTuple{
			d1RecoveryCredentialTuple(t, factors, 0x31),
			d1RecoveryCredentialTuple(t, factors, 0x42),
		}
		// A D1 recovery session receives the already-owned normal input and the
		// same validated-factor borrow. Closing the password makes rebuilding a
		// second canonical transcript impossible while preserving factor metadata.
		factors.password.Close()

		owner, sessionErr := newD1RecoveryCredentialSession(
			context.Background(),
			normal,
			factors,
			tuples,
			probe.reader.admit,
			func(session *RecoverySession) error {
				retainedSession = session
				allTuplesReady = probe.reader.admit.calls == 2 &&
					probe.reader.kdfCalls == 2 &&
					len(session.state.readers) == 2
				for index := range 2 {
					var wrapMAC [derivedKeyBytes]byte
					if err := session.WithTupleKeys(
						context.Background(),
						index,
						KeyRolePrimary,
						func(keys *ReaderKeys) error {
							return keys.CopyKey(KeyRequest{
								Label:       KeyLabelCredentialWrapMAC,
								Role:        KeyRolePrimary,
								OutputBytes: derivedKeyBytes,
							}, wrapMAC[:])
						},
					); err != nil || allZero(wrapMAC[:]) {
						return errors.New("D1 recovery tuple was not live inside the callback")
					}
				}
				return nil
			},
			probe.seams(),
		)
		if owner != nil {
			owner.Close()
			return errors.New("unselected D1 recovery session published an owner")
		}
		return sessionErr
	})
	if err != nil {
		t.Fatalf("newD1RecoveryCredentialSession: %v", err)
	}
	if !allTuplesReady || retainedSession == nil || retainedInput == nil ||
		retainedInput.secret != nil {
		t.Fatal("D1 recovery session did not consume one owned input before lending two tuples")
	}
	if probe.reader.admit.calls != 2 || probe.reader.kdfCalls != 2 ||
		probe.maxActiveKDF != 1 || len(probe.kdfSalts) != 2 ||
		!bytes.Equal(probe.kdfSalts[0], bytes.Repeat([]byte{0x31}, kdfSaltBytes)) ||
		!bytes.Equal(probe.kdfSalts[1], bytes.Repeat([]byte{0x42}, kdfSaltBytes)) {
		t.Fatalf(
			"D1 admission/KDF/max-active/salts = %d/%d/%d/%x; want 2/2/1/[31,42]",
			probe.reader.admit.calls,
			probe.reader.kdfCalls,
			probe.maxActiveKDF,
			probe.kdfSalts,
		)
	}
	if len(probe.kdfInputs) != 2 || len(probe.kdfSnapshots) != 2 ||
		len(inputAlias) != credentialInputNormalBytes ||
		&probe.kdfInputs[0][0] != &inputAlias[0] ||
		&probe.kdfInputs[1][0] != &inputAlias[0] ||
		!bytes.Equal(probe.kdfSnapshots[0], probe.kdfSnapshots[1]) ||
		allZero(probe.kdfSnapshots[0]) {
		t.Fatal("D1 recovery KDFs did not sequentially borrow the one supplied normal input")
	}
	assertD1RecoverySessionExpired(t, retainedSession)
	assertD1RecoveryProbeCleared(t, probe, inputAlias)
}

func TestD1RecoveryCredentialSessionClosesFailureCancellationAndBounds(t *testing.T) {
	t.Run("callback error", func(t *testing.T) {
		probe := newRecoveryCredentialProbe()
		var retained *RecoverySession
		var inputAlias []byte
		err := withD1NormalTestInput(t, func(
			normal *CredentialInputNormal,
			factors *ValidatedFactors,
		) error {
			inputAlias = normal.secret.Bytes()
			factors.password.Close()
			owner, sessionErr := newD1RecoveryCredentialSession(
				context.Background(),
				normal,
				factors,
				[]RecoveryCredentialTuple{
					d1RecoveryCredentialTuple(t, factors, 0x51),
					d1RecoveryCredentialTuple(t, factors, 0x62),
				},
				probe.reader.admit,
				func(session *RecoverySession) error {
					retained = session
					return errors.New("TEST ONLY D1 recovery callback failure")
				},
				probe.seams(),
			)
			if owner != nil {
				owner.Close()
				t.Fatal("failed D1 recovery callback published an owner")
			}
			return sessionErr
		})
		requirePipelineCode(t, err, PipelineErrorCallback, PipelineStageCallback)
		if retained == nil || probe.reader.kdfCalls != 2 || probe.maxActiveKDF != 1 {
			t.Fatal("D1 recovery callback failure did not follow the bounded sequential session path")
		}
		assertD1RecoverySessionExpired(t, retained)
		assertD1RecoveryProbeCleared(t, probe, inputAlias)
	})

	t.Run("cancel before second KDF", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		probe := newRecoveryCredentialProbe()
		seams := probe.seams()
		beforeKDFCalls := 0
		seams.beforeKDF = func() {
			beforeKDFCalls++
			if beforeKDFCalls == 2 {
				cancel()
			}
		}
		callbackCalls := 0
		var inputAlias []byte
		err := withD1NormalTestInput(t, func(
			normal *CredentialInputNormal,
			factors *ValidatedFactors,
		) error {
			inputAlias = normal.secret.Bytes()
			factors.password.Close()
			owner, sessionErr := newD1RecoveryCredentialSession(
				ctx,
				normal,
				factors,
				[]RecoveryCredentialTuple{
					d1RecoveryCredentialTuple(t, factors, 0x71),
					d1RecoveryCredentialTuple(t, factors, 0x82),
				},
				probe.reader.admit,
				func(*RecoverySession) error {
					callbackCalls++
					return nil
				},
				seams,
			)
			if owner != nil {
				owner.Close()
				t.Fatal("cancelled D1 recovery session published an owner")
			}
			return sessionErr
		})
		requirePipelineCode(t, err, PipelineErrorCancelled, PipelineStageKDF)
		if beforeKDFCalls != 2 || probe.reader.kdfCalls != 1 ||
			probe.maxActiveKDF != 1 || callbackCalls != 0 {
			t.Fatalf(
				"cancelled D1 sequence = before %d, KDF %d, max-active %d, callback %d; want 2/1/1/0",
				beforeKDFCalls,
				probe.reader.kdfCalls,
				probe.maxActiveKDF,
				callbackCalls,
			)
		}
		assertD1RecoveryProbeCleared(t, probe, inputAlias)
	})

	t.Run("third tuple rejected before KDF", func(t *testing.T) {
		probe := newRecoveryCredentialProbe()
		callbackCalls := 0
		var inputAlias []byte
		err := withD1NormalTestInput(t, func(
			normal *CredentialInputNormal,
			factors *ValidatedFactors,
		) error {
			inputAlias = normal.secret.Bytes()
			factors.password.Close()
			owner, sessionErr := newD1RecoveryCredentialSession(
				context.Background(),
				normal,
				factors,
				[]RecoveryCredentialTuple{
					d1RecoveryCredentialTuple(t, factors, 0x91),
					d1RecoveryCredentialTuple(t, factors, 0xa2),
					d1RecoveryCredentialTuple(t, factors, 0xb3),
				},
				probe.reader.admit,
				func(*RecoverySession) error {
					callbackCalls++
					return nil
				},
				probe.seams(),
			)
			if owner != nil {
				owner.Close()
				t.Fatal("unbounded D1 recovery tuple set published an owner")
			}
			return sessionErr
		})
		requirePipelineCode(t, err, PipelineErrorSchedule, PipelineStageSchedule)
		if probe.reader.admit.calls != 0 || probe.reader.kdfCalls != 0 || callbackCalls != 0 {
			t.Fatalf(
				"third D1 tuple reached admission/KDF/callback = %d/%d/%d",
				probe.reader.admit.calls,
				probe.reader.kdfCalls,
				callbackCalls,
			)
		}
		assertD1RecoveryProbeCleared(t, probe, inputAlias)
	})

	t.Run("non-paranoid tuple rejected before KDF", func(t *testing.T) {
		probe := newRecoveryCredentialProbe()
		callbackCalls := 0
		var inputAlias []byte
		err := withD1NormalTestInput(t, func(
			normal *CredentialInputNormal,
			factors *ValidatedFactors,
		) error {
			inputAlias = normal.secret.Bytes()
			factors.password.Close()
			tuple := d1RecoveryCredentialTuple(t, factors, 0xb4)
			profile, profileErr := fixedProfileForSuite(SuiteStandard1)
			if profileErr != nil {
				t.Fatalf("load structurally valid non-D1 profile: %v", profileErr)
			}
			tuple.Suite = SuiteStandard1
			tuple.ProfileID = profile.ID
			owner, sessionErr := newD1RecoveryCredentialSession(
				context.Background(),
				normal,
				factors,
				[]RecoveryCredentialTuple{tuple},
				probe.reader.admit,
				func(*RecoverySession) error {
					callbackCalls++
					return nil
				},
				probe.seams(),
			)
			if owner != nil {
				owner.Close()
				t.Fatal("non-D1 recovery tuple published an owner")
			}
			return sessionErr
		})
		requirePipelineCode(t, err, PipelineErrorSchedule, PipelineStageSchedule)
		if probe.reader.admit.calls != 0 || probe.reader.kdfCalls != 0 || callbackCalls != 0 {
			t.Fatalf(
				"non-D1 tuple reached admission/KDF/callback = %d/%d/%d",
				probe.reader.admit.calls,
				probe.reader.kdfCalls,
				callbackCalls,
			)
		}
		assertD1RecoveryProbeCleared(t, probe, inputAlias)
	})

	t.Run("tuple factor mismatch rejected before KDF", func(t *testing.T) {
		probe := newRecoveryCredentialProbe()
		callbackCalls := 0
		var inputAlias []byte
		err := withD1NormalTestInput(t, func(
			normal *CredentialInputNormal,
			factors *ValidatedFactors,
		) error {
			inputAlias = normal.secret.Bytes()
			factors.password.Close()
			tuple := d1RecoveryCredentialTuple(t, factors, 0xc4)
			tuple.CredentialMode = CredentialModePasswordAndKeyfiles
			tuple.KeyfileMode = KeyfileModeOrdered
			tuple.KeyfileCount = 1
			owner, sessionErr := newD1RecoveryCredentialSession(
				context.Background(),
				normal,
				factors,
				[]RecoveryCredentialTuple{tuple},
				probe.reader.admit,
				func(*RecoverySession) error {
					callbackCalls++
					return nil
				},
				probe.seams(),
			)
			if owner != nil {
				owner.Close()
				t.Fatal("factor-mismatched D1 recovery tuple published an owner")
			}
			return sessionErr
		})
		requirePipelineCode(t, err, PipelineErrorFactors, PipelineStageFactors)
		if probe.reader.admit.calls != 0 || probe.reader.kdfCalls != 0 || callbackCalls != 0 {
			t.Fatalf(
				"factor-mismatched D1 tuple reached admission/KDF/callback = %d/%d/%d",
				probe.reader.admit.calls,
				probe.reader.kdfCalls,
				callbackCalls,
			)
		}
		assertD1RecoveryProbeCleared(t, probe, inputAlias)
	})
}

func d1RecoveryCredentialTuple(
	t *testing.T,
	factors *ValidatedFactors,
	marker byte,
) RecoveryCredentialTuple {
	t.Helper()
	profile, err := fixedProfileForSuite(SuiteParanoid1)
	if err != nil {
		t.Fatalf("load D1 inner profile: %v", err)
	}
	return RecoveryCredentialTuple{
		Suite:          SuiteParanoid1,
		ProfileID:      profile.ID,
		CredentialMode: factors.mode,
		KeyfileMode:    factors.keyfileMode,
		KeyfileCount:   uint16(len(factors.descriptors)), //nolint:gosec // Validated factors are bounded to maxKeyfiles.
		ArgonSalt:      bytes.Repeat([]byte{marker}, kdfSaltBytes),
		VolumeID:       bytes.Repeat([]byte{marker + 0x20}, scheduleVolumeIDBytes),
	}
}

func assertD1RecoverySessionExpired(t *testing.T, session *RecoverySession) {
	t.Helper()
	callbackCalls := 0
	err := session.WithTupleKeys(
		context.Background(),
		0,
		KeyRolePrimary,
		func(*ReaderKeys) error {
			callbackCalls++
			return nil
		},
	)
	if err == nil || callbackCalls != 0 {
		t.Fatal("expired D1 recovery session invoked a tuple callback")
	}
}

func assertD1RecoveryProbeCleared(
	t *testing.T,
	probe *recoveryCredentialProbe,
	inputAlias []byte,
) {
	t.Helper()
	if len(inputAlias) != credentialInputNormalBytes || !allZero(inputAlias) {
		t.Fatal("D1 recovery session retained the supplied normal input")
	}
	for index, alias := range probe.kdfInputs {
		if !allZero(alias) {
			t.Fatalf("D1 recovery KDF input alias %d survived session exit", index)
		}
	}
	for index, alias := range probe.reader.providerData {
		if !allZero(alias) {
			t.Fatalf("D1 recovery provider alias %d survived session exit", index)
		}
	}
	for index, alias := range probe.reader.ownedAliases {
		if !allZero(alias) {
			t.Fatalf("D1 recovery owned alias %d survived session exit", index)
		}
	}
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

			owner, err := newRecoveryCredentialSession(
				context.Background(),
				&RecoveryCredentialRequest{
					Factors: factors,
					Tuples:  []RecoveryCredentialTuple{first, second},
				},
				probe.reader.admit,
				func(session *RecoverySession) error {
					for index := range 2 {
						probe.callbackOrder = append(probe.callbackOrder, index)
						if err := session.WithTupleKeys(context.Background(), index,
							KeyRolePrimary, func(*ReaderKeys) error { return nil }); err != nil {
							return err
						}
					}
					candidate, err := session.BindCandidate(context.Background(), 0, transfer)
					if err != nil {
						return err
					}
					return session.Select(candidate)
				},
				probe.seams(),
			)
			if err != nil {
				t.Fatalf("newRecoveryCredentialSession: %v", err)
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
				!slices.Equal(probe.callbackOrder, []int{0, 1}) {
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

func TestRecoveryAdmissionOccursAtEveryKDFBoundary(t *testing.T) {
	tests := []struct {
		name               string
		configureAdmission func(*recoveryCredentialProbe)
		cancelBeforeSecond bool
		cancelDuringSecond bool
		wantCode           PipelineErrorCode
		wantStage          PipelineStage
		wantAdmission      int
		wantKDF            int
		wantCallbacks      []int
		wantBoundaries     []int
		wantOwner          bool
	}{
		{
			name:               "each tuple obtains a fresh decision",
			configureAdmission: func(*recoveryCredentialProbe) {},
			wantAdmission:      2,
			wantKDF:            2,
			wantCallbacks:      []int{0, 1},
			wantBoundaries:     []int{0, 1},
			wantOwner:          true,
		},
		{
			name: "second decision refuses before its KDF",
			configureAdmission: func(probe *recoveryCredentialProbe) {
				probe.reader.admit.onCall = func() {
					if probe.reader.admit.calls == 2 {
						probe.reader.admit.result = KDFAdmissionDenied
					}
				}
			},
			wantCode:       PipelineErrorAdmission,
			wantStage:      PipelineStageAdmission,
			wantAdmission:  2,
			wantKDF:        1,
			wantCallbacks:  nil,
			wantBoundaries: []int{0, 1},
		},
		{
			name:               "cancellation before second decision",
			configureAdmission: func(*recoveryCredentialProbe) {},
			cancelBeforeSecond: true,
			wantCode:           PipelineErrorCancelled,
			wantStage:          PipelineStageKDF,
			wantAdmission:      1,
			wantKDF:            1,
			wantCallbacks:      nil,
			wantBoundaries:     []int{0, 1},
		},
		{
			name:               "cancellation during second key derivation",
			configureAdmission: func(*recoveryCredentialProbe) {},
			cancelDuringSecond: true,
			wantCode:           PipelineErrorCancelled,
			wantStage:          PipelineStageKeyDerivation,
			wantAdmission:      2,
			wantKDF:            2,
			wantCallbacks:      nil,
			wantBoundaries:     []int{0, 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			factors := pipelineRequest(t, SuiteStandard1).Factors
			passwordAlias := factors.Password
			request := &RecoveryCredentialRequest{
				Factors: factors,
				Tuples: []RecoveryCredentialTuple{
					recoveryCredentialTuple(t, SuiteStandard1, factors, 0x31),
					recoveryCredentialTuple(t, SuiteParanoid1, factors, 0x42),
				},
			}
			probe := newRecoveryCredentialProbe()
			test.configureAdmission(probe)
			boundaries := make([]int, 0, 2)
			seams := probe.seams()
			originalObserve := seams.observeCredentialMaterial
			materialCalls := 0
			seams.observeCredentialMaterial = func(material *keyMaterial) {
				originalObserve(material)
				materialCalls++
				if test.cancelDuringSecond && materialCalls == 2 {
					cancel()
				}
			}
			seams.beforeKDF = func() {
				boundaries = append(boundaries, probe.reader.admit.calls)
				if test.cancelBeforeSecond && len(boundaries) == 2 {
					cancel()
				}
			}
			var transfer []byte
			callbacks := make([]int, 0, 2)

			owner, err := newRecoveryCredentialSession(
				ctx,
				request,
				probe.reader.admit,
				func(session *RecoverySession) error {
					for index := range 2 {
						callbacks = append(callbacks, index)
						if err := session.WithTupleKeys(ctx, index,
							KeyRolePrimary, func(*ReaderKeys) error { return nil }); err != nil {
							return err
						}
					}
					transfer = bytes.Repeat([]byte{0x5a}, derivedKeyBytes)
					candidate, err := session.BindCandidate(ctx, 0, transfer)
					if err != nil {
						return err
					}
					return session.Select(candidate)
				},
				seams,
			)

			if test.wantCode == PipelineErrorCode(0) {
				if err != nil {
					if owner != nil {
						owner.Close()
					}
					t.Fatalf("newRecoveryCredentialSession: %v", err)
				}
			} else {
				requirePipelineCode(t, err, test.wantCode, test.wantStage)
			}
			if (owner != nil) != test.wantOwner {
				if owner != nil {
					owner.Close()
				}
				t.Fatalf("owner present = %t; want %t", owner != nil, test.wantOwner)
			}
			if owner != nil {
				owner.Close()
			}
			if probe.reader.admit.calls != test.wantAdmission ||
				probe.reader.kdfCalls != test.wantKDF ||
				!slices.Equal(callbacks, test.wantCallbacks) ||
				!slices.Equal(boundaries, test.wantBoundaries) {
				t.Fatalf(
					"admission/KDF/callbacks/boundaries = %d/%d/%v/%v; want %d/%d/%v/%v",
					probe.reader.admit.calls,
					probe.reader.kdfCalls,
					callbacks,
					boundaries,
					test.wantAdmission,
					test.wantKDF,
					test.wantCallbacks,
					test.wantBoundaries,
				)
			}
			if request.Factors != nil || request.Tuples != nil ||
				!allZero(passwordAlias) || !allZero(transfer) {
				t.Fatal("recovery admission path retained transferred credentials or candidate material")
			}
			for index, alias := range probe.reader.ownedAliases {
				if !allZero(alias) {
					t.Fatalf("recovery admission path retained derived alias %d", index)
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
			request.Tuples = append(
				request.Tuples,
				recoveryCredentialTuple(t, SuiteStandard1, request.Factors, 0x42),
				recoveryCredentialTuple(t, SuiteStandard1, request.Factors, 0x53),
			)
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
			owner, err := newRecoveryCredentialSession(
				context.Background(),
				request,
				probe.reader.admit,
				func(*RecoverySession) error {
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
				owner, err = newRecoveryCredentialSession(
					ctx,
					&RecoveryCredentialRequest{
						Factors: factors,
						Tuples: []RecoveryCredentialTuple{
							recoveryCredentialTuple(t, SuiteStandard1, factors, 0x31),
						},
					},
					probe.reader.admit,
					func(session *RecoverySession) error {
						candidate, bindErr := session.BindCandidate(ctx, 0, transfer)
						if bindErr != nil {
							return bindErr
						}
						if selectErr := session.Select(candidate); selectErr != nil {
							return selectErr
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
