package pcv3credential

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// These replace the obsolete third-Argon tests. Random I is now consumed by
// an HKDF credential route; the lifetime, no-owner-on-failure, bounded tuple,
// policy and cancellation contracts remain production requirements.
func TestD1DerivedInnerOwnerFixedSuiteAndCallbackLifetime(t *testing.T) {
	for _, profile := range []D1Profile{D1ProfileStandard, D1ProfileParanoid} {
		inner := bytes.Repeat([]byte{0x31}, 32)
		volume := bytes.Repeat([]byte{0x51}, 32)
		var retained *Owner
		var borrow *BorrowedKeys
		var aliases map[string][]byte
		err := WithD1InnerCredentialOwner(context.Background(), inner, profile, d1InnerTestFactors(), [16]byte{1}, [32]byte{2}, volume, func(owner *Owner) error {
			retained = owner
			aliases = d1NormalOwnerAliases(owner)
			metadata := owner.Metadata()
			if metadata.Suite != profile.Suite() || metadata.ArgonSalt != [16]byte{1} || metadata.VolumeID != [32]byte{2} || metadata.CredentialMode != CredentialModePasswordOnly {
				t.Fatal("derived inner lost its fixed suite or public factor metadata")
			}
			return owner.WithKeys(context.Background(), func(keys *BorrowedKeys) error {
				borrow = keys
				var key [32]byte
				if err := keys.CopyVolumeKey(key[:]); err != nil {
					return err
				}
				if !bytes.Equal(key[:], bytes.Repeat([]byte{0x51}, 32)) {
					t.Fatal("inner VolumeKey changed with credential root redesign")
				}
				return keys.CopyKey(KeyRequest{Label: KeyLabelCredentialWrapMAC, Role: KeyRolePrimary, OutputBytes: 32}, key[:])
			})
		})
		if err != nil || retained == nil || borrow == nil {
			t.Fatalf("derived inner owner: %v", err)
		}
		if !allZero(inner) || !allZero(volume) {
			t.Fatal("derived inner retained transferred I or V")
		}
		requireOwnerAliasesZero(t, aliases)
		if err := borrow.CopyVolumeKey(make([]byte, 32)); err == nil {
			t.Fatal("inner key borrow survived callback")
		}
		if err := retained.WithKeys(context.Background(), func(*BorrowedKeys) error { return nil }); err == nil {
			t.Fatal("inner owner survived callback")
		}
	}
}

func TestD1DerivedInnerOwnerClearsFailureCancellationAndPanic(t *testing.T) {
	for _, exit := range []string{"callback error", "cancel before", "cancel callback", "panic"} {
		t.Run(exit, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if exit == "cancel before" {
				cancel()
			}
			inner, volume := bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x51}, 32)
			var aliases map[string][]byte
			calls := 0
			callbackErr := errors.New("TEST ONLY inner callback failure")
			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				err = WithD1InnerCredentialOwner(ctx, inner, D1ProfileParanoid, d1InnerTestFactors(), [16]byte{}, [32]byte{}, volume, func(owner *Owner) error {
					calls++
					aliases = d1NormalOwnerAliases(owner)
					if exit == "panic" {
						panic(callbackErr)
					}
					if exit == "cancel callback" {
						cancel()
						return nil
					}
					return callbackErr
				})
			}()
			if exit == "panic" {
				if recovered != callbackErr { //nolint:errorlint // Panic payload must retain exact identity; wrapping it is a regression.
					t.Fatal("inner callback panic was swallowed")
				}
			} else if err == nil || recovered != nil {
				t.Fatalf("inner failure lost: err=%v panic=%v", err, recovered)
			}
			if (exit == "cancel before") != (calls == 0) {
				t.Fatal("cancelled inner owner invoked callback")
			}
			if !allZero(inner) || !allZero(volume) {
				t.Fatal("inner failure retained I or V")
			}
			if aliases != nil {
				requireOwnerAliasesZero(t, aliases)
			}
		})
	}
}

func TestD1DerivedRecoverySessionConsumesRootAndExpiresAllCandidates(t *testing.T) {
	for _, profile := range []D1Profile{D1ProfileStandard, D1ProfileParanoid} {
		factors := d1InnerTestFactors()
		inner := bytes.Repeat([]byte{0x35}, 32)
		tuples := []RecoveryCredentialTuple{d1InnerTestTuple(profile, factors, 0x31), d1InnerTestTuple(profile, factors, 0x42)}
		var retained *RecoverySession
		var candidate *RecoveryVolumeCandidate
		var aliases [][]byte
		owner, err := WithD1DerivedRecoveryCredentialSession(context.Background(), inner, profile, factors, tuples, func(session *RecoverySession) error {
			retained = session
			for index, reader := range session.state.readers {
				aliases = append(aliases, d1MaterialAliases(reader.state.material)...)
				var wrapMAC [32]byte
				if err := session.WithTupleKeys(context.Background(), index, KeyRolePrimary, func(keys *ReaderKeys) error {
					return keys.CopyKey(KeyRequest{Label: KeyLabelCredentialWrapMAC, Role: KeyRolePrimary, OutputBytes: 32}, wrapMAC[:])
				}); err != nil || allZero(wrapMAC[:]) {
					return errors.New("derived tuple unavailable")
				}
			}
			var err error
			candidate, err = session.BindCandidate(context.Background(), 0, bytes.Repeat([]byte{0x71}, 32))
			if err != nil {
				return err
			}
			return session.Select(candidate)
		})
		if err != nil || owner == nil {
			t.Fatalf("select derived recovery owner: %v", err)
		}
		if !allZero(inner) {
			t.Fatal("recovery retained transferred I")
		}
		ownerAliases := d1NormalOwnerAliases(owner)
		owner.Close()
		for _, alias := range aliases {
			if !allZero(alias) {
				t.Fatal("derived reader retained credential material")
			}
		}
		requireOwnerAliasesZero(t, ownerAliases)
		if err := retained.WithTupleKeys(context.Background(), 0, KeyRolePrimary, func(*ReaderKeys) error { return nil }); err == nil {
			t.Fatal("recovery session survived callback")
		}
		if err := retained.Select(candidate); err == nil {
			t.Fatal("derived volume candidate survived session")
		}
	}
}

func TestD1DerivedRecoveryClearsFailuresAndRejectsNonDerivedTuples(t *testing.T) {
	for _, cause := range []string{"callback error", "cancel before", "cancel callback", "panic", "third tuple", "duplicate tuple", "suite mismatch", "old Argon profile", "factor mismatch", "unknown profile", "short root"} {
		t.Run(cause, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			profile := D1ProfileParanoid
			factors := d1InnerTestFactors()
			inner := bytes.Repeat([]byte{0x35}, 32)
			tuples := []RecoveryCredentialTuple{d1InnerTestTuple(profile, factors, 0x31), d1InnerTestTuple(profile, factors, 0x42)}
			switch cause {
			case "cancel before":
				cancel()
			case "third tuple":
				tuples = append(tuples, d1InnerTestTuple(profile, factors, 0x53))
			case "duplicate tuple":
				tuples[1] = tuples[0]
			case "suite mismatch":
				tuples[0].Suite = SuiteStandard1
			case "old Argon profile":
				tuples[0].ProfileID = 2
			case "factor mismatch":
				tuples[0].CredentialMode = CredentialModePasswordAndKeyfiles
				tuples[0].KeyfileMode = KeyfileModeOrdered
				tuples[0].KeyfileCount = 1
			case "unknown profile":
				profile = 0x0103
			case "short root":
				inner = inner[:31]
			}
			var retained *RecoverySession
			var aliases [][]byte
			var owner *Owner
			var err error
			var recovered any
			marker := errors.New("TEST ONLY recovery callback failure")
			func() {
				defer func() { recovered = recover() }()
				owner, err = WithD1DerivedRecoveryCredentialSession(ctx, inner, profile, factors, tuples, func(session *RecoverySession) error {
					retained = session
					for _, reader := range session.state.readers {
						aliases = append(aliases, d1MaterialAliases(reader.state.material)...)
					}
					if cause == "panic" {
						panic(marker)
					}
					if cause == "cancel callback" {
						cancel()
						return nil
					}
					return marker
				})
			}()
			if owner != nil {
				owner.Close()
				t.Fatal("failed derived recovery published owner")
			}
			if cause == "panic" {
				if recovered != marker { //nolint:errorlint // Panic payload must retain exact identity; wrapping it is a regression.
					t.Fatal("derived recovery panic swallowed")
				}
			} else if err == nil || recovered != nil {
				t.Fatalf("derived recovery failure lost: err=%v panic=%v", err, recovered)
			}
			if !allZero(inner) {
				t.Fatal("failed recovery retained I")
			}
			for _, alias := range aliases {
				if !allZero(alias) {
					t.Fatal("failed recovery retained derived material")
				}
			}
			if retained != nil {
				if err := retained.WithTupleKeys(context.Background(), 0, KeyRolePrimary, func(*ReaderKeys) error { return nil }); err == nil {
					t.Fatal("failed recovery retained active session")
				}
			}
		})
	}
}

func d1InnerTestFactors() *ValidatedFactors {
	return &ValidatedFactors{mode: CredentialModePasswordOnly, keyfileMode: KeyfileModeNone, expectedPolicy: FactorPolicyPasswordOnly}
}

func d1InnerTestTuple(profile D1Profile, factors *ValidatedFactors, marker byte) RecoveryCredentialTuple {
	return RecoveryCredentialTuple{Suite: profile.Suite(), ProfileID: D1DerivedRootProfileID, CredentialMode: factors.mode, KeyfileMode: factors.keyfileMode, KeyfileCount: uint16(len(factors.descriptors)), ArgonSalt: bytes.Repeat([]byte{marker}, 16), VolumeID: bytes.Repeat([]byte{marker + 0x20}, 32)} //nolint:gosec // TEST ONLY bounded factors.
}

func d1MaterialAliases(material *keyMaterial) [][]byte {
	var aliases [][]byte
	if material.credentialRoot != nil && material.credentialRoot.secret != nil {
		aliases = append(aliases, material.credentialRoot.secret.Bytes())
	}
	if material.credentialPRK != nil && material.credentialPRK.secret != nil {
		aliases = append(aliases, material.credentialPRK.secret.Bytes())
	}
	for _, key := range material.keys {
		if key.secret != nil {
			aliases = append(aliases, key.secret.Bytes())
		}
	}
	return aliases
}
