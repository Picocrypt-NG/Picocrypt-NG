package pcv3credential

import (
	pcsecret "Picocrypt-NG/internal/secret"
	"context"
	"crypto/sha3"
	"encoding/binary"
)

const d1InnerRootDomain = "Picocrypt-NG/PCV3/D1C/inner/root\x00"

// d1InnerCredentialRoot gives an independently random I its own meaning before
// the unchanged inner credential schedule. The caller retains I; the returned
// credential root is uniquely owned and consumed by the normal key lifecycle.
func d1InnerCredentialRoot(inner []byte, profile D1Profile, extract hkdfExtractor) (*credentialRoot, error) {
	if len(inner) != derivedKeyBytes || profile.Suite() == 0 || extract == nil {
		return nil, newOwnerError(OwnerErrorInvalidRequest)
	}
	contextBytes := binary.BigEndian.AppendUint16([]byte(d1InnerRootDomain), uint16(profile))
	salt := sha3.Sum256(contextBytes)
	returned, err := extract(inner, salt[:])
	owned, err := ownProviderResult(returned, err, profile.Suite(), -1, ScheduleErrorExtract)
	if err != nil {
		return nil, err
	}
	return &credentialRoot{secret: owned}, nil
}

// WithD1InnerCredentialOwner consumes independently random I and V. It runs no
// Argon2 operation; the two independently salted bootstraps protect I.
func WithD1InnerCredentialOwner(
	ctx context.Context,
	innerTransfer []byte,
	profile D1Profile,
	factors *ValidatedFactors,
	innerSalt [kdfSaltBytes]byte,
	volumeID [scheduleVolumeIDBytes]byte,
	volumeTransfer []byte,
	callback func(*Owner) error,
) error {
	defer pcsecret.SecureZero(innerTransfer)
	defer pcsecret.SecureZero(volumeTransfer)
	if ctx == nil || factors == nil || callback == nil || len(volumeTransfer) != derivedKeyBytes || ctx.Err() != nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	root, err := d1InnerCredentialRoot(innerTransfer, profile, defaultHKDFExtract)
	if err != nil {
		return err
	}
	defer root.close()
	schedule, err := fullReaderSchedule(profile.Suite())
	if err != nil {
		return err
	}
	material, err := deriveKeyMaterial(schedule, root, &volumeKey{secret: pcsecret.SecretFrom(volumeTransfer)}, volumeID[:])
	if err != nil {
		return err
	}
	metadata := OwnerMetadata{Suite: profile.Suite(), ExpectedPolicy: factors.expectedPolicy, CredentialMode: factors.mode, KeyfileMode: factors.keyfileMode, KeyfileCount: uint16(len(factors.descriptors)), ArgonSalt: innerSalt, VolumeID: volumeID} //nolint:gosec // Validated factors have at most 64 descriptors.
	owner, err := newOwner(metadata, material)
	if err != nil {
		return err
	}
	defer owner.Close()
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}
	if err := callback(owner); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}
	return nil
}

// WithD1DerivedRecoveryCredentialSession consumes a copy of authenticated I,
// admits only the derived-root marker and the authenticated outer profile's
// suite, and reuses the existing bounded candidate/selection lifecycle.
func WithD1DerivedRecoveryCredentialSession(
	ctx context.Context,
	innerTransfer []byte,
	profile D1Profile,
	factors *ValidatedFactors,
	tuples []RecoveryCredentialTuple,
	callback func(*RecoverySession) error,
) (*Owner, error) {
	defer pcsecret.SecureZero(innerTransfer)
	if ctx == nil || factors == nil || callback == nil || profile.Suite() == 0 || len(tuples) < 1 || len(tuples) > maxRecoveryCredentialTuples {
		return nil, newOwnerError(OwnerErrorInvalidRequest)
	}
	snapshots := make([]recoveryCredentialTupleSnapshot, len(tuples))
	for index, tuple := range tuples {
		if tuple.Suite != profile.Suite() || tuple.ProfileID != D1DerivedRootProfileID || len(tuple.ArgonSalt) != kdfSaltBytes || len(tuple.VolumeID) != scheduleVolumeIDBytes || !validCredentialTuple(tuple.CredentialMode, tuple.KeyfileMode, tuple.KeyfileCount) {
			return nil, newOwnerError(OwnerErrorInvalidRequest)
		}
		snapshot := recoveryCredentialTupleSnapshot{suite: tuple.Suite, profileID: tuple.ProfileID, credentialMode: tuple.CredentialMode, keyfileMode: tuple.KeyfileMode, keyfileCount: tuple.KeyfileCount}
		copy(snapshot.argonSalt[:], tuple.ArgonSalt)
		copy(snapshot.volumeID[:], tuple.VolumeID)
		for previous := range index {
			if snapshots[previous] == snapshot {
				return nil, newOwnerError(OwnerErrorInvalidRequest)
			}
		}
		snapshots[index] = snapshot
	}
	if err := validateRecoveryTupleFactors(snapshots, factors); err != nil {
		return nil, err
	}
	session := newRecoverySession(ctx)
	defer session.close()
	for index, tuple := range snapshots {
		if ctx.Err() != nil {
			return nil, newOwnerError(OwnerErrorCancelled)
		}
		root, err := d1InnerCredentialRoot(innerTransfer, profile, defaultHKDFExtract)
		if err != nil {
			return nil, err
		}
		schedule, err := fullReaderSchedule(tuple.suite)
		if err != nil {
			root.close()
			return nil, err
		}
		metadata := OwnerMetadata{Suite: tuple.suite, ExpectedPolicy: factors.expectedPolicy, CredentialMode: factors.mode, KeyfileMode: factors.keyfileMode, KeyfileCount: tuple.keyfileCount, ArgonSalt: tuple.argonSalt, VolumeID: tuple.volumeID}
		reader, err := newReaderCredentialRoot(ctx, root, schedule, metadata, readerCredentialSeams{extract: defaultHKDFExtract, expand: defaultHKDFExpand})
		if err != nil {
			return nil, err
		}
		if _, err := session.retainReader(index, reader); err != nil {
			reader.close()
			return nil, err
		}
	}
	return session.finish(ctx, callback)
}
