package pcv3credential

import (
	"context"
	"errors"
)

const maxRecoveryCredentialTuples = 2

// RecoveryCredentialTuple is one structurally admitted public credential
// tuple. ArgonSalt and VolumeID are transferred with RecoveryCredentialRequest.
type RecoveryCredentialTuple struct {
	Suite          Suite
	ProfileID      uint8
	CredentialMode CredentialMode
	KeyfileMode    KeyfileMode
	KeyfileCount   uint16
	ArgonSalt      []byte
	VolumeID       []byte
}

// RecoveryCredentialRequest transfers one factor request and one or two
// already-bounded public tuples to WithRecoveryCredential.
type RecoveryCredentialRequest struct {
	Factors *FactorRequest
	Tuples  []RecoveryCredentialTuple
}

func (RecoveryCredentialRequest) String() string {
	return "pcv3credential.RecoveryCredentialRequest([REDACTED])"
}

func (RecoveryCredentialRequest) GoString() string {
	return "pcv3credential.RecoveryCredentialRequest([REDACTED])"
}

// Close releases a request that will not be transferred. It is nil-safe and
// idempotent.
func (request *RecoveryCredentialRequest) Close() error {
	if request == nil {
		return nil
	}
	factors := request.Factors
	request.Factors = nil
	request.Tuples = nil
	if factors == nil {
		return nil
	}
	return factors.Close()
}

type recoveryCredentialTupleSnapshot struct {
	suite          Suite
	profileID      uint8
	credentialMode CredentialMode
	keyfileMode    KeyfileMode
	keyfileCount   uint16
	argonSalt      [kdfSaltBytes]byte
	volumeID       [scheduleVolumeIDBytes]byte
}

// WithRecoveryCredential validates factors once and evaluates the complete
// bounded tuple set sequentially. At most one adopted Owner may escape after
// every tuple callback succeeds.
func WithRecoveryCredential(
	ctx context.Context,
	request *RecoveryCredentialRequest,
	admitter Admitter,
	callback func(int, *ReaderCredential) error,
) (*Owner, error) {
	return newRecoveryCredential(
		ctx,
		request,
		admitter,
		callback,
		readerCredentialSeams{
			derive:  deriveArgon2ID,
			extract: defaultHKDFExtract,
			expand:  defaultHKDFExpand,
		},
	)
}

func newRecoveryCredential(
	ctx context.Context,
	request *RecoveryCredentialRequest,
	admitter Admitter,
	callback func(int, *ReaderCredential) error,
	seams readerCredentialSeams,
) (*Owner, error) {
	if request == nil {
		return nil, newPipelineError(
			PipelineErrorInvalidRequest,
			PipelineStageRequest,
			0,
		)
	}

	factors := request.Factors
	request.Factors = nil
	tuples := request.Tuples
	request.Tuples = nil
	snapshots, ok := snapshotRecoveryCredentialTuples(tuples)
	if !ok {
		releaseFactorRequest(factors)
		return nil, newPipelineError(
			PipelineErrorSchedule,
			PipelineStageSchedule,
			0,
		)
	}
	suite := snapshots[0].suite
	if ctx == nil || admitter == nil || callback == nil ||
		seams.derive == nil || seams.extract == nil || seams.expand == nil {
		releaseFactorRequest(factors)
		return nil, newPipelineError(
			PipelineErrorInvalidRequest,
			PipelineStageRequest,
			suite,
		)
	}
	if ctx.Err() != nil {
		releaseFactorRequest(factors)
		return nil, newPipelineError(
			PipelineErrorCancelled,
			PipelineStageRequest,
			suite,
		)
	}

	var selected *Owner
	completed := false
	defer func() {
		if !completed && selected != nil {
			selected.Close()
		}
	}()

	factorErr := WithValidatedFactors(
		ctx,
		factors,
		func(validated *ValidatedFactors) error {
			for _, tuple := range snapshots {
				if !recoveryTupleMatchesFactors(tuple, validated) {
					return newPipelineError(
						PipelineErrorFactors,
						PipelineStageFactors,
						tuple.suite,
					)
				}
			}

			transcript, err := NewCanonicalTranscript(validated)
			if err != nil {
				return newPipelineError(
					PipelineErrorTranscript,
					PipelineStageTranscript,
					suite,
				)
			}
			defer transcript.Close()

			return withCredentialInputBorrow(
				transcript,
				func(input *credentialInputBorrow) error {
					for index, tuple := range snapshots {
						if ctx.Err() != nil {
							return newPipelineError(
								PipelineErrorCancelled,
								PipelineStageKDF,
								tuple.suite,
							)
						}
						schedule, err := fullReaderSchedule(tuple.suite)
						if err != nil {
							return newPipelineError(
								PipelineErrorSchedule,
								PipelineStageSchedule,
								tuple.suite,
							)
						}
						admitted, err := admitFixedProfile(ctx, tuple.suite, admitter)
						if err != nil {
							return err
						}
						if seams.beforeKDF != nil {
							seams.beforeKDF()
						}
						if ctx.Err() != nil {
							return newPipelineError(
								PipelineErrorCancelled,
								PipelineStageKDF,
								tuple.suite,
							)
						}

						var root *credentialRoot
						var deriveErr error
						if err := input.withInput(func(normalInput []byte) error {
							root, deriveErr = runCredentialKDFBorrowed(
								ctx,
								normalInput,
								tuple.argonSalt[:],
								tuple.suite,
								admitted,
								seams.derive,
							)
							return nil
						}); err != nil {
							return newPipelineError(
								PipelineErrorTranscript,
								PipelineStageTranscript,
								tuple.suite,
							)
						}
						if deriveErr != nil {
							return recoveryKDFPipelineError(deriveErr, tuple.suite)
						}

						metadata := OwnerMetadata{
							Suite:          tuple.suite,
							ExpectedPolicy: validated.expectedPolicy,
							CredentialMode: validated.mode,
							KeyfileMode:    validated.keyfileMode,
							KeyfileCount:   uint16(len(validated.descriptors)), //nolint:gosec // Validated to at most maxKeyfiles.
							ArgonSalt:      tuple.argonSalt,
							VolumeID:       tuple.volumeID,
						}
						owner, err := withReaderCredentialRoot(
							ctx,
							root,
							schedule,
							metadata,
							func(candidate *ReaderCredential) error {
								return callback(index, candidate)
							},
							seams,
						)
						if err != nil {
							return err
						}
						if owner == nil {
							continue
						}
						if selected != nil {
							owner.Close()
							return newPipelineError(
								PipelineErrorOwner,
								PipelineStageOwner,
								tuple.suite,
							)
						}
						selected = owner
					}
					return nil
				},
			)
		},
	)
	if factorErr != nil {
		var pipelineErr *PipelineError
		if errors.As(factorErr, &pipelineErr) {
			return nil, pipelineErr
		}
		var factorFailure *FactorError
		if errors.As(factorErr, &factorFailure) &&
			factorFailure.Code == FactorErrorCancelled {
			return nil, newPipelineError(
				PipelineErrorCancelled,
				PipelineStageFactors,
				suite,
			)
		}
		return nil, newPipelineError(
			PipelineErrorFactors,
			PipelineStageFactors,
			suite,
		)
	}
	if ctx.Err() != nil {
		return nil, newPipelineError(
			PipelineErrorCancelled,
			PipelineStageCallback,
			suite,
		)
	}
	completed = true
	return selected, nil
}

func snapshotRecoveryCredentialTuples(
	tuples []RecoveryCredentialTuple,
) ([]recoveryCredentialTupleSnapshot, bool) {
	if len(tuples) == 0 || len(tuples) > maxRecoveryCredentialTuples {
		return nil, false
	}
	snapshots := make([]recoveryCredentialTupleSnapshot, len(tuples))
	for index, tuple := range tuples {
		profile, err := fixedProfileForSuite(tuple.Suite)
		if err != nil || tuple.ProfileID != profile.ID ||
			!validCredentialTuple(
				tuple.CredentialMode,
				tuple.KeyfileMode,
				tuple.KeyfileCount,
			) ||
			len(tuple.ArgonSalt) != int(profile.SaltBytes) ||
			len(tuple.VolumeID) != scheduleVolumeIDBytes {
			return nil, false
		}
		snapshot := recoveryCredentialTupleSnapshot{
			suite:          tuple.Suite,
			profileID:      tuple.ProfileID,
			credentialMode: tuple.CredentialMode,
			keyfileMode:    tuple.KeyfileMode,
			keyfileCount:   tuple.KeyfileCount,
		}
		copy(snapshot.argonSalt[:], tuple.ArgonSalt)
		copy(snapshot.volumeID[:], tuple.VolumeID)
		for previous := range index {
			if snapshots[previous] == snapshot {
				return nil, false
			}
		}
		snapshots[index] = snapshot
	}
	return snapshots, true
}

func recoveryTupleMatchesFactors(
	tuple recoveryCredentialTupleSnapshot,
	factors *ValidatedFactors,
) bool {
	return factors != nil &&
		tuple.credentialMode == factors.mode &&
		tuple.keyfileMode == factors.keyfileMode &&
		int(tuple.keyfileCount) == len(factors.descriptors)
}

func recoveryKDFPipelineError(err error, suite Suite) error {
	var kdfErr *KDFError
	if errors.As(err, &kdfErr) && kdfErr.Code == KDFErrorCancelled {
		return newPipelineError(
			PipelineErrorCancelled,
			PipelineStageKDF,
			suite,
		)
	}
	return newPipelineError(
		PipelineErrorKDF,
		PipelineStageKDF,
		suite,
	)
}
