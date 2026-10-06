package pcv3credential

import (
	pcsecret "Picocrypt-NG/internal/secret"
	"context"
	"crypto/subtle"
	"errors"
	"sync"
)

const (
	maxRecoveryCredentialTuples = 2
	maxRecoveryVolumeCandidates = 2
)

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

// RecoverySession is a callback-scoped two-step recovery credential session.
// It retains at most two sequentially derived tuple credentials and exposes
// only restricted key borrows and opaque bound candidate handles.
type RecoverySession struct {
	state *recoverySessionState
}

type recoverySessionState struct {
	mu sync.Mutex

	ctx                context.Context
	active             bool
	borrows            int
	selectionAttempted bool
	selected           *RecoveryVolumeCandidate
	readers            []*ReaderCredential
	candidates         []*RecoveryVolumeCandidate
}

// RecoveryVolumeCandidate is an opaque, session-bound VolumeKey candidate.
// Its key bytes never leave the credential core through this handle.
type RecoveryVolumeCandidate struct {
	state *recoveryVolumeCandidateState
}

type recoveryVolumeCandidateState struct {
	session    *recoverySessionState
	tupleIndex int
	active     bool
	volumeKey  *volumeKey
}

func (*RecoverySession) String() string {
	return "pcv3credential.RecoverySession([REDACTED])"
}

func (*RecoverySession) GoString() string {
	return "pcv3credential.RecoverySession([REDACTED])"
}

func (*RecoveryVolumeCandidate) String() string {
	return "pcv3credential.RecoveryVolumeCandidate([REDACTED])"
}

func (*RecoveryVolumeCandidate) GoString() string {
	return "pcv3credential.RecoveryVolumeCandidate([REDACTED])"
}

// WithTupleKeys lends only credential-root keys for one admitted tuple.
func (session *RecoverySession) WithTupleKeys(
	ctx context.Context,
	index int,
	role KeyRole,
	callback func(*ReaderKeys) error,
) error {
	reader, err := session.beginTupleBorrow(ctx, index)
	if err != nil {
		return err
	}
	defer session.endBorrow()
	return reader.WithKeys(ctx, role, callback)
}

// BindCandidate transfers one exact unwrapped VolumeKey into an opaque handle.
// The transfer buffer is cleared on every return.
func (session *RecoverySession) BindCandidate(
	ctx context.Context,
	tupleIndex int,
	transfer []byte,
) (*RecoveryVolumeCandidate, error) {
	defer pcsecret.SecureZero(transfer)
	if session == nil || session.state == nil || ctx == nil ||
		len(transfer) != derivedKeyBytes {
		return nil, newOwnerError(OwnerErrorInvalidRequest)
	}
	state := session.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active || state.selectionAttempted || state.borrows != 0 ||
		tupleIndex < 0 || tupleIndex >= len(state.readers) ||
		len(state.candidates) >= maxRecoveryVolumeCandidates {
		return nil, newOwnerError(OwnerErrorClosed)
	}
	if ctx.Err() != nil || state.ctx.Err() != nil {
		return nil, newOwnerError(OwnerErrorCancelled)
	}
	owned := append([]byte(nil), transfer...)
	candidate := &RecoveryVolumeCandidate{
		state: &recoveryVolumeCandidateState{
			session:    state,
			tupleIndex: tupleIndex,
			active:     true,
			volumeKey:  &volumeKey{secret: pcsecret.SecretFrom(owned)},
		},
	}
	state.candidates = append(state.candidates, candidate)
	return candidate, nil
}

// SameVolumeKey compares two live, exact-session candidates in constant time.
func (session *RecoverySession) SameVolumeKey(
	left *RecoveryVolumeCandidate,
	right *RecoveryVolumeCandidate,
) (bool, error) {
	if session == nil || session.state == nil {
		return false, newOwnerError(OwnerErrorInvalidRequest)
	}
	state := session.state
	state.mu.Lock()
	defer state.mu.Unlock()
	leftState, ok := recoveryCandidateStateLocked(state, left)
	if !state.active || state.selectionAttempted || state.borrows != 0 ||
		state.ctx.Err() != nil || !ok {
		return false, newOwnerError(OwnerErrorClosed)
	}
	rightState, ok := recoveryCandidateStateLocked(state, right)
	if !ok {
		return false, newOwnerError(OwnerErrorClosed)
	}
	return subtle.ConstantTimeCompare(
		leftState.volumeKey.secret.Bytes(),
		rightState.volumeKey.secret.Bytes(),
	) == 1, nil
}

// WithReplicaKey derives and lends only the selected physical role's replica
// MAC key for one exact bound candidate.
func (session *RecoverySession) WithReplicaKey(
	ctx context.Context,
	candidate *RecoveryVolumeCandidate,
	role KeyRole,
	callback func(*ReaderKeys) error,
) error {
	reader, transfer, err := session.beginCandidateBorrow(ctx, candidate)
	if err != nil {
		return err
	}
	defer session.endBorrow()
	defer pcsecret.SecureZero(transfer)
	return reader.WithReplicaKey(ctx, role, transfer, callback)
}

// WithVolumeKeys derives and lends only non-replica volume keys for one exact
// bound candidate. VolumeKey and replica keys remain unavailable to callback.
func (session *RecoverySession) WithVolumeKeys(
	ctx context.Context,
	candidate *RecoveryVolumeCandidate,
	callback func(*ReaderKeys) error,
) error {
	reader, transfer, err := session.beginCandidateBorrow(ctx, candidate)
	if err != nil {
		return err
	}
	defer session.endBorrow()
	defer pcsecret.SecureZero(transfer)
	return reader.withVolumeKeys(ctx, transfer, callback)
}

// Select stages an Owner from one exact live candidate. Selection is
// single-use, including a failed derivation attempt.
func (session *RecoverySession) Select(candidate *RecoveryVolumeCandidate) error {
	if session == nil || session.state == nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	state := session.state
	state.mu.Lock()
	candidateState, ok := recoveryCandidateStateLocked(state, candidate)
	if !state.active || state.selectionAttempted || state.borrows != 0 ||
		state.ctx.Err() != nil || !ok {
		state.mu.Unlock()
		return newOwnerError(OwnerErrorClosed)
	}
	state.selectionAttempted = true
	reader := state.readers[candidateState.tupleIndex]
	transfer := append([]byte(nil), candidateState.volumeKey.secret.Bytes()...)
	state.mu.Unlock()

	if err := reader.AdoptVolumeKey(transfer); err != nil {
		return err
	}
	state.mu.Lock()
	state.selected = candidate
	state.mu.Unlock()
	return nil
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

// WithRecoveryCredentialSession derives the complete bounded tuple set before
// lending one two-step recovery session. Selection is optional; when present,
// exactly one session-bound candidate becomes the returned Owner.
func WithRecoveryCredentialSession(
	ctx context.Context,
	request *RecoveryCredentialRequest,
	admitter Admitter,
	callback func(*RecoverySession) error,
) (*Owner, error) {
	return newRecoveryCredentialSession(
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

// WithD1RecoveryCredentialSession consumes one D1 normal input and lends the
// complete Paranoid-1 tuple set through the shared recovery session lifecycle.
// Factors are borrowed synchronously and remain owned by the caller.
func WithD1RecoveryCredentialSession(
	ctx context.Context,
	input *CredentialInputNormal,
	factors *ValidatedFactors,
	tuples []RecoveryCredentialTuple,
	admitter Admitter,
	callback func(*RecoverySession) error,
) (*Owner, error) {
	return newD1RecoveryCredentialSession(
		ctx,
		input,
		factors,
		tuples,
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
	var selected *Owner
	completed := false
	defer func() {
		if !completed && selected != nil {
			selected.Close()
		}
	}()

	var consumer recoveryReaderConsumer
	if callback != nil {
		consumer = func(index int, reader *ReaderCredential) (bool, error) {
			if err := callback(index, reader); err != nil {
				return false, newPipelineError(
					PipelineErrorCallback,
					PipelineStageCallback,
					reader.state.metadata.Suite,
				)
			}
			if ctx.Err() != nil {
				return false, newPipelineError(
					PipelineErrorCancelled,
					PipelineStageCallback,
					reader.state.metadata.Suite,
				)
			}
			owner := reader.takeOwner()
			if owner == nil {
				return false, nil
			}
			if selected != nil {
				owner.Close()
				return false, newPipelineError(
					PipelineErrorOwner,
					PipelineStageOwner,
					reader.state.metadata.Suite,
				)
			}
			selected = owner
			return false, nil
		}
	}
	if err := withRecoveryCredentialReaders(
		ctx,
		request,
		admitter,
		consumer,
		seams,
	); err != nil {
		return nil, err
	}
	completed = true
	return selected, nil
}

func newRecoveryCredentialSession(
	ctx context.Context,
	request *RecoveryCredentialRequest,
	admitter Admitter,
	callback func(*RecoverySession) error,
	seams readerCredentialSeams,
) (*Owner, error) {
	session := newRecoverySession(ctx)
	defer session.close()

	var consumer recoveryReaderConsumer
	if callback != nil {
		consumer = session.retainReader
	}
	if err := withRecoveryCredentialReaders(
		ctx,
		request,
		admitter,
		consumer,
		seams,
	); err != nil {
		return nil, err
	}
	return session.finish(ctx, callback)
}

func newD1RecoveryCredentialSession(
	ctx context.Context,
	input *CredentialInputNormal,
	factors *ValidatedFactors,
	tuples []RecoveryCredentialTuple,
	admitter Admitter,
	callback func(*RecoverySession) error,
	seams readerCredentialSeams,
) (*Owner, error) {
	defer input.Close()

	snapshots, ok := snapshotRecoveryCredentialTuples(tuples)
	if !ok {
		return nil, newPipelineError(
			PipelineErrorSchedule,
			PipelineStageSchedule,
			0,
		)
	}
	suite := snapshots[0].suite
	if !validD1RecoveryCredentialTuples(snapshots) {
		return nil, newPipelineError(
			PipelineErrorSchedule,
			PipelineStageSchedule,
			suite,
		)
	}
	if ctx == nil || input == nil || factors == nil || admitter == nil || callback == nil ||
		seams.derive == nil || seams.extract == nil || seams.expand == nil {
		return nil, newPipelineError(
			PipelineErrorInvalidRequest,
			PipelineStageRequest,
			suite,
		)
	}
	if ctx.Err() != nil {
		return nil, newPipelineError(
			PipelineErrorCancelled,
			PipelineStageRequest,
			suite,
		)
	}
	if err := validateRecoveryTupleFactors(snapshots, factors); err != nil {
		return nil, err
	}

	session := newRecoverySession(ctx)
	defer session.close()
	err := withCredentialInputNormalBorrow(
		input,
		func(borrow *credentialInputBorrow) error {
			return withRecoveryCredentialReadersFromInput(
				ctx,
				snapshots,
				factors,
				borrow,
				admitter,
				session.retainReader,
				seams,
			)
		},
	)
	if err != nil {
		var pipelineErr *PipelineError
		if errors.As(err, &pipelineErr) {
			return nil, pipelineErr
		}
		return nil, newPipelineError(
			PipelineErrorTranscript,
			PipelineStageTranscript,
			suite,
		)
	}
	return session.finish(ctx, callback)
}

type recoveryReaderConsumer func(int, *ReaderCredential) (bool, error)

func newRecoverySession(ctx context.Context) *RecoverySession {
	return &RecoverySession{state: &recoverySessionState{ctx: ctx}}
}

func (session *RecoverySession) retainReader(
	index int,
	reader *ReaderCredential,
) (bool, error) {
	state := session.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.active || index != len(state.readers) ||
		len(state.readers) >= maxRecoveryCredentialTuples {
		return false, newPipelineError(
			PipelineErrorOwner,
			PipelineStageOwner,
			reader.state.metadata.Suite,
		)
	}
	state.readers = append(state.readers, reader)
	return true, nil
}

func (session *RecoverySession) finish(
	ctx context.Context,
	callback func(*RecoverySession) error,
) (*Owner, error) {
	state := session.state
	state.mu.Lock()
	state.active = true
	suite := state.readers[0].state.metadata.Suite
	state.mu.Unlock()
	if ctx.Err() != nil {
		return nil, newPipelineError(
			PipelineErrorCancelled,
			PipelineStageCallback,
			suite,
		)
	}
	if err := callback(session); err != nil {
		return nil, newPipelineError(
			PipelineErrorCallback,
			PipelineStageCallback,
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
	owner, err := session.takeSelectedOwner()
	if err != nil {
		return nil, err
	}
	return owner, nil
}

// withRecoveryCredentialReaders is the single validation, transcript, KDF,
// and reader-construction driver used by both recovery entry points.
func withRecoveryCredentialReaders(
	ctx context.Context,
	request *RecoveryCredentialRequest,
	admitter Admitter,
	consumer recoveryReaderConsumer,
	seams readerCredentialSeams,
) error {
	if request == nil {
		return newPipelineError(
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
		return newPipelineError(
			PipelineErrorSchedule,
			PipelineStageSchedule,
			0,
		)
	}
	suite := snapshots[0].suite
	if ctx == nil || admitter == nil || consumer == nil ||
		seams.derive == nil || seams.extract == nil || seams.expand == nil {
		releaseFactorRequest(factors)
		return newPipelineError(
			PipelineErrorInvalidRequest,
			PipelineStageRequest,
			suite,
		)
	}
	if ctx.Err() != nil {
		releaseFactorRequest(factors)
		return newPipelineError(
			PipelineErrorCancelled,
			PipelineStageRequest,
			suite,
		)
	}

	factorErr := WithValidatedFactors(
		ctx,
		factors,
		func(validated *ValidatedFactors) error {
			if err := validateRecoveryTupleFactors(snapshots, validated); err != nil {
				return err
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
					return withRecoveryCredentialReadersFromInput(
						ctx,
						snapshots,
						validated,
						input,
						admitter,
						consumer,
						seams,
					)
				},
			)
		},
	)
	if factorErr == nil {
		return nil
	}
	var pipelineErr *PipelineError
	if errors.As(factorErr, &pipelineErr) {
		return pipelineErr
	}
	var factorFailure *FactorError
	if errors.As(factorErr, &factorFailure) &&
		factorFailure.Code == FactorErrorCancelled {
		return newPipelineError(
			PipelineErrorCancelled,
			PipelineStageFactors,
			suite,
		)
	}
	return newPipelineError(
		PipelineErrorFactors,
		PipelineStageFactors,
		suite,
	)
}

func validateRecoveryTupleFactors(
	snapshots []recoveryCredentialTupleSnapshot,
	factors *ValidatedFactors,
) error {
	for _, tuple := range snapshots {
		if !recoveryTupleMatchesFactors(tuple, factors) {
			return newPipelineError(
				PipelineErrorFactors,
				PipelineStageFactors,
				tuple.suite,
			)
		}
	}
	return nil
}

func withRecoveryCredentialReadersFromInput(
	ctx context.Context,
	snapshots []recoveryCredentialTupleSnapshot,
	validated *ValidatedFactors,
	input *credentialInputBorrow,
	admitter Admitter,
	consumer recoveryReaderConsumer,
	seams readerCredentialSeams,
) error {
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
				admitter,
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
			return pipelineErrorFromKDF(deriveErr, tuple.suite)
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
		reader, err := newReaderCredentialRoot(
			ctx,
			root,
			schedule,
			metadata,
			seams,
		)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			reader.close()
			return newPipelineError(
				PipelineErrorCancelled,
				PipelineStageCallback,
				tuple.suite,
			)
		}
		retain := false
		consumeErr := func() error {
			defer func() {
				if !retain {
					reader.close()
				}
			}()
			var err error
			retain, err = consumer(index, reader)
			return err
		}()
		if consumeErr != nil {
			return consumeErr
		}
	}
	return nil
}

func (session *RecoverySession) beginTupleBorrow(
	ctx context.Context,
	index int,
) (*ReaderCredential, error) {
	if session == nil || session.state == nil || ctx == nil {
		return nil, newOwnerError(OwnerErrorInvalidRequest)
	}
	state := session.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active || state.selectionAttempted || state.borrows != 0 ||
		index < 0 || index >= len(state.readers) {
		return nil, newOwnerError(OwnerErrorClosed)
	}
	if ctx.Err() != nil || state.ctx.Err() != nil {
		return nil, newOwnerError(OwnerErrorCancelled)
	}
	state.borrows++
	return state.readers[index], nil
}

func (session *RecoverySession) beginCandidateBorrow(
	ctx context.Context,
	candidate *RecoveryVolumeCandidate,
) (*ReaderCredential, []byte, error) {
	if session == nil || session.state == nil || ctx == nil {
		return nil, nil, newOwnerError(OwnerErrorInvalidRequest)
	}
	state := session.state
	state.mu.Lock()
	defer state.mu.Unlock()
	candidateState, ok := recoveryCandidateStateLocked(state, candidate)
	if !state.active || state.selectionAttempted || state.borrows != 0 || !ok {
		return nil, nil, newOwnerError(OwnerErrorClosed)
	}
	if ctx.Err() != nil || state.ctx.Err() != nil {
		return nil, nil, newOwnerError(OwnerErrorCancelled)
	}
	state.borrows++
	transfer := append([]byte(nil), candidateState.volumeKey.secret.Bytes()...)
	return state.readers[candidateState.tupleIndex], transfer, nil
}

func (session *RecoverySession) endBorrow() {
	if session == nil || session.state == nil {
		return
	}
	state := session.state
	state.mu.Lock()
	if state.borrows > 0 {
		state.borrows--
	}
	state.mu.Unlock()
}

func recoveryCandidateStateLocked(
	state *recoverySessionState,
	candidate *RecoveryVolumeCandidate,
) (*recoveryVolumeCandidateState, bool) {
	if state == nil || candidate == nil || candidate.state == nil ||
		candidate.state.session != state || !candidate.state.active ||
		candidate.state.volumeKey == nil || candidate.state.volumeKey.secret == nil {
		return nil, false
	}
	for _, bound := range state.candidates {
		if bound == candidate {
			return candidate.state, true
		}
	}
	return nil, false
}

func (session *RecoverySession) takeSelectedOwner() (*Owner, error) {
	if session == nil || session.state == nil {
		return nil, newPipelineError(
			PipelineErrorOwner,
			PipelineStageOwner,
			0,
		)
	}
	state := session.state
	state.mu.Lock()
	if !state.active || state.borrows != 0 {
		state.mu.Unlock()
		return nil, newPipelineError(
			PipelineErrorOwner,
			PipelineStageOwner,
			0,
		)
	}
	selected := state.selected
	if selected == nil {
		state.mu.Unlock()
		return nil, nil
	}
	candidateState, ok := recoveryCandidateStateLocked(state, selected)
	if !ok {
		state.mu.Unlock()
		return nil, newPipelineError(
			PipelineErrorOwner,
			PipelineStageOwner,
			0,
		)
	}
	reader := state.readers[candidateState.tupleIndex]
	suite := reader.state.metadata.Suite
	state.mu.Unlock()
	owner := reader.takeOwner()
	if owner == nil {
		return nil, newPipelineError(
			PipelineErrorOwner,
			PipelineStageOwner,
			suite,
		)
	}
	return owner, nil
}

func (session *RecoverySession) close() {
	if session == nil || session.state == nil {
		return
	}
	state := session.state
	state.mu.Lock()
	state.active = false
	state.selectionAttempted = true
	state.selected = nil
	readers := state.readers
	state.readers = nil
	candidates := state.candidates
	state.candidates = nil
	for _, candidate := range candidates {
		if candidate == nil || candidate.state == nil {
			continue
		}
		candidate.state.active = false
		key := candidate.state.volumeKey
		candidate.state.volumeKey = nil
		candidate.state.session = nil
		if key != nil {
			key.close()
		}
	}
	state.mu.Unlock()
	for _, reader := range readers {
		reader.close()
	}
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

func validD1RecoveryCredentialTuples(snapshots []recoveryCredentialTupleSnapshot) bool {
	profile, err := fixedProfileForSuite(SuiteParanoid1)
	if err != nil {
		return false
	}
	for _, tuple := range snapshots {
		if tuple.suite != SuiteParanoid1 || tuple.profileID != profile.ID {
			return false
		}
	}
	return true
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
