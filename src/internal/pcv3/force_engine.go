package pcv3

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
)

// RecoverySegmentSink receives one callback-scoped non-missing record at its
// original canonical plaintext range.
type RecoverySegmentSink func(RecoveryRange, []byte) error

// RecoveryEmitter is live only during RecoveryOutput. It may be invoked once.
type RecoveryEmitter func(RecoverySegmentSink) error

// RecoveryOutput is called only after complete analysis and unambiguous
// candidate selection. A no-output semantic result never invokes it.
type RecoveryOutput func(*RecoveryResult, CapsuleRole, RecoveryEmitter) error

type recoveryEngineError struct{ stage Stage }

type recoverySelection struct {
	resolution forceResolution
	candidate  Candidate
	geometry   Geometry
	records    recoveryRecordAnalysis
}

type recoveryEmitterLease struct {
	mu       sync.Mutex
	idle     *sync.Cond
	active   bool
	called   bool
	inFlight bool
}

func (*recoveryEngineError) Error() string { return "pcv3: recovery operation failed" }

func (err *recoveryEngineError) String() string { return err.Error() }

func (err *recoveryEngineError) GoString() string { return err.Error() }

func (err *recoveryEngineError) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, err.Error())
}

func newRecoveryEmitterLease() *recoveryEmitterLease {
	lease := &recoveryEmitterLease{active: true}
	lease.idle = sync.NewCond(&lease.mu)
	return lease
}

func (lease *recoveryEmitterLease) invoke(callback func() error) error {
	if lease == nil || callback == nil {
		return &recoveryEngineError{stage: StageOutputWrite}
	}
	lease.mu.Lock()
	if !lease.active || lease.called || lease.inFlight {
		lease.mu.Unlock()
		return &recoveryEngineError{stage: StageOutputWrite}
	}
	lease.called = true
	lease.inFlight = true
	lease.mu.Unlock()
	defer func() {
		lease.mu.Lock()
		lease.inFlight = false
		lease.idle.Broadcast()
		lease.mu.Unlock()
	}()
	return callback()
}

func (lease *recoveryEmitterLease) expire() bool {
	if lease == nil {
		return false
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.active = false
	for lease.inFlight {
		lease.idle.Wait()
	}
	return lease.called
}

type sessionForceIdentity struct {
	session   *pcv3credential.RecoverySession
	candidate *pcv3credential.RecoveryVolumeCandidate
}

func (identity *sessionForceIdentity) sameVolumeKey(other forceCandidateIdentity) bool {
	candidate, ok := other.(*sessionForceIdentity)
	if !ok || identity == nil || candidate == nil || identity.session == nil ||
		identity.session != candidate.session {
		return false
	}
	same, err := identity.session.SameVolumeKey(identity.candidate, candidate.candidate)
	return err == nil && same
}

type sessionVolumeKeyBorrower struct {
	session   *pcv3credential.RecoverySession
	candidate *pcv3credential.RecoveryVolumeCandidate
}

func (borrower *sessionVolumeKeyBorrower) withKey(
	ctx context.Context,
	request pcv3credential.KeyRequest,
	callback func([]byte) error,
) error {
	if borrower == nil || borrower.session == nil || borrower.candidate == nil ||
		ctx == nil || callback == nil || request.Role != pcv3credential.KeyRoleNotReplica ||
		request.OutputBytes != 32 {
		return errInvalidForceAnalysis
	}
	var key [32]byte
	defer pcv3crypto.SecureZero(key[:])
	var callbackErr error
	err := borrower.session.WithVolumeKeys(
		ctx,
		borrower.candidate,
		func(keys *pcv3credential.ReaderKeys) error {
			if err := keys.CopyKey(request, key[:]); err != nil {
				return err
			}
			callbackErr = callback(key[:])
			return callbackErr
		},
	)
	if callbackErr != nil {
		return callbackErr
	}
	return err
}

type ownerVolumeKeyBorrower struct{ owner *pcv3credential.Owner }

func (borrower *ownerVolumeKeyBorrower) withKey(
	ctx context.Context,
	request pcv3credential.KeyRequest,
	callback func([]byte) error,
) error {
	if borrower == nil || borrower.owner == nil || ctx == nil || callback == nil ||
		request.Role != pcv3credential.KeyRoleNotReplica || request.OutputBytes != 32 {
		return errInvalidForceAnalysis
	}
	var key [32]byte
	defer pcv3crypto.SecureZero(key[:])
	var callbackErr error
	err := borrower.owner.WithKeys(ctx, func(keys *pcv3credential.BorrowedKeys) error {
		if err := keys.CopyKey(request, key[:]); err != nil {
			return err
		}
		callbackErr = callback(key[:])
		return callbackErr
	})
	if callbackErr != nil {
		return callbackErr
	}
	return err
}

// Recover executes explicit normal-v3 recovery or ordinary Force. It takes
// ownership of factors on every path. Force-unverified uses RecoverUnverified
// so role-bound consent remains callback-scoped and cannot be serialized.
func Recover(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	factors *pcv3credential.FactorRequest,
	admitter pcv3credential.Admitter,
	mode RecoveryMode,
	output RecoveryOutput,
) (*RecoveryResult, error) {
	request, err := newRecoveryRequest(mode)
	if err != nil {
		closeRecoveryFactors(factors)
		return recoveryOperationFailure(StageCredentialPolicy), &recoveryEngineError{stage: StageCredentialPolicy}
	}
	return recoverWithRequest(ctx, source, sourceSize, factors, admitter, request, output)
}

// RecoverUnverified executes Force with one live, exact physical-role consent
// capability. The capability expires before this function returns.
func RecoverUnverified(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	factors *pcv3credential.FactorRequest,
	admitter pcv3credential.Admitter,
	role CapsuleRole,
	output RecoveryOutput,
) (result *RecoveryResult, resultErr error) {
	err := withUnverifiedRecoveryRequest(role, func(request recoveryRequest) error {
		result, resultErr = recoverWithRequest(
			ctx,
			source,
			sourceSize,
			factors,
			admitter,
			request,
			output,
		)
		factors = nil
		return nil
	})
	if err != nil {
		closeRecoveryFactors(factors)
		return recoveryOperationFailure(StageCredentialPolicy), &recoveryEngineError{stage: StageCredentialPolicy}
	}
	return result, resultErr
}

func recoverWithRequest(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	factors *pcv3credential.FactorRequest,
	admitter pcv3credential.Admitter,
	request recoveryRequest,
	output RecoveryOutput,
) (*RecoveryResult, error) {
	if ctx == nil || source == nil || factors == nil || admitter == nil ||
		!request.valid() || output == nil {
		closeRecoveryFactors(factors)
		return recoveryOperationFailure(StageCredentialPolicy), &recoveryEngineError{stage: StageCredentialPolicy}
	}
	if err := ctx.Err(); err != nil {
		closeRecoveryFactors(factors)
		return recoveryOperationFailure(StageCancellation), &recoveryEngineError{stage: StageCancellation}
	}
	structure, err := InspectRecovery(source, sourceSize)
	if err != nil {
		closeRecoveryFactors(factors)
		return recoveryResultForError(err)
	}
	credentialRequest, tupleIndexes, ok := recoveryCredentialRequest(structure, factors)
	if !ok {
		return recoveryOperationFailure(StageCredentialPolicy), &recoveryEngineError{stage: StageCredentialPolicy}
	}

	var selection recoverySelection
	var analysisErr error
	owner, credentialErr := pcv3credential.WithRecoveryCredentialSession(
		ctx,
		credentialRequest,
		admitter,
		func(session *pcv3credential.RecoverySession) error {
			selection, analysisErr = selectRecoveryWithSession(
				ctx,
				source,
				structure,
				tupleIndexes,
				session,
				request,
			)
			return analysisErr
		},
	)
	if analysisErr != nil {
		if owner != nil {
			owner.Close()
		}
		return recoveryResultForError(analysisErr)
	}
	if credentialErr != nil {
		if owner != nil {
			owner.Close()
		}
		stage := credentialPipelineStage(credentialErr)
		return recoveryOperationFailure(stage), &recoveryEngineError{stage: stage}
	}
	if selection.resolution.result == nil {
		if owner != nil {
			owner.Close()
		}
		return recoveryOperationFailure(StageCredentialPolicy), &recoveryEngineError{stage: StageCredentialPolicy}
	}
	if selection.resolution.selected < 0 {
		if owner != nil {
			owner.Close()
		}
		return selection.resolution.result, nil
	}
	if owner == nil {
		return recoveryOperationFailure(StageUnwrap), &recoveryEngineError{stage: StageUnwrap}
	}
	defer owner.Close()
	return emitRecoverySelection(
		ctx,
		source,
		request,
		selection,
		owner,
		selection.resolution.result,
		func(result *RecoveryResult, emitter RecoveryEmitter) error {
			return output(result, selection.candidate.Role(), emitter)
		},
	)
}

func selectRecoveryWithSession(
	ctx context.Context,
	source io.ReaderAt,
	structure RecoveryStructure,
	tupleIndexes [2]int,
	session *pcv3credential.RecoverySession,
	request recoveryRequest,
) (recoverySelection, error) {
	analyses, err := analyzeRecoveryCandidatesWithSession(
		ctx,
		source,
		structure,
		tupleIndexes,
		session,
		request,
	)
	if err != nil {
		return recoverySelection{}, err
	}
	var resolution forceResolution
	if request.Mode() == RecoveryModeNormalV3 {
		resolution, err = resolveNormalRecoveryCandidates(analyses)
	} else {
		resolution, err = resolveForceCandidates(request, analyses)
	}
	if err != nil {
		return recoverySelection{}, err
	}
	return selectRecoveryAnalysis(session, analyses, resolution)
}

func analyzeRecoveryCandidatesWithSession(
	ctx context.Context,
	source io.ReaderAt,
	structure RecoveryStructure,
	tupleIndexes [2]int,
	session *pcv3credential.RecoverySession,
	request recoveryRequest,
) ([]forceCandidateAnalysis, error) {
	if ctx == nil || source == nil || session == nil || !request.valid() ||
		structure.CandidateCount() < 1 || structure.CandidateCount() > 2 {
		return nil, errInvalidForceAnalysis
	}
	analyses := make([]forceCandidateAnalysis, 0, structure.CandidateCount())
	for index := range structure.CandidateCount() {
		candidate, candidateOK := structure.CandidateAt(index)
		geometry, geometryOK := structure.GeometryAt(index)
		if !candidateOK || !geometryOK {
			return nil, errInvalidForceAnalysis
		}
		analysis, include, err := analyzeRecoveryCandidate(
			ctx,
			source,
			structure,
			candidate,
			geometry,
			tupleIndexes[index],
			session,
			request,
		)
		if err != nil {
			return nil, err
		}
		if include {
			analyses = append(analyses, analysis)
		}
	}
	return analyses, nil
}

func selectRecoveryAnalysis(
	session *pcv3credential.RecoverySession,
	analyses []forceCandidateAnalysis,
	resolution forceResolution,
) (recoverySelection, error) {
	selection := recoverySelection{resolution: resolution}
	if session == nil || resolution.result == nil || resolution.selected < -1 ||
		resolution.selected >= len(analyses) {
		if resolution.result != nil {
			resolution.result.Close()
		}
		return recoverySelection{}, errInvalidForceAnalysis
	}
	if resolution.selected < 0 {
		return selection, nil
	}
	selected := analyses[resolution.selected]
	identity, ok := selected.identity.(*sessionForceIdentity)
	if !ok || identity == nil || identity.candidate == nil {
		resolution.result.Close()
		return recoverySelection{}, errInvalidForceAnalysis
	}
	if err := session.Select(identity.candidate); err != nil {
		resolution.result.Close()
		return recoverySelection{}, err
	}
	selection.candidate = selected.candidate
	selection.geometry = selected.geometry
	selection.records = recoveryRecordAnalysis{
		ranges:      append([]RecoveryRange(nil), selected.ranges...),
		final:       selected.final,
		damageStage: selected.damageStage,
	}
	return selection, nil
}

func emitRecoverySelection(
	ctx context.Context,
	source io.ReaderAt,
	request recoveryRequest,
	selection recoverySelection,
	owner *pcv3credential.Owner,
	result *RecoveryResult,
	output func(*RecoveryResult, RecoveryEmitter) error,
) (*RecoveryResult, error) {
	if ctx == nil || source == nil || !request.valid() || owner == nil ||
		selection.resolution.selected < 0 || result == nil || output == nil {
		return recoveryOperationFailure(StageCredentialPolicy), &recoveryEngineError{stage: StageCredentialPolicy}
	}
	return deliverRecoveryOutput(
		ctx,
		result,
		func(sink RecoverySegmentSink) error {
			return emitRecoveryRecords(
				ctx,
				source,
				selection.candidate,
				selection.geometry,
				&ownerVolumeKeyBorrower{owner: owner},
				request,
				selection.candidate.Role(),
				selection.records,
				sink,
			)
		},
		output,
	)
}

func deliverRecoveryOutput(
	ctx context.Context,
	result *RecoveryResult,
	produce func(RecoverySegmentSink) error,
	output func(*RecoveryResult, RecoveryEmitter) error,
) (*RecoveryResult, error) {
	if ctx == nil || result == nil || produce == nil || output == nil {
		return recoveryOperationFailure(StageCredentialPolicy), &recoveryEngineError{stage: StageCredentialPolicy}
	}
	lease := newRecoveryEmitterLease()
	defer lease.expire()
	var emitterErr error
	var sinkErr error
	emitter := func(sink RecoverySegmentSink) error {
		return lease.invoke(func() error {
			if sink == nil {
				emitterErr = &recoveryEngineError{stage: StageOutputWrite}
				return emitterErr
			}
			emitterErr = produce(
				func(recoveryRange RecoveryRange, plaintext []byte) error {
					sinkErr = sink(recoveryRange, plaintext)
					return sinkErr
				},
			)
			return emitterErr
		})
	}
	outputErr := output(result, emitter)
	emitterCalled := lease.expire()
	if sinkErr != nil {
		if cancellation := recordCancellationCause(ctx, sinkErr); cancellation != nil {
			return recoveryOperationFailure(StageCancellation), &recoveryEngineError{stage: StageCancellation}
		}
		return recoveryOperationFailure(StageOutputWrite), &recoveryEngineError{stage: StageOutputWrite}
	}
	if outputErr != nil {
		if emitterErr != nil {
			return recoveryResultForError(emitterErr)
		}
		var failure Failure
		if errors.As(outputErr, &failure) &&
			failure.Outcome() == OutcomeOperationFailed && failure.Stage() == StageOutputWrite {
			if cancellation := recordCancellationCause(ctx, outputErr); cancellation != nil {
				return recoveryOperationFailure(StageCancellation), &recoveryEngineError{stage: StageCancellation}
			}
			return recoveryResultForError(outputErr)
		}
		return result, &recoveryEngineError{stage: StageOutputWrite}
	}
	if emitterErr != nil {
		return recoveryResultForError(emitterErr)
	}
	if !emitterCalled {
		return result, &recoveryEngineError{stage: StageOutputWrite}
	}
	return result, nil
}

func analyzeRecoveryCandidate(
	ctx context.Context,
	source io.ReaderAt,
	structure RecoveryStructure,
	candidate Candidate,
	geometry Geometry,
	tupleIndex int,
	session *pcv3credential.RecoverySession,
	request recoveryRequest,
) (forceCandidateAnalysis, bool, error) {
	var analysis forceCandidateAnalysis
	identity, wrapVerified, replicaVerified, err := bindRecoveryCandidate(
		ctx,
		candidate,
		tupleIndex,
		session,
		request.Mode() != RecoveryModeNormalV3,
	)
	if err != nil {
		return analysis, false, err
	}
	if identity == nil {
		return analysis, false, nil
	}
	if request.Mode() == RecoveryModeNormalV3 && (!wrapVerified || !replicaVerified) {
		return analysis, false, nil
	}
	borrower := &sessionVolumeKeyBorrower{session: session, candidate: identity.candidate}
	damageStage := StageNone
	if structure.PreambleDamaged() || !authenticatedCoreMatchesPreamble(candidate.core, structure.Preamble()) {
		damageStage = earlierRecoveryDamageStage(damageStage, StagePreamble)
	}
	if request.Mode() == RecoveryModeNormalV3 && candidate.Role() == CapsuleRoleBackup {
		damageStage = earlierRecoveryDamageStage(damageStage, structure.primaryDamage)
	}
	if !wrapVerified {
		damageStage = earlierRecoveryDamageStage(damageStage, StageWrapAuth)
	}
	if !replicaVerified {
		damageStage = earlierRecoveryDamageStage(damageStage, StageReplicaAuth)
	}
	if structure.SuffixDamaged() {
		damageStage = earlierRecoveryDamageStage(damageStage, StageTailGeometry)
	}

	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		return forceCandidateAnalysis{}, false, err
	}
	auth := &normalAuthResult{
		outcome:       OutcomeAuthenticatedDegraded,
		stage:         damageStage,
		authenticated: 1,
		candidate:     candidate,
		geometry:      geometry,
		keyBorrower:   borrower,
	}
	metadata, metadataErr := authenticateMetadata(ctx, source, auth, codecs)
	if metadataErr != nil {
		return forceCandidateAnalysis{}, false, metadataErr
	}
	metadataValid := metadata != nil && metadata.state == metadataAuthenticatedPublic
	if metadata != nil {
		metadata.close()
	}
	if !metadataValid {
		damageStage = earlierRecoveryDamageStage(damageStage, StageMetadata)
	}
	records, err := analyzeRecoveryRecords(
		ctx,
		source,
		candidate,
		geometry,
		borrower,
		request,
		candidate.Role(),
	)
	if err != nil {
		return forceCandidateAnalysis{}, false, err
	}
	damageStage = earlierRecoveryDamageStage(damageStage, records.damageStage)
	analysis = forceCandidateAnalysis{
		identity:           identity,
		candidate:          candidate,
		geometry:           geometry,
		damageStage:        damageStage,
		payloadDamageStage: records.damageStage,
		wrapVerified:       wrapVerified,
		replicaValid:       replicaVerified,
		metadataValid:      metadataValid,
		ranges:             records.ranges,
		final:              records.final,
	}
	return analysis, true, nil
}

func bindRecoveryCandidate(
	ctx context.Context,
	candidate Candidate,
	tupleIndex int,
	session *pcv3credential.RecoverySession,
	allowRaw bool,
) (*sessionForceIdentity, bool, bool, error) {
	if ctx == nil || session == nil || tupleIndex < 0 || !validAuthCandidate(candidate) {
		return nil, false, false, errInvalidForceAnalysis
	}
	role, ok := credentialRole(candidate.Role())
	if !ok {
		return nil, false, false, errInvalidForceAnalysis
	}
	var wrapKeys capsuleWrapKeys
	defer wrapKeys.close()
	var callbackErr error
	err := session.WithTupleKeys(ctx, tupleIndex, role, func(keys *pcv3credential.ReaderKeys) error {
		for _, key := range []struct {
			request     pcv3credential.KeyRequest
			destination []byte
		}{
			{
				request:     pcv3credential.KeyRequest{Label: pcv3credential.KeyLabelCredentialWrapXChaCha20, Role: role, OutputBytes: 32},
				destination: wrapKeys.xChaCha20[:],
			},
			{
				request:     pcv3credential.KeyRequest{Label: pcv3credential.KeyLabelCredentialWrapMAC, Role: role, OutputBytes: 32},
				destination: wrapKeys.mac[:],
			},
		} {
			if copyErr := keys.CopyKey(key.request, key.destination); copyErr != nil {
				callbackErr = copyErr
				return copyErr
			}
		}
		if candidate.Suite() == SuiteParanoid {
			callbackErr = keys.CopyKey(pcv3credential.KeyRequest{
				Label: pcv3credential.KeyLabelCredentialWrapSerpent, Role: role, OutputBytes: 32,
			}, wrapKeys.serpent[:])
			return callbackErr
		}
		return nil
	})
	if callbackErr != nil {
		return nil, false, false, callbackErr
	}
	if err != nil {
		return nil, false, false, err
	}
	wrapVerified, err := verifySuiteMAC(
		candidate.Suite(),
		wrapKeys.mac[:],
		wrapAuthMessage(candidate),
		candidate.wrapTag[:],
	)
	if err != nil {
		return nil, false, false, err
	}
	if !wrapVerified && !allowRaw {
		return nil, false, false, nil
	}
	var volumeKey [32]byte
	defer pcv3crypto.SecureZero(volumeKey[:])
	seams := defaultCapsuleAuthSeams()
	switch candidate.Suite() {
	case SuiteStandard:
		err = seams.unwrapStandard(
			volumeKey[:], candidate.wrappedVolumeKey[:], wrapKeys.xChaCha20[:], candidate.wrapNonce[:],
		)
	case SuiteParanoid:
		err = seams.unwrapParanoid(
			volumeKey[:], candidate.wrappedVolumeKey[:], wrapKeys.xChaCha20[:], candidate.wrapNonce[:],
			wrapKeys.serpent[:], candidate.wrapSerpentIV[:],
		)
	default:
		err = errInvalidForceAnalysis
	}
	if err != nil {
		return nil, false, false, err
	}
	handle, err := session.BindCandidate(ctx, tupleIndex, volumeKey[:])
	if err != nil {
		return nil, false, false, err
	}
	identity := &sessionForceIdentity{session: session, candidate: handle}
	var replicaKey [32]byte
	defer pcv3crypto.SecureZero(replicaKey[:])
	callbackErr = nil
	err = session.WithReplicaKey(ctx, handle, role, func(keys *pcv3credential.ReaderKeys) error {
		callbackErr = keys.CopyKey(pcv3credential.KeyRequest{
			Label: pcv3credential.KeyLabelVolumeReplicaMAC, Role: role, OutputBytes: 32,
		}, replicaKey[:])
		return callbackErr
	})
	if callbackErr != nil {
		return nil, false, false, callbackErr
	}
	if err != nil {
		return nil, false, false, err
	}
	replicaVerified, err := verifySuiteMAC(
		candidate.Suite(), replicaKey[:], replicaAuthMessage(candidate), candidate.replicaTag[:],
	)
	if err != nil {
		return nil, false, false, err
	}
	return identity, wrapVerified, replicaVerified, nil
}

func recoveryCredentialRequest(
	structure RecoveryStructure,
	factors *pcv3credential.FactorRequest,
) (*pcv3credential.RecoveryCredentialRequest, [2]int, bool) {
	tuples, tupleIndexes, ok := recoveryCredentialTuples(structure)
	if factors == nil || !ok {
		closeRecoveryFactors(factors)
		return nil, tupleIndexes, false
	}
	return &pcv3credential.RecoveryCredentialRequest{
		Factors: factors,
		Tuples:  tuples,
	}, tupleIndexes, true
}

func recoveryCredentialTuples(
	structure RecoveryStructure,
) ([]pcv3credential.RecoveryCredentialTuple, [2]int, bool) {
	var tupleIndexes [2]int
	if structure.CandidateCount() < 1 || structure.CandidateCount() > 2 {
		return nil, tupleIndexes, false
	}
	var identities []credentialTuple
	var requests []pcv3credential.RecoveryCredentialTuple
	for index := range structure.CandidateCount() {
		candidate, ok := structure.CandidateAt(index)
		if !ok || !validAuthCandidate(candidate) {
			return nil, tupleIndexes, false
		}
		tuple := credentialTupleForCandidate(candidate)
		tupleIndex := -1
		for existing := range identities {
			if identities[existing] == tuple {
				tupleIndex = existing
				break
			}
		}
		if tupleIndex == -1 {
			tupleIndex = len(identities)
			tupleRequest, valid := credentialRecoveryTuple(tuple)
			if !valid {
				return nil, tupleIndexes, false
			}
			identities = append(identities, tuple)
			requests = append(requests, tupleRequest)
		}
		tupleIndexes[index] = tupleIndex
	}
	return requests, tupleIndexes, true
}

func credentialRecoveryTuple(tuple credentialTuple) (pcv3credential.RecoveryCredentialTuple, bool) {
	mode, keyfileMode, ok := credentialRecoveryModes(tuple.credentialMode, tuple.keyfileMode)
	if !ok {
		return pcv3credential.RecoveryCredentialTuple{}, false
	}
	return pcv3credential.RecoveryCredentialTuple{
		Suite:          credentialSuite(tuple.suite),
		ProfileID:      uint8(tuple.kdfProfile),
		CredentialMode: mode,
		KeyfileMode:    keyfileMode,
		KeyfileCount:   tuple.keyfileCount,
		ArgonSalt:      append([]byte(nil), tuple.argonSalt[:]...),
		VolumeID:       append([]byte(nil), tuple.volumeID[:]...),
	}, true
}

func credentialRecoveryModes(
	mode CredentialMode,
	keyfileMode KeyfileMode,
) (pcv3credential.CredentialMode, pcv3credential.KeyfileMode, bool) {
	var credentialMode pcv3credential.CredentialMode
	switch mode {
	case CredentialModePassword:
		credentialMode = pcv3credential.CredentialModePasswordOnly
	case CredentialModeKeyfiles:
		credentialMode = pcv3credential.CredentialModeKeyfilesOnly
	case CredentialModeCombined:
		credentialMode = pcv3credential.CredentialModePasswordAndKeyfiles
	default:
		return 0, 0, false
	}
	var ordered pcv3credential.KeyfileMode
	switch keyfileMode {
	case KeyfileModeNone:
		ordered = pcv3credential.KeyfileModeNone
	case KeyfileModeOrdered:
		ordered = pcv3credential.KeyfileModeOrdered
	case KeyfileModeUnordered:
		ordered = pcv3credential.KeyfileModeUnordered
	default:
		return 0, 0, false
	}
	return credentialMode, ordered, true
}

func resolveNormalRecoveryCandidates(analyses []forceCandidateAnalysis) (forceResolution, error) {
	resolution := forceResolution{selected: -1}
	if len(analyses) == 0 {
		result, err := newRecoveryResult(
			OutcomeCredentialsOrDamage, ForceProvenanceNone, StageWrapAuth, 0, nil, 0,
		)
		resolution.result = result
		return resolution, err
	}
	if len(analyses) > 2 {
		return resolution, errInvalidForceAnalysis
	}
	if len(analyses) == 2 &&
		(analyses[0].candidate.core != analyses[1].candidate.core ||
			!analyses[0].identity.sameVolumeKey(analyses[1].identity)) {
		result, err := newRecoveryResult(
			OutcomeAmbiguousVolume, ForceProvenanceNone, StageCapsuleStructure, 0, nil, 0,
		)
		resolution.result = result
		return resolution, err
	}
	selected := 0
	if len(analyses) == 2 && analyses[1].candidate.Role() == CapsuleRolePrimary {
		selected = 1
	}
	analysis := analyses[selected]
	if !forceAnalysisFullyVerified(analysis) {
		stage := analysis.payloadDamageStage
		if stage == StageNone {
			stage = forceDamageStage(forceCandidateAnalysis{
				ranges: analysis.ranges,
				final:  analysis.final,
			})
		}
		result, err := newRecoveryResult(
			OutcomeAuthenticationFailed, ForceProvenanceNone, stage, 0, nil, 0,
		)
		resolution.result = result
		return resolution, err
	}
	outcome := OutcomeSuccess
	stage := StageNone
	if analysis.damageStage != StageNone {
		outcome = OutcomeAuthenticatedDegraded
		stage = analysis.damageStage
	}
	result, err := newRecoveryResult(outcome, ForceProvenanceNone, stage, 0, nil, 0)
	if err != nil {
		return resolution, err
	}
	resolution.result = result
	resolution.selected = selected
	return resolution, nil
}

func recoveryOperationFailure(stage Stage) *RecoveryResult {
	result, err := newRecoveryResult(
		OutcomeOperationFailed,
		ForceProvenanceNone,
		stage,
		0,
		nil,
		0,
	)
	if err != nil {
		return &RecoveryResult{
			outcome: OutcomeOperationFailed,
			stage:   StageCredentialPolicy,
		}
	}
	return result
}

func recoveryResultForError(err error) (*RecoveryResult, error) {
	var failure Failure
	if errors.As(err, &failure) {
		result, resultErr := newRecoveryResult(
			failure.Outcome(), ForceProvenanceNone, failure.Stage(), 0, nil, 0,
		)
		if resultErr == nil {
			if failure.Outcome() == OutcomeOperationFailed {
				return result, &recoveryEngineError{stage: failure.Stage()}
			}
			return result, nil
		}
	}
	var recordErr *recordFailure
	if errors.As(err, &recordErr) {
		switch recordErr.stage {
		case StageDescriptor, StageRecordBodyRS, StageRecordAuth, StageFinalRecord:
			result, resultErr := newRecoveryResult(
				OutcomeAuthenticationFailed,
				ForceProvenanceNone,
				recordErr.stage,
				0,
				nil,
				0,
			)
			return result, resultErr
		case StageInputIO, StageCredentialPolicy, StageCancellation, StageOutputWrite:
			return recoveryOperationFailure(recordErr.stage), &recoveryEngineError{stage: recordErr.stage}
		}
	}
	return recoveryOperationFailure(StageCredentialPolicy), &recoveryEngineError{stage: StageCredentialPolicy}
}

func closeRecoveryFactors(factors *pcv3credential.FactorRequest) {
	if factors != nil {
		_ = factors.Close()
	}
}
