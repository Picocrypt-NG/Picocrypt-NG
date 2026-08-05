package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	replicaDomain = "Picocrypt-NG/PCV3/replica\x00"
	wrapDomain    = "Picocrypt-NG/PCV3/wrap\x00"
)

type credentialTuple struct {
	suite          Suite
	credentialMode CredentialMode
	keyfileMode    KeyfileMode
	keyfileCount   uint16
	kdfProfile     KDFProfile
	argonSalt      [16]byte
	volumeID       [32]byte
}

type capsuleWrapKeys struct {
	xChaCha20 [32]byte
	serpent   [32]byte
	mac       [32]byte
}

func (keys *capsuleWrapKeys) close() {
	if keys == nil {
		return
	}
	pcv3crypto.SecureZero(keys.xChaCha20[:])
	pcv3crypto.SecureZero(keys.serpent[:])
	pcv3crypto.SecureZero(keys.mac[:])
}

type capsuleCredentialAccess interface {
	withWrapKeys(CapsuleRole, func(*capsuleWrapKeys) error) error
	withReplicaKey(CapsuleRole, []byte, func([]byte) error) error
	adoptVolumeKey([]byte) error
}

type capsuleCredentialProvider interface {
	withCredential(
		context.Context,
		credentialTuple,
		func(capsuleCredentialAccess) error,
	) error
}

type capsuleCredentialProviderCloser interface {
	close()
}

type capsuleOwnerProvider interface {
	takeOwner() *pcv3credential.Owner
}

type capsuleAuthSeams struct {
	unwrapStandard func([]byte, []byte, []byte, []byte) error
	unwrapParanoid func([]byte, []byte, []byte, []byte, []byte, []byte) error
}

func defaultCapsuleAuthSeams() capsuleAuthSeams {
	return capsuleAuthSeams{
		unwrapStandard: pcv3crypto.PCV3UnwrapStandard1,
		unwrapParanoid: pcv3crypto.PCV3UnwrapParanoid1,
	}
}

type authenticatedCandidate struct {
	candidate Candidate
	geometry  Geometry
	volumeKey [32]byte
}

func (candidate *authenticatedCandidate) close() {
	if candidate == nil {
		return
	}
	pcv3crypto.SecureZero(candidate.volumeKey[:])
	candidate.candidate = Candidate{}
	candidate.geometry = Geometry{}
}

type capsuleAuthError struct {
	stage Stage
}

func (*capsuleAuthError) Error() string {
	return "pcv3: capsule authentication operation failed"
}

// authenticateCapsulesWithProvider is the single package-local normal capsule
// engine. Fast tests supply frozen literal keys through provider; the
// production adapter below routes the same interface through
// pcv3credential.WithReaderCredential.
func authenticateCapsulesWithProvider(
	ctx context.Context,
	structure Structure,
	provider capsuleCredentialProvider,
	seams capsuleAuthSeams,
) *normalAuthResult {
	return authenticateCapsulesWithProviderMode(ctx, structure, provider, seams, true, false)
}

// authenticateCapsulesBorrowingProvider keeps a caller-owned provider alive
// through the post-capsule authenticated reader stages.
func authenticateCapsulesBorrowingProvider(
	ctx context.Context,
	structure Structure,
	provider capsuleCredentialProvider,
	seams capsuleAuthSeams,
) *normalAuthResult {
	return authenticateCapsulesWithProviderMode(ctx, structure, provider, seams, false, true)
}

func authenticateCapsulesWithProviderMode(
	ctx context.Context,
	structure Structure,
	provider capsuleCredentialProvider,
	seams capsuleAuthSeams,
	closeProvider bool,
	retainBorrower bool,
) *normalAuthResult {
	if closeProvider {
		closer, ok := provider.(capsuleCredentialProviderCloser)
		if ok {
			defer closer.close()
		}
	}
	tuple, ok := credentialTupleForStructure(structure)
	if !ok {
		return newNormalAuthResult(
			OutcomeInvalidStructurePreKDF,
			StageCapsuleStructure,
			0,
		)
	}
	if ctx == nil || provider == nil ||
		seams.unwrapStandard == nil || seams.unwrapParanoid == nil {
		return newNormalAuthResult(
			OutcomeOperationFailed,
			StageKDFRuntime,
			0,
		)
	}
	if ctx.Err() != nil {
		return newNormalAuthResult(
			OutcomeOperationFailed,
			StageCancellation,
			0,
		)
	}

	var result *normalAuthResult
	callbackCalls := 0
	err := provider.withCredential(
		ctx,
		tuple,
		func(access capsuleCredentialAccess) error {
			callbackCalls++
			if callbackCalls != 1 || access == nil {
				return &capsuleAuthError{stage: StageCredentialPolicy}
			}
			var authenticated [2]*authenticatedCandidate
			var authenticatedCount int
			var failedStages [2]Stage
			defer func() {
				for i := range authenticated {
					if authenticated[i] != nil {
						authenticated[i].close()
					}
				}
			}()

			for i := range structure.candidates {
				if i >= int(structure.candidateCount) {
					break
				}
				candidate := structure.candidates[i]
				verified, failureStage, err := authenticateCandidate(
					candidate,
					structure.geometries[i],
					access,
					seams,
				)
				if err != nil {
					return err
				}
				if failureStage != StageNone {
					failedStages[i] = failureStage
					continue
				}
				authenticated[authenticatedCount] = verified
				authenticatedCount++
			}

			switch authenticatedCount {
			case 0:
				result = newNormalAuthResult(
					OutcomeCredentialsOrDamage,
					StageWrapAuth,
					0,
				)
				return nil
			case 2:
				if !sameAuthenticatedReplica(
					authenticated[0],
					authenticated[1],
				) {
					result = newNormalAuthResult(
						OutcomeAmbiguousVolume,
						StageCapsuleStructure,
						2,
					)
					return nil
				}
			}

			selected := authenticated[0]
			if err := access.adoptVolumeKey(selected.volumeKey[:]); err != nil {
				return &capsuleAuthError{stage: StageUnwrap}
			}
			outcome := OutcomeSuccess
			stage := StageNone
			if authenticatedCount == 1 {
				outcome = OutcomeAuthenticatedDegraded
				stage = failedReplicaStage(structure, failedStages)
			}
			if !authenticatedCoreMatchesPreamble(
				selected.candidate.core,
				structure.Preamble(),
			) {
				outcome = OutcomeAuthenticatedDegraded
				stage = earlierAuthStage(stage, StagePreamble)
			}
			result = newNormalAuthResult(outcome, stage, authenticatedCount)
			result.candidate = selected.candidate
			result.geometry = selected.geometry
			return nil
		},
	)
	var owner *pcv3credential.Owner
	if ownerProvider, ok := provider.(capsuleOwnerProvider); ok {
		owner = ownerProvider.takeOwner()
	}
	if err != nil || callbackCalls != 1 {
		if owner != nil {
			owner.Close()
		}
		stage := StageKDFRuntime
		var authErr *capsuleAuthError
		if errors.As(err, &authErr) {
			stage = authErr.stage
		}
		return newNormalAuthResult(OutcomeOperationFailed, stage, 0)
	}
	if result == nil {
		if owner != nil {
			owner.Close()
		}
		return newNormalAuthResult(
			OutcomeOperationFailed,
			StageCredentialPolicy,
			0,
		)
	}
	if _, ownsCredential := provider.(capsuleOwnerProvider); ownsCredential {
		requiresOwner := result.outcome == OutcomeSuccess ||
			result.outcome == OutcomeAuthenticatedDegraded
		if requiresOwner != (owner != nil) {
			if owner != nil {
				owner.Close()
			}
			return newNormalAuthResult(
				OutcomeOperationFailed,
				StageUnwrap,
				0,
			)
		}
	}
	result.owner = owner
	if retainBorrower && (result.outcome == OutcomeSuccess || result.outcome == OutcomeAuthenticatedDegraded) {
		if borrower, ok := provider.(normalKeyBorrower); ok {
			result.keyBorrower = borrower
		}
	}
	return result
}

func credentialTupleForStructure(
	structure Structure,
) (credentialTuple, bool) {
	if structure.candidateCount == 0 || structure.candidateCount > 2 {
		return credentialTuple{}, false
	}
	first := structure.candidates[0]
	if !validAuthCandidate(first) {
		return credentialTuple{}, false
	}
	tuple := credentialTupleForCandidate(first)
	seenRoles := [2]bool{}
	seenRoles[first.Role()] = true
	for i := 1; i < int(structure.candidateCount); i++ {
		candidate := structure.candidates[i]
		if !validAuthCandidate(candidate) || seenRoles[candidate.Role()] ||
			credentialTupleForCandidate(candidate) != tuple {
			return credentialTuple{}, false
		}
		seenRoles[candidate.Role()] = true
	}
	return tuple, true
}

func credentialTupleForCandidate(candidate Candidate) credentialTuple {
	return credentialTuple{
		suite:          candidate.core.suite,
		credentialMode: candidate.credentialMode,
		keyfileMode:    candidate.keyfileMode,
		keyfileCount:   candidate.keyfileCount,
		kdfProfile:     candidate.kdfProfile,
		argonSalt:      candidate.argonSalt,
		volumeID:       candidate.core.volumeID,
	}
}

func validAuthCandidate(candidate Candidate) bool {
	return validLogicalCore(candidate.core) &&
		isSupportedCapsuleRole(candidate.Role()) &&
		validCredentialTuple(
			candidate.credentialMode,
			candidate.keyfileMode,
			candidate.keyfileCount,
		) &&
		candidate.reserved == [2]byte{} &&
		candidate.kdfProfile == kdfProfileForSuite(candidate.core.suite) &&
		(candidate.core.suite != SuiteStandard ||
			candidate.wrapSerpentIV == [16]byte{})
}

func authenticateCandidate(
	candidate Candidate,
	geometry Geometry,
	access capsuleCredentialAccess,
	seams capsuleAuthSeams,
) (*authenticatedCandidate, Stage, error) {
	verified := &authenticatedCandidate{
		candidate: candidate,
		geometry:  geometry,
	}
	success := false
	defer func() {
		if !success {
			verified.close()
		}
	}()

	wrapVerified := false
	err := access.withWrapKeys(
		candidate.Role(),
		func(keys *capsuleWrapKeys) error {
			message := wrapAuthMessage(candidate)
			valid, err := verifySuiteMAC(
				candidate.core.suite,
				keys.mac[:],
				message,
				candidate.wrapTag[:],
			)
			if err != nil || !valid {
				return err
			}
			wrapVerified = true
			switch candidate.core.suite {
			case SuiteStandard:
				return seams.unwrapStandard(
					verified.volumeKey[:],
					candidate.wrappedVolumeKey[:],
					keys.xChaCha20[:],
					candidate.wrapNonce[:],
				)
			case SuiteParanoid:
				return seams.unwrapParanoid(
					verified.volumeKey[:],
					candidate.wrappedVolumeKey[:],
					keys.xChaCha20[:],
					candidate.wrapNonce[:],
					keys.serpent[:],
					candidate.wrapSerpentIV[:],
				)
			default:
				return pcv3crypto.ErrPCV3StreamShape
			}
		},
	)
	if err != nil {
		var authErr *capsuleAuthError
		if errors.As(err, &authErr) {
			return nil, authErr.stage, authErr
		}
		if !wrapVerified {
			return nil, StageCredentialPolicy,
				&capsuleAuthError{stage: StageCredentialPolicy}
		}
		return nil, StageUnwrap,
			&capsuleAuthError{stage: StageUnwrap}
	}
	if !wrapVerified {
		return nil, StageWrapAuth, nil
	}

	replicaVerified := false
	err = access.withReplicaKey(
		candidate.Role(),
		verified.volumeKey[:],
		func(key []byte) error {
			message := replicaAuthMessage(candidate)
			valid, err := verifySuiteMAC(
				candidate.core.suite,
				key,
				message,
				candidate.replicaTag[:],
			)
			replicaVerified = valid
			return err
		},
	)
	if err != nil {
		var authErr *capsuleAuthError
		if errors.As(err, &authErr) {
			return nil, authErr.stage, authErr
		}
		return nil, StageCredentialPolicy,
			&capsuleAuthError{stage: StageCredentialPolicy}
	}
	if !replicaVerified {
		return nil, StageReplicaAuth, nil
	}
	success = true
	return verified, StageNone, nil
}

func sameAuthenticatedReplica(
	left, right *authenticatedCandidate,
) bool {
	if left == nil || right == nil {
		return false
	}
	if left.candidate.core != right.candidate.core ||
		left.candidate.credentialMode != right.candidate.credentialMode ||
		left.candidate.keyfileMode != right.candidate.keyfileMode ||
		left.candidate.kdfProfile != right.candidate.kdfProfile ||
		left.candidate.keyfileCount != right.candidate.keyfileCount ||
		left.candidate.argonSalt != right.candidate.argonSalt {
		return false
	}
	return subtle.ConstantTimeCompare(
		left.volumeKey[:],
		right.volumeKey[:],
	) == 1
}

func authenticatedCoreMatchesPreamble(
	core logicalCore,
	preamble Preamble,
) bool {
	return core.suite == preamble.suite &&
		core.featureFlags == preamble.featureFlags &&
		core.frontHeaderLength == preamble.frontHeaderLength
}

func failedReplicaStage(structure Structure, failed [2]Stage) Stage {
	stage := StageNone
	for i := range failed {
		if i >= int(structure.candidateCount) {
			break
		}
		stage = earlierAuthStage(stage, failed[i])
	}
	if structure.candidateCount == 1 {
		candidate := structure.candidates[0]
		component := ComponentBackup
		if candidate.Role() == CapsuleRoleBackup {
			component = ComponentPrimary
		}
		if issue, ok := structure.Issue(component); ok {
			stage = earlierAuthStage(stage, issue)
		} else {
			stage = earlierAuthStage(stage, StageCapsuleStructure)
		}
	}
	if stage == StageNone {
		return StageCapsuleStructure
	}
	return stage
}

func earlierAuthStage(left, right Stage) Stage {
	if left == StageNone {
		return right
	}
	if right == StageNone || authStageRank(left) <= authStageRank(right) {
		return left
	}
	return right
}

// authStageRank is the protocol order for nonterminal authenticated warnings.
// Stage declaration order is deliberately unrelated to this order.
func authStageRank(stage Stage) uint8 {
	switch stage {
	case StagePreamble:
		return 1
	case StageCapsuleRS:
		return 2
	case StageCapsuleStructure:
		return 3
	case StageWrapAuth:
		return 4
	case StageReplicaAuth:
		return 5
	case StageMetadata:
		return 6
	case StageTailGeometry:
		return 7
	default:
		return 255
	}
}

func logicalCoreBytes(core logicalCore) [96]byte {
	var encoded [96]byte
	copy(encoded[0:4], core.magic[:])
	binary.BigEndian.PutUint16(encoded[4:6], core.major)
	binary.BigEndian.PutUint16(encoded[6:8], core.schema)
	binary.BigEndian.PutUint16(encoded[8:10], uint16(core.suite))
	binary.BigEndian.PutUint16(encoded[10:12], core.featureFlags)
	binary.BigEndian.PutUint32(encoded[12:16], core.frontHeaderLength)
	copy(encoded[16:48], core.volumeID[:])
	encoded[48] = byte(core.payloadKind)
	encoded[49] = core.recordProfile
	encoded[50] = core.metadataProfile
	encoded[51] = core.reserved
	binary.BigEndian.PutUint64(encoded[52:60], core.plaintextLength)
	binary.BigEndian.PutUint64(encoded[60:68], core.recordCount)
	copy(encoded[68:84], core.xChaChaNoncePrefix[:])
	copy(encoded[84:92], core.serpentIVPrefix[:])
	binary.BigEndian.PutUint32(encoded[92:96], core.commentLength)
	return encoded
}

func capsulePrefixBytes(candidate Candidate) [96]byte {
	var encoded [96]byte
	encoded[0] = byte(candidate.role)
	encoded[1] = byte(candidate.credentialMode)
	encoded[2] = byte(candidate.keyfileMode)
	encoded[3] = byte(candidate.kdfProfile)
	binary.BigEndian.PutUint16(encoded[4:6], candidate.keyfileCount)
	copy(encoded[6:8], candidate.reserved[:])
	copy(encoded[8:24], candidate.argonSalt[:])
	copy(encoded[24:48], candidate.wrapNonce[:])
	copy(encoded[48:64], candidate.wrapSerpentIV[:])
	copy(encoded[64:96], candidate.wrappedVolumeKey[:])
	return encoded
}

func replicaAuthMessage(candidate Candidate) []byte {
	core := logicalCoreBytes(candidate.core)
	prefix := capsulePrefixBytes(candidate)
	message := make([]byte, 0, len(replicaDomain)+len(core)+len(prefix))
	message = append(message, replicaDomain...)
	message = append(message, core[:]...)
	message = append(message, prefix[:]...)
	return message
}

func wrapAuthMessage(candidate Candidate) []byte {
	core := logicalCoreBytes(candidate.core)
	prefix := capsulePrefixBytes(candidate)
	message := make(
		[]byte,
		0,
		len(wrapDomain)+len(core)+len(prefix)+len(candidate.replicaTag),
	)
	message = append(message, wrapDomain...)
	message = append(message, core[:]...)
	message = append(message, prefix[:]...)
	message = append(message, candidate.replicaTag[:]...)
	return message
}

func verifySuiteMAC(
	suite Suite,
	key, message, expected []byte,
) (bool, error) {
	if len(key) != 32 || len(expected) != pcv3crypto.MACSize {
		return false, errors.New("pcv3: invalid capsule MAC shape")
	}
	mac, err := pcv3crypto.NewMAC(key, suite == SuiteParanoid)
	if err != nil {
		return false, errors.New("pcv3: capsule MAC unavailable")
	}
	_, _ = mac.Write(message)
	actual := mac.Sum(nil)
	defer pcv3crypto.SecureZero(actual)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

// readerCredentialProvider is the production adapter. It has no injected KDF
// or root: all credential work remains in WithReaderCredential.
type readerCredentialProvider struct {
	factors  *pcv3credential.FactorRequest
	admitter pcv3credential.Admitter
	owner    *pcv3credential.Owner
	run      readerCredentialRunner
}

type readerCredentialRunner func(
	context.Context,
	*pcv3credential.ReaderCredentialRequest,
	pcv3credential.Admitter,
	Suite,
	func(capsuleCredentialAccess) error,
) (*pcv3credential.Owner, error)

func runReaderCredential(
	ctx context.Context,
	request *pcv3credential.ReaderCredentialRequest,
	admitter pcv3credential.Admitter,
	suite Suite,
	callback func(capsuleCredentialAccess) error,
) (*pcv3credential.Owner, error) {
	return pcv3credential.WithReaderCredential(
		ctx,
		request,
		admitter,
		func(reader *pcv3credential.ReaderCredential) error {
			return callback(&readerCredentialAccess{
				ctx:    ctx,
				suite:  suite,
				reader: reader,
			})
		},
	)
}

func (provider *readerCredentialProvider) withCredential(
	ctx context.Context,
	tuple credentialTuple,
	callback func(capsuleCredentialAccess) error,
) (returnErr error) {
	if provider == nil || callback == nil {
		return &capsuleAuthError{stage: StageCredentialPolicy}
	}
	claimedPolicy, _ := credentialFactorPolicy(tuple.credentialMode)
	request := &pcv3credential.ReaderCredentialRequest{
		Suite:         credentialSuite(tuple.suite),
		ProfileID:     uint8(tuple.kdfProfile),
		Factors:       provider.factors,
		ClaimedPolicy: claimedPolicy,
		ArgonSalt:     append([]byte(nil), tuple.argonSalt[:]...),
		VolumeID:      append([]byte(nil), tuple.volumeID[:]...),
	}
	provider.factors = nil
	defer func() {
		if request.Factors == nil {
			return
		}
		if err := request.Factors.Close(); err != nil && returnErr == nil {
			returnErr = &capsuleAuthError{stage: StageCredentialPolicy}
		}
		request.Factors = nil
	}()

	callbackSucceeded := false
	var callbackErr error
	run := provider.run
	if run == nil {
		run = runReaderCredential
	}
	owner, err := run(
		ctx,
		request,
		provider.admitter,
		tuple.suite,
		func(access capsuleCredentialAccess) error {
			callbackErr = callback(access)
			callbackSucceeded = callbackErr == nil
			return callbackErr
		},
	)
	if owner != nil {
		provider.owner = owner
		return nil
	}
	if callbackErr != nil {
		return callbackErr
	}
	if callbackSucceeded && expectedMissingOwner(err) {
		// Authentication failure intentionally performs no adoption, so the
		// staged credential owner reports no final Owner. The typed capsule
		// result already carries the normative failure.
		return nil
	}
	return &capsuleAuthError{stage: credentialPipelineStage(err)}
}

func credentialFactorPolicy(
	mode CredentialMode,
) (pcv3credential.FactorPolicy, bool) {
	switch mode {
	case CredentialModePassword:
		return pcv3credential.FactorPolicyPasswordOnly, true
	case CredentialModeKeyfiles:
		return pcv3credential.FactorPolicyKeyfilesOnly, true
	case CredentialModeCombined:
		return pcv3credential.FactorPolicyPasswordAndKeyfiles, true
	default:
		return 0, false
	}
}

func expectedMissingOwner(err error) bool {
	var pipelineErr *pcv3credential.PipelineError
	return errors.As(err, &pipelineErr) &&
		pipelineErr.Code == pcv3credential.PipelineErrorOwner &&
		pipelineErr.Stage == pcv3credential.PipelineStageOwner
}

func credentialPipelineStage(err error) Stage {
	var pipelineErr *pcv3credential.PipelineError
	if !errors.As(err, &pipelineErr) {
		return StageKDFRuntime
	}
	switch pipelineErr.Code {
	case pcv3credential.PipelineErrorCancelled:
		return StageCancellation
	case pcv3credential.PipelineErrorInvalidRequest,
		pcv3credential.PipelineErrorFactors,
		pcv3credential.PipelineErrorTranscript,
		pcv3credential.PipelineErrorSchedule,
		pcv3credential.PipelineErrorAdmission:
		return StageCredentialPolicy
	default:
		return StageKDFRuntime
	}
}

func (provider *readerCredentialProvider) close() {
	if provider == nil {
		return
	}
	if provider.factors != nil {
		_ = provider.factors.Close()
		provider.factors = nil
	}
	if provider.owner != nil {
		provider.owner.Close()
		provider.owner = nil
	}
}

func (provider *readerCredentialProvider) takeOwner() *pcv3credential.Owner {
	if provider == nil {
		return nil
	}
	owner := provider.owner
	provider.owner = nil
	return owner
}

type readerCredentialAccess struct {
	ctx    context.Context
	suite  Suite
	reader *pcv3credential.ReaderCredential
}

func (access *readerCredentialAccess) withWrapKeys(
	role CapsuleRole,
	callback func(*capsuleWrapKeys) error,
) error {
	credentialRole, ok := credentialRole(role)
	if access == nil || access.ctx == nil || access.reader == nil || !ok || callback == nil {
		return &capsuleAuthError{stage: StageCredentialPolicy}
	}
	var keys capsuleWrapKeys
	defer keys.close()
	var callbackErr error
	err := access.reader.WithKeys(
		access.ctx,
		credentialRole,
		func(borrowed *pcv3credential.ReaderKeys) error {
			if err := borrowed.CopyKey(pcv3credential.KeyRequest{
				Label:       pcv3credential.KeyLabelCredentialWrapXChaCha20,
				Role:        credentialRole,
				OutputBytes: 32,
			}, keys.xChaCha20[:]); err != nil {
				return err
			}
			if err := borrowed.CopyKey(pcv3credential.KeyRequest{
				Label:       pcv3credential.KeyLabelCredentialWrapMAC,
				Role:        credentialRole,
				OutputBytes: 32,
			}, keys.mac[:]); err != nil {
				return err
			}
			if access.readerSuiteIsParanoid() {
				if err := borrowed.CopyKey(pcv3credential.KeyRequest{
					Label:       pcv3credential.KeyLabelCredentialWrapSerpent,
					Role:        credentialRole,
					OutputBytes: 32,
				}, keys.serpent[:]); err != nil {
					return err
				}
			}
			callbackErr = callback(&keys)
			return callbackErr
		},
	)
	if callbackErr != nil {
		return callbackErr
	}
	if err != nil {
		if access.ctx.Err() != nil {
			return &capsuleAuthError{stage: StageCancellation}
		}
		return &capsuleAuthError{stage: StageCredentialPolicy}
	}
	return nil
}

func (access *readerCredentialAccess) withReplicaKey(
	role CapsuleRole,
	volumeKey []byte,
	callback func([]byte) error,
) error {
	credentialRole, ok := credentialRole(role)
	if access == nil || access.ctx == nil || access.reader == nil || !ok || callback == nil {
		return &capsuleAuthError{stage: StageCredentialPolicy}
	}
	var key [32]byte
	defer pcv3crypto.SecureZero(key[:])
	var callbackErr error
	err := access.reader.WithReplicaKey(
		access.ctx,
		credentialRole,
		volumeKey,
		func(borrowed *pcv3credential.ReaderKeys) error {
			if err := borrowed.CopyKey(pcv3credential.KeyRequest{
				Label:       pcv3credential.KeyLabelVolumeReplicaMAC,
				Role:        credentialRole,
				OutputBytes: 32,
			}, key[:]); err != nil {
				return err
			}
			callbackErr = callback(key[:])
			return callbackErr
		},
	)
	if callbackErr != nil {
		return callbackErr
	}
	if err != nil {
		if access.ctx.Err() != nil {
			return &capsuleAuthError{stage: StageCancellation}
		}
		return &capsuleAuthError{stage: StageCredentialPolicy}
	}
	return nil
}

func (access *readerCredentialAccess) adoptVolumeKey(transfer []byte) error {
	if access == nil || access.reader == nil {
		pcv3crypto.SecureZero(transfer)
		return &capsuleAuthError{stage: StageCredentialPolicy}
	}
	return access.reader.AdoptVolumeKey(transfer)
}

func (access *readerCredentialAccess) readerSuiteIsParanoid() bool {
	return access != nil && access.suite == SuiteParanoid
}

func credentialSuite(suite Suite) pcv3credential.Suite {
	if suite == SuiteParanoid {
		return pcv3credential.SuiteParanoid1
	}
	return pcv3credential.SuiteStandard1
}

func credentialRole(role CapsuleRole) (pcv3credential.KeyRole, bool) {
	switch role {
	case CapsuleRolePrimary:
		return pcv3credential.KeyRolePrimary, true
	case CapsuleRoleBackup:
		return pcv3credential.KeyRoleBackup, true
	default:
		return 0, false
	}
}
