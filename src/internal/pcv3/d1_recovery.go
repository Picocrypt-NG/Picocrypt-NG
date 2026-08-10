package pcv3

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"errors"
	"io"

	pcv3crypto "Picocrypt-NG/internal/crypto"
)

// D1RecoveryOutput receives D1 semantic provenance and a callback-scoped
// emitter. The physical D1 role is never interchangeable with a capsule role.
type D1RecoveryOutput func(*RecoveryResult, D1BootstrapRole, RecoveryEmitter) error

// RecoverD1 executes an explicitly routed normal or Force D1 recovery. It is
// internal to this module tree and is not connected to a public frontend.
func RecoverD1(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	factors *pcv3credential.FactorRequest,
	admitter pcv3credential.Admitter,
	mode RecoveryMode,
	output D1RecoveryOutput,
) (*RecoveryResult, error) {
	request, err := newD1RecoveryRequest(mode)
	if err != nil {
		closeRecoveryFactors(factors)
		return recoveryOperationFailure(StageCredentialPolicy),
			&recoveryEngineError{stage: StageCredentialPolicy}
	}
	return recoverD1WithRequest(
		ctx,
		source,
		sourceSize,
		factors,
		admitter,
		request,
		output,
	)
}

// RecoverD1Unverified executes D1 Force under one live exact physical-role
// authority. The authority expires before this function returns.
func RecoverD1Unverified(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	factors *pcv3credential.FactorRequest,
	admitter pcv3credential.Admitter,
	role D1BootstrapRole,
	output D1RecoveryOutput,
) (result *RecoveryResult, resultErr error) {
	err := withUnverifiedD1RecoveryRequest(role, func(request d1RecoveryRequest) error {
		result, resultErr = recoverD1WithRequest(
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
		return recoveryOperationFailure(StageCredentialPolicy),
			&recoveryEngineError{stage: StageCredentialPolicy}
	}
	return result, resultErr
}

func recoverD1WithRequest(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	factors *pcv3credential.FactorRequest,
	admitter pcv3credential.Admitter,
	request d1RecoveryRequest,
	output D1RecoveryOutput,
) (*RecoveryResult, error) {
	if ctx == nil || source == nil || sourceSize < 0 || factors == nil || admitter == nil ||
		!request.valid() || output == nil {
		closeRecoveryFactors(factors)
		return recoveryOperationFailure(StageCredentialPolicy),
			&recoveryEngineError{stage: StageCredentialPolicy}
	}
	if sourceSize < int64(d1BootstrapLength+d1OuterPrefixLength+d1OuterTagSize) {
		closeRecoveryFactors(factors)
		return newD1ForceTerminalResult(OutcomeCredentialsOrDamage, StageD1Bootstrap)
	}
	if err := ctx.Err(); err != nil {
		closeRecoveryFactors(factors)
		return recoveryOperationFailure(StageCancellation),
			&recoveryEngineError{stage: StageCancellation}
	}

	var frontRaw, tailRaw [d1BootstrapLength]byte
	defer pcv3crypto.SecureZero(frontRaw[:])
	defer pcv3crypto.SecureZero(tailRaw[:])
	if _, err := readExactAt(source, 0, frontRaw[:], StagePreamble); err != nil {
		closeRecoveryFactors(factors)
		return d1BootstrapReadResult(err)
	}
	if err := ctx.Err(); err != nil {
		closeRecoveryFactors(factors)
		return recoveryOperationFailure(StageCancellation),
			&recoveryEngineError{stage: StageCancellation}
	}
	front, err := parseD1Bootstrap(frontRaw[:], D1BootstrapFront)
	if err != nil {
		closeRecoveryFactors(factors)
		return newD1ForceTerminalResult(OutcomeCredentialsOrDamage, StageD1Bootstrap)
	}
	var tail d1BootstrapCandidate
	if request.mode != RecoveryModeNormalV3 {
		tailOffset := sourceSize - d1BootstrapLength
		if _, err := readExactAt(source, tailOffset, tailRaw[:], StagePreamble); err != nil {
			closeRecoveryFactors(factors)
			return d1BootstrapReadResult(err)
		}
		tail, err = parseD1Bootstrap(tailRaw[:], D1BootstrapTail)
		if err != nil {
			closeRecoveryFactors(factors)
			return newD1ForceTerminalResult(OutcomeCredentialsOrDamage, StageD1Bootstrap)
		}
	}
	defer clearD1BootstrapCandidate(&front)
	defer clearD1BootstrapCandidate(&tail)

	var result *RecoveryResult
	var resultErr error
	factorErr := pcv3credential.WithValidatedFactors(
		ctx,
		factors,
		func(validated *pcv3credential.ValidatedFactors) error {
			transcript, err := pcv3credential.NewCanonicalTranscript(validated)
			if err != nil {
				return err
			}
			defer transcript.Close()
			normalInput, outerInput, err := pcv3credential.NewD1CredentialInputs(transcript)
			if err != nil {
				return err
			}
			defer normalInput.Close()
			defer outerInput.Close()

			return withD1RecoveryCredentialCandidate(
				ctx,
				outerInput,
				front,
				admitter,
				request,
				func(frontCandidate *d1ForceCandidate) error {
					var frontAnalysis *d1ForceCandidateAnalysis
					if request.mode == RecoveryModeNormalV3 {
						var selection d1ForceSelection
						var selected bool
						var selectionErr error
						frontAnalysis, selection, selected, selectionErr = selectNormalD1Front(
							ctx,
							source,
							sourceSize,
							frontCandidate,
						)
						if selectionErr != nil {
							return selectionErr
						}
						if selected {
							result, resultErr = recoverD1Selection(
								ctx,
								source,
								sourceSize,
								validated,
								normalInput,
								admitter,
								request,
								selection,
								defaultD1ForceSeams(),
								output,
							)
							return resultErr
						}
					}
					if request.mode == RecoveryModeNormalV3 {
						tailOffset := sourceSize - d1BootstrapLength
						if _, err := readExactAt(source, tailOffset, tailRaw[:], StagePreamble); err != nil {
							result, resultErr = d1BootstrapReadResult(err)
							return resultErr
						}
						var err error
						tail, err = parseD1Bootstrap(tailRaw[:], D1BootstrapTail)
						if err != nil {
							result, resultErr = newD1ForceTerminalResult(
								OutcomeCredentialsOrDamage,
								StageD1Bootstrap,
							)
							return resultErr
						}
					}

					return withD1RecoveryCredentialCandidate(
						ctx,
						outerInput,
						tail,
						admitter,
						request,
						func(tailCandidate *d1ForceCandidate) error {
							candidates := usableD1RecoveryCandidates(
								sourceSize,
								frontCandidate,
								tailCandidate,
							)
							if len(candidates) == 0 {
								result, resultErr = newD1ForceTerminalResult(
									OutcomeCredentialsOrDamage,
									StageD1Bootstrap,
								)
								return resultErr
							}
							result, resultErr = recoverD1Candidates(
								ctx,
								source,
								sourceSize,
								validated,
								normalInput,
								admitter,
								request,
								candidates,
								frontAnalysis,
								output,
							)
							return resultErr
						},
					)
				},
			)
		},
	)
	if resultErr != nil {
		return result, resultErr
	}
	if factorErr != nil {
		if result != nil {
			result.Close()
		}
		stage := d1CredentialFailureStage(ctx, factorErr)
		return recoveryOperationFailure(stage), &recoveryEngineError{stage: stage}
	}
	if result == nil {
		return recoveryOperationFailure(StageCredentialPolicy),
			&recoveryEngineError{stage: StageCredentialPolicy}
	}
	return result, nil
}

func d1BootstrapReadResult(err error) (*RecoveryResult, error) {
	var failure Failure
	if errors.As(err, &failure) && failure.Outcome() == OutcomeOperationFailed {
		return recoveryResultForError(err)
	}
	return newD1ForceTerminalResult(OutcomeCredentialsOrDamage, StageD1Bootstrap)
}

func withD1RecoveryCandidate(
	ctx context.Context,
	bootstrap d1BootstrapCandidate,
	owner *pcv3credential.D1OuterCredentialOwner,
	request d1RecoveryRequest,
	callback func(*d1ForceCandidate) error,
) error {
	if ctx == nil || owner == nil || !request.valid() || callback == nil {
		return errInvalidD1Force
	}
	if request.mode != RecoveryModeNormalV3 {
		return bindD1ForceCandidateWithAccess(
			ctx,
			bootstrap,
			&d1BootstrapOwnerAccess{owner: owner},
			defaultD1BootstrapAuthSeams(),
			callback,
		)
	}
	attempt := authenticateD1Bootstrap(ctx, bootstrap, owner)
	if attempt == nil {
		return errInvalidD1Force
	}
	defer attempt.Close()
	if attempt.Outcome() == OutcomeCredentialsOrDamage {
		return callback(nil)
	}
	if attempt.Outcome() != OutcomeSuccess || attempt.authenticated == nil {
		return newD1OuterFailure(attempt.Stage(), errInvalidD1Force)
	}
	secret := attempt.authenticated.takeSecret()
	if secret == nil || secret.keys == nil || secret.bodyLength == 0 {
		if secret != nil {
			secret.Close()
		}
		return errInvalidD1Force
	}
	candidate := &d1ForceCandidate{
		role:            bootstrap.role,
		bootstrap:       bootstrap,
		bootstrapKnown:  true,
		bodyLength:      secret.bodyLength,
		secret:          secret,
		wrapVerified:    true,
		replicaVerified: true,
	}
	defer candidate.Close()
	return callback(candidate)
}

func withD1RecoveryCredentialCandidate(
	ctx context.Context,
	outerInput *pcv3credential.CredentialInputOuter,
	bootstrap d1BootstrapCandidate,
	admitter pcv3credential.Admitter,
	request d1RecoveryRequest,
	callback func(*d1ForceCandidate) error,
) error {
	if ctx == nil || outerInput == nil || admitter == nil || !request.valid() || callback == nil {
		return errInvalidD1Force
	}
	if !validD1BootstrapRole(bootstrap.role) {
		return errInvalidD1Force
	}
	role := keyRoleForD1Bootstrap(bootstrap.role)
	return pcv3credential.WithD1OuterCredentialOwner(
		ctx,
		outerInput,
		bootstrap.argonSalt[:],
		role,
		admitter,
		func(owner *pcv3credential.D1OuterCredentialOwner) error {
			return withD1RecoveryCandidate(ctx, bootstrap, owner, request, callback)
		},
	)
}

func selectNormalD1Front(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	front *d1ForceCandidate,
) (*d1ForceCandidateAnalysis, d1ForceSelection, bool, error) {
	var selection d1ForceSelection
	if front == nil || !front.valid() {
		return nil, selection, false, nil
	}
	window, err := deriveD1ForceBodyWindow(sourceSize, front.bodyLength, front.role)
	if err != nil {
		return nil, selection, false, nil //nolint:nilerr // Invalid front geometry is candidate damage; normal recovery must still try the tail.
	}
	analysis, err := analyzeD1ForceCandidate(
		ctx,
		source,
		window,
		front,
		defaultD1ForceSeams(),
	)
	if err != nil {
		return nil, selection, false, err
	}
	if !normalD1Geometry(sourceSize, front.bodyLength) || !analysis.outerFullyAuthenticated {
		return analysis, selection, false, nil
	}
	selection = d1ForceSelection{
		analysis:         analysis,
		provenance:       D1BootstrapProvenanceFront,
		bootstrapHealthy: canonicalD1Geometry(sourceSize, front.bodyLength),
		outerHealthy:     true,
	}
	return analysis, selection, true, nil
}

func fullyAuthenticatedD1Candidate(candidate *d1ForceCandidate) bool {
	return candidate != nil && candidate.valid() &&
		candidate.wrapVerified && candidate.replicaVerified
}

func usableD1RecoveryCandidates(
	sourceSize int64,
	candidates ...*d1ForceCandidate,
) []*d1ForceCandidate {
	usable := make([]*d1ForceCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == nil || !candidate.valid() {
			continue
		}
		_, err := deriveD1ForceBodyWindow(
			sourceSize,
			candidate.bodyLength,
			candidate.role,
		)
		if err != nil {
			continue
		}
		if _, err := parseD1OuterGeometry(candidate.bodyLength); err != nil {
			continue
		}
		usable = append(usable, candidate)
	}
	return usable
}

func recoverD1Candidates(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	validated *pcv3credential.ValidatedFactors,
	normalInput *pcv3credential.CredentialInputNormal,
	admitter pcv3credential.Admitter,
	request d1RecoveryRequest,
	candidates []*d1ForceCandidate,
	preanalyzed *d1ForceCandidateAnalysis,
	output D1RecoveryOutput,
) (*RecoveryResult, error) {
	seams := defaultD1ForceSeams()
	selection, terminal, err := selectD1ForceCandidateWithPreanalysis(
		ctx,
		source,
		sourceSize,
		request,
		candidates,
		seams,
		preanalyzed,
	)
	if err != nil {
		return d1OperationResult(ctx, err)
	}
	if terminal != nil {
		return terminal, err
	}
	return recoverD1Selection(
		ctx,
		source,
		sourceSize,
		validated,
		normalInput,
		admitter,
		request,
		selection,
		seams,
		output,
	)
}

func recoverD1Selection(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	validated *pcv3credential.ValidatedFactors,
	normalInput *pcv3credential.CredentialInputNormal,
	admitter pcv3credential.Admitter,
	request d1RecoveryRequest,
	selection d1ForceSelection,
	seams d1ForceSeams,
	output D1RecoveryOutput,
) (*RecoveryResult, error) {
	if selection.analysis == nil || selection.analysis.candidate == nil {
		return d1OperationResult(ctx, errInvalidD1Force)
	}
	if request.mode == RecoveryModeNormalV3 {
		if !normalD1Geometry(sourceSize, selection.analysis.candidate.bodyLength) ||
			!selection.analysis.outerFullyAuthenticated {
			return newD1RecoveryResult(
				OutcomeAuthenticationFailed,
				ForceProvenanceNone,
				StageD1Body,
				selection.provenance,
				StageNone,
				0,
				nil,
				0,
			)
		}
	}

	invoke := func() (*RecoveryResult, error) {
		return recoverD1Inner(
			ctx,
			source,
			sourceSize,
			validated,
			normalInput,
			admitter,
			request,
			selection,
			seams,
			output,
		)
	}
	if !selection.requiresRawAuthority {
		return invoke()
	}
	var result *RecoveryResult
	var resultErr error
	authorityErr := request.withRawOuterAuthority(selection.analysis.candidate.role, func() error {
		result, resultErr = invoke()
		return resultErr
	})
	if resultErr != nil {
		return result, resultErr
	}
	if authorityErr != nil {
		if result != nil {
			result.Close()
		}
		return d1OperationResult(ctx, authorityErr)
	}
	if result == nil {
		return d1OperationResult(ctx, errInvalidD1Force)
	}
	return result, nil
}

func normalD1Geometry(sourceSize int64, bodyLength uint64) bool {
	single, ok := checkedAdd64(uint64(d1BootstrapLength), bodyLength)
	if !ok {
		return false
	}
	canonical, ok := checkedAdd64(uint64(d1BootstrapLength), single)
	if !ok {
		return false
	}
	return uint64(sourceSize) == single || uint64(sourceSize) == canonical //nolint:gosec // D1 entry rejects negative sizes.
}

func canonicalD1Geometry(sourceSize int64, bodyLength uint64) bool {
	if sourceSize < 0 {
		return false
	}
	size, ok := checkedAdd64(bodyLength, 2*uint64(d1BootstrapLength))
	return ok && uint64(sourceSize) == size //nolint:gosec // The negative size guard proves this conversion.
}

func resolveD1InnerRecoveryAnalyses(
	structure RecoveryStructure,
	analyses []forceCandidateAnalysis,
) (forceResolution, []forceCandidateAnalysis, recoveryRequest, error) {
	var empty forceResolution
	if structure.CandidateCount() < 1 || structure.CandidateCount() > 2 ||
		len(analyses) != structure.CandidateCount() {
		return empty, nil, recoveryRequest{}, errInvalidForceAnalysis
	}
	normalRequest, err := newRecoveryRequest(RecoveryModeNormalV3)
	if err != nil {
		return empty, nil, recoveryRequest{}, err
	}
	forceRequest, err := newRecoveryRequest(RecoveryModeForce)
	if err != nil {
		return empty, nil, recoveryRequest{}, err
	}

	ordinary := make([]forceCandidateAnalysis, 0, len(analyses))
	for _, analysis := range analyses {
		if !analysis.wrapVerified || !analysis.replicaValid {
			continue
		}
		candidate := analysis
		if candidate.candidate.Role() == CapsuleRoleBackup {
			candidate.damageStage = earlierRecoveryDamageStage(
				candidate.damageStage,
				structure.primaryDamage,
			)
		}
		ordinary = append(ordinary, candidate)
	}
	ordinaryResolution, err := resolveNormalRecoveryCandidates(ordinary)
	if err != nil {
		return empty, nil, recoveryRequest{}, err
	}
	if ordinaryResolution.selected >= 0 ||
		(ordinaryResolution.result.Outcome() != OutcomeAuthenticationFailed &&
			ordinaryResolution.result.Outcome() != OutcomeCredentialsOrDamage) {
		return ordinaryResolution, ordinary, normalRequest, nil
	}

	forceResolution, err := resolveForceCandidates(forceRequest, analyses)
	if err != nil {
		ordinaryResolution.result.Close()
		return empty, nil, recoveryRequest{}, err
	}
	if forceResolution.selected < 0 && forceResolution.result.Outcome() != OutcomeAmbiguousVolume {
		forceResolution.result.Close()
		return ordinaryResolution, ordinary, normalRequest, nil
	}
	ordinaryResolution.result.Close()
	return forceResolution, analyses, forceRequest, nil
}

func recoverD1Inner(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	validated *pcv3credential.ValidatedFactors,
	normalInput *pcv3credential.CredentialInputNormal,
	admitter pcv3credential.Admitter,
	request d1RecoveryRequest,
	selection d1ForceSelection,
	seams d1ForceSeams,
	output D1RecoveryOutput,
) (*RecoveryResult, error) {
	inner, err := openD1SelectedInner(ctx, source, sourceSize, request, selection, seams)
	if err != nil {
		return d1InnerUnavailableResult(
			ctx,
			source,
			request,
			selection,
			seams,
			err,
			output,
		)
	}
	defer inner.Close()
	structure, err := InspectRecovery(inner, inner.Size())
	if err != nil {
		if d1InnerOuterAuthenticationUnavailable(request, err) {
			return d1InnerUnavailableResult(
				ctx,
				source,
				request,
				selection,
				seams,
				err,
				output,
			)
		}
		innerResult, innerErr := recoveryResultForError(err)
		if innerResult == nil {
			return d1OperationResult(ctx, innerErr)
		}
		defer innerResult.Close()
		mapped, mapErr := mapD1ForceInnerResult(selection, innerResult)
		if mapErr != nil {
			return nil, mapErr
		}
		if innerErr != nil {
			return mapped, innerErr
		}
		return maybeEmitD1RawOuter(
			ctx,
			source,
			request,
			selection,
			seams,
			mapped,
			nil,
			output,
		)
	}
	tuples, tupleIndexes, ok := recoveryCredentialTuples(structure)
	if !ok {
		return nil, errInvalidD1Force
	}
	innerRequest, err := newRecoveryRequest(RecoveryModeNormalV3)
	if err != nil {
		return nil, err
	}
	var innerSelection recoverySelection
	var selectionErr error
	owner, credentialErr := pcv3credential.WithD1RecoveryCredentialSession(
		ctx,
		normalInput,
		validated,
		tuples,
		admitter,
		func(session *pcv3credential.RecoverySession) error {
			if request.mode == RecoveryModeNormalV3 {
				innerSelection, selectionErr = selectRecoveryWithSession(
					ctx,
					inner,
					structure,
					tupleIndexes,
					session,
					innerRequest,
				)
				return selectionErr
			}
			forceRequest, requestErr := newRecoveryRequest(RecoveryModeForce)
			if requestErr != nil {
				selectionErr = requestErr
				return selectionErr
			}
			analyses, analysisErr := analyzeRecoveryCandidatesWithSession(
				ctx,
				inner,
				structure,
				tupleIndexes,
				session,
				forceRequest,
			)
			if analysisErr != nil {
				selectionErr = analysisErr
				return selectionErr
			}
			resolution, resolved, resolvedRequest, resolveErr := resolveD1InnerRecoveryAnalyses(structure, analyses)
			if resolveErr != nil {
				selectionErr = resolveErr
				return selectionErr
			}
			innerRequest = resolvedRequest
			innerSelection, selectionErr = selectRecoveryAnalysis(session, resolved, resolution)
			return selectionErr
		},
	)
	if selectionErr != nil {
		if owner != nil {
			owner.Close()
		}
		if d1InnerOuterAuthenticationUnavailable(request, selectionErr) {
			return d1InnerUnavailableResult(
				ctx,
				source,
				request,
				selection,
				seams,
				selectionErr,
				output,
			)
		}
		innerResult, innerErr := recoveryResultForError(selectionErr)
		if innerResult == nil {
			return d1OperationResult(ctx, innerErr)
		}
		defer innerResult.Close()
		mapped, mapErr := mapD1ForceInnerResult(selection, innerResult)
		if mapErr != nil {
			return nil, mapErr
		}
		if innerErr != nil {
			return mapped, innerErr
		}
		return maybeEmitD1RawOuter(
			ctx,
			source,
			request,
			selection,
			seams,
			mapped,
			nil,
			output,
		)
	}
	if credentialErr != nil {
		if owner != nil {
			owner.Close()
		}
		stage := d1CredentialFailureStage(ctx, credentialErr)
		return recoveryOperationFailure(stage), &recoveryEngineError{stage: stage}
	}
	if innerSelection.resolution.result == nil {
		if owner != nil {
			owner.Close()
		}
		return nil, errInvalidD1Force
	}
	innerResult := innerSelection.resolution.result
	defer innerResult.Close()
	mapped, err := mapD1ForceInnerResult(selection, innerResult)
	if err != nil {
		if owner != nil {
			owner.Close()
		}
		return nil, err
	}
	if innerSelection.resolution.selected < 0 {
		if owner != nil {
			owner.Close()
		}
		return maybeEmitD1RawOuter(
			ctx,
			source,
			request,
			selection,
			seams,
			mapped,
			nil,
			output,
		)
	}
	if owner == nil {
		mapped.Close()
		return recoveryOperationFailure(StageUnwrap),
			&recoveryEngineError{stage: StageUnwrap}
	}
	defer owner.Close()
	returned, emitErr := emitRecoverySelection(
		ctx,
		inner,
		innerRequest,
		innerSelection,
		owner,
		mapped,
		func(result *RecoveryResult, emitter RecoveryEmitter) error {
			return output(result, selection.analysis.candidate.role, emitter)
		},
	)
	if returned != mapped {
		mapped.Close()
	}
	return returned, emitErr
}

func openD1SelectedInner(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	request d1RecoveryRequest,
	selection d1ForceSelection,
	seams d1ForceSeams,
) (*d1InnerReader, error) {
	if selection.analysis == nil || selection.analysis.candidate == nil {
		return nil, errInvalidD1Force
	}
	if request.mode != RecoveryModeNormalV3 {
		return newD1ForceInnerReader(ctx, source, request, selection.analysis, seams)
	}
	return newD1InnerReaderFromCompleteAnalysis(ctx, source, sourceSize, selection.analysis)
}

func d1InnerUnavailableResult(
	ctx context.Context,
	source io.ReaderAt,
	request d1RecoveryRequest,
	selection d1ForceSelection,
	seams d1ForceSeams,
	cause error,
	output D1RecoveryOutput,
) (*RecoveryResult, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return d1OperationResult(ctx, err)
		}
	}
	if stage, ok := d1OperationalStage(ctx, cause); ok &&
		(stage == StageCancellation || !d1InnerOuterAuthenticationUnavailable(request, cause)) {
		return d1OperationResult(ctx, cause)
	}
	if cause != nil && !isD1OuterAuthenticationFailure(cause) {
		return d1OperationResult(ctx, cause)
	}
	outcome := OutcomeAuthenticationFailed
	if request.mode == RecoveryModeNormalV3 {
		outcome = OutcomeCredentialsOrDamage
	}
	result, err := newD1RecoveryResult(
		outcome,
		ForceProvenanceNone,
		StageD1Body,
		selection.provenance,
		StageNone,
		0,
		nil,
		0,
	)
	if err != nil {
		return nil, err
	}
	return maybeEmitD1RawOuter(
		ctx,
		source,
		request,
		selection,
		seams,
		result,
		cause,
		output,
	)
}

func d1InnerOuterAuthenticationUnavailable(request d1RecoveryRequest, err error) bool {
	return (request.mode == RecoveryModeForce || request.mode == RecoveryModeForceUnverified) &&
		isD1OuterAuthenticationFailure(err)
}

func isD1OuterAuthenticationFailure(err error) bool {
	var failure *d1OuterFailure
	return errors.As(err, &failure) && failure.Stage() == StageD1Body &&
		errors.Is(err, errD1OuterAuthentication)
}

func maybeEmitD1RawOuter(
	ctx context.Context,
	source io.ReaderAt,
	request d1RecoveryRequest,
	selection d1ForceSelection,
	seams d1ForceSeams,
	fallback *RecoveryResult,
	cause error,
	output D1RecoveryOutput,
) (*RecoveryResult, error) {
	if fallback == nil ||
		(request.mode != RecoveryModeForce && request.mode != RecoveryModeForceUnverified) ||
		!d1RawFallbackOutcome(fallback.outcome) ||
		(request.mode == RecoveryModeForce && selection.outerHealthy &&
			!d1InnerOuterAuthenticationUnavailable(request, cause)) {
		return fallback, nil
	}
	raw, err := analyzeD1RawOuter(ctx, source, request, selection, seams)
	if err != nil {
		fallback.Close()
		if _, operational := d1OperationalStage(ctx, err); operational {
			return d1OperationResult(ctx, err)
		}
		return nil, err
	}
	if raw == nil {
		return fallback, nil
	}
	fallback.Close()
	returned, emitErr := emitD1RawOuter(
		ctx,
		source,
		request,
		selection,
		seams,
		raw,
		output,
	)
	if returned != raw {
		raw.Close()
	}
	return returned, emitErr
}

func d1RawFallbackOutcome(outcome Outcome) bool {
	return outcome == OutcomeInvalidStructurePreKDF ||
		outcome == OutcomeCredentialsOrDamage ||
		outcome == OutcomeAuthenticationFailed
}

func analyzeD1RawOuter(
	ctx context.Context,
	source io.ReaderAt,
	request d1RecoveryRequest,
	selection d1ForceSelection,
	seams d1ForceSeams,
) (*RecoveryResult, error) {
	analysis := selection.analysis
	if ctx == nil || source == nil || analysis == nil || analysis.candidate == nil ||
		(request.mode != RecoveryModeForce && request.mode != RecoveryModeForceUnverified) ||
		seams.authenticateRecord == nil {
		return nil, errInvalidD1Force
	}
	codec, err := newD1OuterCodec(ctx, analysis.candidate)
	if err != nil {
		return nil, err
	}
	defer codec.Close()
	body := io.NewSectionReader(source, analysis.bodyWindow.offset, analysis.bodyWindow.length)
	ciphertext := make([]byte, d1OuterChunkSize)
	defer pcv3crypto.SecureZero(ciphertext)
	var tag [d1OuterTagSize]byte
	defer pcv3crypto.SecureZero(tag[:])
	ranges := make([]RecoveryRange, 0)
	hasVerified := false
	hasUnverified := false
	hasDamage := false
	final := RecoveryFinalMissing
	for index := range analysis.geometry.recordCount {
		expected, err := expectedD1OuterRecord(analysis.geometry, index)
		if err != nil {
			return nil, err
		}
		loaded, loadedTag, loadErr := loadD1OuterRecord(
			ctx,
			body,
			expected,
			ciphertext,
			tag[:],
		)
		missing := d1OuterRecordMissing(loadErr)
		if loadErr != nil && !missing {
			return nil, loadErr
		}
		state := RecoveryRangeVerified
		finalState := RecoveryFinalVerified
		if missing {
			state = RecoveryRangeMissing
			finalState = RecoveryFinalMissing
			hasDamage = true
		} else {
			authErr := seams.authenticateRecord(
				analysis.candidate,
				codec,
				ctx,
				expected.index,
				expected.final,
				loaded,
				loadedTag,
			)
			if authErr != nil {
				if !errors.Is(authErr, errD1OuterAuthentication) {
					return nil, authErr
				}
				rawAuthorized := request.withRawOuterAuthority(
					analysis.candidate.role,
					func() error { return nil },
				) == nil
				if rawAuthorized {
					state = RecoveryRangeUnverified
					finalState = RecoveryFinalUnverified
					hasUnverified = true
				} else {
					state = RecoveryRangeMissing
					finalState = RecoveryFinalMissing
				}
				hasDamage = true
			} else {
				hasVerified = true
			}
		}
		if expected.ciphertextLength != 0 {
			start, ok := checkedMul64(index, d1OuterChunkSize)
			if !ok {
				return nil, errInvalidD1Force
			}
			end, ok := checkedAdd64(start, uint64(expected.ciphertextLength)) //nolint:gosec // Canonical record lengths are non-negative.
			if !ok {
				return nil, errInvalidD1Force
			}
			ranges = append(ranges, RecoveryRange{
				recordIndex: index,
				start:       start,
				end:         end,
				state:       state,
			})
		}
		if expected.final {
			final = finalState
		}
	}
	if !hasDamage {
		return nil, nil
	}
	var outcome Outcome
	var provenance ForceProvenance
	switch {
	case hasVerified:
		outcome = OutcomeForcePartial
		provenance = ForceProvenancePartial
	case hasUnverified:
		outcome = OutcomeForceUnverified
		provenance = ForceProvenanceUnverified
	default:
		return nil, nil
	}
	stage := StageD1Body
	if !selection.bootstrapHealthy {
		stage = StageD1Bootstrap
	}
	d1Provenance := selection.provenance
	if outcome == OutcomeForceUnverified {
		d1Provenance = d1BootstrapProvenanceForRole(analysis.candidate.role)
	}
	return newD1RecoveryResult(
		outcome,
		provenance,
		stage,
		d1Provenance,
		StageNone,
		analysis.geometry.plaintextLength,
		ranges,
		final,
	)
}

func emitD1RawOuter(
	ctx context.Context,
	source io.ReaderAt,
	request d1RecoveryRequest,
	selection d1ForceSelection,
	seams d1ForceSeams,
	result *RecoveryResult,
	output D1RecoveryOutput,
) (*RecoveryResult, error) {
	analysis := selection.analysis
	if analysis == nil || analysis.candidate == nil || result == nil || output == nil {
		return recoveryOperationFailure(StageCredentialPolicy),
			&recoveryEngineError{stage: StageCredentialPolicy}
	}
	return deliverRecoveryOutput(
		ctx,
		result,
		func(sink RecoverySegmentSink) error {
			codec, err := newD1OuterCodec(ctx, analysis.candidate)
			if err != nil {
				return err
			}
			defer codec.Close()
			body := io.NewSectionReader(source, analysis.bodyWindow.offset, analysis.bodyWindow.length)
			ciphertext := make([]byte, d1OuterChunkSize)
			plaintext := make([]byte, d1OuterChunkSize)
			defer pcv3crypto.SecureZero(ciphertext)
			defer pcv3crypto.SecureZero(plaintext)
			var tag [d1OuterTagSize]byte
			defer pcv3crypto.SecureZero(tag[:])
			rangeIndex := 0
			for index := range analysis.geometry.recordCount {
				expected, err := expectedD1OuterRecord(analysis.geometry, index)
				if err != nil {
					return err
				}
				var recoveryRange RecoveryRange
				if expected.ciphertextLength != 0 {
					if rangeIndex >= len(result.ranges) ||
						result.ranges[rangeIndex].recordIndex != index {
						return errInvalidD1Force
					}
					recoveryRange = result.ranges[rangeIndex]
					rangeIndex++
				}
				if expected.final && expected.ciphertextLength != 0 {
					var wantFinal RecoveryFinalState
					switch recoveryRange.state {
					case RecoveryRangeVerified:
						wantFinal = RecoveryFinalVerified
					case RecoveryRangeUnverified:
						wantFinal = RecoveryFinalUnverified
					case RecoveryRangeMissing:
						wantFinal = RecoveryFinalMissing
					default:
						return errInvalidD1Force
					}
					if result.final != wantFinal {
						return errInvalidD1Force
					}
				}
				if (expected.ciphertextLength != 0 && recoveryRange.state == RecoveryRangeMissing) ||
					(expected.final && result.final == RecoveryFinalMissing) {
					continue
				}
				loaded, loadedTag, err := loadD1OuterRecord(
					ctx,
					body,
					expected,
					ciphertext,
					tag[:],
				)
				if err != nil {
					return err
				}
				opened := plaintext[:expected.ciphertextLength]
				authenticated, err := openD1ForceRecord(
					ctx,
					request,
					analysis.candidate,
					codec,
					expected,
					loaded,
					loadedTag,
					opened,
					seams,
				)
				if err != nil {
					return err
				}
				wantState := RecoveryRangeUnverified
				wantFinal := RecoveryFinalUnverified
				if authenticated {
					wantState = RecoveryRangeVerified
					wantFinal = RecoveryFinalVerified
				}
				if expected.ciphertextLength != 0 {
					if recoveryRange.state != wantState {
						return errInvalidD1Force
					}
					if err := sink(recoveryRange, opened); err != nil {
						return err
					}
					pcv3crypto.SecureZero(opened)
				}
				if expected.final && result.final != wantFinal {
					return errInvalidD1Force
				}
			}
			if rangeIndex != len(result.ranges) {
				return errInvalidD1Force
			}
			return nil
		},
		func(result *RecoveryResult, emitter RecoveryEmitter) error {
			return output(result, analysis.candidate.role, emitter)
		},
	)
}

func d1CredentialFailureStage(ctx context.Context, err error) Stage {
	if stage, ok := d1OperationalStage(ctx, err); ok {
		return stage
	}
	return StageCredentialPolicy
}

func d1OperationResult(ctx context.Context, err error) (*RecoveryResult, error) {
	stage, ok := d1OperationalStage(ctx, err)
	if !ok {
		stage = StageCredentialPolicy
	}
	return recoveryOperationFailure(stage), &recoveryEngineError{stage: stage}
}

func d1OperationalStage(ctx context.Context, err error) (Stage, bool) {
	if ctx != nil && ctx.Err() != nil {
		return StageCancellation, true
	}
	var failure Failure
	if errors.As(err, &failure) && failure.Outcome() == OutcomeOperationFailed {
		return failure.Stage(), true
	}
	var outerFailure *d1OuterFailure
	if errors.As(err, &outerFailure) {
		switch outerFailure.Stage() {
		case StageInputIO, StageCredentialPolicy, StageUnwrap, StageKDFRuntime,
			StageCancellation, StageOutputWrite:
			return outerFailure.Stage(), true
		}
	}
	var recordErr *recordFailure
	if errors.As(err, &recordErr) {
		switch recordErr.stage {
		case StageInputIO, StageCredentialPolicy, StageCancellation, StageOutputWrite:
			return recordErr.stage, true
		}
	}
	var pipelineErr *pcv3credential.PipelineError
	if errors.As(err, &pipelineErr) {
		return credentialPipelineStage(err), true
	}
	var factorErr *pcv3credential.FactorError
	if errors.As(err, &factorErr) {
		if factorErr.Code == pcv3credential.FactorErrorCancelled {
			return StageCancellation, true
		}
		return StageCredentialPolicy, true
	}
	var kdfErr *pcv3credential.KDFError
	if errors.As(err, &kdfErr) {
		if kdfErr.Code == pcv3credential.KDFErrorCancelled {
			return StageCancellation, true
		}
		return StageKDFRuntime, true
	}
	var ownerErr *pcv3credential.OwnerError
	if errors.As(err, &ownerErr) {
		if ownerErr.Code == pcv3credential.OwnerErrorCancelled {
			return StageCancellation, true
		}
		return StageCredentialPolicy, true
	}
	return StageNone, false
}
