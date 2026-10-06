package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

var errInvalidD1Force = errors.New("pcv3: invalid D1 Force request")

type d1ForceCandidate struct {
	role            D1BootstrapRole
	bootstrap       d1BootstrapCandidate
	bootstrapKnown  bool
	bodyLength      uint64
	secret          *d1OuterSecretOwner
	borrowOuterKeys func(
		context.Context,
		func(*pcv3credential.BorrowedD1OuterKeys) error,
	) error
	wrapVerified    bool
	replicaVerified bool
}

func (*d1ForceCandidate) String() string { return "pcv3: D1 Force candidate" }

func (candidate *d1ForceCandidate) GoString() string { return candidate.String() }

func (candidate *d1ForceCandidate) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, candidate.String())
}

func (candidate *d1ForceCandidate) withOuterKeys(
	ctx context.Context,
	callback func(*pcv3credential.BorrowedD1OuterKeys) error,
) error {
	if candidate == nil || ctx == nil || callback == nil {
		return errInvalidD1Force
	}
	hasOwnedSecret := candidate.secret != nil
	hasBorrowedSecret := candidate.borrowOuterKeys != nil
	if hasOwnedSecret == hasBorrowedSecret {
		return errInvalidD1Force
	}
	if hasOwnedSecret {
		return candidate.secret.withOuterKeys(ctx, callback)
	}
	return candidate.borrowOuterKeys(ctx, callback)
}

func (candidate *d1ForceCandidate) Close() {
	if candidate == nil {
		return
	}
	if candidate.secret != nil {
		candidate.secret.Close()
		candidate.secret = nil
	}
	clearD1BootstrapCandidate(&candidate.bootstrap)
	candidate.bootstrapKnown = false
	candidate.borrowOuterKeys = nil
	candidate.role = 0
	candidate.bodyLength = 0
	candidate.wrapVerified = false
	candidate.replicaVerified = false
}

func (candidate *d1ForceCandidate) valid() bool {
	if candidate == nil || !validD1BootstrapRole(candidate.role) || candidate.bodyLength == 0 ||
		!candidate.bootstrapKnown || candidate.bootstrap.role != candidate.role {
		return false
	}
	return (candidate.secret != nil) != (candidate.borrowOuterKeys != nil)
}

func bindD1ForceCandidateWithAccess(
	ctx context.Context,
	bootstrap d1BootstrapCandidate,
	access d1BootstrapCredentialAccess,
	seams d1BootstrapAuthSeams,
	callback func(*d1ForceCandidate) error,
) error {
	if callback == nil {
		return errInvalidD1Force
	}
	return bindD1BootstrapWithAccess(
		ctx,
		bootstrap,
		access,
		seams,
		func(binding *d1BootstrapBinding) error {
			if binding == nil || binding.bodyLength == 0 {
				return errInvalidD1Force
			}
			candidate := &d1ForceCandidate{
				role:            bootstrap.role,
				bootstrap:       bootstrap,
				bootstrapKnown:  true,
				bodyLength:      binding.bodyLength,
				borrowOuterKeys: binding.withOuterKeys,
				wrapVerified:    binding.wrapVerified,
				replicaVerified: binding.replicaVerified,
			}
			defer candidate.Close()
			return callback(candidate)
		},
	)
}

type d1ForceConsentState struct {
	mu        sync.Mutex
	condition *sync.Cond
	active    bool
	role      D1BootstrapRole
	inFlight  uint64
}

func (state *d1ForceConsentState) valid() bool {
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.active && validD1BootstrapRole(state.role)
}

func (state *d1ForceConsentState) authorizes(role D1BootstrapRole) bool {
	if state == nil || !validD1BootstrapRole(role) {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.active && state.role == role
}

func (state *d1ForceConsentState) withAuthority(
	role D1BootstrapRole,
	callback func() error,
) error {
	if state == nil || !validD1BootstrapRole(role) || callback == nil {
		return errInvalidD1Force
	}
	state.mu.Lock()
	if !state.active || state.role != role || state.condition == nil {
		state.mu.Unlock()
		return errInvalidD1Force
	}
	state.inFlight++
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.inFlight--
		state.condition.Broadcast()
		state.mu.Unlock()
	}()
	return callback()
}

func (state *d1ForceConsentState) expire() {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.active = false
	state.role = D1BootstrapRole(0xff)
	for state.inFlight != 0 && state.condition != nil {
		state.condition.Wait()
	}
}

// d1RecoveryRequest is private D1 policy authority. Raw outer access exists
// only while withUnverifiedD1RecoveryRequest owns its callback.
type d1RecoveryRequest struct {
	budget  *pcv3ranges.Budget
	mode    RecoveryMode
	consent *d1ForceConsentState
}

func newD1RecoveryRequest(mode RecoveryMode) (d1RecoveryRequest, error) {
	if mode != RecoveryModeNormalV3 && mode != RecoveryModeForce {
		return d1RecoveryRequest{}, errInvalidRecoveryRequest
	}
	return d1RecoveryRequest{mode: mode, budget: pcv3ranges.NewBudget(pcv3ranges.DefaultBudgetBytes)}, nil
}

func withUnverifiedD1RecoveryRequest(
	role D1BootstrapRole,
	callback func(d1RecoveryRequest) error,
) error {
	if !validD1BootstrapRole(role) || callback == nil {
		return errInvalidRecoveryRequest
	}
	state := &d1ForceConsentState{active: true, role: role}
	state.condition = sync.NewCond(&state.mu)
	defer state.expire()
	return callback(d1RecoveryRequest{
		budget:  pcv3ranges.NewBudget(pcv3ranges.DefaultBudgetBytes),
		mode:    RecoveryModeForceUnverified,
		consent: state,
	})
}

func (request d1RecoveryRequest) valid() bool {
	switch request.mode {
	case RecoveryModeNormalV3, RecoveryModeForce:
		return request.consent == nil
	case RecoveryModeForceUnverified:
		return request.consent != nil && request.consent.valid()
	default:
		return false
	}
}

func (request d1RecoveryRequest) authorizesRawOuter(role D1BootstrapRole) bool {
	return request.mode == RecoveryModeForceUnverified && request.consent != nil &&
		request.consent.authorizes(role)
}

func (request d1RecoveryRequest) withRawOuterAuthority(
	role D1BootstrapRole,
	callback func() error,
) error {
	if request.mode != RecoveryModeForceUnverified || request.consent == nil {
		return errInvalidD1Force
	}
	return request.consent.withAuthority(role, callback)
}

func (d1RecoveryRequest) String() string { return "pcv3: D1 recovery request" }

func (request d1RecoveryRequest) GoString() string { return request.String() }

func (request d1RecoveryRequest) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, request.String())
}

type d1ForceSeams struct {
	authenticateRecord func(
		*d1ForceCandidate,
		*d1OuterCodec,
		context.Context,
		uint64,
		bool,
		[]byte,
		[]byte,
	) error
	decryptRecord func(
		*d1ForceCandidate,
		*d1OuterCodec,
		context.Context,
		uint64,
		bool,
		[]byte,
		[]byte,
	) error
}

func defaultD1ForceSeams() d1ForceSeams {
	return d1ForceSeams{
		authenticateRecord: func(
			_ *d1ForceCandidate,
			codec *d1OuterCodec,
			ctx context.Context,
			index uint64,
			final bool,
			ciphertext, tag []byte,
		) error {
			return codec.authenticateRecord(ctx, index, final, ciphertext, tag)
		},
		decryptRecord: func(
			_ *d1ForceCandidate,
			codec *d1OuterCodec,
			ctx context.Context,
			index uint64,
			final bool,
			ciphertext, plaintext []byte,
		) error {
			return codec.decryptRecord(ctx, index, final, ciphertext, plaintext)
		},
	}
}

type d1ForceBodyWindow struct {
	offset int64
	length int64
}

func deriveD1ForceBodyWindow(
	sourceSize int64,
	bodyLength uint64,
	role D1BootstrapRole,
) (d1ForceBodyWindow, error) {
	if sourceSize < 0 || bodyLength > math.MaxInt64 || !validD1BootstrapRole(role) {
		return d1ForceBodyWindow{}, errInvalidD1Force
	}
	length := int64(bodyLength) //nolint:gosec // The MaxInt64 guard above proves this conversion.
	singleSize, ok := checkedAdd64(uint64(d1BootstrapLength), bodyLength)
	if !ok || singleSize > math.MaxInt64 || sourceSize < int64(singleSize) { //nolint:gosec // The preceding bound proves this conversion.
		return d1ForceBodyWindow{}, errInvalidD1Force
	}
	offset := int64(d1BootstrapLength)
	if role == D1BootstrapTail {
		offset = sourceSize - int64(d1BootstrapLength) - length
	}
	end := offset + length
	if end < offset {
		return d1ForceBodyWindow{}, errInvalidD1Force
	}
	if sourceSize == int64(singleSize) { //nolint:gosec // The preceding bound proves this conversion.
		if (role == D1BootstrapFront && (offset != int64(d1BootstrapLength) || end != sourceSize)) ||
			(role == D1BootstrapTail && (offset != 0 || end != length)) {
			return d1ForceBodyWindow{}, errInvalidD1Force
		}
	} else if offset < 0 || end > sourceSize {
		return d1ForceBodyWindow{}, errInvalidD1Force
	}
	return d1ForceBodyWindow{offset: offset, length: length}, nil
}

type d1ForceCandidateAnalysis struct {
	candidate               *d1ForceCandidate
	bodyWindow              d1ForceBodyWindow
	geometry                d1OuterGeometry
	outerAnchored           bool
	outerFullyAuthenticated bool
}

type d1ForceSelection struct {
	analysis             *d1ForceCandidateAnalysis
	provenance           D1BootstrapProvenance
	bootstrapHealthy     bool
	outerHealthy         bool
	requiresRawAuthority bool
}

func analyzeD1ForceCandidate(
	ctx context.Context,
	source io.ReaderAt,
	window d1ForceBodyWindow,
	candidate *d1ForceCandidate,
	seams d1ForceSeams,
) (*d1ForceCandidateAnalysis, error) {
	if ctx == nil || source == nil || candidate == nil || !candidate.valid() ||
		window.offset < 0 || window.length < 0 || seams.authenticateRecord == nil {
		return nil, errInvalidD1Force
	}
	geometry, err := parseD1OuterGeometry(candidate.bodyLength)
	if err != nil || uint64(window.length) != candidate.bodyLength { //nolint:gosec // Non-negative length is checked above.
		return nil, errInvalidD1Force
	}
	codec, err := newD1OuterCodec(ctx, candidate)
	if err != nil {
		return nil, err
	}
	defer codec.Close()
	ciphertextScratch := make([]byte, d1OuterChunkSize)
	defer pcv3crypto.SecureZero(ciphertextScratch)
	var tagScratch [d1OuterTagSize]byte
	defer pcv3crypto.SecureZero(tagScratch[:])
	analysis := &d1ForceCandidateAnalysis{
		candidate:               candidate,
		bodyWindow:              window,
		geometry:                geometry,
		outerFullyAuthenticated: true,
	}
	bodySource := io.NewSectionReader(source, window.offset, window.length)
	err = evaluateD1OuterRecordsWithAuthenticator(
		ctx,
		bodySource,
		geometry,
		codec,
		ciphertextScratch,
		tagScratch[:],
		func(
			codec *d1OuterCodec,
			ctx context.Context,
			index uint64,
			final bool,
			ciphertext, tag []byte,
		) error {
			return seams.authenticateRecord(
				candidate,
				codec,
				ctx,
				index,
				final,
				ciphertext,
				tag,
			)
		},
		func(expected d1OuterRecordExpectation, authenticationErr error) error {
			if authenticationErr == nil {
				analysis.outerAnchored = true
				return nil
			}
			if errors.Is(authenticationErr, errD1OuterAuthentication) {
				analysis.outerFullyAuthenticated = false
				return nil
			}
			return authenticationErr
		},
	)
	if err != nil {
		return nil, err
	}
	return analysis, nil
}

func selectD1ForceCandidateWithPreanalysis(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	request d1RecoveryRequest,
	candidates []*d1ForceCandidate,
	seams d1ForceSeams,
	preanalyzed *d1ForceCandidateAnalysis,
) (d1ForceSelection, *RecoveryResult, error) {
	var selection d1ForceSelection
	if ctx == nil || source == nil || sourceSize < 0 || !request.valid() ||
		len(candidates) == 0 || len(candidates) > 2 ||
		seams.authenticateRecord == nil || seams.decryptRecord == nil {
		return selection, nil, errInvalidD1Force
	}
	seenRoles := make(map[D1BootstrapRole]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == nil || !candidate.valid() {
			return selection, nil, errInvalidD1Force
		}
		if _, exists := seenRoles[candidate.role]; exists {
			return selection, nil, errInvalidD1Force
		}
		seenRoles[candidate.role] = struct{}{}
	}

	pairSameSecret := false
	pairBootstrapHealthy := false
	if len(candidates) == 2 {
		pairFullyAuthenticated := fullyAuthenticatedD1Candidate(candidates[0]) &&
			fullyAuthenticatedD1Candidate(candidates[1])
		pairParametersIndependent := independentD1BootstrapParameters(
			candidates[0].bootstrap,
			candidates[1].bootstrap,
		)
		if pairFullyAuthenticated && !pairParametersIndependent {
			terminal, err := newD1ForceTerminalResult(
				OutcomeAmbiguousVolume,
				StageD1Bootstrap,
			)
			return selection, terminal, err
		}
		var err error
		pairSameSecret, err = sameD1OuterSecretAccess(
			ctx,
			candidates[0].bodyLength,
			candidates[0],
			candidates[1].bodyLength,
			candidates[1],
		)
		if err != nil {
			return selection, nil, err
		}
		if pairFullyAuthenticated && !pairSameSecret {
			terminal, err := newD1ForceTerminalResult(
				OutcomeAmbiguousVolume,
				StageD1Bootstrap,
			)
			return selection, terminal, err
		}
		pairBootstrapHealthy = pairFullyAuthenticated &&
			pairParametersIndependent && pairSameSecret
	}

	windows := make([]d1ForceBodyWindow, len(candidates))
	analyses := make([]*d1ForceCandidateAnalysis, len(candidates))
	usedPreanalysis := false
	for index, candidate := range candidates {
		window, err := deriveD1ForceBodyWindow(sourceSize, candidate.bodyLength, candidate.role)
		if err != nil {
			return selection, nil, err
		}
		windows[index] = window
		if preanalyzed != nil && preanalyzed.candidate == candidate {
			geometry, geometryErr := parseD1OuterGeometry(candidate.bodyLength)
			if geometryErr != nil || preanalyzed.bodyWindow != window ||
				preanalyzed.geometry != geometry {
				return selection, nil, errInvalidD1Force
			}
			analyses[index] = preanalyzed
			usedPreanalysis = true
			continue
		}
		analysis, err := analyzeD1ForceCandidate(ctx, source, window, candidate, seams)
		if err != nil {
			return selection, nil, err
		}
		analyses[index] = analysis
	}
	if preanalyzed != nil && !usedPreanalysis {
		return selection, nil, errInvalidD1Force
	}

	pairSameContext := len(candidates) == 2 && pairSameSecret && windows[0] == windows[1]
	anchored := make([]int, 0, len(analyses))
	for index, analysis := range analyses {
		if analysis.outerAnchored {
			anchored = append(anchored, index)
		}
	}

	selectedIndex := -1
	switch len(anchored) {
	case 0:
		for index, candidate := range candidates {
			if request.authorizesRawOuter(candidate.role) {
				selectedIndex = index
				selection.provenance = d1BootstrapProvenanceForRole(candidate.role)
				selection.requiresRawAuthority = true
				break
			}
		}
		if selectedIndex < 0 {
			if provenance := authenticatedD1BootstrapProvenance(
				candidates,
				pairSameContext,
			); provenance != D1BootstrapProvenanceNone {
				terminal, err := newD1RecoveryResult(
					OutcomeAuthenticationFailed,
					ForceProvenanceNone,
					StageD1Body,
					provenance,
					StageNone,
					0,
					nil,
					0,
				)
				return selection, terminal, err
			}
			terminal, err := newD1ForceTerminalResult(
				OutcomeCredentialsOrDamage,
				StageD1Bootstrap,
			)
			return selection, terminal, err
		}
	case 1:
		selectedIndex = anchored[0]
		selection.provenance = d1BootstrapProvenanceForRole(candidates[selectedIndex].role)
	case 2:
		if !pairSameContext {
			terminal, err := newD1ForceTerminalResult(
				OutcomeAmbiguousVolume,
				StageD1Body,
			)
			return selection, terminal, err
		}
		selectedIndex = anchored[0]
		if request.mode == RecoveryModeForceUnverified {
			for _, index := range anchored {
				if request.authorizesRawOuter(candidates[index].role) {
					selectedIndex = index
					break
				}
			}
		}
		selection.provenance = D1BootstrapProvenanceMatching
	default:
		return selection, nil, errInvalidD1Force
	}
	if selectedIndex < 0 || selection.provenance == D1BootstrapProvenanceNone {
		return selection, nil, errInvalidD1Force
	}

	selection.analysis = analyses[selectedIndex]
	selection.bootstrapHealthy = pairBootstrapHealthy
	selection.outerHealthy = analyses[selectedIndex].outerFullyAuthenticated
	if selection.bootstrapHealthy {
		for index := range candidates {
			selection.outerHealthy = selection.outerHealthy && analyses[index].outerFullyAuthenticated
		}
	}
	return selection, nil, nil
}

func authenticatedD1BootstrapProvenance(
	candidates []*d1ForceCandidate,
	pairSameContext bool,
) D1BootstrapProvenance {
	var provenance D1BootstrapProvenance
	fullyAuthenticated := 0
	for _, candidate := range candidates {
		if candidate == nil || !candidate.wrapVerified || !candidate.replicaVerified {
			continue
		}
		fullyAuthenticated++
		provenance = d1BootstrapProvenanceForRole(candidate.role)
	}
	switch {
	case fullyAuthenticated == 1:
		return provenance
	case fullyAuthenticated == 2 && pairSameContext:
		return D1BootstrapProvenanceMatching
	default:
		return D1BootstrapProvenanceNone
	}
}

func mapD1ForceInnerResult(
	selection d1ForceSelection,
	innerResult *RecoveryResult,
) (*RecoveryResult, error) {
	if selection.analysis == nil || innerResult == nil ||
		selection.provenance == D1BootstrapProvenanceNone {
		return nil, errInvalidD1Force
	}

	if innerResult.outcome == OutcomeOperationFailed && innerResult.stage == StageResourceBudget {
		return recoveryOperationFailure(StageResourceBudget), nil
	}
	if innerResult.outcome == OutcomeSuccess {
		switch {
		case !selection.bootstrapHealthy:
			return newD1RecoveryResult(
				OutcomeAuthenticatedDegraded,
				ForceProvenanceNone,
				StageD1Bootstrap,
				selection.provenance,
				StageNone,
				0,
				nil,
				0,
			)
		case !selection.outerHealthy:
			return newD1RecoveryResult(
				OutcomeAuthenticatedDegraded,
				ForceProvenanceNone,
				StageD1Body,
				selection.provenance,
				StageNone,
				0,
				nil,
				0,
			)
		default:
			return newD1RecoveryResult(
				OutcomeSuccess,
				ForceProvenanceNone,
				StageNone,
				selection.provenance,
				StageNone,
				0,
				nil,
				0,
			)
		}
	}
	stage := StageInnerVolume
	if !selection.bootstrapHealthy {
		stage = StageD1Bootstrap
	} else if !selection.outerHealthy {
		stage = StageD1Body
	}
	return newD1RecoveryResult(
		innerResult.outcome,
		innerResult.provenance,
		stage,
		selection.provenance,
		innerResult.stage,
		innerResult.plaintextLength,
		innerResult.ranges,
		innerResult.final,
	)
}

func newD1ForceTerminalResult(
	outcome Outcome,
	stage Stage,
) (*RecoveryResult, error) {
	return newD1RecoveryResult(
		outcome,
		ForceProvenanceNone,
		stage,
		D1BootstrapProvenanceNone,
		StageNone,
		0,
		nil,
		0,
	)
}

func d1BootstrapProvenanceForRole(role D1BootstrapRole) D1BootstrapProvenance {
	switch role {
	case D1BootstrapFront:
		return D1BootstrapProvenanceFront
	case D1BootstrapTail:
		return D1BootstrapProvenanceTail
	default:
		return D1BootstrapProvenanceNone
	}
}

func openD1ForceRecord(
	ctx context.Context,
	request d1RecoveryRequest,
	candidate *d1ForceCandidate,
	codec *d1OuterCodec,
	expected d1OuterRecordExpectation,
	ciphertext, tag, plaintext []byte,
	seams d1ForceSeams,
) (bool, error) {
	pcv3crypto.SecureZero(plaintext)
	if ctx == nil || candidate == nil || !candidate.valid() || codec == nil ||
		seams.authenticateRecord == nil || seams.decryptRecord == nil ||
		len(ciphertext) != len(plaintext) || len(tag) != d1OuterTagSize {
		return false, errInvalidD1Force
	}
	authErr := seams.authenticateRecord(
		candidate,
		codec,
		ctx,
		expected.index,
		expected.final,
		ciphertext,
		tag,
	)
	if authErr == nil {
		if err := seams.decryptRecord(
			candidate,
			codec,
			ctx,
			expected.index,
			expected.final,
			ciphertext,
			plaintext,
		); err != nil {
			pcv3crypto.SecureZero(plaintext)
			return false, err
		}
		return true, nil
	}
	if !errors.Is(authErr, errD1OuterAuthentication) {
		return false, authErr
	}
	if request.mode == RecoveryModeForce {
		return false, newD1OuterFailure(StageD1Body, errD1OuterAuthentication)
	}
	if err := decryptD1ForceRecordRaw(
		request,
		candidate,
		codec,
		ctx,
		expected,
		ciphertext,
		plaintext,
		seams,
	); err != nil {
		pcv3crypto.SecureZero(plaintext)
		return false, err
	}
	return false, nil
}

func decryptD1ForceRecordRaw(
	request d1RecoveryRequest,
	candidate *d1ForceCandidate,
	codec *d1OuterCodec,
	ctx context.Context,
	expected d1OuterRecordExpectation,
	ciphertext, plaintext []byte,
	seams d1ForceSeams,
) error {
	pcv3crypto.SecureZero(plaintext)
	if candidate == nil || !candidate.valid() || codec == nil || ctx == nil ||
		seams.decryptRecord == nil || len(ciphertext) != len(plaintext) {
		return errInvalidD1Force
	}
	return request.withRawOuterAuthority(candidate.role, func() error {
		if err := seams.decryptRecord(
			candidate,
			codec,
			ctx,
			expected.index,
			expected.final,
			ciphertext,
			plaintext,
		); err != nil {
			pcv3crypto.SecureZero(plaintext)
			return err
		}
		return nil
	})
}
