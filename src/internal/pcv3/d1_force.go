package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3credential"
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
	candidate.borrowOuterKeys = nil
	candidate.role = 0
	candidate.bodyLength = 0
	candidate.wrapVerified = false
	candidate.replicaVerified = false
}

func (candidate *d1ForceCandidate) valid() bool {
	if candidate == nil || !validD1BootstrapRole(candidate.role) || candidate.bodyLength == 0 {
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
	mode    RecoveryMode
	consent *d1ForceConsentState
}

func newD1RecoveryRequest(mode RecoveryMode) (d1RecoveryRequest, error) {
	if mode != RecoveryModeForce {
		return d1RecoveryRequest{}, errInvalidRecoveryRequest
	}
	return d1RecoveryRequest{mode: mode}, nil
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
		mode:    RecoveryModeForceUnverified,
		consent: state,
	})
}

func (request d1RecoveryRequest) valid() bool {
	switch request.mode {
	case RecoveryModeForce:
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
	minimumSize, ok := checkedAdd64(
		uint64(2*d1BootstrapLength),
		bodyLength,
	)
	if !ok || minimumSize > math.MaxInt64 || sourceSize < int64(minimumSize) { //nolint:gosec // The preceding bound proves this conversion.
		return d1ForceBodyWindow{}, errInvalidD1Force
	}
	offset := int64(d1BootstrapLength)
	if role == D1BootstrapTail {
		offset = sourceSize - int64(d1BootstrapLength) - length
	}
	end := offset + length
	if offset < int64(d1BootstrapLength) || end < offset ||
		end > sourceSize-int64(d1BootstrapLength) {
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

func resolveD1ForceCandidates(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	request d1RecoveryRequest,
	candidates []*d1ForceCandidate,
	inner func(*d1ForceCandidateAnalysis) (*RecoveryResult, error),
) (*RecoveryResult, error) {
	return resolveD1ForceCandidatesWithSeams(
		ctx,
		source,
		sourceSize,
		request,
		candidates,
		defaultD1ForceSeams(),
		inner,
	)
}

func resolveD1ForceCandidatesWithSeams(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	request d1RecoveryRequest,
	candidates []*d1ForceCandidate,
	seams d1ForceSeams,
	inner func(*d1ForceCandidateAnalysis) (*RecoveryResult, error),
) (*RecoveryResult, error) {
	for _, candidate := range candidates {
		defer candidate.Close()
	}
	if ctx == nil || source == nil || sourceSize < 0 || !request.valid() ||
		len(candidates) == 0 || len(candidates) > 2 || inner == nil ||
		seams.authenticateRecord == nil || seams.decryptRecord == nil {
		return nil, errInvalidD1Force
	}
	seenRoles := make(map[D1BootstrapRole]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == nil || !candidate.valid() {
			return nil, errInvalidD1Force
		}
		if _, exists := seenRoles[candidate.role]; exists {
			return nil, errInvalidD1Force
		}
		seenRoles[candidate.role] = struct{}{}
	}

	pairSameSecret := false
	if len(candidates) == 2 {
		var err error
		pairSameSecret, err = sameD1OuterSecretAccess(
			ctx,
			candidates[0].bodyLength,
			candidates[0],
			candidates[1].bodyLength,
			candidates[1],
		)
		if err != nil {
			return nil, err
		}
		if candidates[0].wrapVerified && candidates[0].replicaVerified &&
			candidates[1].wrapVerified && candidates[1].replicaVerified &&
			!pairSameSecret {
			return newD1ForceTerminalResult(
				OutcomeAmbiguousVolume,
				StageD1Bootstrap,
			)
		}
	}

	windows := make([]d1ForceBodyWindow, len(candidates))
	analyses := make([]*d1ForceCandidateAnalysis, len(candidates))
	for index, candidate := range candidates {
		window, err := deriveD1ForceBodyWindow(sourceSize, candidate.bodyLength, candidate.role)
		if err != nil {
			return nil, err
		}
		windows[index] = window
		analysis, err := analyzeD1ForceCandidate(ctx, source, window, candidate, seams)
		if err != nil {
			return nil, err
		}
		analyses[index] = analysis
	}

	pairSameContext := len(candidates) == 2 && pairSameSecret && windows[0] == windows[1]
	anchored := make([]int, 0, len(analyses))
	for index, analysis := range analyses {
		if analysis.outerAnchored {
			anchored = append(anchored, index)
		}
	}

	selectedIndex := -1
	provenance := D1BootstrapProvenanceNone
	switch len(anchored) {
	case 0:
		for index, candidate := range candidates {
			if request.authorizesRawOuter(candidate.role) {
				selectedIndex = index
				provenance = d1BootstrapProvenanceForRole(candidate.role)
				break
			}
		}
		if selectedIndex < 0 {
			return newD1ForceTerminalResult(
				OutcomeCredentialsOrDamage,
				StageD1Bootstrap,
			)
		}
	case 1:
		selectedIndex = anchored[0]
		provenance = d1BootstrapProvenanceForRole(candidates[selectedIndex].role)
	case 2:
		if !pairSameContext {
			return newD1ForceTerminalResult(
				OutcomeAmbiguousVolume,
				StageD1Body,
			)
		}
		selectedIndex = anchored[0]
		provenance = D1BootstrapProvenanceMatching
	default:
		return nil, errInvalidD1Force
	}
	if selectedIndex < 0 || provenance == D1BootstrapProvenanceNone {
		return nil, errInvalidD1Force
	}

	var innerResult *RecoveryResult
	invokeInner := func() error {
		if err := ctx.Err(); err != nil {
			return newD1OuterFailure(StageCancellation, err)
		}
		var innerErr error
		innerResult, innerErr = inner(analyses[selectedIndex])
		if innerErr == nil && ctx.Err() != nil {
			return newD1OuterFailure(StageCancellation, ctx.Err())
		}
		return innerErr
	}
	var err error
	if len(anchored) == 0 {
		err = request.withRawOuterAuthority(candidates[selectedIndex].role, invokeInner)
	} else {
		err = invokeInner()
	}
	if err != nil {
		if innerResult != nil {
			innerResult.Close()
		}
		return nil, err
	}
	if innerResult == nil {
		return nil, errInvalidD1Force
	}
	defer innerResult.Close()

	bootstrapHealthy := provenance == D1BootstrapProvenanceMatching
	outerHealthy := analyses[selectedIndex].outerFullyAuthenticated
	if bootstrapHealthy {
		for index, candidate := range candidates {
			bootstrapHealthy = bootstrapHealthy && candidate.wrapVerified && candidate.replicaVerified
			outerHealthy = outerHealthy && analyses[index].outerFullyAuthenticated
		}
	}
	if innerResult.outcome == OutcomeSuccess {
		switch {
		case !bootstrapHealthy:
			return newD1RecoveryResult(
				OutcomeAuthenticatedDegraded,
				ForceProvenanceNone,
				StageD1Bootstrap,
				provenance,
				StageNone,
				0,
				nil,
				0,
			)
		case !outerHealthy:
			return newD1RecoveryResult(
				OutcomeAuthenticatedDegraded,
				ForceProvenanceNone,
				StageD1Body,
				provenance,
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
				provenance,
				StageNone,
				0,
				nil,
				0,
			)
		}
	}
	return newD1RecoveryResult(
		innerResult.outcome,
		innerResult.provenance,
		StageInnerVolume,
		provenance,
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

func openD1ForceRawRecordWithSeams(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	request d1RecoveryRequest,
	candidate *d1ForceCandidate,
	recordIndex uint64,
	destination []byte,
	seams d1ForceSeams,
) error {
	pcv3crypto.SecureZero(destination)
	if ctx == nil || source == nil || sourceSize < 0 || candidate == nil ||
		!candidate.valid() || seams.decryptRecord == nil {
		return errInvalidD1Force
	}
	return request.withRawOuterAuthority(candidate.role, func() error {
		window, err := deriveD1ForceBodyWindow(sourceSize, candidate.bodyLength, candidate.role)
		if err != nil {
			return err
		}
		geometry, err := parseD1OuterGeometry(candidate.bodyLength)
		if err != nil {
			return err
		}
		expected, err := expectedD1OuterRecord(geometry, recordIndex)
		if err != nil || len(destination) != expected.ciphertextLength {
			return errInvalidD1Force
		}
		codec, err := newD1OuterCodec(ctx, candidate)
		if err != nil {
			return err
		}
		defer codec.Close()
		ciphertext := make([]byte, expected.ciphertextLength)
		defer pcv3crypto.SecureZero(ciphertext)
		var tag [d1OuterTagSize]byte
		defer pcv3crypto.SecureZero(tag[:])
		bodySource := io.NewSectionReader(source, window.offset, window.length)
		loaded, _, err := loadD1OuterRecord(
			ctx,
			bodySource,
			expected,
			ciphertext,
			tag[:],
		)
		if err != nil {
			return err
		}
		if err := seams.decryptRecord(
			candidate,
			codec,
			ctx,
			expected.index,
			expected.final,
			loaded,
			destination,
		); err != nil {
			pcv3crypto.SecureZero(destination)
			return err
		}
		if err := ctx.Err(); err != nil {
			pcv3crypto.SecureZero(destination)
			return newD1OuterFailure(StageCancellation, err)
		}
		return nil
	})
}
