package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"context"
	"errors"
	"sync"
)

// ReaderCredentialRequest transfers ownership of Factors to
// WithReaderCredential. Suite, profile, claimed policy, salt, and volume ID
// are public capsule input and are snapshotted before factor processing. The
// independent caller pin remains Factors.ExpectedPolicy.
type ReaderCredentialRequest struct {
	Suite         Suite
	ProfileID     uint8
	Factors       *FactorRequest
	ClaimedPolicy FactorPolicy
	ArgonSalt     []byte
	VolumeID      []byte
}

func (ReaderCredentialRequest) String() string {
	return "pcv3credential.ReaderCredentialRequest([REDACTED])"
}

func (ReaderCredentialRequest) GoString() string {
	return "pcv3credential.ReaderCredentialRequest([REDACTED])"
}

type readerCredentialSeams struct {
	derive                    kdfDeriver
	extract                   hkdfExtractor
	expand                    hkdfExpander
	beforeKDF                 func()
	observeCredentialMaterial func(*keyMaterial)
	observeReplicaMaterial    func(*keyMaterial)
	observeOwnerMaterial      func(*keyMaterial)
}

// ReaderCredential is a callback-scoped credential-key owner. It is not safe
// for concurrent use and expires when its WithReaderCredential callback
// returns.
type ReaderCredential struct {
	state *readerCredentialState
}

type readerCredentialState struct {
	mu sync.Mutex

	active   bool
	adopting bool
	borrows  int

	metadata OwnerMetadata
	material *keyMaterial
	owner    *Owner

	extract                hkdfExtractor
	expand                 hkdfExpander
	observeReplicaMaterial func(*keyMaterial)
	observeOwnerMaterial   func(*keyMaterial)
}

func (*ReaderCredential) String() string {
	return "pcv3credential.ReaderCredential([REDACTED])"
}

func (*ReaderCredential) GoString() string {
	return "pcv3credential.ReaderCredential([REDACTED])"
}

// ReaderKeys is a callback-scoped, role-restricted key borrow. It exposes no
// CredentialRoot, VolumeKey, or retained raw key slice.
type ReaderKeys struct {
	state *readerKeysState
}

type readerKeysState struct {
	mu       sync.RWMutex
	material *keyMaterial
	role     KeyRole
	root     scheduleRoot
	active   bool
}

func (*ReaderKeys) String() string {
	return "pcv3credential.ReaderKeys([REDACTED])"
}

func (*ReaderKeys) GoString() string {
	return "pcv3credential.ReaderKeys([REDACTED])"
}

// WithReaderCredential derives the normal credential root exactly once, lends
// only callback-scoped keys, and returns an ordinary Owner only after the
// callback transfers one authenticated VolumeKey through AdoptVolumeKey.
func WithReaderCredential(
	ctx context.Context,
	request *ReaderCredentialRequest,
	admitter Admitter,
	callback func(*ReaderCredential) error,
) (*Owner, error) {
	return newReaderCredential(
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

func newReaderCredential(
	ctx context.Context,
	request *ReaderCredentialRequest,
	admitter Admitter,
	callback func(*ReaderCredential) error,
	seams readerCredentialSeams,
) (*Owner, error) {
	if request == nil {
		return nil, newPipelineError(
			PipelineErrorInvalidRequest,
			PipelineStageRequest,
			0,
		)
	}

	suite := request.Suite
	profileID := request.ProfileID
	factors := request.Factors
	request.Factors = nil
	argonSalt := append([]byte(nil), request.ArgonSalt...)
	volumeID := append([]byte(nil), request.VolumeID...)
	claimedPolicy := request.ClaimedPolicy
	expectedPolicy := FactorPolicy(0)
	if factors != nil {
		expectedPolicy = factors.ExpectedPolicy
	}

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
	if !validFactorPolicy(claimedPolicy) || expectedPolicy != claimedPolicy {
		releaseFactorRequest(factors)
		return nil, newPipelineError(
			PipelineErrorFactors,
			PipelineStageFactors,
			suite,
		)
	}

	profile, err := fixedProfileForSuite(suite)
	if err != nil || profile.ID != profileID ||
		len(argonSalt) != int(profile.SaltBytes) ||
		len(volumeID) != scheduleVolumeIDBytes {
		releaseFactorRequest(factors)
		return nil, newPipelineError(
			PipelineErrorSchedule,
			PipelineStageSchedule,
			suite,
		)
	}
	rows, err := fixedScheduleForSuite(suite)
	if err != nil {
		releaseFactorRequest(factors)
		return nil, newPipelineError(
			PipelineErrorSchedule,
			PipelineStageSchedule,
			suite,
		)
	}
	keyRequests := make([]KeyRequest, len(rows))
	for i := range rows {
		keyRequests[i] = rows[i].request
	}
	schedule, err := validateKeySchedule(suite, keyRequests)
	if err != nil {
		releaseFactorRequest(factors)
		return nil, newPipelineError(
			PipelineErrorSchedule,
			PipelineStageSchedule,
			suite,
		)
	}

	var published *Owner
	factorErr := WithValidatedFactors(
		ctx,
		factors,
		func(validated *ValidatedFactors) error {
			transcript, err := NewCanonicalTranscript(validated)
			if err != nil {
				return newPipelineError(
					PipelineErrorTranscript,
					PipelineStageTranscript,
					suite,
				)
			}
			defer transcript.Close()

			input, err := NewCredentialInputNormal(transcript)
			if err != nil {
				return newPipelineError(
					PipelineErrorTranscript,
					PipelineStageTranscript,
					suite,
				)
			}
			defer input.Close()

			admitted, err := admitFixedProfile(ctx, suite, admitter)
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
					suite,
				)
			}

			root, err := runCredentialKDF(
				ctx,
				input,
				argonSalt,
				suite,
				admitted,
				seams.derive,
			)
			if err != nil {
				var kdfErr *KDFError
				if errors.As(err, &kdfErr) &&
					kdfErr.Code == KDFErrorCancelled {
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
			defer root.close()

			material, err := newKeyMaterial(schedule, volumeID)
			if err != nil {
				return newPipelineError(
					PipelineErrorKeyDerivation,
					PipelineStageKeyDerivation,
					suite,
				)
			}
			defer func() {
				if material != nil {
					material.close()
				}
			}()
			if err := deriveCredentialRootStageWith(
				material,
				root,
				seams.extract,
			); err != nil {
				return newPipelineError(
					PipelineErrorKeyDerivation,
					PipelineStageKeyDerivation,
					suite,
				)
			}
			if err := expandKeyMaterialWith(
				material,
				scheduleRootCredential,
				seams.expand,
			); err != nil {
				return newPipelineError(
					PipelineErrorKeyDerivation,
					PipelineStageKeyDerivation,
					suite,
				)
			}
			if seams.observeCredentialMaterial != nil {
				seams.observeCredentialMaterial(material)
			}

			metadata := OwnerMetadata{
				Suite:          suite,
				ExpectedPolicy: expectedPolicy,
			}
			copy(metadata.ArgonSalt[:], argonSalt)
			copy(metadata.VolumeID[:], volumeID)
			reader := &ReaderCredential{
				state: &readerCredentialState{
					active:                 true,
					metadata:               metadata,
					material:               material,
					extract:                seams.extract,
					expand:                 seams.expand,
					observeReplicaMaterial: seams.observeReplicaMaterial,
					observeOwnerMaterial:   seams.observeOwnerMaterial,
				},
			}
			material = nil
			defer reader.close()

			if err := callback(reader); err != nil {
				return newPipelineError(
					PipelineErrorCallback,
					PipelineStageCallback,
					suite,
				)
			}
			if ctx.Err() != nil {
				return newPipelineError(
					PipelineErrorCancelled,
					PipelineStageCallback,
					suite,
				)
			}
			published = reader.takeOwner()
			if published == nil {
				return newPipelineError(
					PipelineErrorOwner,
					PipelineStageOwner,
					suite,
				)
			}
			return nil
		},
	)
	if factorErr == nil {
		return published, nil
	}
	var pipelineErr *PipelineError
	if errors.As(factorErr, &pipelineErr) {
		return nil, pipelineErr
	}
	var factorErrTyped *FactorError
	if errors.As(factorErr, &factorErrTyped) {
		if factorErrTyped.Code == FactorErrorCancelled {
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
	return nil, newPipelineError(
		PipelineErrorFactors,
		PipelineStageFactors,
		suite,
	)
}

// WithKeys lends only credential-root keys for role during callback.
func (reader *ReaderCredential) WithKeys(
	ctx context.Context,
	role KeyRole,
	callback func(*ReaderKeys) error,
) error {
	if reader == nil || reader.state == nil || ctx == nil || callback == nil ||
		!validReplicaRole(role) {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	state := reader.state
	state.mu.Lock()
	if !state.active || state.adopting || state.material == nil ||
		state.owner != nil || ctx.Err() != nil {
		state.mu.Unlock()
		if ctx.Err() != nil {
			return newOwnerError(OwnerErrorCancelled)
		}
		return newOwnerError(OwnerErrorClosed)
	}
	state.borrows++
	material := state.material
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.borrows--
		state.mu.Unlock()
	}()

	return withReaderKeys(ctx, material, role, scheduleRootCredential, callback)
}

// WithReplicaKey derives and lends only one role-specific replica MAC key from
// a read-only candidate VolumeKey borrow. The candidate remains owned by the
// caller for later reconciliation.
func (reader *ReaderCredential) WithReplicaKey(
	ctx context.Context,
	role KeyRole,
	candidate []byte,
	callback func(*ReaderKeys) error,
) error {
	if reader == nil || reader.state == nil || ctx == nil || callback == nil ||
		!validReplicaRole(role) || len(candidate) != derivedKeyBytes {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	state := reader.state
	state.mu.Lock()
	if !state.active || state.adopting || state.material == nil ||
		state.owner != nil || ctx.Err() != nil {
		state.mu.Unlock()
		if ctx.Err() != nil {
			return newOwnerError(OwnerErrorCancelled)
		}
		return newOwnerError(OwnerErrorClosed)
	}
	state.borrows++
	metadata := state.metadata
	extract := state.extract
	expand := state.expand
	observe := state.observeReplicaMaterial
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.borrows--
		state.mu.Unlock()
	}()

	request := KeyRequest{
		Label:       KeyLabelVolumeReplicaMAC,
		Role:        role,
		OutputBytes: derivedKeyBytes,
	}
	schedule, err := validateKeySchedule(metadata.Suite, []KeyRequest{request})
	if err != nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	material, err := newKeyMaterial(schedule, metadata.VolumeID[:])
	if err != nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	defer material.close()
	owned := append([]byte(nil), candidate...)
	key := &volumeKey{secret: crypto.SecretFrom(owned)}
	defer key.close()
	if err := deriveVolumeKeyStageWith(material, key, extract); err != nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	if err := expandKeyMaterialWith(
		material,
		scheduleRootVolume,
		expand,
	); err != nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	if observe != nil {
		observe(material)
	}
	return withReaderKeys(ctx, material, role, scheduleRootVolume, callback)
}

// AdoptVolumeKey transfers one authenticated VolumeKey into the staged owner.
// The caller's transfer buffer is cleared on every return, including rejection.
func (reader *ReaderCredential) AdoptVolumeKey(transfer []byte) (returnErr error) {
	defer crypto.SecureZero(transfer)
	if reader == nil || reader.state == nil || len(transfer) != derivedKeyBytes {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	state := reader.state
	state.mu.Lock()
	if !state.active || state.adopting || state.borrows != 0 ||
		state.material == nil || state.owner != nil {
		state.mu.Unlock()
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	state.adopting = true
	material := state.material
	metadata := state.metadata
	extract := state.extract
	expand := state.expand
	observe := state.observeOwnerMaterial
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.adopting = false
		state.mu.Unlock()
	}()

	owned := append([]byte(nil), transfer...)
	key := &volumeKey{secret: crypto.SecretFrom(owned)}
	defer key.close()
	if err := deriveVolumeKeyStageWith(material, key, extract); err != nil {
		reader.failMaterial()
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	if err := expandKeyMaterialWith(
		material,
		scheduleRootVolume,
		expand,
	); err != nil {
		reader.failMaterial()
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	if observe != nil {
		observe(material)
	}
	owner, err := newOwner(metadata, material)
	if err != nil {
		state.mu.Lock()
		state.material = nil
		state.mu.Unlock()
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	state.mu.Lock()
	state.material = nil
	state.owner = owner
	state.mu.Unlock()
	return nil
}

// CopyKey copies one key matching this borrow's root and role into caller-owned
// storage.
func (keys *ReaderKeys) CopyKey(
	request KeyRequest,
	destination []byte,
) error {
	if keys == nil || keys.state == nil {
		return newOwnerError(OwnerErrorBorrowExpired)
	}
	state := keys.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if !state.active || state.material == nil {
		return newOwnerError(OwnerErrorBorrowExpired)
	}
	if len(destination) != derivedKeyBytes {
		return newOwnerError(OwnerErrorDestination)
	}
	for i := range state.material.keys {
		key := &state.material.keys[i]
		if key.row.root == state.root &&
			key.row.request.Role == state.role &&
			key.row.request == request &&
			key.secret != nil {
			copy(destination, key.secret.Bytes())
			return nil
		}
	}
	return newOwnerError(OwnerErrorUnknownKey)
}

func withReaderKeys(
	ctx context.Context,
	material *keyMaterial,
	role KeyRole,
	root scheduleRoot,
	callback func(*ReaderKeys) error,
) error {
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}
	keys := &ReaderKeys{
		state: &readerKeysState{
			material: material,
			role:     role,
			root:     root,
			active:   true,
		},
	}
	defer keys.expire()
	if err := callback(keys); err != nil {
		return newOwnerError(OwnerErrorCallback)
	}
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}
	return nil
}

func (keys *ReaderKeys) expire() {
	if keys == nil || keys.state == nil {
		return
	}
	state := keys.state
	state.mu.Lock()
	state.active = false
	state.material = nil
	state.mu.Unlock()
}

func (reader *ReaderCredential) takeOwner() *Owner {
	if reader == nil || reader.state == nil {
		return nil
	}
	state := reader.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active || state.adopting || state.borrows != 0 {
		return nil
	}
	owner := state.owner
	state.owner = nil
	return owner
}

func (reader *ReaderCredential) failMaterial() {
	if reader == nil || reader.state == nil {
		return
	}
	state := reader.state
	state.mu.Lock()
	material := state.material
	state.material = nil
	state.mu.Unlock()
	if material != nil {
		material.close()
	}
}

func (reader *ReaderCredential) close() {
	if reader == nil || reader.state == nil {
		return
	}
	state := reader.state
	state.mu.Lock()
	state.active = false
	material := state.material
	owner := state.owner
	state.material = nil
	state.owner = nil
	state.mu.Unlock()
	if material != nil {
		material.close()
	}
	if owner != nil {
		owner.Close()
	}
}

func validReplicaRole(role KeyRole) bool {
	return role == KeyRolePrimary || role == KeyRoleBackup
}
