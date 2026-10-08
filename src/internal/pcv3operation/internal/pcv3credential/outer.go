package pcv3credential

import (
	pcsecret "Picocrypt-NG/internal/secret"
	"context"
	"crypto/sha3"
	"sync"
)

const d1OuterRootDomain = "Picocrypt-NG/PCV3/outer/root\x00"

// D1OuterCredentialLabel is one immutable D1 bootstrap-wrap key purpose.
// Its distinct type prevents substitution into the normal-volume schedule.
type D1OuterCredentialLabel string

const (
	D1OuterCredentialWrapXChaCha20 D1OuterCredentialLabel = "outer/wrap/xchacha20" //nolint:gosec //gitleaks:allow // Public protocol label, not a credential.
	D1OuterCredentialWrapSerpent   D1OuterCredentialLabel = "outer/wrap/serpent"   //nolint:gosec // Public protocol label, not a credential.
	D1OuterCredentialWrapMAC       D1OuterCredentialLabel = "outer/wrap/mac"       //nolint:gosec // Public protocol label, not a credential.
)

// D1OuterKeyLabel is one immutable D1 replica or body key purpose.
type D1OuterKeyLabel string

const (
	D1OuterReplicaMAC           D1OuterKeyLabel = "outer/replica/mac"
	D1OuterPayloadXChaCha20     D1OuterKeyLabel = "outer/payload/xchacha20"
	D1OuterPayloadSerpent       D1OuterKeyLabel = "outer/payload/serpent"
	D1OuterPayloadMAC           D1OuterKeyLabel = "outer/payload/mac"
	D1OuterPayloadXNoncePrefix  D1OuterKeyLabel = "outer/payload/xnonce-prefix"
	D1OuterPayloadSerpentPrefix D1OuterKeyLabel = "outer/payload/serpent-prefix"
)

// D1CreationSalts contains the two independent physical bootstrap salts.
type D1CreationSalts struct {
	Front [kdfSaltBytes]byte
	Tail  [kdfSaltBytes]byte
}

type d1OuterDerivationSeams struct {
	derive  kdfDeriver
	extract hkdfExtractor
	expand  hkdfExpander
}

type d1NormalOwnerSeams struct {
	derive  kdfDeriver
	extract hkdfExtractor
	expand  hkdfExpander
}

type d1OuterCredentialRoot struct {
	secret *pcsecret.Secret
}

func (d1OuterCredentialRoot) String() string {
	return "pcv3credential.d1OuterCredentialRoot([REDACTED])"
}

func (d1OuterCredentialRoot) GoString() string {
	return "pcv3credential.d1OuterCredentialRoot([REDACTED])"
}

func (root *d1OuterCredentialRoot) close() {
	if root == nil || root.secret == nil {
		return
	}
	root.secret.Close()
	root.secret = nil
}

type d1OuterCredentialPRK struct {
	secret *pcsecret.Secret
}

func (d1OuterCredentialPRK) String() string {
	return "pcv3credential.d1OuterCredentialPRK([REDACTED])"
}

func (d1OuterCredentialPRK) GoString() string {
	return "pcv3credential.d1OuterCredentialPRK([REDACTED])"
}

func (prk *d1OuterCredentialPRK) close() {
	if prk == nil || prk.secret == nil {
		return
	}
	prk.secret.Close()
	prk.secret = nil
}

type d1OuterCredentialKey struct {
	label  D1OuterCredentialLabel
	secret *pcsecret.Secret
}

func (d1OuterCredentialKey) String() string {
	return "pcv3credential.d1OuterCredentialKey([REDACTED])"
}

func (d1OuterCredentialKey) GoString() string {
	return "pcv3credential.d1OuterCredentialKey([REDACTED])"
}

type d1OuterCredentialMaterial struct {
	root *d1OuterCredentialRoot
	prk  *d1OuterCredentialPRK
	keys []d1OuterCredentialKey
}

func (d1OuterCredentialMaterial) String() string {
	return "pcv3credential.d1OuterCredentialMaterial([REDACTED])"
}

func (d1OuterCredentialMaterial) GoString() string {
	return "pcv3credential.d1OuterCredentialMaterial([REDACTED])"
}

func (material *d1OuterCredentialMaterial) close() {
	if material == nil {
		return
	}
	if material.root != nil {
		material.root.close()
		material.root = nil
	}
	if material.prk != nil {
		material.prk.close()
		material.prk = nil
	}
	for index := range material.keys {
		if material.keys[index].secret != nil {
			material.keys[index].secret.Close()
			material.keys[index].secret = nil
		}
	}
	material.keys = nil
}

type d1OuterKey struct {
	secret *pcsecret.Secret
}

func (d1OuterKey) String() string {
	return "pcv3credential.d1OuterKey([REDACTED])"
}

func (d1OuterKey) GoString() string {
	return "pcv3credential.d1OuterKey([REDACTED])"
}

func (key *d1OuterKey) close() {
	if key == nil || key.secret == nil {
		return
	}
	key.secret.Close()
	key.secret = nil
}

type d1OuterPRK struct {
	secret *pcsecret.Secret
}

func (d1OuterPRK) String() string {
	return "pcv3credential.d1OuterPRK([REDACTED])"
}

func (d1OuterPRK) GoString() string {
	return "pcv3credential.d1OuterPRK([REDACTED])"
}

func (prk *d1OuterPRK) close() {
	if prk == nil || prk.secret == nil {
		return
	}
	prk.secret.Close()
	prk.secret = nil
}

type d1OuterKeyRequest struct {
	label       D1OuterKeyLabel
	role        KeyRole
	outputBytes int
}

type d1OuterDerivedKey struct {
	request d1OuterKeyRequest
	secret  *pcsecret.Secret
}

func (d1OuterDerivedKey) String() string {
	return "pcv3credential.d1OuterDerivedKey([REDACTED])"
}

func (d1OuterDerivedKey) GoString() string {
	return "pcv3credential.d1OuterDerivedKey([REDACTED])"
}

type d1OuterKeyMaterial struct {
	key  *d1OuterKey
	prk  *d1OuterPRK
	keys []d1OuterDerivedKey
}

func (d1OuterKeyMaterial) String() string {
	return "pcv3credential.d1OuterKeyMaterial([REDACTED])"
}

func (d1OuterKeyMaterial) GoString() string {
	return "pcv3credential.d1OuterKeyMaterial([REDACTED])"
}

func (material *d1OuterKeyMaterial) close() {
	if material == nil {
		return
	}
	if material.key != nil {
		material.key.close()
		material.key = nil
	}
	if material.prk != nil {
		material.prk.close()
		material.prk = nil
	}
	for index := range material.keys {
		if material.keys[index].secret != nil {
			material.keys[index].secret.Close()
			material.keys[index].secret = nil
		}
	}
	material.keys = nil
}

type d1OwnerState[T any] struct {
	mu sync.RWMutex

	material      *T
	closeMaterial func(*T)

	closing     chan struct{}
	closingOnce sync.Once
	closeOwned  sync.Once
}

type d1BorrowState[T any] struct {
	mu       sync.RWMutex
	material *T
	active   bool
}

// D1OuterCredentialOwner is the cleanup authority for one physical
// bootstrap's outer credential root, PRK, and wrap keys.
type D1OuterCredentialOwner struct {
	role  KeyRole
	state *d1OwnerState[d1OuterCredentialMaterial]
}

func (*D1OuterCredentialOwner) String() string {
	return "pcv3credential.D1OuterCredentialOwner([REDACTED])"
}

func (*D1OuterCredentialOwner) GoString() string {
	return "pcv3credential.D1OuterCredentialOwner([REDACTED])"
}

// BorrowedD1OuterCredentialKeys is valid only during its WithKeys callback.
type BorrowedD1OuterCredentialKeys struct {
	state *d1BorrowState[d1OuterCredentialMaterial]
}

func (*BorrowedD1OuterCredentialKeys) String() string {
	return "pcv3credential.BorrowedD1OuterCredentialKeys([REDACTED])"
}

func (*BorrowedD1OuterCredentialKeys) GoString() string {
	return "pcv3credential.BorrowedD1OuterCredentialKeys([REDACTED])"
}

// Role returns the immutable physical front or tail role.
func (owner *D1OuterCredentialOwner) Role() KeyRole {
	if owner == nil {
		return KeyRoleNotReplica
	}
	return owner.role
}

// WithKeys lends the fixed three-key outer credential schedule. The callback
// must not call Close synchronously; Close waits for active callbacks.
func (owner *D1OuterCredentialOwner) WithKeys(
	ctx context.Context,
	callback func(*BorrowedD1OuterCredentialKeys) error,
) error {
	if owner == nil || callback == nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	return withD1OwnedMaterial(
		ctx,
		owner.state,
		func(state *d1BorrowState[d1OuterCredentialMaterial]) error {
			return callback(&BorrowedD1OuterCredentialKeys{state: state})
		},
	)
}

// Close clears every outer credential secret after active borrows return.
func (owner *D1OuterCredentialOwner) Close() {
	if owner == nil {
		return
	}
	closeD1OwnedMaterial(owner.state)
}

// CopyKey copies one fixed outer credential key into caller-owned storage.
func (keys *BorrowedD1OuterCredentialKeys) CopyKey(
	label D1OuterCredentialLabel,
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
	for index := range state.material.keys {
		key := &state.material.keys[index]
		if key.label == label && key.secret != nil {
			copy(destination, key.secret.Bytes())
			return nil
		}
	}
	return newOwnerError(OwnerErrorUnknownKey)
}

// D1OuterKeyOwner is the cleanup authority for one OuterKey, its PRK, and the
// complete fixed replica/body schedule.
type D1OuterKeyOwner struct {
	state *d1OwnerState[d1OuterKeyMaterial]
}

func (*D1OuterKeyOwner) String() string {
	return "pcv3credential.D1OuterKeyOwner([REDACTED])"
}

func (*D1OuterKeyOwner) GoString() string {
	return "pcv3credential.D1OuterKeyOwner([REDACTED])"
}

// BorrowedD1OuterKeys is valid only during its WithKeys callback.
type BorrowedD1OuterKeys struct {
	state *d1BorrowState[d1OuterKeyMaterial]
}

func (*BorrowedD1OuterKeys) String() string {
	return "pcv3credential.BorrowedD1OuterKeys([REDACTED])"
}

func (*BorrowedD1OuterKeys) GoString() string {
	return "pcv3credential.BorrowedD1OuterKeys([REDACTED])"
}

// NewD1OuterKeyOwner takes ownership of outerKey and derives the complete
// fixed D1 schedule.
func NewD1OuterKeyOwner(outerKey []byte) (*D1OuterKeyOwner, error) {
	return newD1OuterKeyOwnerWith(
		outerKey,
		defaultHKDFExtract,
		defaultHKDFExpand,
	)
}

// WithKeys lends the OuterKey and its fixed derived schedule. The callback
// must not call Close synchronously; Close waits for active callbacks.
func (owner *D1OuterKeyOwner) WithKeys(
	ctx context.Context,
	callback func(*BorrowedD1OuterKeys) error,
) error {
	if owner == nil || callback == nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	return withD1OwnedMaterial(
		ctx,
		owner.state,
		func(state *d1BorrowState[d1OuterKeyMaterial]) error {
			return callback(&BorrowedD1OuterKeys{state: state})
		},
	)
}

// Close clears the OuterKey, PRK, and all derived outer keys after active
// borrows return.
func (owner *D1OuterKeyOwner) Close() {
	if owner == nil {
		return
	}
	closeD1OwnedMaterial(owner.state)
}

// CopyOuterKey copies the live OuterKey into caller-owned storage.
func (keys *BorrowedD1OuterKeys) CopyOuterKey(destination []byte) error {
	if keys == nil || keys.state == nil {
		return newOwnerError(OwnerErrorBorrowExpired)
	}
	state := keys.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if !state.active || state.material == nil ||
		state.material.key == nil || state.material.key.secret == nil {
		return newOwnerError(OwnerErrorBorrowExpired)
	}
	if len(destination) != derivedKeyBytes {
		return newOwnerError(OwnerErrorDestination)
	}
	copy(destination, state.material.key.secret.Bytes())
	return nil
}

// CopyKey copies one fixed D1 replica/body key into caller-owned storage.
func (keys *BorrowedD1OuterKeys) CopyKey(
	label D1OuterKeyLabel,
	role KeyRole,
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
	for index := range state.material.keys {
		key := &state.material.keys[index]
		if key.request.label != label || key.request.role != role {
			continue
		}
		if len(destination) != key.request.outputBytes {
			return newOwnerError(OwnerErrorDestination)
		}
		if key.secret == nil {
			return newOwnerError(OwnerErrorBorrowExpired)
		}
		copy(destination, key.secret.Bytes())
		return nil
	}
	return newOwnerError(OwnerErrorUnknownKey)
}

// WithD1OuterCredentialOwner performs one fixed Paranoid-1 outer derivation
// and keeps its owner valid only for callback duration.
func WithD1OuterCredentialOwner(
	ctx context.Context,
	input *CredentialInputOuter,
	salt []byte,
	role KeyRole,
	admitter Admitter,
	callback func(*D1OuterCredentialOwner) error,
) error {
	return withD1OuterCredentialOwner(
		ctx,
		input,
		salt,
		role,
		admitter,
		d1OuterDerivationSeams{
			derive:  deriveArgon2ID,
			extract: defaultHKDFExtract,
			expand:  defaultHKDFExpand,
		},
		callback,
	)
}

// WithD1CreationCredentialRoots fixes the creation order as front outer, tail
// outer, then a callback-owned normal input for the inner derivation.
func WithD1CreationCredentialRoots(
	ctx context.Context,
	normal *CredentialInputNormal,
	outer *CredentialInputOuter,
	salts D1CreationSalts,
	admitter Admitter,
	callback func(
		front *D1OuterCredentialOwner,
		tail *D1OuterCredentialOwner,
		inner *CredentialInputNormal,
	) error,
) error {
	return withD1CreationCredentialRoots(
		ctx,
		normal,
		outer,
		salts,
		admitter,
		d1OuterDerivationSeams{
			derive:  deriveArgon2ID,
			extract: defaultHKDFExtract,
			expand:  defaultHKDFExpand,
		},
		callback,
	)
}

// WithD1NormalCredentialOwner consumes the normal D1 credential input and a
// transferred VolumeKey, derives the fixed full Paranoid-1 schedule, and keeps
// the resulting owner valid only for callback duration.
func WithD1NormalCredentialOwner(
	ctx context.Context,
	input *CredentialInputNormal,
	factors *ValidatedFactors,
	argonSalt [kdfSaltBytes]byte,
	volumeID [scheduleVolumeIDBytes]byte,
	volumeKeyTransfer []byte,
	admitter Admitter,
	callback func(*Owner) error,
) error {
	return withD1NormalCredentialOwner(
		ctx,
		input,
		factors,
		argonSalt,
		volumeID,
		volumeKeyTransfer,
		admitter,
		d1NormalOwnerSeams{
			derive:  deriveArgon2ID,
			extract: defaultHKDFExtract,
			expand:  defaultHKDFExpand,
		},
		callback,
	)
}

func withD1NormalCredentialOwner(
	ctx context.Context,
	input *CredentialInputNormal,
	factors *ValidatedFactors,
	argonSalt [kdfSaltBytes]byte,
	volumeID [scheduleVolumeIDBytes]byte,
	volumeKeyTransfer []byte,
	admitter Admitter,
	seams d1NormalOwnerSeams,
	callback func(*Owner) error,
) error {
	defer input.Close()
	defer pcsecret.SecureZero(volumeKeyTransfer)

	if ctx == nil || input == nil || factors == nil || admitter == nil ||
		callback == nil || len(volumeKeyTransfer) != derivedKeyBytes ||
		!validD1NormalOwnerSeams(seams) {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	metadata := OwnerMetadata{
		Suite:          SuiteParanoid1,
		ExpectedPolicy: factors.expectedPolicy,
		CredentialMode: factors.mode,
		KeyfileMode:    factors.keyfileMode,
		KeyfileCount:   uint16(len(factors.descriptors)), //nolint:gosec // Validated factors are bounded to 64 keyfiles.
		ArgonSalt:      argonSalt,
		VolumeID:       volumeID,
	}
	if !validOwnerMetadata(metadata) {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	if ctx.Err() != nil {
		return newKDFError(KDFErrorCancelled, SuiteParanoid1)
	}

	schedule, err := fullReaderSchedule(SuiteParanoid1)
	if err != nil {
		return err
	}
	root, err := runCredentialKDF(
		ctx,
		input,
		argonSalt[:],
		SuiteParanoid1,
		admitter,
		seams.derive,
	)
	if err != nil {
		return err
	}
	defer root.close()
	if ctx.Err() != nil {
		return newKDFError(KDFErrorCancelled, SuiteParanoid1)
	}

	material, err := deriveKeyMaterialWith(
		schedule,
		root,
		&volumeKey{secret: pcsecret.SecretFrom(volumeKeyTransfer)},
		volumeID[:],
		seams.extract,
		seams.expand,
	)
	if err != nil {
		return err
	}
	owner, err := newOwner(metadata, material)
	if err != nil {
		return err
	}
	defer owner.Close()
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}
	return callback(owner)
}

func validD1NormalOwnerSeams(seams d1NormalOwnerSeams) bool {
	return seams.derive != nil && seams.extract != nil && seams.expand != nil
}

func withD1CreationCredentialRoots(
	ctx context.Context,
	normal *CredentialInputNormal,
	outer *CredentialInputOuter,
	salts D1CreationSalts,
	admitter Admitter,
	seams d1OuterDerivationSeams,
	callback func(
		front *D1OuterCredentialOwner,
		tail *D1OuterCredentialOwner,
		inner *CredentialInputNormal,
	) error,
) error {
	defer normal.Close()
	defer outer.Close()
	if ctx == nil || normal == nil || outer == nil || admitter == nil ||
		callback == nil || !validD1OuterDerivationSeams(seams) {
		return newKDFError(KDFErrorInvalidRequest, SuiteParanoid1)
	}

	front, err := deriveD1OuterCredentialOwner(
		ctx,
		outer,
		salts.Front[:],
		KeyRolePrimary,
		admitter,
		seams,
	)
	if err != nil {
		return err
	}
	defer front.Close()
	if ctx.Err() != nil {
		return newKDFError(KDFErrorCancelled, SuiteParanoid1)
	}

	tail, err := deriveD1OuterCredentialOwner(
		ctx,
		outer,
		salts.Tail[:],
		KeyRoleBackup,
		admitter,
		seams,
	)
	if err != nil {
		return err
	}
	defer tail.Close()
	if ctx.Err() != nil {
		return newKDFError(KDFErrorCancelled, SuiteParanoid1)
	}
	return callback(front, tail, normal)
}

func withD1OuterCredentialOwner(
	ctx context.Context,
	input *CredentialInputOuter,
	salt []byte,
	role KeyRole,
	admitter Admitter,
	seams d1OuterDerivationSeams,
	callback func(*D1OuterCredentialOwner) error,
) error {
	if callback == nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	owner, err := deriveD1OuterCredentialOwner(
		ctx,
		input,
		salt,
		role,
		admitter,
		seams,
	)
	if err != nil {
		return err
	}
	defer owner.Close()
	return callback(owner)
}

func deriveD1OuterCredentialOwner(
	ctx context.Context,
	input *CredentialInputOuter,
	salt []byte,
	role KeyRole,
	admitter Admitter,
	seams d1OuterDerivationSeams,
) (*D1OuterCredentialOwner, error) {
	if ctx == nil || input == nil || admitter == nil ||
		(role != KeyRolePrimary && role != KeyRoleBackup) ||
		!validD1OuterDerivationSeams(seams) {
		return nil, newKDFError(KDFErrorInvalidRequest, SuiteParanoid1)
	}

	var owner *D1OuterCredentialOwner
	err := input.withInput(func(outerInput []byte) error {
		secret, err := runFixedProfileKDFBorrowed(
			ctx,
			outerInput,
			salt,
			SuiteParanoid1,
			admitter,
			seams.derive,
		)
		if err != nil {
			return err
		}
		root := &d1OuterCredentialRoot{secret: secret}
		owner, err = newD1OuterCredentialOwnerWith(
			root,
			salt,
			role,
			seams.extract,
			seams.expand,
		)
		return err
	})
	if err != nil {
		if owner != nil {
			owner.Close()
		}
		return nil, err
	}
	return owner, nil
}

func newD1OuterCredentialOwnerWith(
	root *d1OuterCredentialRoot,
	salt []byte,
	role KeyRole,
	extract hkdfExtractor,
	expand hkdfExpander,
) (*D1OuterCredentialOwner, error) {
	ownedRoot := takeD1OuterCredentialRoot(root)
	material := &d1OuterCredentialMaterial{root: ownedRoot}
	success := false
	defer func() {
		if !success {
			material.close()
		}
	}()

	if (role != KeyRolePrimary && role != KeyRoleBackup) ||
		len(salt) != kdfSaltBytes || extract == nil || expand == nil ||
		material.root == nil || material.root.secret == nil ||
		material.root.secret.Len() != credentialRootBytes {
		return nil, newScheduleError(
			ScheduleErrorInvalidRequest,
			SuiteParanoid1,
			-1,
		)
	}

	returned, err := extract(material.root.secret.Bytes(), salt)
	secret, err := ownProviderResult(
		returned,
		err,
		SuiteParanoid1,
		-1,
		ScheduleErrorExtract,
	)
	if err != nil {
		return nil, err
	}
	material.prk = &d1OuterCredentialPRK{secret: secret}

	labels := fixedD1OuterCredentialLabels()
	material.keys = make([]d1OuterCredentialKey, len(labels))
	for index, label := range labels {
		returned, err = expand(
			material.prk.secret.Bytes(),
			scheduleInfoFor(string(label), SuiteParanoid1, role),
			derivedKeyBytes,
		)
		secret, err = ownProviderResult(
			returned,
			err,
			SuiteParanoid1,
			index,
			ScheduleErrorExpand,
		)
		if err != nil {
			return nil, err
		}
		material.keys[index] = d1OuterCredentialKey{
			label:  label,
			secret: secret,
		}
	}

	owner := &D1OuterCredentialOwner{
		role: role,
		state: newD1OwnerState(
			material,
			func(owned *d1OuterCredentialMaterial) { owned.close() },
		),
	}
	success = true
	return owner, nil
}

func newD1OuterKeyOwnerWith(
	outerKey []byte,
	extract hkdfExtractor,
	expand hkdfExpander,
) (*D1OuterKeyOwner, error) {
	material := &d1OuterKeyMaterial{
		key: &d1OuterKey{secret: pcsecret.SecretFrom(outerKey)},
	}
	success := false
	defer func() {
		if !success {
			material.close()
		}
	}()

	if extract == nil || expand == nil ||
		material.key.secret.Len() != derivedKeyBytes {
		return nil, newScheduleError(
			ScheduleErrorInvalidRequest,
			SuiteParanoid1,
			-1,
		)
	}

	rootSalt := sha3.Sum256([]byte(d1OuterRootDomain))
	returned, err := extract(material.key.secret.Bytes(), rootSalt[:])
	secret, err := ownProviderResult(
		returned,
		err,
		SuiteParanoid1,
		-1,
		ScheduleErrorExtract,
	)
	if err != nil {
		return nil, err
	}
	material.prk = &d1OuterPRK{secret: secret}

	requests := fixedD1OuterKeyRequests()
	material.keys = make([]d1OuterDerivedKey, len(requests))
	for index, request := range requests {
		returned, err = expand(
			material.prk.secret.Bytes(),
			scheduleInfoFor(
				string(request.label),
				SuiteParanoid1,
				request.role,
			),
			request.outputBytes,
		)
		secret, err = ownProviderResultSized(
			returned,
			err,
			request.outputBytes,
			SuiteParanoid1,
			index,
			ScheduleErrorExpand,
		)
		if err != nil {
			return nil, err
		}
		material.keys[index] = d1OuterDerivedKey{
			request: request,
			secret:  secret,
		}
	}

	owner := &D1OuterKeyOwner{
		state: newD1OwnerState(
			material,
			func(owned *d1OuterKeyMaterial) { owned.close() },
		),
	}
	success = true
	return owner, nil
}

func fixedD1OuterCredentialLabels() [3]D1OuterCredentialLabel {
	return [...]D1OuterCredentialLabel{
		D1OuterCredentialWrapXChaCha20,
		D1OuterCredentialWrapSerpent,
		D1OuterCredentialWrapMAC,
	}
}

func fixedD1OuterKeyRequests() [7]d1OuterKeyRequest {
	return [...]d1OuterKeyRequest{
		{D1OuterReplicaMAC, KeyRolePrimary, derivedKeyBytes},
		{D1OuterReplicaMAC, KeyRoleBackup, derivedKeyBytes},
		{D1OuterPayloadXChaCha20, KeyRoleNotReplica, derivedKeyBytes},
		{D1OuterPayloadSerpent, KeyRoleNotReplica, derivedKeyBytes},
		{D1OuterPayloadMAC, KeyRoleNotReplica, derivedKeyBytes},
		{D1OuterPayloadXNoncePrefix, KeyRoleNotReplica, 16},
		{D1OuterPayloadSerpentPrefix, KeyRoleNotReplica, 8},
	}
}

func validD1OuterDerivationSeams(seams d1OuterDerivationSeams) bool {
	return seams.derive != nil && seams.extract != nil && seams.expand != nil
}

func takeD1OuterCredentialRoot(
	root *d1OuterCredentialRoot,
) *d1OuterCredentialRoot {
	if root == nil {
		return nil
	}
	owned := &d1OuterCredentialRoot{secret: root.secret}
	root.secret = nil
	return owned
}

func newD1OwnerState[T any](
	material *T,
	closeMaterial func(*T),
) *d1OwnerState[T] {
	return &d1OwnerState[T]{
		material:      material,
		closeMaterial: closeMaterial,
		closing:       make(chan struct{}),
	}
}

func withD1OwnedMaterial[T any](
	ctx context.Context,
	state *d1OwnerState[T],
	callback func(*d1BorrowState[T]) error,
) error {
	if ctx == nil || state == nil || callback == nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}
	select {
	case <-state.closing:
		return newOwnerError(OwnerErrorClosed)
	default:
	}

	state.mu.RLock()
	defer state.mu.RUnlock()
	select {
	case <-state.closing:
		return newOwnerError(OwnerErrorClosed)
	default:
	}
	if state.material == nil {
		return newOwnerError(OwnerErrorClosed)
	}
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}

	borrow := &d1BorrowState[T]{
		material: state.material,
		active:   true,
	}
	defer expireD1Borrow(borrow)
	if err := callback(borrow); err != nil {
		return newOwnerError(OwnerErrorCallback)
	}
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}
	return nil
}

func closeD1OwnedMaterial[T any](state *d1OwnerState[T]) {
	if state == nil {
		return
	}
	state.closingOnce.Do(func() {
		close(state.closing)
	})
	state.mu.Lock()
	defer state.mu.Unlock()
	state.closeOwned.Do(func() {
		if state.material != nil && state.closeMaterial != nil {
			state.closeMaterial(state.material)
		}
		state.material = nil
	})
}

func expireD1Borrow[T any](state *d1BorrowState[T]) {
	if state == nil {
		return
	}
	state.mu.Lock()
	state.active = false
	state.material = nil
	state.mu.Unlock()
}
