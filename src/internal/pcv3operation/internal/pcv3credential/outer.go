package pcv3credential

import (
	pcsecret "Picocrypt-NG/internal/secret"
	"context"
	"crypto/sha3"
	"encoding/binary"
	"sync"
)

const d1OuterRootDomain = "Picocrypt-NG/PCV3/D1C/outer/root\x00"

// D1Profile binds the hidden payload suite to the D1C format. Both profiles
// use the same fixed Argon2id cost, independent of their stream/MAC choice.
type D1Profile uint16

const (
	D1ProfileStandard D1Profile = 0x0101
	D1ProfileParanoid D1Profile = 0x0102
	// Argon profile IDs and inner root markers occupy separate namespaces;
	// the derived-root marker never invokes the KDF runner.
	D1FixedKDFProfileID    uint8 = 0x03
	D1DerivedRootProfileID uint8 = 0x03
)

func (profile D1Profile) Suite() Suite {
	switch profile {
	case D1ProfileStandard:
		return SuiteStandard1
	case D1ProfileParanoid:
		return SuiteParanoid1
	default:
		return 0
	}
}

func D1ProfileForSuite(suite Suite) D1Profile {
	if suite == SuiteStandard1 {
		return D1ProfileStandard
	}
	if suite == SuiteParanoid1 {
		return D1ProfileParanoid
	}
	return 0
}

func fixedD1Profile() KDFProfile {
	return KDFProfile{ID: D1FixedKDFProfileID, Argon2Version: 0x13, Time: 8, MemoryKiB: 1048576, Parallelism: 8, SaltBytes: 16, OutputBytes: 32}
}

func d1ScheduleInfo(label string, profile D1Profile, role KeyRole) string {
	info := []byte("Picocrypt-NG/PCV3/D1C/HKDF\x00")
	var encoded [2]byte
	for _, value := range []uint16{3, 1, uint16(profile)} {
		binary.BigEndian.PutUint16(encoded[:], value)
		info = append(info, encoded[:]...)
	}
	info = append(info, byte(role))
	binary.BigEndian.PutUint16(encoded[:], uint16(len(label))) //nolint:gosec // Closed protocol label registry.
	info = append(info, encoded[:]...)
	return string(append(info, label...))
}

// D1OuterCredentialLabel is one immutable D1 bootstrap-wrap key purpose.
// Its distinct type prevents substitution into the normal-volume schedule.
type D1OuterCredentialLabel string

const (
	D1OuterCredentialWrapXChaCha20 D1OuterCredentialLabel = "outer/wrap/xchacha20" //nolint:gosec //gitleaks:allow // Public protocol label, not a credential.
	D1OuterCredentialWrapSerpent   D1OuterCredentialLabel = "outer/wrap/serpent"   //nolint:gosec // Public protocol label, not a credential.
	D1OuterCredentialWrapMAC       D1OuterCredentialLabel = "outer/wrap/mac"       //nolint:gosec // Public protocol label, not a credential.
	D1InnerCredentialWrapXChaCha20 D1OuterCredentialLabel = "inner/wrap/xchacha20" //nolint:gosec // Public protocol label.
	D1InnerCredentialWrapSerpent   D1OuterCredentialLabel = "inner/wrap/serpent"   //nolint:gosec // Public protocol label.
	D1InnerCredentialWrapMAC       D1OuterCredentialLabel = "inner/wrap/mac"       //nolint:gosec // Public protocol label.
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
	label   D1OuterCredentialLabel
	profile D1Profile
	secret  *pcsecret.Secret
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
	key     *d1OuterKey
	inner   *pcsecret.Secret
	profile D1Profile
	prk     *d1OuterPRK
	keys    []d1OuterDerivedKey
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
	if material.inner != nil {
		material.inner.Close()
		material.inner = nil
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

// D1OuterCredentialOwner owns one physical bootstrap's purpose- and profile-
// separated wrap keys. Its Argon root and PRK are cleared before publication.
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

// WithKeys lends the fixed two-purpose, two-profile wrap schedule. The callback
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
	return keys.CopyKeyForProfile(D1ProfileParanoid, label, destination)
}

func (keys *BorrowedD1OuterCredentialKeys) CopyKeyForProfile(profile D1Profile, label D1OuterCredentialLabel, destination []byte) error {
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
		if key.label == label && key.profile == profile && key.secret != nil {
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

// NewD1RootsOwner transfers two independently generated random roots. It is
// the production bootstrap entry; missing roots or unknown profiles fail closed.
func NewD1RootsOwner(outerKey, innerRoot []byte, profile D1Profile) (*D1OuterKeyOwner, error) {
	if len(innerRoot) != derivedKeyBytes || profile.Suite() == 0 {
		pcsecret.SecureZero(outerKey)
		pcsecret.SecureZero(innerRoot)
		return nil, newOwnerError(OwnerErrorInvalidRequest)
	}
	return newD1RootsOwnerWith(outerKey, innerRoot, profile, defaultHKDFExtract, defaultHKDFExpand)
}

func (keys *BorrowedD1OuterKeys) Profile() D1Profile {
	if keys == nil || keys.state == nil {
		return 0
	}
	keys.state.mu.RLock()
	defer keys.state.mu.RUnlock()
	if !keys.state.active || keys.state.material == nil {
		return 0
	}
	return keys.state.material.profile
}

func (keys *BorrowedD1OuterKeys) CopyInnerRoot(destination []byte) error {
	if keys == nil || keys.state == nil {
		return newOwnerError(OwnerErrorBorrowExpired)
	}
	keys.state.mu.RLock()
	defer keys.state.mu.RUnlock()
	if !keys.state.active || keys.state.material == nil || keys.state.material.inner == nil {
		return newOwnerError(OwnerErrorBorrowExpired)
	}
	if len(destination) != derivedKeyBytes {
		return newOwnerError(OwnerErrorDestination)
	}
	copy(destination, keys.state.material.inner.Bytes())
	return nil
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

// WithD1OuterCredentialOwner performs one fixed D1C Argon2id derivation and
// keeps both hidden-suite wrap schedules valid only for callback duration.
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

// WithD1CreationCredentialRoots derives the independent front and tail
// credentials sequentially and expires both owners after the callback.
func WithD1CreationCredentialRoots(
	ctx context.Context,
	outer *CredentialInputOuter,
	salts D1CreationSalts,
	admitter Admitter,
	callback func(
		front *D1OuterCredentialOwner,
		tail *D1OuterCredentialOwner,
	) error,
) error {
	return withD1CreationCredentialRoots(
		ctx,
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

func withD1CreationCredentialRoots(
	ctx context.Context,
	outer *CredentialInputOuter,
	salts D1CreationSalts,
	admitter Admitter,
	seams d1OuterDerivationSeams,
	callback func(
		front *D1OuterCredentialOwner,
		tail *D1OuterCredentialOwner,
	) error,
) error {
	defer outer.Close()
	if ctx == nil || outer == nil || admitter == nil ||
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
	return callback(front, tail)
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
		secret, err := runProfileKDFBorrowed(
			ctx,
			outerInput,
			salt,
			SuiteParanoid1,
			fixedD1Profile(),
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
	material.keys = make([]d1OuterCredentialKey, 0, 2*len(labels))
	for _, profile := range []D1Profile{D1ProfileStandard, D1ProfileParanoid} {
		for index, label := range labels {
			returned, err = expand(
				material.prk.secret.Bytes(),
				d1ScheduleInfo(string(label), profile, role),
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
			material.keys = append(material.keys, d1OuterCredentialKey{
				label:   label,
				profile: profile,
				secret:  secret,
			})
		}
	}
	material.root.close()
	material.root = nil
	material.prk.close()
	material.prk = nil

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

func newD1RootsOwnerWith(
	outerKey, innerRoot []byte,
	profile D1Profile,
	extract hkdfExtractor,
	expand hkdfExpander,
) (*D1OuterKeyOwner, error) {
	material := &d1OuterKeyMaterial{
		key:     &d1OuterKey{secret: pcsecret.SecretFrom(outerKey)},
		profile: profile,
	}
	if innerRoot != nil {
		material.inner = pcsecret.SecretFrom(innerRoot)
	}
	success := false
	defer func() {
		if !success {
			material.close()
		}
	}()

	if extract == nil || expand == nil || profile.Suite() == 0 ||
		material.key.secret.Len() != derivedKeyBytes ||
		material.inner == nil || material.inner.Len() != derivedKeyBytes {
		return nil, newScheduleError(
			ScheduleErrorInvalidRequest,
			SuiteParanoid1,
			-1,
		)
	}

	rootContext := binary.BigEndian.AppendUint16([]byte(d1OuterRootDomain), uint16(profile))
	rootSalt := sha3.Sum256(rootContext)
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
			d1ScheduleInfo(
				string(request.label),
				profile,
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

	material.prk.close()
	material.prk = nil
	owner := &D1OuterKeyOwner{
		state: newD1OwnerState(
			material,
			func(owned *d1OuterKeyMaterial) { owned.close() },
		),
	}
	success = true
	return owner, nil
}

func fixedD1OuterCredentialLabels() [6]D1OuterCredentialLabel {
	return [...]D1OuterCredentialLabel{
		D1OuterCredentialWrapXChaCha20,
		D1OuterCredentialWrapSerpent,
		D1OuterCredentialWrapMAC,
		D1InnerCredentialWrapXChaCha20,
		D1InnerCredentialWrapSerpent,
		D1InnerCredentialWrapMAC,
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
