package pcv3credential

import (
	"context"
	"sync"
)

// OwnerMetadata is the immutable public snapshot associated with one admitted
// Phase-2 key owner.
type OwnerMetadata struct {
	Suite          Suite
	ExpectedPolicy FactorPolicy
	CredentialMode CredentialMode
	KeyfileMode    KeyfileMode
	KeyfileCount   uint16
	ArgonSalt      [kdfSaltBytes]byte
	VolumeID       [scheduleVolumeIDBytes]byte
}

// OwnerErrorCode identifies a public, non-secret owner failure.
type OwnerErrorCode uint8

const (
	OwnerErrorInvalidRequest OwnerErrorCode = iota + 1
	OwnerErrorClosed
	OwnerErrorBorrowExpired
	OwnerErrorDestination
	OwnerErrorUnknownKey
	OwnerErrorCallback
	OwnerErrorCancelled
)

// OwnerError contains public identifiers only.
type OwnerError struct {
	Code OwnerErrorCode
}

func (err *OwnerError) Error() string {
	if err == nil {
		return "pcv3credential: owner failure"
	}
	switch err.Code {
	case OwnerErrorInvalidRequest:
		return "pcv3credential: invalid owner request"
	case OwnerErrorClosed:
		return "pcv3credential: owner is closed"
	case OwnerErrorBorrowExpired:
		return "pcv3credential: borrowed keys expired"
	case OwnerErrorDestination:
		return "pcv3credential: invalid borrowed-key destination"
	case OwnerErrorUnknownKey:
		return "pcv3credential: unknown borrowed key"
	case OwnerErrorCallback:
		return "pcv3credential: borrowed-key callback failed"
	case OwnerErrorCancelled:
		return "pcv3credential: borrowed-key callback cancelled"
	default:
		return "pcv3credential: owner failure"
	}
}

// Owner is the single cleanup authority for one complete Phase-2 key set.
type Owner struct {
	state *ownerState
}

type ownerState struct {
	mu sync.RWMutex

	metadata OwnerMetadata
	material *keyMaterial

	closing       chan struct{}
	closingOnce   sync.Once
	closeMaterial sync.Once
}

func (*Owner) String() string {
	return "pcv3credential.Owner([REDACTED])"
}

func (*Owner) GoString() string {
	return "pcv3credential.Owner([REDACTED])"
}

// BorrowedKeys is valid only during its WithKeys callback.
type BorrowedKeys struct {
	state *borrowedKeysState
}

type borrowedKeysState struct {
	mu       sync.RWMutex
	material *keyMaterial
	active   bool
}

func (*BorrowedKeys) String() string {
	return "pcv3credential.BorrowedKeys([REDACTED])"
}

func (*BorrowedKeys) GoString() string {
	return "pcv3credential.BorrowedKeys([REDACTED])"
}

func newOwner(
	metadata OwnerMetadata,
	material *keyMaterial,
) (*Owner, error) {
	if !validOwnerMetadata(metadata) || !validOwnerMaterial(metadata, material) {
		if material != nil {
			material.close()
		}
		return nil, newOwnerError(OwnerErrorInvalidRequest)
	}
	return &Owner{
		state: &ownerState{
			metadata: metadata,
			material: material,
			closing:  make(chan struct{}),
		},
	}, nil
}

// Metadata returns a value copy containing public parameters only.
func (owner *Owner) Metadata() OwnerMetadata {
	if owner == nil || owner.state == nil {
		return OwnerMetadata{}
	}
	return owner.state.metadata
}

// WithKeys lends bounded access to the owner's key material. A callback must
// not call Close synchronously: Close blocks until every active callback
// returns. A different goroutine may initiate Close while the callback is
// active.
func (owner *Owner) WithKeys(
	ctx context.Context,
	callback func(*BorrowedKeys) error,
) error {
	if owner == nil ||
		owner.state == nil ||
		ctx == nil ||
		callback == nil {
		return newOwnerError(OwnerErrorInvalidRequest)
	}
	state := owner.state
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

	borrowed := &BorrowedKeys{
		state: &borrowedKeysState{
			material: state.material,
			active:   true,
		},
	}
	defer borrowed.expire()
	if err := callback(borrowed); err != nil {
		return newOwnerError(OwnerErrorCallback)
	}
	if ctx.Err() != nil {
		return newOwnerError(OwnerErrorCancelled)
	}
	return nil
}

// Close releases all owner-controlled key material and blocks until active
// WithKeys callbacks return. It must not be called synchronously from within a
// WithKeys callback.
func (owner *Owner) Close() {
	if owner == nil || owner.state == nil {
		return
	}
	state := owner.state
	state.closingOnce.Do(func() {
		close(state.closing)
	})
	state.mu.Lock()
	defer state.mu.Unlock()
	state.closeMaterial.Do(func() {
		if state.material != nil {
			state.material.close()
			state.material = nil
		}
	})
}

// CopyVolumeKey copies the live VolumeKey into caller-owned storage.
func (keys *BorrowedKeys) CopyVolumeKey(destination []byte) error {
	if keys == nil || keys.state == nil {
		return newOwnerError(OwnerErrorBorrowExpired)
	}
	state := keys.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if !state.active ||
		state.material == nil ||
		state.material.volumeKey == nil ||
		state.material.volumeKey.secret == nil {
		return newOwnerError(OwnerErrorBorrowExpired)
	}
	if len(destination) != derivedKeyBytes {
		return newOwnerError(OwnerErrorDestination)
	}
	copy(destination, state.material.volumeKey.secret.Bytes())
	return nil
}

// CopyKey copies one requested derived key into caller-owned storage.
func (keys *BorrowedKeys) CopyKey(
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
		if state.material.keys[i].row.request == request &&
			state.material.keys[i].secret != nil {
			copy(destination, state.material.keys[i].secret.Bytes())
			return nil
		}
	}
	return newOwnerError(OwnerErrorUnknownKey)
}

func (keys *BorrowedKeys) expire() {
	if keys == nil || keys.state == nil {
		return
	}
	state := keys.state
	state.mu.Lock()
	state.active = false
	state.material = nil
	state.mu.Unlock()
}

func validOwnerMetadata(metadata OwnerMetadata) bool {
	switch metadata.Suite {
	case SuiteStandard1, SuiteParanoid1:
	default:
		return false
	}
	return validFactorPolicy(metadata.ExpectedPolicy) &&
		policyMatchesMode(metadata.ExpectedPolicy, metadata.CredentialMode) &&
		validCredentialTuple(
			metadata.CredentialMode,
			metadata.KeyfileMode,
			metadata.KeyfileCount,
		)
}

func validOwnerMaterial(
	metadata OwnerMetadata,
	material *keyMaterial,
) bool {
	if material == nil ||
		material.credentialRoot == nil ||
		material.credentialRoot.secret == nil ||
		material.credentialRoot.secret.Len() != credentialRootBytes ||
		material.volumeKey == nil ||
		material.volumeKey.secret == nil ||
		material.volumeKey.secret.Len() != derivedKeyBytes ||
		material.credentialPRK == nil ||
		material.credentialPRK.secret == nil ||
		material.credentialPRK.secret.Len() != derivedKeyBytes ||
		material.volumePRK == nil ||
		material.volumePRK.secret == nil ||
		material.volumePRK.secret.Len() != derivedKeyBytes ||
		len(material.keys) == 0 {
		return false
	}
	for i := range material.keys {
		if material.keys[i].row.suite != metadata.Suite ||
			material.keys[i].secret == nil ||
			material.keys[i].secret.Len() != derivedKeyBytes {
			return false
		}
	}
	return true
}

func newOwnerError(code OwnerErrorCode) *OwnerError {
	return &OwnerError{Code: code}
}
