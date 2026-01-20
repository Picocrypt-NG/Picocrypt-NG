// Package crypto provides cryptographic primitives for Picocrypt volumes.
// This file contains memory zeroing utilities for secure cleanup of sensitive data.

package crypto

import (
	"crypto/subtle"
	"hash"
	"sync"
)

// SecureZero overwrites a byte slice with zeros to prevent sensitive data
// from persisting in memory. This helps mitigate memory dump attacks and
// reduces the window during which keys are recoverable from RAM.
//
// SECURITY NOTE: Due to Go's garbage collector and potential compiler
// optimizations, this function cannot guarantee complete erasure. However,
// it significantly reduces the attack surface compared to no cleanup.
//
// The function uses subtle.ConstantTimeCopy to prevent the compiler from
// optimizing away the zeroing operation.
func SecureZero(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use constant-time copy from a zero slice to prevent optimization removal
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}

// SecureZeroMultiple zeros multiple byte slices in a single call.
// Useful for cleaning up multiple related keys or buffers.
func SecureZeroMultiple(slices ...[]byte) {
	for _, s := range slices {
		SecureZero(s)
	}
}

// SecureZeroHash resets a hash.Hash state to prevent partial hash data
// from remaining in memory. Note: not all Hash implementations may fully
// clear their internal state on Reset().
func SecureZeroHash(h hash.Hash) {
	if h != nil {
		h.Reset()
	}
}

// KeyMaterial wraps sensitive key data with automatic zeroing on Close().
// Use this for temporary key storage that must be cleaned up.
// KeyMaterial is safe for concurrent use.
//
// Example:
//
//	km := NewKeyMaterial(derivedKey)
//	defer km.Close()
//	// ... use km.Bytes() ...
type KeyMaterial struct {
	mu     sync.Mutex
	data   []byte
	closed bool
}

// NewKeyMaterial creates a new KeyMaterial wrapper.
// The data is copied to prevent modification of the original slice.
func NewKeyMaterial(data []byte) *KeyMaterial {
	if data == nil {
		return &KeyMaterial{}
	}
	// Make a copy to own the data
	copied := make([]byte, len(data))
	copy(copied, data)
	return &KeyMaterial{data: copied}
}

// Bytes returns the underlying key data.
// Returns nil if the KeyMaterial has been closed.
func (km *KeyMaterial) Bytes() []byte {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.closed {
		return nil
	}
	return km.data
}

// Len returns the length of the key data.
func (km *KeyMaterial) Len() int {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.closed || km.data == nil {
		return 0
	}
	return len(km.data)
}

// Close securely zeros the key data and marks it as closed.
// This method is idempotent - multiple calls are safe.
func (km *KeyMaterial) Close() {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.closed || km.data == nil {
		return
	}
	SecureZero(km.data)
	km.data = nil
	km.closed = true
}

// IsClosed returns whether the KeyMaterial has been closed.
func (km *KeyMaterial) IsClosed() bool {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.closed
}

// CryptoContext holds all sensitive cryptographic materials for an operation.
// Use Close() to securely zero all materials when done.
// CryptoContext is safe for concurrent use.
type CryptoContext struct {
	mu           sync.Mutex
	Key          []byte
	KeyfileKey   []byte
	MacSubkey    []byte
	SerpentKey   []byte
	HeaderSubkey []byte
	closed       bool
}

// Close securely zeros all cryptographic materials.
// This should be called via defer immediately after creating the context.
func (cc *CryptoContext) Close() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.closed {
		return
	}
	SecureZeroMultiple(
		cc.Key,
		cc.KeyfileKey,
		cc.MacSubkey,
		cc.SerpentKey,
		cc.HeaderSubkey,
	)
	cc.Key = nil
	cc.KeyfileKey = nil
	cc.MacSubkey = nil
	cc.SerpentKey = nil
	cc.HeaderSubkey = nil
	cc.closed = true
}
