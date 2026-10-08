// Package crypto provides cryptographic primitives for Picocrypt volumes.
// This file contains memory zeroing utilities for secure cleanup of sensitive data.

package crypto

import "Picocrypt-NG/internal/secret"

// SecureZero overwrites a byte slice with zeros to prevent sensitive data
// from persisting in memory. This helps mitigate memory dump attacks and
// reduces the window during which keys are recoverable from RAM.
//
// SECURITY NOTE: Due to Go's garbage collector and potential compiler
// optimizations, this function cannot guarantee complete erasure. However,
// it significantly reduces the attack surface compared to no cleanup.
//
// The shared helper uses a non-inlined clear and runtime.KeepAlive without
// allocating a temporary zero buffer. Generated code remains compiler/platform
// dependent; the operation is best-effort cleanup, not complete memory erasure.
func SecureZero(b []byte) {
	secret.SecureZero(b)
}

// SecureZeroMultiple zeros multiple byte slices in a single call.
// Useful for cleaning up multiple related keys or buffers.
func SecureZeroMultiple(slices ...[]byte) {
	secret.SecureZeroMultiple(slices...)
}

// Secret preserves the legacy ownership API using shared memory custody.
type Secret = secret.Secret

func SecretFrom(b []byte) *Secret { return secret.SecretFrom(b) }
