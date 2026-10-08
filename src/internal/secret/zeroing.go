// Package secret provides shared cleanup helpers for sensitive memory.
package secret

import "runtime"

// SecureZero overwrites b in place without allocating a temporary zero buffer.
//
// The noinline boundary and KeepAlive support best-effort cleanup. Generated
// code remains compiler/platform dependent; this cannot guarantee erasure of
// prior compiler/runtime copies, registers, or other owners' buffers.
//
//go:noinline
func SecureZero(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// SecureZeroMultiple zeros multiple byte slices in a single call.
// Useful for cleaning up multiple related keys or buffers.
func SecureZeroMultiple(slices ...[]byte) {
	for _, s := range slices {
		SecureZero(s)
	}
}
