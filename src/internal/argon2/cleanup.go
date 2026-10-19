package argon2

import "runtime"

// wipeBlocks clears the owned workspace in place after its workers and output
// extraction finish. Like secret.SecureZero, this is best-effort cleanup of this
// storage, not a guarantee about compiler, hash, assembly, or register copies.
//
//go:noinline
func wipeBlocks(workspace []block) {
	clear(workspace)
	runtime.KeepAlive(workspace)
}
