//go:build linux

package pcv3publication

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// unixRenameat2NoReplace is the renameat2(RENAME_NOREPLACE) syscall behind a
// package seam so tests can simulate a kernel without renameat2 support.
var unixRenameat2NoReplace = func(parentFD int, oldName, newName string) error {
	return unix.Renameat2(parentFD, oldName, parentFD, newName, unix.RENAME_NOREPLACE)
}

// renameNoReplace atomically renames oldName to newName inside the single
// directory pinned by parentFD, refusing to replace an existing newName.
// Kernels before 3.15 lack renameat2 (Android 7 devices commonly ship kernel
// 3.10) and fail every call with ENOSYS; only for ENOSYS this falls back to
// link(2)+unlink(2), which keeps the same atomic no-replace refusal (EEXIST).
// Both names live in the same pinned directory, so link(2) cannot cross
// filesystems (EXDEV is impossible by construction) and no copy is ever made.
// A filesystem without hard-link support fails link(2) and the error flows
// through the caller's identity-based classification, staying fail-closed.
// If link(2) succeeds but unlink(2) fails, both names reference the staged
// inode; the caller's probes classify that as indeterminate and preserve both
// names instead of deleting anything. linkFallbackFailed owns the platform
// decision for a failed link(2); see the linux and android implementations.
func renameNoReplace(parentFD int, oldName, newName string) error {
	err := unixRenameat2NoReplace(parentFD, oldName, newName)
	if !errors.Is(err, unix.ENOSYS) {
		return err
	}
	linkErr := unix.Linkat(parentFD, oldName, parentFD, newName, 0)
	if linkErr == nil {
		return unix.Unlinkat(parentFD, oldName, 0)
	}
	return linkFallbackFailed(parentFD, oldName, newName, linkErr)
}

func nativeOperations() platformOperations {
	return platformOperations{
		atomicPublish: func(parent *os.File, stageName, targetName string, policy Policy) error {
			if policy != PolicyNoReplace {
				return errors.ErrUnsupported
			}
			parentFD := int(parent.Fd())
			return renameNoReplace(parentFD, stageName, targetName)
		},
		syncDirectory: func(parent *os.File) error {
			return unix.Fsync(int(parent.Fd()))
		},
	}
}
