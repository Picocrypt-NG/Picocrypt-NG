//go:build darwin

package fileops

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

// Kept behind a syscall seam to exercise unsupported filesystems and EINTR.
var darwinFullSync = func(fd uintptr) error {
	_, err := unix.FcntlInt(fd, unix.F_FULLFSYNC, 0)
	return err
}

// SyncDirectory requires directory entry and journal changes to pass a full device barrier after
// fsync. Unsupported full-sync must not grant durable publication authority.
func SyncDirectory(parent *os.File) error {
	for {
		err := unix.Fsync(int(parent.Fd()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	for {
		err := darwinFullSync(parent.Fd())
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
