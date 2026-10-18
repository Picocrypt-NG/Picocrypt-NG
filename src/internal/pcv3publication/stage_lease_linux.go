//go:build linux && !android

package pcv3publication

import (
	"os"

	"golang.org/x/sys/unix"
)

func leasedCleanupAvailable() bool { return true }

// A duplicate shares the directory's open file description. The lock therefore
// survives closing the writer or directory handle and can follow retained custody.
func acquireStageLease(parent *os.File) (*os.File, error) {
	lease, err := duplicateIdentityFile(parent)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lease.Close()
		return nil, err
	}
	return lease, nil
}
