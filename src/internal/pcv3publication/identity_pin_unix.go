//go:build linux || android || darwin

package pcv3publication

import (
	"os"

	"golang.org/x/sys/unix"
)

func duplicateIdentityFile(file *os.File) (*os.File, error) {
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}
