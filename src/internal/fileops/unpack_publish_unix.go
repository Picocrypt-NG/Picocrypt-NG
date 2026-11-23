//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package fileops

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func publishUnpackFile(source, parent *os.File, sourceName, targetName string, _ os.FileInfo) (bool, bool, error) {
	err := unix.Linkat(int(source.Fd()), sourceName, int(parent.Fd()), targetName, 0)
	return err == nil, false, unpackLinkError(parent, err)
}

func unpackLinkError(parent *os.File, err error) error {
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EXDEV) ||
		(errors.Is(err, unix.EPERM) && unpackLinkUnsupportedFilesystem(int(parent.Fd()))) {
		return errors.Join(errors.ErrUnsupported, err)
	}
	return err
}
