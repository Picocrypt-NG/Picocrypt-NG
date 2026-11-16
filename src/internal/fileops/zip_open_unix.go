//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package fileops

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openZIPInputInRoot(root *os.Root, name string) (*os.File, error) {
	// Root.OpenFile resolves symlinks itself, even if O_NOFOLLOW is supplied.
	// Open the single leaf relative to the validated directory descriptor so
	// the kernel enforces no-follow and nonblocking admission atomically.
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	fd, openErr := unix.Openat(int(directory.Fd()), name, regularReadFlags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	err = errors.Join(openErr, directory.Close())
	if err != nil {
		if openErr == nil {
			err = errors.Join(err, unix.Close(fd))
		}
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(root.Name(), name)), nil
}
