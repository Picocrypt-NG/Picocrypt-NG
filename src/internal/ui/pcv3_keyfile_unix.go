//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ui

import (
	"Picocrypt-NG/internal/fileops"
	"os"

	"golang.org/x/sys/unix"
)

// The descriptor must be checked for regular-file status after opening. A
// nonblocking open also rejects a FIFO substituted after path selection without
// waiting for a peer. O_NONBLOCK has no effect on regular-file reads.
func openPCV3InputFile(path string) (*os.File, error) {
	return fileops.OpenExistingNoSymlink(path, os.O_RDONLY|unix.O_NONBLOCK)
}
