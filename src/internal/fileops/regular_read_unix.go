//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package fileops

import (
	"os"

	"golang.org/x/sys/unix"
)

const regularReadFlags = os.O_RDONLY | unix.O_NONBLOCK
