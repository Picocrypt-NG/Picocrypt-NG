//go:build android || linux

package mobile

import "golang.org/x/sys/unix"

func setDescriptorNonblocking(fd int) error {
	return unix.SetNonblock(fd, true)
}
