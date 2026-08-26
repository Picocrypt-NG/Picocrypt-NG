//go:build android || linux

package mobile

import "golang.org/x/sys/unix"

func preparePCV3ArchiveSAFNonblocking(fd int64) bool {
	return unix.SetNonblock(int(fd), true) == nil
}
