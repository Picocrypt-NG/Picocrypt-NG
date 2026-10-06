//go:build linux

package pcv3publication

import (
	"os"
	"syscall"
)

func existingMoveIdentityMatches(info os.FileInfo, device, inode uint64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat != nil && info.Mode().IsRegular() && stat.Dev == device && stat.Ino == inode
}
