package fileops

import "golang.org/x/sys/unix"

var unpackLinkStatfs = unix.Fstatfs

func unpackLinkUnsupportedFilesystem(parentFD int) bool {
	var stat unix.Statfs_t
	if err := unpackLinkStatfs(parentFD, &stat); err != nil {
		return false
	}
	// Linux VFS returns EPERM when the target filesystem has no link operation.
	return stat.Type == unix.MSDOS_SUPER_MAGIC || stat.Type == unix.EXFAT_SUPER_MAGIC
}
