package fileops

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnpackLinkErrorAllowsExclusiveCopyOnFAT(t *testing.T) {
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	original := unpackLinkStatfs
	t.Cleanup(func() { unpackLinkStatfs = original })

	for _, row := range []struct {
		name      string
		fs        unix.Statfs_t
		linkErr   error
		probeErr  error
		allowCopy bool
	}{
		{name: "FAT", fs: unix.Statfs_t{Type: 0x4d44}, linkErr: unix.EPERM, allowCopy: true},
		{name: "exFAT", fs: unix.Statfs_t{Type: 0x2011bab0}, linkErr: unix.EPERM, allowCopy: true},
		{name: "ext4", fs: unix.Statfs_t{Type: 0xef53}, linkErr: unix.EPERM},
		{name: "failed probe", fs: unix.Statfs_t{Type: 0x4d44}, linkErr: unix.EPERM, probeErr: unix.EIO},
		{name: "existing FAT target", fs: unix.Statfs_t{Type: 0x4d44}, linkErr: unix.EEXIST},
	} {
		t.Run(row.name, func(t *testing.T) {
			unpackLinkStatfs = func(fd int, stat *unix.Statfs_t) error {
				if fd != int(parent.Fd()) {
					t.Fatalf("filesystem probe received fd %d, want held parent %d", fd, parent.Fd())
				}
				*stat = row.fs
				return row.probeErr
			}
			got := unpackLinkError(parent, row.linkErr)
			if !errors.Is(got, row.linkErr) || errors.Is(got, errors.ErrUnsupported) != row.allowCopy {
				t.Fatalf("publication error = %v; want %v with exclusive copy allowed=%t", got, row.linkErr, row.allowCopy)
			}
		})
	}
}
