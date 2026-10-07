//go:build linux || android || darwin

package pcv3publication

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIdentityPinCannotBeInheritedAcrossExec(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "private-output"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	pin, err := duplicateIdentityFile(file)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	flags, err := unix.FcntlInt(pin.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("private identity descriptor could survive exec: flags=%x err=%v", flags, err)
	}
}
