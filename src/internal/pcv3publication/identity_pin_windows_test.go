//go:build windows

package pcv3publication

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestIdentityPinCannotBeInheritedByChildProcess(t *testing.T) {
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
	var flags uint32
	getHandleInformation := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")
	result, _, callErr := getHandleInformation.Call(pin.Fd(), uintptr(unsafe.Pointer(&flags)))
	if result == 0 || flags&windows.HANDLE_FLAG_INHERIT != 0 {
		t.Fatalf("private identity handle could be inherited: flags=%x err=%v", flags, callErr)
	}
}
