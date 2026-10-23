//go:build windows

package pcv3publication

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Fixture metadata is independent of the directory barrier under test.
func nativeDirectorySyncSupported(t testing.TB, directory string) bool {
	t.Helper()
	version := windows.RtlGetVersion()
	if version.MajorVersion < 6 || version.MajorVersion == 6 && version.MinorVersion < 2 {
		return false
	}
	path, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		t.Fatal(err)
	}
	var volume [32768]uint16
	if err := windows.GetVolumePathName(path, &volume[0], uint32(len(volume))); err != nil {
		t.Fatalf("observe fixture volume root: %v", err)
	}
	var filesystem [32]uint16
	if err := windows.GetVolumeInformation(&volume[0], nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))); err != nil {
		t.Fatalf("observe fixture filesystem: %v", err)
	}
	if windows.UTF16ToString(filesystem[:]) != "NTFS" {
		return false
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("open fixture for device metadata: %v", err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Fatalf("close fixture metadata handle: %v", err)
		}
	}()
	query := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryVolumeInformationFile")
	if err := query.Find(); err != nil {
		t.Fatalf("find fixture volume query: %v", err)
	}
	var device struct{ Type, Characteristics uint32 }
	var status windows.IO_STATUS_BLOCK
	result, _, _ := query.Call(uintptr(handle), uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&device)), unsafe.Sizeof(device), 4)
	if result != 0 || status.Information != unsafe.Sizeof(device) {
		t.Fatalf("observe fixture device: status=%#x bytes=%d", result, status.Information)
	}
	switch device.Type {
	case 7:
	case 2:
		return false
	default:
		t.Fatalf("unclassified NTFS fixture device type: %d", device.Type)
	}
	if device.Characteristics&(0x10|0x40) != 0 {
		return false
	}
	switch drive := windows.GetDriveType(&volume[0]); drive {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE:
		return true
	case windows.DRIVE_REMOTE, windows.DRIVE_CDROM, windows.DRIVE_RAMDISK:
		return false
	default:
		t.Fatalf("unclassified NTFS fixture drive type: %d", drive)
		return false
	}
}

func TestWindowsDirectoryBarrierUsesPinnedHandleRatherThanPath(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	parent, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if !nativeDirectorySyncSupported(t, directory) {
		if err := nativeOperations().syncDirectory(parent); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("unsupported fixture directory durability = %v; want unsupported", err)
		}
		return
	}
	process := windows.CurrentProcess()
	var handle windows.Handle
	if err := windows.DuplicateHandle(process, windows.Handle(parent.Fd()), process, &handle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	alias := os.NewFile(uintptr(handle), filepath.Join(parent.Name(), "nonexistent-name"))
	defer alias.Close()
	if err := nativeOperations().syncDirectory(alias); err != nil {
		t.Fatalf("barrier through a pinned read-only directory handle: %v", err)
	}
	info, err := alias.Stat()
	if err != nil || !info.IsDir() {
		t.Fatalf("barrier consumed or changed the caller's directory handle: %v", err)
	}
}

func TestWindowsDirectoryBarrierRejectsInvalidObjects(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "regular-file"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, parent := range []*os.File{nil, file} {
		if err := nativeOperations().syncDirectory(parent); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("non-directory barrier = %v; want invalid object", err)
		}
	}
}
