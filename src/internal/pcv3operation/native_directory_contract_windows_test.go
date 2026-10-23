//go:build windows

package pcv3operation

import (
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

// Fixture metadata is independent of the directory barrier under test.
func nativeOperationDirectorySyncSupported(t testing.TB, directory string) bool {
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
