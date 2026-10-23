//go:build windows

package fileops

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SyncDirectory flushes a pinned local NTFS directory. Other storage backends
// retain an uncertain durability result rather than inheriting NTFS guarantees.
func SyncDirectory(parent *os.File) error {
	if parent == nil {
		return os.ErrInvalid
	}
	connection, err := parent.SyscallConn()
	if err != nil {
		return err
	}
	var barrierErr error
	controlErr := connection.Control(func(handle uintptr) {
		barrierErr = syncWindowsDirectory(windows.Handle(handle))
	})
	return errors.Join(controlErr, barrierErr)
}

func syncWindowsDirectory(original windows.Handle) (err error) {
	var expected windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(original, &expected); err != nil {
		return err
	}
	if expected.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || expected.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return os.ErrInvalid
	}
	version := windows.RtlGetVersion()
	if version.MajorVersion < 6 || version.MajorVersion == 6 && version.MinorVersion < 2 {
		return errors.ErrUnsupported
	}
	// An empty relative NT name reopens the original directory, as in os.Root.
	// Reopening by File.Name() would lose the caller's namespace pin.
	name, err := windows.NewNTUnicodeString("")
	if err != nil {
		return err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: original,
		ObjectName:    name,
		Attributes:    windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
		&attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, windows.CloseHandle(handle)) }()
	var current windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &current); err != nil {
		return err
	}
	if current.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || current.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		current.VolumeSerialNumber != expected.VolumeSerialNumber || current.FileIndexHigh != expected.FileIndexHigh || current.FileIndexLow != expected.FileIndexLow {
		return os.ErrInvalid
	}
	if err := windowsLocalNTFS(handle); err != nil {
		return err
	}
	return windows.FlushFileBuffers(handle)
}

func windowsLocalNTFS(handle windows.Handle) error {
	var filesystem [32]uint16
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))); err != nil {
		return err
	}
	if windows.UTF16ToString(filesystem[:]) != "NTFS" {
		return errors.ErrUnsupported
	}
	query := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryVolumeInformationFile")
	if err := query.Find(); err != nil {
		return err
	}
	// FILE_FS_DEVICE_INFORMATION, FileFsDeviceInformation (4), MS-FSCC 2.5.10.
	var device struct{ Type, Characteristics uint32 }
	var status windows.IO_STATUS_BLOCK
	result, _, _ := query.Call(uintptr(handle), uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&device)), unsafe.Sizeof(device), 4) //nolint:gosec // G103: synchronous native query uses x/sys IO_STATUS_BLOCK and an exact 8-byte FILE_FS_DEVICE_INFORMATION buffer.
	if result != 0 {
		return windows.NTStatus(result)
	}
	if status.Information != unsafe.Sizeof(device) {
		return errors.ErrUnsupported
	}
	volume, err := windowsVolumeRootByHandle(handle)
	if err != nil {
		return err
	}
	if !windowsDurableVolume(device.Type, device.Characteristics, windows.GetDriveType(volume)) {
		return errors.ErrUnsupported
	}
	return nil
}

func windowsDurableVolume(deviceType, characteristics, driveType uint32) bool {
	// FILE_VIRTUAL_VOLUME includes memory-backed storage. Persistent virtual
	// volumes with this flag remain outside the verified durability scope too.
	return deviceType == 7 && characteristics&(0x10|0x40) == 0 &&
		(driveType == windows.DRIVE_FIXED || driveType == windows.DRIVE_REMOVABLE)
}

func windowsVolumeRootByHandle(handle windows.Handle) (*uint16, error) {
	buffer := make([]uint16, windows.MAX_PATH)
	for {
		// VOLUME_NAME_GUID identifies the handle's volume without drive-letter
		// resolution. The returned name is used only for a metadata query.
		size, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 1)
		if err != nil {
			return nil, errors.Join(errors.ErrUnsupported, err)
		}
		if size < uint32(len(buffer)) {
			root, err := windowsVolumeGUIDRoot(windows.UTF16ToString(buffer[:size]))
			if err != nil {
				return nil, err
			}
			return windows.UTF16PtrFromString(root)
		}
		if size > windows.MAX_LONG_PATH || len(buffer) == windows.MAX_LONG_PATH {
			return nil, errors.ErrUnsupported
		}
		// An insufficient-buffer result includes the terminating NUL. Ensure
		// progress even if the observed name changes between metadata queries.
		next := int(size)
		if next <= len(buffer) {
			next = min(len(buffer)*2, windows.MAX_LONG_PATH)
		}
		buffer = make([]uint16, next)
	}
}

func windowsVolumeGUIDRoot(path string) (string, error) {
	const prefix = `\\?\Volume`
	const rootLength = len(prefix) + 38 + 1
	if len(path) < rootLength || !strings.HasPrefix(path, prefix+"{") || path[rootLength-1] != '\\' {
		return "", errors.ErrUnsupported
	}
	if _, err := windows.GUIDFromString(path[len(prefix) : rootLength-1]); err != nil {
		return "", errors.ErrUnsupported
	}
	return path[:rootLength], nil
}
