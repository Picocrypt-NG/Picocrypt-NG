//go:build windows

package fileops

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type fileRenameInformation struct {
	replaceIfExists uint32
	rootDirectory   windows.Handle
	fileNameLength  uint32
	fileName        [1]uint16
}

func publishUnpackFile(source, target *os.File, sourceName, targetName string, expected os.FileInfo) (published, consumed bool, retErr error) {
	stage, err := openUnpackWindowsLeaf(source, sourceName, windows.FILE_GENERIC_READ, windows.FILE_OPEN)
	if err != nil {
		return false, false, err
	}
	defer func() {
		if err := stage.Close(); err != nil {
			retErr = errors.Join(retErr, err, ErrUnpackCleanupIncomplete)
		}
	}()
	info, err := stage.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(expected, info) {
		return false, false, errors.Join(os.ErrInvalid, err)
	}
	err = RenameFileNoReplaceWindows(stage, target, targetName)
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_NOT_SAME_DEVICE) {
		return false, false, errors.Join(errors.ErrUnsupported, err)
	}
	return err == nil, err == nil, err
}

func createUnpackCopyTarget(_ *os.Root, directory *os.File, name string) (*os.File, error) {
	return openUnpackWindowsLeaf(directory, name, windows.FILE_GENERIC_WRITE, windows.FILE_CREATE)
}

func removeUnpackCopyTarget(file *os.File) error { return RemoveFileByHandleWindows(file) }

// Open a basename relative to the pinned directory. The final-component
// reparse flag also works on Windows versions without OBJ_DONT_REPARSE.
func openUnpackWindowsLeaf(directory *os.File, leaf string, access, disposition uint32) (*os.File, error) {
	if !filepath.IsLocal(leaf) || filepath.Base(leaf) != leaf || leaf == "." {
		return nil, os.ErrInvalid
	}
	name, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return nil, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(directory.Fd()),
		ObjectName:    name,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access|windows.FILE_READ_ATTRIBUTES|windows.DELETE|windows.SYNCHRONIZE,
		&attrs, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		disposition, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return nil, windowsFileStatusError(err)
	}
	if disposition == windows.FILE_OPEN {
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
			info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, errors.Join(os.ErrInvalid, err, windows.CloseHandle(handle))
		}
	}
	return os.NewFile(uintptr(handle), filepath.Join(directory.Name(), leaf)), nil
}

// RenameFileNoReplaceWindows moves original through its DELETE-capable handle
// to a basename relative to the pinned parent. The target must be absent.
func RenameFileNoReplaceWindows(original, parent *os.File, targetName string) error {
	if original == nil || parent == nil || !filepath.IsLocal(targetName) || filepath.Base(targetName) != targetName || targetName == "." {
		return os.ErrInvalid
	}
	renameBuffer, err := newWindowsRenameBuffer(targetName, windows.Handle(parent.Fd()))
	if err != nil {
		return err
	}
	var status windows.IO_STATUS_BLOCK
	return windowsFileStatusError(windows.NtSetInformationFile(
		windows.Handle(original.Fd()),
		&status,
		unsafe.SliceData(renameBuffer), //nolint:gosec // G103: checked buffer for FileRenameInformation.
		uint32(len(renameBuffer)),      //nolint:gosec // G115: buffer is at most MaxUint32 bytes.
		windows.FileRenameInformation,
	))
}

// RemoveFileByHandleWindows marks an owned object for deletion. The caller
// must have denied FILE_SHARE_DELETE since acquiring the original name.
func RemoveFileByHandleWindows(file *os.File) error {
	if file == nil {
		return os.ErrInvalid
	}
	var status windows.IO_STATUS_BLOCK
	disposition := byte(1)
	return windows.NtSetInformationFile(windows.Handle(file.Fd()), &status, &disposition, uint32(unsafe.Sizeof(disposition)), windows.FileDispositionInformation)
}

func windowsFileStatusError(err error) error {
	var status windows.NTStatus
	if errors.As(err, &status) {
		return status.Errno()
	}
	return err
}

func newWindowsRenameBuffer(targetName string, parent windows.Handle) ([]byte, error) {
	name, err := windows.UTF16FromString(targetName)
	if err != nil {
		return nil, err
	}
	name = name[:len(name)-1]
	nameBytes := uint64(len(name)) * 2
	// Include the complete ABI structure (including its trailing alignment),
	// followed by enough storage for the name. FileNameLength excludes padding.
	bufferBytes := uint64(unsafe.Sizeof(fileRenameInformation{})) + nameBytes
	if nameBytes > math.MaxUint32 || bufferBytes > math.MaxUint32 || bufferBytes > uint64(math.MaxInt) {
		return nil, syscall.EINVAL
	}

	buffer := make([]byte, int(bufferBytes))
	information := (*fileRenameInformation)(unsafe.Pointer(unsafe.SliceData(buffer))) //nolint:gosec // G103: buffer includes the complete native ABI structure and checked trailing UTF-16 storage.
	information.rootDirectory = parent
	information.fileNameLength = uint32(nameBytes)
	copy(unsafe.Slice(&information.fileName[0], len(name)), name) //nolint:gosec // G103: nameBytes and bufferBytes above reserve this exact trailing UTF-16 extent.
	return buffer, nil
}
