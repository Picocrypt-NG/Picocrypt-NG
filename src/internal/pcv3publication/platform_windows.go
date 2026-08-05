//go:build windows

package pcv3publication

import (
	"errors"
	"math"
	"os"
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

func nativeOperations() platformOperations {
	return platformOperations{
		atomicPublish: windowsNoReplace,
		// Windows exposes no documented directory-handle flush contract that
		// proves the renamed directory entry durable. The common classifier
		// therefore reports a proven commit with uncertain durability.
		syncDirectory: func(*os.File) error {
			return errors.ErrUnsupported
		},
	}
}

func windowsNoReplace(
	parent *os.File,
	stageName string,
	targetName string,
	policy Policy,
) error {
	if policy != PolicyNoReplace {
		return errors.ErrUnsupported
	}
	renameBuffer, err := newWindowsRenameBuffer(targetName, windows.Handle(parent.Fd()))
	if err != nil {
		return err
	}

	objectName, err := windows.NewNTUnicodeString(stageName)
	if err != nil {
		return err
	}
	objectAttributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(parent.Fd()),
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var (
		stageHandle windows.Handle
		status      windows.IO_STATUS_BLOCK
	)
	if err := windows.NtCreateFile(
		&stageHandle,
		windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		&objectAttributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT,
		0,
		0,
	); err != nil {
		return err
	}

	renameErr := windows.SetFileInformationByHandle(
		stageHandle,
		windows.FileRenameInfo,
		unsafe.SliceData(renameBuffer),
		uint32(len(renameBuffer)),
	)
	closeErr := windows.CloseHandle(stageHandle)
	return errors.Join(renameErr, closeErr)
}

func newWindowsRenameBuffer(targetName string, parent windows.Handle) ([]byte, error) {
	name, err := windows.UTF16FromString(targetName)
	if err != nil {
		return nil, err
	}
	name = name[:len(name)-1]
	nameBytes := uint64(len(name)) * 2
	headerBytes := uint64(unsafe.Offsetof(fileRenameInformation{}.fileName))
	bufferBytes := headerBytes + nameBytes
	if nameBytes > math.MaxUint32 || bufferBytes > math.MaxUint32 || bufferBytes > uint64(math.MaxInt) {
		return nil, syscall.EINVAL
	}

	buffer := make([]byte, int(bufferBytes))
	information := (*fileRenameInformation)(unsafe.Pointer(unsafe.SliceData(buffer)))
	information.rootDirectory = parent
	information.fileNameLength = uint32(nameBytes)
	copy(unsafe.Slice(&information.fileName[0], len(name)), name)
	return buffer, nil
}
