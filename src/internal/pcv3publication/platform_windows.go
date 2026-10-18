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
	source, parent, original *os.File,
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

	if original == nil {
		return os.ErrInvalid
	}
	var status windows.IO_STATUS_BLOCK

	// Use the NT rename class for a target relative to the pinned directory
	// handle. ReplaceIfExists remains false; no pathname fallback is permitted.
	renameErr := windows.NtSetInformationFile(
		windows.Handle(original.Fd()),
		&status,
		unsafe.SliceData(renameBuffer), //nolint:gosec // G103: native FileRenameInformation buffer is sized and populated by newWindowsRenameBuffer.
		uint32(len(renameBuffer)),      //nolint:gosec // G115: newWindowsRenameBuffer rejects buffer sizes above MaxUint32.
		windows.FileRenameInformation,
	)
	var statusError windows.NTStatus
	if errors.As(renameErr, &statusError) {
		renameErr = statusError.Errno()
	}
	return renameErr
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
