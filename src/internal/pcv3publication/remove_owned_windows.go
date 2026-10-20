//go:build windows

package pcv3publication

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func safePublishedRemoval(parent, original *os.File) bool { return original != nil }

// The original handle denies FILE_SHARE_DELETE throughout custody, preventing
// namespace relocation. Classic FileDispositionInformation works on Windows 7;
// deletion takes effect only after all owned duplicates are closed.
func removeOwnedFile(_ *os.Root, _ string, original *os.File, _ func(*os.Root, string) error) error {
	if original == nil {
		return os.ErrInvalid
	}
	var status windows.IO_STATUS_BLOCK
	disposition := byte(1)
	return windows.NtSetInformationFile(windows.Handle(original.Fd()), &status, &disposition, uint32(unsafe.Sizeof(disposition)), windows.FileDispositionInformation)
}

func removePrivateDirectoryHandle(file *os.File) error { return removeOwnedFile(nil, "", file, nil) }

func safeCapabilityParent(parent *os.File) bool { return parent != nil }
