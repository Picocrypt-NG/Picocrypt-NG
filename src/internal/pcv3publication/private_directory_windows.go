//go:build windows

package pcv3publication

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ownerSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")")
}

// A protected owner-only DACL is established in NtCreateFile itself. Never
// adopt an existing directory or depend on a post-creation permission repair.
func createPrivateDirectory(root *os.Root, parent *os.File, name string) (*os.Root, *os.File, os.FileInfo, error) {
	file, err := createWindowsPrivateObject(parent, name, true)
	if err != nil {
		return nil, nil, nil, err
	}
	info, err := file.Stat()
	var sourceFS, destinationFS windows.ByHandleFileInformation
	filesystemErr := errors.Join(windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &sourceFS), windows.GetFileInformationByHandle(windows.Handle(parent.Fd()), &destinationFS))
	if err != nil || filesystemErr != nil || sourceFS.VolumeSerialNumber != destinationFS.VolumeSerialNumber || sourceFS.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info == nil || !info.IsDir() || !privateWindowsHandle(file) {
		_ = file.Close()
		return nil, nil, nil, errors.New("private directory security unavailable")
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		_ = file.Close()
		return nil, nil, nil, err
	}
	pinned, err := child.Stat(".")
	if err != nil || !os.SameFile(info, pinned) {
		_ = child.Close()
		_ = file.Close()
		return nil, nil, nil, errors.New("private directory identity changed")
	}
	return child, file, info, nil
}

func createPrivateStage(_ *os.Root, parent *os.File, name string) (*os.File, error) {
	return createWindowsPrivateObject(parent, name, false)
}

func createWindowsPrivateObject(parent *os.File, name string, directory bool) (*os.File, error) {
	sd, err := ownerSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(parent.Fd()), ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd}
	options := uint32(windows.FILE_NON_DIRECTORY_FILE | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
	if directory {
		options = windows.FILE_DIRECTORY_FILE | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT
		share |= windows.FILE_SHARE_DELETE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.SYNCHRONIZE, &attrs, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, share, windows.FILE_CREATE, options, 0, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), filepath.Join(parent.Name(), name)), nil
}

func privateDirectoryInfo(os.FileInfo) bool     { return false } // Windows journal recovery remains unsupported.
func trustedCleanupParent(parent *os.File) bool { return privateWindowsHandle(parent) }

func privateWindowsHandle(file *os.File) bool {
	if file == nil {
		return false
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !windows.EqualSid(owner, user.User.Sid) {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 0, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
		return false
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: GetAce returned a validated ACCESS_ALLOWED_ACE; SidStart is its native trailing SID.
	return windows.EqualSid(sid, owner) && uint32(ace.Mask)&(windows.STANDARD_RIGHTS_REQUIRED|windows.SYNCHRONIZE|0x1ff) == (windows.STANDARD_RIGHTS_REQUIRED|windows.SYNCHRONIZE|0x1ff)
}

func trustedLegacyJournalParent(*os.File) bool { return false }

func privateDirectoryBackendAvailable() bool { return true }

func privateDirectoryParentTrusted(*os.File) bool { return true }
