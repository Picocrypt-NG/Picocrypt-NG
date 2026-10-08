//go:build windows

package pcv3publication

import (
	"os"

	"golang.org/x/sys/windows"
)

func duplicateIdentityFile(file *os.File) (*os.File, error) {
	process := windows.CurrentProcess()
	var handle windows.Handle
	err := windows.DuplicateHandle(process, windows.Handle(file.Fd()), process, &handle, 0, false, windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), file.Name()), nil
}
