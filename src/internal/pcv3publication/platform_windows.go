//go:build windows

package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"errors"
	"os"
)

func nativeOperations() platformOperations {
	return platformOperations{
		atomicPublish: windowsNoReplace,
		syncDirectory: fileops.SyncDirectory,
	}
}

func windowsNoReplace(
	_, parent, original *os.File,
	_ string,
	targetName string,
	policy Policy,
) error {
	if policy != PolicyNoReplace {
		return errors.ErrUnsupported
	}
	return fileops.RenameFileNoReplaceWindows(original, parent, targetName)
}
