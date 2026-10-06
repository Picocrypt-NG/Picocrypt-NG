//go:build darwin

package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func nativeOperations() platformOperations {
	return platformOperations{
		atomicPublish: func(parent *os.File, stageName, targetName string, policy Policy) error {
			if policy != PolicyNoReplace {
				return errors.ErrUnsupported
			}
			parentFD := int(parent.Fd())
			return unix.RenameatxNp(
				parentFD,
				stageName,
				parentFD,
				targetName,
				unix.RENAME_EXCL,
			)
		},
		syncDirectory: fileops.SyncDirectory,
	}
}
