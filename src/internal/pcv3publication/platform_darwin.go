//go:build darwin

package pcv3publication

import (
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
		syncDirectory: func(parent *os.File) error {
			return unix.Fsync(int(parent.Fd()))
		},
	}
}
