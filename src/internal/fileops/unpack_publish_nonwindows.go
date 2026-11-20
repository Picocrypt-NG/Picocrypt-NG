//go:build !windows

package fileops

import (
	"errors"
	"os"
)

func createUnpackCopyTarget(root *os.Root, _ *os.File, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
}

func removeUnpackCopyTarget(*os.File) error { return errors.ErrUnsupported }
