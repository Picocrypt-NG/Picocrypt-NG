//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package fileops

import (
	"errors"
	"os"
)

func publishUnpackFile(*os.File, *os.File, string, string, os.FileInfo) (bool, bool, error) {
	return false, false, errors.ErrUnsupported
}
