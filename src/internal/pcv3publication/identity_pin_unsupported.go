//go:build !linux && !android && !darwin && !windows

package pcv3publication

import (
	"errors"
	"os"
)

func duplicateIdentityFile(*os.File) (*os.File, error) {
	return nil, errors.ErrUnsupported
}
