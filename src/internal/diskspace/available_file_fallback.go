//go:build !darwin && !linux

package diskspace

import (
	"errors"
	"os"
)

// AvailableFile is a checked path observation on platforms without the held
// descriptor probe. Both observations must still refer to the held stage.
func AvailableFile(file *os.File) (int64, error) {
	if file == nil {
		return 0, errors.New("disk space: missing file")
	}
	held, err := file.Stat()
	if err != nil {
		return 0, err
	}
	before, err := os.Stat(file.Name())
	if err != nil {
		return 0, err
	}
	if !os.SameFile(held, before) {
		return 0, errors.New("disk space: stage identity changed")
	}
	available, err := Available(file.Name())
	if err != nil {
		return 0, err
	}
	after, err := os.Stat(file.Name())
	if err != nil {
		return 0, err
	}
	if !os.SameFile(held, after) {
		return 0, errors.New("disk space: stage identity changed")
	}
	return available, nil
}
