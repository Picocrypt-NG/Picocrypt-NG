//go:build darwin || linux

package diskspace

import (
	"errors"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

// AvailableFile observes free bytes on the held file's filesystem. It does not
// reserve capacity and remains valid even if the file's pathname is renamed.
func AvailableFile(file *os.File) (int64, error) {
	if file == nil {
		return 0, errors.New("disk space: missing file")
	}
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 || stat.Bavail > uint64(math.MaxInt64)/uint64(stat.Bsize) {
		return 0, errors.New("disk space: invalid filesystem statistics")
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil //nolint:gosec,unconvert // Positive size and MaxInt64 product checked above; platform types differ.
}
