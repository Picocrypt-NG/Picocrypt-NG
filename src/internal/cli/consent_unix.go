//go:build !windows

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// readConsentLine owns an independent open file description. A dup would share
// O_NONBLOCK with the shell's stdin. Canonical editing and echo stay unchanged;
// only this descriptor is nonblocking and every wait checks cancellation.
func readConsentLine(ctx context.Context) (_ string, retErr error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	original, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	path := "/proc/self/fd/" + strconv.Itoa(int(os.Stdin.Fd()))
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOCTTY
	if runtime.GOOS != "linux" {
		// Darwin's /dev/fd duplicates an OFD. Resolve the device node instead and
		// verify its identity again after open, as ttyname-style lookup requires.
		path, err = consentTTYPath(original)
		if err != nil {
			return "", err
		}
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return "", err
	}
	owned := os.NewFile(uintptr(fd), "consent")
	if owned == nil {
		_ = unix.Close(fd)
		return "", errors.New("consent input is unavailable")
	}
	// Keep raw fd use inside this function; no asynchronous reader survives it.
	reopened, err := owned.Stat()
	if err != nil || !os.SameFile(original, reopened) {
		_ = owned.Close()
		return "", errors.New("consent input identity changed")
	}
	// os.File owns descriptor cleanup; use raw reads to avoid a hidden wait.
	defer func() { retErr = errors.Join(retErr, owned.Close()) }()
	line := make([]byte, 0, 32)
	var one [1]byte
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		events := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(events, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", err
		}
		if events[0].Revents == 0 {
			continue
		}
		n, err := unix.Read(fd, one[:])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", err
		}
		if n == 0 || one[0] == '\n' {
			return strings.TrimSuffix(string(line), "\r"), nil
		}
		if len(line) == 4096 {
			return "", errors.New("consent line is too long")
		}
		line = append(line, one[0])
	}
}

func consentTTYPath(identity os.FileInfo) (string, error) {
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && info.Mode()&os.ModeCharDevice != 0 && os.SameFile(identity, info) {
			return filepath.Join("/dev", entry.Name()), nil
		}
	}
	return "", errors.New("consent terminal device is unavailable")
}
