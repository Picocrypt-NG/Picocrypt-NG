package pcv3operation

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// encryptedStreamDestination gives inherited Linux pipes an independent open
// file description. Changing O_NONBLOCK on a dup would also change the caller's
// pipe flags. A blocking inherited os.File cannot cancel an in-flight write.
func encryptedStreamDestination(_ context.Context, destination *os.File, expected os.FileInfo) (encryptedStreamTransport, error) {
	if expected.Mode()&os.ModeNamedPipe == 0 {
		return newFileEncryptedStreamTransport(destination, destination), nil
	}
	raw, err := destination.SyscallConn()
	if err != nil {
		return nil, err
	}
	var transport *os.File
	var openErr error
	err = raw.Control(func(fd uintptr) {
		flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if err != nil {
			openErr = err
			return
		}
		if flags&unix.O_ACCMODE == unix.O_RDONLY {
			openErr = errors.New("encrypted stream destination is read-only")
			return
		}
		if flags&unix.O_NONBLOCK != 0 {
			transport = destination
			return
		}
		// Control pins fd until open returns; the procfs magic link opens that
		// pipe itself, independently of names or shared file status flags.
		transport, openErr = os.OpenFile("/proc/self/fd/"+strconv.FormatUint(uint64(fd), 10), os.O_WRONLY|unix.O_NONBLOCK, 0)
	})
	if err != nil || openErr != nil {
		return nil, errors.Join(err, openErr)
	}
	if transport == destination {
		return newFileEncryptedStreamTransport(transport, destination), nil
	}
	info, err := transport.Stat()
	if err != nil || !os.SameFile(expected, info) || info.Mode()&os.ModeNamedPipe == 0 {
		_ = transport.Close()
		return nil, errors.New("encrypted stream destination changed")
	}
	if err := transport.SetWriteDeadline(time.Time{}); err != nil {
		_ = transport.Close()
		return nil, err
	}
	return newFileEncryptedStreamTransport(transport, destination), nil
}
