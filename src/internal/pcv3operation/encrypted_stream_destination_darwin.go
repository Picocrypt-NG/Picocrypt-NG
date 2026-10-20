package pcv3operation

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

func encryptedStreamDestination(ctx context.Context, destination *os.File, expected os.FileInfo) (encryptedStreamTransport, error) {
	if expected.Mode()&os.ModeNamedPipe == 0 {
		return newFileEncryptedStreamTransport(destination, destination), nil
	}
	raw, err := destination.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var flags int
	var duplicateErr error
	err = raw.Control(func(original uintptr) {
		flags, duplicateErr = unix.FcntlInt(original, unix.F_GETFL, 0)
		if duplicateErr != nil {
			return
		}
		if flags&unix.O_ACCMODE == unix.O_RDONLY {
			duplicateErr = errors.New("encrypted stream destination is read-only")
			return
		}
		if flags&unix.O_NONBLOCK == 0 {
			fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 3)
		}
	})
	if err != nil || duplicateErr != nil {
		return nil, errors.Join(err, duplicateErr)
	}
	if flags&unix.O_NONBLOCK != 0 {
		return newFileEncryptedStreamTransport(destination, destination), nil
	}
	null, err := unix.Open(os.DevNull, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &darwinEncryptedStreamTransport{ctx: ctx, destination: destination, fd: fd, null: null}, nil
}

// Darwin's kernel close drains a pipe's individual fileproc and wakes its
// blocked write. Go File.Close waits for that write before reaching the kernel.
// Use an owned raw duplicate without changing the caller's shared O_NONBLOCK.
// dup2 replaces its slot with /dev/null, keeping a writer paused before its
// syscall from using a recycled descriptor. Keep that slot until copy and
// interrupt have joined. See XNU kern_descrip.c:fileproc_drain and
// sys_pipe.c:pipe_drain (xnu-11215.81.4).
type darwinEncryptedStreamTransport struct {
	ctx           context.Context
	destination   *os.File
	fd, null      int
	interruptOnce sync.Once
	interruptErr  error
	closeOnce     sync.Once
	closeErr      error
}

func (transport *darwinEncryptedStreamTransport) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		if err := transport.ctx.Err(); err != nil {
			return written, err
		}
		n, err := unix.Write(transport.fd, p[written:])
		if n > 0 {
			written += n
		}
		if canceled := transport.ctx.Err(); canceled != nil {
			return written, canceled
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, transport.ctx.Err()
}

func (transport *darwinEncryptedStreamTransport) interrupt() error {
	transport.interruptOnce.Do(func() {
		// dup2 clears close-on-exec. Hold Go's fork lock until it is restored;
		// neither the replacement slot nor the old pipe can escape an exec.
		syscall.ForkLock.RLock()
		transport.interruptErr = unix.Dup2(transport.null, transport.fd)
		if transport.interruptErr == nil {
			_, transport.interruptErr = unix.FcntlInt(uintptr(transport.fd), unix.F_SETFD, unix.FD_CLOEXEC)
		}
		syscall.ForkLock.RUnlock()
		transport.interruptErr = errors.Join(transport.interruptErr, transport.destination.Close())
	})
	return transport.interruptErr
}

func (transport *darwinEncryptedStreamTransport) close() error {
	transport.closeOnce.Do(func() {
		transport.closeErr = errors.Join(unix.Close(transport.fd), unix.Close(transport.null))
	})
	return transport.closeErr
}
