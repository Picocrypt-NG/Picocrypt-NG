//go:build android || linux

package mobile

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetInputNonblockingBorrowsPipeWithoutConsumingOrClosingIt(t *testing.T) {
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pipe[0]); _ = unix.Close(pipe[1]) })
	if err := SetInputNonblocking(int64(pipe[0])); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(uintptr(pipe[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatal("borrowed pipe remains blocking")
	}
	fdFlags, err := unix.FcntlInt(uintptr(pipe[0]), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("borrowed pipe lost close-on-exec: flags=%#x err=%v", fdFlags, err)
	}
	var empty [1]byte
	if _, err := unix.Read(pipe[0], empty[:]); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("empty pipe must return without waiting for EOF: %v", err)
	}
	payload := []byte("caller still owns these bytes")
	if n, err := unix.Write(pipe[1], payload); err != nil || n != len(payload) {
		t.Fatalf("caller write: n=%d err=%v", n, err)
	}
	if err := SetInputNonblocking(int64(pipe[0])); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if n, err := unix.Read(pipe[0], got); err != nil || n != len(payload) || !bytes.Equal(got, payload) {
		t.Fatalf("caller read after repeated borrowed setup: n=%d got=%q err=%v", n, got, err)
	}
}

func TestSetInputNonblockingPreservesAppendModeAndCallerFileOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "caller-owned")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.WriteString("first"); err != nil {
		t.Fatal(err)
	}
	before, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetInputNonblocking(int64(file.Fd())); err != nil {
		t.Fatal(err)
	}
	after, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || after != before|unix.O_NONBLOCK {
		t.Fatalf("borrowed setup changed other file status flags: before=%#x after=%#x err=%v", before, after, err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("second"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "firstsecond" {
		t.Fatalf("borrowed setup lost append behavior or caller ownership: got=%q err=%v", got, err)
	}
}

func TestSetInputNonblockingRefusesInvalidDescriptorsWithoutChangingLivePipe(t *testing.T) {
	var pipe [2]int
	if err := unix.Pipe(pipe[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pipe[0]); _ = unix.Close(pipe[1]) })
	for _, fd := range []int64{-1, math.MaxInt32 + 1, math.MaxInt64, int64(pipe[0]) + 1<<32} {
		if err := SetInputNonblocking(fd); err == nil {
			t.Errorf("invalid descriptor %d accepted", fd)
		}
		flags, err := unix.FcntlInt(uintptr(pipe[0]), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NONBLOCK != 0 {
			t.Fatalf("invalid descriptor %d changed unrelated live pipe: flags=%#x err=%v", fd, flags, err)
		}
	}
}

func TestSetInputNonblockingRefusesClosedDescriptor(t *testing.T) {
	var pipe [2]int
	if err := unix.Pipe(pipe[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pipe[1]) })
	if err := unix.Close(pipe[0]); err != nil {
		t.Fatal(err)
	}
	if err := SetInputNonblocking(int64(pipe[0])); !errors.Is(err, unix.EBADF) {
		t.Fatalf("closed descriptor must fail: %v", err)
	}
}

func TestPreparePCV3ArchiveSAFNonblockingRefusesTruncatedDescriptor(t *testing.T) {
	var pipe [2]int
	if err := unix.Pipe(pipe[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pipe[0]); _ = unix.Close(pipe[1]) })
	before, err := unix.FcntlInt(uintptr(pipe[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A native int descriptor must never be obtained by truncating a Java long.
	if preparePCV3ArchiveSAFNonblocking(int64(pipe[0]) + 1<<32) {
		t.Error("out-of-range descriptor accepted")
	}
	after, err := unix.FcntlInt(uintptr(pipe[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("out-of-range descriptor changed unrelated pipe flags: %#x -> %#x", before, after)
	}
}
