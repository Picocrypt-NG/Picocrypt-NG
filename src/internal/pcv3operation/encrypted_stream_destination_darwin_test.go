package pcv3operation

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Cancel immediately after Write checks the old context state. This widens the
// real check-before-syscall race without replacing the pipe or syscall itself.
type cancelBeforePipeWriteContext struct {
	context.Context
	once   sync.Once
	cancel func()
}

func (ctx *cancelBeforePipeWriteContext) Err() error {
	err := ctx.Context.Err()
	if ctx.cancel != nil {
		ctx.once.Do(ctx.cancel)
	}
	return err
}

func darwinBlockingStreamFixture(t *testing.T, ctx context.Context) (*darwinEncryptedStreamTransport, *os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	// Match an inherited blocking descriptor rather than os.Pipe's pollable
	// wrapper. The public subprocess regression separately exercises inheritance.
	_ = writer.Fd()
	info, err := writer.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stream, err := encryptedStreamDestination(ctx, writer, info)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := stream.(*darwinEncryptedStreamTransport)
	if !ok {
		t.Fatal("blocking pipe did not get an independently owned transport")
	}
	return transport, reader, writer
}

func TestDarwinEncryptedStreamCancellationReservesDescriptorUntilWriterJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gap := &cancelBeforePipeWriteContext{Context: ctx}
	transport, reader, _ := darwinBlockingStreamFixture(t, gap)
	defer func() {
		if err := transport.close(); err != nil {
			t.Error(err)
		}
	}()
	for _, fd := range []int{transport.fd, transport.null} {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("owned descriptor can escape exec: flags=%#x err=%v", flags, err)
		}
	}
	var sentinels []*os.File
	defer func() {
		for _, file := range sentinels {
			_ = file.Close()
		}
	}()
	gap.cancel = func() {
		cancel()
		if err := transport.interrupt(); err != nil {
			t.Fatal(err)
		}
		flags, err := unix.FcntlInt(uintptr(transport.fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("cancellation freed its slot or lost close-on-exec: flags=%#x err=%v", flags, err)
		}
		// If cancellation closed the numeric slot, one of these real files
		// could inherit it before Write enters the kernel and receive plaintext.
		for range 8 {
			file, err := os.CreateTemp(t.TempDir(), "unrelated-destination")
			if err != nil {
				t.Fatal(err)
			}
			sentinels = append(sentinels, file)
		}
	}
	if _, err := transport.Write([]byte("plaintext must not reach a recycled descriptor")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost its terminal cause:", err)
	}
	for _, file := range sentinels {
		info, err := file.Stat()
		if err != nil || info.Size() != 0 {
			t.Fatal("canceled write reached an unrelated file")
		}
	}
	if got, err := io.ReadAll(reader); err != nil || len(got) != 0 {
		t.Fatalf("pre-syscall cancellation released plaintext: bytes=%d err=%v", len(got), err)
	}
}

func TestDarwinEncryptedStreamPreservesExistingPipeDeadline(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := writer.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	info, err := writer.Stat()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := encryptedStreamDestination(context.Background(), writer, info)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transport.close() }()
	if n, err := transport.Write([]byte("deadline-protected plaintext")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("transport reset a caller deadline: bytes=%d err=%v", n, err)
	}
}

func TestDarwinEncryptedStreamClosedReaderReleasesOwnedDescriptors(t *testing.T) {
	transport, reader, writer := darwinBlockingStreamFixture(t, context.Background())
	defer func() { _ = transport.close() }()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := transport.Write([]byte("closed reader")); n != 0 || !errors.Is(err, unix.EPIPE) {
		t.Fatalf("closed reader did not fail promptly: bytes=%d err=%v", n, err)
	}
	if err := transport.close(); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{transport.fd, transport.null} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatal("finished transport retained an owned descriptor:", err)
		}
	}
	if _, err := writer.Stat(); err != nil {
		t.Fatal("failed transport closed the caller's destination:", err)
	}
}
