package cli

import (
	"Picocrypt-NG/internal/diskspace"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/secret"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
)

var activeEncryptedStdin atomic.Pointer[fileops.EncryptedSpool]

// The copy context controls accumulation only. The sealed owner retains the
// caller's operation context, so retiring this registration cannot revoke it.
type encryptedStdinCopy struct {
	cancel context.CancelFunc
	input  io.Closer
}

var activeEncryptedStdinCopy atomic.Pointer[encryptedStdinCopy]

func cancelActiveEncryptedStdinCopy() bool {
	buffering := activeEncryptedStdinCopy.Swap(nil)
	if buffering == nil {
		return false
	}
	buffering.cancel()
	if buffering.input != nil {
		// A reader's Close can wait on external I/O. Keep the signal controller
		// available for a forced second interrupt while the command unwinds.
		go func() { _ = buffering.input.Close() }()
	}
	return true
}

func cleanupActiveEncryptedStdin() error {
	return activeEncryptedStdin.Swap(nil).Close()
}

func closeEncryptedStdin(spool *fileops.EncryptedSpool) error {
	if spool == nil {
		return nil
	}
	activeEncryptedStdin.CompareAndSwap(spool, nil)
	return spool.Close()
}

func bufferEncryptionStdin(ctx context.Context, outputPath string) (*fileops.EncryptedSpool, error) {
	return bufferEncryptedInput(ctx, os.Stdin, outputPath)
}

// The unknown-length ciphertext allowance uses the existing 1.5x plus 10 MiB
// temporary-space policy, applied to physical bytes including every STREAM tag.
// It is an observation, not a reservation: write and Sync failures remain fatal.
func encryptedStdinPhysicalBudget(available int64) (uint64, error) {
	if available <= minBuffer {
		return 0, errors.New("insufficient space for encrypted stdin staging")
	}
	return uint64(available-minBuffer) * 2 / 3, nil //nolint:gosec // Positive signed extent; doubling fits uint64.
}

func bufferEncryptedInput(ctx context.Context, input io.Reader, outputPath string) (spool *fileops.EncryptedSpool, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := ChooseTempDir(0, outputPath)
	if err != nil {
		return nil, fmt.Errorf("selecting stdin temporary directory: %w", err)
	}
	available, err := diskspace.Available(dir)
	if err != nil {
		return nil, err
	}
	budget, err := encryptedStdinPhysicalBudget(available)
	if err != nil {
		return nil, err
	}
	spool, err = fileops.CreateEncryptedSpool(ctx, fileops.EncryptedSpoolOptions{NearPath: filepath.Join(dir, "stdin"), MaxPhysicalBytes: budget})
	if err != nil {
		return nil, err
	}
	if !activeEncryptedStdin.CompareAndSwap(nil, spool) {
		return nil, errors.Join(errors.New("another encrypted stdin stream is already active"), spool.Close())
	}
	transferred := false
	defer func() {
		if transferred {
			return
		}
		panicValue := recover()
		cleanupErr := closeEncryptedStdin(spool)
		spool = nil
		if panicValue != nil {
			fileops.RepanicWithCleanup(panicValue, cleanupErr)
		}
		retErr = errors.Join(retErr, cleanupErr)
	}()
	copyCtx, cancelCopy := context.WithCancel(ctx)
	defer cancelCopy()
	buffering := &encryptedStdinCopy{cancel: cancelCopy}
	buffering.input, _ = input.(io.Closer)
	if !activeEncryptedStdinCopy.CompareAndSwap(nil, buffering) {
		return spool, errors.New("another encrypted stdin copy is already active")
	}
	defer activeEncryptedStdinCopy.CompareAndSwap(buffering, nil)

	scratch := make([]byte, 32<<10)
	defer secret.SecureZero(scratch)
	if _, err = io.CopyBuffer(spool, stdinContextReader{ctx: copyCtx, Reader: input}, scratch); err != nil {
		return spool, fmt.Errorf("buffering encrypted stdin: %w", errors.Join(copyCtx.Err(), err))
	}
	if err = copyCtx.Err(); err != nil {
		return spool, err
	}
	if err = spool.Seal(); err != nil {
		return spool, fmt.Errorf("sealing encrypted stdin: %w", errors.Join(copyCtx.Err(), err))
	}
	// Retiring and cancelling compete for one registration. If the signal won,
	// reject even before its cancel function has had a chance to run.
	if !activeEncryptedStdinCopy.CompareAndSwap(buffering, nil) {
		return spool, context.Canceled
	}
	if err = copyCtx.Err(); err != nil {
		return spool, err
	}
	transferred = true
	return spool, nil
}

type stdinContextReader struct {
	ctx context.Context
	io.Reader
}

func (reader stdinContextReader) Read(p []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.Reader.Read(p)
}
