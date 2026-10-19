package fileops

import (
	"Picocrypt-NG/internal/secret"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrEncryptedSpoolCleanupIncomplete marks failed cleanup of an owned spool
// during construction; callers must preserve cleanup uncertainty in the result.
var ErrEncryptedSpoolCleanupIncomplete = errors.New("fileops: encrypted temporary stream cleanup incomplete")

// EncryptedSpoolOptions admits a private sequential stream. MaxPhysicalBytes
// includes authentication tags and must be at least one tag. NearPath chooses
// the directory; no plaintext or key is written to the stage.
type EncryptedSpoolOptions struct {
	NearPath         string
	MaxPhysicalBytes uint64
	Cancel           CancelFunc
}

// EncryptedSpool owns one fresh key and a pinned mode-0600 ciphertext stage.
// Write once, Seal, then open sequential readers, at most one at a time. Close
// revokes readers and wipes controllable scratch; Go and the AEAD implementation
// can retain private copies without a supported zeroing API. Handles are borrowed
// and must not outlive the owner. A copied value gains no authority.
type EncryptedSpool struct {
	self           *EncryptedSpool
	mu             sync.Mutex
	stage          *StagedFile
	a              cipher.AEAD
	writer         *tempStreamWriter
	reader         *spoolReadCloser
	length, extent uint64
	info           os.FileInfo
	cancel         CancelFunc
	syncFile       func(*os.File) error
	sealed, closed bool
	closeErr       error
}

// EncryptedSpoolPhysicalSize computes the exact disk allowance, including the
// final authentication tag, for admission before writing a known-length spool.
func EncryptedSpoolPhysicalSize(length uint64) (uint64, error) {
	return tempStreamExtent(length)
}

func CreateEncryptedSpool(ctx context.Context, opts EncryptedSpoolOptions) (*EncryptedSpool, error) {
	return createEncryptedSpool(ctx, opts, (*os.File).Sync)
}

func createEncryptedSpool(ctx context.Context, opts EncryptedSpoolOptions, syncFile func(*os.File) error) (owner *EncryptedSpool, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.NearPath == "" {
		return nil, os.ErrInvalid
	}
	if opts.MaxPhysicalBytes < tempStreamTag {
		return nil, errTempStreamBudget
	}
	cancel := func() bool { return ctx.Err() != nil || (opts.Cancel != nil && opts.Cancel()) }
	if cancel() {
		return nil, errZIPCancelled
	}
	owner = &EncryptedSpool{cancel: cancel, syncFile: syncFile}
	owner.self = owner
	transferred := false
	defer func() {
		if transferred {
			return
		}
		panicValue := recover()
		cleanupErr := owner.Close()
		owner = nil
		if panicValue != nil {
			RepanicWithCleanup(panicValue, cleanupErr)
		}
		if cleanupErr != nil {
			retErr = errors.Join(retErr, ErrEncryptedSpoolCleanupIncomplete, cleanupErr)
		}
	}()
	var err error
	owner.stage, err = CreateSiblingTemp(opts.NearPath)
	if err != nil {
		return owner, err
	}
	var key [32]byte
	defer secret.SecureZero(key[:])
	if _, err = rand.Read(key[:]); err != nil {
		return owner, err
	}
	owner.a, err = chacha20poly1305.New(key[:])
	secret.SecureZero(key[:])
	if err != nil {
		return owner, err
	}
	owner.writer = newTempStreamWriter(owner.stage.File(), owner.a, opts.MaxPhysicalBytes, cancel)
	if cancel() {
		return owner, errZIPCancelled
	}
	transferred = true
	return owner, nil
}

func (s *EncryptedSpool) Write(p []byte) (int, error) {
	if s == nil || s.self != s {
		return 0, errTempStreamClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.sealed || s.writer == nil {
		return 0, errTempStreamClosed
	}
	return s.writer.Write(p)
}

// Seal emits the authenticated final record and syncs the original descriptor.
// A failed Seal is terminal; the owner cannot restart its key/nonce session.
func (s *EncryptedSpool) Seal() error {
	if s == nil || s.self != s {
		return errTempStreamClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.sealed || s.writer == nil {
		return errTempStreamClosed
	}
	writer := s.writer
	defer func() { writer.close(); s.writer = nil }()
	if s.cancel() {
		return errZIPCancelled
	}
	if err := writer.finish(); err != nil {
		return err
	}
	s.length = writer.length
	var err error
	s.extent, err = tempStreamExtent(s.length)
	if err != nil {
		return err
	}
	s.info, err = s.stage.File().Stat()
	if err != nil {
		return err
	}
	if err = s.checkExtent(); err != nil {
		return err
	}
	if s.cancel() {
		return errZIPCancelled
	}
	if err = s.syncFile(s.stage.File()); err != nil {
		return err
	}
	if s.cancel() {
		return errZIPCancelled
	}
	s.sealed = true
	return nil
}

func (s *EncryptedSpool) checkExtent() error {
	info, err := s.stage.File().Stat()
	if err != nil {
		return err
	}
	if s.info == nil || !info.Mode().IsRegular() || !os.SameFile(s.info, info) || info.Size() < 0 || uint64(info.Size()) != s.extent {
		return fmt.Errorf("%w: extent changed", errTempStream)
	}
	return nil
}

func (s *EncryptedSpool) OpenReader() (io.ReadCloser, error) {
	if s == nil || s.self != s {
		return nil, errTempStreamClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.sealed || s.reader != nil {
		return nil, errTempStreamClosed
	}
	if s.cancel() {
		return nil, errZIPCancelled
	}
	if err := s.checkExtent(); err != nil {
		return nil, err
	}
	reader := newTempStreamReader(s.stage.File(), s.a, s.length, s.cancel)
	reader.checkExtent = s.checkExtent
	s.reader = &spoolReadCloser{tempStreamReader: reader, owner: s}
	return s.reader, nil
}

func (s *EncryptedSpool) Length() uint64 {
	if s == nil || s.self != s {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.sealed {
		return 0
	}
	return s.length
}

func (s *EncryptedSpool) File() *os.File {
	if s == nil || s.self != s {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.stage.File()
}

func (s *EncryptedSpool) Path() string {
	if s == nil || s.self != s {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	return s.stage.Path()
}

func (s *EncryptedSpool) Close() error {
	if s == nil {
		return nil
	}
	if s.self != s {
		return errTempStreamClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.writer != nil {
		s.writer.close()
		s.writer = nil
	}
	if s.reader != nil {
		s.reader.close()
		s.reader = nil
	}
	s.a = nil
	s.cancel = nil
	s.info = nil
	s.syncFile = nil
	if s.stage != nil {
		s.closeErr = s.stage.Cleanup()
		s.stage = nil
	}
	return s.closeErr
}

type spoolReadCloser struct {
	*tempStreamReader
	owner *EncryptedSpool
}

func (r *spoolReadCloser) Read(p []byte) (int, error) {
	s := r.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.reader != r {
		return 0, errTempStreamClosed
	}
	return r.tempStreamReader.Read(p)
}

func (r *spoolReadCloser) Close() error {
	s := r.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reader == r {
		r.close()
		s.reader = nil
	}
	return nil
}
