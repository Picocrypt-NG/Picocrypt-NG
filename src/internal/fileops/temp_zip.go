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

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrTempZipCleanupIncomplete marks an owned stage cleanup failure.
var ErrTempZipCleanupIncomplete = errors.New("fileops: temporary ZIP cleanup incomplete")

// TempZipOptions admits a private sequential archive. MaxPhysicalBytes is a
// trusted disk extent allowance, including tags, and must be nonzero.
type TempZipOptions struct {
	Files            []string
	RootDir          string
	EntryNames       map[string]string
	NearPath         string
	Compress         bool
	MaxPhysicalBytes uint64
	Progress         ProgressFunc
	Status           StatusFunc
	Cancel           CancelFunc
	Budget           *ZIPResourceBudget
}

// TempZip owns its stage and one fresh AEAD key for one write/read session.
// Controllable buffers are wiped. Go and the AEAD/compressor implementation
// retain private state with no supported zeroing API; no complete-erasure claim
// is made. Call Close on every exit. Borrowed handles do not outlive this owner.
type TempZip struct {
	self           *TempZip // copied handles do not acquire read or cleanup authority
	stage          *StagedFile
	a              cipher.AEAD
	reader         *tempStreamReader
	length, extent uint64
	info           os.FileInfo
	cancel         CancelFunc
	opened, closed bool
	closeErr       error
}

func CreateTempZip(ctx context.Context, opts TempZipOptions) (*TempZip, error) {
	return createTempZip(ctx, opts, (*os.File).Sync)
}

// The narrow synchronization seam keeps lifecycle fault tests on real stages.
func createTempZip(ctx context.Context, opts TempZipOptions, syncFile func(*os.File) error) (result *TempZip, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.MaxPhysicalBytes < tempStreamTag {
		return nil, errTempStreamBudget
	}
	cancel := func() bool { return ctx.Err() != nil || (opts.Cancel != nil && opts.Cancel()) }
	if cancel() {
		return nil, errZIPCancelled
	}
	zipOpts := ZipOptions{Files: opts.Files, RootDir: opts.RootDir, EntryNames: opts.EntryNames, Compress: opts.Compress, Progress: opts.Progress, Status: opts.Status, Cancel: cancel, Budget: opts.Budget}
	budget := opts.Budget
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	charge, e := zipWriterWorkingBytes(zipOpts)
	if e != nil {
		return nil, e
	}
	if e = budget.Reserve(charge); e != nil {
		return nil, e
	}
	defer budget.Release(charge)
	owner := &TempZip{cancel: cancel}
	owner.self = owner
	transferred := false
	defer func() {
		if transferred {
			return
		}
		panicValue := recover()
		cleanupErr := owner.Close()
		if panicValue != nil {
			RepanicWithCleanup(panicValue, cleanupErr)
		}
		if cleanupErr != nil {
			retErr = errors.Join(retErr, ErrTempZipCleanupIncomplete, cleanupErr)
		}
	}()

	owner.stage, e = CreateSiblingTemp(opts.NearPath)
	if e != nil {
		return nil, e
	}
	var key [32]byte
	defer secret.SecureZero(key[:])
	if _, e = rand.Read(key[:]); e != nil {
		return nil, e
	}
	owner.a, e = chacha20poly1305.New(key[:])
	secret.SecureZero(key[:])
	if e != nil {
		return nil, e
	}
	writer := newTempStreamWriter(owner.stage.File(), owner.a, opts.MaxPhysicalBytes, cancel)
	defer writer.close()
	if e = emitZIP(writer, zipOpts); e != nil {
		return nil, e
	}
	if cancel() {
		return nil, errZIPCancelled
	}
	if e = writer.finish(); e != nil {
		return nil, e
	}
	owner.length = writer.length
	owner.extent, e = tempStreamExtent(owner.length)
	if e != nil {
		return nil, e
	}
	owner.info, e = owner.stage.File().Stat()
	if e != nil {
		return nil, e
	}
	if owner.info.Size() < 0 || uint64(owner.info.Size()) != owner.extent {
		return nil, errTempStream
	}
	if cancel() {
		return nil, errZIPCancelled
	}
	if e = syncFile(owner.stage.File()); e != nil {
		return nil, e
	}
	if cancel() {
		return nil, errZIPCancelled
	}
	transferred = true
	return owner, nil
}

func (t *TempZip) OpenReader() (io.Reader, error) {
	if t == nil || t.self != t || t.closed || t.opened {
		return nil, errTempStreamClosed
	}
	t.opened = true
	if e := t.checkExtent(); e != nil {
		return nil, e
	}
	t.reader = newTempStreamReader(t.stage.File(), t.a, t.length, t.cancel)
	t.reader.checkExtent = t.checkExtent
	return t.reader, nil
}

func (t *TempZip) checkExtent() error {
	info, e := t.stage.File().Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || !os.SameFile(t.info, info) || info.Size() < 0 || uint64(info.Size()) != t.extent {
		return fmt.Errorf("%w: extent changed", errTempStream)
	}
	return nil
}

func (t *TempZip) Length() uint64 {
	if t == nil || t.self != t || t.closed {
		return 0
	}
	return t.length
}

func (t *TempZip) File() *os.File {
	if t == nil || t.self != t || t.closed {
		return nil
	}
	return t.stage.File()
}

func (t *TempZip) Path() string {
	if t == nil || t.self != t || t.closed {
		return ""
	}
	return t.stage.Path()
}

func (t *TempZip) Close() error {
	if t == nil {
		return nil
	}
	if t.self != t {
		return errTempStreamClosed
	}
	if t.closed {
		return t.closeErr
	}
	t.closed = true
	if t.reader != nil {
		t.reader.close()
	}
	t.reader = nil
	t.a = nil
	t.cancel = nil
	t.info = nil
	if t.stage != nil {
		t.closeErr = t.stage.Cleanup()
		t.stage = nil
	}
	return t.closeErr
}
