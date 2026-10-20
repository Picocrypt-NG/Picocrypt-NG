package fileops

import (
	"context"
	"errors"
	"io"
	"os"
)

// ErrTempZipCleanupIncomplete marks an owned stage cleanup failure.
var ErrTempZipCleanupIncomplete = errors.New("fileops: temporary ZIP cleanup incomplete")

// TempZipOptions admits a private sequential archive. MaxPhysicalBytes is a
// trusted disk extent allowance, including tags, and must be nonzero.
type TempZipOptions struct {
	Files           []string
	InputIdentities []ZIPInputIdentity
	// SingleSource replaces the byte source for exactly one identity-pinned entry.
	SingleSource     *ZIPSequentialSource
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

// TempZip owns its stage and one fresh AEAD key for one finalized archive.
// Controllable buffers are wiped. Go and the AEAD/compressor implementation
// retain private state with no supported zeroing API; no complete-erasure claim
// is made. Call Close on every exit. Borrowed handles do not outlive this owner.
type TempZip struct {
	self  *TempZip
	spool *EncryptedSpool
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
	zipOpts := ZipOptions{Files: opts.Files, InputIdentities: opts.InputIdentities, RootDir: opts.RootDir, EntryNames: opts.EntryNames, Compress: opts.Compress, Progress: opts.Progress, Status: opts.Status, Cancel: cancel, Budget: opts.Budget, singleSource: opts.SingleSource}
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
	zipOpts.InputIdentities, e = CaptureZIPInputs(opts.Files, opts.InputIdentities)
	if e != nil {
		return nil, e
	}
	owner := &TempZip{}
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
	owner.spool, e = createEncryptedSpool(ctx, EncryptedSpoolOptions{NearPath: opts.NearPath, MaxPhysicalBytes: opts.MaxPhysicalBytes, Cancel: cancel}, syncFile)
	if e != nil {
		if errors.Is(e, ErrEncryptedSpoolCleanupIncomplete) {
			e = errors.Join(e, ErrTempZipCleanupIncomplete)
		}
		return nil, e
	}
	if e = emitZIP(owner.spool, zipOpts); e != nil {
		return nil, e
	}
	if e = owner.spool.Seal(); e != nil {
		return nil, e
	}
	transferred = true
	return owner, nil
}

func (t *TempZip) OpenReader() (io.Reader, error) {
	if t == nil || t.self != t {
		return nil, errTempStreamClosed
	}
	return t.spool.OpenReader()
}

func (t *TempZip) Length() uint64 {
	if t == nil || t.self != t {
		return 0
	}
	return t.spool.Length()
}

func (t *TempZip) File() *os.File {
	if t == nil || t.self != t {
		return nil
	}
	return t.spool.File()
}

func (t *TempZip) Path() string {
	if t == nil || t.self != t {
		return ""
	}
	return t.spool.Path()
}

func (t *TempZip) Close() error {
	if t == nil {
		return nil
	}
	if t.self != t {
		return errTempStreamClosed
	}
	return t.spool.Close()
}
