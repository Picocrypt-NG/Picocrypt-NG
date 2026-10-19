package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/secret"
	"context"
	"errors"
	"io"
	"os"
	"sync"
)

// StreamState describes transport only; it grants no publication authority.
type StreamState uint8

const (
	StreamNone StreamState = iota
	StreamPending
	StreamComplete
	StreamFailed
)

// EncryptedOutput owns a sealed temporary stream. Copies share one consumable
// stdout action; no SaveTo, archive, or source-deletion authority is provided.
type EncryptedOutput struct{ state *encryptedOutputState }

type encryptedOutputState struct {
	mu    sync.Mutex
	spool *fileops.EncryptedSpool
	state StreamState
}

// OwnEncryptedOutput takes ownership even on failure. The owner must be sealed;
// the complete stream is authenticated again before the first output byte.
func OwnEncryptedOutput(spool *fileops.EncryptedSpool) (*EncryptedOutput, error) {
	if spool == nil {
		return nil, errors.New("encrypted output is unavailable")
	}
	reader, err := spool.OpenReader()
	if err == nil {
		err = reader.Close()
	}
	if err != nil {
		failure := errors.New("encrypted output is unavailable")
		if spool.Close() != nil {
			failure = errors.Join(failure, fileops.ErrEncryptedSpoolCleanupIncomplete)
		}
		return nil, failure
	}
	return &EncryptedOutput{state: &encryptedOutputState{spool: spool, state: StreamPending}}, nil
}

func (output *EncryptedOutput) State() StreamState {
	if output == nil || output.state == nil {
		return StreamNone
	}
	output.state.mu.Lock()
	defer output.state.mu.Unlock()
	return output.state.state
}

func (output *EncryptedOutput) live() bool {
	if output == nil || output.state == nil {
		return false
	}
	output.state.mu.Lock()
	defer output.state.mu.Unlock()
	return output.state.state == StreamPending && output.state.spool != nil
}

// StreamFollowUp grants only the live, one-shot stdout action. A presentation
// snapshot or a successful filesystem publication cannot mint this owner.
func (result *Result) StreamFollowUp() *EncryptedOutput {
	if result == nil || result.encryptedOutput == nil || !result.encryptedOutput.live() ||
		result.publicationAttempted || result.archiveFollowUp != nil ||
		!validSemanticPresentation(result.outcome, result.stage, result.code) {
		return nil
	}
	return result.encryptedOutput
}

func adoptEncryptedOutput(ctx context.Context, result *Result, spool *fileops.EncryptedSpool) {
	if spool == nil {
		return
	}
	if result == nil || result.publicationAttempted || result.archiveFollowUp != nil ||
		result.diagnostic != DiagnosticNone ||
		(result.outcome != OutcomeSuccess && result.outcome != OutcomeAuthenticatedDegraded &&
			result.outcome != OutcomeForcePartial && result.outcome != OutcomeForceUnverified) {
		if spool.Close() != nil && result != nil {
			result.appendWarning(WarningCleanupIncomplete)
		}
		return
	}
	output, err := OwnEncryptedOutput(spool)
	if err != nil {
		if errors.Is(err, fileops.ErrEncryptedSpoolCleanupIncomplete) {
			result.appendWarning(WarningCleanupIncomplete)
		}
		failEncryptedOutput(ctx, result)
		return
	}
	result.encryptedOutput = output
	if ctx != nil && ctx.Err() != nil {
		failEncryptedOutput(ctx, result)
	}
}

// failEncryptedOutput revokes shared stream custody before clearing output
// trust. Only the fixed cancellation cause and actual cleanup uncertainty survive.
func failEncryptedOutput(ctx context.Context, result *Result) {
	cleanupIncomplete := cleanupEncryptedOutput(result) || result.hasWarning(WarningCleanupIncomplete)
	stage, diagnostic := StageOutputWrite, DiagnosticCoreFailure
	if ctx != nil && ctx.Err() != nil {
		stage, diagnostic = StageCancellation, DiagnosticCancellation
	}
	*result = *closedFailure(OutcomeOperationFailed, stage, CodeOperationFailed, diagnostic)
	if diagnostic == DiagnosticCancellation {
		result.cancellationDeadline = errors.Is(ctx.Err(), context.DeadlineExceeded)
	}
	if cleanupIncomplete {
		result.appendWarning(WarningCleanupIncomplete)
	}
}

func cleanupEncryptedOutput(result *Result) bool {
	if result == nil || result.encryptedOutput == nil {
		return false
	}
	output := result.encryptedOutput
	result.encryptedOutput = nil
	return output.Discard().CleanupIncomplete()
}

func (output *EncryptedOutput) take() *fileops.EncryptedSpool {
	if output == nil || output.state == nil {
		return nil
	}
	output.state.mu.Lock()
	defer output.state.mu.Unlock()
	spool := output.state.spool
	output.state.spool = nil
	return spool
}

func (output *EncryptedOutput) Discard() OutputActionResult {
	spool := output.take()
	if spool == nil {
		return OutputActionResult{code: OutputActionExpired}
	}
	output.state.mu.Lock()
	output.state.state = StreamFailed
	output.state.mu.Unlock()
	if err := spool.Close(); err != nil {
		return OutputActionResult{code: OutputActionDiscardCleanupIncomplete, cleanupIncomplete: true}
	}
	return OutputActionResult{code: OutputActionDiscarded}
}

// StreamTo consumes the owner before effects. It validates the entire spool,
// then authenticates each record while copying. Cancellation closes destination
// to interrupt a blocked pipe; successful transport leaves destination open.
func (output *EncryptedOutput) StreamTo(ctx context.Context, destination *os.File) (result OutputActionResult) {
	spool := output.take()
	if spool == nil {
		return OutputActionResult{code: OutputActionExpired}
	}
	result.code = OutputActionSaveFailed
	defer func() {
		output.state.mu.Lock()
		defer output.state.mu.Unlock()
		output.state.state = StreamFailed
		if result.code == OutputActionSaved || result.code == OutputActionSavedCleanupIncomplete {
			output.state.state = StreamComplete
		}
	}()
	defer func() {
		if spool.Close() != nil {
			result.cleanupIncomplete = true
			if result.code == OutputActionSaved {
				result.code = OutputActionSavedCleanupIncomplete
			} else {
				result.code = OutputActionSaveFailedCleanupIncomplete
			}
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if destination == nil || ctx.Err() != nil {
		return result
	}
	source := spool.File()
	if source == nil {
		return result
	}
	sourceInfo, sourceErr := source.Stat()
	destinationInfo, destinationErr := destination.Stat()
	if sourceErr != nil || destinationErr != nil || os.SameFile(sourceInfo, destinationInfo) {
		return result
	}
	buffer := make([]byte, 64<<10)
	defer secret.SecureZero(buffer)
	if err := copyEncryptedSpool(ctx, spool, encryptedStreamWriter{Writer: io.Discard}, buffer); err != nil {
		return result
	}
	transport, err := encryptedStreamDestination(ctx, destination, destinationInfo)
	if err != nil {
		return result
	}
	defer func() {
		if transport.close() != nil {
			result.cleanupIncomplete = true
			if result.code == OutputActionSaved {
				result.code = OutputActionSavedCleanupIncomplete
			} else {
				result.code = OutputActionSaveFailedCleanupIncomplete
			}
		}
	}()
	done := make(chan struct{})
	stopped := make(chan struct{})
	var interruptErr error
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			interruptErr = transport.interrupt()
		case <-done:
		}
	}()
	func() {
		defer func() { close(done); <-stopped }()
		err = copyEncryptedSpool(ctx, spool, encryptedStreamWriter{Writer: transport}, buffer)
	}()
	if err != nil || interruptErr != nil || ctx.Err() != nil {
		return result
	}
	result.code = OutputActionSaved
	return result
}

// interrupt may run during Write; close releases owned descriptors only after
// both the copy and its cancellation watcher have joined.
type encryptedStreamTransport interface {
	io.Writer
	interrupt() error
	close() error
}

type fileEncryptedStreamTransport struct {
	file, destination *os.File
	closeOnce         sync.Once
	closeErr          error
}

func newFileEncryptedStreamTransport(file, destination *os.File) encryptedStreamTransport {
	return &fileEncryptedStreamTransport{file: file, destination: destination}
}

func (transport *fileEncryptedStreamTransport) Write(p []byte) (int, error) {
	return transport.file.Write(p)
}

func (transport *fileEncryptedStreamTransport) closeFile() error {
	transport.closeOnce.Do(func() { transport.closeErr = transport.file.Close() })
	return transport.closeErr
}

func (transport *fileEncryptedStreamTransport) interrupt() error {
	err := transport.closeFile()
	if transport.file != transport.destination {
		err = errors.Join(err, transport.destination.Close())
	}
	return err
}

func (transport *fileEncryptedStreamTransport) close() error {
	if transport.file == transport.destination {
		return nil
	}
	return transport.closeFile()
}

type encryptedStreamReader struct {
	ctx context.Context
	io.Reader
}

type encryptedStreamWriter struct{ io.Writer }

func (reader encryptedStreamReader) Read(p []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.Reader.Read(p)
}

func copyEncryptedSpool(ctx context.Context, spool *fileops.EncryptedSpool, destination io.Writer, buffer []byte) (retErr error) {
	reader, err := spool.OpenReader()
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, reader.Close()) }()
	written, err := io.CopyBuffer(destination, encryptedStreamReader{ctx: ctx, Reader: reader}, buffer)
	if err != nil {
		return err
	}
	if written < 0 || uint64(written) != spool.Length() {
		return errors.New("encrypted output length changed")
	}
	return ctx.Err()
}
