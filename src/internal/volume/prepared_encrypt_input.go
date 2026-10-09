package volume

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"io"
	"os"
)

// ErrEncryptInputCleanupIncomplete marks failed cleanup of an owned preparation artifact.
var ErrEncryptInputCleanupIncomplete = errors.New("encryption input cleanup incomplete")

// EncryptInputRequest contains input preparation only, without credentials or
// output publication authority. BorrowedSource, when supplied for a bare file,
// remains owned by the caller.
type EncryptInputRequest struct {
	ZIPBudget                          *fileops.ZIPResourceBudget
	InputFile                          string
	InputFiles, OnlyFiles, OnlyFolders []string
	InputIdentities                    []fileops.ZIPInputIdentity
	OutputFile                         string
	Compress                           bool
	// Final-output geometry used only for temporary-disk admission.
	PCV3, Paranoid, Deniability, ReedSolomon, Split bool
	Comments                                        string
	BorrowedSource                                  *os.File
	Reporter                                        ProgressReporter
}

// PreparedEncryptInput owns the authenticated encrypted temporary archive.
// Reader decrypts that temporary file as it is read; File pins its identity.
// All accessors are borrowed and become invalid after Close.
type PreparedEncryptInput struct {
	operation *OperationContext
	file      *os.File
	reader    io.Reader
	length    uint64
	closeFile bool
}

func PrepareEncryptInput(ctx context.Context, input EncryptInputRequest) (*PreparedEncryptInput, error) {
	req := &EncryptRequest{
		ZIPBudget: input.ZIPBudget,
		InputFile: input.InputFile, InputFiles: input.InputFiles,
		InputIdentities: input.InputIdentities,
		OnlyFiles:       input.OnlyFiles, OnlyFolders: input.OnlyFolders, OutputFile: input.OutputFile,
		Compress: input.Compress, Reporter: input.Reporter,
		PCV3: input.PCV3, Paranoid: input.Paranoid, Deniability: input.Deniability, ReedSolomon: input.ReedSolomon, Split: input.Split, Comments: input.Comments,
	}
	return prepareEncryptInput(NewEncryptContext(ctx, req), req, input.BorrowedSource)
}

func prepareEncryptInput(ctx *OperationContext, req *EncryptRequest, borrowed *os.File) (prepared *PreparedEncryptInput, err error) {
	prepared = &PreparedEncryptInput{operation: ctx}
	transferred := false
	defer func() {
		if transferred {
			return
		}
		panicValue := recover()
		cleanupErr := prepared.Close()
		prepared = nil
		if panicValue != nil {
			fileops.RepanicWithCleanup(panicValue, cleanupErr)
		}
		if cleanupErr != nil {
			err = errors.Join(err, ErrEncryptInputCleanupIncomplete, cleanupErr)
		}
	}()

	if err = encryptPreprocessWithBorrowed(ctx, req, borrowed); err != nil {
		return prepared, err
	}
	if ctx.tempZip != nil || ctx.selectedEncryptFile != nil || (ctx.tempInput != nil && ctx.InputFile == ctx.tempInput.Path()) {
		prepared.file, _, err = ctx.openInput()
	} else if borrowed != nil {
		prepared.file = borrowed
	} else {
		prepared.file, err = fileops.OpenExistingNoSymlink(ctx.InputFile, os.O_RDONLY)
		prepared.closeFile = err == nil
	}
	if err != nil {
		return prepared, err
	}
	info, err := prepared.file.Stat()
	if err != nil {
		return prepared, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return prepared, errors.New("encryption input must be regular")
	}
	prepared.length = uint64(info.Size()) //nolint:gosec // non-negative above
	if ctx.tempZip != nil {
		prepared.length = ctx.tempZip.Length()
	}
	prepared.reader, err = ctx.TempZipReader(prepared.file)
	if err != nil {
		return prepared, err
	}
	transferred = true
	return prepared, nil
}

func (input *PreparedEncryptInput) Reader() io.Reader { return input.reader }
func (input *PreparedEncryptInput) File() *os.File    { return input.file }
func (input *PreparedEncryptInput) Path() string      { return input.operation.InputFile }
func (input *PreparedEncryptInput) Length() uint64    { return input.length }
func (input *PreparedEncryptInput) PayloadKind() pcv3operation.PayloadKind {
	if input.operation.tempZip != nil {
		return pcv3operation.PayloadKindArchive
	}
	return pcv3operation.PayloadKindRaw
}

func (input *PreparedEncryptInput) Close() error {
	if input == nil {
		return nil
	}
	var err error
	if input.closeFile && input.file != nil {
		err = input.file.Close()
	}
	input.file = nil
	input.reader = nil
	input.length = 0
	if input.operation != nil {
		err = errors.Join(err, input.operation.Close())
		input.operation = nil
	}
	return err
}
