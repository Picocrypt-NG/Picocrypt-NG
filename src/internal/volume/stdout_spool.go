package volume

import (
	"Picocrypt-NG/internal/diskspace"
	"Picocrypt-NG/internal/fileops"
	"errors"
	"fmt"
	"path/filepath"
)

func validateEncryptedDecryptOutput(req *DecryptRequest) error {
	if req == nil || req.EncryptedOutput == nil {
		return nil
	}
	if *req.EncryptedOutput != nil {
		return errors.New("encrypted decrypt output is already owned by the caller")
	}
	if req.AutoUnzip {
		return errors.New("encrypted stdout output cannot extract an archive")
	}
	return nil
}

// encryptedDecryptOutputBudget applies the CLI's existing 1.5x plus 10 MiB
// temporary-space policy to physical ciphertext, including every record tag.
// Observed free space is not reserved; write and Seal errors remain fatal.
func encryptedDecryptOutputBudget(available int64) (uint64, error) {
	const reserve = 10 << 20
	if available <= reserve {
		return 0, errors.New("insufficient space for encrypted stdout staging")
	}
	return uint64(available-reserve) * 2 / 3, nil //nolint:gosec // Positive extent; doubling fits uint64.
}

func (ctx *OperationContext) discardEncryptedOutput() error {
	spool := ctx.encryptedOutput
	ctx.encryptedOutput = nil
	return spool.Close()
}

// Every payload attempt gets a fresh key and nonce session. In particular, an
// RS retry must never reset/truncate an existing encrypted owner.
func (ctx *OperationContext) beginEncryptedOutput() error {
	if err := ctx.discardEncryptedOutput(); err != nil {
		return err
	}
	available, err := diskspace.Available(filepath.Dir(ctx.OutputFile))
	if err != nil {
		return err
	}
	budget, err := encryptedDecryptOutputBudget(available)
	if err != nil {
		return err
	}
	ctx.encryptedOutput, err = fileops.CreateEncryptedSpool(ctx.Ctx, fileops.EncryptedSpoolOptions{
		NearPath: ctx.OutputFile, MaxPhysicalBytes: budget, Cancel: ctx.IsCancelled,
	})
	return err
}

// The sealed owner stays private until all operation-owned input and temporary
// cleanup succeeds. Failure also revokes the withheld output authority.
func finishLegacyDecrypt(ctx *OperationContext, req *DecryptRequest, resultErr error) error {
	var output *fileops.EncryptedSpool
	if resultErr == nil && req.EncryptedOutput != nil {
		output = ctx.encryptedOutput
		ctx.encryptedOutput = nil
		if output == nil {
			resultErr = errors.New("encrypted decrypt output is unavailable")
		}
	}
	resultErr = errors.Join(resultErr, ctx.Close())
	if err := ctx.cleanupRecombinedFile(); err != nil {
		resultErr = errors.Join(resultErr, fmt.Errorf("cleanup recombined input: %w", err))
	}
	// Reporter callbacks have already completed before cleanup. Consult only
	// the context here: a callback panic after detaching output would orphan it.
	if req.EncryptedOutput != nil && ctx.Ctx != nil {
		resultErr = errors.Join(resultErr, ctx.Ctx.Err())
	}
	if resultErr != nil {
		return errors.Join(resultErr, output.Close())
	}
	if req.EncryptedOutput != nil {
		*req.EncryptedOutput = output
	}
	return nil
}
