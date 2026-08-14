package volume

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"

	perrors "Picocrypt-NG/internal/errors"
)

// LegacyDecodeMode records the payload decoding mode whose real legacy MAC
// authenticated. Migration must reuse this exact choice instead of probing a
// second policy while plaintext is being consumed.
type LegacyDecodeMode uint8

const (
	LegacyDecodeUnknown LegacyDecodeMode = iota
	LegacyDecodePlain
	LegacyDecodeRSFast
	LegacyDecodeRSFull
)

// VerifiedLegacyPayload is an opaque, authenticated v1/v2 plaintext source.
// It intentionally exposes no descriptor, key, header, reader, or operation
// context. Close must be called even when StreamTo fails.
type VerifiedLegacyPayload struct {
	mu         sync.Mutex
	ctx        *OperationContext
	req        DecryptRequest
	decodeMode LegacyDecodeMode
	length     int64
	closed     bool
}

// PrepareVerifiedLegacyPayload consumes preparedInput on success and returns
// an owner only after the production v1/v2 header and payload MAC contracts
// authenticate. On failure, preparedInput remains owned by the caller.
func PrepareVerifiedLegacyPayload(
	ctx context.Context,
	req *DecryptRequest,
	preparedInput *PreparedDecryptInput,
) (*VerifiedLegacyPayload, error) {
	return prepareVerifiedLegacyPayload(ctx, req, preparedInput)
}

func prepareVerifiedLegacyPayload(
	ctx context.Context,
	req *DecryptRequest,
	preparedInput *PreparedDecryptInput,
) (_ *VerifiedLegacyPayload, retErr error) {
	if req == nil || preparedInput == nil || !preparedInput.matches(req.InputFile, req.Recombine) {
		return nil, errors.New("legacy migration input is unavailable")
	}
	if req.RSCodecs == nil {
		return nil, errors.New("legacy Reed-Solomon codecs are unavailable")
	}
	if req.ForceDecrypt {
		return nil, errors.New("Force-decrypted legacy input is not eligible for migration")
	}
	if req.Deniability {
		return nil, errors.New("explicit deniability requires the deniable legacy source")
	}

	opCtx := NewDecryptContext(ctx, req)
	opCtx.protectedInputInfos = append(opCtx.protectedInputInfos, preparedInput.inputInfos...)
	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		retErr = errors.Join(retErr, opCtx.Close())
		if err := opCtx.cleanupRecombinedFile(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup recombined input: %w", err))
		}
	}()

	if opCtx.IsCancelled() {
		return nil, opCtx.CancellationError()
	}
	if err := decryptPreprocess(opCtx, req, preparedInput); err != nil {
		return nil, err
	}
	if err := decryptReadHeader(opCtx, req); err != nil {
		return nil, err
	}
	if err := decryptDeriveProcessVerify(opCtx, req); err != nil {
		return nil, err
	}
	mode, length, err := decryptVerifyMACFirstWithDecode(opCtx, req, true)
	if err != nil {
		return nil, err
	}
	if opCtx.IsCancelled() {
		return nil, opCtx.CancellationError()
	}

	// Transfer the exact authenticated descriptor. A non-recombined operation
	// borrowed it from PreparedDecryptInput; a recombined operation already owns
	// its operation-created ciphertext descriptor and can release chunk zero.
	if opCtx.pinnedLegacyInput == preparedInput.file {
		preparedInput.detach()
		opCtx.ownsPinnedLegacyInput = true
	} else if err := preparedInput.Close(); err != nil {
		return nil, fmt.Errorf("close prepared chunk descriptor after authentication: %w", err)
	}

	owner := &VerifiedLegacyPayload{
		ctx: opCtx,
		req: DecryptRequest{
			RSCodecs: req.RSCodecs,
		},
		decodeMode: mode,
		length:     length,
	}
	succeeded = true
	return owner, nil
}

// Len is the exact authenticated plaintext length.
func (payload *VerifiedLegacyPayload) Len() int64 {
	if payload == nil {
		return 0
	}
	payload.mu.Lock()
	defer payload.mu.Unlock()
	return payload.length
}

// DecodeMode is the exact payload decode mode selected by authentication.
func (payload *VerifiedLegacyPayload) DecodeMode() LegacyDecodeMode {
	if payload == nil {
		return LegacyDecodeUnknown
	}
	payload.mu.Lock()
	defer payload.mu.Unlock()
	return payload.decodeMode
}

// StreamTo performs one bounded sequential pass over the retained descriptor.
// It recreates all per-pass derivation/cipher/MAC state, reuses the authenticated
// RS choice, and reports success only after the final legacy MAC matches.
func (payload *VerifiedLegacyPayload) StreamTo(output io.Writer) error {
	if payload == nil || output == nil {
		return errors.New("verified legacy payload or output is unavailable")
	}
	payload.mu.Lock()
	defer payload.mu.Unlock()
	if payload.closed || payload.ctx == nil {
		return errors.New("verified legacy payload is closed")
	}
	if payload.ctx.IsCancelled() {
		return payload.ctx.CancellationError()
	}
	// Recheck descriptor identity and exact size before any plaintext write.
	if _, err := payload.ctx.openLegacyDecryptInput(); err != nil {
		return err
	}
	if err := decryptDeriveKeys(payload.ctx, &payload.req); err != nil {
		return err
	}
	if err := decryptVerifyAuth(payload.ctx, &payload.req); err != nil {
		return err
	}

	fastDecode := payload.decodeMode != LegacyDecodeRSFull
	bounded := &verifiedLegacyWriter{dst: output, remaining: payload.length}
	if err := decryptPayloadTo(payload.ctx, &payload.req, fastDecode, bounded); err != nil {
		return err
	}
	if bounded.remaining != 0 {
		return errors.New("legacy payload length changed during streaming")
	}
	computedMAC := payload.ctx.CipherSuite.Sum()
	if subtle.ConstantTimeCompare(computedMAC, payload.ctx.Header.AuthTag) != 1 {
		return perrors.ErrAuthFailed
	}
	return nil
}

// Close is idempotent. It zeros all owned legacy credentials and crypto state,
// closes the exact source descriptor, and removes only an owned recombination
// stage when one exists.
func (payload *VerifiedLegacyPayload) Close() error {
	if payload == nil {
		return nil
	}
	payload.mu.Lock()
	defer payload.mu.Unlock()
	if payload.closed {
		return nil
	}
	payload.closed = true
	ctx := payload.ctx
	payload.ctx = nil
	if ctx == nil {
		return nil
	}
	return errors.Join(ctx.Close(), ctx.cleanupRecombinedFile())
}

type verifiedLegacyWriter struct {
	dst       io.Writer
	remaining int64
}

func (writer *verifiedLegacyWriter) Write(data []byte) (n int, err error) {
	if int64(len(data)) > writer.remaining {
		return 0, errors.New("legacy payload exceeded authenticated length")
	}
	defer func() {
		if recover() != nil {
			n = 0
			err = errors.New("legacy payload consumer panicked")
		}
	}()
	n, err = writer.dst.Write(data)
	if n < 0 || n > len(data) {
		n = 0
		return n, io.ErrShortWrite
	}
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	writer.remaining -= int64(n)
	return n, err
}
