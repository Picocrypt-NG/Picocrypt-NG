package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	perrors "Picocrypt-NG/internal/errors"

	"golang.org/x/crypto/chacha20"
)

const (
	deniableOuterSaltSize   = 16
	deniableOuterNonceSize  = 24
	deniableOuterHeaderSize = deniableOuterSaltSize + deniableOuterNonceSize
)

// DeniableSource is an opaque authenticated plaintext source for an explicitly
// selected legacy deniability wrapper. It owns the PreparedDecryptInput after a
// successful PrepareDeniableSource call, but never detaches or reopens its
// descriptor. Close must be called even when StreamTo fails.
type DeniableSource struct {
	mu sync.Mutex

	ctx      *OperationContext
	request  DecryptRequest
	prepared *PreparedDecryptInput

	wrapperInfo os.FileInfo
	wrapperSize int64
	salt        []byte
	nonce       []byte
	outerKey    *crypto.Secret

	decodeMode LegacyDecodeMode
	length     int64
	closed     bool
	ownsInput  bool
}

// PrepareDeniableSource consumes preparedInput on success and returns a source
// only after the explicit wrapper and the production inner v1/v2 authentication
// contract succeed. On failure, preparedInput remains owned by the caller.
func PrepareDeniableSource(
	ctx context.Context,
	req *DecryptRequest,
	preparedInput *PreparedDecryptInput,
) (*DeniableSource, error) {
	return prepareDeniableSource(ctx, req, preparedInput)
}

func prepareDeniableSource(
	ctx context.Context,
	req *DecryptRequest,
	preparedInput *PreparedDecryptInput,
) (_ *DeniableSource, retErr error) {
	if req == nil || preparedInput == nil || !preparedInput.matches(req.InputFile, req.Recombine) {
		return nil, errors.New("deniable legacy migration input is unavailable")
	}
	if !req.Deniability {
		return nil, errors.New("legacy deniability must be selected explicitly")
	}
	if req.Recombine {
		return nil, errors.New("split deniable migration requires an unsupported ciphertext stage")
	}
	if req.RSCodecs == nil {
		return nil, errors.New("legacy Reed-Solomon codecs are unavailable")
	}
	if req.ForceDecrypt {
		return nil, errors.New("force-decrypted deniable input is not eligible for migration")
	}

	opCtx := NewDecryptContext(ctx, req)
	if opCtx.IsCancelled() {
		return nil, opCtx.CancellationError()
	}

	fin, err := preparedInput.rewindRouted()
	if err != nil {
		return nil, err
	}
	info, err := fin.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat deniable wrapper: %w", err)
	}
	if info.Size() < int64(deniableOuterHeaderSize+header.BaseHeaderSize) {
		return nil, errors.New("deniable wrapper is truncated")
	}

	salt := make([]byte, deniableOuterSaltSize)
	nonce := make([]byte, deniableOuterNonceSize)
	probe := make([]byte, header.VersionEncSize)
	defer crypto.SecureZero(probe)
	if _, err := io.ReadFull(fin, salt); err != nil {
		return nil, fmt.Errorf("read deniable salt: %w", err)
	}
	if _, err := io.ReadFull(fin, nonce); err != nil {
		crypto.SecureZero(salt)
		return nil, fmt.Errorf("read deniable nonce: %w", err)
	}
	if _, err := io.ReadFull(fin, probe); err != nil {
		crypto.SecureZero(salt)
		crypto.SecureZero(nonce)
		return nil, fmt.Errorf("read deniable version probe: %w", err)
	}

	outerKeyBytes, err := selectDeniabilityKey(req.Password, salt, nonce, probe, req.RSCodecs)
	if err != nil {
		crypto.SecureZero(salt)
		crypto.SecureZero(nonce)
		return nil, err
	}
	source := &DeniableSource{
		ctx:         opCtx,
		request:     DecryptRequest{RSCodecs: req.RSCodecs},
		prepared:    preparedInput,
		wrapperInfo: info,
		wrapperSize: info.Size(),
		salt:        salt,
		nonce:       nonce,
		outerKey:    crypto.SecretFrom(outerKeyBytes),
	}
	opCtx.legacyInputFactory = source.newPass
	opCtx.Total = source.innerSize() - int64(header.BaseHeaderSize)

	succeeded := false
	defer func() {
		if succeeded {
			return
		}
		retErr = errors.Join(retErr, source.close(false))
	}()

	if err := decryptReadHeader(opCtx, req); err != nil {
		return nil, err
	}
	if err := opCtx.closeLegacyInputPass(); err != nil {
		return nil, err
	}
	if err := decryptDeriveProcessVerify(opCtx, req); err != nil {
		return nil, err
	}
	mode, length, err := decryptVerifyMACFirstWithDecode(opCtx, req, true)
	if err != nil {
		return nil, err
	}
	if err := opCtx.closeLegacyInputPass(); err != nil {
		return nil, err
	}
	if opCtx.IsCancelled() {
		return nil, opCtx.CancellationError()
	}

	source.decodeMode = mode
	source.length = length
	source.ownsInput = true
	succeeded = true
	return source, nil
}

// Len is the exact authenticated inner plaintext length.
func (source *DeniableSource) Len() int64 {
	if source == nil {
		return 0
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.length
}

// DecodeMode is the exact inner payload decode mode selected by authentication.
func (source *DeniableSource) DecodeMode() LegacyDecodeMode {
	if source == nil {
		return LegacyDecodeUnknown
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.decodeMode
}

// StreamTo performs one bounded sequential wrapper and inner-payload pass. It
// revalidates the same descriptor, size, salt, and nonce before deriving fresh
// inner state, recreates the outer stream, and reports success only after the
// final legacy MAC matches.
func (source *DeniableSource) StreamTo(output io.Writer) (retErr error) {
	if source == nil || output == nil {
		return errors.New("deniable legacy source or output is unavailable")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || source.ctx == nil {
		return errors.New("deniable legacy source is closed")
	}
	defer func() {
		retErr = errors.Join(retErr, source.ctx.closeLegacyInputPass())
	}()
	if source.ctx.IsCancelled() {
		return source.ctx.CancellationError()
	}
	if _, err := source.validateWrapper(); err != nil {
		return err
	}
	if err := decryptDeriveKeys(source.ctx, &source.request); err != nil {
		return err
	}
	if err := decryptVerifyAuth(source.ctx, &source.request); err != nil {
		return err
	}

	fastDecode := source.decodeMode != LegacyDecodeRSFull
	bounded := &verifiedLegacyWriter{dst: output, remaining: source.length}
	if err := decryptPayloadTo(source.ctx, &source.request, fastDecode, bounded); err != nil {
		return err
	}
	if bounded.remaining != 0 {
		return errors.New("deniable legacy payload length changed during streaming")
	}
	computedMAC := source.ctx.CipherSuite.Sum()
	if subtle.ConstantTimeCompare(computedMAC, source.ctx.Header.AuthTag) != 1 {
		return perrors.ErrAuthFailed
	}
	return nil
}

// Close is idempotent. It closes only the consumed prepared descriptor and
// zeros the outer key, inner operation secrets, stream state, and buffers.
func (source *DeniableSource) Close() error {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.close(source.ownsInput)
}

func (source *DeniableSource) close(closeInput bool) error {
	if source == nil || source.closed {
		return nil
	}
	source.closed = true
	var cleanup []error
	if source.ctx != nil {
		cleanup = append(cleanup, source.ctx.Close())
		source.ctx = nil
	}
	if source.outerKey != nil {
		source.outerKey.Close()
		source.outerKey = nil
	}
	crypto.SecureZeroMultiple(source.salt, source.nonce)
	source.salt = nil
	source.nonce = nil
	source.wrapperInfo = nil
	source.wrapperSize = 0
	if closeInput && source.prepared != nil {
		cleanup = append(cleanup, source.prepared.Close())
	}
	source.prepared = nil
	source.ownsInput = false
	return errors.Join(cleanup...)
}

func (source *DeniableSource) innerSize() int64 {
	return source.wrapperSize - int64(deniableOuterHeaderSize)
}

func (source *DeniableSource) validateWrapper() (*os.File, error) {
	if source.prepared == nil || source.wrapperInfo == nil || source.outerKey == nil {
		return nil, errors.New("deniable wrapper owner is unavailable")
	}
	fin, err := source.prepared.rewindRouted()
	if err != nil {
		return nil, err
	}
	current, err := fin.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat deniable wrapper: %w", err)
	}
	if !os.SameFile(source.wrapperInfo, current) {
		return nil, errors.New("deniable wrapper identity changed")
	}
	if current.Size() != source.wrapperSize {
		return nil, errors.New("deniable wrapper size changed")
	}

	salt := make([]byte, deniableOuterSaltSize)
	nonce := make([]byte, deniableOuterNonceSize)
	defer crypto.SecureZeroMultiple(salt, nonce)
	if _, err := io.ReadFull(fin, salt); err != nil {
		return nil, fmt.Errorf("read deniable salt: %w", err)
	}
	if _, err := io.ReadFull(fin, nonce); err != nil {
		return nil, fmt.Errorf("read deniable nonce: %w", err)
	}
	if subtle.ConstantTimeCompare(salt, source.salt) != 1 {
		return nil, errors.New("deniable wrapper salt changed")
	}
	if subtle.ConstantTimeCompare(nonce, source.nonce) != 1 {
		return nil, errors.New("deniable wrapper nonce changed")
	}
	return fin, nil
}

func (source *DeniableSource) newPass() (io.ReadSeeker, error) {
	fin, err := source.validateWrapper()
	if err != nil {
		return nil, err
	}
	nonce := append([]byte(nil), source.nonce...)
	cipher, err := chacha20.NewUnauthenticatedCipher(source.outerKey.Bytes(), nonce)
	if err != nil {
		crypto.SecureZero(nonce)
		return nil, fmt.Errorf("create deniability stream: %w", err)
	}
	return &deniablePass{
		ctx:       source.ctx.Ctx,
		reader:    newDeniabilityReader(fin),
		cipher:    cipher,
		key:       source.outerKey.Bytes(),
		nonce:     nonce,
		remaining: source.innerSize(),
		raw:       util.GetMiBBuffer(),
		plain:     util.GetMiBBuffer(),
	}, nil
}

// deniablePass is a forward-only io.ReadSeeker. SeekStart is implemented by
// consuming decrypted bytes, so callers retain the legacy header/payload API
// without gaining random access or a second descriptor.
type deniablePass struct {
	ctx context.Context

	reader io.Reader
	cipher *chacha20.Cipher
	key    []byte
	nonce  []byte

	raw   []byte
	plain []byte
	start int
	end   int

	remaining int64
	position  int64
	counter   int64
	pending   error
	closed    bool
}

func (pass *deniablePass) Read(destination []byte) (int, error) {
	if pass == nil || pass.closed {
		return 0, os.ErrClosed
	}
	if len(destination) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(destination) {
		if err := pass.contextError(); err != nil {
			if written != 0 {
				return written, nil
			}
			return 0, err
		}
		if pass.start == pass.end {
			if pass.pending != nil {
				err := pass.pending
				pass.pending = nil
				if written != 0 {
					return written, nil
				}
				return 0, err
			}
			if pass.remaining == 0 {
				if written != 0 {
					return written, nil
				}
				return 0, io.EOF
			}
			if err := pass.fill(); err != nil {
				if written != 0 {
					pass.pending = err
					return written, nil
				}
				return 0, err
			}
		}
		copied := copy(destination[written:], pass.plain[pass.start:pass.end])
		crypto.SecureZero(pass.plain[pass.start : pass.start+copied])
		pass.start += copied
		pass.position += int64(copied)
		written += copied
	}
	return written, nil
}

func (pass *deniablePass) fill() error {
	want := int64(len(pass.raw))
	if pass.remaining < want {
		want = pass.remaining
	}
	n, err := io.ReadFull(pass.reader, pass.raw[:int(want)])
	if n == 0 {
		if err == nil {
			return io.ErrNoProgress
		}
		return err
	}
	pass.cipher.XORKeyStream(pass.plain[:n], pass.raw[:n])
	crypto.SecureZero(pass.raw[:n])
	pass.start = 0
	pass.end = n
	pass.remaining -= int64(n)
	pass.counter += int64(util.MiB)
	if pass.counter >= crypto.RekeyThreshold {
		cipher, nonce, rekeyErr := crypto.DeniabilityRekey(pass.key, pass.nonce)
		if rekeyErr != nil {
			crypto.SecureZero(pass.plain[:n])
			pass.start = 0
			pass.end = 0
			return fmt.Errorf("rekey deniability stream: %w", rekeyErr)
		}
		crypto.SecureZero(pass.nonce)
		pass.cipher = cipher
		pass.nonce = nonce
		pass.counter = 0
	}
	if err != nil {
		pass.pending = err
	}
	return nil
}

func (pass *deniablePass) Seek(offset int64, whence int) (int64, error) {
	if pass == nil || pass.closed {
		return 0, os.ErrClosed
	}
	if whence != io.SeekStart || offset < pass.position {
		return pass.position, errors.New("deniability pass permits only forward absolute seeks")
	}
	if offset > pass.position+pass.remaining+int64(pass.end-pass.start) {
		return pass.position, errors.New("deniability pass seek exceeds the inner volume")
	}
	if delta := offset - pass.position; delta > 0 {
		if _, err := io.CopyN(io.Discard, pass, delta); err != nil {
			return pass.position, err
		}
	}
	return pass.position, nil
}

func (pass *deniablePass) Close() error {
	if pass == nil || pass.closed {
		return nil
	}
	pass.closed = true
	crypto.SecureZeroMultiple(pass.raw, pass.plain, pass.nonce)
	util.PutMiBBuffer(pass.raw)
	util.PutMiBBuffer(pass.plain)
	pass.raw = nil
	pass.plain = nil
	pass.key = nil
	pass.nonce = nil
	pass.reader = nil
	pass.cipher = nil
	pass.pending = nil
	return nil
}

func (pass *deniablePass) contextError() error {
	if pass.ctx == nil {
		return nil
	}
	select {
	case <-pass.ctx.Done():
		return pass.ctx.Err()
	default:
		return nil
	}
}
