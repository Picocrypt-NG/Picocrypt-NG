// Package pcv3credential implements the PCV3 credential foundation.
package pcv3credential

import (
	pcsecret "Picocrypt-NG/internal/secret"
	"bytes"
	"context"
	"crypto/sha3"
	"errors"
	"io"
	"reflect"
	"sort"
)

const (
	maxPasswordBytes         = 1 << 20
	maxKeyfiles              = 64
	keyfileScratchBytes      = 32 << 10
	maxConsecutiveEmptyReads = 100
	keyfileDomain            = "Picocrypt-NG/PCV3/keyfile\x00"
)

// CredentialMode is the complete factor combination encoded in a PCV3
// credential transcript.
type CredentialMode uint8

const (
	CredentialModePasswordOnly        CredentialMode = 0x01
	CredentialModeKeyfilesOnly        CredentialMode = 0x02
	CredentialModePasswordAndKeyfiles CredentialMode = 0x03
)

// KeyfileMode controls canonical keyfile digest ordering.
type KeyfileMode uint8

const (
	KeyfileModeNone      KeyfileMode = 0x00
	KeyfileModeOrdered   KeyfileMode = 0x01
	KeyfileModeUnordered KeyfileMode = 0x02
)

// FactorPolicy is the caller-pinned factor policy retained independently from
// untrusted volume metadata.
type FactorPolicy uint8

const (
	FactorPolicyPasswordOnly        FactorPolicy = 0x01
	FactorPolicyKeyfilesOnly        FactorPolicy = 0x02
	FactorPolicyPasswordAndKeyfiles FactorPolicy = 0x03
)

// KeyfileReader is the ownership handle for one already-opened keyfile reader.
// OwnKeyfileReader must be called exactly once for a reader; callers must not
// retain, reuse, close, or wrap the transferred reader again. A handle and its
// copies share one close state and are not safe for concurrent use.
type KeyfileReader struct {
	state *keyfileReaderState
}

type keyfileReaderState struct {
	reader io.ReadCloser
	closed bool
}

// OwnKeyfileReader transfers ownership of reader into a keyfile handle.
func OwnKeyfileReader(reader io.ReadCloser) *KeyfileReader {
	return &KeyfileReader{
		state: &keyfileReaderState{reader: reader},
	}
}

func (KeyfileReader) String() string {
	return "pcv3credential.KeyfileReader([REDACTED])"
}

func (KeyfileReader) GoString() string {
	return "pcv3credential.KeyfileReader([REDACTED])"
}

// Close releases a handle that will not be transferred to FactorRequest. It is
// idempotent and redacts any underlying close failure.
func (reader *KeyfileReader) Close() error {
	if reader.close() {
		return newFactorError(FactorErrorClose, -1, 0)
	}
	return nil
}

// FactorRequest transfers ownership of Password, the Keyfiles slice, and every
// keyfile handle to WithValidatedFactors. Callers must not retain or reuse
// their backing storage.
type FactorRequest struct {
	requireNonemptyKeyfiles bool
	Mode                    CredentialMode
	KeyfileMode             KeyfileMode
	ExpectedPolicy          FactorPolicy
	Password                []byte
	Keyfiles                []*KeyfileReader
}

// RequireNonemptyKeyfiles strengthens creation policy without changing legacy
// read transcripts. Emptiness is checked while consuming the owned reader.
func (request *FactorRequest) RequireNonemptyKeyfiles() {
	if request != nil {
		request.requireNonemptyKeyfiles = true
	}
}

func (FactorRequest) String() string {
	return "pcv3credential.FactorRequest([REDACTED])"
}

func (FactorRequest) GoString() string {
	return "pcv3credential.FactorRequest([REDACTED])"
}

// Close releases a factor request that will not be transferred to
// WithValidatedFactors. It is idempotent and redacts keyfile close failures.
func (request *FactorRequest) Close() error {
	if request == nil {
		return nil
	}
	return takeFactorRequest(request).close()
}

// FactorErrorCode identifies a public, non-secret failure reason.
type FactorErrorCode uint8

const (
	FactorErrorInvalidRequest FactorErrorCode = iota + 1
	FactorErrorInvalidMode
	FactorErrorInvalidPolicy
	FactorErrorPolicyMismatch
	FactorErrorInvalidCombination
	FactorErrorPasswordLength
	FactorErrorKeyfileCount
	FactorErrorNilReader
	FactorErrorRead
	FactorErrorReaderContract
	FactorErrorNoProgress
	FactorErrorClose
	FactorErrorCancelled
	FactorErrorDuplicate
	FactorErrorEmptyKeyfile
)

// FactorError contains public identifiers and sizes only.
type FactorError struct {
	Code  FactorErrorCode
	Index int
	Size  uint64
}

func (e *FactorError) Error() string {
	if e == nil {
		return "pcv3credential: factor failure"
	}
	switch e.Code {
	case FactorErrorEmptyKeyfile:
		return "pcv3credential: empty creation keyfile"
	case FactorErrorInvalidRequest:
		return "pcv3credential: invalid factor request"
	case FactorErrorInvalidMode:
		return "pcv3credential: invalid credential or keyfile mode"
	case FactorErrorInvalidPolicy:
		return "pcv3credential: invalid factor policy"
	case FactorErrorPolicyMismatch:
		return "pcv3credential: factor policy mismatch"
	case FactorErrorInvalidCombination:
		return "pcv3credential: invalid factor combination"
	case FactorErrorPasswordLength:
		return "pcv3credential: password length rejected"
	case FactorErrorKeyfileCount:
		return "pcv3credential: keyfile count rejected"
	case FactorErrorNilReader:
		return "pcv3credential: nil keyfile reader"
	case FactorErrorRead:
		return "pcv3credential: keyfile read failed"
	case FactorErrorReaderContract:
		return "pcv3credential: keyfile reader contract violated"
	case FactorErrorNoProgress:
		return "pcv3credential: keyfile reader made no progress"
	case FactorErrorClose:
		return "pcv3credential: keyfile close failed"
	case FactorErrorCancelled:
		return "pcv3credential: factor processing cancelled"
	case FactorErrorDuplicate:
		return "pcv3credential: duplicate keyfile digest"
	default:
		return "pcv3credential: factor failure"
	}
}

// FactorDescriptor is a validated keyfile digest record. Its digest is private
// to this package and is valid only during the validation callback.
type FactorDescriptor struct {
	digest *pcsecret.Secret
}

func (FactorDescriptor) String() string {
	return "pcv3credential.FactorDescriptor([REDACTED])"
}

func (FactorDescriptor) GoString() string {
	return "pcv3credential.FactorDescriptor([REDACTED])"
}

// ValidatedFactors is a scoped borrow supplied to the validation callback.
type ValidatedFactors struct {
	mode           CredentialMode
	keyfileMode    KeyfileMode
	expectedPolicy FactorPolicy
	password       *pcsecret.Secret
	descriptors    []FactorDescriptor
}

func (ValidatedFactors) String() string {
	return "pcv3credential.ValidatedFactors([REDACTED])"
}

func (ValidatedFactors) GoString() string {
	return "pcv3credential.ValidatedFactors([REDACTED])"
}

type factorHooks struct {
	observeScratch          func([]byte)
	observeProcessedChunk   func(int, []byte, []byte)
	observeDescriptorDigest func(int, []byte)
	observeSortedCopy       func([][32]byte)
}

type ownedFactors struct {
	requireNonemptyKeyfiles bool
	password                *pcsecret.Secret
	readers                 []*KeyfileReader
	descriptors             []FactorDescriptor
	sortedCopy              [][32]byte
	closed                  bool
}

// WithValidatedFactors validates and owns one complete factor request for the
// duration of callback.
func WithValidatedFactors(
	ctx context.Context,
	request *FactorRequest,
	callback func(*ValidatedFactors) error,
) error {
	return withValidatedFactors(ctx, request, callback, nil)
}

func withValidatedFactors(
	ctx context.Context,
	request *FactorRequest,
	callback func(*ValidatedFactors) error,
	hooks *factorHooks,
) (err error) {
	if request == nil {
		return newFactorError(FactorErrorInvalidRequest, -1, 0)
	}

	owned := takeFactorRequest(request)
	defer func() {
		closeErr := owned.close()
		switch {
		case closeErr == nil:
		case err == nil:
			err = closeErr
		default:
			err = errors.Join(err, closeErr)
		}
	}()

	if ctx == nil || callback == nil {
		return newFactorError(FactorErrorInvalidRequest, -1, 0)
	}
	if err := validateFactorShape(
		owned,
		request.Mode,
		request.KeyfileMode,
		request.ExpectedPolicy,
	); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return newFactorError(FactorErrorCancelled, -1, 0)
	}

	if len(owned.readers) > 0 {
		scratch := make([]byte, keyfileScratchBytes)
		defer pcsecret.SecureZero(scratch)
		if hooks != nil && hooks.observeScratch != nil {
			hooks.observeScratch(scratch)
		}
		owned.descriptors = make([]FactorDescriptor, len(owned.readers))
		for i, reader := range owned.readers {
			digest, digestErr := digestKeyfile(
				ctx,
				reader.readCloser(),
				i,
				scratch,
				hooks,
				owned.requireNonemptyKeyfiles,
			)
			if digestErr != nil {
				return digestErr
			}
			owned.descriptors[i].digest = digest
			if hooks != nil && hooks.observeDescriptorDigest != nil {
				hooks.observeDescriptorDigest(i, digest.Bytes())
			}
		}

		owned.sortedCopy = make([][32]byte, len(owned.descriptors))
		for i := range owned.descriptors {
			copy(owned.sortedCopy[i][:], owned.descriptors[i].digest.Bytes())
		}
		if hooks != nil && hooks.observeSortedCopy != nil {
			hooks.observeSortedCopy(owned.sortedCopy)
		}
		sort.Slice(owned.sortedCopy, func(i, j int) bool {
			return bytes.Compare(owned.sortedCopy[i][:], owned.sortedCopy[j][:]) < 0
		})
		for i := 1; i < len(owned.sortedCopy); i++ {
			if owned.sortedCopy[i] == owned.sortedCopy[i-1] {
				return newFactorError(FactorErrorDuplicate, -1, uint64(len(owned.sortedCopy)))
			}
		}
	}

	if ctx.Err() != nil {
		return newFactorError(FactorErrorCancelled, -1, 0)
	}
	if err := owned.closeReaders(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return newFactorError(FactorErrorCancelled, -1, 0)
	}
	validated := &ValidatedFactors{
		mode:           request.Mode,
		keyfileMode:    request.KeyfileMode,
		expectedPolicy: request.ExpectedPolicy,
		password:       owned.password,
		descriptors:    owned.descriptors,
	}
	return callback(validated)
}

func takeFactorRequest(request *FactorRequest) *ownedFactors {
	owned := &ownedFactors{
		requireNonemptyKeyfiles: request.requireNonemptyKeyfiles,
		password:                pcsecret.SecretFrom(request.Password),
		readers:                 request.Keyfiles,
	}
	request.requireNonemptyKeyfiles = false
	request.Password = nil
	request.Keyfiles = nil
	return owned
}

func validateFactorShape(
	owned *ownedFactors,
	mode CredentialMode,
	keyfileMode KeyfileMode,
	policy FactorPolicy,
) error {
	switch mode {
	case CredentialModePasswordOnly,
		CredentialModeKeyfilesOnly,
		CredentialModePasswordAndKeyfiles:
	default:
		return newFactorError(FactorErrorInvalidMode, -1, uint64(mode))
	}
	switch keyfileMode {
	case KeyfileModeNone, KeyfileModeOrdered, KeyfileModeUnordered:
	default:
		return newFactorError(FactorErrorInvalidMode, -1, uint64(keyfileMode))
	}
	if !validFactorPolicy(policy) {
		return newFactorError(FactorErrorInvalidPolicy, -1, uint64(policy))
	}
	if !policyMatchesMode(policy, mode) {
		return newFactorError(FactorErrorPolicyMismatch, -1, uint64(policy))
	}

	passwordLen := owned.password.Len()
	keyfileCount := len(owned.readers)
	if passwordLen > maxPasswordBytes {
		return newFactorError(FactorErrorPasswordLength, -1, uint64(passwordLen))
	}
	if keyfileCount > maxKeyfiles {
		return newFactorError(FactorErrorKeyfileCount, -1, uint64(keyfileCount))
	}

	validPassword := false
	switch mode {
	case CredentialModePasswordOnly:
		validPassword = passwordLen > 0
	case CredentialModeKeyfilesOnly:
		validPassword = passwordLen == 0
	case CredentialModePasswordAndKeyfiles:
		validPassword = passwordLen > 0
	}
	if !validPassword || !validCredentialTuple(
		mode,
		keyfileMode,
		uint16(keyfileCount), //nolint:gosec // Bounded to maxKeyfiles above.
	) {
		return newFactorError(
			FactorErrorInvalidCombination,
			-1,
			uint64(keyfileCount),
		)
	}

	seenReaders := make(map[*keyfileReaderState]struct{}, keyfileCount)
	for i, reader := range owned.readers {
		if reader == nil ||
			reader.state == nil ||
			reader.state.closed ||
			isNilReadCloser(reader.state.reader) {
			return newFactorError(FactorErrorNilReader, i, uint64(keyfileCount))
		}
		if _, duplicate := seenReaders[reader.state]; duplicate {
			return newFactorError(FactorErrorDuplicate, i, uint64(keyfileCount))
		}
		seenReaders[reader.state] = struct{}{}
	}
	return nil
}

// validCredentialTuple is the single structural credential tuple check shared
// by factor admission and the immutable key owner. Password presence remains a
// factor-admission concern and is implied by CredentialMode after validation.
func validCredentialTuple(
	mode CredentialMode,
	keyfileMode KeyfileMode,
	keyfileCount uint16,
) bool {
	switch mode {
	case CredentialModePasswordOnly:
		return keyfileMode == KeyfileModeNone && keyfileCount == 0
	case CredentialModeKeyfilesOnly, CredentialModePasswordAndKeyfiles:
		return (keyfileMode == KeyfileModeOrdered || keyfileMode == KeyfileModeUnordered) &&
			keyfileCount > 0 && keyfileCount <= maxKeyfiles
	default:
		return false
	}
}

func validFactorPolicy(policy FactorPolicy) bool {
	switch policy {
	case FactorPolicyPasswordOnly,
		FactorPolicyKeyfilesOnly,
		FactorPolicyPasswordAndKeyfiles:
		return true
	default:
		return false
	}
}

func policyMatchesMode(policy FactorPolicy, mode CredentialMode) bool {
	switch policy {
	case FactorPolicyPasswordOnly:
		return mode == CredentialModePasswordOnly
	case FactorPolicyKeyfilesOnly:
		return mode == CredentialModeKeyfilesOnly
	case FactorPolicyPasswordAndKeyfiles:
		return mode == CredentialModePasswordAndKeyfiles
	default:
		return false
	}
}

func isNilReadCloser(reader io.ReadCloser) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (reader *KeyfileReader) readCloser() io.ReadCloser {
	if reader == nil ||
		reader.state == nil ||
		reader.state.closed {
		return nil
	}
	return reader.state.reader
}

func (reader *KeyfileReader) close() (failed bool) {
	if reader == nil ||
		reader.state == nil ||
		reader.state.closed {
		return false
	}

	reader.state.closed = true
	owned := reader.state.reader
	reader.state.reader = nil
	if isNilReadCloser(owned) {
		return false
	}

	closeErr, panicked := safeClose(owned)
	return closeErr != nil || panicked
}

func digestKeyfile(
	ctx context.Context,
	reader io.ReadCloser,
	index int,
	scratch []byte,
	hooks *factorHooks,
	requireNonempty bool,
) (*pcsecret.Secret, error) {
	hasher := sha3.New256()
	_, _ = hasher.Write([]byte(keyfileDomain))

	emptyReads := 0
	readAny := false
	for {
		if ctx.Err() != nil {
			return nil, newFactorError(FactorErrorCancelled, index, 0)
		}

		n, readErr, panicked := safeRead(reader, scratch)
		validCount := n >= 0 && n <= len(scratch)
		if validCount && n > 0 {
			readAny = true
			_, _ = hasher.Write(scratch[:n])
			if hooks != nil && hooks.observeProcessedChunk != nil {
				processedDigest := hasher.Sum(nil)
				func() {
					defer pcsecret.SecureZero(processedDigest)
					hooks.observeProcessedChunk(index, scratch[:n], processedDigest)
				}()
			}
			emptyReads = 0
		}
		pcsecret.SecureZero(scratch)

		if panicked {
			return nil, newFactorError(FactorErrorRead, index, 0)
		}
		if !validCount {
			return nil, newFactorError(
				FactorErrorReaderContract,
				index,
				uint64(max(n, 0)),
			)
		}
		if n == 0 && readErr == nil {
			emptyReads++
			if emptyReads > maxConsecutiveEmptyReads {
				return nil, newFactorError(FactorErrorNoProgress, index, uint64(emptyReads))
			}
		}

		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return nil, newFactorError(FactorErrorRead, index, uint64(max(n, 0)))
			}
			if requireNonempty && !readAny {
				return nil, newFactorError(FactorErrorEmptyKeyfile, index, 0)
			}
			sum := hasher.Sum(nil)
			return pcsecret.SecretFrom(sum), nil
		}
	}
}

func safeRead(reader io.Reader, scratch []byte) (n int, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			n = 0
			err = nil
			panicked = true
		}
	}()
	n, err = reader.Read(scratch)
	return n, err, false
}

func safeClose(reader io.Closer) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err = nil
			panicked = true
		}
	}()
	err = reader.Close()
	return err, false
}

func (owned *ownedFactors) close() error {
	if owned == nil || owned.closed {
		return nil
	}
	owned.closed = true

	if owned.password != nil {
		owned.password.Close()
		owned.password = nil
	}
	for i := range owned.descriptors {
		if owned.descriptors[i].digest != nil {
			owned.descriptors[i].digest.Close()
			owned.descriptors[i].digest = nil
		}
	}
	owned.descriptors = nil
	for i := range owned.sortedCopy {
		pcsecret.SecureZero(owned.sortedCopy[i][:])
	}
	owned.sortedCopy = nil

	return owned.closeReaders()
}

func (owned *ownedFactors) closeReaders() error {
	var closeFailure *FactorError
	for i, reader := range owned.readers {
		if reader.close() && closeFailure == nil {
			closeFailure = newFactorError(FactorErrorClose, i, 0)
		}
		owned.readers[i] = nil
	}
	owned.readers = nil
	if closeFailure != nil {
		return closeFailure
	}
	return nil
}

func newFactorError(code FactorErrorCode, index int, size uint64) *FactorError {
	return &FactorError{Code: code, Index: index, Size: size}
}
