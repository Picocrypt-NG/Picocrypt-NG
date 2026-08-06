package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3unicode"
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
)

const (
	credentialTranscriptVersion = 0x01
	credentialTranscriptFixed   = 10
	keyfileDigestBytes          = 32
	credentialInputBytes        = 64
	credentialInputNormalBytes  = credentialInputBytes
	normalInputDomain           = "Picocrypt-NG/PCV3/credential/normal\x00"
	outerInputDomain            = "Picocrypt-NG/PCV3/credential/outer\x00"
	maxCredentialTranscript     = credentialTranscriptFixed +
		maxPasswordBytes +
		(maxKeyfiles * keyfileDigestBytes)
)

// TranscriptErrorCode identifies a public canonical-transcript failure.
type TranscriptErrorCode uint8

const (
	TranscriptErrorInvalidFactors TranscriptErrorCode = iota + 1
	TranscriptErrorPasswordCanonicalization
	TranscriptErrorLength
	TranscriptErrorClosed
)

// TranscriptError contains public identifiers and sizes only.
type TranscriptError struct {
	Code   TranscriptErrorCode
	Reason pcv3unicode.Rejection
	Size   uint64
}

func (err *TranscriptError) Error() string {
	if err == nil {
		return "pcv3credential: canonical transcript failure"
	}
	switch err.Code {
	case TranscriptErrorInvalidFactors:
		return "pcv3credential: invalid canonical transcript factors"
	case TranscriptErrorPasswordCanonicalization:
		return "pcv3credential: password canonicalization failed"
	case TranscriptErrorLength:
		return "pcv3credential: canonical transcript length rejected"
	case TranscriptErrorClosed:
		return "pcv3credential: canonical transcript owner is closed"
	default:
		return "pcv3credential: canonical transcript failure"
	}
}

// CanonicalTranscript owns one serialized complete-factor transcript. It must
// not be copied or used concurrently.
type CanonicalTranscript struct {
	secret *crypto.Secret
}

func (CanonicalTranscript) String() string {
	return "pcv3credential.CanonicalTranscript([REDACTED])"
}

func (CanonicalTranscript) GoString() string {
	return "pcv3credential.CanonicalTranscript([REDACTED])"
}

// NewCanonicalTranscript serializes one validated complete factor set.
func NewCanonicalTranscript(
	factors *ValidatedFactors,
) (*CanonicalTranscript, error) {
	return newCanonicalTranscript(factors, pcv3unicode.Canonicalize)
}

func newCanonicalTranscript(
	factors *ValidatedFactors,
	canonicalize func([]byte) ([]byte, error),
) (*CanonicalTranscript, error) {
	if canonicalize == nil {
		return nil, newTranscriptError(TranscriptErrorInvalidFactors, 0, 0)
	}

	digests, err := canonicalTranscriptDigests(factors)
	if err != nil {
		return nil, err
	}
	defer clearTranscriptDigests(digests)

	password := factors.password.Bytes()
	var canonicalPassword []byte
	if len(password) > 0 {
		canonicalInput := append([]byte(nil), password...)
		defer crypto.SecureZero(canonicalInput)
		canonicalPassword, err = canonicalize(canonicalInput)
		defer crypto.SecureZero(canonicalPassword)
		if err != nil {
			var unicodeErr *pcv3unicode.Error
			if errors.As(err, &unicodeErr) {
				return nil, newTranscriptError(
					TranscriptErrorPasswordCanonicalization,
					unicodeErr.Reason,
					uint64(len(password)),
				)
			}
			return nil, newTranscriptError(
				TranscriptErrorPasswordCanonicalization,
				0,
				uint64(len(password)),
			)
		}
		if len(canonicalPassword) == 0 {
			return nil, newTranscriptError(
				TranscriptErrorInvalidFactors,
				0,
				0,
			)
		}
		if len(canonicalPassword) > maxPasswordBytes {
			return nil, newTranscriptError(
				TranscriptErrorLength,
				0,
				uint64(len(canonicalPassword)),
			)
		}
	}

	passwordBytes := uint64(len(canonicalPassword))
	digestBytes := uint64(len(digests)) * keyfileDigestBytes
	if passwordBytes > ^uint64(0)-credentialTranscriptFixed {
		return nil, newTranscriptError(
			TranscriptErrorLength,
			0,
			passwordBytes,
		)
	}
	totalBytes := uint64(credentialTranscriptFixed) + passwordBytes
	if digestBytes > ^uint64(0)-totalBytes {
		return nil, newTranscriptError(
			TranscriptErrorLength,
			0,
			digestBytes,
		)
	}
	totalBytes += digestBytes
	if totalBytes > maxCredentialTranscript ||
		totalBytes > uint64(^uint(0)>>1) {
		return nil, newTranscriptError(
			TranscriptErrorLength,
			0,
			totalBytes,
		)
	}

	serialized := make([]byte, int(totalBytes))
	serialized[0] = credentialTranscriptVersion
	serialized[1] = byte(factors.mode)
	serialized[2] = byte(factors.keyfileMode)
	passwordLength := uint32(len(canonicalPassword)) //nolint:gosec // Bounded to 1 MiB above.
	binary.BigEndian.PutUint32(serialized[4:8], passwordLength)

	offset := 8
	offset += copy(serialized[offset:], canonicalPassword)
	keyfileCount := uint16(len(digests)) //nolint:gosec // Bounded to 64 above.
	binary.BigEndian.PutUint16(serialized[offset:offset+2], keyfileCount)
	offset += 2
	for i := range digests {
		offset += copy(serialized[offset:], digests[i][:])
	}

	return &CanonicalTranscript{secret: crypto.SecretFrom(serialized)}, nil
}

// Close clears the owned transcript. It is nil-safe and idempotent.
func (transcript *CanonicalTranscript) Close() {
	if transcript == nil || transcript.secret == nil {
		return
	}
	transcript.secret.Close()
	transcript.secret = nil
}

// CredentialInputNormal owns the exact 64-byte normal Argon2id input. It must
// not be copied or used concurrently.
type CredentialInputNormal struct {
	secret *crypto.Secret
}

func (CredentialInputNormal) String() string {
	return "pcv3credential.CredentialInputNormal([REDACTED])"
}

func (CredentialInputNormal) GoString() string {
	return "pcv3credential.CredentialInputNormal([REDACTED])"
}

// NewCredentialInputNormal consumes transcript and returns its normal-domain
// SHA3-512 digest.
func NewCredentialInputNormal(
	transcript *CanonicalTranscript,
) (*CredentialInputNormal, error) {
	var input *CredentialInputNormal
	err := consumeCanonicalTranscript(transcript, func(serialized []byte) error {
		input = &CredentialInputNormal{
			secret: credentialInputDigest(normalInputDomain, serialized),
		}
		return nil
	})
	return input, err
}

// Close clears the owned normal credential input. It is nil-safe and
// idempotent.
func (input *CredentialInputNormal) Close() {
	if input == nil || input.secret == nil {
		return
	}
	input.secret.Close()
	input.secret = nil
}

func (input *CredentialInputNormal) consume(
	callback func([]byte) error,
) error {
	if input == nil {
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}

	owned := input.secret
	input.secret = nil
	if owned == nil {
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}
	defer owned.Close()

	if callback == nil || owned.Len() != credentialInputNormalBytes {
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}
	return callback(owned.Bytes())
}

// CredentialInputOuter owns the exact 64-byte D1 outer Argon2id input. It may
// be borrowed sequentially for the independent front and tail derivations and
// must not be copied.
type CredentialInputOuter struct {
	secret    *crypto.Secret
	state     *credentialInputBorrowState
	closeOnce sync.Once
}

func (*CredentialInputOuter) String() string {
	return "pcv3credential.CredentialInputOuter([REDACTED])"
}

func (*CredentialInputOuter) GoString() string {
	return "pcv3credential.CredentialInputOuter([REDACTED])"
}

// NewD1CredentialInputs consumes one transcript and derives both protocol
// inputs without reopening or rehashing any factor source.
func NewD1CredentialInputs(
	transcript *CanonicalTranscript,
) (*CredentialInputNormal, *CredentialInputOuter, error) {
	var normal *CredentialInputNormal
	var outer *CredentialInputOuter
	err := consumeCanonicalTranscript(transcript, func(serialized []byte) error {
		normal = &CredentialInputNormal{
			secret: credentialInputDigest(normalInputDomain, serialized),
		}
		outerSecret := credentialInputDigest(outerInputDomain, serialized)
		state := &credentialInputBorrowState{
			input:  outerSecret.Bytes(),
			active: true,
		}
		state.idle = sync.NewCond(&state.mu)
		outer = &CredentialInputOuter{
			secret: outerSecret,
			state:  state,
		}
		return nil
	})
	if err != nil {
		if normal != nil {
			normal.Close()
		}
		if outer != nil {
			outer.Close()
		}
		return nil, nil, err
	}
	return normal, outer, nil
}

// Close clears the owned outer credential input after any active borrow
// returns. It is nil-safe and idempotent.
func (input *CredentialInputOuter) Close() {
	if input == nil {
		return
	}
	input.closeOnce.Do(func() {
		if input.state != nil {
			input.state.expire()
		}
		if input.secret != nil {
			input.secret.Close()
		}
	})
}

func (input *CredentialInputOuter) withInput(
	callback func([]byte) error,
) error {
	if input == nil || input.state == nil {
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}
	return (&credentialInputBorrow{state: input.state}).withInput(callback)
}

func consumeCanonicalTranscript(
	transcript *CanonicalTranscript,
	callback func([]byte) error,
) error {
	if transcript == nil || callback == nil {
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}

	owned := transcript.secret
	transcript.secret = nil
	if owned == nil {
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}
	defer owned.Close()

	if owned.Len() < credentialTranscriptFixed ||
		owned.Len() > maxCredentialTranscript {
		ownedLength := uint64(owned.Len()) //nolint:gosec // Secret.Len cannot be negative.
		return newTranscriptError(
			TranscriptErrorLength,
			0,
			ownedLength,
		)
	}
	return callback(owned.Bytes())
}

func credentialInputDigest(domain string, serialized []byte) *crypto.Secret {
	hasher := sha3.New512()
	defer hasher.Reset()
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write(serialized)
	return crypto.SecretFrom(hasher.Sum(nil))
}

// credentialInputBorrow lends one callback-scoped normal input to at most one
// synchronous borrower at a time. Copies share the same expiry state.
type credentialInputBorrow struct {
	state *credentialInputBorrowState
}

type credentialInputBorrowState struct {
	mu     sync.Mutex
	idle   *sync.Cond
	input  []byte
	active bool
	inUse  bool
}

func withCredentialInputBorrow(
	transcript *CanonicalTranscript,
	callback func(*credentialInputBorrow) error,
) error {
	if callback == nil {
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}
	input, err := NewCredentialInputNormal(transcript)
	if err != nil {
		return err
	}
	return withCredentialInputNormalBorrow(input, callback)
}

func withCredentialInputNormalBorrow(
	input *CredentialInputNormal,
	callback func(*credentialInputBorrow) error,
) error {
	if input == nil || callback == nil {
		if input != nil {
			input.Close()
		}
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}
	defer input.Close()
	return input.consume(func(normalInput []byte) error {
		state := &credentialInputBorrowState{
			input:  normalInput,
			active: true,
		}
		state.idle = sync.NewCond(&state.mu)
		defer state.expire()
		return callback(&credentialInputBorrow{state: state})
	})
}

func (borrow *credentialInputBorrow) withInput(
	callback func([]byte) error,
) error {
	if borrow == nil || borrow.state == nil || callback == nil {
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}
	state := borrow.state
	state.mu.Lock()
	if !state.active || state.inUse ||
		len(state.input) != credentialInputNormalBytes {
		state.mu.Unlock()
		return newTranscriptError(TranscriptErrorClosed, 0, 0)
	}
	state.inUse = true
	input := state.input
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.inUse = false
		state.idle.Broadcast()
		state.mu.Unlock()
	}()
	return callback(input)
}

func (state *credentialInputBorrowState) expire() {
	if state == nil {
		return
	}
	state.mu.Lock()
	state.active = false
	for state.inUse {
		state.idle.Wait()
	}
	state.input = nil
	state.mu.Unlock()
}

func canonicalTranscriptDigests(
	factors *ValidatedFactors,
) ([][keyfileDigestBytes]byte, error) {
	if factors == nil {
		return nil, newTranscriptError(TranscriptErrorInvalidFactors, 0, 0)
	}

	passwordLen := factors.password.Len()
	keyfileCount := len(factors.descriptors)
	if passwordLen > maxPasswordBytes {
		return nil, newTranscriptError(
			TranscriptErrorLength,
			0,
			uint64(passwordLen),
		)
	}
	if keyfileCount > maxKeyfiles ||
		!policyMatchesMode(factors.expectedPolicy, factors.mode) {
		return nil, newTranscriptError(
			TranscriptErrorInvalidFactors,
			0,
			uint64(keyfileCount),
		)
	}

	switch factors.mode {
	case CredentialModePasswordOnly:
		if passwordLen == 0 ||
			factors.keyfileMode != KeyfileModeNone ||
			keyfileCount != 0 {
			return nil, newTranscriptError(
				TranscriptErrorInvalidFactors,
				0,
				uint64(keyfileCount),
			)
		}
	case CredentialModeKeyfilesOnly:
		if passwordLen != 0 ||
			(factors.keyfileMode != KeyfileModeOrdered &&
				factors.keyfileMode != KeyfileModeUnordered) ||
			keyfileCount == 0 {
			return nil, newTranscriptError(
				TranscriptErrorInvalidFactors,
				0,
				uint64(keyfileCount),
			)
		}
	case CredentialModePasswordAndKeyfiles:
		if passwordLen == 0 ||
			(factors.keyfileMode != KeyfileModeOrdered &&
				factors.keyfileMode != KeyfileModeUnordered) ||
			keyfileCount == 0 {
			return nil, newTranscriptError(
				TranscriptErrorInvalidFactors,
				0,
				uint64(keyfileCount),
			)
		}
	default:
		return nil, newTranscriptError(
			TranscriptErrorInvalidFactors,
			0,
			uint64(factors.mode),
		)
	}

	digests := make([][keyfileDigestBytes]byte, keyfileCount)
	transferred := false
	defer func() {
		if !transferred {
			clearTranscriptDigests(digests)
		}
	}()
	for i := range factors.descriptors {
		if factors.descriptors[i].digest == nil ||
			factors.descriptors[i].digest.Len() != keyfileDigestBytes {
			return nil, newTranscriptError(
				TranscriptErrorInvalidFactors,
				0,
				uint64(keyfileCount),
			)
		}
		copy(digests[i][:], factors.descriptors[i].digest.Bytes())
	}

	if factors.keyfileMode == KeyfileModeUnordered {
		sortTranscriptDigests(digests)
		if hasDuplicateTranscriptDigest(digests) {
			return nil, newTranscriptError(
				TranscriptErrorInvalidFactors,
				0,
				uint64(keyfileCount),
			)
		}
		transferred = true
		return digests, nil
	}

	sorted := make([][keyfileDigestBytes]byte, len(digests))
	copy(sorted, digests)
	defer clearTranscriptDigests(sorted)
	sortTranscriptDigests(sorted)
	if hasDuplicateTranscriptDigest(sorted) {
		return nil, newTranscriptError(
			TranscriptErrorInvalidFactors,
			0,
			uint64(keyfileCount),
		)
	}
	transferred = true
	return digests, nil
}

func sortTranscriptDigests(digests [][keyfileDigestBytes]byte) {
	sort.Slice(digests, func(i, j int) bool {
		return bytes.Compare(digests[i][:], digests[j][:]) < 0
	})
}

func hasDuplicateTranscriptDigest(
	digests [][keyfileDigestBytes]byte,
) bool {
	for i := 1; i < len(digests); i++ {
		if digests[i] == digests[i-1] {
			return true
		}
	}
	return false
}

func clearTranscriptDigests(digests [][keyfileDigestBytes]byte) {
	for i := range digests {
		crypto.SecureZero(digests[i][:])
	}
}

func newTranscriptError(
	code TranscriptErrorCode,
	reason pcv3unicode.Rejection,
	size uint64,
) *TranscriptError {
	return &TranscriptError{Code: code, Reason: reason, Size: size}
}
