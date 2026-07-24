package header

import (
	"Picocrypt-NG/internal/encoding"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// ErrCorruptedHeader indicates the header could not be decoded
var ErrCorruptedHeader = errors.New("volume header is damaged")

// ErrInvalidVersion indicates the version string is not valid
var ErrInvalidVersion = errors.New("invalid version format")

// ErrUnsupportedVersion indicates a syntactically valid version whose
// cryptographic generation this reader must not route through v1/v2 logic.
var ErrUnsupportedVersion = errors.New("unsupported volume version")

// ErrInvalidCommentLength indicates the comment length field is corrupted
var ErrInvalidCommentLength = errors.New("unable to read comments length")

// Package-scope, compile-once header validation patterns (QUAL-01/D-03).
// versionRE is the single anchored version pattern; it stays private and
// immutable — callers use MatchVersion instead of compiling their own copy.
var (
	versionRE    = regexp.MustCompile(`^v\d\.\d{2}$`)
	commentLenRE = regexp.MustCompile(`^\d{5}$`)
)

// MatchVersion reports whether b is a well-formed Picocrypt version string
// ("v2.09", "v1.49", ...). It encapsulates the single anchored version pattern
// shared by the header parser, the GUI preview, and deniability detection so
// every site uses the exact same (anchored) match (UI-01/QUAL-01/D-03).
func MatchVersion(b []byte) bool { return versionRE.Match(b) }

// IsSupportedVersion separates syntax recognition from cryptographic routing.
// Picocrypt-NG 2.19 reads v1 and v2; future majors must fail closed before flags
// or KDF inputs are trusted.
func IsSupportedVersion(b []byte) bool {
	return MatchVersion(b) && (b[1] == '1' || b[1] == '2')
}

// Reader handles reading volume headers from an input stream
type Reader struct {
	r  io.Reader
	rs *encoding.RSCodecs
}

// NewReader creates a header reader for the given input stream
func NewReader(r io.Reader, rs *encoding.RSCodecs) *Reader {
	return &Reader{r: r, rs: rs}
}

// ReadResult contains the parsed header and any decoding errors encountered
type ReadResult struct {
	Header                *VolumeHeader
	DecodeError           error // Non-nil if any RS decode errors occurred (header may still be usable)
	CommentDecodeError    bool  // True if one or more comment bytes failed RS decode
	NonCommentDecodeError bool  // True if any non-comment header field failed RS decode
	BytesRead             int   // Total bytes consumed from the reader
}

// ReadHeader reads and decodes a complete volume header.
// Returns the header even if RS decode errors occur (for force-decrypt scenarios).
// The DecodeError field will be set if any corruption was detected.
func (r *Reader) ReadHeader() (*ReadResult, error) {
	result := &ReadResult{
		Header: &VolumeHeader{},
	}
	h := result.Header
	var decodeErrors []error

	// Read version (15 bytes -> 5 bytes)
	versionEnc := make([]byte, VersionEncSize)
	n, err := io.ReadFull(r.r, versionEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read version: %w", err)
	}

	versionDec, err := encoding.Decode(r.rs.RS5, versionEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}
	h.Version = string(versionDec)

	// Validate version format
	if !versionRE.Match(versionDec) {
		return result, ErrInvalidVersion
	}
	if !IsSupportedVersion(versionDec) {
		return result, fmt.Errorf("%w %q", ErrUnsupportedVersion, string(versionDec))
	}

	// Read comment length (15 bytes -> 5 bytes)
	commentLenEnc := make([]byte, CommentLenEncSize)
	n, err = io.ReadFull(r.r, commentLenEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read comment length: %w", err)
	}

	commentLenDec, err := encoding.Decode(r.rs.RS5, commentLenEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}

	// Validate comment length format (5 digits)
	if !commentLenRE.Match(commentLenDec) {
		return result, ErrInvalidCommentLength
	}

	commentsLen, _ := strconv.Atoi(string(commentLenDec))

	// D-02 defense-in-depth bound: the ^\d{5}$ guard above already caps
	// commentsLen to [0, 99999] and forbids '-', but bound the value
	// explicitly against MaxCommentLen before allocating so any future
	// caller can never drive an oversized make([]byte, ...) allocation (SEC-01).
	if commentsLen < 0 || commentsLen > MaxCommentLen {
		return result, ErrInvalidCommentLength
	}

	// Read comments (each byte is rs1 encoded: 3 bytes -> 1 byte)
	comments := make([]byte, 0, commentsLen)
	for i := range commentsLen {
		cEnc := make([]byte, 3) // rs1: 1 -> 3
		n, err = io.ReadFull(r.r, cEnc)
		result.BytesRead += n
		if err != nil {
			return result, fmt.Errorf("read comment char %d: %w", i, err)
		}

		cDec, err := encoding.Decode(r.rs.RS1, cEnc, false)
		if err != nil {
			decodeErrors = append(decodeErrors, err)
			result.CommentDecodeError = true
		}
		comments = append(comments, cDec...)
	}
	h.Comments = string(comments)

	// Read flags (15 bytes -> 5 bytes)
	flagsEnc := make([]byte, FlagsEncSize)
	n, err = io.ReadFull(r.r, flagsEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read flags: %w", err)
	}

	flagsDec, err := encoding.Decode(r.rs.RS5, flagsEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}
	h.Flags = FlagsFromBytes(flagsDec)

	// Read salt (48 bytes -> 16 bytes)
	saltEnc := make([]byte, SaltEncSize)
	n, err = io.ReadFull(r.r, saltEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read salt: %w", err)
	}

	h.Salt, err = encoding.Decode(r.rs.RS16, saltEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}

	// Read HKDF salt (96 bytes -> 32 bytes)
	hkdfSaltEnc := make([]byte, HKDFSaltEncSize)
	n, err = io.ReadFull(r.r, hkdfSaltEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read hkdf salt: %w", err)
	}

	h.HKDFSalt, err = encoding.Decode(r.rs.RS32, hkdfSaltEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}

	// Read Serpent IV (48 bytes -> 16 bytes)
	serpentIVEnc := make([]byte, SerpentIVEncSize)
	n, err = io.ReadFull(r.r, serpentIVEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read serpent iv: %w", err)
	}

	h.SerpentIV, err = encoding.Decode(r.rs.RS16, serpentIVEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}

	// Read nonce (72 bytes -> 24 bytes)
	nonceEnc := make([]byte, NonceEncSize)
	n, err = io.ReadFull(r.r, nonceEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read nonce: %w", err)
	}

	h.Nonce, err = encoding.Decode(r.rs.RS24, nonceEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}

	// Read key hash (192 bytes -> 64 bytes)
	keyHashEnc := make([]byte, KeyHashEncSize)
	n, err = io.ReadFull(r.r, keyHashEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read key hash: %w", err)
	}

	h.KeyHash, err = encoding.Decode(r.rs.RS64, keyHashEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}

	// Read keyfile hash (96 bytes -> 32 bytes)
	keyfileHashEnc := make([]byte, KeyfileHashEncSize)
	n, err = io.ReadFull(r.r, keyfileHashEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read keyfile hash: %w", err)
	}

	h.KeyfileHash, err = encoding.Decode(r.rs.RS32, keyfileHashEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}

	// Read auth tag (192 bytes -> 64 bytes)
	authTagEnc := make([]byte, AuthTagEncSize)
	n, err = io.ReadFull(r.r, authTagEnc)
	result.BytesRead += n
	if err != nil {
		return result, fmt.Errorf("read auth tag: %w", err)
	}

	h.AuthTag, err = encoding.Decode(r.rs.RS64, authTagEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
		result.NonCommentDecodeError = true
	}

	// Set combined decode error if any occurred
	if len(decodeErrors) > 0 {
		result.DecodeError = ErrCorruptedHeader
	}

	return result, nil
}

// PeekVersion reads only the version from a volume to determine format.
// This is useful for checking if a file is a valid Picocrypt volume.
// Returns the version string and any error.
func PeekVersion(r io.Reader, rs *encoding.RSCodecs) (string, error) {
	versionEnc := make([]byte, VersionEncSize)
	if _, err := io.ReadFull(r, versionEnc); err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		return "", err
	}

	return string(versionDec), nil
}
