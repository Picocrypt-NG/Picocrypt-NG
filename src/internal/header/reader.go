package header

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"Picocrypt-NG/internal/encoding"
)

// ErrCorruptedHeader indicates the header could not be decoded
var ErrCorruptedHeader = errors.New("volume header is damaged")

// ErrInvalidVersion indicates the version string is not valid
var ErrInvalidVersion = errors.New("invalid version format")

// ErrInvalidCommentLength indicates the comment length field is corrupted
var ErrInvalidCommentLength = errors.New("unable to read comments length")

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
	Header      *VolumeHeader
	DecodeError error // Non-nil if any RS decode errors occurred (header may still be usable)
	BytesRead   int   // Total bytes consumed from the reader
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
	}
	h.Version = string(versionDec)

	// Validate version format
	if valid, _ := regexp.Match(`^v\d\.\d{2}$`, versionDec); !valid {
		return result, ErrInvalidVersion
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
	}

	// Validate comment length format (5 digits)
	if valid, _ := regexp.Match(`^\d{5}$`, commentLenDec); !valid {
		return result, ErrInvalidCommentLength
	}

	commentsLen, _ := strconv.Atoi(string(commentLenDec))

	// Read comments (each byte is rs1 encoded: 3 bytes -> 1 byte)
	comments := make([]byte, 0, commentsLen)
	for i := 0; i < commentsLen; i++ {
		cEnc := make([]byte, 3) // rs1: 1 -> 3
		n, err = io.ReadFull(r.r, cEnc)
		result.BytesRead += n
		if err != nil {
			return result, fmt.Errorf("read comment char %d: %w", i, err)
		}

		cDec, err := encoding.Decode(r.rs.RS1, cEnc, false)
		if err != nil {
			decodeErrors = append(decodeErrors, err)
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

// RawHeaderFields holds the raw (decoded but unprocessed) header field bytes.
// Used for v2 header MAC computation where we need the exact decoded bytes.
type RawHeaderFields struct {
	Version     []byte
	CommentsLen int
	Comments    []byte
	Flags       []byte
}

// ReadHeaderRawResult contains the result of reading raw header fields.
type ReadHeaderRawResult struct {
	Raw         *RawHeaderFields
	Header      *VolumeHeader
	DecodeError error // Non-nil if any RS decode errors occurred (header may still be usable)
}

// ReadHeaderRaw reads header fields and returns raw bytes for MAC computation.
// This is needed for v2 header authentication where we MAC the decoded field values.
// Returns the header even if RS decode errors occur (for force-decrypt scenarios).
// The DecodeError field will be set if any corruption was detected.
func (r *Reader) ReadHeaderRaw() (*ReadHeaderRawResult, error) {
	result := &ReadHeaderRawResult{
		Raw:    &RawHeaderFields{},
		Header: &VolumeHeader{},
	}
	raw := result.Raw
	h := result.Header
	var decodeErrors []error

	// Read version
	versionEnc := make([]byte, VersionEncSize)
	if _, err := io.ReadFull(r.r, versionEnc); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	versionDec, err := encoding.Decode(r.rs.RS5, versionEnc, false)
	if err != nil {
		return nil, fmt.Errorf("decode version: %w", err)
	}
	raw.Version = versionDec
	h.Version = string(versionDec)

	// Read comment length
	commentLenEnc := make([]byte, CommentLenEncSize)
	if _, err := io.ReadFull(r.r, commentLenEnc); err != nil {
		return nil, fmt.Errorf("read comment length: %w", err)
	}
	commentLenDec, err := encoding.Decode(r.rs.RS5, commentLenEnc, false)
	if err != nil {
		return nil, fmt.Errorf("decode comment length: %w", err)
	}
	commentsLen, _ := strconv.Atoi(string(commentLenDec))
	raw.CommentsLen = commentsLen

	// Read comments (track corruption but continue reading)
	raw.Comments = make([]byte, 0, commentsLen)
	commentsCorrupted := false
	for i := 0; i < commentsLen; i++ {
		cEnc := make([]byte, 3)
		if _, err := io.ReadFull(r.r, cEnc); err != nil {
			return nil, fmt.Errorf("read comment char %d: %w", i, err)
		}
		cDec, err := encoding.Decode(r.rs.RS1, cEnc, false)
		if err != nil {
			commentsCorrupted = true
			decodeErrors = append(decodeErrors, err)
		}
		raw.Comments = append(raw.Comments, cDec...)
	}
	if commentsCorrupted {
		h.Comments = "Comments are corrupted"
	} else {
		h.Comments = string(raw.Comments)
	}

	// Read flags
	flagsEnc := make([]byte, FlagsEncSize)
	if _, err := io.ReadFull(r.r, flagsEnc); err != nil {
		return nil, fmt.Errorf("read flags: %w", err)
	}
	flagsDec, err := encoding.Decode(r.rs.RS5, flagsEnc, false)
	if err != nil {
		return nil, fmt.Errorf("decode flags: %w", err)
	}
	raw.Flags = flagsDec
	h.Flags = FlagsFromBytes(flagsDec)

	// Read remaining crypto fields (collect errors but continue for force-decrypt)
	saltEnc := make([]byte, SaltEncSize)
	if _, err := io.ReadFull(r.r, saltEnc); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	h.Salt, err = encoding.Decode(r.rs.RS16, saltEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	hkdfSaltEnc := make([]byte, HKDFSaltEncSize)
	if _, err := io.ReadFull(r.r, hkdfSaltEnc); err != nil {
		return nil, fmt.Errorf("read hkdf salt: %w", err)
	}
	h.HKDFSalt, err = encoding.Decode(r.rs.RS32, hkdfSaltEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	serpentIVEnc := make([]byte, SerpentIVEncSize)
	if _, err := io.ReadFull(r.r, serpentIVEnc); err != nil {
		return nil, fmt.Errorf("read serpent iv: %w", err)
	}
	h.SerpentIV, err = encoding.Decode(r.rs.RS16, serpentIVEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	nonceEnc := make([]byte, NonceEncSize)
	if _, err := io.ReadFull(r.r, nonceEnc); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	h.Nonce, err = encoding.Decode(r.rs.RS24, nonceEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	keyHashEnc := make([]byte, KeyHashEncSize)
	if _, err := io.ReadFull(r.r, keyHashEnc); err != nil {
		return nil, fmt.Errorf("read key hash: %w", err)
	}
	h.KeyHash, err = encoding.Decode(r.rs.RS64, keyHashEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	keyfileHashEnc := make([]byte, KeyfileHashEncSize)
	if _, err := io.ReadFull(r.r, keyfileHashEnc); err != nil {
		return nil, fmt.Errorf("read keyfile hash: %w", err)
	}
	h.KeyfileHash, err = encoding.Decode(r.rs.RS32, keyfileHashEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	authTagEnc := make([]byte, AuthTagEncSize)
	if _, err := io.ReadFull(r.r, authTagEnc); err != nil {
		return nil, fmt.Errorf("read auth tag: %w", err)
	}
	h.AuthTag, err = encoding.Decode(r.rs.RS64, authTagEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	// Set combined decode error if any occurred
	if len(decodeErrors) > 0 {
		result.DecodeError = ErrCorruptedHeader
	}

	return result, nil
}
