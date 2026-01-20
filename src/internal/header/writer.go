package header

import (
	"errors"
	"fmt"
	"io"

	"Picocrypt-NG/internal/encoding"
)

// Writer handles writing volume headers to an output stream
type Writer struct {
	w  io.Writer
	rs *encoding.RSCodecs
}

// NewWriter creates a header writer for the given output stream
func NewWriter(w io.Writer, rs *encoding.RSCodecs) *Writer {
	return &Writer{w: w, rs: rs}
}

// WriteHeader writes a complete volume header to the output stream.
// This writes all fields in the exact order required by the Picocrypt format.
// Returns the number of bytes written and any error.
//
// Header format (total = 789 + comments*3 bytes):
//   - Version:      15 bytes (rs5 encoded)
//   - CommentLen:   15 bytes (rs5 encoded, 5-digit decimal)
//   - Comments:     commentsLen*3 bytes (each byte rs1 encoded)
//   - Flags:        15 bytes (rs5 encoded)
//   - Salt:         48 bytes (rs16 encoded)
//   - HKDFSalt:     96 bytes (rs32 encoded)
//   - SerpentIV:    48 bytes (rs16 encoded)
//   - Nonce:        72 bytes (rs24 encoded)
//   - KeyHash:      192 bytes (rs64 encoded) - placeholder, filled later
//   - KeyfileHash:  96 bytes (rs32 encoded) - placeholder, filled later
//   - AuthTag:      192 bytes (rs64 encoded) - placeholder, filled later
func (w *Writer) WriteHeader(h *VolumeHeader) (int, error) {
	if len(h.Comments) > MaxCommentLen {
		return 0, errors.New("comments exceed maximum length")
	}

	var totalWritten int

	// Write version
	n, err := w.w.Write(encoding.Encode(w.rs.RS5, []byte(h.Version)))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write version: %w", err)
	}

	// Write comment length (5-digit zero-padded)
	commentsLenStr := fmt.Sprintf("%05d", len(h.Comments))
	n, err = w.w.Write(encoding.Encode(w.rs.RS5, []byte(commentsLenStr)))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write comment length: %w", err)
	}

	// Write each comment character (rs1 encoded)
	for _, c := range []byte(h.Comments) {
		n, err = w.w.Write(encoding.Encode(w.rs.RS1, []byte{c}))
		totalWritten += n
		if err != nil {
			return totalWritten, fmt.Errorf("write comment char: %w", err)
		}
	}

	// Write flags
	n, err = w.w.Write(encoding.Encode(w.rs.RS5, h.Flags.ToBytes()))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write flags: %w", err)
	}

	// Write cryptographic values
	n, err = w.w.Write(encoding.Encode(w.rs.RS16, h.Salt))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write salt: %w", err)
	}

	n, err = w.w.Write(encoding.Encode(w.rs.RS32, h.HKDFSalt))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write hkdf salt: %w", err)
	}

	n, err = w.w.Write(encoding.Encode(w.rs.RS16, h.SerpentIV))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write serpent iv: %w", err)
	}

	n, err = w.w.Write(encoding.Encode(w.rs.RS24, h.Nonce))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write nonce: %w", err)
	}

	// Write placeholders for authentication values (filled in after encryption)
	n, err = w.w.Write(make([]byte, KeyHashEncSize))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write key hash placeholder: %w", err)
	}

	n, err = w.w.Write(make([]byte, KeyfileHashEncSize))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write keyfile hash placeholder: %w", err)
	}

	n, err = w.w.Write(make([]byte, AuthTagEncSize))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write auth tag placeholder: %w", err)
	}

	return totalWritten, nil
}

// WriteAuthValues writes the authentication values to a seekable writer.
// This should be called after encryption is complete.
// offset is the position in the file where auth values begin (309 + comments*3 for v2.02)
func WriteAuthValues(w io.WriterAt, offset int64, keyHash, keyfileHash, authTag []byte, rs *encoding.RSCodecs) error {
	pos := offset

	// Write encoded key hash
	if _, err := w.WriteAt(encoding.Encode(rs.RS64, keyHash), pos); err != nil {
		return fmt.Errorf("write key hash: %w", err)
	}
	pos += KeyHashEncSize

	// Write encoded keyfile hash
	if _, err := w.WriteAt(encoding.Encode(rs.RS32, keyfileHash), pos); err != nil {
		return fmt.Errorf("write keyfile hash: %w", err)
	}
	pos += KeyfileHashEncSize

	// Write encoded auth tag
	if _, err := w.WriteAt(encoding.Encode(rs.RS64, authTag), pos); err != nil {
		return fmt.Errorf("write auth tag: %w", err)
	}

	return nil
}

// AuthValuesOffset calculates the file offset where auth values are stored
// Formula: version(15) + commentLen(15) + comments(len*3) + flags(15) +
//
//	salt(48) + hkdfSalt(96) + serpentIV(48) + nonce(72) = 309 + comments*3
func AuthValuesOffset(commentsLen int) int64 {
	return int64(VersionEncSize + CommentLenEncSize + commentsLen*3 + FlagsEncSize +
		SaltEncSize + HKDFSaltEncSize + SerpentIVEncSize + NonceEncSize)
}
