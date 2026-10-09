// Package encoding provides Reed-Solomon error correction and PKCS#7 padding for Picocrypt volumes.
//
// Reed-Solomon encoding provides forward error correction, allowing the recovery
// of corrupted data without retransmission. Picocrypt uses multiple RS configurations:
//
//   - RS1 (1->3):   For individual comment characters (highest redundancy)
//   - RS5 (5->15):  For version string, comment length, and flags
//   - RS16 (16->48): For Argon2 salt and Serpent IV
//   - RS24 (24->72): For XChaCha20 nonce
//   - RS32 (32->96): For HKDF salt and keyfile hash
//   - RS64 (64->192): For key hash and authentication tag
//   - RS128 (128->136): For payload data (minimal overhead for bulk data)
//
// The encoding ratio determines fault tolerance: RS128 can correct up to 4 byte
// errors per 136-byte block, while RS1 can survive 1 error per 3-byte block.
package encoding

import (
	"errors"
	"fmt"

	"github.com/Picocrypt/infectious"
)

// Reed-Solomon chunk sizes for payload data (RS128)
const (
	RS128DataSize    = 128 // Input chunk size for RS128
	RS128EncodedSize = 136 // Output chunk size for RS128 (128 + 8 parity)
)

// RSCodecs holds pre-initialized Reed-Solomon Forward Error Correction (FEC) codecs.
// All codecs are created once at startup and reused throughout the application lifetime.
//
// The naming convention RSn means n data bytes are encoded into n*3 total bytes
// (except RS128 which uses n->n+8 for efficiency on bulk payload data).
type RSCodecs struct {
	RS1   *infectious.FEC // 1 data -> 3 total bytes (66% redundancy) - comment symbols
	RS5   *infectious.FEC // 5 data -> 15 total bytes - version, comment length, flags
	RS16  *infectious.FEC // 16 data -> 48 total bytes - Argon2 salt, Serpent IV
	RS24  *infectious.FEC // 24 data -> 72 total bytes - XChaCha20 nonce
	RS32  *infectious.FEC // 32 data -> 96 total bytes - HKDF salt, keyfile hash
	RS64  *infectious.FEC // 64 data -> 192 total bytes - key hash, auth tag
	RS128 *infectious.FEC // 128 data -> 136 total bytes (6% overhead) - payload chunks
}

// NewRSCodecs initializes all Reed-Solomon codecs.
// Returns an error if any codec fails to initialize.
func NewRSCodecs() (*RSCodecs, error) {
	rs1, err1 := infectious.NewFEC(1, 3)
	rs5, err2 := infectious.NewFEC(5, 15)
	rs16, err3 := infectious.NewFEC(16, 48)
	rs24, err4 := infectious.NewFEC(24, 72)
	rs32, err5 := infectious.NewFEC(32, 96)
	rs64, err6 := infectious.NewFEC(64, 192)
	rs128, err7 := infectious.NewFEC(128, 136)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil ||
		err5 != nil || err6 != nil || err7 != nil {
		return nil, errors.New("failed to initialize Reed-Solomon codecs")
	}

	return &RSCodecs{
		RS1:   rs1,
		RS5:   rs5,
		RS16:  rs16,
		RS24:  rs24,
		RS32:  rs32,
		RS64:  rs64,
		RS128: rs128,
	}, nil
}

// Encode applies Reed-Solomon encoding to data using the specified codec.
// The input data length must match the codec's Required() size.
// Returns encoded data with parity bytes appended (length = codec.Total()).
//
// Precondition: len(data) must equal rs.Required(); otherwise a non-nil error
// is returned (never panics). The exact-size check is required because the
// res[s.Number] = s.Data[0] callback assumes a single block (block_size == 1):
// a wrong-but-multiple-of-k size (e.g. 256 for RS128) would pass infectious's
// own len%k check yet misalign the result, so relying on rs.Encode's error
// alone is insufficient.
//
// Example: Encode(rs128, 128-byte-data) -> 136 bytes with 8 parity bytes.
func Encode(rs *infectious.FEC, data []byte) ([]byte, error) {
	res := make([]byte, rs.Total())
	if err := EncodeInto(res, rs, data); err != nil {
		return nil, err
	}
	return res, nil
}

// EncodeInto is the allocation-free form of Encode: it writes the codec.Total()
// output bytes directly into dst instead of returning a fresh slice. It is for
// hot loops (the RS128 payload encoder) that already own an output buffer.
//
// dst must have length exactly rs.Total(); data must have length exactly
// rs.Required(). The output bytes are identical to Encode's. Preconditions are
// checked and return a non-nil error (never panic).
func EncodeInto(dst []byte, rs *infectious.FEC, data []byte) error {
	if len(data) != rs.Required() {
		return fmt.Errorf("rs encode: input size %d != required %d", len(data), rs.Required())
	}
	if len(dst) != rs.Total() {
		return fmt.Errorf("rs encode: dst size %d != total %d", len(dst), rs.Total())
	}
	if err := rs.Encode(data, func(s infectious.Share) {
		dst[s.Number] = s.Data[0]
	}); err != nil {
		return fmt.Errorf("rs encode: %w", err)
	}
	return nil
}

// ErrCorruptData is returned by DecodeRSPayloadBlock when a block has more
// errors than Reed-Solomon can correct and forceDecode is false. Callers in the
// volume layer translate this to perrors.ErrCorruptData to preserve errors.Is
// behavior; encoding stays free of the app error layer.
var ErrCorruptData = errors.New("rs payload: data corrupted")

// RSEncodedBlockSize is the on-disk byte size of one Reed-Solomon-encoded 1 MiB
// payload block: each 128-byte (RS128DataSize) chunk encodes to 136 bytes
// (RS128EncodedSize), so a 1 MiB block expands to 1,114,112 bytes. The 1<<20 is
// util.MiB inlined (encoding must not import util). Untyped const: byte-identical
// in int and int64 contexts, keeping the write format frozen.
const RSEncodedBlockSize = (1 << 20) / RS128DataSize * RS128EncodedSize

// EncodeRSPayloadBlock RS128-encodes one already-encrypted payload block (<= 1 MiB).
// For partial blocks (< 1 MiB) it ALWAYS appends one PKCS#7-padded chunk, even when
// the data is a multiple of 128, because decode ALWAYS unpads the last chunk of a
// partial block. Output is byte-identical to the original desktop encoder.
func EncodeRSPayloadBlock(data []byte, rs *RSCodecs) ([]byte, error) {
	const miB = 1 << 20
	chunks := (len(data) + RS128DataSize - 1) / RS128DataSize
	if len(data) < miB {
		chunks++ // extra chunk for padding in partial blocks
	}
	result := make([]byte, 0, chunks*RS128EncodedSize)

	encodeChunk := func(chunk []byte) error {
		start := len(result)
		result = result[:start+RS128EncodedSize]
		return EncodeInto(result[start:], rs.RS128, chunk)
	}

	if len(data) == miB {
		for i := 0; i < miB; i += RS128DataSize {
			if err := encodeChunk(data[i : i+RS128DataSize]); err != nil {
				return nil, err
			}
		}
		return result, nil
	}

	fullChunks := len(data) / RS128DataSize
	for i := range fullChunks {
		if err := encodeChunk(data[i*RS128DataSize : (i+1)*RS128DataSize]); err != nil {
			return nil, err
		}
	}
	remaining := data[fullChunks*RS128DataSize:]
	if err := encodeChunk(Pad(remaining)); err != nil {
		return nil, err
	}
	return result, nil
}

// DecodeRSPayloadBlock decodes one RS128-encoded payload block. fastDecode=true
// strips parity without correction (fast path); false applies full RS correction.
// forceDecode=true returns raw bytes on uncorrectable input (desktop ForceDecrypt);
// false returns ErrCorruptData. isLast+padded control unpadding of the final chunk.
func DecodeRSPayloadBlock(data []byte, rs *RSCodecs, isLast, padded, forceDecode, fastDecode bool) ([]byte, error) {
	if !forceDecode && len(data)%RS128EncodedSize != 0 {
		return nil, ErrCorruptData
	}
	result := make([]byte, 0, len(data)/RS128EncodedSize*RS128DataSize)
	fullBlockEncodedSize := RSEncodedBlockSize

	if len(data) == fullBlockEncodedSize {
		for i := 0; i < fullBlockEncodedSize; i += RS128EncodedSize {
			decoded, err := Decode(rs.RS128, data[i:i+RS128EncodedSize], fastDecode)
			if err != nil {
				if forceDecode {
					decoded = data[i : i+RS128DataSize]
				} else {
					return nil, ErrCorruptData
				}
			}
			if isLast && i == fullBlockEncodedSize-RS128EncodedSize && padded {
				decoded = Unpad(decoded)
			}
			result = append(result, decoded...)
		}
	} else {
		if len(data) < RS128EncodedSize {
			if forceDecode {
				return data, nil
			}
			return nil, ErrCorruptData
		}
		chunks := len(data)/RS128EncodedSize - 1
		for i := range chunks {
			decoded, err := Decode(rs.RS128, data[i*RS128EncodedSize:(i+1)*RS128EncodedSize], fastDecode)
			if err != nil {
				if forceDecode {
					decoded = data[i*RS128EncodedSize : i*RS128EncodedSize+RS128DataSize]
				} else {
					return nil, ErrCorruptData
				}
			}
			result = append(result, decoded...)
		}
		lastChunkStart := chunks * RS128EncodedSize
		lastChunkEnd := min(lastChunkStart+RS128EncodedSize, len(data))
		decoded, err := Decode(rs.RS128, data[lastChunkStart:lastChunkEnd], fastDecode)
		if err != nil {
			if forceDecode {
				safeEnd := min(lastChunkStart+RS128DataSize, len(data))
				decoded = data[lastChunkStart:safeEnd]
			} else {
				return nil, ErrCorruptData
			}
		}
		result = append(result, Unpad(decoded)...)
	}
	return result, nil
}

// Decode attempts to decode and repair Reed-Solomon encoded data.
//
// Parameters:
//   - rs: The Reed-Solomon codec matching the one used for encoding
//   - data: Encoded data (length must match codec.Total())
//   - fastDecode: If true AND codec is RS128, skip error correction for speed
//
// The fastDecode optimization is critical for performance: during initial decryption,
// we assume no errors and skip RS processing. If MAC verification fails at the end,
// we retry with fastDecode=false to attempt error correction.
//
// Returns:
//   - Decoded data (original bytes without parity)
//   - Error if too many bytes are corrupted to recover (returns partial data anyway)
func Decode(rs *infectious.FEC, data []byte, fastDecode bool) ([]byte, error) {
	// Precondition: input must be exactly codec.Total() bytes; otherwise the
	// share loop and the data[:128]/data[:Total()/3] slices below would panic
	// on attacker-controlled .pcv input. Mirrors the Encode precondition.
	if len(data) != rs.Total() {
		return nil, fmt.Errorf("rs decode: input size %d != total %d", len(data), rs.Total())
	}

	// Fast decode optimization: skip RS decoding for payload data
	if rs.Total() == 136 && fastDecode {
		return data[:128], nil //nolint:gosec // G602: len(data)==rs.Total() guaranteed by precondition above; 128<=Total
	}

	tmp := make([]infectious.Share, rs.Total())
	for i := range rs.Total() {
		tmp[i].Number = i
		tmp[i].Data = append(tmp[i].Data, data[i])
	}
	res, err := rs.Decode(nil, tmp)
	// Force decode the data but return the error as well
	if err != nil {
		if rs.Total() == 136 {
			return data[:128], err //nolint:gosec // G602: len(data)==rs.Total() guaranteed by precondition above; 128<=Total
		}
		return data[:rs.Total()/3], err
	}

	// No issues, return the decoded data
	return res, nil
}
