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
// Example: Encode(rs128, 128-byte-data) -> 136 bytes with 8 parity bytes.
func Encode(rs *infectious.FEC, data []byte) []byte {
	res := make([]byte, rs.Total())
	if err := rs.Encode(data, func(s infectious.Share) {
		res[s.Number] = s.Data[0]
	}); err != nil {
		// This should never happen with correct input size
		panic("rs.Encode failed: " + err.Error())
	}
	return res
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
	// Fast decode optimization: skip RS decoding for payload data
	if rs.Total() == 136 && fastDecode {
		return data[:128], nil
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
			return data[:128], err
		}
		return data[:rs.Total()/3], err
	}

	// No issues, return the decoded data
	return res, nil
}
