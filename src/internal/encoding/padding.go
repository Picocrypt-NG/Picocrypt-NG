package encoding

import "bytes"

// BlockSize is the chunk size for RS128 encoding and PKCS#7 padding.
// Reed-Solomon RS128 operates on 128-byte data blocks, producing 136-byte encoded blocks.
const BlockSize = 128

// Pad applies PKCS#7 padding to ensure data fills a complete 128-byte block.
//
// PKCS#7 padding works by appending N bytes, each with value N, where N is the
// number of bytes needed to reach BlockSize. If data is already a multiple of
// BlockSize, a full block of padding (128 bytes of 0x80) is added.
//
// This is required when the final payload chunk is smaller than 128 bytes,
// so it can be properly RS128-encoded.
//
// Example: 100-byte data -> 128 bytes (28 bytes of value 0x1C appended)
func Pad(data []byte) []byte {
	padLen := BlockSize - len(data)%BlockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// Unpad removes PKCS#7 padding from a 128-byte block.
//
// The padding length is determined by the value of the last byte:
// if last byte is 0x05, remove the last 5 bytes.
//
// Returns original data unchanged if:
//   - Data is empty or shorter than BlockSize (128 bytes)
//   - Padding value is invalid (> 128 or 0)
//
// This graceful handling prevents crashes on corrupted data.
func Unpad(data []byte) []byte {
	if len(data) < BlockSize {
		return data // Too short to be a valid padded block
	}
	padLen := int(data[BlockSize-1])
	if padLen > BlockSize || padLen == 0 {
		return data // Invalid padding, return as-is
	}
	return data[:BlockSize-padLen]
}
