package encoding

import (
	"bytes"
	"testing"
)

func TestPadUnpad(t *testing.T) {
	// Test various data sizes
	for size := 1; size <= 128; size++ {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		padded := Pad(data)

		// Padded data should be a multiple of BlockSize
		if len(padded)%BlockSize != 0 {
			t.Errorf("Pad(%d bytes) = %d bytes; want multiple of %d", size, len(padded), BlockSize)
		}

		// For data that's exactly BlockSize, padding adds another full block
		if size == BlockSize && len(padded) != 2*BlockSize {
			t.Errorf("Pad(%d bytes) = %d bytes; want %d", size, len(padded), 2*BlockSize)
		}

		// Unpad should recover original data (for sizes < BlockSize)
		if size < BlockSize {
			unpadded := Unpad(padded)
			if !bytes.Equal(unpadded, data) {
				t.Errorf("Unpad(Pad(%d bytes)) did not recover original data", size)
			}
		}
	}
}

func TestPadUnpadRoundtrip(t *testing.T) {
	// Test specific edge cases
	testCases := [][]byte{
		{0x01},                          // 1 byte
		{0x01, 0x02, 0x03},              // 3 bytes
		bytes.Repeat([]byte{0xAB}, 127), // 127 bytes (just under block)
		bytes.Repeat([]byte{0xCD}, 64),  // 64 bytes (half block)
	}

	for i, data := range testCases {
		padded := Pad(data)
		// Take only the first BlockSize bytes for unpadding (simulates RS decode)
		unpadded := Unpad(padded[:BlockSize])

		if !bytes.Equal(unpadded, data) {
			t.Errorf("Test case %d: roundtrip failed for %d bytes", i, len(data))
		}
	}
}

func TestUnpadInvalidData(t *testing.T) {
	// Empty data should return empty
	result := Unpad([]byte{})
	if len(result) != 0 {
		t.Errorf("Unpad(empty) should return empty, got %d bytes", len(result))
	}

	// Short data (< 128 bytes) should return unchanged without panic
	shortData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	result = Unpad(shortData)
	if !bytes.Equal(result, shortData) {
		t.Errorf("Unpad(short) should return data unchanged, got %v", result)
	}

	// 127-byte data should return unchanged (just under BlockSize)
	almostFull := make([]byte, 127)
	for i := range almostFull {
		almostFull[i] = byte(i)
	}
	result = Unpad(almostFull)
	if !bytes.Equal(result, almostFull) {
		t.Errorf("Unpad(127 bytes) should return data unchanged")
	}

	// Single byte should not panic
	result = Unpad([]byte{0xFF})
	if !bytes.Equal(result, []byte{0xFF}) {
		t.Errorf("Unpad(1 byte) should return data unchanged")
	}
}
