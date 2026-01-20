package encoding

import (
	"bytes"
	"testing"
)

func TestNewRSCodecs(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Verify all codecs were initialized
	if codecs.RS1 == nil || codecs.RS5 == nil || codecs.RS16 == nil ||
		codecs.RS24 == nil || codecs.RS32 == nil || codecs.RS64 == nil ||
		codecs.RS128 == nil {
		t.Fatal("NewRSCodecs() returned nil codec(s)")
	}

	// Verify codec parameters
	if codecs.RS1.Required() != 1 || codecs.RS1.Total() != 3 {
		t.Errorf("RS1: got Required=%d, Total=%d; want 1, 3", codecs.RS1.Required(), codecs.RS1.Total())
	}
	if codecs.RS5.Required() != 5 || codecs.RS5.Total() != 15 {
		t.Errorf("RS5: got Required=%d, Total=%d; want 5, 15", codecs.RS5.Required(), codecs.RS5.Total())
	}
	if codecs.RS16.Required() != 16 || codecs.RS16.Total() != 48 {
		t.Errorf("RS16: got Required=%d, Total=%d; want 16, 48", codecs.RS16.Required(), codecs.RS16.Total())
	}
	if codecs.RS24.Required() != 24 || codecs.RS24.Total() != 72 {
		t.Errorf("RS24: got Required=%d, Total=%d; want 24, 72", codecs.RS24.Required(), codecs.RS24.Total())
	}
	if codecs.RS32.Required() != 32 || codecs.RS32.Total() != 96 {
		t.Errorf("RS32: got Required=%d, Total=%d; want 32, 96", codecs.RS32.Required(), codecs.RS32.Total())
	}
	if codecs.RS64.Required() != 64 || codecs.RS64.Total() != 192 {
		t.Errorf("RS64: got Required=%d, Total=%d; want 64, 192", codecs.RS64.Required(), codecs.RS64.Total())
	}
	if codecs.RS128.Required() != 128 || codecs.RS128.Total() != 136 {
		t.Errorf("RS128: got Required=%d, Total=%d; want 128, 136", codecs.RS128.Required(), codecs.RS128.Total())
	}
}

func TestRSEncodeDecodeRS128(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Test RS128 specifically (most commonly used for payload)
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}

	// Encode
	encoded := Encode(codecs.RS128, data)
	if len(encoded) != 136 {
		t.Errorf("Encode(RS128) length = %d; want 136", len(encoded))
	}

	// Decode with fastDecode=false (full decode)
	decoded, err := Decode(codecs.RS128, encoded, false)
	if err != nil {
		t.Fatalf("Decode(RS128) failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Error("Decode(RS128) did not recover original data")
	}

	// Decode with fastDecode=true (skip RS, just return first 128 bytes)
	decoded, err = Decode(codecs.RS128, encoded, true)
	if err != nil {
		t.Fatalf("Decode(RS128, fastDecode=true) failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Error("Decode(RS128, fastDecode=true) did not recover original data")
	}
}

func TestRSEncodeDecodeRS5(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Test RS5 (used for version, flags, etc.)
	data := []byte("v2.00")

	// Encode
	encoded := Encode(codecs.RS5, data)
	if len(encoded) != 15 {
		t.Errorf("Encode(RS5) length = %d; want 15", len(encoded))
	}

	// Decode
	decoded, err := Decode(codecs.RS5, encoded, false)
	if err != nil {
		t.Fatalf("Decode(RS5) failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Decode(RS5) = %q; want %q", decoded, data)
	}
}

func TestRSEncodeDecodeRS1(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Test RS1 (used for comment symbols)
	data := []byte("A")

	// Encode
	encoded := Encode(codecs.RS1, data)
	if len(encoded) != 3 {
		t.Errorf("Encode(RS1) length = %d; want 3", len(encoded))
	}

	// Decode
	decoded, err := Decode(codecs.RS1, encoded, false)
	if err != nil {
		t.Fatalf("Decode(RS1) failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Decode(RS1) = %q; want %q", decoded, data)
	}
}

func TestRSErrorCorrection(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Test error correction capability of RS5
	data := []byte("v2.00")
	encoded := Encode(codecs.RS5, data)

	// Corrupt some bytes (RS5 can correct up to 5 errors since total=15, required=5)
	corrupted := make([]byte, len(encoded))
	copy(corrupted, encoded)
	corrupted[0] ^= 0xFF // Flip bits in first byte
	corrupted[1] ^= 0xFF // Flip bits in second byte

	// Should still decode correctly
	decoded, err := Decode(codecs.RS5, corrupted, false)
	if err != nil {
		t.Fatalf("Decode(RS5) with errors failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Decode(RS5) with errors = %q; want %q", decoded, data)
	}
}

func TestRSAllCodecsRoundtrip(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	testCases := []struct {
		name  string
		codec interface {
			Required() int
			Total() int
		}
		dataSize int
	}{
		{"RS1", codecs.RS1, 1},
		{"RS5", codecs.RS5, 5},
		{"RS16", codecs.RS16, 16},
		{"RS24", codecs.RS24, 24},
		{"RS32", codecs.RS32, 32},
		{"RS64", codecs.RS64, 64},
		{"RS128", codecs.RS128, 128},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test data
			data := make([]byte, tc.dataSize)
			for i := range data {
				data[i] = byte((i * 37) % 256) // Use a pattern
			}

			// Get the actual FEC codec using type assertion
			var encoded []byte
			var decoded []byte
			var decErr error

			switch tc.name {
			case "RS1":
				encoded = Encode(codecs.RS1, data)
				decoded, decErr = Decode(codecs.RS1, encoded, false)
			case "RS5":
				encoded = Encode(codecs.RS5, data)
				decoded, decErr = Decode(codecs.RS5, encoded, false)
			case "RS16":
				encoded = Encode(codecs.RS16, data)
				decoded, decErr = Decode(codecs.RS16, encoded, false)
			case "RS24":
				encoded = Encode(codecs.RS24, data)
				decoded, decErr = Decode(codecs.RS24, encoded, false)
			case "RS32":
				encoded = Encode(codecs.RS32, data)
				decoded, decErr = Decode(codecs.RS32, encoded, false)
			case "RS64":
				encoded = Encode(codecs.RS64, data)
				decoded, decErr = Decode(codecs.RS64, encoded, false)
			case "RS128":
				encoded = Encode(codecs.RS128, data)
				decoded, decErr = Decode(codecs.RS128, encoded, false)
			}

			if decErr != nil {
				t.Fatalf("Decode failed: %v", decErr)
			}

			// Check encoded length
			if len(encoded) != tc.codec.Total() {
				t.Errorf("Encoded length = %d; want %d", len(encoded), tc.codec.Total())
			}

			// Check decoded data matches original
			if !bytes.Equal(decoded, data) {
				t.Error("Decoded data does not match original")
			}
		})
	}
}
