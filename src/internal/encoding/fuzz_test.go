package encoding

import (
	"testing"
)

// FuzzUnpad tests Unpad with arbitrary input to ensure it never panics.
// Run with: go test -fuzz=FuzzUnpad -fuzztime=30s
func FuzzUnpad(f *testing.F) {
	// Seed corpus with interesting cases
	f.Add([]byte{})                       // empty
	f.Add([]byte{0x01})                   // single byte
	f.Add(make([]byte, 127))              // just under BlockSize
	f.Add(make([]byte, 128))              // exactly BlockSize
	f.Add(make([]byte, 129))              // just over BlockSize
	f.Add([]byte{0x00, 0x00, 0x00, 0x00}) // zeros
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // max bytes
	f.Add(Pad([]byte("test data")))       // valid padded data

	f.Fuzz(func(t *testing.T, data []byte) {
		// Unpad should never panic regardless of input
		result := Unpad(data)

		// Result should not be longer than input
		if len(result) > len(data) {
			t.Errorf("Unpad produced longer output: input=%d, output=%d", len(data), len(result))
		}
	})
}

// FuzzPad tests Pad with arbitrary input to ensure it produces valid output.
// Run with: go test -fuzz=FuzzPad -fuzztime=30s
func FuzzPad(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 127))
	f.Add(make([]byte, 128))

	f.Fuzz(func(t *testing.T, data []byte) {
		padded := Pad(data)

		// Padded output must be multiple of BlockSize
		if len(padded)%BlockSize != 0 {
			t.Errorf("Pad output not multiple of BlockSize: len=%d", len(padded))
		}

		// Padded output must be at least BlockSize
		if len(padded) < BlockSize {
			t.Errorf("Pad output too short: len=%d", len(padded))
		}

		// Padded output must be longer than or equal to input
		if len(padded) < len(data) {
			t.Errorf("Pad output shorter than input: input=%d, output=%d", len(data), len(padded))
		}
	})
}

// FuzzRSEncodeDecode tests RS128 encode/decode roundtrip with arbitrary valid input.
// Run with: go test -fuzz=FuzzRSEncodeDecode -fuzztime=30s
func FuzzRSEncodeDecode(f *testing.F) {
	// Seed with 128-byte blocks (RS128 input size)
	f.Add(make([]byte, 128))
	f.Add([]byte("This is exactly 128 bytes of test data for Reed-Solomon encoding and decoding verification purposes!!!!"))

	codecs, err := NewRSCodecs()
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// RS128 requires exactly 128 bytes
		if len(data) != 128 {
			t.Skip("RS128 requires exactly 128 bytes")
		}

		// Encode
		encoded := Encode(codecs.RS128, data)
		if len(encoded) != 136 {
			t.Errorf("Encoded length wrong: got %d, want 136", len(encoded))
		}

		// Decode (fast mode)
		decoded, err := Decode(codecs.RS128, encoded, true)
		if err != nil {
			t.Errorf("Fast decode failed: %v", err)
		}
		if string(decoded) != string(data) {
			t.Error("Fast decode produced different data")
		}

		// Decode (full mode)
		decoded, err = Decode(codecs.RS128, encoded, false)
		if err != nil {
			t.Errorf("Full decode failed: %v", err)
		}
		if string(decoded) != string(data) {
			t.Error("Full decode produced different data")
		}
	})
}
