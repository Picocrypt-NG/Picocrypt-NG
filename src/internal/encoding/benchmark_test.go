package encoding

import (
	"testing"
)

var codecs *RSCodecs

func init() {
	var err error
	codecs, err = NewRSCodecs()
	if err != nil {
		panic(err)
	}
}

// BenchmarkPad measures PKCS#7 padding performance.
func BenchmarkPad(b *testing.B) {
	data := make([]byte, 100) // Typical partial chunk size
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Pad(data)
	}
}

// BenchmarkUnpad measures PKCS#7 unpadding performance.
func BenchmarkUnpad(b *testing.B) {
	data := Pad(make([]byte, 100))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Unpad(data)
	}
}

// BenchmarkRS128Encode measures RS128 encoding performance (per 128-byte block).
func BenchmarkRS128Encode(b *testing.B) {
	data := make([]byte, RS128DataSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Encode(codecs.RS128, data)
	}
}

// BenchmarkRS128DecodeFast measures RS128 fast decoding (no error correction).
func BenchmarkRS128DecodeFast(b *testing.B) {
	data := Encode(codecs.RS128, make([]byte, RS128DataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(codecs.RS128, data, true)
	}
}

// BenchmarkRS128DecodeFull measures RS128 full decoding (with error correction).
func BenchmarkRS128DecodeFull(b *testing.B) {
	data := Encode(codecs.RS128, make([]byte, RS128DataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(codecs.RS128, data, false)
	}
}

// BenchmarkRS5Encode measures RS5 encoding (used for header fields).
func BenchmarkRS5Encode(b *testing.B) {
	data := make([]byte, 5) // Version, flags, etc.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Encode(codecs.RS5, data)
	}
}

// BenchmarkRS5Decode measures RS5 decoding.
func BenchmarkRS5Decode(b *testing.B) {
	data := Encode(codecs.RS5, make([]byte, 5))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(codecs.RS5, data, false)
	}
}

// BenchmarkRS1MiBEncode measures encoding a full 1 MiB block (typical chunk size).
func BenchmarkRS1MiBEncode(b *testing.B) {
	const MiB = 1 << 20
	data := make([]byte, MiB)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result []byte
		for j := 0; j < MiB; j += RS128DataSize {
			result = append(result, Encode(codecs.RS128, data[j:j+RS128DataSize])...)
		}
		_ = result
	}
}

// BenchmarkRS1MiBDecodeFast measures fast decoding a full 1 MiB RS-encoded block.
func BenchmarkRS1MiBDecodeFast(b *testing.B) {
	const MiB = 1 << 20
	// Create RS-encoded 1 MiB block
	data := make([]byte, MiB)
	var encoded []byte
	for j := 0; j < MiB; j += RS128DataSize {
		encoded = append(encoded, Encode(codecs.RS128, data[j:j+RS128DataSize])...)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result []byte
		for j := 0; j < len(encoded); j += RS128EncodedSize {
			decoded, _ := Decode(codecs.RS128, encoded[j:j+RS128EncodedSize], true)
			result = append(result, decoded...)
		}
		_ = result
	}
}
