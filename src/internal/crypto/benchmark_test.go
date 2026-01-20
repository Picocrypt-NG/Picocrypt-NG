package crypto

import (
	"testing"

	"golang.org/x/crypto/chacha20"
)

// BenchmarkDeriveKeyNormal measures Argon2id key derivation in normal mode.
// This is intentionally slow (~1 second) for security.
func BenchmarkDeriveKeyNormal(b *testing.B) {
	password := []byte("test-password-123")
	salt := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeriveKey(password, salt, false)
	}
}

// BenchmarkDeriveKeyParanoid measures Argon2id key derivation in paranoid mode.
// This is intentionally slower (~2 seconds) for enhanced security.
func BenchmarkDeriveKeyParanoid(b *testing.B) {
	password := []byte("test-password-123")
	salt := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeriveKey(password, salt, true)
	}
}

// BenchmarkNewMAC_BLAKE2b measures BLAKE2b-512 MAC initialization.
func BenchmarkNewMAC_BLAKE2b(b *testing.B) {
	subkey := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewMAC(subkey, false)
	}
}

// BenchmarkNewMAC_HMACSHA3 measures HMAC-SHA3-512 MAC initialization.
func BenchmarkNewMAC_HMACSHA3(b *testing.B) {
	subkey := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewMAC(subkey, true)
	}
}

// BenchmarkMACWrite_BLAKE2b measures BLAKE2b-512 data processing.
func BenchmarkMACWrite_BLAKE2b(b *testing.B) {
	subkey := make([]byte, 32)
	mac, _ := NewMAC(subkey, false)
	data := make([]byte, 1<<20) // 1 MiB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		mac.Reset()
		mac.Write(data)
		_ = mac.Sum(nil)
	}
}

// BenchmarkMACWrite_HMACSHA3 measures HMAC-SHA3-512 data processing.
func BenchmarkMACWrite_HMACSHA3(b *testing.B) {
	subkey := make([]byte, 32)
	mac, _ := NewMAC(subkey, true)
	data := make([]byte, 1<<20) // 1 MiB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		mac.Reset()
		mac.Write(data)
		_ = mac.Sum(nil)
	}
}

// BenchmarkXChaCha20 measures XChaCha20 encryption throughput.
func BenchmarkXChaCha20(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	cipher, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	data := make([]byte, 1<<20) // 1 MiB
	dst := make([]byte, len(data))

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		cipher.XORKeyStream(dst, data)
	}
}

// BenchmarkSecureZero measures secure memory zeroing performance.
func BenchmarkSecureZero(b *testing.B) {
	data := make([]byte, 32) // Typical key size

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SecureZero(data)
	}
}

// BenchmarkSecureZeroLarge measures secure zeroing of larger buffers.
func BenchmarkSecureZeroLarge(b *testing.B) {
	data := make([]byte, 1<<20) // 1 MiB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		SecureZero(data)
	}
}

// BenchmarkDeniabilityRekey measures deniability rekeying performance.
func BenchmarkDeniabilityRekey(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = DeniabilityRekey(key, nonce)
	}
}
