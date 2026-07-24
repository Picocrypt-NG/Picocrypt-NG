package wasm

import (
	picoencoding "Picocrypt-NG/internal/encoding"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// Authored by the published pre-containment writer at
	// d03345f6b4d73d9279c968845a5f91e0a1246977 with password "test",
	// keyfile_alpha.bin, Reed-Solomon, and legacyWASMKeyfileRSPlaintext.
	legacyWASMKeyfileRSFixture = "pico_test_v2_keyfile_rs.pcv.b64"
	legacyWASMKeyfileRSSHA256  = "03dca9ea6793911282c780f3c734897a06cc794726fc398d5dee60cf3ea09e29"
	wasmGoldenPlaintext        = "There is a test file for Picocrypt validation.\n"
)

func readWASMGoldenFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden fixture %s: %v", name, err)
	}
	return data
}

func readWASMLegacyKeyfileRSFixture(t *testing.T) []byte {
	t.Helper()

	encoded := readWASMGoldenFixture(t, legacyWASMKeyfileRSFixture)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode golden fixture %s: %v", legacyWASMKeyfileRSFixture, err)
	}
	sum := sha256.Sum256(decoded)
	if got := hex.EncodeToString(sum[:]); got != legacyWASMKeyfileRSSHA256 {
		t.Fatalf(
			"decoded %s SHA-256 = %s, want %s",
			legacyWASMKeyfileRSFixture,
			got,
			legacyWASMKeyfileRSSHA256,
		)
	}
	if len(decoded) != 1469 {
		t.Fatalf("decoded %s length = %d, want 1469", legacyWASMKeyfileRSFixture, len(decoded))
	}
	return decoded
}

func legacyWASMKeyfileRSPlaintext() []byte {
	plaintext := make([]byte, 4*picoencoding.RS128DataSize)
	for i := range plaintext {
		plaintext[i] = byte(i*13 + 7)
	}
	return plaintext
}
