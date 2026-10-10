package wasm

import (
	picoencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
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

func TestWASMLegacyV2AuthenticatesHeaderBeforeKeyfileErrors(t *testing.T) {
	useProductionTestWASMKDF(t)
	fixture := readWASMGoldenFixture(t, "pico_test_v2_keyfile_single.txt.pcv")
	keyfile := readWASMGoldenFixture(t, "keyfile_alpha.bin")
	rs, err := picoencoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	modifiedHash := bytes.Clone(fixture)
	hdr := readHeaderForTest(t, fixture)
	hashBytes := bytes.Clone(hdr.KeyfileHash)
	hashBytes[0] ^= 1
	encoded, err := picoencoding.Encode(rs.RS32, hashBytes)
	if err != nil {
		t.Fatal(err)
	}
	hashOffset := header.HeaderSize(len(hdr.Comments)) - header.AuthTagEncSize - header.KeyfileHashEncSize
	copy(modifiedHash[hashOffset:hashOffset+header.KeyfileHashEncSize], encoded)

	for _, test := range []struct {
		name     string
		volume   []byte
		password string
		keyfiles [][]byte
		code     int
	}{
		{"wrong password missing keyfile", fixture, "wrong public password", nil, ErrWrongPassword},
		{"wrong password incorrect keyfile", fixture, "wrong public password", [][]byte{[]byte("incorrect public factor")}, ErrWrongPassword},
		{"modified public keyfile hash", modifiedHash, "test", [][]byte{keyfile}, ErrWrongPassword},
		{"authenticated missing keyfile", fixture, "test", nil, ErrKeyfilesRequired},
		{"authenticated incorrect keyfile", fixture, "test", [][]byte{[]byte("incorrect public factor")}, ErrKeyfilesIncorrect},
		{"authenticated correct keyfile", fixture, "test", [][]byte{keyfile}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := bytes.Clone(test.volume)
			result, code := DecryptVolume(test.volume, []byte(test.password), DecryptOptions{Keyfiles: test.keyfiles})
			if code != test.code {
				t.Fatalf("code=%d; want %d", code, test.code)
			}
			if code == 0 {
				if result.Kept || string(result.Plaintext) != wasmGoldenPlaintext {
					t.Fatalf("frozen legacy plaintext changed: kept=%v plaintext=%q", result.Kept, result.Plaintext)
				}
			} else if result.Plaintext != nil || result.Kept {
				t.Fatalf("failed header/factor check returned plaintext: kept=%v bytes=%d", result.Kept, len(result.Plaintext))
			}
			if !bytes.Equal(test.volume, original) {
				t.Fatal("header/factor check changed caller-owned ciphertext")
			}
		})
	}
}
