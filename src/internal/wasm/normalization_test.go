package wasm

import (
	"bytes"
	"testing"
)

// Built from explicit code points so the source literal cannot be silently
// re-normalized: nfdPassword is "é" decomposed (U+0065 U+0301), nfcPassword is
// the composed form (U+00E9). Same visible password, different bytes.
var (
	nfdPassword = string([]rune{0x0065, 0x0301})
	nfcPassword = string([]rune{0x00E9})
)

// TestWASMEncryptNormalizesPassword proves the web build normalizes the
// password to NFC on encrypt: a volume created with the decomposed form must
// decrypt with the composed form (#19). Without normalization the two forms
// derive different Argon2 keys and decryption fails with ErrWrongPassword.
func TestWASMEncryptNormalizesPassword(t *testing.T) {
	original := []byte("cross-platform web volume")
	var writerKDFInput []byte
	previousKDF := deriveWASMKey
	t.Cleanup(swapWASMTestKDF(func(password, salt []byte, paranoid bool) ([]byte, error) {
		writerKDFInput = bytes.Clone(password)
		return previousKDF(password, salt, paranoid)
	}))

	ciphertext, errCode := EncryptVolume(original, []byte(nfdPassword), EncryptOptions{})
	if errCode != 0 {
		t.Fatalf("encrypt failed with error code %d", errCode)
	}
	if !bytes.Equal(writerKDFInput, []byte{0xc3, 0xa9}) {
		t.Fatalf("writer KDF password = %x; want NFC UTF-8 c3a9", writerKDFInput)
	}

	res, errCode := DecryptVolume(ciphertext, []byte(nfcPassword), DecryptOptions{})
	if errCode != 0 {
		t.Fatalf("decrypt with composed form failed (code %d): encrypt did not normalize to NFC", errCode)
	}
	if !bytes.Equal(res.Plaintext, original) {
		t.Errorf("roundtrip mismatch\ngot:  %q\nwant: %q", res.Plaintext, original)
	}
}

// TestWASMDecryptTriesNormalizationForms proves the web decrypt path tries
// multiple password forms: a volume stored under the NFC form must also open
// when the user types the decomposed form (#19). Without decrypt-side try-both
// the decomposed form derives a different key and fails with ErrWrongPassword.
func TestWASMDecryptTriesNormalizationForms(t *testing.T) {
	cases := []struct {
		name    string
		encrypt string
		decrypt string
	}{
		{"NFC_encrypt_NFD_decrypt", nfcPassword, nfdPassword},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := []byte("web cross-form payload")
			ciphertext, errCode := EncryptVolume(original, []byte(tc.encrypt), EncryptOptions{})
			if errCode != 0 {
				t.Fatalf("encrypt failed with error code %d", errCode)
			}
			res, errCode := DecryptVolume(ciphertext, []byte(tc.decrypt), DecryptOptions{})
			if errCode != 0 {
				t.Fatalf("decrypt failed with error code %d (try-both not applied?)", errCode)
			}
			if !bytes.Equal(res.Plaintext, original) {
				t.Errorf("roundtrip mismatch\ngot:  %q\nwant: %q", res.Plaintext, original)
			}
		})
	}
}
