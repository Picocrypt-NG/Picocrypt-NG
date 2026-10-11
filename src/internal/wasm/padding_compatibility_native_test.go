//go:build !js

package wasm

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWASMDecryptsDesktopNonRSPaddedFlag(t *testing.T) {
	useProductionTestWASMKDF(t)
	plaintext := bytes.Repeat([]byte{0xA7}, util.MiB-1)
	password := []byte("desktop-unused-padding-flag")
	directory := t.TempDir()
	input := filepath.Join(directory, "input")
	output := filepath.Join(directory, "encrypted.pcv")
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	if err := volume.Encrypt(context.Background(), &volume.EncryptRequest{
		InputFile: input, OutputFile: output, Password: password, RSCodecs: rs,
	}); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := header.NewReader(bytes.NewReader(ciphertext), rs).ReadHeader()
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Header.Flags.Padded || parsed.Header.Flags.ReedSolomon {
		t.Fatal("desktop fixture must have the unused Padded flag without RS")
	}
	borrowed := bytes.Clone(ciphertext)
	result, code := DecryptVolume(ciphertext, password, DecryptOptions{})
	if code != 0 || !bytes.Equal(result.Plaintext, plaintext) || result.Kept {
		t.Fatalf("desktop non-RS volume: code=%d plaintext length=%d kept=%v", code, len(result.Plaintext), result.Kept)
	}
	if !bytes.Equal(ciphertext, borrowed) || !bytes.Equal(password, []byte("desktop-unused-padding-flag")) {
		t.Error("decryption changed caller-owned ciphertext or password")
	}
}
