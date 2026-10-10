package mobile

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyDeniabilityWrongPasswordOffersRetryWithoutOutput(t *testing.T) {
	golden := filepath.Join("..", "testdata", "golden")
	fixture, err := os.ReadFile(filepath.Join(golden, "pico_test_v2_keyfile_only_deniable.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	input := filepath.Join(directory, "legacy.pcv")
	output := filepath.Join(directory, "plaintext")
	if err := os.WriteFile(input, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	request := &volume.DecryptRequest{
		InputFile: input, OutputFile: output, Password: []byte("incorrect public password"),
		Keyfiles:    []string{filepath.Join(golden, "keyfile_alpha.bin")},
		Deniability: true, RSCodecs: rs,
	}
	err = volume.Decrypt(context.Background(), request)
	if code := errorCode(err); code != "AUTH_FAILED" {
		t.Fatalf("legacy deniability error lost password retry: code=%s error=%v", code, err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != "legacy.pcv" {
		t.Fatalf("wrong password left output/staging: entries=%v error=%v", entries, readErr)
	}
	after, readErr := os.ReadFile(input)
	if readErr != nil || !bytes.Equal(after, fixture) {
		t.Fatalf("wrong password changed encrypted source: %v", readErr)
	}
	// An old keyfile-only deniable volume must still decrypt with its original
	// empty outer password and selected keyfile, rather than being retired.
	request.Password = nil
	if err := volume.Decrypt(context.Background(), request); err != nil {
		t.Fatalf("original legacy factors no longer decrypt: %v", err)
	}
	plaintext, err := os.ReadFile(output)
	if err != nil || string(plaintext) != "There is a test file for Picocrypt validation.\n" {
		t.Fatalf("legacy plaintext=%q error=%v", plaintext, err)
	}
}
