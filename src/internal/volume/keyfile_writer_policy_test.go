package volume

import (
	cryptorand "crypto/rand"
	"os"
	"path/filepath"
	"testing"

	perrors "Picocrypt-NG/internal/errors"
)

type countingZeroKeyfileWriterReader struct {
	reads int
}

func (r *countingZeroKeyfileWriterReader) Read(p []byte) (int, error) {
	r.reads++
	clear(p)
	return len(p), nil
}

func TestEncryptRejectsAllNewV2KeyfileWritesBeforeWork(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	keyfile := filepath.Join(dir, "factor.key")
	if err := os.WriteFile(input, []byte("plaintext"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := os.WriteFile(keyfile, []byte("keyfile material"), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}

	originalReader := cryptorand.Reader
	randomReader := &countingZeroKeyfileWriterReader{}
	cryptorand.Reader = randomReader
	t.Cleanup(func() {
		cryptorand.Reader = originalReader
	})

	previousVolumeKey := deriveVolumeKey
	deriveCalls := 0
	deriveVolumeKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		deriveCalls++
		return previousVolumeKey(password, salt, paranoid)
	}
	t.Cleanup(func() {
		deriveVolumeKey = previousVolumeKey
	})

	for _, tc := range []struct {
		name     string
		password []byte
	}{
		{name: "keyfile only", password: nil},
		{name: "password and keyfile", password: []byte("secret")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(dir, tc.name+".pcv")
			req := &EncryptRequest{
				InputFile:  input,
				OutputFile: output,
				Password:   tc.password,
				Keyfiles:   []string{keyfile},
			}

			err := Encrypt(t.Context(), req)
			var validationErr *perrors.ValidationError
			if !perrors.As(err, &validationErr) {
				t.Fatalf("Encrypt() error = %v; want *ValidationError", err)
			}
			if validationErr.Field != "Keyfiles" {
				t.Fatalf("ValidationError.Field = %q; want Keyfiles", validationErr.Field)
			}
			const want = "creating new v2 volumes with keyfiles is disabled pending a reviewed v3 format"
			if validationErr.Message != want {
				t.Fatalf("ValidationError.Message = %q; want %q", validationErr.Message, want)
			}
			if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
				t.Fatalf("rejected writer created output %q: %v", output, statErr)
			}
		})
	}

	if randomReader.reads != 0 {
		t.Fatalf("crypto/rand reads = %d; keyfile writer policy must fail before randomness", randomReader.reads)
	}
	if deriveCalls != 0 {
		t.Fatalf("deriveVolumeKey calls = %d; keyfile writer policy must fail before Argon2id", deriveCalls)
	}
}
