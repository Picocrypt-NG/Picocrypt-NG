package cli

import (
	perrors "Picocrypt-NG/internal/errors"
	cryptorand "crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

type countingZeroCLIReader struct {
	reads int
}

func (r *countingZeroCLIReader) Read(p []byte) (int, error) {
	r.reads++
	clear(p)
	return len(p), nil
}

func resetDeniabilityKeyfileCLIFlags() {
	resetEncryptFlagsForDirTest()
	resetDecryptFlagsForDirTest()
	encPasswordStdin = false
	decPasswordStdin = false
}

func useCLIStdin(t *testing.T, data []byte) {
	t.Helper()

	oldStdin := os.Stdin
	os.Stdin = stdinFile(t, data)
	t.Cleanup(func() {
		os.Stdin = oldStdin
	})
}

func TestEncryptRejectsAllNewV2KeyfileWritesBeforeCreatingOutput(t *testing.T) {
	originalReader := cryptorand.Reader
	reader := &countingZeroCLIReader{}
	cryptorand.Reader = reader
	t.Cleanup(func() {
		cryptorand.Reader = originalReader
	})

	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	keyfile := filepath.Join(dir, "keyfile.bin")
	if err := os.WriteFile(input, []byte("plaintext must never reach a deniable output"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := os.WriteFile(keyfile, []byte("fixed keyfile test material"), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}

	for _, tc := range []struct {
		name          string
		password      string
		passwordStdin bool
	}{
		{name: "keyfile only", passwordStdin: true},
		{name: "password and keyfile", password: "secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetDeniabilityKeyfileCLIFlags()
			t.Cleanup(resetDeniabilityKeyfileCLIFlags)

			output := filepath.Join(dir, tc.name+".pcv")
			if tc.passwordStdin {
				useCLIStdin(t, []byte("\n"))
			}
			encOutput = output
			encPassword = tc.password
			encPasswordStdin = tc.passwordStdin
			encKeyfiles = []string{keyfile}
			encQuiet = true
			encYes = true

			err := encryptCmd.RunE(encryptCmd, []string{input})
			const wantErr = "validation: Keyfiles: creating new v2 volumes with keyfiles is disabled pending a reviewed v3 format"
			if err == nil {
				t.Error("encrypt returned nil; new v2 keyfile writes must be rejected")
			} else if got := err.Error(); got != wantErr {
				t.Errorf("encrypt error = %q; want exact actionable error %q", got, wantErr)
			}
			if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
				t.Errorf("rejected keyfile writer created output %q: %v", output, statErr)
			}
		})
	}
	if reader.reads != 0 {
		t.Errorf("crypto/rand reads = %d; keyfile writer policy must fail before generating volume material", reader.reads)
	}
}

func TestEncryptRejectsEmptyDeniabilityPasswordBeforeCreatingOutput(t *testing.T) {
	originalReader := cryptorand.Reader
	reader := &countingZeroCLIReader{}
	cryptorand.Reader = reader
	t.Cleanup(func() {
		cryptorand.Reader = originalReader
	})

	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	output := filepath.Join(dir, "deniable.pcv")
	if err := os.WriteFile(input, []byte("plaintext must not reach an empty-password wrapper"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	resetDeniabilityKeyfileCLIFlags()
	t.Cleanup(resetDeniabilityKeyfileCLIFlags)
	useCLIStdin(t, []byte("\n"))
	encOutput = output
	encPasswordStdin = true
	encDeniability = true
	encQuiet = true
	encYes = true

	err := encryptCmd.RunE(encryptCmd, []string{input})
	var validationErr *perrors.ValidationError
	if !perrors.As(err, &validationErr) {
		t.Fatalf("encrypt error = %v; want *errors.ValidationError", err)
	}
	if validationErr.Field != "Password" {
		t.Errorf("ValidationError.Field = %q; want Password", validationErr.Field)
	}
	if validationErr.Message != perrors.DeniabilityPasswordRequiredMessage {
		t.Errorf(
			"ValidationError.Message = %q; want %q",
			validationErr.Message,
			perrors.DeniabilityPasswordRequiredMessage,
		)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Errorf("empty-password deniability created output %q: %v", output, statErr)
	}
	if reader.reads != 0 {
		t.Errorf("crypto/rand reads = %d; empty-password deniability must fail before randomness", reader.reads)
	}
}
