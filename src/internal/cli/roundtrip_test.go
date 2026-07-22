package cli

import (
	"Picocrypt-NG/internal/header"
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestCLIRoundTrip encrypts a fixed plaintext then decrypts it using the real
// Cobra commands and asserts recovered bytes == original. Each row is a
// distinct flag combination. The fast-KDF seam lives in internal/volume and is
// not exported to this package, so we keep payloads tiny (8 bytes) to limit
// wall-clock time while still exercising the full codepath.
func TestCLIRoundTrip(t *testing.T) {
	plaintext := []byte("testdata")

	// writeKeyfile writes fixed bytes to a temp file and returns its path.
	writeKeyfile := func(t *testing.T, content []byte) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "keyfile.key")
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatalf("write keyfile: %v", err)
		}
		return p
	}

	tests := []struct {
		name         string
		setupEncrypt func(t *testing.T, in, out string)
		setupDecrypt func(t *testing.T, in, out string)
		wantErr      bool // expect decrypt to fail (wrong-password row)
	}{
		{
			name: "plain",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass1"
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass1"
			},
		},
		{
			name: "single keyfile",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass2"
				encKeyfiles = []string{writeKeyfile(t, []byte("keyA"))}
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass2"
				decKeyfiles = []string{writeKeyfile(t, []byte("keyA"))}
			},
		},
		{
			name: "multi keyfile ordered",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass3"
				kf1 := writeKeyfile(t, []byte("alpha"))
				kf2 := writeKeyfile(t, []byte("beta"))
				encKeyfiles = []string{kf1, kf2}
				encKeyfileOrder = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass3"
				// keyfile paths must be re-created in same order; we use the
				// encKeyfiles that were set during encrypt (same temp files are
				// still present because they share the same t.TempDir scope).
				decKeyfiles = encKeyfiles
			},
		},
		{
			name: "paranoid",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass4"
				encParanoid = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass4"
			},
		},
		{
			name: "reed-solomon",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass5"
				encReedSolomon = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass5"
			},
		},
		{
			name: "deniability",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass6"
				encDeniability = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass6"
				decDeniability = true
			},
		},
		{
			// compress wraps the file in a zip before encryption; the decrypted
			// output is a zip archive. We verify the zip contains the plaintext.
			name: "compress",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass7"
				encCompress = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass7"
			},
		},
		{
			name: "verify-first",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass8"
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass8"
				decVerifyFirst = true
			},
		},
		{
			name: "wrong password",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "correct"
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "wrong"
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset all flags before and after each sub-test to prevent bleed.
			resetEncryptFlagsForDirTest()
			resetDecryptFlagsForDirTest()
			t.Cleanup(resetEncryptFlagsForDirTest)
			t.Cleanup(resetDecryptFlagsForDirTest)

			tmpDir := t.TempDir()
			inputFile := filepath.Join(tmpDir, "plain.bin")
			encryptedFile := filepath.Join(tmpDir, "enc.pcv")
			decryptedFile := filepath.Join(tmpDir, "dec.bin")

			if err := os.WriteFile(inputFile, plaintext, 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}

			// --- ENCRYPT ---
			encOutput = encryptedFile
			encQuiet = true
			encYes = true
			tc.setupEncrypt(t, inputFile, encryptedFile)

			if err := encryptCmd.RunE(encryptCmd, []string{inputFile}); err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			// --- DECRYPT ---
			decOutput = decryptedFile
			decQuiet = true
			decYes = true
			tc.setupDecrypt(t, encryptedFile, decryptedFile)

			decErr := decryptCmd.RunE(decryptCmd, []string{encryptedFile})
			if tc.wantErr {
				if decErr == nil {
					t.Fatal("expected decrypt error (wrong password), got nil")
				}
				// A bare non-nil check passes even on a crash or unrelated error.
				// Assert the specific auth type so the test is falsifiable: a
				// wrong-password error MUST be *header.AuthError with
				// PasswordIncorrect=true (Rule 9). errors.Is on a plain sentinel
				// would not match because decrypt.go returns *header.AuthError
				// (not perrors.ErrAuthFailed) for header-phase auth failures.
				var authErr *header.AuthError
				if !errors.As(decErr, &authErr) || !authErr.PasswordIncorrect {
					t.Fatalf("wrong-password decrypt error = %v; want *header.AuthError{PasswordIncorrect:true}", decErr)
				}
				return
			}
			if decErr != nil {
				t.Fatalf("decrypt: %v", decErr)
			}

			// Assert recovered bytes == original.
			// The compress case produces a zip archive; verify the first entry.
			if tc.name == "compress" {
				assertZipContainsPlaintext(t, decryptedFile, plaintext)
			} else {
				got, err := os.ReadFile(decryptedFile)
				if err != nil {
					t.Fatalf("read decrypted output: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("roundtrip mismatch: got %q, want %q", got, plaintext)
				}
			}
		})
	}
}

// assertZipContainsPlaintext checks that path is a valid zip whose first entry
// contains exactly plaintext. This is needed for the "compress" round-trip: the
// encrypt step wraps a single file in a zip (Compress=true) before encryption,
// so the decrypted output is a zip archive, not raw bytes.
func assertZipContainsPlaintext(t *testing.T, path string, plaintext []byte) {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("compress: decrypted output is not a valid zip: %v", err)
	}
	defer func() { _ = zr.Close() }()

	if len(zr.File) == 0 {
		t.Fatal("compress: zip archive contains no entries")
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("compress: open first zip entry: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("compress: read first zip entry: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("compress: zip entry content = %q, want %q", got, plaintext)
	}
}
