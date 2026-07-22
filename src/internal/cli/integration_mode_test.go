package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStdinOverwriteGuard exercises the real CLI overwrite guard that protects a
// pre-existing output file when input comes from stdin. Without -y the guard at
// encrypt.go:182 / decrypt.go:156 must refuse and tell the user to pass -y; this
// guard returns BEFORE any stdin buffering, so the without-y path is deterministic
// and never touches os.Stdin. It is otherwise only covered by the default-skipped
// os/exec integration suite, so it is asserted here in-process.
//
// (Replaces the former TestCLIIntegrationEnabled, which only re-derived a
// test-only env gate and exercised zero production code. The real-binary suite
// is now owned by the central TestCLIIntegration parent.)
func TestStdinOverwriteGuard(t *testing.T) {
	t.Run("encrypt stdin refuses pre-existing output without -y", func(t *testing.T) {
		resetEncryptFlagsForDirTest()
		t.Cleanup(resetEncryptFlagsForDirTest)

		out := filepath.Join(t.TempDir(), "existing.pcv")
		if err := os.WriteFile(out, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}

		encOutput = out
		encPassword = "test"
		encYes = false

		err := encryptCmd.RunE(encryptCmd, []string{"-"})
		if err == nil {
			t.Fatal("expected overwrite error for stdin encrypt without -y")
		}
		if !strings.Contains(err.Error(), "already exists") ||
			!strings.Contains(err.Error(), "use -y to overwrite") {
			t.Fatalf("expected stdin overwrite guidance, got: %v", err)
		}

		// Guard must run before any stdin buffering: the pre-existing file is untouched.
		data, err := os.ReadFile(out)
		if err != nil || string(data) != "original" {
			t.Fatalf("pre-existing output must be left intact, got %q err %v", data, err)
		}
	})

	t.Run("encrypt stdin -y bypasses the overwrite guard", func(t *testing.T) {
		resetEncryptFlagsForDirTest()

		out := filepath.Join(t.TempDir(), "existing.pcv")
		if err := os.WriteFile(out, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}

		// Feed empty stdin so the run proceeds past the guard deterministically;
		// it will fail later (empty input), but never on the overwrite guard.
		oldStdin := os.Stdin
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		os.Stdin = r

		encOutput = out
		encPassword = "test"
		encYes = true
		t.Cleanup(func() {
			os.Stdin = oldStdin
			_ = r.Close()
			resetEncryptFlagsForDirTest()
		})

		err = encryptCmd.RunE(encryptCmd, []string{"-"})
		if err != nil && strings.Contains(err.Error(), "use -y to overwrite") {
			t.Fatalf("-y must bypass the overwrite guard, got: %v", err)
		}
	})

	t.Run("decrypt stdin refuses pre-existing output without -y", func(t *testing.T) {
		resetDecryptFlagsForDirTest()
		t.Cleanup(resetDecryptFlagsForDirTest)

		out := filepath.Join(t.TempDir(), "decrypted-existing")
		if err := os.WriteFile(out, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}

		decOutput = out
		decPassword = "test"
		decYes = false

		err := decryptCmd.RunE(decryptCmd, []string{"-"})
		if err == nil {
			t.Fatal("expected overwrite error for stdin decrypt without -y")
		}
		if !strings.Contains(err.Error(), "already exists") ||
			!strings.Contains(err.Error(), "use -y to overwrite") {
			t.Fatalf("expected stdin overwrite guidance, got: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil || string(data) != "original" {
			t.Fatalf("pre-existing output must be left intact, got %q err %v", data, err)
		}
	})
}
