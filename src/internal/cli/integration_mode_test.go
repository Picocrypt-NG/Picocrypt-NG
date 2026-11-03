package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStdinOverwriteGuard protects occupied destinations before stdin buffering.
// PCV3 encryption refuses replacement with either value of --yes; legacy
// decryption preserves its overwrite-confirmation policy.
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
			!strings.Contains(err.Error(), "--yes does not replace PCV3 outputs") {
			t.Fatalf("expected stdin overwrite guidance, got: %v", err)
		}

		// Guard must run before any stdin buffering: the pre-existing file is untouched.
		data, err := os.ReadFile(out)
		if err != nil || string(data) != "original" {
			t.Fatalf("pre-existing output must be left intact, got %q err %v", data, err)
		}
	})

	t.Run("PCV3 encrypt stdin refuses pre-existing output even with -y", func(t *testing.T) {
		resetEncryptFlagsForDirTest()

		out := filepath.Join(t.TempDir(), "existing.pcv")
		if err := os.WriteFile(out, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}

		// The PCV3 output guard must reject before consuming stdin.
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
		if err == nil || !strings.Contains(err.Error(), "already exists") ||
			!strings.Contains(err.Error(), "--yes does not replace PCV3 outputs") {
			t.Fatalf("expected PCV3 overwrite refusal with -y, got: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil || string(data) != "original" {
			t.Fatalf("pre-existing PCV3 output changed with -y: got %q err %v", data, err)
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
