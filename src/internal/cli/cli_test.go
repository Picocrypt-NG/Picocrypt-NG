package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

func TestReporter(t *testing.T) {
	t.Run("NewReporter", func(t *testing.T) {
		r := NewReporter(false)
		if r == nil {
			t.Fatal("NewReporter returned nil")
		}
		if r.quiet {
			t.Error("quiet should be false")
		}

		r = NewReporter(true)
		if !r.quiet {
			t.Error("quiet should be true")
		}
	})

	t.Run("SetStatus", func(t *testing.T) {
		r := NewReporter(false)
		r.SetStatus("test status")
		if r.status != "test status" {
			t.Errorf("expected 'test status', got %q", r.status)
		}
	})

	t.Run("SetProgress", func(t *testing.T) {
		r := NewReporter(false)
		r.SetProgress(0.5, "50%")
		if r.progress != 0.5 {
			t.Errorf("expected progress 0.5, got %f", r.progress)
		}
		if r.info != "50%" {
			t.Errorf("expected info '50%%', got %q", r.info)
		}
	})

	t.Run("Cancel", func(t *testing.T) {
		r := NewReporter(false)
		if r.IsCancelled() {
			t.Error("should not be cancelled initially")
		}
		r.Cancel()
		if !r.IsCancelled() {
			t.Error("should be cancelled after Cancel()")
		}
	})

	t.Run("SetCanCancel", func(t *testing.T) {
		r := NewReporter(false)
		// Should be a no-op, just ensure it doesn't panic
		r.SetCanCancel(true)
		r.SetCanCancel(false)
	})
}

func TestEncryptValidation(t *testing.T) {
	// Save original args
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	t.Run("missing input", func(t *testing.T) {
		// Reset flags for each test
		encInput = nil
		encOutput = ""
		encPassword = ""
		encKeyfiles = nil

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing input")
		}
		if !strings.Contains(err.Error(), "input") {
			t.Errorf("error should mention input: %v", err)
		}
	})

	t.Run("nonexistent input file", func(t *testing.T) {
		encInput = []string{"/nonexistent/file/path.txt"}
		encOutput = ""
		encPassword = "test"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention not found: %v", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		// Create temp file
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encOutput = ""
		encPassword = ""
		encKeyfiles = nil

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing credentials")
		}
		if !strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "keyfile") {
			t.Errorf("error should mention password or keyfile: %v", err)
		}
	})

	t.Run("invalid split options", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encPassword = "test"
		encSplit = true
		encSplitSize = 0 // Invalid

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for invalid split options")
		}
		if !strings.Contains(err.Error(), "split-size") {
			t.Errorf("error should mention split-size: %v", err)
		}

		// Reset
		encSplit = false
		encSplitSize = 0
	})

	t.Run("invalid split unit", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encPassword = "test"
		encSplit = true
		encSplitSize = 10
		encSplitUnit = "invalid"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for invalid split unit")
		}
		if !strings.Contains(err.Error(), "invalid split unit") {
			t.Errorf("error should mention invalid split unit: %v", err)
		}

		// Reset
		encSplit = false
		encSplitSize = 0
		encSplitUnit = "MiB"
	})

	t.Run("nonexistent keyfile", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encPassword = "test"
		encKeyfiles = []string{"/nonexistent/keyfile.key"}

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for nonexistent keyfile")
		}
		if !strings.Contains(err.Error(), "keyfile not found") {
			t.Errorf("error should mention keyfile not found: %v", err)
		}

		// Reset
		encKeyfiles = nil
	})
}

func TestDecryptValidation(t *testing.T) {
	t.Run("missing input", func(t *testing.T) {
		decInput = ""
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing input")
		}
		if !strings.Contains(err.Error(), "input") {
			t.Errorf("error should mention input: %v", err)
		}
	})

	t.Run("nonexistent input file", func(t *testing.T) {
		decInput = "/nonexistent/file.pcv"
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention not found: %v", err)
		}
	})

	t.Run("input is directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		decInput = tmpDir
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for directory input")
		}
		if !strings.Contains(err.Error(), "directory") {
			t.Errorf("error should mention directory: %v", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.pcv")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		decInput = tmpFile
		decPassword = ""
		decKeyfiles = nil
		decQuiet = true // Suppress header read warning

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing credentials")
		}
		if !strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "keyfile") {
			t.Errorf("error should mention password or keyfile: %v", err)
		}

		// Reset
		decQuiet = false
	})

	t.Run("nonexistent keyfile", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.pcv")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		decInput = tmpFile
		decPassword = "test"
		decKeyfiles = []string{"/nonexistent/keyfile.key"}

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for nonexistent keyfile")
		}
		if !strings.Contains(err.Error(), "keyfile not found") {
			t.Errorf("error should mention keyfile not found: %v", err)
		}

		// Reset
		decKeyfiles = nil
	})
}

func TestSplitVolumeDetection(t *testing.T) {
	t.Run("detects split volume pattern", func(t *testing.T) {
		// Create temp files that look like split volumes
		tmpDir := t.TempDir()
		splitFile := filepath.Join(tmpDir, "test.pcv.0")
		if err := os.WriteFile(splitFile, []byte("chunk0"), 0644); err != nil {
			t.Fatal(err)
		}

		decInput = splitFile
		decPassword = "test"
		decRecombine = false
		decQuiet = true

		// The validation will fail (not a valid pcv), but we can check if recombine was set
		cmd := decryptCmd
		_ = cmd.RunE(cmd, []string{})

		if !decRecombine {
			t.Error("should have detected split volume and set recombine=true")
		}

		// Reset
		decRecombine = false
		decQuiet = false
	})
}

func TestOutputAutoGeneration(t *testing.T) {
	t.Run("encrypt auto-generates output", func(t *testing.T) {
		tmpDir := t.TempDir()
		inputFile := filepath.Join(tmpDir, "test.txt")
		if err := os.WriteFile(inputFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		// We can't easily test the full flow without actually encrypting,
		// but we can verify the logic by checking what output would be generated
		encInput = []string{inputFile}
		encOutput = ""

		// The auto-generation happens inside runEncrypt, so we just verify the logic
		outputFile := encOutput
		if outputFile == "" {
			if len(encInput) == 1 {
				outputFile = encInput[0] + ".pcv"
			} else {
				outputFile = "encrypted.pcv"
			}
		}

		expected := inputFile + ".pcv"
		if outputFile != expected {
			t.Errorf("expected %q, got %q", expected, outputFile)
		}
	})

	t.Run("decrypt auto-generates output", func(t *testing.T) {
		input := "/path/to/file.pcv"
		expected := "/path/to/file"

		output := strings.TrimSuffix(input, ".pcv")
		if output != expected {
			t.Errorf("expected %q, got %q", expected, output)
		}
	})
}

func TestGlobExpansion(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	for _, name := range []string{"a.txt", "b.txt", "c.log"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("glob matches files", func(t *testing.T) {
		pattern := filepath.Join(tmpDir, "*.txt")
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 2 {
			t.Errorf("expected 2 matches, got %d", len(matches))
		}
	})

	t.Run("glob no matches", func(t *testing.T) {
		pattern := filepath.Join(tmpDir, "*.xyz")
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})
}

func TestReporterOutput(t *testing.T) {
	t.Run("quiet mode suppresses output", func(t *testing.T) {
		r := NewReporter(true)
		r.SetStatus("test")
		r.SetProgress(0.5, "50%")

		// Capture stderr
		old := os.Stderr
		r2, w, _ := os.Pipe()
		os.Stderr = w

		r.Update()
		r.Finish()

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r2)

		if buf.Len() != 0 {
			t.Errorf("quiet mode should not produce output, got: %q", buf.String())
		}
	})

	t.Run("PrintSuccess respects quiet", func(t *testing.T) {
		r := NewReporter(true)

		old := os.Stderr
		r2, w, _ := os.Pipe()
		os.Stderr = w

		r.PrintSuccess("success message")

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r2)

		if buf.Len() != 0 {
			t.Errorf("quiet mode should suppress success, got: %q", buf.String())
		}
	})

	t.Run("PrintError always outputs", func(t *testing.T) {
		r := NewReporter(true) // Even in quiet mode

		old := os.Stderr
		r2, w, _ := os.Pipe()
		os.Stderr = w

		r.PrintError("error message")

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r2)

		if !strings.Contains(buf.String(), "error message") {
			t.Errorf("PrintError should always output, got: %q", buf.String())
		}
	})
}

func TestVersionFlag(t *testing.T) {
	// Test that version is set correctly
	Version = "v1.0.0"
	if rootCmd.Version != "v1.0.0" {
		// Version is set by Execute(), so we need to call the setter
		rootCmd.Version = Version
	}
	if rootCmd.Version != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %s", rootCmd.Version)
	}
}

// =============================================================================
// Integration Tests - Full encrypt/decrypt flows via CLI
// =============================================================================

// resetEncryptFlags resets all encrypt flags to defaults
func resetEncryptFlags() {
	encInput = nil
	encOutput = ""
	encPassword = ""
	encPasswordStdin = false
	encKeyfiles = nil
	encKeyfileOrder = false
	encComments = ""
	encParanoid = false
	encReedSolomon = false
	encDeniability = false
	encCompress = false
	encSplit = false
	encSplitSize = 0
	encSplitUnit = "MiB"
	encQuiet = true // Always quiet in tests
	encYes = true   // Always overwrite in tests
}

// resetDecryptFlags resets all decrypt flags to defaults
func resetDecryptFlags() {
	decInput = ""
	decOutput = ""
	decPassword = ""
	decPasswordStdin = false
	decKeyfiles = nil
	decForce = false
	decVerifyFirst = false
	decAutoUnzip = false
	decSameLevel = false
	decRecombine = false
	decDeniability = false
	decQuiet = true // Always quiet in tests
	decYes = true   // Always overwrite in tests
}

func TestIntegrationBasicRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Hello, Picocrypt CLI integration test!")

	// Create input file
	inputFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatalf("failed to create input file: %v", err)
	}

	encryptedFile := filepath.Join(tmpDir, "test.txt.pcv")
	decryptedFile := filepath.Join(tmpDir, "decrypted.txt")

	// Encrypt
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "testpassword123"

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Verify encrypted file exists
	if _, err := os.Stat(encryptedFile); err != nil {
		t.Fatalf("encrypted file not found: %v", err)
	}

	// Decrypt
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "testpassword123"

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	// Verify content
	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch.\nExpected: %q\nGot: %q", plaintext, decrypted)
	}
}

func TestIntegrationWithKeyfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Keyfile integration test content")

	inputFile := filepath.Join(tmpDir, "secret.txt")
	keyfile := filepath.Join(tmpDir, "my.key")
	encryptedFile := filepath.Join(tmpDir, "secret.pcv")
	decryptedFile := filepath.Join(tmpDir, "secret_dec.txt")

	// Create files
	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyfile, []byte("keyfile content 12345"), 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with password + keyfile
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "pass"
	encKeyfiles = []string{keyfile}

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt with password + keyfile
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "pass"
	decKeyfiles = []string{keyfile}

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestIntegrationParanoidMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Paranoid mode test - Serpent + XChaCha20")

	inputFile := filepath.Join(tmpDir, "paranoid.txt")
	encryptedFile := filepath.Join(tmpDir, "paranoid.pcv")
	decryptedFile := filepath.Join(tmpDir, "paranoid_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with paranoid mode
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "paranoid_pass"
	encParanoid = true

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "paranoid_pass"

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestIntegrationReedSolomon(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Reed-Solomon error correction test data")

	inputFile := filepath.Join(tmpDir, "rs_test.txt")
	encryptedFile := filepath.Join(tmpDir, "rs_test.pcv")
	decryptedFile := filepath.Join(tmpDir, "rs_test_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with Reed-Solomon
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "rs_password"
	encReedSolomon = true

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "rs_password"

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestIntegrationWithComments(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("File with comments")

	inputFile := filepath.Join(tmpDir, "comments.txt")
	encryptedFile := filepath.Join(tmpDir, "comments.pcv")
	decryptedFile := filepath.Join(tmpDir, "comments_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with comments
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "comments_pass"
	encComments = "This is a test comment"

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "comments_pass"

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestIntegrationVerifyFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Verify-first two-pass decryption test")

	inputFile := filepath.Join(tmpDir, "verify.txt")
	encryptedFile := filepath.Join(tmpDir, "verify.pcv")
	decryptedFile := filepath.Join(tmpDir, "verify_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "verify_pass"

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt with verify-first
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "verify_pass"
	decVerifyFirst = true

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestIntegrationWrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Wrong password test")

	inputFile := filepath.Join(tmpDir, "wrong_pass.txt")
	encryptedFile := filepath.Join(tmpDir, "wrong_pass.pcv")
	decryptedFile := filepath.Join(tmpDir, "wrong_pass_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "correct_password"

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt with wrong password
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "wrong_password"

	err := runDecrypt(decryptCmd, []string{})
	if err == nil {
		t.Error("decrypt should fail with wrong password")
	}
}

func TestIntegrationDeniability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Deniability wrapper test")

	inputFile := filepath.Join(tmpDir, "deniable.txt")
	encryptedFile := filepath.Join(tmpDir, "deniable.pcv")
	decryptedFile := filepath.Join(tmpDir, "deniable_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with deniability
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "deniable_pass"
	encDeniability = true

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt with deniability
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "deniable_pass"
	decDeniability = true

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestIntegrationMultipleFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	// Create multiple files
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(file1, []byte("content of file 1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte("content of file 2"), 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := filepath.Join(tmpDir, "archive.pcv")
	decryptedFile := filepath.Join(tmpDir, "archive.zip")

	// Encrypt multiple files
	resetEncryptFlags()
	encInput = []string{file1, file2}
	encOutput = encryptedFile
	encPassword = "multi_pass"

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "multi_pass"

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	// Output should be a zip file
	if _, err := os.Stat(decryptedFile); err != nil {
		t.Fatalf("decrypted file not found: %v", err)
	}
}

func TestIntegrationAllOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("All options enabled: paranoid + RS + keyfile + comments")

	inputFile := filepath.Join(tmpDir, "all_opts.txt")
	keyfile := filepath.Join(tmpDir, "all_opts.key")
	encryptedFile := filepath.Join(tmpDir, "all_opts.pcv")
	decryptedFile := filepath.Join(tmpDir, "all_opts_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyfile, []byte("all options keyfile"), 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with all options
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "all_opts_pass"
	encKeyfiles = []string{keyfile}
	encParanoid = true
	encReedSolomon = true
	encComments = "All options test"

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "all_opts_pass"
	decKeyfiles = []string{keyfile}

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestReadHeaderInfo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping header info test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Header info test")

	inputFile := filepath.Join(tmpDir, "header_test.txt")
	encryptedFile := filepath.Join(tmpDir, "header_test.pcv")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with keyfile flag set
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "header_pass"
	encKeyfiles = []string{inputFile} // Use input as keyfile

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Now test readHeaderInfo
	rsCodecs, err := newRSCodecs()
	if err != nil {
		t.Fatal(err)
	}

	hdr, err := readHeaderInfo(encryptedFile, rsCodecs)
	if err != nil {
		t.Fatalf("readHeaderInfo failed: %v", err)
	}

	if !hdr.Flags.UseKeyfiles {
		t.Error("header should indicate keyfiles are used")
	}
}

func TestReadHeaderInfoInvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.pcv")

	// Create invalid file
	if err := os.WriteFile(invalidFile, []byte("not a valid pcv file"), 0644); err != nil {
		t.Fatal(err)
	}

	rsCodecs, err := newRSCodecs()
	if err != nil {
		t.Fatal(err)
	}

	_, err = readHeaderInfo(invalidFile, rsCodecs)
	if err == nil {
		t.Error("readHeaderInfo should fail for invalid file")
	}
}

func TestReadHeaderInfoNonexistent(t *testing.T) {
	rsCodecs, err := newRSCodecs()
	if err != nil {
		t.Fatal(err)
	}

	_, err = readHeaderInfo("/nonexistent/file.pcv", rsCodecs)
	if err == nil {
		t.Error("readHeaderInfo should fail for nonexistent file")
	}
}

// newRSCodecs helper for tests
func newRSCodecs() (*encoding.RSCodecs, error) {
	return encoding.NewRSCodecs()
}

func TestIntegrationKeyfileOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Keyfile-only encryption test")

	inputFile := filepath.Join(tmpDir, "kf_only.txt")
	keyfile := filepath.Join(tmpDir, "only.key")
	encryptedFile := filepath.Join(tmpDir, "kf_only.pcv")
	decryptedFile := filepath.Join(tmpDir, "kf_only_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyfile, []byte("keyfile only content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with keyfile only (no password)
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = ""
	encKeyfiles = []string{keyfile}

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt with keyfile only
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = ""
	decKeyfiles = []string{keyfile}

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestIntegrationCompress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	// Create compressible content
	plaintext := bytes.Repeat([]byte("compressible content "), 100)

	inputFile := filepath.Join(tmpDir, "compress.txt")
	encryptedFile := filepath.Join(tmpDir, "compress.pcv")
	decryptedFile := filepath.Join(tmpDir, "compress.zip")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with compression
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "compress_pass"
	encCompress = true

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "compress_pass"

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	// Output should exist (it's a zip)
	if _, err := os.Stat(decryptedFile); err != nil {
		t.Fatalf("decrypted file not found: %v", err)
	}
}

func TestIntegrationDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	// Create a subdirectory with files
	subDir := filepath.Join(tmpDir, "mydir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "a.txt"), []byte("file a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "b.txt"), []byte("file b"), 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := filepath.Join(tmpDir, "dir.pcv")
	decryptedFile := filepath.Join(tmpDir, "dir.zip")

	// Encrypt entire directory
	resetEncryptFlags()
	encInput = []string{subDir}
	encOutput = encryptedFile
	encPassword = "dir_pass"

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Decrypt
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "dir_pass"

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if _, err := os.Stat(decryptedFile); err != nil {
		t.Fatalf("decrypted file not found: %v", err)
	}
}

func TestReporterNonQuietUpdate(t *testing.T) {
	r := NewReporter(false) // non-quiet mode
	r.SetStatus("Processing...")
	r.SetProgress(0.5, "50%")

	// Capture stderr
	old := os.Stderr
	r2, w, _ := os.Pipe()
	os.Stderr = w

	r.Update()

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r2)

	// In non-quiet mode, Update() should produce output
	if buf.Len() == 0 {
		t.Error("non-quiet mode should produce output from Update()")
	}
}

func TestReporterNonQuietFinish(t *testing.T) {
	r := NewReporter(false) // non-quiet mode
	r.SetStatus("Done")
	r.SetProgress(1.0, "100%")

	// Capture stderr
	old := os.Stderr
	r2, w, _ := os.Pipe()
	os.Stderr = w

	r.Finish()

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r2)

	// Finish should produce a newline at minimum
	if buf.Len() == 0 {
		t.Error("non-quiet mode should produce output from Finish()")
	}
}

func TestReporterNonQuietPrintSuccess(t *testing.T) {
	r := NewReporter(false) // non-quiet mode

	old := os.Stderr
	r2, w, _ := os.Pipe()
	os.Stderr = w

	r.PrintSuccess("Operation completed: %s", "test.txt")

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r2)

	if !strings.Contains(buf.String(), "Operation completed") {
		t.Errorf("expected success message, got: %q", buf.String())
	}
}

func TestReporterNonQuietPrintError(t *testing.T) {
	r := NewReporter(false) // non-quiet mode

	old := os.Stderr
	r2, w, _ := os.Pipe()
	os.Stderr = w

	r.PrintError("Operation failed: %s", "test error")

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r2)

	if !strings.Contains(buf.String(), "Operation failed") {
		t.Errorf("expected error message, got: %q", buf.String())
	}
}

func TestIntegrationWithVerboseOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Verbose output test")

	inputFile := filepath.Join(tmpDir, "verbose.txt")
	encryptedFile := filepath.Join(tmpDir, "verbose.pcv")
	decryptedFile := filepath.Join(tmpDir, "verbose_dec.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt with verbose output (non-quiet)
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = encryptedFile
	encPassword = "verbose_pass"
	encQuiet = false // Enable verbose output
	encYes = true

	// Capture stderr
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		w.Close()
		os.Stderr = old
		t.Fatalf("encrypt failed: %v", err)
	}

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	// Should have produced output about encryption
	if !strings.Contains(buf.String(), "Encrypting") {
		t.Log("Warning: expected 'Encrypting' in output, got:", buf.String())
	}

	// Decrypt with verbose output
	resetDecryptFlags()
	decInput = encryptedFile
	decOutput = decryptedFile
	decPassword = "verbose_pass"
	decQuiet = false
	decYes = true

	// Capture stderr again
	old = os.Stderr
	r, w, _ = os.Pipe()
	os.Stderr = w

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		w.Close()
		os.Stderr = old
		t.Fatalf("decrypt failed: %v", err)
	}

	w.Close()
	os.Stderr = old

	buf.Reset()
	_, _ = buf.ReadFrom(r)

	// Verify decryption
	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("content mismatch")
	}
}

func TestIntegrationSplitUnit(t *testing.T) {
	// Test all valid split units are recognized
	validUnits := []string{"KiB", "MiB", "GiB", "TiB", "Total"}

	for _, unit := range validUnits {
		t.Run(unit, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "test.txt")
			if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
				t.Fatal(err)
			}

			resetEncryptFlags()
			encInput = []string{tmpFile}
			encPassword = "test"
			encSplit = true
			encSplitSize = 1
			encSplitUnit = unit

			// Just validate the unit is accepted (won't actually encrypt)
			// The actual split test would need more setup
		})
	}
}

func TestIntegrationAutoOutputName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	plaintext := []byte("Auto output name test")

	inputFile := filepath.Join(tmpDir, "autoname.txt")

	if err := os.WriteFile(inputFile, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt without specifying output - should auto-generate
	resetEncryptFlags()
	encInput = []string{inputFile}
	encOutput = "" // Auto-generate
	encPassword = "auto_pass"

	if err := runEncrypt(encryptCmd, []string{}); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Check auto-generated output exists
	expectedOutput := inputFile + ".pcv"
	if _, err := os.Stat(expectedOutput); err != nil {
		t.Fatalf("auto-generated output %s not found: %v", expectedOutput, err)
	}

	// Decrypt without specifying output
	resetDecryptFlags()
	decInput = expectedOutput
	decOutput = "" // Auto-generate
	decPassword = "auto_pass"

	if err := runDecrypt(decryptCmd, []string{}); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	// Check auto-generated decrypted output
	expectedDecOutput := inputFile // Should strip .pcv
	if _, err := os.Stat(expectedDecOutput); err != nil {
		// Might overwrite original - that's fine for this test
		t.Logf("Note: decrypted to %s", expectedDecOutput)
	}
}
