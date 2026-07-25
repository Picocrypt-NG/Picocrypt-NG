package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Integration tests for stdin/stdout functionality.
// These tests build and run the actual CLI binary to verify end-to-end behavior.

func TestCLIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("PICOCRYPT_RUN_CLI_INTEGRATION") != "1" {
		t.Skip("set PICOCRYPT_RUN_CLI_INTEGRATION=1 to run CLI integration tests")
	}

	t.Run("stdin_stdout", testStdinStdoutIntegration)
	t.Run("error_cases", testStdinStdoutErrorCases)
}

// stdinFile materializes data as a real *os.File for use as a subprocess's stdin.
//
// When exec.Cmd.Stdin is an *os.File, os/exec hands the fd straight to the child;
// for any other io.Reader (e.g. bytes.Reader) it spawns a parent-side goroutine
// (writerDescriptor) to pump the pipe. Under the race detector on a busy CI
// runner that pump goroutine can fail to deliver EOF, so the child blocks
// forever on its stdin read, is left orphaned (the picocrypt-test process), and
// the whole -race suite is killed with SIGTERM (exit 143). A regular file always
// reaches EOF and needs no pump goroutine, so the child can never wedge on stdin.
func stdinFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing stdin temp: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening stdin temp: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func testStdinStdoutIntegration(t *testing.T) {
	// Build CLI binary
	tmpDir := t.TempDir()
	binaryName := "picocrypt-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tmpDir, binaryName)

	// Get absolute path to src directory (parent of internal/cli)
	srcDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("getting source dir: %v", err)
	}

	cmd := exec.Command("go", "build", "-tags", "cli", "-o", binaryPath, "./cmd/picocrypt")
	cmd.Dir = srcDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building binary: %v\nOutput: %s", err, output)
	}

	testPassword := "testpassword123"

	t.Run("stdin encrypt to file", func(t *testing.T) {
		inputData := []byte("secret data for stdin encryption test")
		outputFile := filepath.Join(tmpDir, "stdin-encrypt.pcv")

		cmd := exec.Command(binaryPath, "encrypt",
			"-",
			"-o", outputFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = stdinFile(t, inputData)

		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("stdin encrypt failed: %v\nOutput: %s", err, output)
		}

		// Verify output file exists and has content
		info, err := os.Stat(outputFile)
		if err != nil {
			t.Fatalf("output file not found: %v", err)
		}
		if info.Size() == 0 {
			t.Error("output file is empty")
		}
		if info.Size() <= int64(len(inputData)) {
			t.Error("output file should be larger than input (has header)")
		}

		// Decrypt and verify
		decryptedFile := filepath.Join(tmpDir, "stdin-decrypted")
		cmd = exec.Command(binaryPath, "decrypt",
			outputFile,
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("decrypt verification failed: %v\nOutput: %s", err, output)
		}

		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("reading decrypted file: %v", err)
		}
		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("stdin encrypt existing output requires --yes", func(t *testing.T) {
		inputData := []byte("stdin overwrite check")
		outputFile := filepath.Join(tmpDir, "stdin-overwrite-encrypt.pcv")
		if err := os.WriteFile(outputFile, []byte("existing"), 0o644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			"-",
			"-o", outputFile,
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, inputData)

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected overwrite error for stdin encrypt without -y")
		}
		if !bytes.Contains(output, []byte("use -y to overwrite")) {
			t.Fatalf("expected explicit -y guidance, got: %s", output)
		}
	})

	t.Run("file encrypt to stdout", func(t *testing.T) {
		inputData := []byte("secret data for stdout encryption test")
		inputFile := filepath.Join(tmpDir, "stdout-input.txt")
		if err := os.WriteFile(inputFile, inputData, 0o644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			inputFile,
			"-o", "-",
			"-p", testPassword,
		)

		encrypted, err := cmd.Output()
		if err != nil {
			exitErr := &exec.ExitError{}
			if errors.As(err, &exitErr) {
				t.Fatalf("stdout encrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("stdout encrypt failed: %v", err)
		}

		if len(encrypted) == 0 {
			t.Error("no data written to stdout")
		}
		if len(encrypted) <= len(inputData) {
			t.Error("stdout output should be larger than input (has header)")
		}

		// Save and decrypt to verify
		encryptedFile := filepath.Join(tmpDir, "stdout-test.pcv")
		if err := os.WriteFile(encryptedFile, encrypted, 0o644); err != nil {
			t.Fatal(err)
		}

		decryptedFile := filepath.Join(tmpDir, "stdout-decrypted")
		cmd = exec.Command(binaryPath, "decrypt",
			encryptedFile,
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("decrypt verification failed: %v\nOutput: %s", err, output)
		}

		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("reading decrypted file: %v", err)
		}
		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("stdin to stdout full pipeline", func(t *testing.T) {
		inputData := []byte("full pipeline test data through stdin to stdout")

		cmd := exec.Command(binaryPath, "encrypt",
			"-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, inputData)

		encrypted, err := cmd.Output()
		if err != nil {
			exitErr := &exec.ExitError{}
			if errors.As(err, &exitErr) {
				t.Fatalf("stdin->stdout encrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("stdin->stdout encrypt failed: %v", err)
		}

		if len(encrypted) == 0 {
			t.Fatal("no encrypted data produced")
		}

		// Decrypt via stdin->stdout
		cmd = exec.Command(binaryPath, "decrypt",
			"-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, encrypted)

		decrypted, err := cmd.Output()
		if err != nil {
			exitErr := &exec.ExitError{}
			if errors.As(err, &exitErr) {
				t.Fatalf("stdin->stdout decrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("stdin->stdout decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("round-trip content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("stdin decrypt from file", func(t *testing.T) {
		inputData := []byte("data to decrypt from stdin")
		encryptedFile := filepath.Join(tmpDir, "for-stdin-decrypt.pcv")

		// Create encrypted file first
		cmd := exec.Command(binaryPath, "encrypt",
			"-",
			"-o", encryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = stdinFile(t, inputData)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("encryption failed: %v\nOutput: %s", err, output)
		}

		// Read encrypted file to feed via stdin
		encrypted, err := os.ReadFile(encryptedFile)
		if err != nil {
			t.Fatal(err)
		}

		decryptedFile := filepath.Join(tmpDir, "stdin-decrypt-output")
		cmd = exec.Command(binaryPath, "decrypt",
			"-",
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = stdinFile(t, encrypted)

		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("stdin decrypt failed: %v\nOutput: %s", err, output)
		}

		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("reading decrypted file: %v", err)
		}
		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("stdin decrypt existing output requires --yes", func(t *testing.T) {
		inputData := []byte("stdin decrypt overwrite check")
		encryptedFile := filepath.Join(tmpDir, "stdin-overwrite-decrypt.pcv")
		if err := os.WriteFile(encryptedFile, inputData, 0o644); err != nil {
			t.Fatal(err)
		}

		existingOutput := filepath.Join(tmpDir, "stdin-overwrite-output")
		if err := os.WriteFile(existingOutput, []byte("existing"), 0o644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(binaryPath, "decrypt",
			"-",
			"-o", existingOutput,
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, inputData)

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected overwrite error for stdin decrypt without -y")
		}
		if !bytes.Contains(output, []byte("use -y to overwrite")) {
			t.Fatalf("expected explicit -y guidance, got: %s", output)
		}
	})

	t.Run("file decrypt to stdout", func(t *testing.T) {
		inputData := []byte("data to decrypt to stdout")
		encryptedFile := filepath.Join(tmpDir, "for-stdout-decrypt.pcv")

		// Create encrypted file
		cmd := exec.Command(binaryPath, "encrypt",
			"-",
			"-o", encryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = stdinFile(t, inputData)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("encryption failed: %v\nOutput: %s", err, output)
		}

		// Decrypt to stdout
		cmd = exec.Command(binaryPath, "decrypt",
			encryptedFile,
			"-o", "-",
			"-p", testPassword,
		)

		decrypted, err := cmd.Output()
		if err != nil {
			exitErr := &exec.ExitError{}
			if errors.As(err, &exitErr) {
				t.Fatalf("stdout decrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("stdout decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("large data through pipeline", func(t *testing.T) {
		// Test with 1 MiB of data
		inputData := make([]byte, 1024*1024)
		for i := range inputData {
			inputData[i] = byte(i % 256)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			"-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, inputData)

		encrypted, err := cmd.Output()
		if err != nil {
			exitErr := &exec.ExitError{}
			if errors.As(err, &exitErr) {
				t.Fatalf("large data encrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("large data encrypt failed: %v", err)
		}

		cmd = exec.Command(binaryPath, "decrypt",
			"-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, encrypted)

		decrypted, err := cmd.Output()
		if err != nil {
			exitErr := &exec.ExitError{}
			if errors.As(err, &exitErr) {
				t.Fatalf("large data decrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("large data decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, inputData) {
			t.Error("large data round-trip content mismatch")
		}
	})

	t.Run("auto-unzip works with auto-generated output path", func(t *testing.T) {
		inputA := filepath.Join(tmpDir, "auto-unzip-a.txt")
		inputB := filepath.Join(tmpDir, "auto-unzip-b.txt")
		if err := os.WriteFile(inputA, []byte("alpha"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inputB, []byte("bravo"), 0o644); err != nil {
			t.Fatal(err)
		}

		volumePath := filepath.Join(tmpDir, "auto-unzip.pcv")
		cmd := exec.Command(binaryPath, "encrypt",
			inputA, inputB,
			"-o", volumePath,
			"-p", testPassword,
			"-y",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("multi-file encrypt failed: %v\nOutput: %s", err, output)
		}

		cmd = exec.Command(binaryPath, "decrypt",
			volumePath,
			"-p", testPassword,
			"-y",
			"--auto-unzip",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("auto-unzip decrypt failed: %v\nOutput: %s", err, output)
		}

		extractedDir := filepath.Join(tmpDir, "auto-unzip")
		info, err := os.Stat(extractedDir)
		if err != nil {
			t.Fatalf("expected extracted directory %q: %v", extractedDir, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected %q to be a directory after auto-unzip", extractedDir)
		}

		if _, err := os.Stat(filepath.Join(extractedDir, filepath.Base(inputA))); err != nil {
			t.Fatalf("missing extracted file %q: %v", filepath.Base(inputA), err)
		}
		if _, err := os.Stat(filepath.Join(extractedDir, filepath.Base(inputB))); err != nil {
			t.Fatalf("missing extracted file %q: %v", filepath.Base(inputB), err)
		}
	})
}

func testStdinStdoutErrorCases(t *testing.T) {
	// Build CLI binary
	tmpDir := t.TempDir()
	binaryName := "picocrypt-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tmpDir, binaryName)

	srcDir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("getting source dir: %v", err)
	}

	cmd := exec.Command("go", "build", "-tags", "cli", "-o", binaryPath, "./cmd/picocrypt")
	cmd.Dir = srcDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building binary: %v\nOutput: %s", err, output)
	}

	t.Run("stdin with -P conflicts", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "encrypt",
			"-",
			"-o", filepath.Join(tmpDir, "out.pcv"),
			"-P",
		)
		cmd.Stdin = stdinFile(t, []byte("test"))

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected error for -i - with -P")
		}
		if !bytes.Contains(output, []byte("cannot use -P")) {
			t.Errorf("error should mention -P conflict, got: %s", output)
		}
	})

	t.Run("stdout with --split conflicts", func(t *testing.T) {
		inputFile := filepath.Join(tmpDir, "split-test.txt")
		if err := os.WriteFile(inputFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			inputFile,
			"-o", "-",
			"-p", "test",
			"--split",
			"--split-size", "10",
		)

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected error for -o - with --split")
		}
		if !bytes.Contains(output, []byte("not compatible with --split")) {
			t.Errorf("error should mention --split conflict, got: %s", output)
		}
	})

	t.Run("stdout decrypt with --auto-unzip conflicts", func(t *testing.T) {
		// Create a valid encrypted file first
		inputFile := filepath.Join(tmpDir, "unzip-test.txt")
		encFile := filepath.Join(tmpDir, "unzip-test.pcv")
		if err := os.WriteFile(inputFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			inputFile,
			"-o", encFile,
			"-p", "test",
			"-y",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("setup encrypt failed: %v\nOutput: %s", err, output)
		}

		cmd = exec.Command(binaryPath, "decrypt",
			encFile,
			"-o", "-",
			"-p", "test",
			"--auto-unzip",
		)

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected error for -o - with --auto-unzip")
		}
		if !bytes.Contains(output, []byte("not compatible with --auto-unzip")) {
			t.Errorf("error should mention --auto-unzip conflict, got: %s", output)
		}
	})

	t.Run("wrong password via stdin decrypt fails with auth error", func(t *testing.T) {
		inputData := []byte("secret")
		encFile := filepath.Join(tmpDir, "wrong-pw.pcv")

		// Encrypt with correct password.
		cmd := exec.Command(binaryPath, "encrypt",
			"-",
			"-o", encFile,
			"-p", "correctpassword",
			"-y",
		)
		cmd.Stdin = stdinFile(t, inputData)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("encrypt failed: %v\nOutput: %s", err, output)
		}

		// Try decrypt with wrong password — must fail with the auth sentinel text
		// ("authentication failed" from perrors.ErrAuthFailed). A generic non-nil
		// check passes even if the binary crashes or prints a different error.
		encrypted, err := os.ReadFile(encFile)
		if err != nil {
			t.Fatalf("reading encrypted file: %v", err)
		}
		cmd = exec.Command(binaryPath, "decrypt",
			"-",
			"-o", "-",
			"-p", "wrongpassword",
		)
		cmd.Stdin = stdinFile(t, encrypted)

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected error for wrong password, got nil")
		}
		// For v2 volumes (the default), a wrong password is caught at the
		// header-auth phase before the MAC tail is ever reached. The decrypt
		// pipeline returns *header.AuthError (NewV2PasswordOrTamperError),
		// whose message is "The password is incorrect or header is tampered".
		// The CLI prints that verbatim via reporter.PrintError("%v", err).
		// Asserting this specific substring ensures a crash or unrelated error
		// doesn't silently pass (bare non-nil check would not be falsifiable).
		const wantMsg = "password is incorrect"
		if !bytes.Contains(output, []byte(wantMsg)) {
			t.Errorf("wrong-password error must contain %q; got: %s",
				wantMsg, output)
		}
	})
}
