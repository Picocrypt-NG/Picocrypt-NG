package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

// Run the real CLI with isolated staging so payload transport and cleanup are
// observable independently of its terminal status. Native Windows cannot grant
// the durable plaintext owner required for stdout; that committed temp is kept.
func runStreamIntegrationCommand(t *testing.T, cmd *exec.Cmd, retainedPlaintext []byte) cliTestResult {
	t.Helper()
	stagingDir := t.TempDir()
	cmd.Args = append(cmd.Args, "-q", "--temp-dir", stagingDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running CLI: %v", err)
		}
		exitCode = exitErr.ExitCode()
	}
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" && retainedPlaintext != nil {
		if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "picocrypt-out-") {
			t.Fatalf("uncertain plaintext stdout staging = %v; want only retained output", entries)
		}
		retained, err := os.ReadFile(filepath.Join(stagingDir, entries[0].Name()))
		if err != nil || !bytes.Equal(retained, retainedPlaintext) {
			t.Fatalf("retained plaintext mismatch: got %d bytes, want %d; read error: %v", len(retained), len(retainedPlaintext), err)
		}
	} else if len(entries) != 0 {
		t.Fatalf("CLI left stdin/stdout staging files: %v", entries)
	}
	return cliTestResult{exitCode: exitCode, stdout: stdout.Bytes(), stderr: stderr.String()}
}

func requireNativePCV3CiphertextStream(t *testing.T, result cliTestResult) {
	t.Helper()
	terminal := result
	terminal.stdout = nil
	if runtime.GOOS == "windows" {
		const cleanupWarning = "Warning: cleanup of operation-owned temporary files could not be confirmed\n"
		if !strings.HasSuffix(terminal.stderr, cleanupWarning) {
			t.Fatalf("native ciphertext stream lost cleanup uncertainty: %q", terminal.stderr)
		}
		terminal.stderr = strings.TrimSuffix(terminal.stderr, cleanupWarning)
	}
	requireNativePCV3Published(t, terminal, "")
}

func requireNativePCV3PlaintextStream(t *testing.T, result cliTestResult, plaintext []byte) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Authentication/publication succeeded, but no durable retained owner
		// exists. The refused callback must never publish plaintext to stdout.
		wantStderr := "Outcome: success\nPublication: published-durability-uncertain\n" +
			nativePCV3DurabilityWarning +
			"Warning: an operation callback failed; clean completion was not confirmed\n"
		if result.exitCode != ExitPCV3DurabilityUncertain || len(result.stdout) != 0 || result.stderr != wantStderr {
			t.Fatalf("native plaintext stdout = exit %d stdout %q stderr %q; want exit 3, no stdout and %q", result.exitCode, result.stdout, result.stderr, wantStderr)
		}
		return
	}
	terminal := result
	terminal.stdout = nil
	requireNativePCV3Published(t, terminal, "")
	if !bytes.Equal(result.stdout, plaintext) {
		t.Fatalf("plaintext stdout mismatch: got %d bytes, want %d", len(result.stdout), len(plaintext))
	}
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

		cmd := exec.Command(
			binaryPath, "encrypt",
			"-",
			"-o", outputFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = stdinFile(t, inputData)

		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")

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
		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
			outputFile,
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")

		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("reading decrypted file: %v", err)
		}
		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("stdin encrypt preserves existing output even with --yes", func(t *testing.T) {
		inputData := []byte("stdin overwrite check")
		outputFile := filepath.Join(tmpDir, "stdin-overwrite-encrypt.pcv")
		if err := os.WriteFile(outputFile, []byte("existing"), 0o644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(
			binaryPath, "encrypt",
			"-",
			"-o", outputFile,
			"-p", testPassword, "--yes",
		)
		cmd.Stdin = stdinFile(t, inputData)

		result := runStreamIntegrationCommand(t, cmd, nil)
		if result.exitCode != ExitGeneralError || len(result.stdout) != 0 {
			t.Fatalf("stdin encrypt no-replace refusal = %+v", result)
		}
		if !strings.Contains(result.stderr, "--yes does not replace PCV3 outputs") {
			t.Fatalf("expected no-replace guidance, got: %s", result.stderr)
		}
		got, readErr := os.ReadFile(outputFile)
		if readErr != nil || string(got) != "existing" {
			t.Fatalf("occupied output changed: %q, %v", got, readErr)
		}
	})

	t.Run("file encrypt to stdout", func(t *testing.T) {
		inputData := []byte("secret data for stdout encryption test")
		inputFile := filepath.Join(tmpDir, "stdout-input.txt")
		if err := os.WriteFile(inputFile, inputData, 0o644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(
			binaryPath, "encrypt",
			inputFile,
			"-o", "-",
			"-p", testPassword,
		)

		result := runStreamIntegrationCommand(t, cmd, nil)
		requireNativePCV3CiphertextStream(t, result)
		encrypted := result.stdout
		if source, err := os.ReadFile(inputFile); err != nil || !bytes.Equal(source, inputData) {
			t.Fatalf("stdout encryption changed source: %q, %v", source, err)
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
		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
			encryptedFile,
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")

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

		cmd := exec.Command(
			binaryPath, "encrypt",
			"-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, inputData)

		result := runStreamIntegrationCommand(t, cmd, nil)
		requireNativePCV3CiphertextStream(t, result)
		encrypted := result.stdout

		if len(encrypted) == 0 {
			t.Fatal("no encrypted data produced")
		}

		// Decrypt via stdin->stdout
		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
			"-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, encrypted)

		result = runStreamIntegrationCommand(t, cmd, inputData)
		requireNativePCV3PlaintextStream(t, result, inputData)
	})

	t.Run("stdin decrypt from file", func(t *testing.T) {
		inputData := []byte("data to decrypt from stdin")
		encryptedFile := filepath.Join(tmpDir, "for-stdin-decrypt.pcv")

		// Create encrypted file first
		cmd := exec.Command(
			binaryPath, "encrypt",
			"-",
			"-o", encryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = stdinFile(t, inputData)
		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")

		// Read encrypted file to feed via stdin
		encrypted, err := os.ReadFile(encryptedFile)
		if err != nil {
			t.Fatal(err)
		}

		decryptedFile := filepath.Join(tmpDir, "stdin-decrypt-output")
		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
			"-",
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = stdinFile(t, encrypted)

		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")

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

		cmd := exec.Command(
			binaryPath, "decrypt",
			"-",
			"-o", existingOutput,
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, inputData)

		result := runStreamIntegrationCommand(t, cmd, nil)
		if result.exitCode != ExitGeneralError || len(result.stdout) != 0 {
			t.Fatalf("stdin decrypt overwrite refusal = %+v", result)
		}
		if !strings.Contains(result.stderr, "use -y to overwrite") {
			t.Fatalf("expected explicit -y guidance, got: %s", result.stderr)
		}
		if existing, err := os.ReadFile(existingOutput); err != nil || string(existing) != "existing" {
			t.Fatalf("stdin decrypt changed existing output: %q, %v", existing, err)
		}
	})

	t.Run("file decrypt to stdout", func(t *testing.T) {
		inputData := []byte("data to decrypt to stdout")
		encryptedFile := filepath.Join(tmpDir, "for-stdout-decrypt.pcv")

		// Create encrypted file
		cmd := exec.Command(
			binaryPath, "encrypt",
			"-",
			"-o", encryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = stdinFile(t, inputData)
		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")
		encrypted, err := os.ReadFile(encryptedFile)
		if err != nil {
			t.Fatal(err)
		}

		// Decrypt to stdout
		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
			encryptedFile,
			"-o", "-",
			"-p", testPassword,
		)

		result := runStreamIntegrationCommand(t, cmd, inputData)
		requireNativePCV3PlaintextStream(t, result, inputData)
		if source, err := os.ReadFile(encryptedFile); err != nil || !bytes.Equal(source, encrypted) {
			t.Fatalf("stdout decrypt changed encrypted source: %q, %v", source, err)
		}
	})

	t.Run("large data through pipeline", func(t *testing.T) {
		// Test with 1 MiB of data
		inputData := make([]byte, 1024*1024)
		for i := range inputData {
			inputData[i] = byte(i % 256)
		}

		cmd := exec.Command(
			binaryPath, "encrypt",
			"-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, inputData)

		result := runStreamIntegrationCommand(t, cmd, nil)
		requireNativePCV3CiphertextStream(t, result)
		encrypted := result.stdout
		if len(encrypted) <= len(inputData) {
			t.Fatal("large-data stdout output must contain ciphertext and header")
		}

		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
			"-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = stdinFile(t, encrypted)

		result = runStreamIntegrationCommand(t, cmd, inputData)
		requireNativePCV3PlaintextStream(t, result, inputData)
	})

	t.Run("PCV3 archive extraction works with auto-generated output path", func(t *testing.T) {
		inputA := filepath.Join(tmpDir, "auto-unzip-a.txt")
		inputB := filepath.Join(tmpDir, "auto-unzip-b.txt")
		if err := os.WriteFile(inputA, []byte("alpha"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inputB, []byte("bravo"), 0o644); err != nil {
			t.Fatal(err)
		}

		volumePath := filepath.Join(tmpDir, "auto-unzip.pcv")
		cmd := exec.Command(
			binaryPath, "encrypt",
			inputA, inputB,
			"-o", volumePath,
			"-p", testPassword,
			"-y",
		)
		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")
		encrypted, err := os.ReadFile(volumePath)
		if err != nil {
			t.Fatal(err)
		}

		extractedDir := filepath.Join(tmpDir, "extracted")
		if err := os.Mkdir(extractedDir, 0o700); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
			volumePath,
			"-p", testPassword,
			"-y",
			"--pcv3-archive=extract", "--pcv3-extract-to", extractedDir,
		)
		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")

		info, err := os.Stat(extractedDir)
		if err != nil {
			t.Fatalf("expected extracted directory %q: %v", extractedDir, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected %q to be a directory after auto-unzip", extractedDir)
		}

		for path, want := range map[string]string{inputA: "alpha", inputB: "bravo"} {
			for _, candidate := range []string{path, filepath.Join(extractedDir, filepath.Base(path))} {
				if got, err := os.ReadFile(candidate); err != nil || string(got) != want {
					t.Fatalf("archive/source %q = %q, %v; want %q", candidate, got, err, want)
				}
			}
		}
		if source, err := os.ReadFile(volumePath); err != nil || !bytes.Equal(source, encrypted) {
			t.Fatalf("archive extraction changed encrypted source: %q, %v", source, err)
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
		cmd := exec.Command(
			binaryPath, "encrypt",
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

		cmd := exec.Command(
			binaryPath, "encrypt",
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

		cmd := exec.Command(
			binaryPath, "encrypt",
			inputFile,
			"-o", encFile,
			"-p", "test",
			"-y",
		)
		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")

		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
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
		cmd := exec.Command(
			binaryPath, "encrypt",
			"-",
			"-o", encFile,
			"-p", "correctpassword",
			"-y",
		)
		cmd.Stdin = stdinFile(t, inputData)
		requireNativePCV3Published(t, runStreamIntegrationCommand(t, cmd, nil), "")

		// Authentication refusal must not release plaintext or leave staging files.
		encrypted, err := os.ReadFile(encFile)
		if err != nil {
			t.Fatalf("reading encrypted file: %v", err)
		}
		cmd = exec.Command(
			binaryPath, "decrypt", "--pcv3-factors=password",
			"-",
			"-o", "-",
			"-p", "wrongpassword",
		)
		cmd.Stdin = stdinFile(t, encrypted)

		result := runStreamIntegrationCommand(t, cmd, nil)
		if result.exitCode != ExitGeneralError || len(result.stdout) != 0 ||
			result.stderr != "Outcome: credentials-or-damage\nPublication: not-attempted\n" {
			t.Fatalf("stdin authentication refusal = %+v", result)
		}
		if source, err := os.ReadFile(encFile); err != nil || !bytes.Equal(source, encrypted) {
			t.Fatalf("authentication refusal changed encrypted source: %v", err)
		}
	})
}
