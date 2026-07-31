package cli

import (
	"Picocrypt-NG/internal/pcv3"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const pcv3CLIUnavailableLine = "Error: this PCV volume is not supported by this version; no output was created\n"

func loadPCV3CLIFixture(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("..", "pcv3", "testdata", "schema1-minimal.pcv"))
	if err != nil {
		t.Fatalf("read literal PCV3 fixture: %v", err)
	}
	return fixture
}

func runPCV3CLIWithStdin(t *testing.T, binaryPath, dir string, stdin []byte, args ...string) cliTestResult {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	return cliTestResult{exitCode: exitCode, stdout: stdout.Bytes(), stderr: stderr.String()}
}

func requirePCV3CLIUnavailable(t *testing.T, result cliTestResult) {
	t.Helper()
	if result.exitCode != ExitGeneralError {
		t.Fatalf("exit code = %d; want %d; stderr = %q", result.exitCode, ExitGeneralError, result.stderr)
	}
	if result.stderr != pcv3CLIUnavailableLine {
		t.Fatalf("stderr = %q; want exact %q", result.stderr, pcv3CLIUnavailableLine)
	}
	if len(result.stdout) != 0 {
		t.Fatalf("stdout = %q; want empty", result.stdout)
	}
}

func TestCLIRejectsPCV3BeforePrompts(t *testing.T) {
	fixture := loadPCV3CLIFixture(t)
	binaryPath := buildCLITestBinary(t)

	t.Run("file route precedes overwrite and password prompts", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "claimed.pcv")
		output := filepath.Join(dir, "existing.txt")
		originalOutput := []byte("must remain unchanged")
		mustWriteCLIContractFile(t, input, fixture)
		mustWriteCLIContractFile(t, output, originalOutput)

		result := runCLIInputContractCommandWithOpenStdin(t, binaryPath, dir,
			"decrypt", input, "-o", output, "--force")
		requirePCV3CLIUnavailable(t, result)
		got, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(got, originalOutput) {
			t.Fatalf("existing output = %q, err = %v; want exact original bytes", got, err)
		}
	})

	t.Run("quiet and force do not change the public error", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "claimed.pcv")
		output := filepath.Join(dir, "plaintext")
		mustWriteCLIContractFile(t, input, fixture)

		result := runCLIInputContractCommand(t, binaryPath, dir,
			"decrypt", input, "-o", output, "-p", "unused", "-q", "-y", "--force")
		requirePCV3CLIUnavailable(t, result)
		assertCLIContractAbsent(t, output, output+".incomplete")
	})

	t.Run("buffered stdin routes before output setup", func(t *testing.T) {
		dir := t.TempDir()
		output := filepath.Join(dir, "plaintext")
		result := runPCV3CLIWithStdin(t, binaryPath, dir, fixture,
			"--temp-dir", dir, "decrypt", "-", "-o", output, "--force")
		requirePCV3CLIUnavailable(t, result)
		assertCLIContractAbsent(t, output, output+".incomplete")
		if names := cliContractDirNames(t, dir); len(names) != 0 {
			t.Fatalf("stdin rejection left staging artifacts: %v", names)
		}
	})

	t.Run("stdout destination is not staged", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "claimed.pcv")
		missingTempDir := filepath.Join(dir, "must-not-be-consulted")
		mustWriteCLIContractFile(t, input, fixture)

		result := runCLIInputContractCommand(t, binaryPath, dir,
			"--temp-dir", missingTempDir, "decrypt", input, "-o", "-", "-p", "unused", "--force")
		requirePCV3CLIUnavailable(t, result)
		if names := cliContractDirNames(t, dir); len(names) != 1 || names[0] != filepath.Base(input) {
			t.Fatalf("stdout rejection filesystem = %v; want only original input", names)
		}
	})

	t.Run("typed cause survives public translation", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "claimed.pcv")
		output := filepath.Join(dir, "plaintext")
		mustWriteCLIContractFile(t, input, fixture)

		resetDecryptFlagsForDirTest()
		t.Cleanup(resetDecryptFlagsForDirTest)
		decOutput = output
		decPassword = "unused"
		decQuiet = true
		decYes = true
		err := decryptCmd.RunE(decryptCmd, []string{input})
		if err == nil || err.Error() != pcv3CLIUnavailableLine[len("Error: "):len(pcv3CLIUnavailableLine)-1] {
			t.Fatalf("RunE error = %v; want canonical public error", err)
		}
		if !errors.Is(err, pcv3.ErrReaderUnavailable) {
			t.Fatalf("RunE error = %v; want retained ErrReaderUnavailable cause", err)
		}
	})

	t.Run("partial and mismatched prefixes remain legacy eligible", func(t *testing.T) {
		for _, test := range []struct {
			name string
			data []byte
		}{
			{name: "partial", data: []byte{'P', 'C', 'V'}},
			{name: "mismatch", data: []byte{'P', 'C', 'X', 0}},
		} {
			t.Run(test.name, func(t *testing.T) {
				dir := t.TempDir()
				input := filepath.Join(dir, "legacy.pcv")
				output := filepath.Join(dir, "plaintext")
				mustWriteCLIContractFile(t, input, test.data)
				result := runCLIInputContractCommand(t, binaryPath, dir,
					"decrypt", input, "-o", output, "-p", "unused", "-q", "-y")
				if result.exitCode == 0 {
					t.Fatal("malformed legacy input unexpectedly decrypted")
				}
				if result.stderr == pcv3CLIUnavailableLine {
					t.Fatalf("legacy-eligible prefix received PCV3 terminal error: %q", result.stderr)
				}
				if len(result.stdout) != 0 {
					t.Fatalf("legacy failure stdout = %q; want empty", result.stdout)
				}
				assertCLIContractAbsent(t, output, output+".incomplete")
			})
		}
	})
}
