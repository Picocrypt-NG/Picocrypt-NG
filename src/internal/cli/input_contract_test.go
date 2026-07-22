package cli

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runCLIInputContractCommand(t *testing.T, binaryPath, dir string, args ...string) cliTestResult {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
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

func mustWriteCLIContractFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCLIInputContract(t *testing.T) {
	binaryPath := buildCLITestBinary(t)
	const password = "input-contract-test"

	t.Run("literal pattern-looking path wins over decoy", func(t *testing.T) {
		dir := t.TempDir()
		literal := filepath.Join(dir, "report[1].txt")
		decoy := filepath.Join(dir, "report1.txt")
		volumePath := filepath.Join(dir, "literal.pcv")
		recovered := filepath.Join(dir, "recovered.txt")
		mustWriteCLIContractFile(t, literal, []byte("literal brackets"))
		mustWriteCLIContractFile(t, decoy, []byte("decoy"))

		enc := runCLIInputContractCommand(t, binaryPath, "", "encrypt", literal,
			"-o", volumePath, "-p", password, "-q", "-y")
		if enc.exitCode != 0 {
			t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
		}
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", volumePath,
			"-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("decrypt exit = %d, want 0; stderr: %s", dec.exitCode, dec.stderr)
		}
		got, err := os.ReadFile(recovered)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "literal brackets" {
			t.Fatalf("recovered = %q, want literal bracket file", got)
		}
	})

	t.Run("malformed literal remains a literal path", func(t *testing.T) {
		dir := t.TempDir()
		literal := filepath.Join(dir, "video[.avi")
		volumePath := filepath.Join(dir, "literal.pcv")
		recovered := filepath.Join(dir, "recovered.avi")
		mustWriteCLIContractFile(t, literal, []byte("literal malformed bracket"))

		enc := runCLIInputContractCommand(t, binaryPath, "", "encrypt", literal,
			"-o", volumePath, "-p", password, "-q", "-y")
		if enc.exitCode != 0 {
			t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
		}
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", volumePath,
			"-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("decrypt exit = %d, want 0; stderr: %s", dec.exitCode, dec.stderr)
		}
		got, err := os.ReadFile(recovered)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "literal malformed bracket" {
			t.Fatalf("recovered = %q, want malformed literal file", got)
		}
	})

	t.Run("explicit glob round trip preserves exactly matched entries", func(t *testing.T) {
		dir := t.TempDir()
		matchedA := filepath.Join(dir, "alpha.txt")
		matchedB := filepath.Join(dir, "bravo.txt")
		mustWriteCLIContractFile(t, matchedA, []byte("alpha"))
		mustWriteCLIContractFile(t, matchedB, []byte("bravo"))
		mustWriteCLIContractFile(t, filepath.Join(dir, "ignored.log"), []byte("ignored"))
		volumePath := filepath.Join(dir, "glob.pcv")
		recovered := filepath.Join(dir, "glob.zip")

		enc := runCLIInputContractCommand(t, binaryPath, "", "encrypt", "--glob", filepath.Join(dir, "*.txt"), "-o", volumePath, "-p", password, "-q", "-y")
		if enc.exitCode != 0 {
			t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
		}
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", volumePath, "-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("decrypt exit = %d, want 0; stderr: %s", dec.exitCode, dec.stderr)
		}
		assertCLIContractZip(t, recovered, map[string][]byte{"alpha.txt": []byte("alpha"), "bravo.txt": []byte("bravo")})
	})

	t.Run("positional and overlapping glob have unique entries", func(t *testing.T) {
		dir := t.TempDir()
		alpha := filepath.Join(dir, "alpha.txt")
		bravo := filepath.Join(dir, "bravo.txt")
		mustWriteCLIContractFile(t, alpha, []byte("alpha"))
		mustWriteCLIContractFile(t, bravo, []byte("bravo"))
		volumePath := filepath.Join(dir, "overlap.pcv")
		recovered := filepath.Join(dir, "overlap.zip")

		enc := runCLIInputContractCommand(t, binaryPath, "", "encrypt", alpha, "--glob", filepath.Join(dir, "*.txt"), "-o", volumePath, "-p", password, "-q", "-y")
		if enc.exitCode != 0 {
			t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
		}
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", volumePath, "-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("decrypt exit = %d, want 0; stderr: %s", dec.exitCode, dec.stderr)
		}
		assertCLIContractZip(t, recovered, map[string][]byte{"alpha.txt": []byte("alpha"), "bravo.txt": []byte("bravo")})
	})

	t.Run("literal glob-like operand gives migration hint", func(t *testing.T) {
		dir := t.TempDir()
		volumePath := filepath.Join(dir, "literal.pcv")
		result := runCLIInputContractCommand(t, binaryPath, "", "encrypt", filepath.Join(dir, "*.txt"), "-o", volumePath, "-p", password, "-q", "-y")
		if result.exitCode == 0 || !strings.Contains(result.stderr, "use --glob") {
			t.Fatalf("literal glob result = exit %d stderr %q, want migration error", result.exitCode, result.stderr)
		}
		assertCLIContractAbsent(t, volumePath, volumePath+".incomplete")
	})

	t.Run("malformed and empty globs have distinct errors", func(t *testing.T) {
		dir := t.TempDir()
		malformedOut := filepath.Join(dir, "malformed.pcv")
		malformed := runCLIInputContractCommand(t, binaryPath, "", "encrypt", "--glob", "[", "-o", malformedOut, "-p", password, "-q", "-y")
		if malformed.exitCode == 0 || !strings.Contains(malformed.stderr, "invalid glob pattern") {
			t.Fatalf("malformed glob result = exit %d stderr %q", malformed.exitCode, malformed.stderr)
		}
		assertCLIContractAbsent(t, malformedOut, malformedOut+".incomplete")

		noMatchOut := filepath.Join(dir, "empty.pcv")
		noMatch := runCLIInputContractCommand(t, binaryPath, "", "encrypt", "--glob", filepath.Join(dir, "*.none"), "-o", noMatchOut, "-p", password, "-q", "-y")
		if noMatch.exitCode == 0 || !strings.Contains(noMatch.stderr, "matched no paths") {
			t.Fatalf("empty glob result = exit %d stderr %q", noMatch.exitCode, noMatch.stderr)
		}
		assertCLIContractAbsent(t, noMatchOut, noMatchOut+".incomplete")
	})

	t.Run("stdin cannot combine with operand or glob before input read", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "file.txt")
		mustWriteCLIContractFile(t, file, []byte("file"))
		for _, args := range [][]string{
			{"encrypt", "-", file, "-o", filepath.Join(dir, "mixed.pcv"), "-p", password, "-q", "-y"},
			{"encrypt", file, "-", "-o", filepath.Join(dir, "reversed.pcv"), "-p", password, "-q", "-y"},
			{"encrypt", "-", "--glob", filepath.Join(dir, "*.txt"), "-o", filepath.Join(dir, "glob.pcv"), "-p", password, "-q", "-y"},
		} {
			result := runCLIInputContractCommand(t, binaryPath, "", args...)
			if result.exitCode == 0 || !strings.Contains(result.stderr, "cannot be combined") {
				t.Fatalf("stdin exclusion result = exit %d stderr %q", result.exitCode, result.stderr)
			}
		}
	})

	t.Run("dash-prefixed path after separator round trips", func(t *testing.T) {
		dir := t.TempDir()
		literal := "-report.txt"
		mustWriteCLIContractFile(t, filepath.Join(dir, literal), []byte("dash path"))
		volumePath := filepath.Join(dir, "dash.pcv")
		recovered := filepath.Join(dir, "recovered.txt")
		enc := runCLIInputContractCommand(t, binaryPath, dir, "encrypt", "-o", volumePath, "-p", password, "-q", "-y", "--", literal)
		if enc.exitCode != 0 {
			t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
		}
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", volumePath, "-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("decrypt exit = %d, want 0; stderr: %s", dec.exitCode, dec.stderr)
		}
		got, err := os.ReadFile(recovered)
		if err != nil || string(got) != "dash path" {
			t.Fatalf("recovered dash path = %q, err = %v", got, err)
		}
	})

	t.Run("legacy input flag is hidden tombstone", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "plain.txt")
		volumePath := filepath.Join(dir, "legacy.pcv")
		mustWriteCLIContractFile(t, file, []byte("plain"))
		legacy := runCLIInputContractCommand(t, binaryPath, "", "encrypt", "-i", file, "-o", volumePath, "-p", password, "-q", "-y")
		if legacy.exitCode == 0 || !strings.Contains(legacy.stderr, "--input/-i was removed") {
			t.Fatalf("legacy input result = exit %d stderr %q", legacy.exitCode, legacy.stderr)
		}
		assertCLIContractAbsent(t, volumePath, volumePath+".incomplete")
		help := runCLIInputContractCommand(t, binaryPath, "", "encrypt", "--help")
		if help.exitCode != 0 || strings.Contains(help.stdoutString(), "--input") {
			t.Fatalf("encrypt help exposed legacy input: exit %d stdout %q", help.exitCode, help.stdoutString())
		}
	})

	t.Run("decrypt requires exactly one operand before output", func(t *testing.T) {
		dir := t.TempDir()
		output := filepath.Join(dir, "recovered")
		result := runCLIInputContractCommand(t, binaryPath, "", "decrypt", "one.pcv", "two.pcv", "-o", output, "-p", password, "-q", "-y")
		if result.exitCode == 0 || !strings.Contains(result.stderr, "accepts 1 arg") {
			t.Fatalf("decrypt count result = exit %d stderr %q", result.exitCode, result.stderr)
		}
		assertCLIContractAbsent(t, output, output+".incomplete")
	})

	t.Run("compression staging collision leaves source unchanged", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "archive.tmp")
		output := filepath.Join(dir, "archive.pcv")
		mustWriteCLIContractFile(t, input, []byte("must survive"))
		result := runCLIInputContractCommand(t, binaryPath, "", "encrypt", input, "--compress", "-o", output, "-p", password, "-q", "-y")
		if result.exitCode == 0 || !strings.Contains(result.stderr, "conflicts with output artifact") {
			t.Fatalf("collision result = exit %d stderr %q", result.exitCode, result.stderr)
		}
		got, err := os.ReadFile(input)
		if err != nil || string(got) != "must survive" {
			t.Fatalf("collision changed input = %q, err = %v", got, err)
		}
		assertCLIContractAbsent(t, output, output+".incomplete", filepath.Join(dir, "archive.tmp.incomplete"))
	})
}

func (result cliTestResult) stdoutString() string {
	return string(result.stdout)
}

func assertCLIContractAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("unexpected artifact %q: %v", path, err)
		}
	}
}

func assertCLIContractZip(t *testing.T, path string, want map[string][]byte) {
	t.Helper()
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	got := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		if _, exists := got[file.Name]; exists {
			t.Fatalf("duplicate zip entry %q", file.Name)
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		got[file.Name] = content
	}
	if len(got) != len(want) {
		t.Fatalf("zip entry count = %d, want %d: got %#v", len(got), len(want), got)
	}
	for name, wantContent := range want {
		if content, ok := got[name]; !ok || !bytes.Equal(content, wantContent) {
			t.Fatalf("zip entry %q = %q, want %q", name, content, wantContent)
		}
	}
}
