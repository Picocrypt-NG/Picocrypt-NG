package cli

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
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

func runCLIInputContractCommandWithOpenStdin(t *testing.T, binaryPath, dir string, args ...string) cliTestResult {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	cmd.Stdin = reader
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		t.Fatal(err)
	}
	_ = reader.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	select {
	case waitErr = <-done:
		_ = writer.Close()
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		_ = writer.Close()
		waitErr = <-done
		t.Fatalf("command did not exit before stdin EOF; killed after timeout: %v; stderr: %s", waitErr, stderr.String())
	}

	exitCode := 0
	if waitErr != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
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

func requireCLIContractZipEntry(t *testing.T, zipPath, name string, want []byte) {
	t.Helper()

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open recovered ZIP: %v", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Errorf("close recovered ZIP: %v", err)
		}
	}()
	wantName := filepath.ToSlash(name)
	for _, file := range reader.File {
		if file.Name != wantName {
			continue
		}
		entry, err := file.Open()
		if err != nil {
			t.Fatalf("open recovered ZIP entry %q: %v", wantName, err)
		}
		got, readErr := io.ReadAll(entry)
		closeErr := entry.Close()
		if readErr != nil {
			t.Fatalf("read recovered ZIP entry %q: %v", wantName, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close recovered ZIP entry %q: %v", wantName, closeErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("recovered ZIP entry %q = %q, want %q", wantName, got, want)
		}
		return
	}
	t.Fatalf("recovered ZIP does not contain %q", wantName)
}

func cliContractDirNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("read directory %s: %v", path, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
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

	t.Run("decrypt yes never authorizes replacing the encrypted input", func(t *testing.T) {
		dir := t.TempDir()
		plaintext := []byte("public CLI alias-safety round-trip")
		input := filepath.Join(dir, "input.txt")
		volumePath := filepath.Join(dir, "volume.pcv")
		mustWriteCLIContractFile(t, input, plaintext)

		enc := runCLIInputContractCommand(t, binaryPath, "", "encrypt", input,
			"-o", volumePath, "-p", password, "-q", "-y")
		if enc.exitCode != 0 {
			t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
		}
		before, err := os.ReadFile(volumePath)
		if err != nil {
			t.Fatalf("read encrypted fixture: %v", err)
		}

		rejected := runCLIInputContractCommand(t, binaryPath, "", "decrypt", volumePath,
			"-o", volumePath, "-p", password, "-q", "-y")
		if rejected.exitCode == 0 {
			t.Fatalf("decrypt replaced its encrypted input despite -y; stderr: %s", rejected.stderr)
		}
		if !strings.Contains(rejected.stderr, "OutputFile") || !strings.Contains(rejected.stderr, "protected source") {
			t.Fatalf("decrypt alias rejection was not explicit: %q", rejected.stderr)
		}
		after, err := os.ReadFile(volumePath)
		if err != nil {
			t.Fatalf("read protected encrypted input: %v", err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("rejected CLI decrypt changed the encrypted input")
		}

		safeOutput := filepath.Join(dir, "safe-output.txt")
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", volumePath,
			"-o", safeOutput, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("safe decrypt exit = %d, want 0; stderr: %s", dec.exitCode, dec.stderr)
		}
		got, err := os.ReadFile(safeOutput)
		if err != nil {
			t.Fatalf("read safe decrypted output: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("safe decrypted output = %q, want %q", got, plaintext)
		}
	})

	t.Run("decrypt yes never authorizes an existing auto-unzip extraction root", func(t *testing.T) {
		dir := t.TempDir()
		inputA := filepath.Join(dir, "input-a.txt")
		inputB := filepath.Join(dir, "input-b.txt")
		volumePath := filepath.Join(dir, "archive.pcv")
		mustWriteCLIContractFile(t, inputA, []byte("first real ZIP payload"))
		mustWriteCLIContractFile(t, inputB, []byte("second real ZIP payload"))

		enc := runCLIInputContractCommand(t, binaryPath, "", "encrypt", inputA, inputB,
			"-o", volumePath, "-p", password, "-q", "-y")
		if enc.exitCode != 0 {
			t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
		}

		for _, tc := range []struct {
			name       string
			outputZip  bool
			rootIsFile bool
		}{
			{name: "suffixless regular file", rootIsFile: true},
			{name: "suffixless nonempty directory"},
			{name: "zip output with occupied derived directory", outputZip: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				caseDir := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
				if err := os.Mkdir(caseDir, 0o700); err != nil {
					t.Fatalf("create case directory: %v", err)
				}
				existingRoot := filepath.Join(caseDir, "recovered")
				outputPath := existingRoot
				if tc.outputZip {
					outputPath += ".zip"
				}
				protectedBytes := []byte("existing extraction root must remain byte-for-byte unchanged")
				protectedPath := existingRoot
				if tc.rootIsFile {
					mustWriteCLIContractFile(t, existingRoot, protectedBytes)
				} else {
					if err := os.Mkdir(existingRoot, 0o700); err != nil {
						t.Fatalf("create occupied extraction directory: %v", err)
					}
					protectedPath = filepath.Join(existingRoot, "foreign.txt")
					mustWriteCLIContractFile(t, protectedPath, protectedBytes)
				}
				protectedInfo, err := os.Lstat(existingRoot)
				if err != nil {
					t.Fatalf("inspect protected extraction root: %v", err)
				}
				entriesBefore := cliContractDirNames(t, caseDir)

				rejected := runCLIInputContractCommandWithOpenStdin(
					t,
					binaryPath,
					"",
					"decrypt",
					volumePath,
					"-o",
					outputPath,
					"--auto-unzip",
					"-q",
					"-y",
				)
				if rejected.exitCode == 0 {
					t.Fatalf("decrypt replaced an existing auto-unzip extraction root; stderr: %s", rejected.stderr)
				}
				if !strings.Contains(rejected.stderr, "auto-unzip extraction root") {
					t.Fatalf("auto-unzip root rejection was not explicit: %q", rejected.stderr)
				}

				currentInfo, err := os.Lstat(existingRoot)
				if err != nil {
					t.Fatalf("inspect protected extraction root after rejection: %v", err)
				}
				if currentInfo.Mode().IsRegular() != tc.rootIsFile ||
					!os.SameFile(protectedInfo, currentInfo) {
					t.Fatal("protected auto-unzip extraction root changed type or identity")
				}
				got, err := os.ReadFile(protectedPath)
				if err != nil {
					t.Fatalf("read protected extraction-root data: %v", err)
				}
				if !bytes.Equal(got, protectedBytes) {
					t.Fatalf("protected extraction-root data = %q, want %q", got, protectedBytes)
				}
				entriesAfter := cliContractDirNames(t, caseDir)
				if !slices.Equal(entriesAfter, entriesBefore) {
					t.Fatalf("directory entries changed after rejected decrypt: before %v, after %v", entriesBefore, entriesAfter)
				}
			})
		}
	})

	t.Run("failed split preserves occupied chunk and recoverable volume", func(t *testing.T) {
		dir := t.TempDir()
		plaintext := []byte("recoverable output after safe split refusal")
		input := filepath.Join(dir, "input.txt")
		output := filepath.Join(dir, "output.pcv")
		occupiedChunk := output + ".0"
		occupiedBytes := []byte("foreign chunk must remain untouched")
		mustWriteCLIContractFile(t, input, plaintext)
		mustWriteCLIContractFile(t, occupiedChunk, occupiedBytes)

		enc := runCLIInputContractCommand(t, binaryPath, "", "encrypt", input,
			"-o", output,
			"-p", password,
			"--split",
			"--split-size", "2",
			"--split-unit", "Total",
			"-q",
			"-y",
		)
		if enc.exitCode == 0 {
			t.Fatal("split unexpectedly replaced an occupied chunk")
		}
		if !strings.Contains(enc.stderr, "split artifact already exists") {
			t.Fatalf("split refusal was not explicit: %q", enc.stderr)
		}
		gotChunk, err := os.ReadFile(occupiedChunk)
		if err != nil {
			t.Fatalf("read occupied chunk: %v", err)
		}
		if !bytes.Equal(gotChunk, occupiedBytes) {
			t.Fatalf("occupied chunk = %q, want %q", gotChunk, occupiedBytes)
		}

		recovered := filepath.Join(dir, "recovered.txt")
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", output,
			"-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("published volume was not recoverable after split refusal: exit %d; stderr: %s", dec.exitCode, dec.stderr)
		}
		got, err := os.ReadFile(recovered)
		if err != nil {
			t.Fatalf("read recovered plaintext: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("recovered plaintext = %q, want %q", got, plaintext)
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

	t.Run("two-file directory uses directory default output and exact archive paths", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "documents")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		alpha := filepath.Join(dir, "alpha.txt")
		bravo := filepath.Join(dir, "bravo.bin")
		mustWriteCLIContractFile(t, alpha, []byte("alpha directory bytes"))
		mustWriteCLIContractFile(t, bravo, []byte{0x00, 0x01, 0xfe, 0xff})
		volumePath := dir + ".zip.pcv"
		recovered := filepath.Join(root, "recovered.zip")

		enc := runCLIInputContractCommand(t, binaryPath, root, "encrypt", dir, "-p", password, "-q", "-y")
		if enc.exitCode != 0 {
			t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
		}
		if _, err := os.Stat(volumePath); err != nil {
			t.Fatalf("default directory output %q missing: %v", volumePath, err)
		}
		assertCLIContractAbsent(t, filepath.Join(root, "encrypted.zip.pcv"))

		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", volumePath, "-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("decrypt exit = %d, want 0; stderr: %s", dec.exitCode, dec.stderr)
		}
		assertCLIContractZip(t, recovered, map[string][]byte{
			"documents/alpha.txt": []byte("alpha directory bytes"),
			"documents/bravo.bin": {0x00, 0x01, 0xfe, 0xff},
		})
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
		for _, tc := range []struct {
			name   string
			output string
			args   []string
		}{
			{name: "stdin first", output: filepath.Join(dir, "mixed.pcv"), args: []string{"encrypt", "-", file, "-o", filepath.Join(dir, "mixed.pcv"), "-p", password, "-q", "-y"}},
			{name: "stdin last", output: filepath.Join(dir, "reversed.pcv"), args: []string{"encrypt", file, "-", "-o", filepath.Join(dir, "reversed.pcv"), "-p", password, "-q", "-y"}},
			{name: "stdin and glob", output: filepath.Join(dir, "glob.pcv"), args: []string{"encrypt", "-", "--glob", filepath.Join(dir, "*.txt"), "-o", filepath.Join(dir, "glob.pcv"), "-p", password, "-q", "-y"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				result := runCLIInputContractCommandWithOpenStdin(t, binaryPath, "", tc.args...)
				if result.exitCode == 0 || !strings.Contains(result.stderr, "cannot be combined") {
					t.Fatalf("stdin exclusion result = exit %d stderr %q", result.exitCode, result.stderr)
				}
				assertCLIContractAbsent(t, tc.output, tc.output+".incomplete")
			})
		}
	})

	t.Run("invalid split size is rejected before password input or artifacts", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "input.txt")
		output := filepath.Join(dir, "out.pcv")
		mustWriteCLIContractFile(t, input, []byte("input stays unread by validation"))
		maxInt := int(^uint(0) >> 1)

		result := runCLIInputContractCommandWithOpenStdin(t, binaryPath, "", "encrypt", input,
			"-o", output, "--split", "--split-size", strconv.Itoa(maxInt), "--split-unit", "TiB", "-q", "-y")
		if result.exitCode == 0 || !strings.Contains(result.stderr, "chunk size too large") {
			t.Fatalf("invalid split result = exit %d stderr %q, want overflow diagnostic", result.exitCode, result.stderr)
		}
		assertCLIContractAbsent(t, output, output+".incomplete", output+".0", output+".0.incomplete")
	})

	t.Run("missing keyfile is rejected before stdin buffering", func(t *testing.T) {
		dir := t.TempDir()
		output := filepath.Join(dir, "out.pcv")
		missingKeyfile := filepath.Join(dir, "missing.key")

		result := runCLIInputContractCommandWithOpenStdin(t, binaryPath, "", "encrypt", "-",
			"-o", output, "-p", password, "-k", missingKeyfile, "-q", "-y")
		if result.exitCode == 0 || !strings.Contains(result.stderr, "keyfile not found") {
			t.Fatalf("missing keyfile result = exit %d stderr %q", result.exitCode, result.stderr)
		}
		assertCLIContractAbsent(t, output, output+".incomplete")
	})

	t.Run("stdin keyfile final-output collision is rejected before input read", func(t *testing.T) {
		dir := t.TempDir()
		output := filepath.Join(dir, "final.pcv")
		keyfileBytes := []byte("stdin collision keyfile exact bytes")
		mustWriteCLIContractFile(t, output, keyfileBytes)

		result := runCLIInputContractCommandWithOpenStdin(t, binaryPath, "", "encrypt", "-",
			"-o", strings.TrimSuffix(output, ".pcv"), "-p", password, "-k", output, "-q", "-y")
		if result.exitCode == 0 || !strings.Contains(result.stderr, "conflicts with output artifact") {
			t.Fatalf("stdin collision result = exit %d stderr %q", result.exitCode, result.stderr)
		}
		got, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(got, keyfileBytes) {
			t.Fatalf("keyfile = %q, err = %v; want exact original bytes", got, err)
		}
	})

	t.Run("legacy staging-named keyfiles round trip", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			keyfile  func(string) string
			compress bool
		}{
			{name: "incomplete suffix", keyfile: func(output string) string { return output + ".incomplete" }},
			{name: "tmp suffix", keyfile: func(output string) string { return strings.TrimSuffix(output, ".pcv") + ".tmp" }, compress: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				input := filepath.Join(dir, "input.txt")
				inputBytes := []byte("legacy staging names are ordinary protected paths")
				mustWriteCLIContractFile(t, input, inputBytes)
				output := filepath.Join(dir, "output.pcv")
				keyfile := tc.keyfile(output)
				keyfileBytes := []byte("keyfile using a formerly reserved staging name")
				mustWriteCLIContractFile(t, keyfile, keyfileBytes)

				args := []string{"encrypt", input, "-o", output, "-p", password, "-k", keyfile, "-q", "-y"}
				if tc.compress {
					args = append(args, "--compress")
				}
				enc := runCLIInputContractCommand(t, binaryPath, "", args...)
				if enc.exitCode != 0 {
					t.Fatalf("encrypt exit = %d, want 0; stderr: %s", enc.exitCode, enc.stderr)
				}
				recovered := filepath.Join(dir, "recovered")
				if tc.compress {
					recovered += ".zip"
				}
				dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", output,
					"-o", recovered, "-p", password, "-k", keyfile, "-q", "-y")
				if dec.exitCode != 0 {
					t.Fatalf("decrypt exit = %d, want 0; stderr: %s", dec.exitCode, dec.stderr)
				}
				if tc.compress {
					requireCLIContractZipEntry(t, recovered, filepath.Base(input), inputBytes)
				} else {
					got, err := os.ReadFile(recovered)
					if err != nil || !bytes.Equal(got, inputBytes) {
						t.Fatalf("recovered = %q, err = %v; want %q", got, err, inputBytes)
					}
				}
				gotKeyfile, err := os.ReadFile(keyfile)
				if err != nil || !bytes.Equal(gotKeyfile, keyfileBytes) {
					t.Fatalf("keyfile = %q, err = %v; want exact original bytes", gotKeyfile, err)
				}
			})
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

	t.Run("tmp-named source round trips with compression", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "archive.tmp")
		output := filepath.Join(dir, "archive.pcv")
		inputBytes := []byte("tmp-named source must survive and round trip")
		mustWriteCLIContractFile(t, input, inputBytes)
		result := runCLIInputContractCommand(t, binaryPath, "", "encrypt", input, "--compress", "-o", output, "-p", password, "-q", "-y")
		if result.exitCode != 0 {
			t.Fatalf("encrypt result = exit %d stderr %q", result.exitCode, result.stderr)
		}
		got, err := os.ReadFile(input)
		if err != nil || !bytes.Equal(got, inputBytes) {
			t.Fatalf("encryption changed input = %q, err = %v", got, err)
		}
		recovered := filepath.Join(dir, "recovered.zip")
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", output, "-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("decrypt result = exit %d stderr %q", dec.exitCode, dec.stderr)
		}
		requireCLIContractZipEntry(t, recovered, filepath.Base(input), inputBytes)
	})

	t.Run("tmp-named directory round trips", func(t *testing.T) {
		dir := t.TempDir()
		selection := filepath.Join(dir, "archive.tmp")
		if err := os.Mkdir(selection, 0o700); err != nil {
			t.Fatal(err)
		}
		leaf := filepath.Join(selection, "payload.txt")
		output := filepath.Join(dir, "archive.pcv")
		leafBytes := []byte("tmp-named directory must survive and round trip")
		mustWriteCLIContractFile(t, leaf, leafBytes)

		result := runCLIInputContractCommand(t, binaryPath, "", "encrypt", selection, "-o", output, "-p", password, "-q", "-y")
		if result.exitCode != 0 {
			t.Fatalf("directory encrypt result = exit %d stderr %q", result.exitCode, result.stderr)
		}
		got, err := os.ReadFile(leaf)
		if err != nil || !bytes.Equal(got, leafBytes) {
			t.Fatalf("directory encryption changed leaf = %q, err = %v", got, err)
		}
		recovered := filepath.Join(dir, "directory-recovered.zip")
		dec := runCLIInputContractCommand(t, binaryPath, "", "decrypt", output, "-o", recovered, "-p", password, "-q", "-y")
		if dec.exitCode != 0 {
			t.Fatalf("directory decrypt result = exit %d stderr %q", dec.exitCode, dec.stderr)
		}
		requireCLIContractZipEntry(t, recovered, filepath.Join(filepath.Base(selection), filepath.Base(leaf)), leafBytes)
	})

	t.Run("numeric split artifact collisions protect inputs and keyfiles", func(t *testing.T) {
		const longIndex = "18446744073709551616"
		for _, tc := range []struct {
			name       string
			asKeyfile  bool
			incomplete bool
		}{
			{name: "input final"},
			{name: "input incomplete", incomplete: true},
			{name: "keyfile final", asKeyfile: true},
			{name: "keyfile incomplete", asKeyfile: true, incomplete: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				output := filepath.Join(dir, "out.pcv")
				protected := output + "." + longIndex
				if tc.incomplete {
					protected += ".incomplete"
				}
				protectedBytes := []byte("protected exact bytes")
				mustWriteCLIContractFile(t, protected, protectedBytes)

				input := protected
				args := []string{"encrypt"}
				if tc.asKeyfile {
					input = filepath.Join(dir, "input.txt")
					mustWriteCLIContractFile(t, input, []byte("ordinary input"))
				}
				args = append(args, input, "-o", output, "-p", password, "--split", "--split-size", "2", "--split-unit", "Total", "-q", "-y")
				if tc.asKeyfile {
					args = append(args, "-k", protected)
				}

				result := runCLIInputContractCommand(t, binaryPath, "", args...)
				if result.exitCode == 0 || !strings.Contains(result.stderr, "conflicts with output artifact") {
					t.Errorf("numeric collision result = exit %d stderr %q", result.exitCode, result.stderr)
				}
				got, err := os.ReadFile(protected)
				if err != nil || !bytes.Equal(got, protectedBytes) {
					t.Errorf("protected file = %q, err = %v; want exact original bytes", got, err)
				}
				assertCLIContractAbsent(t, output, output+".incomplete", output+".0", output+".0.incomplete", output+".1", output+".1.incomplete")
			})
		}
	})

	t.Run("numeric split artifact aliases are refused", func(t *testing.T) {
		const longIndex = "18446744073709551616"
		for _, tc := range []struct {
			name string
			link func(string, string) error
		}{
			{name: "hardlink", link: os.Link},
			{name: "symlink", link: os.Symlink},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				source := filepath.Join(dir, "source.txt")
				output := filepath.Join(dir, "out.pcv")
				artifact := output + "." + longIndex + ".incomplete"
				content := []byte("aliased protected bytes")
				mustWriteCLIContractFile(t, source, content)
				if err := tc.link(source, artifact); err != nil {
					t.Skipf("%s creation is unavailable: %v", tc.name, err)
				}

				result := runCLIInputContractCommand(t, binaryPath, "", "encrypt", source, "-o", output, "-p", password,
					"--split", "--split-size", "2", "--split-unit", "Total", "-q", "-y")
				if result.exitCode == 0 || !strings.Contains(result.stderr, "conflicts with output artifact") {
					t.Errorf("alias collision result = exit %d stderr %q", result.exitCode, result.stderr)
				}
				for _, path := range []string{source, artifact} {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, content) {
						t.Errorf("alias path %q = %q, err = %v; want exact original bytes", path, got, err)
					}
				}
				assertCLIContractAbsent(t, output, output+".incomplete", output+".0", output+".0.incomplete", output+".1", output+".1.incomplete")
			})
		}
	})

	t.Run("case variant numeric split artifacts follow filesystem semantics", func(t *testing.T) {
		const longIndex = "18446744073709551616"
		for _, tc := range []struct {
			name       string
			asKeyfile  bool
			incomplete bool
			exactBase  bool
		}{
			{name: "input final"},
			{name: "input incomplete", incomplete: true},
			{name: "input uppercase incomplete suffix", incomplete: true, exactBase: true},
			{name: "keyfile final", asKeyfile: true},
			{name: "keyfile incomplete", asKeyfile: true, incomplete: true},
			{name: "keyfile uppercase incomplete suffix", asKeyfile: true, incomplete: true, exactBase: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				caseInsensitive := cliContractFilesystemCaseInsensitive(t, dir)
				output := filepath.Join(dir, "out.pcv")
				protectedBase := "OUT.PCV"
				if tc.exactBase {
					protectedBase = "out.pcv"
				}
				protected := filepath.Join(dir, protectedBase+"."+longIndex)
				if tc.incomplete {
					protected += ".INCOMPLETE"
				}
				protectedBytes := []byte("case variant protected exact bytes")
				mustWriteCLIContractFile(t, protected, protectedBytes)

				input := protected
				args := []string{"encrypt"}
				if tc.asKeyfile {
					input = filepath.Join(dir, "input.txt")
					mustWriteCLIContractFile(t, input, []byte("ordinary input"))
				}
				args = append(args, input, "-o", output, "-p", password, "--split", "--split-size", "2", "--split-unit", "Total", "-q", "-y")
				if tc.asKeyfile {
					args = append(args, "-k", protected)
				}

				result := runCLIInputContractCommand(t, binaryPath, "", args...)
				if caseInsensitive {
					if result.exitCode == 0 || !strings.Contains(result.stderr, "conflicts with output artifact") {
						t.Errorf("case-insensitive collision result = exit %d stderr %q", result.exitCode, result.stderr)
					}
					assertCLIContractAbsent(t, output, output+".incomplete")
				} else {
					if result.exitCode != 0 {
						t.Errorf("case-sensitive distinct path result = exit %d stderr %q", result.exitCode, result.stderr)
					}
					if _, err := os.Stat(output + ".0"); err != nil {
						t.Errorf("case-sensitive split output missing: %v", err)
					}
				}
				got, err := os.ReadFile(protected)
				if err != nil || !bytes.Equal(got, protectedBytes) {
					t.Errorf("protected file = %q, err = %v; want exact original bytes", got, err)
				}
			})
		}
	})
}

func TestSplitArtifactSuffixUsesCanonicalIncompleteSpelling(t *testing.T) {
	const digits = "18446744073709551616"
	suffix, ok := splitArtifactSuffix("out.pcv." + digits + ".INCOMPLETE")
	want := "." + digits + ".incomplete"
	if !ok || suffix != want {
		t.Fatalf("splitArtifactSuffix() = %q, %v; want %q, true", suffix, ok, want)
	}
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

func cliContractFilesystemCaseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	lower := filepath.Join(dir, "case-probe")
	upper := filepath.Join(dir, "CASE-PROBE")
	mustWriteCLIContractFile(t, lower, []byte("probe"))
	defer func() { _ = os.Remove(lower) }()
	if _, err := os.Stat(upper); err == nil {
		return true
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("probe filesystem case sensitivity: %v", err)
	}
	return false
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
