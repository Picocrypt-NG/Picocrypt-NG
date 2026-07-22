package cli

import (
	"Picocrypt-NG/internal/header"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEncryptValidation(t *testing.T) {
	// Save original args
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	t.Run("missing input", func(t *testing.T) {
		// Reset flags for each test
		encGlob = nil
		encLegacyInputs = nil
		encOutput = ""
		encPassword = ""
		encKeyfiles = nil

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing input")
		}
		if !strings.Contains(err.Error(), "at least one input path") {
			t.Errorf("error should mention required operand: %v", err)
		}
	})

	t.Run("nonexistent input file", func(t *testing.T) {
		encOutput = ""
		encPassword = "test"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{"/nonexistent/file/path.txt"})
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error should mention missing path: %v", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		// Create temp file
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		encOutput = ""
		encPassword = ""
		encKeyfiles = nil

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{tmpFile})
		if err == nil {
			t.Error("expected error for missing credentials")
		}
		if !strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "keyfile") {
			t.Errorf("error should mention password or keyfile: %v", err)
		}
	})

	t.Run("invalid split options", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		encPassword = "test"
		encSplit = true
		encSplitSize = 0 // Invalid

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{tmpFile})
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
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		encPassword = "test"
		encSplit = true
		encSplitSize = 10
		encSplitUnit = "invalid"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{tmpFile})
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
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		encPassword = "test"
		encKeyfiles = []string{"/nonexistent/keyfile.key"}

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{tmpFile})
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
		decLegacyInputs = nil
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing input")
		}
		if !strings.Contains(err.Error(), "accepts 1 arg") {
			t.Errorf("error should mention required operand: %v", err)
		}
	})

	t.Run("nonexistent input file", func(t *testing.T) {
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{"/nonexistent/file.pcv"})
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention not found: %v", err)
		}
	})

	t.Run("input is directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{tmpDir})
		if err == nil {
			t.Error("expected error for directory input")
		}
		if !strings.Contains(err.Error(), "directory") {
			t.Errorf("error should mention directory: %v", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.pcv")
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		decPassword = ""
		decKeyfiles = nil
		decQuiet = true // Suppress header read warning

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{tmpFile})
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
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		decPassword = "test"
		decKeyfiles = []string{"/nonexistent/keyfile.key"}

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{tmpFile})
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

func TestForceDecryptKeptExitCode(t *testing.T) {
	binaryPath := buildCLITestBinary(t)
	goldenPath := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")
	if _, err := os.Stat(goldenPath); err != nil {
		t.Fatalf("golden volume missing: %v", err)
	}

	t.Run("clean decrypt exits zero without kept warning", func(t *testing.T) {
		outputPath := filepath.Join(t.TempDir(), "clean.txt")
		result := runCLITestCommand(t, binaryPath, "decrypt",
			goldenPath,
			"-o", outputPath,
			"-p", "test",
			"-q",
			"-y",
		)

		if result.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", result.exitCode, result.stderr)
		}
		if strings.Contains(result.stderr, "kept") || strings.Contains(result.stderr, "MAC verification failed") {
			t.Fatalf("clean decrypt emitted kept-output warning:\n%s", result.stderr)
		}
		if _, err := os.Stat(outputPath); err != nil {
			t.Fatalf("clean output missing: %v", err)
		}
	})

	t.Run("force decrypt kept output exits two with warning", func(t *testing.T) {
		tmpDir := t.TempDir()
		corruptPath := filepath.Join(tmpDir, "corrupt.pcv")
		copyCLITestFile(t, goldenPath, corruptPath)
		corruptCLITestPayload(t, corruptPath)

		outputPath := filepath.Join(tmpDir, "recovered.txt")
		result := runCLITestCommand(t, binaryPath, "decrypt",
			corruptPath,
			"-o", outputPath,
			"-p", "test",
			"--force",
			"-q",
			"-y",
		)

		if result.exitCode != 2 {
			t.Fatalf("exit code = %d, want 2\nstderr:\n%s", result.exitCode, result.stderr)
		}
		if !strings.Contains(result.stderr, "Warning:") || !strings.Contains(result.stderr, "MAC verification failed") {
			t.Fatalf("kept-output warning missing from stderr:\n%s", result.stderr)
		}
		if _, err := os.Stat(outputPath); err != nil {
			t.Fatalf("kept output missing: %v", err)
		}
	})

	t.Run("unrecoverable force decrypt stays general failure", func(t *testing.T) {
		tmpDir := t.TempDir()
		junkPath := filepath.Join(tmpDir, "junk.pcv")
		if err := os.WriteFile(junkPath, []byte("not a valid Picocrypt volume"), 0o600); err != nil {
			t.Fatalf("write junk input: %v", err)
		}
		outputPath := filepath.Join(tmpDir, "unsafe.txt")

		result := runCLITestCommand(t, binaryPath, "decrypt",
			junkPath,
			"-o", outputPath,
			"-p", "test",
			"--force",
			"-q",
			"-y",
		)

		if result.exitCode != 1 {
			t.Fatalf("exit code = %d, want 1\nstderr:\n%s", result.exitCode, result.stderr)
		}
		if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
			t.Fatalf("unsafe output should not remain, stat err: %v", err)
		}
		if _, err := os.Stat(outputPath + ".incomplete"); !os.IsNotExist(err) {
			t.Fatalf("unsafe incomplete output should not remain, stat err: %v", err)
		}
	})
}

func TestForceDecryptKeptStdoutOrdering(t *testing.T) {
	binaryPath := buildCLITestBinary(t)
	goldenPath := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")
	if _, err := os.Stat(goldenPath); err != nil {
		t.Fatalf("golden volume missing: %v", err)
	}

	t.Run("clean stdout decrypt exits zero without warning", func(t *testing.T) {
		result := runCLITestCommand(t, binaryPath, "decrypt",
			goldenPath,
			"-o", "-",
			"-p", "test",
			"-q",
		)

		if result.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", result.exitCode, result.stderr)
		}
		if len(result.stdout) == 0 {
			t.Fatal("expected clean plaintext on stdout")
		}
		if strings.Contains(result.stderr, "Warning:") || strings.Contains(result.stderr, "MAC verification failed") {
			t.Fatalf("clean stdout decrypt emitted warning:\n%s", result.stderr)
		}
	})

	t.Run("kept stdout decrypt writes bytes before non-clean exit", func(t *testing.T) {
		tmpDir := t.TempDir()
		corruptPath := filepath.Join(tmpDir, "corrupt-stdout.pcv")
		copyCLITestFile(t, goldenPath, corruptPath)
		corruptCLITestPayload(t, corruptPath)

		result := runCLITestCommand(t, binaryPath, "decrypt",
			corruptPath,
			"-o", "-",
			"-p", "test",
			"--force",
			"-q",
		)

		if result.exitCode != 2 {
			t.Fatalf("exit code = %d, want 2\nstderr:\n%s", result.exitCode, result.stderr)
		}
		if len(result.stdout) == 0 {
			t.Fatal("expected recovered bytes on stdout before non-clean exit")
		}
		if !strings.Contains(result.stderr, "Warning:") || !strings.Contains(result.stderr, "MAC verification failed") {
			t.Fatalf("kept-output warning missing from stderr:\n%s", result.stderr)
		}
		if bytes.Contains(result.stdout, []byte("Warning:")) || bytes.Contains(result.stdout, []byte("MAC verification failed")) {
			t.Fatalf("stdout contains warning text: %q", result.stdout)
		}
	})
}

type cliTestResult struct {
	exitCode int
	stdout   []byte
	stderr   string
}

func buildCLITestBinary(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	binaryName := "picocrypt-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tmpDir, binaryName)

	srcDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("source dir: %v", err)
	}

	cmd := exec.Command("go", "build", "-tags", "cli", "-o", binaryPath, "./cmd/picocrypt")
	cmd.Dir = srcDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build CLI binary: %v\n%s", err, output)
	}
	return binaryPath
}

func runCLITestCommand(t *testing.T, binaryPath string, args ...string) cliTestResult {
	t.Helper()

	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = 1
		exitErr := &exec.ExitError{}
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	return cliTestResult{
		exitCode: exitCode,
		stdout:   append([]byte(nil), stdout.Bytes()...),
		stderr:   stderr.String(),
	}
}

func copyCLITestFile(t *testing.T, src, dst string) {
	t.Helper()

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

func corruptCLITestPayload(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	payloadOffset := header.HeaderSize(0)
	if payloadOffset >= len(data) {
		t.Fatalf("payload offset %d exceeds file size %d", payloadOffset, len(data))
	}
	data[payloadOffset] ^= 0x80
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write corrupted %s: %v", path, err)
	}
}

// TestSplitVolumeDetection drives runDecrypt's split-volume auto-detection
// (decrypt.go:181-189). With decQuiet=false the guidance line must reach stderr
// and decRecombine must flip to true only when the trailing ".pcv.<n>" suffix is
// numeric. A non-numeric suffix (Sscanf fails) and a plain ".pcv" path must both
// leave decRecombine false and emit no guidance.
//
// Mutation: dropping the Sscanf numeric-suffix guard would flip decRecombine on
// "test.pcv.notanumber"; dropping the guidance fmt.Fprintln would drop the
// "Detected split volume" message on the positive case.
func TestSplitVolumeDetection(t *testing.T) {
	origPassword := decPassword
	origRecombine, origQuiet := decRecombine, decQuiet
	t.Cleanup(func() {
		decPassword = origPassword
		decRecombine = origRecombine
		decQuiet = origQuiet
	})

	// runDecryptCapturingStderr swaps os.Stderr for a pipe, runs the decrypt
	// command (which fails downstream — the inputs are not valid volumes — but
	// only after the detection branch runs), and returns the captured stderr.
	runDecryptCapturingStderr := func(t *testing.T, input string) string {
		t.Helper()
		decPassword = "test"
		decRecombine = false
		decQuiet = false // guidance message only prints when not quiet

		old := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stderr = w

		_ = decryptCmd.RunE(decryptCmd, []string{input})

		_ = w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r); err != nil {
			t.Fatalf("reading captured stderr: %v", err)
		}
		return buf.String()
	}

	t.Run("numeric chunk suffix detected and recombine set", func(t *testing.T) {
		tmpDir := t.TempDir()
		splitFile := filepath.Join(tmpDir, "test.pcv.0")
		if err := os.WriteFile(splitFile, []byte("chunk0"), 0o644); err != nil {
			t.Fatal(err)
		}

		stderr := runDecryptCapturingStderr(t, splitFile)

		if !decRecombine {
			t.Error("numeric chunk suffix should set decRecombine=true")
		}
		if !strings.Contains(stderr, "Detected split volume") {
			t.Errorf("expected split-volume guidance on stderr, got: %q", stderr)
		}
	})

	t.Run("non-numeric chunk suffix is not a split volume", func(t *testing.T) {
		tmpDir := t.TempDir()
		notChunk := filepath.Join(tmpDir, "test.pcv.notanumber")
		if err := os.WriteFile(notChunk, []byte("not a chunk"), 0o644); err != nil {
			t.Fatal(err)
		}

		stderr := runDecryptCapturingStderr(t, notChunk)

		if decRecombine {
			t.Error("non-numeric .pcv. suffix must not set decRecombine")
		}
		if strings.Contains(stderr, "Detected split volume") {
			t.Errorf("non-numeric suffix must not emit split-volume guidance, got: %q", stderr)
		}
	})

	t.Run("plain .pcv path is not a split volume", func(t *testing.T) {
		tmpDir := t.TempDir()
		plain := filepath.Join(tmpDir, "test.pcv")
		if err := os.WriteFile(plain, []byte("plain volume"), 0o644); err != nil {
			t.Fatal(err)
		}

		_ = runDecryptCapturingStderr(t, plain)

		if decRecombine {
			t.Error("plain .pcv path must not set decRecombine")
		}
	})
}

// TestOutputAutoGeneration drives the REAL runEncrypt/runDecrypt auto-generation
// branches (encOutput=="" / decOutput==""), rather than recomputing the rule
// inline. The decrypt half is the mutation-catcher: it pins that the auto output
// is the input with ".pcv" stripped (decrypt.go:205); dropping the TrimSuffix
// would write the plaintext over the .pcv path and turn this red.
func TestOutputAutoGeneration(t *testing.T) {
	t.Run("encrypt auto-generates output as input+.pcv", func(t *testing.T) {
		resetEncryptFlagsForDirTest()
		t.Cleanup(resetEncryptFlagsForDirTest)

		tmpDir := t.TempDir()
		inputFile := filepath.Join(tmpDir, "secret.txt")
		if err := os.WriteFile(inputFile, []byte("plaintext"), 0o644); err != nil {
			t.Fatal(err)
		}

		encOutput = "" // force auto-generation through runEncrypt
		encPassword = "pw"
		encQuiet = true
		encYes = true

		if err := encryptCmd.RunE(encryptCmd, []string{inputFile}); err != nil {
			t.Fatalf("runEncrypt: %v", err)
		}

		wantOut := inputFile + ".pcv"
		info, err := os.Stat(wantOut)
		if err != nil {
			t.Fatalf("expected auto-generated output %q to exist: %v", wantOut, err)
		}
		if info.Size() == 0 {
			t.Fatalf("auto-generated output %q is empty", wantOut)
		}
	})

	t.Run("decrypt auto-generates output as input minus .pcv", func(t *testing.T) {
		resetDecryptFlagsForDirTest()
		t.Cleanup(resetDecryptFlagsForDirTest)

		goldenPath := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")
		if _, err := os.Stat(goldenPath); err != nil {
			t.Fatalf("golden volume missing: %v", err)
		}

		tmpDir := t.TempDir()
		volPath := filepath.Join(tmpDir, "vol.txt.pcv")
		copyCLITestFile(t, goldenPath, volPath)

		decOutput = "" // force auto-generation through runDecrypt
		decPassword = "test"
		decQuiet = true
		decYes = true

		if err := decryptCmd.RunE(decryptCmd, []string{volPath}); err != nil {
			t.Fatalf("runDecrypt: %v", err)
		}

		wantOut := strings.TrimSuffix(volPath, ".pcv") // vol.txt
		if wantOut == volPath {
			t.Fatalf("test setup error: input %q has no .pcv suffix", volPath)
		}
		got, err := os.ReadFile(wantOut)
		if err != nil {
			t.Fatalf("expected auto-generated output %q to exist: %v", wantOut, err)
		}
		const wantPlaintext = "There is a test file for Picocrypt validation.\n"
		if string(got) != wantPlaintext {
			t.Fatalf("decrypted %q = %q, want %q", wantOut, got, wantPlaintext)
		}
		// Under the mutation (outputFile = inputPath, no .pcv stripping) the
		// plaintext would be written over the .pcv path, not vol.txt.
		if _, err := os.Stat(volPath); err != nil {
			t.Fatalf("input volume %q unexpectedly gone: %v", volPath, err)
		}
	})
}

// TestGlobExpansion drives runEncrypt's real glob-expansion path (encrypt.go:203)
// rather than re-testing filepath.Glob. A non-matching pattern must surface the
// specific "input file not found" guard (encrypt.go:207-209); a matching pattern
// must flow through the expansion loop and succeed.
func TestGlobExpansion(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	for _, name := range []string{"a.txt", "b.txt", "c.log"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("non-matching pattern reports input file not found", func(t *testing.T) {
		resetEncryptFlagsForDirTest()
		t.Cleanup(resetEncryptFlagsForDirTest)

		encGlob = []string{filepath.Join(tmpDir, "*.xyz")}
		encOutput = filepath.Join(tmpDir, "out.pcv")
		encPassword = "pw"
		encQuiet = true
		encYes = true

		err := encryptCmd.RunE(encryptCmd, []string{})
		if err == nil {
			t.Fatal("expected error for non-matching glob pattern")
		}
		// The specific guard message is load-bearing: deleting the len==0 guard
		// lets execution fall through to "no files found to encrypt", so a bare
		// err!=nil check would not catch the mutation.
		if !strings.Contains(err.Error(), "matched no paths") {
			t.Fatalf("expected %q in error, got: %v", "matched no paths", err)
		}
	})

	t.Run("matching pattern is expanded and encrypted", func(t *testing.T) {
		resetEncryptFlagsForDirTest()
		t.Cleanup(resetEncryptFlagsForDirTest)

		outPath := filepath.Join(tmpDir, "matched.pcv")
		encGlob = []string{filepath.Join(tmpDir, "*.txt")} // matches a.txt, b.txt
		encOutput = outPath
		encPassword = "pw"
		encQuiet = true
		encYes = true

		if err := encryptCmd.RunE(encryptCmd, []string{}); err != nil {
			t.Fatalf("runEncrypt with matching glob: %v", err)
		}
		info, err := os.Stat(outPath)
		if err != nil {
			t.Fatalf("expected encrypted output %q to exist: %v", outPath, err)
		}
		if info.Size() == 0 {
			t.Fatalf("encrypted output %q is empty", outPath)
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
		// PrintError prepends "Error: " (reporter.go:101). A leading newline may
		// precede it when progress was shown; strip it before asserting prefix.
		// Mutation: dropping the "Error: " prefix in PrintError would turn this red.
		if got := strings.TrimLeft(buf.String(), "\n"); !strings.HasPrefix(got, "Error: ") {
			t.Errorf("PrintError output should be %q-prefixed, got: %q", "Error: ", buf.String())
		}
	})
}

// Version wiring is covered behaviorally by TestVersionFlagReachesOutput (version_test.go),
// which drives the real Execute()/rootCmd and asserts the version reaches CLI output;
// a tautological "set rootCmd.Version then assert it" test was removed here.

func TestDetectCLIMode(t *testing.T) {
	testCases := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "encrypt subcommand",
			args: []string{"encrypt", "a", "-o", "a.pcv"},
			want: true,
		},
		{
			name: "persistent flag before subcommand",
			args: []string{"--temp-dir", "/tmp", "encrypt", "a", "-o", "a.pcv"},
			want: true,
		},
		{
			name: "persistent flag equals form before subcommand",
			args: []string{"--temp-dir=/tmp", "decrypt", "a.pcv"},
			want: true,
		},
		{
			name: "root version flag",
			args: []string{"--version"},
			want: true,
		},
		{
			name: "bare version token is not a command",
			args: []string{"version"},
			want: false,
		},
		{
			name: "invalid root flag before subcommand",
			args: []string{"--bogus", "encrypt", "a", "-o", "a.pcv"},
			want: true,
		},
		{
			name: "missing value root flag before subcommand",
			args: []string{"--temp-dir", "encrypt", "a", "-o", "a.pcv", "-p", "pw"},
			want: true,
		},
		{
			name: "unknown GUI-style arg",
			args: []string{"--fyne-driver=software"},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectCLIMode(tc.args); got != tc.want {
				t.Fatalf("detectCLIMode(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestDefaultEncryptOutput(t *testing.T) {
	t.Run("multiple expanded matches", func(t *testing.T) {
		pattern := "/tmp/*.txt"
		allFiles := []string{"/tmp/a.txt", "/tmp/b.txt"}

		got := defaultEncryptOutput(pattern, allFiles, nil, false, true)
		if got != "encrypted.zip.pcv" {
			t.Fatalf("defaultEncryptOutput(%q, %q, nil, false, true) = %q, want %q",
				pattern, allFiles, got, "encrypted.zip.pcv")
		}
	})

	t.Run("single expanded match", func(t *testing.T) {
		pattern := "/tmp/*.txt"
		allFiles := []string{"/tmp/a.txt"}

		got := defaultEncryptOutput(pattern, allFiles, nil, false, false)
		if got != "/tmp/a.txt.pcv" {
			t.Fatalf("defaultEncryptOutput(%q, %q, nil, false, false) = %q, want %q",
				pattern, allFiles, got, "/tmp/a.txt.pcv")
		}
	})

	t.Run("compressed stdin", func(t *testing.T) {
		got := defaultEncryptOutput("", []string{"stdin-temp"}, nil, true, true)
		if got != "encrypted.zip.pcv" {
			t.Fatalf("defaultEncryptOutput(%q, %q, nil, true, true) = %q, want %q",
				"", []string{"stdin-temp"}, got, "encrypted.zip.pcv")
		}
	})
}

func TestDefaultCompressOutputNameUsesZipSuffix(t *testing.T) {
	resetEncryptFlagsForDirTest()
	resetDecryptFlagsForDirTest()
	t.Cleanup(resetEncryptFlagsForDirTest)
	t.Cleanup(resetDecryptFlagsForDirTest)

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "page.html")
	plaintext := []byte("<!doctype html><h1>compressed</h1>\n")
	if err := os.WriteFile(inputFile, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	encPassword = "pw"
	encCompress = true
	encQuiet = true
	encYes = true

	if err := encryptCmd.RunE(encryptCmd, []string{inputFile}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	want := inputFile + ".zip.pcv"
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("compressed default output %q missing: %v", want, err)
	}
	if _, err := os.Stat(inputFile + ".pcv"); !os.IsNotExist(err) {
		t.Fatalf("compressed default output should not hide zip payload as %q", inputFile+".pcv")
	}

	resetDecryptFlagsForDirTest()
	decPassword = "pw"
	decQuiet = true
	decYes = true

	if err := decryptCmd.RunE(decryptCmd, []string{want}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	assertZipContainsPlaintext(t, inputFile+".zip", plaintext)
}

func TestDefaultCompressStdinOutputNameUsesZipSuffix(t *testing.T) {
	resetEncryptFlagsForDirTest()
	t.Cleanup(resetEncryptFlagsForDirTest)

	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
	})
	if _, err := w.Write([]byte("<!doctype html><h1>compressed stdin</h1>\n")); err != nil {
		t.Fatalf("write stdin pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close stdin pipe: %v", err)
	}

	encPassword = "pw"
	encCompress = true
	encQuiet = true
	encYes = true

	if err := encryptCmd.RunE(encryptCmd, []string{"-"}); err != nil {
		t.Fatalf("encrypt stdin: %v", err)
	}

	if _, err := os.Stat("encrypted.zip.pcv"); err != nil {
		t.Fatalf("compressed stdin default output missing: %v", err)
	}
	if _, err := os.Stat("encrypted.pcv"); !os.IsNotExist(err) {
		t.Fatal("compressed stdin default output should use encrypted.zip.pcv, not encrypted.pcv")
	}
}

func TestEncryptStdinValidation(t *testing.T) {
	t.Run("stdin with password stdin conflict", func(t *testing.T) {
		encOutput = "test.pcv"
		encPassword = ""
		encPasswordStdin = true
		encKeyfiles = nil
		encSplit = false
		encDeniability = false

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{"-"})
		if err == nil {
			t.Error("expected error for stdin with -P conflict")
		}
		if !strings.Contains(err.Error(), "cannot use -P") {
			t.Errorf("error should mention -P conflict: %v", err)
		}

		// Reset
		encPasswordStdin = false
	})

	t.Run("password stdin empty without keyfiles", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		oldStdin := os.Stdin
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = r
		if _, err := w.WriteString("\n"); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		t.Cleanup(func() {
			os.Stdin = oldStdin
			_ = r.Close()
		})

		encOutput = filepath.Join(t.TempDir(), "test.pcv")
		encPassword = ""
		encPasswordStdin = true
		encKeyfiles = nil
		encSplit = false
		encDeniability = false

		cmd := encryptCmd
		err = cmd.RunE(cmd, []string{tmpFile})
		if err == nil {
			t.Fatal("expected error for empty password from stdin")
		}
		if !strings.Contains(err.Error(), ErrPasswordEmpty.Error()) {
			t.Errorf("expected empty password error, got: %v", err)
		}

		encPasswordStdin = false
	})

	t.Run("stdin with multiple inputs conflict", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		encOutput = "test.pcv"
		encPassword = "test"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{"-", tmpFile})
		if err == nil {
			t.Error("expected error for stdin with multiple inputs")
		}
		if !strings.Contains(err.Error(), "cannot be combined") {
			t.Errorf("error should mention cannot be combined: %v", err)
		}
	})

	t.Run("stdin/stdout with split conflict", func(t *testing.T) {
		encOutput = "test.pcv"
		encPassword = "test"
		encPasswordStdin = false
		encSplit = true
		encSplitSize = 10
		encSplitUnit = "MiB"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{"-"})
		if err == nil {
			t.Error("expected error for stdin with --split")
		}
		if !strings.Contains(err.Error(), "not compatible with --split") {
			t.Errorf("error should mention --split incompatibility: %v", err)
		}

		// Reset
		encSplit = false
		encSplitSize = 0
	})

	t.Run("stdout with split conflict", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		encOutput = "-"
		encPassword = "test"
		encSplit = true
		encSplitSize = 10
		encSplitUnit = "MiB"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{tmpFile})
		if err == nil {
			t.Error("expected error for stdout with --split")
		}
		if !strings.Contains(err.Error(), "not compatible with --split") {
			t.Errorf("error should mention --split incompatibility: %v", err)
		}

		// Reset
		encSplit = false
		encSplitSize = 0
	})

	t.Run("stdin with deniability conflict", func(t *testing.T) {
		encOutput = "test.pcv"
		encPassword = "test"
		encDeniability = true

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{"-"})
		if err == nil {
			t.Error("expected error for stdin with --deniability")
		}
		if !strings.Contains(err.Error(), "not compatible with --deniability") {
			t.Errorf("error should mention --deniability incompatibility: %v", err)
		}

		// Reset
		encDeniability = false
	})
}

func TestCleanupEncryptError(t *testing.T) {
	t.Run("preserves pre-existing output file", func(t *testing.T) {
		tmpDir := t.TempDir()
		output := filepath.Join(tmpDir, "existing.pcv")
		if err := os.WriteFile(output, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
		incomplete := output + ".incomplete"
		if err := os.WriteFile(incomplete, []byte("partial"), 0o644); err != nil {
			t.Fatal(err)
		}

		cleanupEncryptError(output, false, true)

		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatalf("expected pre-existing output file to remain: %v", err)
		}
		if string(data) != "original" {
			t.Fatalf("expected original content preserved, got %q", string(data))
		}
		if _, err := os.Stat(incomplete); !os.IsNotExist(err) {
			t.Fatalf("expected incomplete file removed, got: %v", err)
		}
	})

	t.Run("removes new output file", func(t *testing.T) {
		tmpDir := t.TempDir()
		output := filepath.Join(tmpDir, "new.pcv")
		if err := os.WriteFile(output, []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}
		incomplete := output + ".incomplete"
		if err := os.WriteFile(incomplete, []byte("partial"), 0o644); err != nil {
			t.Fatal(err)
		}

		cleanupEncryptError(output, false, false)

		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("expected output file removed, got: %v", err)
		}
		if _, err := os.Stat(incomplete); !os.IsNotExist(err) {
			t.Fatalf("expected incomplete file removed, got: %v", err)
		}
	})

	t.Run("stdout mode does not remove output file", func(t *testing.T) {
		tmpDir := t.TempDir()
		output := filepath.Join(tmpDir, "stdout-temp.pcv")
		if err := os.WriteFile(output, []byte("temp"), 0o644); err != nil {
			t.Fatal(err)
		}

		cleanupEncryptError(output, true, false)

		if _, err := os.Stat(output); err != nil {
			t.Fatalf("expected stdout path untouched, got: %v", err)
		}
	})
}

func TestDecryptStdinValidation(t *testing.T) {
	t.Run("stdin with password stdin conflict", func(t *testing.T) {
		decOutput = "test.txt"
		decPassword = ""
		decPasswordStdin = true
		decKeyfiles = nil
		decRecombine = false
		decDeniability = false
		decAutoUnzip = false

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{"-"})
		if err == nil {
			t.Error("expected error for stdin with -P conflict")
		}
		if !strings.Contains(err.Error(), "cannot use -P") {
			t.Errorf("error should mention -P conflict: %v", err)
		}

		// Reset
		decPasswordStdin = false
	})

	t.Run("stdin with recombine conflict", func(t *testing.T) {
		decOutput = "test.txt"
		decPassword = "test"
		decRecombine = true

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{"-"})
		if err == nil {
			t.Error("expected error for stdin with --recombine")
		}
		if !strings.Contains(err.Error(), "not compatible with --recombine") {
			t.Errorf("error should mention --recombine incompatibility: %v", err)
		}

		// Reset
		decRecombine = false
	})

	t.Run("stdin with deniability conflict", func(t *testing.T) {
		decOutput = "test.txt"
		decPassword = "test"
		decDeniability = true

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{"-"})
		if err == nil {
			t.Error("expected error for stdin with --deniability")
		}
		if !strings.Contains(err.Error(), "not compatible with --deniability") {
			t.Errorf("error should mention --deniability incompatibility: %v", err)
		}

		// Reset
		decDeniability = false
	})

	t.Run("stdout with auto-unzip conflict", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.pcv")
		if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}

		decOutput = "-"
		decPassword = "test"
		decAutoUnzip = true

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{tmpFile})
		if err == nil {
			t.Error("expected error for stdout with --auto-unzip")
		}
		if !strings.Contains(err.Error(), "not compatible with --auto-unzip") {
			t.Errorf("error should mention --auto-unzip incompatibility: %v", err)
		}

		// Reset
		decAutoUnzip = false
	})
}
