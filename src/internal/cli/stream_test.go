package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestIsStdin(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"-", true},
		{"", false},
		{"stdin", false},
		{"/dev/stdin", false},
		{"file.txt", false},
		{"-file", false},
		{"file-", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsStdin(tt.path); got != tt.want {
				t.Errorf("IsStdin(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsStdout(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"-", true},
		{"", false},
		{"stdout", false},
		{"/dev/stdout", false},
		{"file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsStdout(tt.path); got != tt.want {
				t.Errorf("IsStdout(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestBufferStdinToTemp(t *testing.T) {
	testData := []byte("test data for stdin buffering\nwith multiple lines\n")

	// Create pipe to simulate stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	// Save and replace stdin
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Write test data in goroutine
	go func() {
		w.Write(testData)
		w.Close()
	}()

	// Call function under test
	tmpPath, err := BufferStdinToTemp("")
	if err != nil {
		t.Fatalf("BufferStdinToTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = cleanupTempFiles(tmpPath) })

	// Verify file exists with correct permissions
	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("temp file not found: %v", err)
	}
	// Windows doesn't support Unix-style permissions
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("temp file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Verify content
	content, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("reading temp file: %v", err)
	}
	if !bytes.Equal(content, testData) {
		t.Errorf("content mismatch\ngot:  %q\nwant: %q", content, testData)
	}
}

func TestBufferStdinToTempEmpty(t *testing.T) {
	// Test with empty stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Close immediately (empty input)
	w.Close()

	tmpPath, err := BufferStdinToTemp("")
	if err != nil {
		t.Fatalf("BufferStdinToTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = cleanupTempFiles(tmpPath) })

	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("temp file not found: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected empty file, got size %d", info.Size())
	}
	// The 0600 chmod must apply even on the empty-stdin path (mirrors the
	// non-empty sibling). Mutation: dropping the Chmod(0600) in BufferStdinToTemp
	// would leak stdin plaintext staging under a world-readable mode.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("temp file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestBufferStdinToTempLarge(t *testing.T) {
	// Test with larger data (1 MiB)
	testData := make([]byte, 1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	go func() {
		w.Write(testData)
		w.Close()
	}()

	tmpPath, err := BufferStdinToTemp("")
	if err != nil {
		t.Fatalf("BufferStdinToTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = cleanupTempFiles(tmpPath) })

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("reading temp file: %v", err)
	}
	if !bytes.Equal(content, testData) {
		t.Error("large data content mismatch")
	}
}

func TestBufferStdinToTempDoesNotUseOutputDir(t *testing.T) {
	testData := []byte("stdin output-path isolation")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	go func() {
		_, _ = w.Write(testData)
		_ = w.Close()
	}()

	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "output.pcv")

	tmpPath, err := BufferStdinToTemp(outputPath)
	if err != nil {
		t.Fatalf("BufferStdinToTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = cleanupTempFiles(tmpPath) })

	if filepath.Dir(tmpPath) == outputDir {
		t.Fatalf("stdin temp file should not be created in output dir %s", outputDir)
	}
}

func TestCreateTempOutput(t *testing.T) {
	tmpPath, err := CreateTempOutput(0)
	if err != nil {
		t.Fatalf("CreateTempOutput() error = %v", err)
	}
	defer os.Remove(tmpPath)

	// Verify file exists with correct permissions
	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("temp file not found: %v", err)
	}
	// Windows doesn't support Unix-style permissions
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("temp file permissions = %o, want 0600", info.Mode().Perm())
	}

	// File should be empty initially
	if info.Size() != 0 {
		t.Errorf("expected empty file, got size %d", info.Size())
	}
}

func TestStreamFileToStdout(t *testing.T) {
	testData := []byte("output data to stream\nwith multiple lines\n")

	// Create temp file with test data
	tmpFile, err := os.CreateTemp("", "stream-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(testData); err != nil {
		tmpFile.Close()
		t.Fatal(err)
	}
	tmpFile.Close()

	// Capture stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	os.Stdout = w

	// Stream in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- StreamFileToStdout(context.Background(), tmpPath)
		w.Close()
	}()

	// Read captured output
	var captured bytes.Buffer
	io.Copy(&captured, r)
	os.Stdout = oldStdout

	if err := <-errCh; err != nil {
		t.Fatalf("StreamFileToStdout() error = %v", err)
	}

	if !bytes.Equal(captured.Bytes(), testData) {
		t.Errorf("output mismatch\ngot:  %q\nwant: %q", captured.Bytes(), testData)
	}
	if _, err := os.Lstat(tmpPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stdout plaintext temp remained after streaming: %v", err)
	}
}

func TestStreamFileToStdoutNonexistent(t *testing.T) {
	err := StreamFileToStdout(context.Background(), "/nonexistent/file/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestCleanupTempFilesRemovesTemp verifies that the stdin/stdout staging temps
// are removed by cleanupTempFiles. Cleanup is plain os.Remove (no shredding —
// overwrite-before-unlink was dropped as useless on flash/CoW filesystems);
// the invariant is only that the temp no longer exists afterwards.
func TestCleanupTempFilesRemovesTemp(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
	}{
		{"decrypt-to-stdout plaintext temp", "picocrypt-out-"},
		{"encrypt-from-stdin plaintext temp", "picocrypt-stdin-"},
		{"ciphertext staging temp", "picocrypt-cipher-"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tmp := filepath.Join(dir, tc.prefix+"fixture")
			if err := os.WriteFile(tmp, []byte("plaintext fragment"), 0o600); err != nil {
				t.Fatalf("write temp: %v", err)
			}

			cleanupTempFiles(tmp)

			if _, err := os.Stat(tmp); !os.IsNotExist(err) {
				t.Fatalf("temp still exists after cleanup: %v", err)
			}
		})
	}
}

// TestCleanupTempFilesRemovesAllProvidedTemps proves the shared helper handles
// the real call shape from both runEncrypt and runDecrypt: a stdin staging temp
// AND a stdout staging temp are both removed in one cleanup pass.
func TestCleanupTempFilesRemovesAllProvidedTemps(t *testing.T) {
	dir := t.TempDir()
	stdinTemp := filepath.Join(dir, "picocrypt-stdin-a")
	stdoutTemp := filepath.Join(dir, "picocrypt-out-b")
	for _, p := range []string{stdinTemp, stdoutTemp} {
		if err := os.WriteFile(p, []byte("plaintext fragment"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	cleanupTempFiles(stdinTemp, stdoutTemp)

	for _, p := range []string{stdinTemp, stdoutTemp} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("temp %s still exists after cleanup", p)
		}
	}
}

// TestCleanupTempFilesSkipsEmptyPaths guards the "no temp was created" case:
// runEncrypt/runDecrypt pass "" when stdin/stdout buffering never ran, and the
// helper must skip empty paths rather than attempting to remove a sibling file.
func TestCleanupTempFilesSkipsEmptyPaths(t *testing.T) {
	dir := t.TempDir()
	bystander := filepath.Join(dir, "bystander")
	if err := os.WriteFile(bystander, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("write bystander: %v", err)
	}

	cleanupTempFiles("", "")

	if _, err := os.Stat(bystander); err != nil {
		t.Fatalf("cleanupTempFiles disturbed an unrelated file on empty input: %v", err)
	}
}

func TestCLIReportsStdinTempCleanupFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions cannot reliably force unlink failure on this host")
	}

	dir := t.TempDir()
	tempDir := filepath.Join(dir, "temp")
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		t.Fatalf("create temp directory: %v", err)
	}
	output := filepath.Join(dir, "encrypted.pcv")
	binary := buildCLITestBinary(t)
	command := exec.Command(
		binary,
		"--temp-dir", tempDir,
		"encrypt", "-", "-o", output,
		"--pcv3", "-p", "cleanup-password", "--quiet",
	)
	command.Stdin = bytes.NewReader([]byte("plaintext requiring fail-loud cleanup"))
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start CLI: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()

	deadline := time.Now().Add(5 * time.Second)
	found := false
	exited := false
	var runErr error
	for time.Now().Before(deadline) {
		select {
		case runErr = <-waited:
			exited = true
		default:
		}
		if exited {
			break
		}
		entries, err := os.ReadDir(tempDir)
		if err != nil {
			_ = command.Process.Kill()
			<-waited
			t.Fatalf("inspect temp directory: %v", err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "picocrypt-stdin-") {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		if exited {
			// A legitimate platform resource-admission denial refuses the
			// fixed 1 GiB KDF profile before encryption, so the staging temp
			// is created and removed within milliseconds and the poll cannot
			// observe it. Convert only that environment denial into a skip;
			// any other early exit stays a failure with stderr attached.
			exitCode := 0
			if runErr != nil {
				exitCode = 1
				var exitErr *exec.ExitError
				if errors.As(runErr, &exitErr) {
					exitCode = exitErr.ExitCode()
				}
			}
			result := cliTestResult{exitCode: exitCode, stderr: stderr.String()}
			t.Fatalf("CLI exited before the stdin plaintext temp was observed: exit %d stderr %q", exitCode, result.stderr)
		}
		_ = command.Process.Kill()
		<-waited
		t.Fatal("CLI did not create the stdin plaintext temp")
	}
	if err := os.Chmod(tempDir, 0o500); err != nil {
		_ = command.Process.Kill()
		<-waited
		t.Fatalf("make temp directory non-writable: %v", err)
	}
	err := <-waited
	if chmodErr := os.Chmod(tempDir, 0o700); chmodErr != nil {
		t.Fatalf("restore temp directory permissions: %v", chmodErr)
	}
	if err == nil {
		t.Fatalf("CLI reported success after plaintext cleanup failed; stderr = %q", stderr.String())
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "cleanup") {
		t.Fatalf("cleanup failure was not reported: %q", stderr.String())
	}
}

func TestPCV3DecryptStdoutCancelsWithoutPlaintextResidue(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process interrupt and unlink semantics are platform-specific")
	}

	dir := t.TempDir()
	tempDir := filepath.Join(dir, "temp")
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		t.Fatalf("create temp directory: %v", err)
	}
	plaintext := bytes.Repeat([]byte("blocked stdout plaintext\n"), 100_000)
	input := filepath.Join(dir, "plain.bin")
	volume := filepath.Join(dir, "encrypted.pcv")
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	binary := buildCLITestBinary(t)
	encrypted := runCLITestCommand(
		t,
		binary,
		"encrypt", input, "-o", volume, "--pcv3", "-p", "signal-password", "--quiet",
	)
	if encrypted.exitCode != 0 {
		t.Fatalf("prepare PCV3 volume: exit %d stderr %q", encrypted.exitCode, encrypted.stderr)
	}

	stderrPath := filepath.Join(dir, "stderr")
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		t.Fatalf("create stderr capture: %v", err)
	}
	command := exec.Command(
		binary,
		"--temp-dir", tempDir,
		"decrypt", volume, "-o", "-",
		"--pcv3-factors=password", "-p", "signal-password", "--quiet",
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stderrFile.Close()
		t.Fatalf("create stdout pipe: %v", err)
	}
	defer stdout.Close()
	command.Stderr = stderrFile
	if err := command.Start(); err != nil {
		_ = stderrFile.Close()
		t.Fatalf("start decrypt: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	published := false
	for time.Now().Before(deadline) {
		captured, readErr := os.ReadFile(stderrPath)
		if readErr != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			_ = stderrFile.Close()
			t.Fatalf("read stderr capture: %v", readErr)
		}
		if bytes.Contains(captured, []byte("Publication: published-durable")) {
			published = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !published {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = stderrFile.Close()
		t.Fatal("decrypt did not reach durable publication")
	}
	if err := command.Process.Signal(os.Interrupt); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = stderrFile.Close()
		t.Fatalf("interrupt decrypt: %v", err)
	}

	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-waited
		_ = stderrFile.Close()
		t.Fatal("decrypt did not stop after SIGINT")
	}
	if err := stderrFile.Close(); err != nil {
		t.Fatalf("close stderr capture: %v", err)
	}
	captured, err := os.ReadFile(stderrPath)
	if err != nil {
		t.Fatalf("read final stderr: %v", err)
	}
	if !bytes.Contains(captured, []byte("Cancelling operation")) {
		t.Fatalf("SIGINT bypassed cooperative cancellation: %q", captured)
	}
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("inspect temp directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "picocrypt-out-") {
			t.Fatalf("plaintext temp remained after SIGINT: %s", entry.Name())
		}
	}
}

func TestCLIInterruptDuringStdinBufferingRemovesPlaintextTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process interrupt and open-file unlink semantics are platform-specific")
	}

	dir := t.TempDir()
	tempDir := filepath.Join(dir, "temp")
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		t.Fatalf("create temp directory: %v", err)
	}
	binary := buildCLITestBinary(t)
	command := exec.Command(
		binary,
		"--temp-dir", tempDir,
		"encrypt", "-", "-o", filepath.Join(dir, "encrypted.pcv"),
		"--pcv3", "-p", "buffer-signal-password", "--quiet",
	)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		t.Fatalf("start encrypt: %v", err)
	}
	if _, err := stdin.Write([]byte("plaintext held in an open input pipe")); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("write stdin: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		entries, readErr := os.ReadDir(tempDir)
		if readErr != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("inspect temp directory: %v", readErr)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "picocrypt-stdin-") {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("CLI did not create the stdin plaintext temp")
	}
	if err := command.Process.Signal(os.Interrupt); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("interrupt encrypt: %v", err)
	}
	_ = stdin.Close()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-waited
		t.Fatal("encrypt did not stop after SIGINT")
	}
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("inspect final temp directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "picocrypt-stdin-") {
			t.Fatalf("plaintext temp remained after SIGINT: %s", entry.Name())
		}
	}
}

func TestStreamFileToStdoutLarge(t *testing.T) {
	// Test streaming 1 MiB
	testData := make([]byte, 1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	tmpFile, err := os.CreateTemp("", "stream-large-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(testData); err != nil {
		tmpFile.Close()
		t.Fatal(err)
	}
	tmpFile.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	os.Stdout = w

	errCh := make(chan error, 1)
	go func() {
		errCh <- StreamFileToStdout(context.Background(), tmpPath)
		w.Close()
	}()

	var captured bytes.Buffer
	io.Copy(&captured, r)
	os.Stdout = oldStdout

	if err := <-errCh; err != nil {
		t.Fatalf("StreamFileToStdout() error = %v", err)
	}

	if !bytes.Equal(captured.Bytes(), testData) {
		t.Error("large data output mismatch")
	}
}
