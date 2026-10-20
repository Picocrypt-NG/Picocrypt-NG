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
	"sync"
	"testing"
	"time"
)

// The pipe deliberately stays open, so this exercises crash residue before any
// KDF or public volume output. Replacing encrypted staging with plaintext must
// fail even when the process never reaches normal cleanup.
func TestCLIEncryptionStdinCrashLeavesOnlyCiphertext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("open stage inspection is POSIX-specific")
	}
	dir := t.TempDir()
	command := exec.Command(buildCLITestBinary(t), "--temp-dir", dir, "encrypt", "-", "-o", filepath.Join(t.TempDir(), "out.pcv"), "-p", "unused-before-eof", "--quiet")
	pipe, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = pipe.Close(); _ = command.Wait() }()
	marker := []byte("sensitive stdin crash residue marker ")
	plain := bytes.Repeat(marker, 6000)
	if _, err := pipe.Write(plain); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var stage string
	var physical []byte
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "picocrypt-stdin-") || strings.HasPrefix(entry.Name(), ".picocrypt-") {
				stage = filepath.Join(dir, entry.Name())
				physical, err = os.ReadFile(stage)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		if len(physical) > 65536 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(physical) <= 65536 {
		t.Fatalf("stdin staging not observed: %s", stderr.String())
	}
	if bytes.Contains(physical, marker) {
		t.Fatal("encryption stdin wrote plaintext to crash-visible disk staging")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	physical, err = os.ReadFile(stage)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(physical, marker) {
		t.Fatal("killed CLI left plaintext staging")
	}
}

func TestEncryptedStdinSpoolReadbackAndCleanup(t *testing.T) {
	old := TempDirOverride
	TempDirOverride = t.TempDir()
	defer func() { TempDirOverride = old }()
	for _, plain := range [][]byte{nil, bytes.Repeat([]byte("private piped input"), 10000)} {
		spool, err := bufferEncryptedInput(context.Background(), bytes.NewReader(plain), "")
		if err != nil {
			t.Fatal(err)
		}
		path := spool.Path()
		disk, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(plain) > 0 && bytes.Contains(disk, plain[:64]) {
			t.Fatal("plaintext staging")
		}
		reader, err := spool.OpenReader()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("stdin readback: %v", err)
		}
		if err := closeEncryptedStdin(spool); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging retained: %v", err)
		}
	}
}

func TestEncryptedStdinPhysicalBudgetRetainsExistingHeadroom(t *testing.T) {
	for _, row := range []struct {
		available int64
		want      uint64
		fail      bool
	}{
		{minBuffer, 0, true}, {minBuffer + 24, 16, false}, {minBuffer + 98352, 65568, false},
	} {
		got, err := encryptedStdinPhysicalBudget(row.available)
		if (err != nil) != row.fail || got != row.want {
			t.Fatalf("available=%d budget=%d err=%v", row.available, got, err)
		}
	}
}

func TestCLIEncryptedStdinPipeRoundTrip(t *testing.T) {
	if os.Getenv("PICOCRYPT_RUN_CLI_INTEGRATION") != "1" {
		t.Skip("set PICOCRYPT_RUN_CLI_INTEGRATION=1 for real-KDF pipe roundtrips")
	}
	binary := buildCLITestBinary(t)
	for _, row := range []struct {
		name     string
		plain    []byte
		compress bool
	}{
		{name: "empty"},
		{name: "multiple_records", plain: bytes.Repeat([]byte("raw pipe plaintext "), 12000)},
		{name: "compressed_multiple_records", plain: bytes.Repeat([]byte("compress pipe plaintext "), 12000), compress: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			volumePath := filepath.Join(dir, "volume.pcv")
			args := []string{"encrypt", "-", "-o", volumePath, "-p", "stdin-pipe-roundtrip"}
			if row.compress {
				args = append(args, "--compress")
			}
			command := exec.Command(binary, args...)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			command.Stdin = reader
			written := make(chan error, 1)
			go func() { _, err := writer.Write(row.plain); written <- errors.Join(err, writer.Close()) }()
			result := runStreamIntegrationCommand(t, command, nil)
			_ = reader.Close()
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			requireNativePCV3Published(t, result, "")
			recovered := filepath.Join(dir, "recovered")
			decryptArgs := []string{"decrypt", volumePath, "-o", recovered, "--pcv3-factors=password", "-p", "stdin-pipe-roundtrip"}
			extractDir := ""
			if row.compress {
				extractDir = t.TempDir()
				decryptArgs = append(decryptArgs, "--pcv3-archive=extract", "--pcv3-extract-to="+extractDir)
			}
			command = exec.Command(binary, decryptArgs...)
			requireNativePCV3Published(t, runStreamIntegrationCommand(t, command, nil), "")
			if row.compress {
				entries, err := os.ReadDir(extractDir)
				if err != nil || len(entries) != 1 || entries[0].IsDir() {
					t.Fatalf("single piped ZIP entry: %v %v", entries, err)
				}
				recovered = filepath.Join(extractDir, entries[0].Name())
			}
			got, err := os.ReadFile(recovered)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, row.plain) {
				t.Fatalf("recovered plaintext differs: got %d want %d", len(got), len(row.plain))
			}
		})
	}
}

func TestEncryptedStdinReadFailureCleansOwnedStageWithoutFallback(t *testing.T) {
	old := TempDirOverride
	TempDirOverride = t.TempDir()
	defer func() { TempDirOverride = old }()
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	spool, err := bufferEncryptedInput(context.Background(), source, "")
	if err == nil || spool != nil {
		t.Fatal("failed stdin read transferred an encrypted owner")
	}
	if activeEncryptedStdin.Load() != nil {
		t.Fatal("failed read retained active cleanup authority")
	}
	entries, err := os.ReadDir(TempDirOverride)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed read left temporary data: %v %v", entries, err)
	}
}

type stdinEnteredReader struct {
	*os.File
	entered chan struct{}
	once    sync.Once
}

func (reader *stdinEnteredReader) Read(p []byte) (int, error) {
	reader.once.Do(func() { close(reader.entered) })
	return reader.File.Read(p)
}

func TestEncryptedStdinSignalCancelsBlockedReadAndLetsCommandCleanUp(t *testing.T) {
	oldDir, oldExit := TempDirOverride, exitFn
	TempDirOverride = t.TempDir()
	globalReporter.Store(nil)
	defer func() { TempDirOverride = oldDir; exitFn = oldExit }()
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	source := &stdinEnteredReader{File: input, entered: make(chan struct{})}
	exited := make(chan int, 1)
	exitFn = func(code int) { exited <- code }
	buffered := make(chan error, 1)
	go func() {
		spool, err := bufferEncryptedInput(context.Background(), source, "")
		if spool != nil {
			_ = closeEncryptedStdin(spool)
		}
		buffered <- err
	}()
	defer func() {
		_ = input.Close()
		select {
		case <-buffered:
		case <-time.After(2 * time.Second):
			t.Error("buffering goroutine did not unwind")
		}
	}()
	select {
	case <-source.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("stdin buffering did not reach blocked read")
	}
	signalDone := make(chan struct{})
	go func() { handleSignal(); close(signalDone) }()
	select {
	case <-signalDone:
	case <-time.After(2 * time.Second):
		t.Fatal("signal controller waited for spool cleanup")
	}
	select {
	case code := <-exited:
		t.Errorf("active buffering exited directly with code %d", code)
	default:
	}
	select {
	case err := <-buffered:
		buffered <- err // retain completion for cleanup above
		if !errors.Is(err, context.Canceled) {
			t.Errorf("blocked stdin cancellation=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("signal failed to interrupt the blocked stdin read")
	}
	entries, err := os.ReadDir(TempDirOverride)
	if err != nil || len(entries) != 0 {
		t.Errorf("cancelled stdin retained owned stage: %v %v", entries, err)
	}
}
