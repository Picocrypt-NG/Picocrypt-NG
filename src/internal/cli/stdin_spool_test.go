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
	"testing/iotest"
	"time"

	"github.com/spf13/cobra"
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

func TestDecryptStdinStagingHonorsCancelledContextBeforeReading(t *testing.T) {
	oldDir, oldStdin := TempDirOverride, os.Stdin
	TempDirOverride = t.TempDir()
	defer func() { TempDirOverride, os.Stdin = oldDir, oldStdin }()
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdin = source

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	if err := runDecrypt(cmd, []string{"-"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("decrypt with a cancelled context = %v, want context.Canceled", err)
	}
}

func TestDecryptStdinStagingHonorsPhysicalBudget(t *testing.T) {
	oldDir, oldProbe := TempDirOverride, availableStdinTempSpace
	TempDirOverride = t.TempDir()
	defer func() { TempDirOverride, availableStdinTempSpace = oldDir, oldProbe }()
	availableStdinTempSpace = func(stage *os.File) (int64, error) {
		info, err := stage.Stat()
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() || info.Size() != 0 {
			return 0, errors.New("budget observation requires a held empty stage")
		}
		return minBuffer + 9, nil // Six ciphertext bytes after the reserve and multiplier.
	}

	t.Run("exact budget", func(t *testing.T) {
		path, err := bufferStdinToTemp(context.Background(), strings.NewReader("123456"), "")
		if err != nil {
			t.Fatal(err)
		}
		defer cleanupTempFiles(path)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "123456" {
			t.Fatalf("staged bytes = %q, error %v", got, err)
		}
	})

	for _, useStdout := range []bool{false, true} {
		name := "file output"
		if useStdout {
			name = "stdout output"
		}
		t.Run(name, func(t *testing.T) {
			input, err := os.CreateTemp(t.TempDir(), "input")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err := input.WriteString("1234567"); err != nil {
				t.Fatal(err)
			}
			if _, err := input.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}

			stdout, err := os.CreateTemp(t.TempDir(), "stdout")
			if err != nil {
				t.Fatal(err)
			}
			defer stdout.Close()
			target := filepath.Join(t.TempDir(), "output")
			if err := os.WriteFile(target, []byte("existing output"), 0o600); err != nil {
				t.Fatal(err)
			}

			oldInput, oldStdout, oldOutput, oldQuiet := os.Stdin, os.Stdout, decOutput, decQuiet
			defer func() { os.Stdin, os.Stdout, decOutput, decQuiet = oldInput, oldStdout, oldOutput, oldQuiet }()
			os.Stdin, os.Stdout, decOutput = input, stdout, target
			if useStdout {
				decOutput = "-"
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			if err := runDecrypt(cmd, []string{"-"}); !errors.Is(err, errStdinTempBudget) {
				t.Fatalf("decrypt above stage budget = %v, want budget error", err)
			}

			info, err := stdout.Stat()
			if err != nil || info.Size() != 0 {
				t.Fatalf("budget rejection wrote to stdout: %v, %v", info, err)
			}
			got, err := os.ReadFile(target)
			if err != nil || string(got) != "existing output" {
				t.Fatalf("budget rejection changed target: %q, %v", got, err)
			}
			entries, err := os.ReadDir(TempDirOverride)
			if err != nil || len(entries) != 0 || activeStdinTempPath.Load() != nil {
				t.Fatalf("budget rejection left temporary data: %v, %v", entries, err)
			}
		})
	}
}

func TestCopyStdinWithinBudgetNeverWritesExcess(t *testing.T) {
	var output strings.Builder
	input := iotest.OneByteReader(strings.NewReader("1234567"))
	err := copyStdinWithinBudget(context.Background(), &output, input, 6)
	if !errors.Is(err, errStdinTempBudget) || output.String() != "123456" {
		t.Fatalf("copy beyond budget wrote %q, error %v", output.String(), err)
	}
}

func TestCopyStdinWithinBudgetChecksCancellationBeforeWriting(t *testing.T) {
	var output strings.Builder
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := cliTestReaderFunc(func(p []byte) (int, error) {
		cancel()
		return copy(p, "data"), io.EOF
	})
	if err := copyStdinWithinBudget(ctx, &output, input, 6); output.Len() != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled copy wrote %d bytes, error %v", output.Len(), err)
	}
}

func TestDecryptStdinStagingCleansUpIfSpaceProbeFails(t *testing.T) {
	oldDir, oldProbe := TempDirOverride, availableStdinTempSpace
	TempDirOverride = t.TempDir()
	defer func() { TempDirOverride, availableStdinTempSpace = oldDir, oldProbe }()
	probeErr := errors.New("temporary space observation failed")
	var stage *os.File
	availableStdinTempSpace = func(file *os.File) (int64, error) {
		stage = file
		return 0, probeErr
	}
	input := cliTestReaderFunc(func([]byte) (int, error) {
		t.Error("input was read after resource check failed")
		return 0, io.EOF
	})
	path, err := bufferStdinToTemp(context.Background(), input, "")
	if path != "" || !errors.Is(err, probeErr) || stage == nil {
		t.Fatalf("space probe failure returned path %q, error %v", path, err)
	}
	if _, err := stage.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("space probe failure left the stage open: %v", err)
	}
	if _, err := os.Stat(stage.Name()); !errors.Is(err, os.ErrNotExist) || activeStdinTempPath.Load() != nil {
		t.Fatalf("space probe failure retained the stage: %v", err)
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
