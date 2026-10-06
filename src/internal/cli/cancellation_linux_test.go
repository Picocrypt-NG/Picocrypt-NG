package cli

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Self-reexec runs the real CLI entry point and signal registration. Only the
// deliberately uncooperative command is synthetic; it models a stuck provider.
func TestCLICancellationProcess(t *testing.T) {
	mode := os.Getenv("PICOCRYPT_CANCELLATION_HELPER")
	if mode == "" {
		return
	}
	args := strings.Split(os.Getenv("PICOCRYPT_CANCELLATION_ARGS"), "\n")
	if mode == "legacy-fixture" {
		codecs, err := encoding.NewRSCodecs()
		if err != nil {
			os.Exit(82)
		}
		if err := volume.Encrypt(context.Background(), &volume.EncryptRequest{InputFiles: []string{args[0]}, OnlyFiles: []string{args[0]}, OutputFile: args[1], Password: []byte("test-password"), RSCodecs: codecs}); err != nil {
			os.Exit(83)
		}
		os.Exit(0)
	}
	if mode == "stuck" || mode == "stalled" {
		rootCmd.AddCommand(&cobra.Command{Use: "stuck", Run: func(*cobra.Command, []string) {
			captureTerminalState()
			state, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
			if err != nil {
				os.Exit(80)
			}
			state.Lflag &^= unix.ECHO
			if unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, state) != nil {
				os.Exit(81)
			}
			reporter := NewReporter(false)
			globalReporter.Store(reporter)
			go func() {
				for !reporter.IsCancelled() {
					time.Sleep(time.Millisecond)
				}
				_ = os.WriteFile(os.Getenv("PICOCRYPT_CANCELLATION_RESULT"), []byte("CANCEL OBSERVED"), 0o600)
			}()
			fmt.Fprintln(os.Stderr, "STUCK READY")
			if mode == "stalled" {
				reporter.SetStatus(strings.Repeat("progress", 100000))
				reporter.Update()
			}
			select {}
		}})
	}
	if mode == "consent" {
		realRun := pcv3CLIRunOperation
		pcv3CLIRunOperation = func(ctx context.Context, request *pcv3operation.Request, retain bool) pcv3CLIResult {
			result := realRun(ctx, request, retain)
			actual := result.(pcv3CLIResultAdapter).result
			if actual.Diagnostic() != pcv3operation.DiagnosticCancellation {
				_ = os.WriteFile(os.Getenv("PICOCRYPT_CANCELLATION_RESULT"), []byte(actual.Outcome().String()), 0o600)
			}
			if actual.Diagnostic() == pcv3operation.DiagnosticCancellation && actual.Stage() == pcv3operation.StageCancellation && !actual.PublicationAttempted() {
				_ = os.WriteFile(os.Getenv("PICOCRYPT_CANCELLATION_RESULT"), []byte("cancelled-no-publication"), 0o600)
			}
			return result
		}
	}
	os.Args = append([]string{os.Args[0]}, args...)
	Execute("test")
	if mode == "returned" {
		fmt.Fprintln(os.Stderr, "RETURNED")
		for {
			time.Sleep(time.Hour)
		}
	}
	os.Exit(0)
}

func cancellationPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func cancellationChild(t *testing.T, mode string, stdin, stdout *os.File, args ...string) (*exec.Cmd, <-chan error, string, string) {
	t.Helper()
	dir := t.TempDir()
	stderrPath, resultPath := filepath.Join(dir, "stderr"), filepath.Join(dir, "result")
	stderr, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stderr.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLICancellationProcess$")
	cmd.Env = append(os.Environ(), "PICOCRYPT_CANCELLATION_HELPER="+mode, "PICOCRYPT_CANCELLATION_ARGS="+strings.Join(args, "\n"), "PICOCRYPT_CANCELLATION_RESULT="+resultPath)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if mode == "stalled" {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
		cmd.Stderr = writer
		// Read only the readiness line. The following progress write fills the
		// pipe and holds the real Reporter's rendering mutex until process exit.
		ready := make(chan struct{})
		go func() {
			defer close(ready)
			var one [1]byte
			for {
				n, err := reader.Read(one[:])
				if err != nil {
					return
				}
				if n == 1 && one[0] == '\n' {
					_ = os.WriteFile(stderrPath, []byte("STUCK READY"), 0o600)
					return
				}
			}
		}()
		t.Cleanup(func() { _ = reader.Close(); <-ready })
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
	return cmd, done, stderrPath, resultPath
}

func awaitCancellationText(t *testing.T, path, text string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(text)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, _ := os.ReadFile(path)
	t.Fatalf("did not reach %q; stderr=%q", text, data)
}

func requireCancellationExit(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatalf("exit=%v; want exit code 1", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CLI did not exit after cancellation while input/consumer remained open")
	}
}

func TestPCV3ConsentSIGINTWithoutNewlineRestoresTTY(t *testing.T) {
	master, slave := cancellationPTY(t)
	original, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(slave.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "short.pcv"), filepath.Join(dir, "out")
	if err := os.WriteFile(input, []byte{'P', 'C', 'V', 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, done, stderr, result := cancellationChild(t, "consent", slave, nil, "decrypt", input, "-o", output, "--pcv3-action=force", "--pcv3-role=primary", "--pcv3-factors=password", "-p", "test-password", "-q")
	awaitCancellationText(t, stderr, "Type RECOVER UNVERIFIED")
	if _, err := master.Write([]byte("RECOVER")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	requireCancellationExit(t, done)
	data, err := os.ReadFile(result)
	if err != nil || string(data) != "cancelled-no-publication" {
		t.Fatalf("cancellation result=%q, err=%v", data, err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("cancelled consent published output: %v", err)
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil || !reflect.DeepEqual(original, after) {
		t.Fatalf("terminal mode changed: %v", err)
	}
	afterFlags, err := unix.FcntlInt(slave.Fd(), unix.F_GETFL, 0)
	if err != nil || flags != afterFlags {
		t.Fatalf("stdin flags changed: before=%x after=%x err=%v", flags, afterFlags, err)
	}
}

func TestCLIRepeatedSIGINTRestoresTTYAndExits(t *testing.T) {
	for _, mode := range []string{"stuck", "stalled"} {
		t.Run(mode, func(t *testing.T) {
			_, slave := cancellationPTY(t)
			original, err := term.GetState(int(slave.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			cmd, done, stderr, result := cancellationChild(t, mode, slave, nil, "stuck")
			awaitCancellationText(t, stderr, "STUCK READY")
			if mode == "stalled" {
				time.Sleep(50 * time.Millisecond)
			}
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				data, _ := os.ReadFile(result)
				if string(data) == "CANCEL OBSERVED" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("first SIGINT blocked behind progress output")
				}
				time.Sleep(time.Millisecond)
			}
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			requireCancellationExit(t, done)
			after, err := term.GetState(int(slave.Fd()))
			if err != nil || !reflect.DeepEqual(original, after) {
				t.Fatalf("forced exit left terminal no-echo: %v", err)
			}
		})
	}
}

func TestLegacyDecryptStdoutSIGINTWhileConsumerStalled(t *testing.T) {
	dir := t.TempDir()
	input, encrypted := filepath.Join(dir, "plain"), filepath.Join(dir, "legacy.pcv")
	plaintext := bytes.Repeat([]byte("legacy stdout cancellation\n"), 50000)
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	_, fixtureDone, _, _ := cancellationChild(t, "legacy-fixture", nil, nil, input, encrypted)
	select {
	case err := <-fixtureDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("legacy fixture encryption did not finish")
	}
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancel), func(t *testing.T) {
			tempDir := t.TempDir()
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			cmd, done, stderr, _ := cancellationChild(t, "legacy", nil, writer, "--temp-dir", tempDir, "decrypt", encrypted, "-o", "-", "-p", "test-password", "-q")
			_ = writer.Close()
			_ = reader.SetReadDeadline(time.Now().Add(20 * time.Second))
			if !cancel {
				got, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(got, plaintext) {
					t.Fatalf("stdout plaintext mismatch: len=%d err=%v", len(got), err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("CLI did not finish after stdout EOF")
				}
			} else {
				_ = reader.SetReadDeadline(time.Now().Add(10 * time.Second))
				var first [1]byte
				if _, err := io.ReadFull(reader, first[:]); err != nil {
					t.Fatal(err)
				}
				if err := cmd.Process.Signal(os.Interrupt); err != nil {
					t.Fatal(err)
				}
				requireCancellationExit(t, done)
				// The signal controller stays nonblocking; its ordinary unwind owns
				// the same visible cancellation notice previously printed by the handler.
				captured, err := os.ReadFile(stderr)
				if err != nil || !bytes.Contains(captured, []byte("Cancelling operation")) {
					t.Fatalf("missing cancellation notice: %q %v", captured, err)
				}
			}
			entries, err := os.ReadDir(tempDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("plaintext staging residue: %v %v", entries, err)
			}
		})
	}
}

// Real cooked input must still accept only the exact phrase; an incomplete
// source stops the approved case before KDF without requiring a mock runner.
func TestPCV3ConsentPTYAcceptsExactPhraseAndRefusesOtherText(t *testing.T) {
	for _, tc := range []struct{ name, line, outcome string }{
		{"valid", "RECOVER UNVERIFIED\n", "invalid-structure-pre-kdf"},
		{"refused", "recover unverified\n", "operation-failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master, slave := cancellationPTY(t)
			dir := t.TempDir()
			input, output := filepath.Join(dir, "short.pcv"), filepath.Join(dir, "out")
			if err := os.WriteFile(input, []byte{'P', 'C', 'V', 0}, 0o600); err != nil {
				t.Fatal(err)
			}
			_, done, stderr, result := cancellationChild(t, "consent", slave, nil, "decrypt", input, "-o", output, "--pcv3-action=force", "--pcv3-role=primary", "--pcv3-factors=password", "-p", "test-password", "-q")
			awaitCancellationText(t, stderr, "Type RECOVER UNVERIFIED")
			if _, err := master.Write([]byte(tc.line)); err != nil {
				t.Fatal(err)
			}
			requireCancellationExit(t, done)
			got, err := os.ReadFile(result)
			if err != nil || string(got) != tc.outcome {
				t.Fatalf("outcome=%q err=%v; want %q", got, err, tc.outcome)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("unexpected output: %v", err)
			}
		})
	}
}

func TestCLIReturnUnregistersSignals(t *testing.T) {
	cmd, done, stderr, _ := cancellationChild(t, "returned", nil, nil, "--version")
	awaitCancellationText(t, stderr, "RETURNED")
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != unix.SIGINT {
			t.Fatalf("signal still intercepted after Execute returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SIGINT ignored after Execute returned")
	}
}

func TestLegacyDecryptHonorsCancelledCommandContext(t *testing.T) {
	resetDecryptFlagsForDirTest()
	t.Cleanup(resetDecryptFlagsForDirTest)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decryptCmd.SetContext(ctx)
	t.Cleanup(func() { decryptCmd.SetContext(context.Background()) })
	decOutput = filepath.Join(t.TempDir(), "out")
	decPassword = "test"
	decQuiet = true
	err := runDecrypt(decryptCmd, []string{filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled command=%v", err)
	}
	if _, err := os.Lstat(decOutput); !os.IsNotExist(err) {
		t.Fatalf("cancelled command published output: %v", err)
	}
	if globalReporter.Load() != nil {
		t.Fatal("completed command retained global reporter")
	}
}
