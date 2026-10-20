//go:build linux

package cli

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// A real EncryptedSpool holds its normal owner lock while the existing Cancel
// callback stalls a write/seal. Only that uncooperative I/O boundary is injected;
// the child runs the production OS signal controller and exit path.
func TestEncryptedStdinBlockedOwnerSignalProcess(t *testing.T) {
	mode := os.Getenv("PICOCRYPT_STDIN_LOCK_HELPER")
	if mode == "" {
		return
	}
	rootCmd.AddCommand(&cobra.Command{Use: "blocked-spool", Run: func(*cobra.Command, []string) {
		var block atomic.Bool
		entered := make(chan struct{})
		release := make(chan struct{})
		owner, err := fileops.CreateEncryptedSpool(context.Background(), fileops.EncryptedSpoolOptions{NearPath: filepath.Join(os.Getenv("PICOCRYPT_STDIN_LOCK_DIR"), "out"), MaxPhysicalBytes: 1 << 20, Cancel: func() bool {
			if block.Load() {
				close(entered)
				<-release
			}
			return false
		}})
		if err != nil {
			os.Exit(80)
		}
		if mode == "seal" {
			if _, err := owner.Write([]byte("pending plaintext is memory only")); err != nil {
				os.Exit(81)
			}
		}
		activeEncryptedStdin.Store(owner)
		reporter := NewReporter(true)
		globalReporter.Store(reporter)
		block.Store(true)
		go func() {
			if mode == "seal" {
				_ = owner.Seal()
			} else {
				_, _ = owner.Write(make([]byte, 65537))
			}
		}()
		<-entered
		go func() {
			for !reporter.IsCancelled() {
				time.Sleep(time.Millisecond)
			}
			_ = os.WriteFile(os.Getenv("PICOCRYPT_STDIN_LOCK_RESULT"), []byte("CANCEL OBSERVED"), 0o600)
		}()
		fmt.Fprintln(os.Stderr, "BLOCKED SPOOL READY")
		select {}
	}})
	os.Args = []string{os.Args[0], "blocked-spool"}
	os.Exit(executeCLICommand())
}

func TestEncryptedStdinForcedInterruptDoesNotWaitForOwnerWriteOrSeal(t *testing.T) {
	for _, mode := range []string{"write", "seal"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			stderrPath, resultPath := filepath.Join(dir, "stderr"), filepath.Join(dir, "result")
			stderr, err := os.Create(stderrPath)
			if err != nil {
				t.Fatal(err)
			}
			defer stderr.Close()
			command := exec.Command(os.Args[0], "-test.run=^TestEncryptedStdinBlockedOwnerSignalProcess$")
			command.Env = append(os.Environ(), "PICOCRYPT_STDIN_LOCK_HELPER="+mode, "PICOCRYPT_STDIN_LOCK_DIR="+dir, "PICOCRYPT_STDIN_LOCK_RESULT="+resultPath)
			command.Stderr = stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait(); close(done) }()
			t.Cleanup(func() { _ = command.Process.Kill(); <-done })
			awaitCancellationText(t, stderrPath, "BLOCKED SPOOL READY")
			if err := command.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				observed, _ := os.ReadFile(resultPath)
				if string(observed) == "CANCEL OBSERVED" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("first interrupt waited behind the encrypted owner lock")
				}
				time.Sleep(time.Millisecond)
			}
			if err := command.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			requireCancellationExit(t, done)
		})
	}
}
