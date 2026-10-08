//go:build linux

package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A substituted FIFO must fail before operation/KDF admission and release all
// descriptors already accumulated by the CLI request.
func TestPCV3CLIKeyfileFIFORefusesBeforeOperationWithoutBlocking(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first.key")
	pipe := filepath.Join(directory, "factor.pipe")
	target := filepath.Join(directory, "output")
	if err := os.WriteFile(first, []byte("regular keyfile"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	oldOutput, oldFactors, oldOrder, oldKeyfiles := decOutput, decPCV3Factors, decPCV3Order, decKeyfiles
	decOutput, decPCV3Factors, decPCV3Order, decKeyfiles = target, "keyfiles", "ordered", []string{first, pipe}
	originalOpen, originalRun := pcv3CLIOpenKeyfile, pcv3CLIRunOperation
	var opened []*os.File
	called := false
	pcv3CLIOpenKeyfile = func(path string) (*os.File, error) {
		file, err := originalOpen(path)
		if file != nil {
			opened = append(opened, file)
		}
		return file, err
	}
	pcv3CLIRunOperation = func(context.Context, *pcv3operation.Request, bool) pcv3CLIResult { called = true; return nil }
	t.Cleanup(func() {
		decOutput, decPCV3Factors, decPCV3Order, decKeyfiles = oldOutput, oldFactors, oldOrder, oldKeyfiles
		pcv3CLIOpenKeyfile, pcv3CLIRunOperation = originalOpen, originalRun
	})
	done := make(chan error, 1)
	go func() { done <- runPCV3CLI(context.Background(), source, true, "", "") }()
	blocked := false
	select {
	case err = <-done:
	case <-time.After(250 * time.Millisecond):
		blocked = true
		fd, peerErr := unix.Open(pipe, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if peerErr != nil {
			t.Fatal(peerErr)
		}
		if peerErr = unix.Close(fd); peerErr != nil {
			t.Fatal(peerErr)
		}
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("keyfile preparation did not finish after FIFO peer release")
		}
	}
	if err == nil || called {
		t.Fatalf("FIFO reached operation admission: err=%v called=%v", err, called)
	}
	if len(opened) == 0 {
		t.Fatal("regular factor was never opened; cleanup oracle is vacuous")
	}
	for _, file := range append(opened, source) {
		if _, err := file.Stat(); err == nil {
			t.Fatalf("rejected request retained descriptor %q", file.Name())
		}
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FIFO request created output: %v", err)
	}
	if blocked {
		t.Fatal("keyfile preparation blocked until an external FIFO writer connected")
	}
}
