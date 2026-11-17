//go:build linux

package fileops

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRecombineRejectsLaterFIFOReplacementWithoutWaitingForPeer(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "input.pcv")
	expected := make([]os.FileInfo, 2)
	for i, path := range []string{base + ".0", base + ".1"} {
		if err := os.WriteFile(path, []byte("selected chunk"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		expected[i], err = os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "recombined")
	done := make(chan error, 1)
	go func() {
		done <- Recombine(RecombineOptions{InputBase: base, OutputPath: output, ExpectedInputs: expected, Progress: func(_ float32, part string) {
			if part == "1/2" {
				if err := os.Rename(base+".1", base+".1.selected"); err != nil {
					panic(err)
				}
				if err := unix.Mkfifo(base+".1", 0o600); err != nil {
					panic(err)
				}
			}
		}})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO replacement accepted")
		}
	case <-time.After(250 * time.Millisecond):
		fd, err := unix.Open(base+".1", unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("FIFO reader did not stop after releasing peer")
		}
		t.Fatal("chunk open waited for FIFO peer")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FIFO refusal retained output: %v", err)
	}
	if got, err := os.ReadFile(base + ".1.selected"); err != nil || string(got) != "selected chunk" {
		t.Fatalf("selected source changed: %q %v", got, err)
	}
}
