//go:build linux

package volume

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPrepareLegacySplitRejectsSpecialChunkZeroWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.pcv.0")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		prepared, err := PrepareDecryptInput(path, true)
		if prepared != nil {
			err = prepared.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("special chunk zero accepted")
		}
	case <-time.After(250 * time.Millisecond):
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("FIFO preparation did not stop after releasing peer")
		}
		t.Fatal("chunk-zero preparation waited for FIFO peer")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("special source changed: %v %v", info, err)
	}
}
