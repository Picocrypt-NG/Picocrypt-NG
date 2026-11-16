//go:build linux

package fileops

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCountChunksFIFOParentRefusesWithoutBlockingCancellation(t *testing.T) {
	const child = "PICOCRYPT_COUNT_FIFO_PARENT_CHILD"
	if pipe := os.Getenv(child); pipe != "" {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		timer := time.AfterFunc(50*time.Millisecond, cancel)
		defer timer.Stop()
		count, size, err := CountChunksWithCancel(filepath.Join(pipe, "input.pcv"), func() bool { return ctx.Err() != nil })
		if err == nil || count != 0 || size != 0 || !strings.Contains(err.Error(), "read chunk dir") {
			t.Fatalf("FIFO parent was not refused before directory reading: count=%d size=%d err=%v", count, size, err)
		}
		return
	}
	pipe := filepath.Join(t.TempDir(), "parent")
	if err := unix.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCountChunksFIFOParentRefusesWithoutBlockingCancellation$", "-test.v")
	command.Env = append(os.Environ(), child+"="+pipe)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("FIFO parent count blocked or failed: %v context=%v\n%s", err, ctx.Err(), output)
	}
	info, err := os.Lstat(pipe)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO source changed: %v %v", info, err)
	}
}
