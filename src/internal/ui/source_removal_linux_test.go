//go:build linux && !android

package ui

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestSourceRemovalLowFDChild(t *testing.T) {
	const child = "PICOCRYPT_SOURCE_REMOVAL_LOW_FD"
	if os.Getenv(child) == "" {
		command := exec.Command(os.Args[0], "-test.run=^TestSourceRemovalLowFDChild$", "-test.count=1")
		command.Env = append(os.Environ(), child+"=1", "GOMAXPROCS=2")
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "ready-output")
	if err := os.WriteFile(output, []byte("ready output"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := &operationDeletionManifest{}
	for n := range 384 {
		parent := filepath.Join(dir, strconv.Itoa(n))
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		manifest.files = append(manifest.files, sourceRemovalFixture(t, parent, "source"))
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	limit := original
	limit.Cur = uint64(len(before) + 16)
	if limit.Cur > original.Cur {
		t.Fatalf("insufficient initial fd allowance: %+v", original)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &original); err != nil {
			t.Error(err)
		}
	}()
	result := (&App{}).cleanupOperationSources(context.Background(), operationInput{mode: "decrypt", delete: true}, manifest, operationResult{completed: true})
	if result.err != nil || !result.completed || result.cancelled || result.deleteFailed {
		t.Fatalf("cleanup under fd limit=%+v", result)
	}
	requireSourceRemovalBytes(t, output, "ready output")
	for _, source := range manifest.files {
		if _, err := os.Lstat(source.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source remains: %v", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before) {
		t.Fatalf("cleanup retained file descriptors: before=%d after=%d", len(before), len(after))
	}
}
