//go:build linux

package ui

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The real walk retains an enumeration descriptor through its final context
// check. Substitute its already-classified directory at that boundary, before
// the deletion-manifest callback reopens it. No filesystem operation is mocked.
type deletionDirectoryFIFOContext struct {
	context.Context
	mu         sync.Mutex
	root       string
	liveChecks int
	swapped    bool
	swapErr    error
}

func (ctx *deletionDirectoryFIFOContext) Err() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if !ctx.swapped && ctx.swapErr == nil {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			ctx.swapErr = err
			return ctx.Context.Err()
		}
		live := false
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if err != nil && !os.IsNotExist(err) {
				ctx.swapErr = err
				return ctx.Context.Err()
			}
			live = live || target == ctx.root
		}
		if live {
			ctx.liveChecks++
		}
		if ctx.liveChecks == 2 {
			ctx.swapErr = os.Rename(ctx.root, ctx.root+".original")
			if ctx.swapErr == nil {
				ctx.swapErr = unix.Mkfifo(ctx.root, 0o600)
			}
			ctx.swapped = ctx.swapErr == nil
		}
	}
	return ctx.Context.Err()
}

func TestDeletionManifestDirectorySubstitutionCannotBlockOnFIFO(t *testing.T) {
	if dir := os.Getenv("PICOCRYPT_DELETION_DIRECTORY_FIFO_HELPER"); dir != "" {
		budget := fileops.NewZIPResourceBudget()
		ctx := &deletionDirectoryFIFOContext{Context: context.Background(), root: filepath.Join(dir, "selected")}
		manifest, err := captureOperationDeletionManifestWithBudget(ctx, operationInput{mode: "encrypt", inputFiles: []string{filepath.Join(dir, "source")}, onlyFolders: []string{ctx.root}, delete: true}, budget)
		if manifest != nil {
			manifest.metadata.Release()
			budget.Release(manifest.charged)
		}
		if !ctx.swapped || ctx.swapErr != nil {
			t.Fatalf("substitution did not run: swapped=%v err=%v", ctx.swapped, ctx.swapErr)
		}
		if err == nil || manifest != nil {
			t.Fatalf("FIFO directory admitted: manifest=%v err=%v", manifest, err)
		}
		if budget.CurrentBytes() != 0 {
			t.Fatal("refused manifest retained metadata")
		}
		return
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "selected"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "source"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDeletionManifestDirectorySubstitutionCannotBlockOnFIFO$", "-test.v")
	command.Env = append(os.Environ(), "PICOCRYPT_DELETION_DIRECTORY_FIFO_HELPER="+dir)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("manifest directory reopen blocked/failed: %v context=%v\n%s", err, ctx.Err(), output)
	}
	if body, err := os.ReadFile(filepath.Join(dir, "source")); err != nil || string(body) != "original" {
		t.Fatalf("source changed: %q %v", body, err)
	}
}
