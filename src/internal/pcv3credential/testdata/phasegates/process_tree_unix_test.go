//go:build linux || darwin

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixProcessTreeTimeoutKillsDescendants(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve Unix helper executable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(
		ctx,
		executable,
		"-test.run=^TestUnixProcessTreeHelper$",
		"--",
		"parent",
	)
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create Unix helper stdin pipe: %v", err)
	}
	defer stdinReader.Close()
	defer stdinWriter.Close()
	cmd.Stdin = stdinReader
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("open Unix helper stdout: %v", err)
	}
	tree, err := newProcessTree(cmd)
	if err != nil {
		t.Fatalf("construct Unix process tree: %v", err)
	}
	cmd.Cancel = tree.Terminate
	cmd.WaitDelay = processWaitDelay
	if err := tree.Start(); err != nil {
		t.Fatalf("start Unix process tree: %v", err)
	}
	parentPID := cmd.Process.Pid
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("read grandchild PID: %v", scanner.Err())
	}
	grandchildPID, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	if err != nil {
		t.Fatalf("parse grandchild PID: %v", err)
	}

	cancel()
	waitErr := tree.Wait()
	if waitErr == nil {
		t.Fatal("canceled Unix process tree unexpectedly exited successfully")
	}
	if err := stdinWriter.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatalf("close Unix helper stdin writer: %v", err)
	}
	for scanner.Scan() {
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatalf("drain Unix helper stdout after cancellation: %v", err)
	}
	active, err := waitForProcessTreeInactive(tree, processWaitDelay)
	if err != nil {
		t.Fatalf("wait for terminated Unix process group: %v", err)
	}
	if active {
		t.Fatal("Unix process group remains active after bounded cancellation wait")
	}
	if processIsRunning(parentPID) {
		t.Fatalf("parent PID %d survived process-group cancellation", parentPID)
	}
	if processIsRunning(grandchildPID) {
		t.Fatalf("grandchild PID %d survived process-group cancellation", grandchildPID)
	}
	if err := tree.Wait(); err == nil {
		t.Fatal("Unix process tree allowed Wait more than once")
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("close Unix process tree: %v", err)
	}
}

func TestPublicationProofLinkNeverReplaces(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openEvidenceRootHandle(rootPath)
	if err != nil {
		t.Fatalf("open publication-proof root: %v", err)
	}
	defer root.Close()
	pending, err := createEvidenceFileAt(root, "pending")
	if err != nil {
		t.Fatalf("create pending proof: %v", err)
	}
	if _, err := pending.Write([]byte("proof")); err != nil {
		t.Fatalf("write pending proof: %v", err)
	}
	if _, err := pending.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind pending proof: %v", err)
	}
	pendingInfo, err := pending.Stat()
	if err != nil {
		t.Fatalf("stat pending proof: %v", err)
	}
	existing, err := createEvidenceFileAt(root, "verified")
	if err != nil {
		t.Fatalf("create existing proof: %v", err)
	}
	if _, err := existing.Write([]byte("existing")); err != nil {
		t.Fatalf("write existing proof: %v", err)
	}
	if err := existing.Close(); err != nil {
		t.Fatalf("close existing proof: %v", err)
	}
	if err := linkPublicationProofAt(root, "pending", "verified"); err == nil {
		t.Fatal("publication proof hard link replaced an existing final path")
	}
	existingBytes, err := os.ReadFile(filepath.Join(rootPath, "verified"))
	if err != nil || string(existingBytes) != "existing" {
		t.Fatalf("failed hard link changed existing proof: %q, %v", existingBytes, err)
	}
	if err := os.Remove(filepath.Join(rootPath, "verified")); err != nil {
		t.Fatalf("remove existing proof fixture: %v", err)
	}
	if err := linkPublicationProofAt(root, "pending", "verified"); err != nil {
		t.Fatalf("publish proof hard link: %v", err)
	}
	verifiedInfo, err := os.Stat(filepath.Join(rootPath, "verified"))
	if err != nil {
		t.Fatalf("stat verified proof: %v", err)
	}
	if !os.SameFile(pendingInfo, verifiedInfo) {
		t.Fatal("publication proof was not linked from the verified pending inode")
	}
	if _, err := os.Lstat(filepath.Join(rootPath, "pending")); !os.IsNotExist(err) {
		t.Fatalf("published pending proof path still exists: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatalf("close pending proof handle: %v", err)
	}
}

// Kills replacing the production directory-sync seam with a test-only no-op.
func TestDefaultDirectorySyncUsesRealImplementation(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openEvidenceRootHandle(rootPath)
	if err != nil {
		t.Fatalf("open real directory-sync root: %v", err)
	}
	entry, err := createEvidenceFileAt(root, "durable-entry")
	if err != nil {
		t.Fatalf("create real directory-sync entry: %v", err)
	}
	if _, err := entry.Write([]byte("durability smoke fixture")); err != nil {
		_ = entry.Close()
		t.Fatalf("write real directory-sync entry: %v", err)
	}
	if err := entry.Sync(); err != nil {
		_ = entry.Close()
		t.Fatalf("sync real directory-sync entry: %v", err)
	}
	if err := entry.Close(); err != nil {
		t.Fatalf("close real directory-sync entry: %v", err)
	}
	if err := defaultDeps().syncDirectory(root); err != nil {
		t.Fatalf("sync real authenticated directory: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("close real authenticated directory: %v", err)
	}
	if err := defaultDeps().syncDirectory(root); err == nil {
		t.Fatal("production directory sync accepted a closed handle")
	}
}

// Kills returning publication success after the final proof link exists but
// removal of the pending publication name failed.
func TestPublicationProofLinkFailsWhenPendingCannotBeUnlinked(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openEvidenceRootHandle(rootPath)
	if err != nil {
		t.Fatalf("open publication-proof root: %v", err)
	}
	defer root.Close()
	pending, err := createEvidenceFileAt(root, "pending")
	if err != nil {
		t.Fatalf("create pending proof: %v", err)
	}
	if _, err := pending.Write([]byte("proof")); err != nil {
		t.Fatalf("write pending proof: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatalf("close pending proof: %v", err)
	}
	sentinel := errors.New("sentinel pending unlink failure")
	err = linkPublicationProofAtWithUnlink(
		root,
		"pending",
		"verified",
		func(int, string, int) error {
			return sentinel
		},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("publication unlink error = %v; want sentinel in error chain", err)
	}
	finalInfo, finalErr := os.Stat(filepath.Join(rootPath, "verified"))
	pendingInfo, pendingErr := os.Stat(filepath.Join(rootPath, "pending"))
	if finalErr != nil || pendingErr != nil ||
		!os.SameFile(finalInfo, pendingInfo) {
		t.Fatalf(
			"test did not reach post-link pending-unlink failure: final=%v pending=%v",
			finalErr,
			pendingErr,
		)
	}
}

func TestUnixProcessTreeHelper(t *testing.T) {
	args := flag.Args()
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "parent":
		executable, err := os.Executable()
		if err != nil {
			t.Fatalf("resolve grandchild executable: %v", err)
		}
		grandchild := exec.Command(
			executable,
			"-test.run=^TestUnixProcessTreeHelper$",
			"--",
			"grandchild",
		)
		grandchild.Stdin = os.Stdin
		grandchild.Stdout = io.Discard
		grandchild.Stderr = os.Stderr
		if err := grandchild.Start(); err != nil {
			t.Fatalf("start grandchild: %v", err)
		}
		fmt.Println(grandchild.Process.Pid)
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = grandchild.Wait()
	case "grandchild":
		_, _ = io.Copy(io.Discard, os.Stdin)
	default:
		t.Fatalf("unknown Unix helper mode %q", args[0])
	}
}

func processIsRunning(pid int) bool {
	if runtimeState, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		fields := strings.Fields(string(runtimeState))
		return len(fields) < 3 || fields[2] != "Z"
	}
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}
