//go:build linux && !android

package pcv3publication

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Run in an isolated root-owned scratch container with only SETUID/SETGID,
// no other capabilities. The hostile child is a real different UID, not a
// same-process seam pretending that POSIX 0700 enforced a boundary.
func TestPrivateCustodyDifferentUID(t *testing.T) {
	if os.Getenv("PICOCRYPT_CUSTODY_UID_CHILD") == "1" {
		fd := 3
		name := os.Getenv("PICOCRYPT_CUSTODY_DIR")
		inner := os.Getenv("PICOCRYPT_CUSTODY_STAGE")
		if os.Geteuid() != 1001 {
			t.Fatal("adversary identity not changed")
		}
		if os.Getenv("PICOCRYPT_CUSTODY_UID_VERIFY") == "1" {
			foreign, err := unix.Openat(fd, name+"/foreign", unix.O_RDONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 64)
			n, err := unix.Read(foreign, buffer)
			_ = unix.Close(foreign)
			if err != nil || string(buffer[:n]) != "foreign bytes" {
				t.Fatalf("foreign bytes changed: %q %v", buffer[:n], err)
			}
			if err := unix.Unlinkat(fd, name+"/foreign", 0); err != nil {
				t.Fatal(err)
			}
			if err := unix.Unlinkat(fd, name, unix.AT_REMOVEDIR); err != nil {
				t.Fatal(err)
			}
			return
		}
		// Same namespace rights can relocate the old design's 0600 sibling.
		if err := unix.Renameat(fd, "old-sibling", fd, "old-sibling-moved"); err != nil {
			t.Fatal(err)
		}
		for _, action := range []func() error{
			func() error {
				n, err := unix.Openat(fd, name+"/"+inner, unix.O_RDONLY, 0)
				if n >= 0 {
					_ = unix.Close(n)
				}
				return err
			},
			func() error { return unix.Renameat(fd, name+"/"+inner, fd, "stolen") },
			func() error { return unix.Unlinkat(fd, name+"/"+inner, 0) },
		} {
			if err := action(); !errors.Is(err, unix.EACCES) {
				t.Fatalf("private access must be denied: %v", err)
			}
		}
		if err := unix.Renameat(fd, name, fd, "relocated"); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkdirat(fd, name, 0o700); err != nil {
			t.Fatal(err)
		}
		foreign, err := unix.Openat(fd, name+"/foreign", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(foreign, []byte("foreign bytes")); err != nil {
			t.Fatal(err)
		}
		if err := unix.Close(foreign); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("PICOCRYPT_RUN_CUSTODY_UID") != "1" {
		t.Skip("requires isolated different-UID container lane")
	}
	if os.Geteuid() != 0 {
		t.Fatal("different-UID coordinator must run in isolated container as root")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "old-sibling"), []byte("legacy sibling"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := Create(filepath.Join(parent, "target"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if _, err := stage.File().Write([]byte("private plaintext")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPrivateCustodyDifferentUID$", "-test.v")
	cmd.Env = append(os.Environ(), "PICOCRYPT_CUSTODY_UID_CHILD=1", "PICOCRYPT_CUSTODY_DIR="+stage.sourceName, "PICOCRYPT_CUSTODY_STAGE="+stage.stageName)
	parentHandle, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentHandle.Close()
	cmd.ExtraFiles = []*os.File{parentHandle}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1001, Gid: 1001}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("different UID adversary: %v\n%s", err, output)
	}
	verify := func() {
		check := exec.Command(os.Args[0], "-test.run=^TestPrivateCustodyDifferentUID$", "-test.v")
		check.Env = append(append([]string(nil), cmd.Env...), "PICOCRYPT_CUSTODY_UID_VERIFY=1")
		check.ExtraFiles = []*os.File{parentHandle}
		check.SysProcAttr = cmd.SysProcAttr
		if output, err := check.CombinedOutput(); err != nil {
			t.Fatalf("foreign-owner verification: %v\n%s", err, output)
		}
	}
	// Root has no DAC override in this lane, so don't enter the attacker-owned
	// replacement. Child's successful writes plus its untouched directory inode
	// are independent preservation evidence; inspect via another UID1001 child.
	if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("unretired directory metadata: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(parent, "relocated"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("private plaintext residue: %v %v", entries, err)
	}
	if _, err := os.Lstat(filepath.Join(parent, stage.sourceName)); err != nil {
		t.Fatalf("foreign replacement removed: %v", err)
	}
	requireFileBytes(t, filepath.Join(parent, "old-sibling-moved"), []byte("legacy sibling"))
	verify()
}

func TestPrivateJournalSurvivesProcessKill(t *testing.T) {
	if boundary := os.Getenv("PICOCRYPT_CUSTODY_KILL_CHILD"); boundary != "" {
		parent := os.Getenv("PICOCRYPT_CUSTODY_KILL_PARENT")
		stage, err := Create(filepath.Join(parent, "target"), nil, PolicyNoReplace)
		if err != nil {
			t.Fatal(err)
		}
		if err := stage.PersistCleanupJournal(); err != nil {
			t.Fatal(err)
		}
		if _, err := stage.File().Write([]byte("authenticated plaintext")); err != nil {
			t.Fatal(err)
		}
		if err := stage.File().Sync(); err != nil {
			t.Fatal(err)
		}
		stop := func() { fmt.Println("custody-boundary"); select {} }
		if boundary == "before publish" {
			stop()
		}
		atomic := stage.operations.atomicPublish
		committed := false
		stage.operations.atomicPublish = func(source, parent, original *os.File, old, target string, policy Policy) error {
			err := atomic(source, parent, original, old, target, policy)
			if err == nil {
				committed = true
				if boundary == "after rename" {
					stop()
				}
			}
			return err
		}
		syncDirectory := stage.operations.syncDirectory
		syncs := 0
		stage.operations.syncDirectory = func(file *os.File) error {
			err := syncDirectory(file)
			if committed && err == nil {
				syncs++
				if boundary == "after namespace sync" && syncs == 2 {
					stop()
				}
			}
			return err
		}
		_ = stage.Publish(context.Background())
		t.Fatal("kill boundary not reached")
	}
	for _, boundary := range []string{"before publish", "after rename", "after namespace sync"} {
		t.Run(boundary, func(t *testing.T) {
			parent := t.TempDir()
			foreign := filepath.Join(parent, "foreign")
			if err := os.WriteFile(foreign, []byte("preserve foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPrivateJournalSurvivesProcessKill$")
			cmd.Env = append(os.Environ(), "PICOCRYPT_CUSTODY_KILL_CHILD="+boundary, "PICOCRYPT_CUSTODY_KILL_PARENT="+parent)
			pipe, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(pipe)
			if !scanner.Scan() || scanner.Text() != "custody-boundary" {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("child failed before kill boundary")
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err == nil {
				t.Fatal("expected killed child")
			}
			state, err := CleanupJournaledStage(parent)
			if err != nil || state != CleanupJournalCleaned {
				t.Fatalf("restart cleanup at %s: %v %v", boundary, state, err)
			}
			requireFileBytes(t, foreign, []byte("preserve foreign"))
			requireNoStageEntries(t, parent)
			requireAbsent(t, filepath.Join(parent, "target"))
		})
	}
}
