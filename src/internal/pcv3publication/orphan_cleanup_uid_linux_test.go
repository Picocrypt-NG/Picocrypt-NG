//go:build linux && !android

package pcv3publication

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Run only in the isolated root coordinator lane with SETUID/SETGID and no
// DAC override, CHOWN, or FOWNER. Ownership must come from real kernel UIDs.
func TestDesktopRecoveryDifferentUID(t *testing.T) {
	if action := os.Getenv("PICOCRYPT_ORPHAN_UID_ACTION"); action != "" {
		if os.Getenv("PICOCRYPT_RUN_CUSTODY_UID") != "1" {
			t.Fatal("different-UID child requires the isolated container lane")
		}
		if err := unix.Fchdir(3); err != nil {
			t.Fatal(err)
		}
		runOrphanUIDChild(t, action)
		return
	}
	if os.Getenv("PICOCRYPT_RUN_CUSTODY_UID") != "1" {
		t.Skip("requires isolated different-UID container lane")
	}
	if os.Geteuid() != 0 {
		t.Fatal("different-UID coordinator must run in isolated container as root")
	}
	for _, uid := range []uint32{0, 1001} {
		for _, action := range []string{"cleanup", "malformed"} {
			t.Run(fmt.Sprintf("euid%d/%s", uid, action), func(t *testing.T) {
				parent := t.TempDir()
				// Create resolves its target absolutely; expose only this test's
				// ancestor for traversal, and share the actual sticky destination.
				if err := os.Chmod(filepath.Dir(parent), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
					t.Fatal(err)
				}
				handle, err := os.Open(parent)
				if err != nil {
					t.Fatal(err)
				}
				defer handle.Close()
				run := func(uid uint32, role string) []byte {
					t.Helper()
					cmd := exec.Command(os.Args[0], "-test.run=^TestDesktopRecoveryDifferentUID$")
					cmd.Env = append(os.Environ(), "PICOCRYPT_ORPHAN_UID_ACTION="+role)
					cmd.ExtraFiles = []*os.File{handle}
					cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
					output, err := cmd.CombinedOutput()
					if err != nil {
						t.Errorf("euid %d %s: %v\n%s", uid, role, err, output)
					}
					return output
				}
				if action == "malformed" {
					run(uid, action)
					return
				}
				before := run(1002, "seed")
				defer run(1002, "remove")
				run(uid, action)
				if after := run(1002, "inspect"); string(after) != string(before) {
					t.Errorf("foreign inode, ownership, mode, link target or bytes changed\nbefore: %s\nafter: %s", before, after)
				}
			})
		}
	}
}

func runOrphanUIDChild(t *testing.T, action string) {
	t.Helper()
	const regular = stageNamePrefix + "foreign-file"
	const private = stageNamePrefix + "private-foreign-directory"
	const link = stageNamePrefix + "private-foreign-link"
	if action == "cleanup" {
		if os.Geteuid() != 0 && os.Geteuid() != 1001 {
			t.Fatal("cleanup identity not changed")
		}
		if err := os.WriteFile("victim", []byte("selected victim survives"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove("victim")
		victim, err := os.Lstat("victim")
		if err != nil {
			t.Fatal(err)
		}
		stage := createBoundedListingOrphan(t, ".", "output")
		defer os.RemoveAll(filepath.Dir(stage))
		state, err := CleanupOrphanedStages(".", nil)
		if err != nil || state != CleanupJournalCleaned {
			t.Errorf("foreign entries vetoed own orphan cleanup: %v, %v", state, err)
		}
		requireAbsent(t, filepath.Dir(stage))
		requireFileBytes(t, "victim", []byte("selected victim survives"))
		requireBoundedListingIdentity(t, "victim", victim)
		return
	}
	if action == "malformed" {
		if os.Geteuid() != 0 && os.Geteuid() != 1001 {
			t.Fatal("cleanup identity not changed")
		}
		for _, name := range []string{stageNamePrefix + "own-legacy", stageNamePrefix + "private-own-malformed"} {
			if err := os.WriteFile(name, []byte("owned uncertain residue"), 0o600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(name)
			state, err := CleanupOrphanedStages(".", nil)
			if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Errorf("own malformed residue must fail closed: %v, %v", state, err)
			}
			requireFileBytes(t, name, []byte("owned uncertain residue"))
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	if os.Geteuid() != 1002 {
		t.Fatal("foreign identity not changed")
	}
	if action == "remove" {
		for _, name := range []string{regular, private, link} {
			if err := os.RemoveAll(name); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	if action == "seed" {
		if err := os.WriteFile(regular, []byte("foreign file survives"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(private, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(private, "sentinel"), []byte("foreign private bytes survive"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("victim", link); err != nil {
			t.Fatal(err)
		}
	} else if action != "inspect" {
		t.Fatalf("unexpected UID helper action %q", action)
	}
	type snapshot struct {
		Device, Inode uint64
		UID           uint32
		Mode          os.FileMode
		Bytes         string
	}
	var objects []snapshot
	for _, object := range []struct {
		name string
		mode os.FileMode
	}{{regular, 0o600}, {private, os.ModeDir | 0o700}, {filepath.Join(private, "sentinel"), 0o600}, {link, os.ModeSymlink | 0o777}} {
		name := object.name
		info, err := os.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 1002 || info.Mode() != object.mode {
			t.Fatalf("foreign ownership or mode not preserved: %s", name)
		}
		item := snapshot{Device: stat.Dev, Inode: stat.Ino, UID: stat.Uid, Mode: info.Mode()}
		switch {
		case info.Mode().IsRegular():
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			item.Bytes = string(data)
		case info.Mode()&os.ModeSymlink != 0:
			item.Bytes, err = os.Readlink(name)
			if err != nil {
				t.Fatal(err)
			}
		}
		objects = append(objects, item)
	}
	if err := json.NewEncoder(os.Stdout).Encode(objects); err != nil {
		t.Fatal(err)
	}
}
