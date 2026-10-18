//go:build darwin && cgo

package pcv3publication

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDarwinPrivateDirectoryRemovesInheritedExtendedACL(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	// Darwin ACL allow entries are evaluated before restrictive BSD mode bits.
	// A deny-only inherited ACL cannot weaken BSD privacy. Production clears
	// it only on its new private child, without changing the parent ACL.
	output, err := exec.Command("/bin/chmod", "+a", "everyone deny delete,file_inherit,directory_inherit", parent).CombinedOutput()
	if err != nil {
		t.Fatalf("establish real inherited ACL: %v %s", err, output)
	}
	t.Cleanup(func() {
		if output, err := exec.Command("/bin/chmod", "-N", parent).CombinedOutput(); err != nil {
			t.Errorf("remove test ACL: %v %s", err, output)
		}
	})
	original, err := exec.Command("/bin/ls", "-lde", parent).Output()
	if err != nil {
		t.Fatal(err)
	}
	handle, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if !trustedCleanupParent(handle) {
		t.Fatal("deny-only ACL lost trusted parent authority")
	}
	stage, err := Create(filepath.Join(parent, "output"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	private := filepath.Dir(stage.File().Name())
	listing, err := exec.Command("/bin/ls", "-lde", private).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(listing), "\n")[1:] {
		if strings.HasPrefix(strings.TrimSpace(line), "0:") {
			t.Fatalf("private stage inherited an ACL before writable exposure: %s", listing)
		}
	}
	if _, err := stage.File().Write([]byte("owned plaintext")); err != nil {
		t.Fatal(err)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	current, err := exec.Command("/bin/ls", "-lde", parent).Output()
	if err != nil {
		t.Fatal(err)
	}
	// Compare ACL lines, not mtime/directory size after our own namespace effects.
	if strings.Join(strings.Split(string(original), "\n")[1:], "\n") != strings.Join(strings.Split(string(current), "\n")[1:], "\n") {
		t.Fatal("caller-owned parent ACL changed")
	}
	requireNoStageEntries(t, parent)
}

// This is a native process/credential lane, not a same-UID ACL inspection.
func TestDarwinInheritedACLDoesNotExposeStageToDifferentUID(t *testing.T) {
	if os.Getenv("PICOCRYPT_DARWIN_CUSTODY_CHILD") == "1" {
		if os.Geteuid() != 65534 {
			t.Fatal("adversary did not run as nobody")
		}
		control, err := unix.Openat(3, "control", unix.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("inherited ACL positive control: %v", err)
		}
		buffer := make([]byte, 64)
		n, err := unix.Read(control, buffer)
		_ = unix.Close(control)
		if err != nil || string(buffer[:n]) != "inherited ACL positive control" {
			t.Fatal("wrong positive-control bytes")
		}
		// The adversary must have real namespace authority in the shared parent.
		sibling, err := unix.Openat(3, "adversary-control", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("create shared-parent positive control: %v", err)
		}
		defer unix.Close(sibling)
		payload := []byte("shared-parent positive control")
		if n, err := unix.Write(sibling, payload); err != nil || n != len(payload) {
			t.Fatalf("write shared-parent positive control: %d %v", n, err)
		}
		if n, err := unix.Pread(sibling, buffer, 0); err != nil || string(buffer[:n]) != string(payload) {
			t.Fatalf("read shared-parent positive control: %d %v", n, err)
		}
		var original unix.Stat_t
		if err := unix.Fstat(sibling, &original); err != nil || original.Uid != 65534 {
			t.Fatalf("positive control is not adversary-owned: %v", err)
		}
		if err := unix.Renameat(3, "adversary-control", 3, "adversary-renamed"); err != nil {
			t.Fatalf("rename shared-parent positive control: %v", err)
		}
		var renamed unix.Stat_t
		if err := unix.Fstatat(3, "adversary-renamed", &renamed, unix.AT_SYMLINK_NOFOLLOW); err != nil || original.Dev != renamed.Dev || original.Ino != renamed.Ino {
			t.Fatalf("rename changed positive-control identity: %v", err)
		}
		if err := unix.Unlinkat(3, "adversary-renamed", 0); err != nil {
			t.Fatalf("unlink shared-parent positive control: %v", err)
		}
		stagePath := os.Getenv("PICOCRYPT_DARWIN_CUSTODY_INNER")
		directory, err := unix.Openat(3, filepath.Dir(stagePath), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if directory >= 0 {
			_ = unix.Close(directory)
		}
		if !errors.Is(err, unix.EACCES) {
			t.Fatalf("private directory exposed to a different UID: %v", err)
		}
		var inner unix.Stat_t
		if err := unix.Fstatat(3, stagePath, &inner, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.EACCES) {
			t.Fatalf("different UID could traverse private directory: %v", err)
		}
		file, err := unix.Openat(3, stagePath, unix.O_RDWR, 0)
		if file >= 0 {
			_ = unix.Close(file)
		}
		if !errors.Is(err, unix.EACCES) {
			t.Fatalf("private stage exposed to a different UID: %v", err)
		}
		if err := unix.Unlinkat(3, stagePath, 0); !errors.Is(err, unix.EACCES) {
			t.Fatalf("different UID could mutate private stage: %v", err)
		}
		return
	}
	if os.Getenv("PICOCRYPT_RUN_DARWIN_CUSTODY_UID") != "1" {
		t.Skip("requires native isolated Darwin root-to-nobody credential lane")
	}
	if os.Geteuid() != 0 {
		t.Fatal("different-UID coordinator must be an isolated native root lane")
	}
	parent := t.TempDir()
	output, err := exec.Command("/bin/chmod", "+a", "everyone allow list,add_file,search,delete_child,add_subdirectory,file_inherit,directory_inherit", parent).CombinedOutput()
	if err != nil {
		t.Fatalf("install inherited ACL: %v %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(parent, "control"), []byte("inherited ACL positive control"), 0o600); err != nil {
		t.Fatal(err)
	}
	rejected, rejectErr := Create(filepath.Join(parent, "refused"), nil, PolicyNoReplace)
	if rejected != nil || requireResultError(t, rejectErr).Code() != CodePolicyUnsupported {
		t.Fatal("unsafe inherited allow ACL was accepted")
	}
	if output, err := exec.Command("/bin/chmod", "-N", parent).CombinedOutput(); err != nil {
		t.Fatalf("remove controlled fixture ACL: %v %s", err, output)
	}
	if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	stage, err := Create(filepath.Join(parent, "output"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	payload := []byte("private plaintext")
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatal(err)
	}
	handle, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	relative, err := filepath.Rel(parent, stage.File().Name())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDarwinInheritedACLDoesNotExposeStageToDifferentUID$")
	cmd.Env = append(os.Environ(), "PICOCRYPT_DARWIN_CUSTODY_CHILD=1", "PICOCRYPT_DARWIN_CUSTODY_INNER="+relative)
	cmd.ExtraFiles = []*os.File{handle}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("different UID native denial: %v %s", err, output)
	}
	requireFileBytes(t, stage.File().Name(), payload)
}

func TestDarwinInheritedWriteSecurityACLIsRefusedBeforeStaging(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	permissions := "everyone allow list,add_file,search,delete_child,add_subdirectory,writesecurity,chown,file_inherit,directory_inherit"
	output, err := exec.Command("/bin/chmod", "+a", permissions, parent).CombinedOutput()
	if err != nil {
		t.Fatalf("set inherited write-security fixture: %v %s", err, output)
	}
	t.Cleanup(func() {
		if output, err := exec.Command("/bin/chmod", "-N", parent).CombinedOutput(); err != nil {
			t.Errorf("remove fixture ACL: %v %s", err, output)
		}
	})
	before, err := exec.Command("/bin/ls", "-lde", parent).Output()
	if err != nil {
		t.Fatal(err)
	}
	stage, err := Create(filepath.Join(parent, "output"), nil, PolicyNoReplace)
	if stage != nil || requireResultError(t, err).Code() != CodePolicyUnsupported {
		t.Fatal("inherited write-security permissions gained staging authority")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("ACL refusal created filesystem effects: %v %v", entries, err)
	}
	after, err := exec.Command("/bin/ls", "-lde", parent).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("refusal changed caller parent metadata or ACL")
	}
}
