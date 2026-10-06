//go:build linux

package pcv3publication

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMoveExistingNoReplaceKeepsCompleteInputIdentity(t *testing.T) {
	dir, source, info, device, inode := existingMoveFixture(t)
	state, err := MoveExistingNoReplace(dir, "input.incomplete", "input_file.pcv", device, inode)
	if state != ExistingFilePublished || err != nil {
		t.Fatalf("publication = %v, %v", state, err)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source name remains: %v", err)
	}
	assertExistingMoveFile(t, filepath.Join(dir, "input_file.pcv"), info, "complete input")
}

func TestMoveExistingNoReplaceRefusesExistingOwnerAndAlias(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign", true: "same-inode-alias"}[alias], func(t *testing.T) {
			dir, source, sourceInfo, device, inode := existingMoveFixture(t)
			target := filepath.Join(dir, "input_file.pcv")
			want := "foreign input"
			if alias {
				want = "complete input"
				if err := os.Link(source, target); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte(want), 0o600); err != nil {
				t.Fatal(err)
			}
			targetInfo, err := os.Lstat(target)
			if err != nil {
				t.Fatal(err)
			}
			state, err := MoveExistingNoReplace(dir, "input.incomplete", "input_file.pcv", device, inode)
			if state != ExistingFileNotPublished || !errors.Is(err, os.ErrExist) {
				t.Fatalf("collision granted target custody: %v, %v", state, err)
			}
			assertExistingMoveFile(t, source, sourceInfo, "complete input")
			assertExistingMoveFile(t, target, targetInfo, want)
		})
	}
}

func TestMoveExistingNoReplacePreservesLateCollision(t *testing.T) {
	dir, source, sourceInfo, device, inode := existingMoveFixture(t)
	target := filepath.Join(dir, "input_file.pcv")
	ops := nativeOperations()
	native := ops.atomicPublish
	var targetInfo os.FileInfo
	ops.atomicPublish = func(parent *os.File, oldName, newName string, policy Policy) error {
		if err := os.WriteFile(target, []byte("late foreign input"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		targetInfo, err = os.Lstat(target)
		if err != nil {
			t.Fatal(err)
		}
		return native(parent, oldName, newName, policy)
	}
	state, err := moveExistingNoReplace(dir, "input.incomplete", "input_file.pcv", device, inode, ops)
	if state != ExistingFileNotPublished || !errors.Is(err, os.ErrExist) {
		t.Fatalf("late collision granted target custody: %v, %v", state, err)
	}
	assertExistingMoveFile(t, source, sourceInfo, "complete input")
	assertExistingMoveFile(t, target, targetInfo, "late foreign input")
}

func TestMoveExistingNoReplaceRetainsPublishedCustodyOnErrors(t *testing.T) {
	for _, phase := range []string{"syscall-after-move", "source-close"} {
		t.Run(phase, func(t *testing.T) {
			dir, source, info, device, inode := existingMoveFixture(t)
			failure := errors.New("injected publication failure")
			ops := nativeOperations()
			if phase == "syscall-after-move" {
				native := ops.atomicPublish
				ops.atomicPublish = func(parent *os.File, oldName, newName string, policy Policy) error {
					if err := native(parent, oldName, newName, policy); err != nil {
						return err
					}
					return failure
				}
			} else {
				ops.closeStage = func(file *os.File) error { return errors.Join(file.Close(), failure) }
			}
			state, err := moveExistingNoReplace(dir, "input.incomplete", "input_file.pcv", device, inode, ops)
			if state != ExistingFilePublished || !errors.Is(err, failure) {
				t.Fatalf("lost post-move cleanup custody: %v, %v", state, err)
			}
			if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("source: %v", err)
			}
			assertExistingMoveFile(t, filepath.Join(dir, "input_file.pcv"), info, "complete input")
		})
	}
}

func TestMoveExistingNoReplaceRefusesChangedIdentityAndSymlinks(t *testing.T) {
	for _, mode := range []string{"inode", "source-symlink", "parent-symlink", "outside-name"} {
		t.Run(mode, func(t *testing.T) {
			dir, source, info, device, inode := existingMoveFixture(t)
			parent, name := dir, "input.incomplete"
			switch mode {
			case "inode":
				inode++
			case "source-symlink":
				name = "link"
				if err := os.Symlink(source, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				parent = filepath.Join(t.TempDir(), "parent")
				if err := os.Symlink(dir, parent); err != nil {
					t.Fatal(err)
				}
			case "outside-name":
				name = "../input.incomplete"
			}
			state, err := MoveExistingNoReplace(parent, name, "input_file.pcv", device, inode)
			if state != ExistingFileNotPublished || err == nil {
				t.Fatalf("unsafe source admitted: %v, %v", state, err)
			}
			assertExistingMoveFile(t, source, info, "complete input")
			if _, err := os.Lstat(filepath.Join(dir, "input_file.pcv")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe source produced output: %v", err)
			}
		})
	}
}

func TestMoveExistingNoReplaceDenialNeverGrantsCleanup(t *testing.T) {
	dir, source, info, device, inode := existingMoveFixture(t)
	ops := nativeOperations()
	ops.atomicPublish = func(*os.File, string, string, Policy) error { return syscall.ENOSYS }
	state, err := moveExistingNoReplace(dir, "input.incomplete", "input_file.pcv", device, inode, ops)
	if state != ExistingFileNotPublished || !errors.Is(err, syscall.ENOSYS) {
		t.Fatalf("unsupported move = %v, %v", state, err)
	}
	assertExistingMoveFile(t, source, info, "complete input")
}

func TestMoveExistingNoReplacePreservesReusedSourceName(t *testing.T) {
	dir, source, info, device, inode := existingMoveFixture(t)
	ops := nativeOperations()
	native := ops.atomicPublish
	var replacement os.FileInfo
	ops.atomicPublish = func(parent *os.File, oldName, newName string, policy Policy) error {
		if err := native(parent, oldName, newName, policy); err != nil {
			return err
		}
		if err := os.WriteFile(source, []byte("new source owner"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		replacement, err = os.Lstat(source)
		return err
	}
	state, err := moveExistingNoReplace(dir, "input.incomplete", "input_file.pcv", device, inode, ops)
	if state != ExistingFilePublished || err != nil {
		t.Fatalf("lost moved input: %v, %v", state, err)
	}
	assertExistingMoveFile(t, source, replacement, "new source owner")
	assertExistingMoveFile(t, filepath.Join(dir, "input_file.pcv"), info, "complete input")
}

func TestMoveExistingNoReplaceDoesNotGrantReplacedTargetCustody(t *testing.T) {
	dir, _, info, device, inode := existingMoveFixture(t)
	target := filepath.Join(dir, "input_file.pcv")
	saved := filepath.Join(dir, "moved-input")
	var replacement os.FileInfo
	ops := nativeOperations()
	native := ops.atomicPublish
	ops.atomicPublish = func(parent *os.File, oldName, newName string, policy Policy) error {
		if err := native(parent, oldName, newName, policy); err != nil {
			return err
		}
		if err := os.Rename(target, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("replacement target"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		replacement, err = os.Lstat(target)
		return err
	}
	state, err := moveExistingNoReplace(dir, "input.incomplete", "input_file.pcv", device, inode, ops)
	if state != ExistingFileMoveIndeterminate || err == nil {
		t.Fatalf("replacement granted target custody: %v, %v", state, err)
	}
	assertExistingMoveFile(t, target, replacement, "replacement target")
	assertExistingMoveFile(t, saved, info, "complete input")
}

func existingMoveFixture(t *testing.T) (string, string, os.FileInfo, uint64, uint64) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "input.incomplete")
	if err := os.WriteFile(source, []byte("complete input"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	return dir, source, info, stat.Dev, stat.Ino
}

func assertExistingMoveFile(t *testing.T, path string, expected os.FileInfo, contents string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, expected) {
		t.Fatalf("changed identity at %s: %v", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != contents {
		t.Fatalf("changed bytes at %s: %q, %v", path, data, err)
	}
}
