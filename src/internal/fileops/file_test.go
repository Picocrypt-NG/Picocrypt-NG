package fileops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCreateSecureNoSymlinkRejectsSymlink locks the SEC-02 invariant: a
// pre-planted symlink at a write target is rejected before any file is opened,
// and the symlink's victim (size/mtime/content) is left untouched (no
// follow-through write or truncate).
func TestCreateSecureNoSymlinkRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()

	outsideDir := filepath.Join(tmpDir, "outside")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("Create outside dir: %v", err)
	}
	victimPath := filepath.Join(outsideDir, "owned.pcv")
	if err := os.WriteFile(victimPath, []byte("outside"), 0o600); err != nil {
		t.Fatalf("Create victim file: %v", err)
	}

	beforeInfo, err := os.Stat(victimPath)
	if err != nil {
		t.Fatalf("Stat victim file: %v", err)
	}
	beforeSize := beforeInfo.Size()
	beforeMod := beforeInfo.ModTime()

	outputPath := filepath.Join(tmpDir, "output.pcv")
	if err := os.Symlink(victimPath, outputPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	f, err := CreateSecureNoSymlink(outputPath)
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("expected symlink rejection, got nil error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("error does not mention symlink: %v", err)
	}

	// Victim must be untouched: content, size, and mtime unchanged proves no
	// follow-through write or O_TRUNC truncate happened.
	got, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("Read victim file: %v", err)
	}
	if string(got) != "outside" {
		t.Fatalf("Victim file content modified: got %q, want %q", got, "outside")
	}

	afterInfo, err := os.Stat(victimPath)
	if err != nil {
		t.Fatalf("Stat victim file after: %v", err)
	}
	if afterInfo.Size() != beforeSize {
		t.Fatalf("Victim file size changed: got %d, want %d", afterInfo.Size(), beforeSize)
	}
	if !afterInfo.ModTime().Equal(beforeMod) {
		t.Fatalf("Victim file mtime changed: got %v, want %v", afterInfo.ModTime(), beforeMod)
	}
}

func TestOpenExistingNoSymlinkRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	victimPath := filepath.Join(tmpDir, "victim.pcv")
	if err := os.WriteFile(victimPath, []byte("victim"), 0o600); err != nil {
		t.Fatalf("Create victim file: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "output.pcv.incomplete")
	if err := os.Symlink(victimPath, outputPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	f, err := OpenExistingNoSymlink(outputPath, os.O_WRONLY|os.O_APPEND)
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("expected symlink rejection, got nil error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("error does not mention symlink: %v", err)
	}

	got, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("Read victim file: %v", err)
	}
	if string(got) != "victim" {
		t.Fatalf("Victim file content modified: got %q, want %q", got, "victim")
	}
}

func TestOpenRootNoSymlinkPinsSelectedDirectory(t *testing.T) {
	temp := t.TempDir()
	selected := filepath.Join(temp, "selected")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(selected)
	if err != nil {
		t.Fatal(err)
	}
	root, err := OpenRootNoSymlink(selected)
	if err != nil {
		t.Fatalf("open selected directory: %v", err)
	}
	opened, err := root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(expected, opened) {
		t.Fatal("opened root identity differs from the selected directory")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}

	notDirectory := filepath.Join(temp, "file")
	if err := os.WriteFile(notDirectory, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := OpenRootNoSymlink(notDirectory); err == nil || unexpected != nil {
		if unexpected != nil {
			_ = unexpected.Close()
		}
		t.Fatalf("regular file root = (%v, %v); want nil, error", unexpected, err)
	}

	alias := filepath.Join(temp, "alias")
	if err := os.Symlink(selected, alias); err != nil {
		t.Skipf("directory symlinks unavailable on this platform: %v", err)
	}
	if unexpected, err := OpenRootNoSymlink(alias); err == nil || unexpected != nil {
		if unexpected != nil {
			_ = unexpected.Close()
		}
		t.Fatalf("symlink root = (%v, %v); want nil, error", unexpected, err)
	}
	marker := filepath.Join(selected, "marker")
	if err := os.WriteFile(marker, []byte("target unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "target unchanged" {
		t.Fatalf("symlink rejection affected target: %q, %v", content, err)
	}
}
