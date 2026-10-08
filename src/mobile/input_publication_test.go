//go:build linux

package mobile

import (
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPublishInputCopyPreservesTargetOnCollision(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "input.incomplete")
	target := filepath.Join(dir, "input_file.pcv")
	if err := os.WriteFile(source, []byte("selected input"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Dev > math.MaxInt64 || stat.Ino > math.MaxInt64 {
		t.Fatal("fixture identity does not fit Android signed long")
	}
	if err := os.WriteFile(target, []byte("foreign target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := PublishInputCopy(dir, "input.incomplete", "input_file.pcv", int64(stat.Dev), int64(stat.Ino)); result != "not-published" {
		t.Fatalf("collision = %q", result)
	}
	for path, expected := range map[string]string{source: "selected input", target: "foreign target"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != expected {
			t.Fatalf("changed owner: %q %v", data, err)
		}
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if result := PublishInputCopy(dir, "input.incomplete", "input_file.pcv", int64(stat.Dev), int64(stat.Ino)); result != "published" {
		t.Fatalf("move = %q", result)
	}
	current, err := os.Lstat(target)
	if err != nil || !os.SameFile(info, current) {
		t.Fatalf("published identity: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "selected input" {
		t.Fatalf("published bytes: %q %v", data, err)
	}
}
