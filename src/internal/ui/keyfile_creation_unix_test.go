//go:build (darwin && cgo) || (linux && !android)

package ui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedKeyfilePublishedWithOwnerOnlyMode(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "generated.bin")
	if err := writeGeneratedKeyfile(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("published keyfile permissions = %04o, want 0600", got)
	}
}
