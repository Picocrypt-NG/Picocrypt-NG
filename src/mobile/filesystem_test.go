package mobile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveTreeNoFollowRemovesOwnedTree(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "picocrypt_files", "staging")
	if err := os.MkdirAll(filepath.Join(target, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "folder", "plaintext.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := RemoveTreeNoFollow(root, target); got != "" {
		t.Fatalf("RemoveTreeNoFollow returned %q", got)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("owned staging tree still exists: %v", err)
	}
}

func TestRemoveTreeNoFollowUnlinksTerminalSymlinkWithoutFollowingIt(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "picocrypt_files")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "foreign.txt")
	want := []byte("must survive cleanup")
	if err := os.WriteFile(sentinel, want, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "staging")
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if got := RemoveTreeNoFollow(root, target); got != "" {
		t.Fatalf("RemoveTreeNoFollow returned %q", got)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("terminal symlink still exists: %v", err)
	}
	if got, err := os.ReadFile(sentinel); err != nil {
		t.Fatal(err)
	} else if string(got) != string(want) {
		t.Fatalf("outside sentinel changed: got %q, want %q", got, want)
	}
}

func TestRemoveTreeNoFollowRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideStaging := filepath.Join(outside, "staging")
	if err := os.Mkdir(outsideStaging, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outsideStaging, "foreign.txt")
	want := []byte("outside tree must survive")
	if err := os.WriteFile(sentinel, want, 0o600); err != nil {
		t.Fatal(err)
	}
	internalLink := filepath.Join(root, "picocrypt_files")
	if err := os.Symlink(outside, internalLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	target := filepath.Join(internalLink, "staging")
	if got := RemoveTreeNoFollow(root, target); got == "" {
		t.Fatal("cleanup followed an intermediate symlink")
	}
	if got, err := os.ReadFile(sentinel); err != nil {
		t.Fatal(err)
	} else if string(got) != string(want) {
		t.Fatalf("outside sentinel changed: got %q, want %q", got, want)
	}
}

func TestRemoveTreeNoFollowRejectsTargetOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "foreign.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := RemoveTreeNoFollow(root, sentinel); got == "" {
		t.Fatal("cleanup accepted a target outside its root")
	}
	if got, err := os.ReadFile(sentinel); err != nil {
		t.Fatal(err)
	} else if string(got) != "keep" {
		t.Fatalf("outside sentinel changed: %q", got)
	}
}
