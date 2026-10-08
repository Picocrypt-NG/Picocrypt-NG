package fileops

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularReadNoSymlinkReturnsReadOnlySeekableOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyfile")
	want := []byte("regular keyfile bytes")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := OpenRegularReadNoSymlink(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write([]byte("overwrite")); err == nil {
		t.Fatal("read-only admission granted write authority")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("regular file contents = %q, %v", got, err)
	}
}

func TestOpenRegularReadNoSymlinkRejectsDirectoryAndMissingFile(t *testing.T) {
	directory := t.TempDir()
	for _, path := range []string{directory, filepath.Join(directory, "missing")} {
		file, err := OpenRegularReadNoSymlink(path)
		if file != nil {
			_ = file.Close()
			t.Fatalf("rejected input returned a descriptor: %q", path)
		}
		if err == nil {
			t.Fatalf("nonregular or missing input accepted: %q", path)
		}
	}
}
