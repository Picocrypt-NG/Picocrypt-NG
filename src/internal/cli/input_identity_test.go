package cli

import (
	"Picocrypt-NG/internal/fileops"
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveTopLevelSymlinkPolicy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "chosen.txt")
	want := []byte("explicitly selected target")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Run("default refuses symlink", func(t *testing.T) {
		inputs, err := resolveEncryptInputs([]string{link}, nil, false)
		if err == nil {
			t.Fatalf("follow=false accepted top-level symlink: %v", inputs.inputFiles)
		}
	})
	t.Run("explicit follows regular target", func(t *testing.T) {
		inputs, err := resolveEncryptInputs([]string{link}, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		// Retargeting the chosen link cannot change the resolved selection.
		foreign := filepath.Join(dir, "foreign.txt")
		if err := os.WriteFile(foreign, []byte("private foreign bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(foreign, link); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(dir, "explicit.zip")
		if err := fileops.CreateZip(fileops.ZipOptions{Files: inputs.inputFiles, InputIdentities: inputs.inputIdentities, RootDir: dir, OutputPath: output}); err != nil {
			t.Fatal(err)
		}
		archive, err := zip.OpenReader(output)
		if err != nil {
			t.Fatal(err)
		}
		defer archive.Close()
		if len(archive.File) != 1 || archive.File[0].Name != "chosen.txt" {
			t.Fatalf("wrong archive entries: %+v", archive.File)
		}
		member, err := archive.File[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(member)
		_ = member.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("followed target=%q want=%q", got, want)
		}
	})
}
