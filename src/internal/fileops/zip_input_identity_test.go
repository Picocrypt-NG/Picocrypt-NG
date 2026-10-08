package fileops

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestZIPInputSnapshotMatchesMovedSelectedDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "selected")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := CaptureZIPInput(path, false)
	if err != nil {
		t.Fatal(err)
	}
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err := os.Open(moved)
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	// Windows pathname FileInfo defers identity lookup until SameFile. The
	// discovery snapshot must already be bound before the old name is reused.
	if err := identity.CheckFile(selected); err != nil {
		t.Fatalf("snapshot rebound to replacement instead of selected descriptor: %v", err)
	}
	if foreign, err := identity.Open(); err == nil {
		_ = foreign.Close()
		t.Fatal("snapshot accepted replacement at the former selected name")
	}
}

func TestCreateZipRejectsSelectedInputReplacement(t *testing.T) {
	for _, kind := range []string{"symlink", "regular"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "chosen.txt")
			secret := filepath.Join(dir, "outside.txt")
			output := filepath.Join(dir, "shared.zip")
			chosen := []byte("selected contents")
			outside := []byte("unintended secret")
			if len(chosen) != len(outside) {
				t.Fatal("fixture sizes differ")
			}
			if err := os.WriteFile(source, chosen, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(secret, outside, 0o600); err != nil {
				t.Fatal(err)
			}
			replaced := false
			err := CreateZip(ZipOptions{Files: []string{source}, RootDir: dir, OutputPath: output, Progress: func(float32, string) {
				if replaced {
					return
				}
				replaced = true
				if err := os.Rename(source, source+".selected"); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					if err := os.Symlink(secret, source); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(source, outside, 0o600); err != nil {
					t.Fatal(err)
				}
			}})
			if err == nil {
				archive, openErr := zip.OpenReader(output)
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer archive.Close()
				member, openErr := archive.File[0].Open()
				if openErr != nil {
					t.Fatal(openErr)
				}
				got, readErr := io.ReadAll(member)
				_ = member.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				t.Fatalf("input %s replacement published archive; unintended bytes=%v payload=%q", kind, bytes.Equal(got, outside), got)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("rejected input left output: %v", err)
			}
		})
	}
}

func TestCreateTempZipRejectsSelectedInputReplacement(t *testing.T) {
	for _, kind := range []string{"symlink", "regular"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "chosen.txt")
			secret := filepath.Join(dir, "outside.txt")
			chosen := []byte("selected contents")
			outside := []byte("unintended secret")
			if err := os.WriteFile(source, chosen, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(secret, outside, 0o600); err != nil {
				t.Fatal(err)
			}
			replaced := false
			owner, err := CreateTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "shared.pcv"), MaxPhysicalBytes: 1 << 20, Progress: func(float32, string) {
				if replaced {
					return
				}
				replaced = true
				if err := os.Rename(source, source+".selected"); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					if err := os.Symlink(secret, source); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(source, outside, 0o600); err != nil {
					t.Fatal(err)
				}
			}})
			if owner != nil {
				defer owner.Close()
			}
			if err == nil {
				reader, openErr := owner.OpenReader()
				if openErr != nil {
					t.Fatal(openErr)
				}
				data, readErr := io.ReadAll(reader)
				if readErr != nil {
					t.Fatal(readErr)
				}
				archive, openErr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
				if openErr != nil {
					t.Fatal(openErr)
				}
				member, openErr := archive.File[0].Open()
				if openErr != nil {
					t.Fatal(openErr)
				}
				got, readErr := io.ReadAll(member)
				_ = member.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				t.Fatalf("input %s replacement admitted temporary archive; unintended bytes=%v payload=%q", kind, bytes.Equal(got, outside), got)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				if len(entry.Name()) >= 11 && entry.Name()[:11] == ".picocrypt-" {
					t.Fatalf("rejected input left stage %q", entry.Name())
				}
			}
		})
	}
}
