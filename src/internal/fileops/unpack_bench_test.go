package fileops

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkUnpackOwnership(b *testing.B) {
	const entries = 1024
	for _, shape := range []string{"flat", "shared-depth-eight", "directory-per-file"} {
		b.Run(shape, func(b *testing.B) {
			b.StopTimer()
			base := b.TempDir()
			archive := filepath.Join(base, "source.zip")
			file, err := os.Create(archive)
			if err != nil {
				b.Fatal(err)
			}
			writer := zip.NewWriter(file)
			expected := make(map[string]struct{}, entries)
			for i := range entries {
				name := fmt.Sprintf("file-%04d", i)
				switch shape {
				case "shared-depth-eight":
					name = "a/b/c/d/e/f/g/h/" + name
				case "directory-per-file":
					name = fmt.Sprintf("dir-%04d/%s", i, name)
				}
				entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
				if err != nil {
					b.Fatal(err)
				}
				if _, err := entry.Write([]byte{'Z'}); err != nil {
					b.Fatal(err)
				}
				expected[filepath.FromSlash(name)] = struct{}{}
			}
			if err := writer.Close(); err != nil {
				b.Fatal(err)
			}
			if err := file.Close(); err != nil {
				b.Fatal(err)
			}
			source, err := os.ReadFile(archive)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(entries)
			for i := range b.N {
				out := filepath.Join(base, fmt.Sprintf("out-%d", i))
				if err := os.Mkdir(out, 0o700); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				result := UnpackWithResult(UnpackOptions{ZipPath: archive, ExtractDir: out})
				b.StopTimer()
				if errors.Is(result, ErrUnpackCleanupIncomplete) {
					b.Fatalf("unexpected extraction state: %v (%v)", result, errors.Unwrap(result))
				}
				switch result.State() {
				case UnpackStatePublishedDurable:
					if err := errors.Unwrap(result); err != nil {
						b.Fatalf("durable extraction reported an error: %v", err)
					}
				case UnpackStatePublishedDurabilityUncertain:
					if errors.Unwrap(result) == nil {
						b.Fatal("durability-uncertain extraction lost its error")
					}
				default:
					b.Fatalf("unexpected extraction state: %v (%v)", result, errors.Unwrap(result))
				}
				seen := 0
				err := filepath.WalkDir(out, func(path string, entry fs.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if strings.HasPrefix(entry.Name(), ".picocrypt-unpack-") {
						return fmt.Errorf("stage residue: %s", path)
					}
					if entry.IsDir() {
						return nil
					}
					rel, err := filepath.Rel(out, path)
					if err != nil {
						return err
					}
					if _, ok := expected[rel]; !ok {
						return fmt.Errorf("unexpected output: %s", rel)
					}
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					if !bytes.Equal(data, []byte{'Z'}) {
						return fmt.Errorf("unexpected output bytes: %s", rel)
					}
					seen++
					if err := os.Remove(path); err != nil {
						return err
					}
					return nil
				})
				if err != nil {
					b.Fatal(err)
				}
				if seen != entries {
					b.Fatalf("extracted files = %d, want %d", seen, entries)
				}
				// Remove only the verified empty fixture directories, deepest first.
				var directories []string
				if err := filepath.WalkDir(out, func(path string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if entry.IsDir() {
						directories = append(directories, path)
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
				for j := len(directories) - 1; j >= 0; j-- {
					if err := os.Remove(directories[j]); err != nil {
						b.Fatal(err)
					}
				}
				preserved, err := os.ReadFile(archive)
				if err != nil || !bytes.Equal(source, preserved) {
					b.Fatalf("source archive changed: %v", err)
				}
			}
		})
	}
}
