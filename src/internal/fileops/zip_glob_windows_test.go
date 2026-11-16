package fileops

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestZIPInputsPreserveWindowsNativeExplicitLookupAndBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "other", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unselected.txt"), []byte("native directory bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "other", "nested"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{`missing\..\unselected.txt`, `link\..\unselected.txt`} {
		t.Run(relative, func(t *testing.T) {
			path := root + string(filepath.Separator) + relative
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{"capture", "inspect", "borrowed"} {
				t.Run(method, func(t *testing.T) {
					budget := NewZIPResourceBudget()
					var metadata ZIPInputMetadataReservation
					defer metadata.Release()
					var identity ZIPInputIdentity
					var err error
					switch method {
					case "capture":
						identity, err = CaptureZIPInput(path, false)
					case "inspect":
						var candidate ZIPInputCandidate
						candidate, err = metadata.Inspect(budget, path)
						if err == nil {
							identity, err = metadata.Capture(budget, candidate, false)
						}
					case "borrowed":
						borrowed, openErr := os.Open(path)
						if openErr != nil {
							t.Fatal(openErr)
						}
						defer borrowed.Close()
						info, statErr := borrowed.Stat()
						if statErr != nil {
							t.Fatal(statErr)
						}
						identity, err = metadata.FromFileInfo(budget, path, info)
					}
					if err != nil {
						t.Fatal(err)
					}
					if identity.selectedPath != path {
						t.Fatalf("selected lexical path changed: %q", identity.selectedPath)
					}
					file, err := identity.Open()
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(file)
					if closeErr := file.Close(); err != nil || closeErr != nil || !bytes.Equal(body, want) {
						t.Fatalf("explicit source differs from native read: %q err=%v close=%v", body, err, closeErr)
					}
				})
			}
		})
	}
}

func TestGlobZIPInputCandidatesPreserveWindowsNativeLookupAndBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "other", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unselected.txt"), []byte("native directory bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "other", "selected.txt"), []byte("physical symlink parent bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "other", "nested"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{`missing\..\*.txt`, `link\..\*.txt`, `missing\..\unselected.txt`, `link\..\unselected.txt`, `*\..\*.txt`} {
		t.Run(relative, func(t *testing.T) {
			pattern := root + string(filepath.Separator) + relative
			want, err := filepath.Glob(pattern)
			if err != nil {
				t.Fatal(err)
			}
			budget := NewZIPResourceBudget()
			var metadata ZIPInputMetadataReservation
			var got []string
			err = GlobZIPInputCandidates(context.Background(), pattern, budget, func(candidate ZIPInputCandidate) error {
				got = append(got, candidate.Path)
				identity, err := metadata.Capture(budget, candidate, false)
				if err != nil {
					return err
				}
				file, err := identity.Open()
				if err != nil {
					return err
				}
				body, err := io.ReadAll(file)
				closeErr := file.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
				expected, err := os.ReadFile(candidate.Path)
				if err != nil {
					return err
				}
				if !bytes.Equal(body, expected) {
					t.Fatalf("glob source bytes differ from native selected path: %q", candidate.Path)
				}
				return nil
			})
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("glob=%v paths=%v native=%v", err, got, want)
			}
			metadata.Release()
			if budget.CurrentBytes() != 0 {
				t.Fatal("glob retained metadata")
			}
		})
	}
}
