package fileops

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installOccupiedPath(t *testing.T, path, kind string) func() {
	t.Helper()

	content := []byte("foreign victim content")
	targetPath := path + ".victim"
	switch kind {
	case "regular":
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("create regular victim: %v", err)
		}
	case "hardlink":
		if err := os.WriteFile(targetPath, content, 0o600); err != nil {
			t.Fatalf("create hardlink target: %v", err)
		}
		if err := os.Link(targetPath, path); err != nil {
			t.Skipf("hardlinks unavailable on this platform: %v", err)
		}
	case "symlink":
		if err := os.WriteFile(targetPath, content, 0o600); err != nil {
			t.Fatalf("create symlink target: %v", err)
		}
		if err := os.Symlink(targetPath, path); err != nil {
			t.Skipf("symlinks unavailable on this platform: %v", err)
		}
	default:
		t.Fatalf("unknown occupied-path kind %q", kind)
	}

	before, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat occupied path: %v", err)
	}
	linkTarget := ""
	if kind == "symlink" {
		linkTarget, err = os.Readlink(path)
		if err != nil {
			t.Fatalf("read symlink target: %v", err)
		}
	}

	return func() {
		t.Helper()

		after, err := os.Lstat(path)
		if err != nil {
			t.Errorf("occupied path was removed: %v", err)
			return
		}
		if !os.SameFile(before, after) {
			t.Errorf("occupied path identity changed")
		}
		if kind == "symlink" {
			if after.Mode()&os.ModeSymlink == 0 {
				t.Errorf("occupied symlink was replaced by mode %v", after.Mode())
			}
			if got, err := os.Readlink(path); err != nil {
				t.Errorf("read preserved symlink: %v", err)
			} else if got != linkTarget {
				t.Errorf("symlink target = %q, want %q", got, linkTarget)
			}
		}
		if kind == "hardlink" {
			targetInfo, err := os.Stat(targetPath)
			if err != nil {
				t.Errorf("stat hardlink target: %v", err)
			} else if !os.SameFile(after, targetInfo) {
				t.Errorf("occupied path is no longer a hardlink to its victim")
			}
		}
		if got, err := os.ReadFile(path); err != nil {
			t.Errorf("read occupied path: %v", err)
		} else if !bytes.Equal(got, content) {
			t.Errorf("occupied bytes = %q, want %q", got, content)
		}
		if kind != "regular" {
			if got, err := os.ReadFile(targetPath); err != nil {
				t.Errorf("read victim target: %v", err)
			} else if !bytes.Equal(got, content) {
				t.Errorf("victim target bytes = %q, want %q", got, content)
			}
		}
	}
}

func TestSplitPreservesOccupiedChunkPaths(t *testing.T) {
	for _, suffix := range []string{".0", ".0.incomplete"} {
		for _, kind := range []string{"regular", "hardlink", "symlink"} {
			t.Run(suffix+"/"+kind, func(t *testing.T) {
				tmpDir := t.TempDir()
				inputPath := filepath.Join(tmpDir, "archive.pcv")
				input := bytes.Repeat([]byte("split payload"), 1024)
				if err := os.WriteFile(inputPath, input, 0o600); err != nil {
					t.Fatalf("create split input: %v", err)
				}

				assertUnchanged := installOccupiedPath(t, inputPath+suffix, kind)
				chunks, err := Split(SplitOptions{
					InputPath: inputPath,
					ChunkSize: 1,
					Unit:      SplitUnitKiB,
				})
				if err == nil {
					t.Errorf("Split succeeded with occupied path, chunks = %v", chunks)
				} else if !errors.Is(err, os.ErrExist) {
					t.Errorf("Split error = %v, want os.ErrExist", err)
				}

				assertUnchanged()
				if got, err := os.ReadFile(inputPath); err != nil {
					t.Fatalf("read split input: %v", err)
				} else if !bytes.Equal(got, input) {
					t.Errorf("split input was modified")
				}
			})
		}
	}
}

func TestSplitRefusesReplacementOfPreviouslyPublishedChunk(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "archive.pcv")
	input := bytes.Repeat([]byte("split payload"), 4096)
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatalf("create split input: %v", err)
	}

	replaced := false
	var assertUnchanged func()
	firstChunkBackup := inputPath + ".0.owned"
	_, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 1,
		Unit:      SplitUnitKiB,
		Progress: func(_ float32, info string) {
			if replaced || !strings.HasPrefix(info, "2/") {
				return
			}
			firstChunk := inputPath + ".0"
			if err := os.Rename(firstChunk, firstChunkBackup); err != nil {
				t.Fatalf("move operation-owned first chunk: %v", err)
			}
			assertUnchanged = installOccupiedPath(t, firstChunk, "regular")
			replaced = true
		},
	})
	if err == nil || !strings.Contains(err.Error(), "chunk 0 path changed during splitting") {
		t.Fatalf("Split error = %v, want changed-chunk refusal", err)
	}
	if !replaced {
		t.Fatal("test did not replace the previously published chunk")
	}
	assertUnchanged()
	if got, readErr := os.ReadFile(firstChunkBackup); readErr != nil {
		t.Fatalf("read operation-owned first chunk backup: %v", readErr)
	} else if !bytes.Equal(got, input[:1024]) {
		t.Fatal("operation-owned first chunk changed after pathname replacement")
	}
	if got, err := os.ReadFile(inputPath); err != nil {
		t.Fatalf("read split input: %v", err)
	} else if !bytes.Equal(got, input) {
		t.Fatal("split input changed after chunk replacement")
	}
	for _, suffix := range []string{".1", ".2"} {
		if _, err := os.Stat(inputPath + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("operation-owned chunk %s survived failed split: %v", suffix, err)
		}
	}
}

func TestSplitRejectsConcurrentSourceMutationAndRollsBack(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "truncate",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Truncate(path, 512); err != nil {
					t.Fatalf("truncate split source: %v", err)
				}
			},
		},
		{
			name: "same-size overwrite",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatalf("open split source for mutation: %v", err)
				}
				_, writeErr := file.WriteAt([]byte{0xff}, 0)
				closeErr := file.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("mutate split source: write=%v close=%v", writeErr, closeErr)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			inputPath := filepath.Join(dir, "archive.pcv")
			input := bytes.Repeat([]byte("stable split source"), 2048)
			if err := os.WriteFile(inputPath, input, 0o600); err != nil {
				t.Fatalf("write split source: %v", err)
			}
			mutated := false
			_, err := Split(SplitOptions{
				InputPath:            inputPath,
				ChunkSize:            1,
				Unit:                 SplitUnitKiB,
				RequireDirectorySync: true,
				Progress: func(_ float32, _ string) {
					if !mutated {
						test.mutate(t, inputPath)
						mutated = true
					}
				},
			})
			if err == nil {
				t.Fatal("Split accepted a source modified during chunk creation")
			}
			if !mutated {
				t.Fatal("test did not mutate the split source")
			}
			if _, statErr := os.Lstat(inputPath); statErr != nil {
				t.Fatalf("modified full source was removed: %v", statErr)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatalf("inspect split directory: %v", readErr)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "archive.pcv.") {
					t.Fatalf("chunk survived rejected source mutation: %s", entry.Name())
				}
			}
		})
	}
}

func TestSplitPinnedKeepsEveryChunkInTheRetainedDirectory(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "selected")
	moved := filepath.Join(parent, "moved")
	replacement := filepath.Join(parent, "replacement")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create split directory: %v", err)
	}
	inputPath := filepath.Join(directory, "archive.pcv")
	input := bytes.Repeat([]byte("pinned split source"), 160)
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatalf("write split source: %v", err)
	}

	root, err := OpenRootNoSymlink(directory)
	if err != nil {
		t.Fatalf("open split root: %v", err)
	}
	defer func() { _ = root.Close() }()
	parentFile, err := root.Open(".")
	if err != nil {
		t.Fatalf("open split directory: %v", err)
	}
	defer func() { _ = parentFile.Close() }()
	inputFile, err := root.Open(filepath.Base(inputPath))
	if err != nil {
		t.Fatalf("open split input: %v", err)
	}
	defer func() { _ = inputFile.Close() }()
	inputInfo, err := inputFile.Stat()
	if err != nil {
		t.Fatalf("stat split input: %v", err)
	}
	parentInfo, err := parentFile.Stat()
	if err != nil {
		t.Fatalf("stat split directory: %v", err)
	}
	expectedDigest := sha256.Sum256(input)

	swaps := 0
	chunks, err := SplitPinned(SplitOptions{
		InputPath:            inputPath,
		ExpectedInput:        inputInfo,
		ExpectedDirectory:    parentInfo,
		ExpectedSHA256:       &expectedDigest,
		ChunkSize:            1,
		Unit:                 SplitUnitKiB,
		RequireDirectorySync: true,
		Progress: func(_ float32, info string) {
			switch {
			case swaps == 0 && info == "1/3":
				if err := os.Rename(directory, moved); err != nil {
					t.Fatalf("move retained directory: %v", err)
				}
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatalf("create replacement directory: %v", err)
				}
				swaps++
			case swaps == 1 && info == "2/3":
				if err := os.Rename(directory, replacement); err != nil {
					t.Fatalf("move replacement directory: %v", err)
				}
				if err := os.Rename(moved, directory); err != nil {
					t.Fatalf("restore retained directory: %v", err)
				}
				swaps++
			}
		},
	}, inputFile, root, parentFile)
	if err != nil {
		t.Fatalf("split through retained directory: %v", err)
	}
	if swaps != 2 || len(chunks) != 3 {
		t.Fatalf("directory swaps=%d chunks=%d; want 2 and 3", swaps, len(chunks))
	}
	entries, err := os.ReadDir(replacement)
	if err != nil {
		t.Fatalf("read replacement directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("split wrote outside retained directory: %v", entries)
	}
	recombined := filepath.Join(parent, "recombined.pcv")
	if err := Recombine(RecombineOptions{InputBase: inputPath, OutputPath: recombined}); err != nil {
		t.Fatalf("recombine pinned chunks: %v", err)
	}
	if got, err := os.ReadFile(recombined); err != nil || !bytes.Equal(got, input) {
		t.Fatalf("recombined pinned chunks differ: size=%d err=%v", len(got), err)
	}
}

func TestRecombinePreservesExistingOutputPaths(t *testing.T) {
	for _, kind := range []string{"regular", "hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			tmpDir := t.TempDir()
			basePath := filepath.Join(tmpDir, "archive.pcv")
			if err := os.WriteFile(basePath+".0", []byte("chunk"), 0o600); err != nil {
				t.Fatalf("create chunk: %v", err)
			}

			outputPath := filepath.Join(tmpDir, "output.pcv")
			assertUnchanged := installOccupiedPath(t, outputPath, kind)
			err := Recombine(RecombineOptions{
				InputBase:  basePath,
				OutputPath: outputPath,
			})
			if err == nil {
				t.Fatal("Recombine succeeded with an occupied output path")
			}
			if !errors.Is(err, os.ErrExist) {
				t.Errorf("Recombine error = %v, want os.ErrExist", err)
			}
			assertUnchanged()
		})
	}
}

func TestRecombineFailurePreservesReplacementAtOutputPath(t *testing.T) {
	for _, kind := range []string{"regular", "hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			tmpDir := t.TempDir()
			basePath := filepath.Join(tmpDir, "archive.pcv")
			if err := os.WriteFile(basePath+".0", bytes.Repeat([]byte("C"), 2*1024*1024), 0o600); err != nil {
				t.Fatalf("create chunk: %v", err)
			}

			outputPath := filepath.Join(tmpDir, "output.pcv")
			var assertUnchanged func()
			replaced := false
			err := Recombine(RecombineOptions{
				InputBase:  basePath,
				OutputPath: outputPath,
				Progress: func(float32, string) {
					if replaced {
						return
					}
					if err := os.Remove(outputPath); err != nil {
						t.Fatalf("remove operation-owned output: %v", err)
					}
					assertUnchanged = installOccupiedPath(t, outputPath, kind)
					replaced = true
				},
				Cancel: func() bool {
					return replaced
				},
			})
			if err == nil {
				t.Fatal("Recombine succeeded after cancellation")
			}
			if !replaced {
				t.Fatal("test did not replace the operation-owned output")
			}
			assertUnchanged()
		})
	}
}

func TestRecombineRefusesReplacementAtCompletedOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "archive.pcv")
	if err := os.WriteFile(basePath+".0", bytes.Repeat([]byte("C"), 2*1024*1024), 0o600); err != nil {
		t.Fatalf("create chunk: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "output.pcv")
	replaced := false
	var assertUnchanged func()
	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
		Progress: func(float32, string) {
			if replaced {
				return
			}
			if err := os.Remove(outputPath); err != nil {
				t.Fatalf("remove operation-owned output: %v", err)
			}
			assertUnchanged = installOccupiedPath(t, outputPath, "regular")
			replaced = true
		},
	})
	if err == nil || err.Error() != "output path changed during recombination" {
		t.Fatalf("Recombine error = %v, want changed-output refusal", err)
	}
	if !replaced {
		t.Fatal("test did not replace the operation-owned output")
	}
	assertUnchanged()
}
