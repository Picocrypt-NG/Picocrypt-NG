package fileops

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitCompleteDirectoryUncertaintyPreservesReconstructableChunks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "ciphertext")
	payload := bytes.Repeat([]byte("complete authenticated ciphertext"), 100)
	if err := os.WriteFile(target, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	root, parent, _, err := openSplitDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer parent.Close()
	injected := errors.New("final directory barrier unavailable")
	result, err := SplitPinnedWithResult(SplitOptions{InputPath: target, ChunkSize: 1, Unit: SplitUnitKiB}, input, root, parent, func(*os.File) error { return injected })
	if err != nil || result.State != SplitCompleteDurabilityUncertain || !errors.Is(result.DurabilityError, injected) {
		t.Fatalf("completion = %+v, %v", result, err)
	}
	chunks := result.Chunks

	var reconstructed []byte
	for _, chunk := range chunks {
		data, err := os.ReadFile(chunk)
		if err != nil {
			t.Fatal(err)
		}
		reconstructed = append(reconstructed, data...)
	}
	if !bytes.Equal(reconstructed, payload) {
		t.Fatalf("complete chunks lost after final barrier uncertainty: reconstructed %d of %d bytes", len(reconstructed), len(payload))
	}
	current, err := os.Stat(target)
	if err != nil || !os.SameFile(original, current) {
		t.Fatalf("full ciphertext identity changed: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("full ciphertext bytes changed: %v", err)
	}
}

func TestSplitTypedFailureRollsBackBeforeDirectoryUncertainty(t *testing.T) {
	for _, failure := range []string{"collision", "cancel", "source-digest", "chunk-digest", "source-path", "source-shrink", "directory-identity", "closed-directory"} {
		t.Run(failure, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ciphertext")
			payload := bytes.Repeat([]byte("ciphertext"), 400)
			if err := os.WriteFile(target, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			// A borrowed share-delete-capable input permits the replacement
			// attack on Windows too; the pinned split must reject it itself.
			input, err := OpenExistingNoSymlink(target, os.O_RDONLY)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			root, parent, _, err := openSplitDirectory(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			defer parent.Close()
			opts := SplitOptions{InputPath: target, ChunkSize: 1, Unit: SplitUnitKiB}
			moved := directory + "-moved"
			changed := false
			replacementBlocked := false
			barrierCalls := 0
			switch failure {
			case "collision":
				if err := os.WriteFile(target+".0", []byte("foreign"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				opts.Cancel = func() bool { return changed }
			case "source-digest":
				digest := [32]byte{}
				opts.ExpectedSHA256 = &digest
			}
			opts.Progress = func(_ float32, _ string) {
				if changed {
					return
				}
				if failure == "chunk-digest" {
					if _, err := os.Stat(target + ".0"); err != nil {
						return
					}
				}
				changed = true
				switch failure {
				case "directory-identity":
					if err := os.Rename(directory, moved); err != nil {
						if windowsPreventedOpenHandleRename(err) {
							replacementBlocked = true
							return
						}
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Rename(moved, directory) })
					if err := os.Mkdir(directory, 0o700); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Remove(directory) })
				case "source-path":
					if err := os.Rename(target, target+"-moved"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, []byte("foreign"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "source-shrink":
					if err := os.Truncate(target, 1); err != nil {
						t.Fatal(err)
					}
				case "closed-directory":
					if err := parent.Close(); err != nil {
						t.Fatal(err)
					}
				case "chunk-digest":
					if err := os.WriteFile(target+".0", bytes.Repeat([]byte("X"), 1024), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			result, err := SplitPinnedWithResult(opts, input, root, parent, func(*os.File) error { barrierCalls++; return errors.ErrUnsupported })
			if replacementBlocked {
				if err != nil || result.State != SplitCompleteDurabilityUncertain || barrierCalls != 1 || !errors.Is(result.DurabilityError, errors.ErrUnsupported) {
					t.Fatalf("split after blocked directory replacement = %+v, %v, barriers=%d", result, err, barrierCalls)
				}
				var reconstructed []byte
				for _, chunk := range result.Chunks {
					data, readErr := os.ReadFile(chunk)
					if readErr != nil || filepath.Dir(chunk) != directory {
						t.Fatalf("blocked replacement redirected a chunk: %q, %v", chunk, readErr)
					}
					reconstructed = append(reconstructed, data...)
				}
				if !bytes.Equal(reconstructed, payload) {
					t.Fatal("blocked replacement corrupted complete chunks")
				}
				original, readErr := os.ReadFile(target)
				if readErr != nil || !bytes.Equal(original, payload) {
					t.Fatalf("blocked replacement changed complete ciphertext: %v", readErr)
				}
				if _, statErr := os.Lstat(moved); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("blocked replacement moved the retained directory: %v", statErr)
				}
				return
			}
			if err == nil || result.State != SplitFailed || len(result.Chunks) != 0 || barrierCalls != 0 {
				t.Fatalf("failed split classified as complete: %+v, %v, calls=%d", result, err, barrierCalls)
			}
			base := directory
			if failure == "directory-identity" {
				base = moved
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if failure == "source-path" {
				want = 2
				foreign, err := os.ReadFile(target)
				if err != nil || string(foreign) != "foreign" {
					t.Fatal("source replacement changed")
				}
				original, err := os.ReadFile(target + "-moved")
				if err != nil || !bytes.Equal(original, payload) {
					t.Fatal("moved source changed")
				}
			}
			if failure == "collision" {
				want = 2
				foreign, err := os.ReadFile(target + ".0")
				if err != nil || string(foreign) != "foreign" {
					t.Fatal("collision changed")
				}
			}
			if len(entries) != want {
				t.Fatalf("owned partial chunks remain: %v", entries)
			}
		})
	}
}
