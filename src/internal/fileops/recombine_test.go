package fileops

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRecombineValidatesAndConsumesSameFirstChunkBeforeOutput(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "split.pcv")
	output := filepath.Join(dir, "recombined.pcv")
	backup := filepath.Join(dir, "original-chunk-zero")
	replacement := filepath.Join(dir, "replacement")
	originalFirst := []byte("original first chunk")
	tail := []byte(" and original tail")
	replacementFirst := []byte("PCV\x00replacement")
	if err := os.WriteFile(base+".0", originalFirst, 0o600); err != nil {
		t.Fatalf("write original chunk zero: %v", err)
	}
	if err := os.WriteFile(base+".1", tail, 0o600); err != nil {
		t.Fatalf("write original tail: %v", err)
	}
	if err := os.WriteFile(replacement, replacementFirst, 0o600); err != nil {
		t.Fatalf("write replacement chunk: %v", err)
	}
	firstChunk, err := os.Open(base + ".0")
	if err != nil {
		t.Fatalf("open routed chunk zero: %v", err)
	}
	t.Cleanup(func() { _ = firstChunk.Close() })

	validationCalls := 0
	err = Recombine(RecombineOptions{
		InputBase:  base,
		OutputPath: output,
		FirstChunk: firstChunk,
		ValidateFirstChunk: func(source *os.File) error {
			validationCalls++
			if source != firstChunk {
				return errors.New("recombine did not validate the borrowed chunk-zero descriptor")
			}
			if _, err := os.Lstat(output); err == nil {
				return errors.New("recombine output exists before first-chunk validation")
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("inspect output before first-chunk validation: %w", err)
			}
			observed := make([]byte, len(originalFirst))
			if _, err := source.ReadAt(observed, 0); err != nil {
				return fmt.Errorf("read validated chunk: %w", err)
			}
			if !bytes.Equal(observed, originalFirst) {
				return fmt.Errorf("validated bytes = %q; want original chunk", observed)
			}
			if err := os.Rename(base+".0", backup); err != nil {
				return fmt.Errorf("retain validated chunk: %w", err)
			}
			if err := os.Rename(replacement, base+".0"); err != nil {
				return fmt.Errorf("replace chunk path: %w", err)
			}
			if _, err := source.Seek(0, io.SeekEnd); err != nil {
				return fmt.Errorf("move validation cursor: %w", err)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Recombine: %v", err)
	}
	if validationCalls != 1 {
		t.Fatalf("validation calls = %d; want one exact first-chunk validation", validationCalls)
	}
	if _, err := firstChunk.Stat(); err != nil {
		t.Fatalf("Recombine closed the borrowed chunk-zero descriptor: %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read recombined output: %v", err)
	}
	want := append(append([]byte(nil), originalFirst...), tail...)
	if !bytes.Equal(got, want) {
		t.Fatalf("recombined bytes = %q; want bytes from validated descriptor %q", got, want)
	}
	currentFirst, err := os.ReadFile(base + ".0")
	if err != nil {
		t.Fatalf("read replacement chunk path: %v", err)
	}
	if !bytes.Equal(currentFirst, replacementFirst) {
		t.Fatalf("replacement chunk changed: got %q want %q", currentFirst, replacementFirst)
	}
}

// TestRecombineSourceCloseFailureRemovesOutput asserts that when a source-chunk
// close fails mid-recombine, the partial output file is removed before Recombine
// returns.  Before the fix the fin.Close error path returns without calling
// os.Remove(outputPath), leaving a partial output on disk.
//
// Failure injection: recombineCloseFn is overridden to return an error for chunk 0.
func TestRecombineSourceCloseFailureRemovesOutput(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")
	outputPath := filepath.Join(tmpDir, "output.pcv")

	chunk0 := basePath + ".0"
	chunk1 := basePath + ".1"
	if err := os.WriteFile(chunk0, bytes.Repeat([]byte{0xAA}, 512), 0o644); err != nil {
		t.Fatalf("create chunk 0: %v", err)
	}
	if err := os.WriteFile(chunk1, bytes.Repeat([]byte{0xBB}, 512), 0o644); err != nil {
		t.Fatalf("create chunk 1: %v", err)
	}

	// Override the close hook so that closing chunk 0 returns a synthetic error.
	// Restore afterward so other tests are unaffected.
	orig := recombineCloseFn
	recombineCloseFn = func(f *os.File) error {
		if filepath.Base(f.Name()) == "test.pcv.0" {
			_ = f.Close() // actually close the fd so we don't leak it
			return fmt.Errorf("injected close failure on %s", f.Name())
		}
		return f.Close()
	}
	t.Cleanup(func() { recombineCloseFn = orig })

	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})
	if err == nil {
		t.Fatal("expected error from injected close failure, got nil")
	}

	// The partial output file must NOT remain after the error.
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Errorf("partial output %q should be removed after source-close failure; stat: %v", outputPath, statErr)
	}
}

// TestRecombineSyncFailureRemovesOutput asserts that when fout.Sync() fails,
// the partial output file is removed before Recombine returns.  Before the fix
// the Sync error path returns without calling os.Remove(outputPath).
func TestRecombineSyncFailureRemovesOutput(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")
	outputPath := filepath.Join(tmpDir, "output.pcv")

	if err := os.WriteFile(basePath+".0", bytes.Repeat([]byte{0xCC}, 256), 0o644); err != nil {
		t.Fatalf("create chunk: %v", err)
	}

	orig := recombineSyncFn
	recombineSyncFn = func(f *os.File) error {
		return errors.New("injected sync failure")
	}
	t.Cleanup(func() { recombineSyncFn = orig })

	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})
	if err == nil {
		t.Fatal("expected error from injected sync failure, got nil")
	}

	// The partial output file must NOT remain.
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Errorf("partial output %q should be removed after sync failure; stat: %v", outputPath, statErr)
	}
}
