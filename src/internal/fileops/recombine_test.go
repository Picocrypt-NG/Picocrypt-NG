package fileops

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestRecombineExpectedInputsRejectsReplacedLaterChunkBeforeReading(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "split.pcv")
	output := filepath.Join(dir, "recombined.pcv")
	originalTailPath := base + ".1.original"
	replacement := []byte("foreign replacement")
	for path, content := range map[string][]byte{
		base + ".0": []byte("first chunk"),
		base + ".1": []byte("original tail bytes"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write chunk %s: %v", path, err)
		}
	}
	expected := make([]os.FileInfo, 2)
	for i := range expected {
		info, err := os.Stat(fmt.Sprintf("%s.%d", base, i))
		if err != nil {
			t.Fatalf("stat expected chunk %d: %v", i, err)
		}
		expected[i] = info
	}
	if err := os.Rename(base+".1", originalTailPath); err != nil {
		t.Fatalf("retain original later chunk: %v", err)
	}
	if err := os.WriteFile(base+".1", replacement, 0o600); err != nil {
		t.Fatalf("install replacement later chunk: %v", err)
	}

	readReplacement := false
	err := Recombine(RecombineOptions{
		InputBase:      base,
		OutputPath:     output,
		ExpectedInputs: expected,
		Progress: func(_ float32, info string) {
			if info == "2/2" {
				readReplacement = true
			}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "chunk 1 changed before recombination") {
		t.Fatalf("Recombine error = %v, want pinned-identity refusal", err)
	}
	if readReplacement {
		t.Fatal("Recombine reported reading the replacement before rejecting it")
	}
	if got, readErr := os.ReadFile(base + ".1"); readErr != nil {
		t.Fatalf("read replacement later chunk: %v", readErr)
	} else if !bytes.Equal(got, replacement) {
		t.Fatalf("replacement later chunk = %q, want %q", got, replacement)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial recombined output survived refusal: %v", statErr)
	}
}

func TestRecombineExpectedInputsRejectsChangedLaterChunkSizeBeforeReading(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "split.pcv")
	output := filepath.Join(dir, "recombined.pcv")
	for path, content := range map[string][]byte{
		base + ".0": []byte("first chunk"),
		base + ".1": []byte("tail"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write chunk %s: %v", path, err)
		}
	}
	expected := make([]os.FileInfo, 2)
	for i := range expected {
		info, err := os.Stat(fmt.Sprintf("%s.%d", base, i))
		if err != nil {
			t.Fatalf("stat expected chunk %d: %v", i, err)
		}
		expected[i] = info
	}
	changedTail := []byte("tail grew after routing")
	if err := os.WriteFile(base+".1", changedTail, 0o600); err != nil {
		t.Fatalf("resize later chunk: %v", err)
	}

	err := Recombine(RecombineOptions{
		InputBase:      base,
		OutputPath:     output,
		ExpectedInputs: expected,
	})
	if err == nil || !strings.Contains(err.Error(), "chunk 1 changed before recombination") {
		t.Fatalf("Recombine error = %v, want pinned-size refusal", err)
	}
	if got, readErr := os.ReadFile(base + ".1"); readErr != nil {
		t.Fatalf("read resized later chunk: %v", readErr)
	} else if !bytes.Equal(got, changedTail) {
		t.Fatalf("resized later chunk = %q, want %q", got, changedTail)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial recombined output survived refusal: %v", statErr)
	}
}

func TestRecombineExpectedInputsDoNotFollowLaterChunkSymlink(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "split.pcv")
	output := filepath.Join(dir, "recombined.pcv")
	originalTailPath := base + ".1.original"
	for path, content := range map[string][]byte{
		base + ".0": []byte("first chunk"),
		base + ".1": []byte("original tail"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write chunk %s: %v", path, err)
		}
	}
	expected := make([]os.FileInfo, 2)
	for i := range expected {
		info, err := os.Stat(fmt.Sprintf("%s.%d", base, i))
		if err != nil {
			t.Fatalf("stat expected chunk %d: %v", i, err)
		}
		expected[i] = info
	}
	if err := os.Rename(base+".1", originalTailPath); err != nil {
		t.Fatalf("retain original later chunk: %v", err)
	}
	if err := os.Symlink(originalTailPath, base+".1"); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	err := Recombine(RecombineOptions{
		InputBase:      base,
		OutputPath:     output,
		ExpectedInputs: expected,
	})
	if err == nil || !strings.Contains(err.Error(), "open chunk 1") {
		t.Fatalf("Recombine error = %v, want no-follow open refusal", err)
	}
	if target, readErr := os.Readlink(base + ".1"); readErr != nil {
		t.Fatalf("replacement symlink was removed: %v", readErr)
	} else if target != originalTailPath {
		t.Fatalf("replacement symlink target = %q, want %q", target, originalTailPath)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial recombined output survived refusal: %v", statErr)
	}
}

func TestRecombineWritesToBorrowedOutputAndLeavesItOpen(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "split.pcv")
	payload := []byte("first chunk and tail")
	if err := os.WriteFile(base+".0", payload[:11], 0o600); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	if err := os.WriteFile(base+".1", payload[11:], 0o600); err != nil {
		t.Fatalf("write later chunk: %v", err)
	}
	outputPath := filepath.Join(dir, "borrowed-stage")
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create borrowed output: %v", err)
	}
	t.Cleanup(func() { _ = output.Close() })
	before, err := output.Stat()
	if err != nil {
		t.Fatalf("stat borrowed output: %v", err)
	}

	err = Recombine(RecombineOptions{
		InputBase: base,
		Output:    output,
	})
	if err != nil {
		t.Fatalf("Recombine: %v", err)
	}
	got, err := io.ReadAll(output)
	if err != nil {
		t.Fatalf("read rewound borrowed output: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("borrowed output = %q, want %q", got, payload)
	}
	after, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatalf("borrowed output pathname was cleaned: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("borrowed output pathname changed identity")
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
