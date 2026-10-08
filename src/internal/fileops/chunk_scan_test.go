package fileops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCountChunksBoundsRetainedMemoryAmongUnrelatedSiblings(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "split.pcv")
	if err := os.WriteFile(base+".0", []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range 12000 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("unrelated-%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak uint64
	checks := 0
	count, size, err := CountChunksWithCancel(base, func() bool {
		checks++
		if checks <= 8 {
			// Collection distinguishes retained directory entries from temporary
			// names already consumed. Reading the whole directory keeps its
			// entries live throughout iteration and exceeds this allowance.
			runtime.GC()
			var current runtime.MemStats
			runtime.ReadMemStats(&current)
			if current.HeapAlloc > before.HeapAlloc {
				peak = max(peak, current.HeapAlloc-before.HeapAlloc)
			}
		}
		return false
	})
	if err != nil || count != 1 || size != 6 {
		t.Fatalf("chunk set among siblings = %d/%d/%v; want 1/6/nil", count, size, err)
	}
	if checks < 3 || peak > 512<<10 {
		t.Fatalf("chunk discovery retained %d heap bytes across %d cancellation polls; want bounded batches below 512 KiB", peak, checks)
	}
	t.Logf("observed retained heap above baseline: %d bytes", peak)
}

func TestCountChunksRetainsOnlyMatchingMetadata(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "literal[1].pcv")
	for i, body := range []string{"one", "two", "three"} {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", base, i), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	budget := &ZIPResourceBudget{limit: (128 << 10) + (32 << 10)}
	count, size, err := countChunks(base, nil, nil, budget)
	if err != nil || count != 3 || size != 11 {
		t.Fatalf("stable chunks = %d/%d/%v; want 3/11/nil", count, size, err)
	}
	peak := budget.PeakBytes()
	for i := range 3000 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("unrelated-%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	count, size, err = countChunks(base, nil, nil, budget)
	if err != nil || count != 3 || size != 11 {
		t.Fatalf("chunks among unrelated siblings = %d/%d/%v; want 3/11/nil", count, size, err)
	}
	if budget.CurrentBytes() != 0 || budget.PeakBytes() != peak {
		t.Fatalf("unrelated siblings retained metadata: live=%d peak=%d, previous peak=%d", budget.CurrentBytes(), budget.PeakBytes(), peak)
	}
	refused := &ZIPResourceBudget{limit: (128 << 10) + 1}
	count, size, err = countChunks(base, nil, nil, refused)
	if !errors.Is(err, ErrChunkMetadataLimit) || count != 0 || size != 0 || refused.CurrentBytes() != 0 {
		t.Fatalf("metadata refusal = %d/%d/%v live=%d; want refusal with no retained state", count, size, err, refused.CurrentBytes())
	}
	for i, want := range []string{"one", "two", "three"} {
		got, err := os.ReadFile(fmt.Sprintf("%s.%d", base, i))
		if err != nil || string(got) != want {
			t.Fatalf("metadata refusal changed source %d: %q, %v", i, got, err)
		}
	}
}

func TestRecombineCancelsWhileScanningUnrelatedSiblings(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "split.pcv")
	if err := os.WriteFile(base+".0", []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range 1000 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("unrelated-%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checks := 0
	output := filepath.Join(root, "output.pcv")
	err := Recombine(RecombineOptions{InputBase: base, OutputPath: output, Cancel: func() bool {
		checks++
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Errorf("recombination created output before directory discovery finished: %v", err)
		}
		return checks >= 3
	}})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("directory scan did not stop on cancellation: %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("cancelled directory scan created output: %v", err)
	}
	got, err := os.ReadFile(base + ".0")
	if err != nil || string(got) != "source" {
		t.Fatalf("cancelled directory scan changed source: %q, %v", got, err)
	}
}

func TestRecombineCancelsDiscoveryBeforeGapOrOutput(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "split.pcv")
	for _, name := range []string{base + ".0", base + ".2"} {
		if err := os.WriteFile(name, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(root, "output.pcv")
	err := Recombine(RecombineOptions{InputBase: base, OutputPath: output, Cancel: func() bool { return true }})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("cancelled discovery returned %v; must stop before scanning gaps", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("cancelled discovery created output: %v", err)
	}
	for _, name := range []string{base + ".0", base + ".2"} {
		got, err := os.ReadFile(name)
		if err != nil || string(got) != "untouched" {
			t.Fatalf("source changed: %q, %v", got, err)
		}
	}
}
