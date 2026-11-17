package fileops

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecombineBoundsPreparedChunkReadsAndRejectsMidReadGrowth(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "input.pcv")
	first := bytes.Repeat([]byte("A"), 2<<20)
	if err := os.WriteFile(base+".0", first, 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(base + ".0")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "recombined")
	grew := false
	var largest int64
	err = Recombine(RecombineOptions{InputBase: base, OutputPath: output, ExpectedInputs: []os.FileInfo{expected}, Progress: func(float32, string) {
		info, err := os.Stat(output)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > largest {
			largest = info.Size()
		}
		if !grew {
			grew = true
			f, err := os.OpenFile(base+".0", os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := f.Write(bytes.Repeat([]byte("R"), 3<<20))
			closeErr := f.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("grow input: %v %v", writeErr, closeErr)
			}
		}
	}})
	if err == nil || !strings.Contains(err.Error(), "chunk 0 changed") {
		t.Fatalf("growth accepted: %v", err)
	}
	if largest > expected.Size() {
		t.Fatalf("read beyond prepared size: consumed=%d prepared=%d", largest, expected.Size())
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("growth refusal retained output: %v", err)
	}
	info, err := os.Stat(base + ".0")
	if err != nil || info.Size() != 5<<20 {
		t.Fatalf("source growth changed by reader: %v %v", info, err)
	}
}

func TestRecombineRejectsChunkCountChangeDuringRead(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "input.pcv")
	if err := os.WriteFile(base+".0", []byte("selected"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(base + ".0")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "recombined")
	err = Recombine(RecombineOptions{InputBase: base, OutputPath: output, ExpectedInputs: []os.FileInfo{info}, Progress: func(float32, string) {
		if err := os.WriteFile(base+".1", []byte("late"), 0o600); err != nil {
			t.Fatal(err)
		}
	}})
	if err == nil || !strings.Contains(err.Error(), "chunk") {
		t.Fatalf("late chunk accepted: %v", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("count refusal retained output: %v", err)
	}
	for i, want := range []string{"selected", "late"} {
		got, err := os.ReadFile(fmt.Sprintf("%s.%d", base, i))
		if err != nil || string(got) != want {
			t.Fatalf("source changed: %q %v", got, err)
		}
	}
}

func TestRecombineRejectsPreparedChunkZeroGrowthWhileLaterChunkIsRead(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "input.pcv")
	expected := make([]os.FileInfo, 2)
	for i, part := range []string{"first", "tail"} {
		path := fmt.Sprintf("%s.%d", base, i)
		if err := os.WriteFile(path, []byte(part), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		expected[i], err = os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	first, err := os.Open(base + ".0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	output := filepath.Join(dir, "recombined")
	err = Recombine(RecombineOptions{InputBase: base, OutputPath: output, FirstChunk: first, ExpectedInputs: expected, Progress: func(_ float32, part string) {
		if part == "2/2" {
			if err := os.Truncate(base+".0", expected[0].Size()+1); err != nil {
				t.Fatal(err)
			}
		}
	}})
	if err == nil || !strings.Contains(err.Error(), "chunk 0 changed") {
		t.Fatalf("prepared chunk zero growth accepted after its read: %v", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("growth refusal retained output: %v", err)
	}
}
