package fileops

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestZIPResourceAboveFormerCountRealExtraction(t *testing.T) {
	if os.Getenv("PICOCRYPT_RUN_ZIP_RESOURCE_INTEGRATION") != "1" {
		t.Skip("opt-in real filesystem extraction above former ZIP count threshold")
	}
	for _, count := range []int{65_537, 100_003} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			data := independentStoredZIP(t, count, 0)
			archive := filepath.Join(t.TempDir(), "original.zip")
			if err := os.WriteFile(archive, data, 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "out")
			if err := os.Mkdir(out, 0o700); err != nil {
				t.Fatal(err)
			}
			budget := NewZIPResourceBudget()
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			result := UnpackWithResult(UnpackOptions{ZipPath: archive, ExtractDir: out, Budget: budget})
			runtime.ReadMemStats(&after)
			if result.State() != UnpackStatePublishedDurable || result.(*unpackResult).err != nil {
				t.Fatalf("extraction=%v cause=%v", result, result.(*unpackResult).err)
			}
			elapsed := time.Since(start)
			if budget.CurrentBytes() != 0 || budget.PeakBytes() > budget.LimitBytes() {
				t.Fatalf("budget did not settle: current=%d peak=%d", budget.CurrentBytes(), budget.PeakBytes())
			}
			entries, err := os.ReadDir(out)
			if err != nil || len(entries) != count {
				t.Fatalf("output count=%d err=%v", len(entries), err)
			}
			for index := range count {
				name := fmt.Sprintf("f%06d", index)
				got, err := os.ReadFile(filepath.Join(out, name))
				if err != nil {
					t.Fatal(err)
				}
				if sha256.Sum256(got) != sha256.Sum256([]byte{byte(index % 251)}) {
					t.Fatalf("output body hash changed: %s", name)
				}
			}
			for _, entry := range entries {
				if len(entry.Name()) != 7 || entry.IsDir() {
					t.Fatalf("stage residue or unexpected output: %s", entry.Name())
				}
			}
			original, err := os.ReadFile(archive)
			if err != nil || !bytes.Equal(original, data) {
				t.Fatal("successful extraction changed original ZIP")
			}
			t.Logf("count=%d working_peak=%d cumulative_alloc_bytes=%d extraction_elapsed=%s", count, budget.PeakBytes(), after.TotalAlloc-before.TotalAlloc, elapsed)
		})
	}
}

// This repeats the original zip_memory_probe_test.go productionUnpack1024
// shape, including names, Stored bodies, writer and default Unpack path.
func TestZIPUnpackAllocationMeasurement(t *testing.T) {
	if os.Getenv("PICOCRYPT_RUN_ZIP_RESOURCE_MEASUREMENTS") != "1" {
		t.Skip("opt-in extraction allocation comparison")
	}
	dir := t.TempDir()
	archive := filepath.Join(dir, "input.zip")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for index := range 1024 {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("f%08d", index), Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	err = Unpack(UnpackOptions{ZipPath: archive, ExtractDir: filepath.Join(dir, "out")})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 64<<20 {
		t.Fatalf("small-file extraction reintroduced per-file buffers: alloc=%d", allocated)
	}
	t.Logf("entries=1024 cumulative_alloc=%d heap_delta=%d elapsed=%s", allocated, int64(after.HeapAlloc)-int64(before.HeapAlloc), time.Since(start))
}

func TestZIPResourceAllocationMeasurement(t *testing.T) {
	if os.Getenv("PICOCRYPT_RUN_ZIP_RESOURCE_MEASUREMENTS") != "1" {
		t.Skip("opt-in allocation calibration")
	}
	for _, scenario := range []struct {
		name            string
		count, comments int
	}{
		{"short1000", 1000, 0}, {"short16000", 16000, 0}, {"short65537", 65537, 0}, {"short100003", 100003, 0}, {"short200000", 200000, 0}, {"commentsAbove32MiB", 1025, 32768},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var data []byte
			var source io.ReaderAt
			var size int64
			if fixtureDir := os.Getenv("PICOCRYPT_ZIP_CALIBRATION_DIR"); fixtureDir != "" {
				file, err := os.Open(filepath.Join(fixtureDir, scenario.name+".zip"))
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				info, err := file.Stat()
				if err != nil {
					t.Fatal(err)
				}
				source = file
				size = info.Size()
			} else {
				data = independentStoredZIP(t, scenario.count, scenario.comments)
				source = bytes.NewReader(data)
				size = int64(len(data))
			}
			budget := NewZIPResourceBudget()
			var before, after, retained runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			reader, err := OpenZIPReader(source, size, ZIPReadOptions{Budget: budget})
			if err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			runtime.GC()
			runtime.ReadMemStats(&retained)
			live := int64(retained.HeapAlloc) - int64(before.HeapAlloc)
			// A measured retained footprint exceeding the conservative reader
			// charge is a failed calibration, not permission to raise the ceiling.
			if live > int64(budget.CurrentBytes()) {
				t.Fatalf("measured reader heap=%d exceeds charge=%d", live, budget.CurrentBytes())
			}
			t.Logf("entries=%d comments=%d retained_heap=%d retained_charge=%d working_peak=%d cumulative_alloc=%d elapsed=%s", scenario.count, scenario.comments, live, budget.CurrentBytes(), budget.PeakBytes(), after.TotalAlloc-before.TotalAlloc, elapsed)
			if status, err := os.ReadFile("/proc/self/status"); err == nil {
				for _, line := range strings.Split(string(status), "\n") {
					if strings.HasPrefix(line, "VmHWM:") || strings.HasPrefix(line, "VmRSS:") {
						t.Log(line)
					}
				}
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			runtime.KeepAlive(data)
		})
	}
}
