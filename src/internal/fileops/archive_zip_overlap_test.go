package fileops

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnpackRejectsOverlappingZIPPayloadsBeforeCreatingOutput(t *testing.T) {
	zipPath := filepath.Join("testdata", "zip_payload_overlap.zip")
	reader := requireReadableZIPPayloadFixture(t, zipPath, map[string]string{
		"first.txt": "shared ZIP payload\n",
		"other.txt": "shared ZIP payload\n",
	})
	firstOffset, err := reader.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	otherOffset, err := reader.File[1].DataOffset()
	if err != nil || firstOffset != otherOffset || reader.File[0].CompressedSize64 == 0 {
		t.Fatalf("fixture must share a nonempty payload: first=%d other=%d err=%v", firstOffset, otherOffset, err)
	}

	extractDir := filepath.Join(t.TempDir(), "out")
	err = Unpack(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "overlap") {
		t.Fatalf("overlapping ZIP extraction error = %v; want overlap rejection", err)
	}
	if _, err := os.Lstat(extractDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("overlap rejection created an extraction directory or plaintext: %v", err)
	}
}

func TestUnpackAllowsDisjointZIPPayloadsInReversedOrderAndEmptyFile(t *testing.T) {
	zipPath := filepath.Join("testdata", "zip_disjoint_reordered.zip")
	want := map[string]string{
		"first.txt": "first stored payload\n",
		"empty.txt": "",
		"last.txt":  "last stored payload\n",
	}
	requireReadableZIPPayloadFixture(t, zipPath, want)
	extractDir := filepath.Join(t.TempDir(), "out")
	if err := Unpack(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir}); err != nil {
		t.Fatalf("disjoint ZIP extraction failed: %v", err)
	}
	for name, contents := range want {
		got, err := os.ReadFile(filepath.Join(extractDir, name))
		if err != nil || string(got) != contents {
			t.Fatalf("extracted %s = %q, err=%v; want %q", name, got, err, contents)
		}
	}
}

// The overlap fixture has two distinct central names referring to one stored
// payload. Decode every entry through archive/zip first: malformed sizes, CRCs,
// or truncated data must not accidentally satisfy the extraction refusal test.
func requireReadableZIPPayloadFixture(t *testing.T, path string, want map[string]string) *zip.ReadCloser {
	t.Helper()
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	if len(reader.File) != len(want) {
		t.Fatalf("fixture has %d entries; want %d", len(reader.File), len(want))
	}
	for _, file := range reader.File {
		expected, ok := want[file.Name]
		if !ok {
			t.Fatalf("unexpected fixture entry %q", file.Name)
		}
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(entry)
		closeErr := entry.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(got, []byte(expected)) {
			t.Fatalf("fixture entry %s failed content/CRC validation: read=%v close=%v", file.Name, readErr, closeErr)
		}
	}
	return reader
}
