package fileops

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
)

func FuzzOpenZIPReaderMetadataAdmission(f *testing.F) {
	seed, err := os.ReadFile("testdata/zip_disjoint_reordered.zip")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add(append([]byte{'P', 'K', 5, 6}, make([]byte, 18)...))
	f.Add([]byte("PK\x05\x06"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			t.Skip("bounded metadata fuzz input")
		}
		reader, err := OpenZIPReader(bytes.NewReader(data), int64(len(data)), ZIPReadOptions{})
		if err != nil {
			if reader != nil {
				t.Fatal("refusal granted reader")
			}
			return
		}
		defer reader.Close()
		if reader.Budget().PeakBytes() > reader.Budget().LimitBytes() {
			t.Fatal("admission exceeded working budget")
		}
		standard, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil || len(reader.File) != len(standard.File) {
			t.Fatalf("admitted ZIP changed standard parsing: %v", err)
		}
		for index, file := range reader.File {
			if file.Name != standard.File[index].Name || file.CompressedSize64 != standard.File[index].CompressedSize64 || file.UncompressedSize64 != standard.File[index].UncompressedSize64 {
				t.Fatal("admission changed parsed entry metadata")
			}
		}
	})
}
