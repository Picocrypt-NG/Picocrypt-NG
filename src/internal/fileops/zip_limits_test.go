package fileops

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The count wraps just as classic ZIP counts do. All entries refer to one
// empty local directory, keeping this regression bounded to about 3.5 MiB.
func repeatedEmptyZIP(t *testing.T, entries int) []byte {
	t.Helper()
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	if _, err := w.Create("empty/"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	original := data.Bytes()
	end := len(original) - 22
	start := int(binary.LittleEndian.Uint32(original[end+16:]))
	entry := original[start:end]
	result := append([]byte(nil), original[:start]...)
	for range entries {
		result = append(result, entry...)
	}
	footer := append([]byte(nil), original[end:]...)
	binary.LittleEndian.PutUint16(footer[8:], uint16(entries))
	binary.LittleEndian.PutUint16(footer[10:], uint16(entries))
	binary.LittleEndian.PutUint32(footer[12:], uint32(len(entry)*entries))
	return append(result, footer...)
}

func TestUnpackMetadataLimitPrecedesReviewAndOutput(t *testing.T) {
	archive := repeatedEmptyZIP(t, 65_537)
	path := filepath.Join(t.TempDir(), "many.zip")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, held := range []bool{false, true} {
		t.Run(map[bool]string{false: "path", true: "held file"}[held], func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			reviewed := false
			opts := UnpackOptions{ZipPath: path, ExtractDir: out, Budget: &ZIPResourceBudget{limit: 8 << 20}, Review: func(ZIPSummary) error {
				reviewed = true
				return errors.New("unexpected review")
			}}
			if held {
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				opts.ZipFile = file
			}
			err := Unpack(opts)
			if err == nil || reviewed {
				t.Fatalf("excessive metadata reached review: reviewed=%v err=%v", reviewed, err)
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("metadata refusal created output: %v", err)
			}
		})
	}
}

func TestUnpackDirectoryPassObservesCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directories.zip")
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	for _, name := range []string{"first/", "second/"} {
		if _, err := w.Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	observed := false
	err := Unpack(UnpackOptions{ZipPath: path, ExtractDir: out, Cancel: func() bool {
		if _, err := os.Stat(filepath.Join(out, "first")); err != nil {
			return false
		}
		observed = true
		if _, err := os.Stat(filepath.Join(out, "second")); !errors.Is(err, os.ErrNotExist) {
			t.Error("directory creation continued after cancellation became observable")
		}
		return true
	}})
	if !observed || err == nil || !strings.Contains(err.Error(), "operation cancelled") {
		t.Fatalf("cancellation observed=%v err=%v", observed, err)
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled directory pass left residue: %v %v", entries, err)
	}
}

func TestZIPPreflightSizeOnlyZIP64MatchesLinkedStandardLibrary(t *testing.T) {
	archive := zip64FromClassic(t, repeatedEmptyZIP(t, 1), 1)
	end := len(archive) - 22
	start := binary.LittleEndian.Uint64(archive[end-76+48:])
	binary.LittleEndian.PutUint16(archive[end+8:], 1)
	binary.LittleEndian.PutUint16(archive[end+10:], 1)
	binary.LittleEndian.PutUint32(archive[end+16:], uint32(start))
	for _, sentinel := range []uint32{0xffff, 0xffffffff} {
		binary.LittleEndian.PutUint32(archive[end+12:], sentinel)
		standard, standardErr := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		bounded, err := OpenZIPReader(bytes.NewReader(archive), int64(len(archive)), ZIPReadOptions{})
		if bounded != nil {
			defer bounded.Close()
		}
		if standardErr == nil {
			if err != nil || len(bounded.File) != len(standard.File) {
				t.Fatalf("linked ZIP64 sentinel %#x refused: %v", sentinel, err)
			}
		} else if err == nil {
			t.Fatalf("unrecognized ZIP64 sentinel %#x accepted", sentinel)
		}
	}
}

func zip64FromClassic(t *testing.T, archive []byte, count uint64) []byte {
	t.Helper()
	end := len(archive) - 22
	footer := append([]byte(nil), archive[end:]...)
	var extension [76]byte
	binary.LittleEndian.PutUint32(extension[:], 0x06064b50)
	binary.LittleEndian.PutUint64(extension[4:], 44)
	binary.LittleEndian.PutUint16(extension[12:], 45)
	binary.LittleEndian.PutUint16(extension[14:], 45)
	binary.LittleEndian.PutUint64(extension[24:], count)
	binary.LittleEndian.PutUint64(extension[32:], count)
	binary.LittleEndian.PutUint64(extension[40:], uint64(binary.LittleEndian.Uint32(footer[12:])))
	binary.LittleEndian.PutUint64(extension[48:], uint64(binary.LittleEndian.Uint32(footer[16:])))
	binary.LittleEndian.PutUint32(extension[56:], 0x07064b50)
	binary.LittleEndian.PutUint64(extension[64:], uint64(end))
	binary.LittleEndian.PutUint32(extension[72:], 1)
	binary.LittleEndian.PutUint16(footer[8:], 0xffff)
	binary.LittleEndian.PutUint16(footer[10:], 0xffff)
	binary.LittleEndian.PutUint32(footer[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(footer[16:], 0xffffffff)
	result := append([]byte(nil), archive[:end]...)
	result = append(result, extension[:]...)
	return append(result, footer...)
}

func TestZIPPreflightPreservesClassicZIP64AndPrependedArchives(t *testing.T) {
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	entry, err := w.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("exact compatible payload")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for name, archive := range map[string][]byte{
		"classic":                        data.Bytes(),
		"zip64":                          zip64FromClassic(t, data.Bytes(), 1),
		"prepended":                      append([]byte("self-extracting prefix"), data.Bytes()...),
		"empty":                          repeatedEmptyZIP(t, 0),
		"classic wrapped count boundary": repeatedEmptyZIP(t, 65_536),
		"zip64 count boundary":           zip64FromClassic(t, repeatedEmptyZIP(t, 65_536), 65_536),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := OpenZIPReader(bytes.NewReader(archive), int64(len(archive)), ZIPReadOptions{})
			if r != nil {
				defer r.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if name == "empty" {
				if len(r.File) != 0 {
					t.Fatal("empty ZIP changed")
				}
				return
			}
			if strings.Contains(name, "boundary") {
				if len(r.File) != 65_536 {
					t.Fatalf("entry count %d", len(r.File))
				}
				return
			}
			if len(r.File) != 1 || r.File[0].Name != "payload.txt" {
				t.Fatalf("metadata changed: %+v", r.File)
			}
			body, err := r.File[0].Open()
			if err != nil {
				t.Fatal(err)
			}
			defer body.Close()
			got, err := io.ReadAll(body)
			if err != nil || string(got) != "exact compatible payload" {
				t.Fatalf("payload=%q err=%v", got, err)
			}
		})
	}
}

func TestZIPPreflightRejectsImpossibleDirectoryAndHostileDeclaredCount(t *testing.T) {
	classic := repeatedEmptyZIP(t, 1)
	oversized := append([]byte(nil), classic...)
	binary.LittleEndian.PutUint32(oversized[len(oversized)-10:], (32<<20)+1)
	for name, test := range map[string]struct {
		archive []byte
		want    error
	}{
		"directory extends beyond source": {oversized, zip.ErrFormat},
		"hostile ZIP64 count":             {zip64FromClassic(t, classic, math.MaxUint64), ErrZIPMetadataLimit},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := OpenZIPReader(bytes.NewReader(test.archive), int64(len(test.archive)), ZIPReadOptions{})
			if r != nil {
				defer r.Close()
			}
			if r != nil || !errors.Is(err, test.want) {
				t.Fatalf("excess granted reader=%v err=%v", r, err)
			}
		})
	}
}

func TestZIPPreflightCountsActualMetadataWhenDirectorySizeLies(t *testing.T) {
	archive := repeatedEmptyZIP(t, 1)
	end := len(archive) - 22
	start := int(binary.LittleEndian.Uint32(archive[end+16:]))
	header := append([]byte(nil), archive[start:end]...)
	binary.LittleEndian.PutUint16(header[32:], 65_535)
	comment := make([]byte, 65_535)
	var data bytes.Buffer
	data.Grow(start + 512*(len(header)+len(comment)) + 22)
	data.Write(archive[:start])
	for range 512 {
		data.Write(header)
		data.Write(comment)
	}
	footer := append([]byte(nil), archive[end:]...)
	binary.LittleEndian.PutUint16(footer[8:], 512)
	binary.LittleEndian.PutUint16(footer[10:], 512)
	// archive/zip can recover this incorrect size using its raw-offset fallback.
	// The actual metadata budget must hold even when that field understates it.
	binary.LittleEndian.PutUint32(footer[12:], 0)
	data.Write(footer)
	r, err := OpenZIPReader(bytes.NewReader(data.Bytes()), int64(data.Len()), ZIPReadOptions{Budget: &ZIPResourceBudget{limit: 16 << 20}})
	if r != nil {
		defer r.Close()
	}
	if r != nil || !errors.Is(err, ErrZIPMetadataLimit) {
		t.Fatalf("understated metadata granted reader=%v err=%v", r, err)
	}
}

type changingZIPReader struct {
	data      []byte
	afterRead func()
}

func (reader *changingZIPReader) ReadAt(data []byte, offset int64) (int, error) {
	n, err := bytes.NewReader(reader.data).ReadAt(data, offset)
	if reader.afterRead != nil {
		action := reader.afterRead
		reader.afterRead = nil
		action()
	}
	return n, err
}

func TestZIPPreflightFreezesMetadataUntilEagerParsingEnds(t *testing.T) {
	archive := repeatedEmptyZIP(t, 1)
	source := &changingZIPReader{data: archive}
	source.afterRead = func() {
		end := len(archive) - 22
		start := int(binary.LittleEndian.Uint32(archive[end+16:]))
		copy(archive[start+46:], "other/")
		binary.LittleEndian.PutUint16(archive[end+10:], 0xffff)
	}
	r, err := OpenZIPReader(source, int64(len(archive)), ZIPReadOptions{})
	if r != nil {
		defer r.Close()
	}
	if err != nil || len(r.File) != 1 || r.File[0].Name != "empty/" {
		t.Fatalf("mutable metadata bypassed frozen admission: reader=%v err=%v", r, err)
	}
}

func TestZIPPreflightCancellationStopsBeforeReadingCentralMetadata(t *testing.T) {
	archive := repeatedEmptyZIP(t, 65_536)
	cancelled := false
	source := &changingZIPReader{data: archive, afterRead: func() { cancelled = true }}
	r, err := OpenZIPReader(source, int64(len(archive)), ZIPReadOptions{Cancel: func() bool { return cancelled }})
	if r != nil {
		defer r.Close()
	}
	if r != nil || err == nil || !strings.Contains(err.Error(), "operation cancelled") {
		t.Fatalf("cancelled parse returned reader=%v err=%v", r, err)
	}
}
