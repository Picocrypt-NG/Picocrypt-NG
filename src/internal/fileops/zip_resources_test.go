package fileops

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// independentStoredZIP assembles the documented Stored ZIP records directly,
// independently of archive/zip's writer and the production preflight parser.
// Every name and payload has an externally defined index-based oracle.
func independentStoredZIP(t *testing.T, count, commentBytes int) []byte {
	t.Helper()
	var local, central bytes.Buffer
	for index := range count {
		name := fmt.Sprintf("f%06d", index)
		body := []byte{byte(index % 251)}
		crc := crc32.ChecksumIEEE(body)
		var header [30]byte
		binary.LittleEndian.PutUint32(header[:], 0x04034b50)
		binary.LittleEndian.PutUint16(header[4:], 20)
		binary.LittleEndian.PutUint32(header[14:], crc)
		binary.LittleEndian.PutUint32(header[18:], 1)
		binary.LittleEndian.PutUint32(header[22:], 1)
		binary.LittleEndian.PutUint16(header[26:], uint16(len(name)))
		var entry [46]byte
		binary.LittleEndian.PutUint32(entry[:], 0x02014b50)
		binary.LittleEndian.PutUint16(entry[4:], 20)
		binary.LittleEndian.PutUint16(entry[6:], 20)
		binary.LittleEndian.PutUint32(entry[16:], crc)
		binary.LittleEndian.PutUint32(entry[20:], 1)
		binary.LittleEndian.PutUint32(entry[24:], 1)
		binary.LittleEndian.PutUint16(entry[28:], uint16(len(name)))
		binary.LittleEndian.PutUint16(entry[32:], uint16(commentBytes))
		binary.LittleEndian.PutUint32(entry[42:], uint32(local.Len()))
		local.Write(header[:])
		local.WriteString(name)
		local.Write(body)
		central.Write(entry[:])
		central.WriteString(name)
		central.Write(bytes.Repeat([]byte{'c'}, commentBytes))
	}
	var end [22]byte
	binary.LittleEndian.PutUint32(end[:], 0x06054b50)
	binary.LittleEndian.PutUint16(end[8:], uint16(count))
	binary.LittleEndian.PutUint16(end[10:], uint16(count))
	binary.LittleEndian.PutUint32(end[12:], uint32(central.Len()))
	binary.LittleEndian.PutUint32(end[16:], uint32(local.Len()))
	local.Write(central.Bytes())
	local.Write(end[:])
	return local.Bytes()
}

func TestUnpackDirectoryCleanupBoundsErrorsAndStillAttemptsEveryOwnedDirectory(t *testing.T) {
	out := t.TempDir()
	root, err := os.OpenRoot(out)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	dirs := &ownedUnpackDirs{}
	for index := range 41 {
		name := fmt.Sprintf("d%03d", index)
		if err := root.Mkdir(name, 0o700); err != nil {
			t.Fatal(err)
		}
		info, err := root.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		dirs.record(ownedUnpackDir{targetName: name, outPath: filepath.Join(out, name), info: info})
		if index > 0 {
			// Keep the original inode alive elsewhere so no filesystem inode
			// reuse can make the foreign replacement look operation-owned.
			if err := root.Rename(name, name+"-original"); err != nil {
				t.Fatal(err)
			}
			if err := root.Mkdir(name, 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	err = dirs.cleanup(root)
	if err == nil || strings.Count(err.Error(), "changed before rollback") > 16 {
		t.Fatalf("cleanup retained unbounded errors: %v", err)
	}
	if _, err := root.Lstat("d000"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup stopped after error cap: %v", err)
	}
	for index := 1; index < 41; index++ {
		if _, err := root.Lstat(fmt.Sprintf("d%03d", index)); err != nil {
			t.Fatalf("foreign directory removed: %v", err)
		}
	}
}

func TestUnpackCancellationDuringPublicationRollsBackCompletedPrefix(t *testing.T) {
	data := independentStoredZIP(t, 3, 0)
	archive := filepath.Join(t.TempDir(), "original.zip")
	if err := os.WriteFile(archive, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	originalLink := unpackLinkFn
	cancelled := false
	unpackLinkFn = func(root *os.Root, oldName, newName string) error {
		err := originalLink(root, oldName, newName)
		if err == nil {
			cancelled = true
		}
		return err
	}
	t.Cleanup(func() { unpackLinkFn = originalLink })
	err := Unpack(UnpackOptions{ZipPath: archive, ExtractDir: out, Cancel: func() bool { return cancelled }})
	if !errors.Is(err, errZIPCancelled) {
		t.Fatalf("publication ignored cancellation: %v", err)
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled publication left output/stage: %v %v", entries, err)
	}
	got, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("cancelled publication changed original")
	}
}

func TestUnpackWorkingBudgetRefusesBeforeReviewAndFilesystemEffects(t *testing.T) {
	data := independentStoredZIP(t, 1, 0)
	archive := filepath.Join(t.TempDir(), "saved.zip")
	if err := os.WriteFile(archive, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "absent")
	// Reader admission fits; the retained reader plus staging/path/rollback
	// envelope does not. Plaintext review cannot authorize extra working memory.
	budget := &ZIPResourceBudget{limit: 10 << 20}
	reviewed := false
	err := Unpack(UnpackOptions{ZipPath: archive, ExtractDir: out, Budget: budget, Review: func(ZIPSummary) error { reviewed = true; return nil }})
	if !errors.Is(err, ErrZIPMetadataLimit) || reviewed {
		t.Fatalf("budget refusal=%v reviewed=%v", err, reviewed)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resource refusal created root: %v", err)
	}
	got, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("resource refusal modified original")
	}
	if budget.CurrentBytes() != 0 {
		t.Fatalf("retained charge after refusal=%d", budget.CurrentBytes())
	}
}

func TestZIPResourcePolicyAcceptsIndependentArchivesAboveFormerLimits(t *testing.T) {
	for _, scenario := range []struct {
		name            string
		count, comments int
	}{
		{"entry count", 65_537, 0}, {"central directory bytes", 1_025, 32_768},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if strconv.IntSize == 32 && scenario.comments != 0 {
				t.Skip("32-bit working policy cannot admit this long-comment calibration fixture")
			}
			data := independentStoredZIP(t, scenario.count, scenario.comments)
			reader, err := OpenZIPReader(bytes.NewReader(data), int64(len(data)), ZIPReadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if len(reader.File) != scenario.count {
				t.Fatalf("count=%d", len(reader.File))
			}
			for index, entry := range reader.File {
				if entry.Name != fmt.Sprintf("f%06d", index) || entry.Comment != string(bytes.Repeat([]byte{'c'}, scenario.comments)) {
					t.Fatalf("metadata changed at %d", index)
				}
				body, err := entry.Open()
				if err != nil {
					t.Fatal(err)
				}
				got, readErr := io.ReadAll(body)
				closeErr := body.Close()
				if readErr != nil || closeErr != nil || !bytes.Equal(got, []byte{byte(index % 251)}) {
					t.Fatalf("body/CRC changed at %d: %x %v %v", index, got, readErr, closeErr)
				}
			}
		})
	}
}

type zipCountingReader struct {
	io.ReaderAt
	requested int64
}

type zipMutationAtOffsetReader struct {
	data   []byte
	offset int64
	mutate func()
}

func (reader *zipMutationAtOffsetReader) ReadAt(data []byte, offset int64) (int, error) {
	n, err := bytes.NewReader(reader.data).ReadAt(data, offset)
	if offset == reader.offset && reader.mutate != nil {
		action := reader.mutate
		reader.mutate = nil
		action()
	}
	return n, err
}

func TestZIPPreflightFreezesRawSFXCandidateAndTerminatingHeader(t *testing.T) {
	classic := independentStoredZIP(t, 1, 0)
	end := len(classic) - 22
	start := int(binary.LittleEndian.Uint32(classic[end+16:]))
	raw := append([]byte(nil), classic[start:end]...)
	copy(raw[46:], "raw0000")
	computed := append([]byte(nil), classic[start:end]...)
	copy(computed[46:], "tail000")
	data := append([]byte(nil), classic[:start]...)
	data = append(data, raw...)
	terminator := len(data)
	data = append(data, make([]byte, 70<<10)...)
	data = append(data, computed...)
	data = append(data, classic[end:]...)
	source := &zipMutationAtOffsetReader{data: data, offset: int64(terminator)}
	source.mutate = func() {
		copy(data[start+46:], "mutated")
		copy(data[terminator:], raw)
	}
	reader, err := OpenZIPReader(source, int64(len(data)), ZIPReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if source.mutate != nil || len(reader.File) != 1 || reader.File[0].Name != "raw0000" {
		t.Fatalf("raw SFX frozen metadata changed: %+v", reader.File)
	}
	body, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(body)
	body.Close()
	if err != nil || !bytes.Equal(got, []byte{0}) {
		t.Fatalf("SFX payload=%x err=%v", got, err)
	}
}

func (reader *zipCountingReader) ReadAt(data []byte, offset int64) (int, error) {
	reader.requested += int64(len(data))
	return reader.ReaderAt.ReadAt(data, offset)
}

func TestZIPForgedHugeDeclaredCountRefusesBeforeEagerAllocationOrDirectoryScan(t *testing.T) {
	data := zip64FromClassic(t, independentStoredZIP(t, 1, 0), 1<<63)
	source := &zipCountingReader{ReaderAt: bytes.NewReader(data)}
	budget := NewZIPResourceBudget()
	reader, err := OpenZIPReader(source, int64(len(data)), ZIPReadOptions{Budget: budget})
	if reader != nil || !errors.Is(err, ErrZIPMetadataLimit) {
		t.Fatalf("hostile declared count reached reader: %v %v", reader, err)
	}
	if source.requested > 1024 || budget.CurrentBytes() != 0 {
		t.Fatalf("hostile count caused directory scan or retained charge: bytes=%d live=%d", source.requested, budget.CurrentBytes())
	}
}

func TestZIPPayloadRangeBudgetAndCancellationRetireTemporaryCharge(t *testing.T) {
	data := independentStoredZIP(t, 1000, 0)
	reader, err := OpenZIPReader(bytes.NewReader(data), int64(len(data)), ZIPReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	budget := &ZIPResourceBudget{limit: 15_999}
	if err := ValidateZIPPayloadRanges(reader.File, ZIPReadOptions{Budget: budget}); !errors.Is(err, ErrZIPMetadataLimit) {
		t.Fatalf("overlap allocation bypassed budget: %v", err)
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("range refusal retained charge")
	}
	budget = NewZIPResourceBudget()
	calls := 0
	err = ValidateZIPPayloadRanges(reader.File, ZIPReadOptions{Budget: budget, Cancel: func() bool { calls++; return calls == 17 }})
	if !errors.Is(err, errZIPCancelled) || budget.CurrentBytes() != 0 {
		t.Fatalf("cancelled range scan leaked reservation: %v %d", err, budget.CurrentBytes())
	}
}

func TestCreateZipResourceRefusalPrecedesOutputAndPreservesSelection(t *testing.T) {
	input := filepath.Join(t.TempDir(), "input")
	body := []byte("original selection remains intact")
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "refused.zip")
	budget := &ZIPResourceBudget{limit: 8 << 20}
	err := CreateZip(ZipOptions{Files: []string{input}, RootDir: filepath.Dir(input), OutputPath: output, Budget: budget})
	if !errors.Is(err, ErrZIPMetadataLimit) {
		t.Fatalf("writer ignored working budget: %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writer resource refusal created output: %v", err)
	}
	got, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("writer refusal modified selected input")
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("writer refusal leaked charge")
	}
}

func TestCreateZipCancellationDuringCentralDirectoryCloseRemovesOutput(t *testing.T) {
	input := filepath.Join(t.TempDir(), "input")
	body := []byte{42}
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "cancelled.zip")
	finishedBody := false
	checksAfterBody := 0
	err := CreateZip(ZipOptions{
		Files: []string{input}, RootDir: filepath.Dir(input), OutputPath: output,
		Progress: func(progress float32, _ string) {
			if progress == 1 {
				finishedBody = true
			}
		},
		Cancel: func() bool {
			if !finishedBody {
				return false
			}
			checksAfterBody++
			return checksAfterBody >= 2
		},
	})
	// The first check after the body precedes its EOF read; the next occurs
	// when zip.Writer flushes its buffered central directory during Close.
	if !errors.Is(err, errZIPCancelled) || !strings.Contains(err.Error(), "close zip writer") {
		t.Fatalf("central Close ignored cancellation: %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled central Close left output: %v", err)
	}
	got, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("central Close cancellation modified input")
	}
}

func TestZIPResourceBudgetChargesOverflowCancellationAndOwnerRetirement(t *testing.T) {
	data := independentStoredZIP(t, 1, 0)
	for _, test := range []struct {
		name string
		data []byte
		opts ZIPReadOptions
		want error
	}{
		{"declared ZIP64 overflow", zip64FromClassic(t, data, math.MaxUint64), ZIPReadOptions{Budget: &ZIPResourceBudget{limit: 16 << 20}}, ErrZIPMetadataLimit},
		{"cancelled preflight", data, ZIPReadOptions{Budget: &ZIPResourceBudget{limit: 16 << 20}, Cancel: func() bool { return true }}, errZIPCancelled},
		{"capacity refusal", data, ZIPReadOptions{Budget: &ZIPResourceBudget{limit: 8 << 20}}, ErrZIPMetadataLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, err := OpenZIPReader(bytes.NewReader(test.data), int64(len(test.data)), test.opts)
			if reader != nil || !errors.Is(err, test.want) {
				t.Fatalf("reader=%v err=%v", reader, err)
			}
			if test.opts.Budget.CurrentBytes() != 0 || test.opts.Budget.PeakBytes() > test.opts.Budget.LimitBytes() {
				t.Fatal("refusal leaked or exceeded charge")
			}
		})
	}
	budget := NewZIPResourceBudget()
	reader, err := OpenZIPReader(bytes.NewReader(data), int64(len(data)), ZIPReadOptions{Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	if budget.CurrentBytes() == 0 || budget.Release(math.MaxUint64) {
		t.Fatal("unowned retirement changed admission authority")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("closed reader retained charge")
	}
}

func TestZIPExtraDetachmentPreservesZIP64FieldsAndCRC(t *testing.T) {
	data := independentStoredZIP(t, 1, 0)
	end := len(data) - 22
	start := int(binary.LittleEndian.Uint32(data[end+16:]))
	var extra [20]byte
	binary.LittleEndian.PutUint16(extra[:], 1)
	binary.LittleEndian.PutUint16(extra[2:], 16)
	binary.LittleEndian.PutUint64(extra[4:], 1)
	binary.LittleEndian.PutUint64(extra[12:], 1)
	binary.LittleEndian.PutUint32(data[start+20:], math.MaxUint32)
	binary.LittleEndian.PutUint32(data[start+24:], math.MaxUint32)
	binary.LittleEndian.PutUint16(data[start+30:], uint16(len(extra)))
	footer := append([]byte(nil), data[end:]...)
	binary.LittleEndian.PutUint32(footer[12:], uint32(end-start+len(extra)))
	data = append(data[:end], extra[:]...)
	data = append(data, footer...)
	reader, err := OpenZIPReader(bytes.NewReader(data), int64(len(data)), ZIPReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	entry := reader.File[0]
	if !bytes.Equal(entry.Extra, extra[:]) || entry.CompressedSize64 != 1 || entry.UncompressedSize64 != 1 {
		t.Fatalf("ZIP64 metadata changed: %+v", entry.FileHeader)
	}
	body, err := entry.Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(body)
	body.Close()
	if err != nil || !bytes.Equal(got, []byte{0}) {
		t.Fatalf("body=%x err=%v", got, err)
	}
	data[30+7] = 1
	body, err = entry.Open()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(body)
	body.Close()
	if !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("Extra detachment bypassed CRC: %v", err)
	}
}
