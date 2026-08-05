package pcv3artifact

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

type literalArtifactExpectation struct {
	name     string
	metadata Metadata
	entry    Entry
	segment  []byte
}

func TestParseIndependentLiteralArtifactsPreservesExactEvidence(t *testing.T) {
	tests := []literalArtifactExpectation{
		{
			name: "partial",
			metadata: Metadata{
				State: StatePartial, Role: RoleNone, Final: FinalMissing,
				HeaderLength: 80, RangeEntryLength: 40,
				PlaintextLength: 5, RangeCount: 1, EmittedSegmentCount: 1,
				TableOffset: 80, DataOffset: 120, TotalLength: 125,
			},
			entry: Entry{
				RecordIndex: 0, Start: 0, End: 5,
				SegmentOffset: 120, SegmentLength: 5, Status: RangeVerified,
			},
			segment: []byte{'V', 'F', 'Y', '!', '\n'},
		},
		{
			name: "unverified",
			metadata: Metadata{
				State: StateUnverifiedForensic, Role: RoleBackup, Final: FinalMissing,
				HeaderLength: 80, RangeEntryLength: 40,
				PlaintextLength: 6, RangeCount: 1, EmittedSegmentCount: 1,
				TableOffset: 80, DataOffset: 120, TotalLength: 126,
			},
			entry: Entry{
				RecordIndex: 0, Start: 0, End: 6,
				SegmentOffset: 120, SegmentLength: 6, Status: RangeUnverified,
			},
			segment: []byte{'R', 'A', 'W', '?', 0, '!'},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			literal := readLiteralArtifact(t, test.name)
			artifact, err := Parse(bytes.NewReader(literal), int64(len(literal)))
			if err != nil {
				t.Fatalf("parse independent literal: %v", err)
			}
			if got := artifact.Metadata(); got != test.metadata {
				t.Fatalf("metadata = %#v; want %#v", got, test.metadata)
			}

			visits := 0
			err = artifact.VisitRanges(func(entry Entry, segment io.Reader) error {
				visits++
				if entry != test.entry {
					return fmt.Errorf("entry = %#v; want %#v", entry, test.entry)
				}
				got, readErr := io.ReadAll(segment)
				if readErr != nil {
					return readErr
				}
				if !bytes.Equal(got, test.segment) {
					return fmt.Errorf("segment = %x; want %x", got, test.segment)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("visit independent literal: %v", err)
			}
			if visits != 1 {
				t.Fatalf("range visits = %d; want 1", visits)
			}
		})
	}
}

func TestEncodeMatchesIndependentLiteralArtifacts(t *testing.T) {
	tests := []struct {
		name       string
		descriptor Descriptor
		segment    []byte
	}{
		{
			name: "partial",
			descriptor: Descriptor{
				State: StatePartial, Role: RoleNone, Final: FinalMissing,
				PlaintextLength: 5,
				Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeVerified}},
			},
			segment: []byte{'V', 'F', 'Y', '!', '\n'},
		},
		{
			name: "unverified",
			descriptor: Descriptor{
				State: StateUnverifiedForensic, Role: RoleBackup, Final: FinalMissing,
				PlaintextLength: 6,
				Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 6, Status: RangeUnverified}},
			},
			segment: []byte{'R', 'A', 'W', '?', 0, '!'},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := Encode(&output, test.descriptor, func(yield func(uint64, io.Reader) error) error {
				return yield(0, bytes.NewReader(test.segment))
			})
			if err != nil {
				t.Fatalf("encode artifact: %v", err)
			}
			want := readLiteralArtifact(t, test.name)
			if !bytes.Equal(output.Bytes(), want) {
				t.Fatalf("encoded bytes = %x; want independent literal %x", output.Bytes(), want)
			}
		})
	}
}

func TestEncodeRejectsNonCanonicalMapBeforeWriting(t *testing.T) {
	valid := Descriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: 5,
		Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeVerified}},
	}
	tests := []struct {
		name   string
		mutate func(*Descriptor)
	}{
		{name: "unknown state", mutate: func(value *Descriptor) { value.State = State(255) }},
		{name: "partial without damage", mutate: func(value *Descriptor) { value.Final = FinalVerified }},
		{name: "partial role without unverified bytes", mutate: func(value *Descriptor) { value.Role = RolePrimary }},
		{name: "unverified without selected role", mutate: func(value *Descriptor) {
			value.State = StateUnverifiedForensic
			value.Role = RoleNone
			value.Ranges[0].Status = RangeUnverified
		}},
		{name: "unverified carrying verified range", mutate: func(value *Descriptor) {
			value.State = StateUnverifiedForensic
			value.Role = RolePrimary
		}},
		{name: "wrong record index", mutate: func(value *Descriptor) { value.Ranges[0].RecordIndex = 1 }},
		{name: "gap at start", mutate: func(value *Descriptor) { value.Ranges[0].Start = 1 }},
		{name: "wrong end", mutate: func(value *Descriptor) { value.Ranges[0].End = 4 }},
		{name: "unknown range status", mutate: func(value *Descriptor) { value.Ranges[0].Status = RangeStatus(255) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := valid
			descriptor.Ranges = append([]Range(nil), valid.Ranges...)
			test.mutate(&descriptor)
			var output bytes.Buffer
			err := Encode(&output, descriptor, nil)
			if err == nil {
				t.Fatal("noncanonical descriptor unexpectedly encoded")
			}
			if output.Len() != 0 {
				t.Fatalf("descriptor rejection wrote %d bytes; want zero", output.Len())
			}
		})
	}
}

func TestEncodeRejectsIncompleteOrMisorderedSegmentStream(t *testing.T) {
	descriptor := Descriptor{
		State: StateUnverifiedForensic, Role: RolePrimary, Final: FinalMissing,
		PlaintextLength: 5,
		Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeUnverified}},
	}
	tests := []struct {
		name   string
		source SegmentSource
	}{
		{name: "missing callback", source: func(func(uint64, io.Reader) error) error { return nil }},
		{name: "short segment", source: func(yield func(uint64, io.Reader) error) error {
			return yield(0, strings.NewReader("four"))
		}},
		{name: "extra segment byte", source: func(yield func(uint64, io.Reader) error) error {
			return yield(0, strings.NewReader("six!!!"))
		}},
		{name: "wrong record first", source: func(yield func(uint64, io.Reader) error) error {
			return yield(1, strings.NewReader("12345"))
		}},
		{name: "duplicate record", source: func(yield func(uint64, io.Reader) error) error {
			if err := yield(0, strings.NewReader("12345")); err != nil {
				return err
			}
			return yield(0, strings.NewReader("12345"))
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := Encode(&output, descriptor, test.source); err == nil {
				t.Fatal("invalid segment stream unexpectedly completed")
			}
		})
	}
}

func TestMissingRangeHasNoSegmentAndDoesNotEraseRecordAttribution(t *testing.T) {
	descriptor := Descriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: (1 << 20) + 3,
		Ranges: []Range{
			{RecordIndex: 0, Start: 0, End: 1 << 20, Status: RangeMissing},
			{RecordIndex: 1, Start: 1 << 20, End: (1 << 20) + 3, Status: RangeVerified},
		},
	}
	var output bytes.Buffer
	if err := Encode(&output, descriptor, func(yield func(uint64, io.Reader) error) error {
		return yield(1, strings.NewReader("yes"))
	}); err != nil {
		t.Fatalf("encode map with leading missing range: %v", err)
	}
	artifact, err := Parse(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatalf("parse map with leading missing range: %v", err)
	}
	metadata := artifact.Metadata()
	if metadata.RangeCount != 2 || metadata.EmittedSegmentCount != 1 ||
		metadata.DataOffset != 160 || metadata.TotalLength != 163 {
		t.Fatalf("mixed-map metadata = %#v; want two ranges and one three-byte segment", metadata)
	}

	visits := 0
	err = artifact.VisitRanges(func(entry Entry, segment io.Reader) error {
		defer func() { visits++ }()
		switch visits {
		case 0:
			if entry.RecordIndex != 0 || entry.Start != 0 || entry.End != 1<<20 ||
				entry.Status != RangeMissing || entry.SegmentOffset != 0 ||
				entry.SegmentLength != 0 || segment != nil {
				return fmt.Errorf("missing entry exposed data or lost attribution: %#v", entry)
			}
		case 1:
			contents, readErr := io.ReadAll(segment)
			if readErr != nil {
				return readErr
			}
			if string(contents) != "yes" || entry.RecordIndex != 1 ||
				entry.Status != RangeVerified || entry.SegmentOffset != 160 || entry.SegmentLength != 3 {
				return fmt.Errorf("verified entry = %#v, %q", entry, contents)
			}
		default:
			return errors.New("unexpected range visit")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("visit mixed evidence map: %v", err)
	}
	if visits != 2 {
		t.Fatalf("mixed-map visits = %d; want 2", visits)
	}
}

func TestEncodeFreezesRangeMapBeforeCallingExternalCode(t *testing.T) {
	ranges := []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeVerified}}
	descriptor := Descriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: 5,
		Ranges:          ranges,
	}
	var output bytes.Buffer
	err := Encode(&output, descriptor, func(yield func(uint64, io.Reader) error) error {
		ranges[0].End = 4
		return yield(0, strings.NewReader("fixed"))
	})
	if err != nil {
		t.Fatalf("caller mutation changed validated evidence map: %v", err)
	}
	want := readLiteralArtifact(t, "partial")
	copy(want[len(want)-5:], []byte("fixed"))
	if !bytes.Equal(output.Bytes(), want) {
		t.Fatalf("encoded bytes changed after caller mutation: %x; want %x", output.Bytes(), want)
	}
}

func TestParseRejectsMalformedLayoutsBeforeAttackerSizedReads(t *testing.T) {
	valid := readLiteralArtifact(t, "partial")
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "unknown major", mutate: setByte(16, 2)},
		{name: "unknown schema", mutate: setByte(17, 2)},
		{name: "unknown critical flag", mutate: setByte(21, 1)},
		{name: "nonzero header reserved", mutate: setByte(22, 1)},
		{name: "wrong header length", mutate: setByte(27, 79)},
		{name: "wrong range length", mutate: setByte(31, 39)},
		{name: "range count exceeds physical table", mutate: func(input []byte) []byte {
			input[40] = 0xff
			return input
		}},
		{name: "segment count mismatch", mutate: setByte(55, 2)},
		{name: "wrong table offset", mutate: setByte(63, 79)},
		{name: "wrong data offset", mutate: setByte(71, 121)},
		{name: "wrong total length", mutate: setByte(79, 124)},
		{name: "range gap", mutate: setByte(95, 1)},
		{name: "segment aliases table", mutate: setByte(111, 80)},
		{name: "nonzero range reserved", mutate: setByte(117, 1)},
		{name: "missing range carries data", mutate: setByte(116, 3)},
		{name: "trailing byte", mutate: func(input []byte) []byte { return append(input, 0) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := test.mutate(append([]byte(nil), valid...))
			reader := &observedReaderAt{reader: bytes.NewReader(mutated)}
			artifact, err := Parse(reader, int64(len(mutated)))
			if err == nil || artifact != nil {
				t.Fatal("malformed artifact unexpectedly exposed a parsed result")
			}
			if reader.maximumRequest > 80 {
				t.Fatalf("malformed parse requested %d bytes; want at most fixed header", reader.maximumRequest)
			}
		})
	}
}

func TestZeroLengthFinalOnlyEvidenceHasCanonicalForm(t *testing.T) {
	literal := mustDecodeHex(t, ""+
		"5049434f2d5245434f564552592d3300"+
		"0101020102000000"+
		"00000050"+
		"00000028"+
		"0000000000000000"+
		"0000000000000000"+
		"0000000000000000"+
		"0000000000000050"+
		"0000000000000050"+
		"0000000000000050")
	artifact, err := Parse(bytes.NewReader(literal), int64(len(literal)))
	if err != nil {
		t.Fatalf("parse zero-length final-only evidence: %v", err)
	}
	metadata := artifact.Metadata()
	if metadata.State != StateUnverifiedForensic || metadata.Role != RolePrimary ||
		metadata.Final != FinalUnverified || metadata.RangeCount != 0 ||
		metadata.EmittedSegmentCount != 0 || metadata.DataOffset != 80 || metadata.TotalLength != 80 {
		t.Fatalf("zero-length metadata = %#v; want unverified primary final-only evidence", metadata)
	}
	visits := 0
	if err := artifact.VisitRanges(func(Entry, io.Reader) error { visits++; return nil }); err != nil {
		t.Fatalf("visit zero-length evidence: %v", err)
	}
	if visits != 0 {
		t.Fatalf("zero-length range visits = %d; want zero", visits)
	}

	for _, offset := range []int{18, 20} {
		mutated := append([]byte(nil), literal...)
		mutated[offset] = 3
		if parsed, parseErr := Parse(bytes.NewReader(mutated), int64(len(mutated))); parseErr == nil || parsed != nil {
			t.Fatalf("noncanonical zero-length mutation at byte %d parsed", offset)
		}
	}
}

func TestCodecErrorsDoNotFormatRawSourceOrWriterDetails(t *testing.T) {
	canary := "private/path/keyfile-canary"
	literal := readLiteralArtifact(t, "partial")
	reader := &failingReaderAt{cause: errors.New(canary)}
	_, readErr := Parse(reader, int64(len(literal)))

	descriptor := Descriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: 5,
		Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeVerified}},
	}
	writeErr := Encode(failingWriter{cause: errors.New(canary)}, descriptor, nil)
	streamErr := Encode(io.Discard, descriptor, func(func(uint64, io.Reader) error) error {
		return errors.New(canary)
	})
	for _, err := range []error{readErr, writeErr, streamErr} {
		if err == nil {
			t.Fatal("fault injection unexpectedly succeeded")
		}
		for _, rendered := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
			if strings.Contains(rendered, canary) {
				t.Fatalf("codec error disclosed raw detail in %q", rendered)
			}
		}
	}
}

type observedReaderAt struct {
	reader         io.ReaderAt
	maximumRequest int
}

func (reader *observedReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	if len(destination) > reader.maximumRequest {
		reader.maximumRequest = len(destination)
	}
	return reader.reader.ReadAt(destination, offset)
}

type failingReaderAt struct{ cause error }

func (reader *failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, reader.cause }

type failingWriter struct{ cause error }

func (writer failingWriter) Write([]byte) (int, error) { return 0, writer.cause }

func setByte(offset int, value byte) func([]byte) []byte {
	return func(input []byte) []byte {
		input[offset] = value
		return input
	}
}

func readLiteralArtifact(t *testing.T, name string) []byte {
	t.Helper()
	encoded, err := os.ReadFile("testdata/" + name + ".hex")
	if err != nil {
		t.Fatalf("read independent literal %q: %v", name, err)
	}
	return mustDecodeHex(t, strings.Join(strings.Fields(string(encoded)), ""))
}

func mustDecodeHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode independent literal: %v", err)
	}
	return decoded
}
