package pcv3artifact

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"bytes"
	"context"
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

type scratchReaderMode uint8

const (
	scratchSuccess scratchReaderMode = iota + 1
	scratchShort
	scratchSourceError
	scratchPanic
	scratchOverlongProbe
	scratchProbePanic
)

var errScratchSource = errors.New("TEST ONLY segment source fault")

const scratchProbeCanary byte = 0xa7

type retainingScratchReader struct {
	input      []byte
	mode       scratchReaderMode
	reads      int
	aliases    [][]byte
	panicValue any
}

func (reader *retainingScratchReader) Read(destination []byte) (int, error) {
	reader.reads++
	reader.aliases = append(reader.aliases, destination[:cap(destination)])
	switch reader.mode {
	case scratchSuccess:
		if reader.reads == 1 {
			copy(destination, reader.input)
			return len(reader.input), nil
		}
		return 0, io.EOF
	case scratchShort:
		if reader.reads == 1 {
			copy(destination, reader.input[:len(reader.input)-1])
			return len(reader.input) - 1, nil
		}
		return 0, io.EOF
	case scratchSourceError:
		copy(destination, reader.input[:2])
		return 2, errScratchSource
	case scratchPanic:
		copy(destination, reader.input)
		panic(reader.panicValue)
	case scratchOverlongProbe, scratchProbePanic:
		if reader.reads == 1 {
			copy(destination, reader.input)
			return len(reader.input), nil
		}
		destination[0] = scratchProbeCanary
		if reader.mode == scratchProbePanic {
			panic(reader.panicValue)
		}
		return 1, nil
	default:
		return 0, io.ErrNoProgress
	}
}

type segmentFailWriter struct {
	written int
}

func (writer *segmentFailWriter) Write(data []byte) (int, error) {
	if writer.written >= 120 {
		return 0, errors.New("TEST ONLY segment writer fault")
	}
	writer.written += len(data)
	return len(data), nil
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
			artifact, err := Parse(context.Background(), bytes.NewReader(literal), int64(len(literal)))
			if err != nil {
				t.Fatalf("parse independent literal: %v", err)
			}
			if got := artifact.Metadata(); got != test.metadata {
				t.Fatalf("metadata = %#v; want %#v", got, test.metadata)
			}

			visits := 0
			err = artifact.VisitRanges(context.Background(), func(entry Entry, segment io.Reader) error {
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
		descriptor fixtureDescriptor
		segment    []byte
	}{
		{
			name: "partial",
			descriptor: fixtureDescriptor{
				State: StatePartial, Role: RoleNone, Final: FinalMissing,
				PlaintextLength: 5,
				Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeVerified}},
			},
			segment: []byte{'V', 'F', 'Y', '!', '\n'},
		},
		{
			name: "unverified",
			descriptor: fixtureDescriptor{
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
			err := encodeFixture(&output, test.descriptor, func(yield func(uint64, io.Reader) error) error {
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

func TestD1ArtifactPhysicalRoles(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		wireRole byte
	}{
		{name: "front", role: RoleD1Front, wireRole: 3},
		{name: "tail", role: RoleD1Tail, wireRole: 4},
	}
	segment := []byte("raw outer evidence")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := fixtureDescriptor{
				State:           StateUnverifiedForensic,
				Role:            test.role,
				Final:           FinalUnverified,
				PlaintextLength: uint64(len(segment)),
				Ranges: []Range{{
					RecordIndex: 0,
					Start:       0,
					End:         uint64(len(segment)),
					Status:      RangeUnverified,
				}},
			}

			var encoded bytes.Buffer
			err := encodeFixture(&encoded, descriptor, func(yield func(uint64, io.Reader) error) error {
				return yield(0, bytes.NewReader(segment))
			})
			if err != nil {
				t.Fatalf("encode D1 recovery artifact: %v", err)
			}
			contents := encoded.Bytes()
			if got := contents[19]; got != test.wireRole {
				t.Fatalf("physical role byte = %d; want frozen D1 %s value %d", got, test.name, test.wireRole)
			}

			artifact, err := Parse(context.Background(), bytes.NewReader(contents), int64(len(contents)))
			if err != nil {
				t.Fatalf("parse D1 recovery artifact: %v", err)
			}
			if got := artifact.Metadata().Role; got != test.role {
				t.Fatalf("parsed physical role = %v; want %v", got, test.role)
			}
			visits := 0
			err = artifact.VisitRanges(context.Background(), func(entry Entry, reader io.Reader) error {
				visits++
				if entry.RecordIndex != 0 || entry.Status != RangeUnverified {
					return fmt.Errorf("entry = %#v; want one unverified range", entry)
				}
				got, readErr := io.ReadAll(reader)
				if readErr != nil {
					return readErr
				}
				if !bytes.Equal(got, segment) {
					return fmt.Errorf("segment = %x; want %x", got, segment)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("visit D1 recovery artifact: %v", err)
			}
			if visits != 1 {
				t.Fatalf("range visits = %d; want 1", visits)
			}
		})
	}

	unknown := fixtureDescriptor{
		State:           StateUnverifiedForensic,
		Role:            Role(5),
		Final:           FinalUnverified,
		PlaintextLength: 1,
		Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 1, Status: RangeUnverified}},
	}
	var output bytes.Buffer
	if err := encodeFixture(&output, unknown, nil); err == nil || output.Len() != 0 {
		t.Fatalf("unknown physical role = error %v, bytes %d; want pre-write rejection", err, output.Len())
	}
}

func TestEncodeZeroesPlaintextScratchOnEveryExit(t *testing.T) {
	segmentPanic := &struct{ label string }{label: "TEST ONLY segment panic"}
	probePanic := &struct{ label string }{label: "TEST ONLY probe panic"}
	tests := []struct {
		name      string
		mode      scratchReaderMode
		writer    func() io.Writer
		wantError bool
		wantPanic any
	}{
		{name: "success", mode: scratchSuccess, writer: func() io.Writer { return new(bytes.Buffer) }},
		{name: "short segment", mode: scratchShort, writer: func() io.Writer { return io.Discard }, wantError: true},
		{name: "source error", mode: scratchSourceError, writer: func() io.Writer { return io.Discard }, wantError: true},
		{name: "writer error", mode: scratchSuccess, writer: func() io.Writer { return new(segmentFailWriter) }, wantError: true},
		{name: "segment panic", mode: scratchPanic, writer: func() io.Writer { return io.Discard }, wantPanic: segmentPanic},
		{name: "overlong probe", mode: scratchOverlongProbe, writer: func() io.Writer { return io.Discard }, wantError: true},
		{name: "probe panic", mode: scratchProbePanic, writer: func() io.Writer { return io.Discard }, wantPanic: probePanic},
	}
	descriptor := fixtureDescriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: 5,
		Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeVerified}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := []byte{'V', 'F', 'Y', '!', '\n'}
			frozenInput := append([]byte(nil), input...)
			reader := &retainingScratchReader{input: input, mode: test.mode, panicValue: test.wantPanic}
			destination := test.writer()
			var encodeErr error
			var panicResult any
			func() {
				defer func() { panicResult = recover() }()
				encodeErr = encodeFixture(destination, descriptor, func(yield func(uint64, io.Reader) error) error {
					return yield(0, reader)
				})
			}()
			if panicResult != test.wantPanic {
				t.Fatalf("Encode panic = %v; want original identity %v", panicResult, test.wantPanic)
			}
			if (encodeErr != nil) != test.wantError {
				t.Fatalf("Encode error = %v; want error %v", encodeErr, test.wantError)
			}
			if len(reader.aliases) == 0 || cap(reader.aliases[0]) != segmentBufferLength {
				t.Fatalf("retained production scratch = %d aliases, first capacity %d; want actual %d-byte buffer", len(reader.aliases), cap(reader.aliases[0]), segmentBufferLength)
			}
			for aliasIndex, alias := range reader.aliases {
				for byteIndex, value := range alias {
					if value != 0 {
						t.Fatalf("production scratch alias %d byte %d = %x; want zero after unwind", aliasIndex, byteIndex, value)
					}
				}
			}
			if !bytes.Equal(input, frozenInput) {
				t.Fatal("artifact cleanup zeroed caller-owned segment input")
			}
			if test.name == "success" {
				output := destination.(*bytes.Buffer).Bytes()
				if !bytes.Equal(output, readLiteralArtifact(t, "partial")) {
					t.Fatal("successful zeroing case changed independent artifact bytes")
				}
			}
			if test.name == "success" || test.mode == scratchOverlongProbe || test.mode == scratchProbePanic {
				if len(reader.aliases) != 2 || cap(reader.aliases[1]) != 1 {
					t.Fatalf("extra-byte scratch = %d aliases, final capacity %d; want retained one-byte production probe", len(reader.aliases), cap(reader.aliases[len(reader.aliases)-1]))
				}
			}
		})
	}
}

func TestEncodeRejectsNonCanonicalMapBeforeWriting(t *testing.T) {
	valid := fixtureDescriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: 5,
		Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeVerified}},
	}
	tests := []struct {
		name   string
		mutate func(*fixtureDescriptor)
	}{
		{name: "unknown state", mutate: func(value *fixtureDescriptor) { value.State = State(255) }},
		{name: "partial without damage", mutate: func(value *fixtureDescriptor) { value.Final = FinalVerified }},
		{name: "partial role without unverified bytes", mutate: func(value *fixtureDescriptor) { value.Role = RolePrimary }},
		{name: "unverified without selected role", mutate: func(value *fixtureDescriptor) {
			value.State = StateUnverifiedForensic
			value.Role = RoleNone
			value.Ranges[0].Status = RangeUnverified
		}},
		{name: "unverified carrying verified range", mutate: func(value *fixtureDescriptor) {
			value.State = StateUnverifiedForensic
			value.Role = RolePrimary
		}},
		{name: "wrong record index", mutate: func(value *fixtureDescriptor) { value.Ranges[0].RecordIndex = 1 }},
		{name: "gap at start", mutate: func(value *fixtureDescriptor) { value.Ranges[0].Start = 1 }},
		{name: "wrong end", mutate: func(value *fixtureDescriptor) { value.Ranges[0].End = 4 }},
		{name: "unknown range status", mutate: func(value *fixtureDescriptor) { value.Ranges[0].Status = RangeStatus(255) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := valid
			descriptor.Ranges = append([]Range(nil), valid.Ranges...)
			test.mutate(&descriptor)
			var output bytes.Buffer
			err := encodeFixture(&output, descriptor, nil)
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
	descriptor := fixtureDescriptor{
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
			if err := encodeFixture(&output, descriptor, test.source); err == nil {
				t.Fatal("invalid segment stream unexpectedly completed")
			}
		})
	}
}

func TestMissingRangeHasNoSegmentAndDoesNotEraseRecordAttribution(t *testing.T) {
	descriptor := fixtureDescriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: (1 << 20) + 3,
		Ranges: []Range{
			{RecordIndex: 0, Start: 0, End: 1 << 20, Status: RangeMissing},
			{RecordIndex: 1, Start: 1 << 20, End: (1 << 20) + 3, Status: RangeVerified},
		},
	}
	var output bytes.Buffer
	if err := encodeFixture(&output, descriptor, func(yield func(uint64, io.Reader) error) error {
		return yield(1, strings.NewReader("yes"))
	}); err != nil {
		t.Fatalf("encode map with leading missing range: %v", err)
	}
	artifact, err := Parse(context.Background(), bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatalf("parse map with leading missing range: %v", err)
	}
	metadata := artifact.Metadata()
	if metadata.RangeCount != 2 || metadata.EmittedSegmentCount != 1 ||
		metadata.DataOffset != 160 || metadata.TotalLength != 163 {
		t.Fatalf("mixed-map metadata = %#v; want two ranges and one three-byte segment", metadata)
	}

	visits := 0
	err = artifact.VisitRanges(context.Background(), func(entry Entry, segment io.Reader) error {
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
	descriptor := fixtureDescriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: 5,
		Ranges:          ranges,
	}
	var output bytes.Buffer
	err := encodeFixture(&output, descriptor, func(yield func(uint64, io.Reader) error) error {
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
			artifact, err := Parse(context.Background(), reader, int64(len(mutated)))
			if err == nil || artifact != nil {
				t.Fatal("malformed artifact unexpectedly exposed a parsed result")
			}
			if reader.maximumRequest > 80 {
				t.Fatalf("malformed parse requested %d bytes; want at most fixed header", reader.maximumRequest)
			}
		})
	}
}

func TestParseRetriesBoundedFixedFieldReadsAtHeaderAndRangeEntry(t *testing.T) {
	literal := readLiteralArtifact(t, "partial")
	targets := []struct {
		name   string
		start  int64
		length int
	}{
		{name: "header", start: 0, length: int(headerLength)},
		{name: "range entry", start: int64(headerLength), length: int(rangeEntryLength)},
	}

	for _, target := range targets {
		t.Run(target.name+" positive short nil", func(t *testing.T) {
			reader := &fixedFieldReaderAt{
				data:        literal,
				targetStart: target.start,
				targetEnd:   target.start + int64(target.length),
				chunk:       7,
			}
			artifact, err := Parse(context.Background(), reader, int64(len(literal)))
			if err != nil {
				t.Fatalf("parse valid artifact through short-nil %s reads: %v", target.name, err)
			}
			metadata := artifact.Metadata()
			if metadata.State != StatePartial || metadata.RangeCount != 1 || metadata.TotalLength != uint64(len(literal)) {
				t.Fatalf("short-nil %s metadata = %#v; want independent partial literal", target.name, metadata)
			}
			wantCalls := (target.length + reader.chunk - 1) / reader.chunk
			if reader.targetCalls != wantCalls {
				t.Fatalf("short-nil %s calls = %d; want exact bounded progress count %d", target.name, reader.targetCalls, wantCalls)
			}
			if reader.targetMaximumRequest > target.length || reader.maximumRequest > int(headerLength) {
				t.Fatalf("short-nil %s requested target/global bytes %d/%d; want at most %d/%d", target.name, reader.targetMaximumRequest, reader.maximumRequest, target.length, headerLength)
			}
		})

		t.Run(target.name+" repeated zero progress", func(t *testing.T) {
			reader := &fixedFieldReaderAt{
				data:        literal,
				targetStart: target.start,
				targetEnd:   target.start + int64(target.length),
				stall:       true,
			}
			artifact, err := Parse(context.Background(), reader, int64(len(literal)))
			if artifact != nil || !errors.Is(err, io.ErrNoProgress) {
				t.Fatalf("repeated zero-progress %s parse = (%#v, %v); want bounded no-progress failure", target.name, artifact, err)
			}
			if reader.targetCalls != 2 {
				t.Fatalf("repeated zero-progress %s calls = %d; want rejection after 2", target.name, reader.targetCalls)
			}
			if reader.targetMaximumRequest > target.length || reader.maximumRequest > int(headerLength) {
				t.Fatalf("zero-progress %s requested target/global bytes %d/%d; want at most %d/%d", target.name, reader.targetMaximumRequest, reader.maximumRequest, target.length, headerLength)
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
	artifact, err := Parse(context.Background(), bytes.NewReader(literal), int64(len(literal)))
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
	if err := artifact.VisitRanges(context.Background(), func(Entry, io.Reader) error { visits++; return nil }); err != nil {
		t.Fatalf("visit zero-length evidence: %v", err)
	}
	if visits != 0 {
		t.Fatalf("zero-length range visits = %d; want zero", visits)
	}

	for _, offset := range []int{18, 20} {
		mutated := append([]byte(nil), literal...)
		mutated[offset] = 3
		if parsed, parseErr := Parse(context.Background(), bytes.NewReader(mutated), int64(len(mutated))); parseErr == nil || parsed != nil {
			t.Fatalf("noncanonical zero-length mutation at byte %d parsed", offset)
		}
	}
}

func TestCodecErrorsDoNotFormatRawSourceOrWriterDetails(t *testing.T) {
	canary := "private/path/keyfile-canary"
	literal := readLiteralArtifact(t, "partial")
	reader := &failingReaderAt{cause: errors.New(canary)}
	_, readErr := Parse(context.Background(), reader, int64(len(literal)))

	descriptor := fixtureDescriptor{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		PlaintextLength: 5,
		Ranges:          []Range{{RecordIndex: 0, Start: 0, End: 5, Status: RangeVerified}},
	}
	writeErr := encodeFixture(failingWriter{cause: errors.New(canary)}, descriptor, nil)
	streamErr := encodeFixture(io.Discard, descriptor, func(func(uint64, io.Reader) error) error {
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

type fixedFieldReaderAt struct {
	data                 []byte
	targetStart          int64
	targetEnd            int64
	chunk                int
	stall                bool
	targetCalls          int
	targetMaximumRequest int
	maximumRequest       int
}

func (reader *fixedFieldReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	if len(destination) > reader.maximumRequest {
		reader.maximumRequest = len(destination)
	}
	targeted := offset >= reader.targetStart && offset < reader.targetEnd
	if targeted {
		reader.targetCalls++
		if len(destination) > reader.targetMaximumRequest {
			reader.targetMaximumRequest = len(destination)
		}
		if reader.stall {
			return 0, nil
		}
	}
	if offset < 0 || offset >= int64(len(reader.data)) {
		return 0, io.EOF
	}
	readLength := len(destination)
	if targeted && reader.chunk < readLength {
		readLength = reader.chunk
	}
	remaining := len(reader.data) - int(offset)
	if remaining < readLength {
		readLength = remaining
	}
	read := copy(destination[:readLength], reader.data[int(offset):])
	if targeted && read < len(destination) {
		return read, nil
	}
	if read < len(destination) {
		return read, io.EOF
	}
	return read, nil
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

// fixtureDescriptor retains malformed legacy fixture inputs solely in tests;
// production accepts only the sealed map and cannot represent these mutations.
type fixtureDescriptor struct {
	State           State
	Role            Role
	Final           FinalStatus
	PlaintextLength uint64
	Ranges          []Range
}

func encodeFixture(dst io.Writer, d fixtureDescriptor, source SegmentSource) error {
	b, err := pcv3ranges.NewBuilder(d.PlaintextLength, nil)
	if err != nil {
		return err
	}
	defer b.Close()
	if uint64(len(d.Ranges)) != canonicalRangeCount(d.PlaintextLength) {
		return newArtifactError(errorInvalidDescriptor, nil)
	}
	for i, r := range d.Ranges {
		start, end, ok := canonicalBounds(uint64(i), d.PlaintextLength)
		if !ok || r.RecordIndex != uint64(i) || r.Start != start || r.End != end {
			return newArtifactError(errorInvalidDescriptor, nil)
		}
		if err = b.Append(pcv3ranges.State(r.Status)); err != nil {
			return err
		}
	}
	m, err := b.Seal()
	if err != nil {
		return err
	}
	plan, err := Prepare(Descriptor{State: d.State, Role: d.Role, Final: d.Final, PlaintextLength: d.PlaintextLength, Ranges: m})
	if err != nil {
		return err
	}
	return Encode(context.Background(), dst, plan, source)
}
