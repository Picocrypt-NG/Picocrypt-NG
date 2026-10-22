package pcv3artifact

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestArtifactPreservesPhysicalOffsetsAboveFourGiB(t *testing.T) {
	prefix := largeArtifactTable(t)
	// Only the header/table and final three bytes exist. This tests metadata
	// validation and section offsets, not traversal of a four-GiB payload.
	source := artifactMetadataSource{prefix: prefix, finalSegment: []byte("END")}
	artifact, err := Parse(context.Background(), source, 4295131259)
	if err != nil {
		t.Fatal(err)
	}
	if got := artifact.Metadata().TotalLength; got != 4295131259 {
		t.Fatalf("physical total length = %d, want 4295131259", got)
	}
	visitedLast := false
	err = artifact.VisitRanges(context.Background(), func(entry Entry, segment io.Reader) error {
		if entry.RecordIndex != 4096 {
			return nil
		}
		visitedLast = true
		want := Entry{
			RecordIndex: 4096, Start: 4294967296, End: 4294967299,
			SegmentOffset: 4295131256, SegmentLength: 3, Status: RangeVerified,
		}
		if entry != want {
			t.Fatalf("last range = %#v, want %#v", entry, want)
		}
		got, readErr := io.ReadAll(segment)
		if readErr != nil || !bytes.Equal(got, []byte("END")) {
			t.Fatalf("last segment at physical offset 4295131256 = %q, %v", got, readErr)
		}
		return nil
	})
	if err != nil || !visitedLast {
		t.Fatalf("visit last large-offset segment: visited=%v error=%v", visitedLast, err)
	}
}

func TestArtifactRejectsOverflowAndTruncatedLargePhysicalLayout(t *testing.T) {
	prefix := largeArtifactTable(t)
	for _, test := range []struct {
		name  string
		field int
		value uint64
		size  int64
	}{
		{"physical EOF before declared total", -1, 0, 4295131258},
		{"last segment extends past declared EOF", 72, 4295131258, 4295131258},
		{"last segment end overflows uint64", 163944, 0xfffffffffffffffe, 4295131259},
		{"last segment aliases a low 32-bit offset", 163944, 163960, 4295131259},
		{"total length exceeds signed physical offsets", 72, 0x8000000000000000, 9223372036854775807},
	} {
		t.Run(test.name, func(t *testing.T) {
			malformed := bytes.Clone(prefix)
			if test.field >= 0 {
				binary.BigEndian.PutUint64(malformed[test.field:test.field+8], test.value)
			}
			artifact, err := Parse(context.Background(), artifactMetadataSource{prefix: malformed}, test.size)
			if err == nil || artifact != nil {
				t.Fatalf("invalid physical layout exposed an artifact: artifact=%v error=%v", artifact, err)
			}
		})
	}
}

func largeArtifactTable(t *testing.T) []byte {
	t.Helper()
	builder, err := pcv3ranges.NewBuilder(4294967299, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()
	for range 4097 {
		if err := builder.Append(pcv3ranges.Verified); err != nil {
			t.Fatal(err)
		}
	}
	ranges, err := builder.Seal()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Prepare(Descriptor{
		State: StatePartial, Final: FinalMissing, PlaintextLength: 4294967299, Ranges: ranges,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Metadata{
		State: StatePartial, Role: RoleNone, Final: FinalMissing,
		HeaderLength: 80, RangeEntryLength: 40, PlaintextLength: 4294967299,
		RangeCount: 4097, EmittedSegmentCount: 4097,
		TableOffset: 80, DataOffset: 163960, TotalLength: 4295131259,
	}
	if got := plan.Metadata(); got != want {
		t.Fatalf("large physical plan = %#v, want %#v", got, want)
	}
	var output bytes.Buffer
	stop := errors.New("TEST ONLY stop after artifact table")
	err = Encode(context.Background(), &output, plan, func(func(uint64, io.Reader) error) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("metadata-only encoding error = %v, want deliberate payload stop", err)
	}
	prefix := output.Bytes()
	if len(prefix) != 163960 {
		t.Fatalf("encoded metadata extent = %d, want 163960", len(prefix))
	}
	// Frozen 80-byte header and final 40-byte entry, assembled from the wire
	// schema independently of Prepare, encodeHeader, and encodeEntry.
	for _, literal := range []struct {
		start, end int
		hex        string
	}{
		{0, 80, "5049434f2d5245434f564552592d33000101010003000000000000500000002800000001000000030000000000001001000000000000100100000000000000500000000000028078000000010002807b"},
		{163920, 163960, "00000000000010000000000100000000000000010000000300000001000280780000000301000000"},
	} {
		want, err := hex.DecodeString(literal.hex)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(prefix[literal.start:literal.end], want) {
			t.Fatalf("encoded bytes [%d:%d] = %x, want %x", literal.start, literal.end, prefix[literal.start:literal.end], want)
		}
	}
	return prefix
}

type artifactMetadataSource struct {
	prefix       []byte
	finalSegment []byte
}

func (source artifactMetadataSource) ReadAt(destination []byte, offset int64) (int, error) {
	if offset >= 0 && offset < int64(len(source.prefix)) {
		return bytes.NewReader(source.prefix).ReadAt(destination, offset)
	}
	if offset >= 4295131256 {
		return bytes.NewReader(source.finalSegment).ReadAt(destination, offset-4295131256)
	}
	return 0, io.EOF
}
