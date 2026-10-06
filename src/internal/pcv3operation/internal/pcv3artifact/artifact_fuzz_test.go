package pcv3artifact

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
)

func FuzzParseEnforcesCanonicalSemanticLayout(f *testing.F) {
	partial := readFuzzLiteral(f, "partial")
	unverified := readFuzzLiteral(f, "unverified")
	f.Add(partial)
	f.Add(unverified)
	f.Add(mutateFuzzSeed(partial, 21, 1))
	f.Add(mutateFuzzSeed(partial, 55, 2))
	f.Add(mutateFuzzSeed(partial, 95, 1))
	f.Add(mutateFuzzSeed(partial, 111, 80))
	f.Add(append(append([]byte(nil), partial...), 0))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 2<<20 {
			return
		}
		artifact, err := Parse(context.Background(), bytes.NewReader(input), int64(len(input)))
		if err != nil {
			if artifact != nil {
				t.Fatal("rejected input exposed an artifact")
			}
			return
		}
		if artifact == nil {
			t.Fatal("successful parse returned a nil artifact")
		}

		metadata := artifact.Metadata()
		if metadata.HeaderLength != 80 || metadata.RangeEntryLength != 40 ||
			metadata.TableOffset != 80 || metadata.TotalLength != uint64(len(input)) {
			t.Fatalf("successful parse exposed noncanonical fixed layout: %#v", metadata)
		}
		wantRangeCount := uint64(0)
		if metadata.PlaintextLength != 0 {
			wantRangeCount = (metadata.PlaintextLength-1)/(1<<20) + 1
		}
		if metadata.RangeCount != wantRangeCount ||
			metadata.DataOffset != 80+40*metadata.RangeCount {
			t.Fatalf("successful parse exposed noncanonical range geometry: %#v", metadata)
		}

		nextStart := uint64(0)
		nextSegmentOffset := metadata.DataOffset
		emitted := uint64(0)
		hasVerified := metadata.Final == FinalVerified
		hasUnverified := metadata.Final == FinalUnverified
		hasDamage := metadata.Final != FinalVerified
		visitErr := artifact.VisitRanges(context.Background(), func(entry Entry, segment io.Reader) error {
			if entry.RecordIndex != emittedRangeIndex(nextStart) || entry.Start != nextStart ||
				entry.End <= entry.Start || entry.End-entry.Start > 1<<20 ||
				entry.End > metadata.PlaintextLength {
				t.Fatalf("successful parse exposed noncanonical range: %#v", entry)
			}
			if entry.End != metadata.PlaintextLength && entry.End-entry.Start != 1<<20 {
				t.Fatalf("non-final range has length %d; want 1 MiB", entry.End-entry.Start)
			}
			nextStart = entry.End
			switch entry.Status {
			case RangeMissing:
				hasDamage = true
				if segment != nil || entry.SegmentOffset != 0 || entry.SegmentLength != 0 {
					t.Fatalf("missing range exposed data: %#v", entry)
				}
				return nil
			case RangeVerified:
				hasVerified = true
			case RangeUnverified:
				hasUnverified = true
				hasDamage = true
			default:
				t.Fatalf("successful parse exposed unknown range status %d", entry.Status)
			}
			if segment == nil || entry.SegmentOffset != nextSegmentOffset ||
				uint64(entry.SegmentLength) != entry.End-entry.Start {
				t.Fatalf("emitted range has noncanonical segment: %#v", entry)
			}
			contents, readErr := io.ReadAll(segment)
			if readErr != nil || len(contents) != int(entry.SegmentLength) {
				t.Fatalf("bounded segment read = %d, %v; want %d bytes", len(contents), readErr, entry.SegmentLength)
			}
			nextSegmentOffset += uint64(entry.SegmentLength)
			emitted++
			return nil
		})
		if visitErr != nil {
			t.Fatalf("validated artifact could not be visited: %v", visitErr)
		}
		if nextStart != metadata.PlaintextLength || emitted != metadata.EmittedSegmentCount ||
			nextSegmentOffset != metadata.TotalLength {
			t.Fatalf("successful parse exposed incomplete evidence coverage: %#v", metadata)
		}
		switch metadata.State {
		case StatePartial:
			if !hasVerified || !hasDamage ||
				(hasUnverified && metadata.Role == RoleNone) ||
				(!hasUnverified && metadata.Role != RoleNone) {
				t.Fatalf("successful parse exposed noncanonical partial semantics: %#v", metadata)
			}
		case StateUnverifiedForensic:
			if hasVerified || !hasUnverified ||
				metadata.Role == RoleNone || !validRole(metadata.Role) {
				t.Fatalf("successful parse exposed noncanonical unverified semantics: %#v", metadata)
			}
		default:
			t.Fatalf("successful parse exposed unknown state %d", metadata.State)
		}
	})
}

func emittedRangeIndex(start uint64) uint64 {
	return start / (1 << 20)
}

func readFuzzLiteral(f *testing.F, name string) []byte {
	f.Helper()
	encoded, err := os.ReadFile("testdata/" + name + ".hex")
	if err != nil {
		f.Fatalf("read fuzz literal %q: %v", name, err)
	}
	decoded, err := hex.DecodeString(strings.Join(strings.Fields(string(encoded)), ""))
	if err != nil {
		f.Fatalf("decode fuzz literal %q: %v", name, err)
	}
	return decoded
}

func mutateFuzzSeed(input []byte, offset int, value byte) []byte {
	mutated := append([]byte(nil), input...)
	mutated[offset] = value
	return mutated
}
