package pcv3

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

func FuzzReadStructure(f *testing.F) {
	fixture, err := os.ReadFile("testdata/schema1-minimal.pcv")
	if err != nil {
		f.Fatalf("read literal fixture: %v", err)
	}
	f.Add(append([]byte(nil), fixture...), int64(len(fixture)))
	for _, boundary := range []int{0, 1, 3, 4, 15, 16, 975, 976, 1223, 1224, 2183, 2184, 2231} {
		f.Add(append([]byte(nil), fixture[:boundary]...), int64(boundary))
	}
	for _, offset := range []int{int(primaryCapsuleOffset), len(fixture) - int(fixedSuffixLength), len(fixture) - int(trailerLength)} {
		corrupted := append([]byte(nil), fixture...)
		corrupted[offset] ^= 0xff
		f.Add(corrupted, int64(len(corrupted)))
	}
	f.Add(append([]byte(nil), fixture...), int64(-1))
	f.Add(append([]byte(nil), fixture...), int64(^uint64(0)>>1))

	f.Fuzz(func(t *testing.T, data []byte, claimedSize int64) {
		source := &fuzzReaderAt{reader: bytes.NewReader(data)}
		route, structure, probeErr := Probe(source, claimedSize)
		if probeErr != nil {
			var failure Failure
			if !errors.As(probeErr, &failure) {
				t.Fatalf("Probe() error type = %T; want closed pcv3.Failure", probeErr)
			}
		}
		if route == RouteLegacyEligible && structure.CandidateCount() != 0 {
			t.Fatalf("legacy-eligible input retained %d PCV3 candidates", structure.CandidateCount())
		}
		if structure.CandidateCount() > 2 {
			t.Fatalf("CandidateCount() = %d; fixed bound is 2", structure.CandidateCount())
		}
		seen := [2]bool{}
		for index := 0; index < structure.CandidateCount(); index++ {
			candidate, ok := structure.CandidateAt(index)
			if !ok || candidate.Role() > CapsuleRoleBackup || seen[candidate.Role()] {
				t.Fatalf("CandidateAt(%d) has invalid or repeated role %v", index, candidate.Role())
			}
			seen[candidate.Role()] = true
			geometry, ok := structure.GeometryAt(index)
			if !ok || geometry.FileSize() != claimedSize {
				t.Fatalf("candidate %d retained without canonical claimed-size geometry", index)
			}
		}
		for _, component := range []Component{ComponentPrimary, ComponentTrailer, ComponentBackup} {
			if stage, ok := structure.Issue(component); ok && (stage < StageCapsuleRS || stage > StageTailGeometry) {
				t.Fatalf("Issue(%v) stage = %v; want structural component stage", component, stage)
			}
		}
		if source.calls > 5 || source.maxRequest > int(backupCapsuleLength) {
			t.Fatalf("ReaderAt budget = %d calls, max request %d; want <=5 and <=%d", source.calls, source.maxRequest, backupCapsuleLength)
		}
	})
}

type fuzzReaderAt struct {
	reader     *bytes.Reader
	calls      int
	maxRequest int
}

func (reader *fuzzReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	reader.calls++
	reader.maxRequest = max(reader.maxRequest, len(dst))
	count, err := reader.reader.ReadAt(dst, offset)
	if err == nil || errors.Is(err, io.EOF) {
		return count, err
	}
	return count, err
}
