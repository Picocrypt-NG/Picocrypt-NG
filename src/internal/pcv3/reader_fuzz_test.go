package pcv3

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func FuzzReadStructure(f *testing.F) {
	fixture, err := os.ReadFile("testdata/schema1-minimal.pcv")
	if err != nil {
		f.Fatalf("read literal fixture: %v", err)
	}
	f.Add(append([]byte(nil), fixture...), int64(len(fixture)))
	f.Add(
		append(
			append([]byte(nil), fixture...),
			fixture[len(fixture)-int(fixedSuffixLength):]...,
		),
		int64(len(fixture))+int64(fixedSuffixLength),
	)
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
		if route == RouteNormalPCV && structure.observedSize != claimedSize {
			t.Fatalf("Structure observed size = %d; want exact claimed size %d", structure.observedSize, claimedSize)
		}
		if structure.CandidateCount() > 2 {
			t.Fatalf("CandidateCount() = %d; fixed bound is 2", structure.CandidateCount())
		}
		seen := [2]bool{}
		for index := range structure.CandidateCount() {
			candidate, ok := structure.CandidateAt(index)
			if !ok || candidate.Role() > CapsuleRoleBackup || seen[candidate.Role()] {
				t.Fatalf("CandidateAt(%d) has invalid or repeated role %v", index, candidate.Role())
			}
			seen[candidate.Role()] = true
			geometry, ok := structure.GeometryAt(index)
			if !ok || geometry.FileSize() < 0 {
				t.Fatalf("candidate %d retained without host-safe canonical geometry", index)
			}
			canonical, deriveErr := DeriveGeometry(candidate, uint64(geometry.FileSize()))
			if deriveErr != nil || canonical != geometry {
				t.Fatalf("candidate %d retained without self-consistent canonical geometry", index)
			}
			if candidate.Role() == CapsuleRoleBackup && geometry.FileSize() != claimedSize {
				t.Fatalf("EOF-relative backup retained without exact observed geometry")
			}
		}
		for _, component := range []Component{ComponentPrimary, ComponentTrailer, ComponentBackup} {
			if stage, ok := structure.Issue(component); ok && !isReaderStructuralIssueStage(stage) {
				t.Fatalf("Issue(%v) stage = %v; want structural component stage", component, stage)
			}
		}
		if source.calls > 5 || source.maxRequest > int(backupCapsuleLength) {
			t.Fatalf("ReaderAt budget = %d calls, max request %d; want <=5 and <=%d", source.calls, source.maxRequest, backupCapsuleLength)
		}
		assertFuzzRequestsDoNotOverlap(t, source.requests)
	})
}

func isReaderStructuralIssueStage(stage Stage) bool {
	switch stage {
	case StageCapsuleRS, StageCapsuleStructure, StageTailGeometry:
		return true
	default:
		return false
	}
}

func assertFuzzRequestsDoNotOverlap(t *testing.T, requests []fuzzReadRequest) {
	t.Helper()
	for left := range requests {
		if requests[left].offset < 0 || requests[left].length < 0 {
			t.Fatalf("invalid ReaderAt request: %+v", requests[left])
		}
		leftEnd := requests[left].offset + int64(requests[left].length)
		if leftEnd < requests[left].offset {
			t.Fatalf("ReaderAt request overflow: %+v", requests[left])
		}
		for right := left + 1; right < len(requests); right++ {
			rightEnd := requests[right].offset + int64(requests[right].length)
			if rightEnd < requests[right].offset {
				t.Fatalf("ReaderAt request overflow: %+v", requests[right])
			}
			if requests[left].offset < rightEnd && requests[right].offset < leftEnd {
				t.Fatalf("ReaderAt requests overlap: %+v and %+v", requests[left], requests[right])
			}
		}
	}
}

type fuzzReadRequest struct {
	offset int64
	length int
}

type fuzzReaderAt struct {
	reader     *bytes.Reader
	calls      int
	maxRequest int
	requests   []fuzzReadRequest
}

func (reader *fuzzReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	reader.calls++
	reader.maxRequest = max(reader.maxRequest, len(dst))
	reader.requests = append(reader.requests, fuzzReadRequest{offset: offset, length: len(dst)})
	return reader.reader.ReadAt(dst, offset)
}
