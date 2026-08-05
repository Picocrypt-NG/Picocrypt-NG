package pcv3

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

var (
	errNormalFuzzReadBound   = errors.New("TEST ONLY normal fuzz read bound")
	errNormalFuzzSinkCounter = errors.New("TEST ONLY normal fuzz sink counter overflow")
)

const (
	normalFuzzProbeReadLimit        uint64 = 5
	normalFuzzProbeCount            uint64 = 2
	normalFuzzSuffixReadCount       uint64 = 2
	normalFuzzEOFReadCount          uint64 = 1
	normalFuzzFinalRecordReadCount  uint64 = 2
	normalFuzzDataRecordReadCount   uint64 = 2
	normalFuzzSessionFixedReadCount        = normalFuzzProbeCount*normalFuzzProbeReadLimit +
		normalFuzzSuffixReadCount +
		normalFuzzEOFReadCount +
		normalFuzzFinalRecordReadCount
)

type normalFuzzSource struct {
	reader     *bytes.Reader
	callLimit  uint64
	maxRequest uint64
	calls      uint64
	violation  string
}

func (source *normalFuzzSource) ReadAt(destination []byte, offset int64) (int, error) {
	source.calls++
	if source.calls > source.callLimit {
		source.violation = "call budget"
		return 0, errNormalFuzzReadBound
	}
	if offset < 0 || uint64(offset) > (^uint64(0)>>1)-uint64(len(destination)) {
		source.violation = "invalid request range"
		return 0, errNormalFuzzReadBound
	}
	if uint64(len(destination)) > source.maxRequest {
		source.violation = "request size"
		return 0, errNormalFuzzReadBound
	}
	return source.reader.ReadAt(destination, offset)
}

func (source *normalFuzzSource) setCallLimit(limit uint64) {
	source.callLimit = limit
}

func (source *normalFuzzSource) assertBounds(t *testing.T) {
	t.Helper()
	if source.violation != "" {
		t.Fatalf("normal reader exceeded fuzz %s", source.violation)
	}
}

type normalFuzzSink struct {
	records uint64
	bytes   uint64
	aborted bool
}

func (sink *normalFuzzSink) writeVerifiedRecord(
	_ context.Context,
	_ uint64,
	plaintext []byte,
) error {
	if uint64(len(plaintext)) > ^uint64(0)-sink.bytes || sink.records == ^uint64(0) {
		return errNormalFuzzSinkCounter
	}
	sink.records++
	sink.bytes += uint64(len(plaintext))
	return nil
}

func (sink *normalFuzzSink) abortUncommitted() {
	sink.records = 0
	sink.bytes = 0
	sink.aborted = true
}

var _ normalVolumeSink = (*normalFuzzSink)(nil)

func FuzzReadNormalVolume(f *testing.F) {
	manifest := loadNormalFixtureManifest(f)
	if len(manifest.Fixtures) == 0 {
		f.Fatal("TEST ONLY normal fixture manifest is empty")
	}
	maximumRequest, ok := encodedRecordBodyLength(recordPlaintextMax, true)
	if !ok {
		f.Fatal("derive TEST ONLY RS record-body fuzz bound")
	}
	for index, fixture := range manifest.Fixtures {
		volume := readNormalFixtureArtifact(f, fixture.Volume)
		f.Add(uint32(index), volume)
	}

	f.Fuzz(func(t *testing.T, selector uint32, volume []byte) {
		fixture := manifest.Fixtures[int(uint64(selector)%uint64(len(manifest.Fixtures)))]
		source := &normalFuzzSource{
			reader:     bytes.NewReader(volume),
			callLimit:  normalFuzzProbeReadLimit,
			maxRequest: maximumRequest,
		}
		sourceSize := int64(len(volume))
		route, structure, err := Probe(source, sourceSize)
		if err != nil || route != RouteNormalPCV {
			source.assertBounds(t)
			return
		}

		callLimit, ok := normalFuzzSessionCallLimit(structure)
		if !ok {
			t.Fatal("normal-admitted fuzz source has unbounded read geometry")
		}
		source.setCallLimit(callLimit)
		sink := &normalFuzzSink{}
		provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
		result, completion := readNormalVolumeWithProvider(
			context.Background(), source, sourceSize, structure, provider, sink,
		)
		if result == nil {
			t.Fatal("normal reader returned no typed result")
		}
		defer result.Close()
		source.assertBounds(t)
		if provider.closeCalls != 1 {
			t.Fatalf("normal reader provider cleanup calls = %d; want one", provider.closeCalls)
		}
		switch result.Outcome() {
		case OutcomeSuccess, OutcomeAuthenticatedDegraded:
			if completion == nil || sink.aborted {
				t.Fatalf("successful fuzz read completion/abort = %v/%v; want sealed completion and retained sink", completion != nil, sink.aborted)
			}
			if !normalFuzzSinkMatchesCandidate(structure, sink) {
				t.Fatalf("successful fuzz read sink = records %d, bytes %d; want one cached admitted geometry", sink.records, sink.bytes)
			}
		default:
			if completion != nil {
				t.Fatal("failed fuzz read returned sealed completion")
			}
			if !sink.aborted || sink.records != 0 || sink.bytes != 0 {
				t.Fatalf("failed fuzz read sink = aborted %v, records %d, bytes %d; want reset", sink.aborted, sink.records, sink.bytes)
			}
		}
	})
}

func normalFuzzSinkMatchesCandidate(structure Structure, sink *normalFuzzSink) bool {
	if sink == nil || sink.aborted {
		return false
	}
	for index := range structure.CandidateCount() {
		candidate, candidateOK := structure.CandidateAt(index)
		geometry, geometryOK := structure.GeometryAt(index)
		if !candidateOK || !geometryOK || candidate.RecordCount() != geometry.RecordCount() {
			continue
		}
		if sink.records == geometry.RecordCount() && sink.bytes == candidate.PlaintextLength() {
			return true
		}
	}
	return false
}

func normalFuzzSessionCallLimit(structure Structure) (uint64, bool) {
	maximumMetadataBlocks := uint64(0)
	maximumRecordCount := uint64(0)
	for index := range structure.CandidateCount() {
		geometry, ok := structure.GeometryAt(index)
		if !ok {
			return 0, false
		}
		maximumMetadataBlocks = max(maximumMetadataBlocks, geometry.MetadataBlocks())
		maximumRecordCount = max(maximumRecordCount, geometry.RecordCount())
	}
	recordReads, ok := checkedMul64(normalFuzzDataRecordReadCount, maximumRecordCount)
	if !ok {
		return 0, false
	}
	limit, ok := checkedAdd64(normalFuzzSessionFixedReadCount, maximumMetadataBlocks)
	if !ok {
		return 0, false
	}
	return checkedAdd64(limit, recordReads)
}
