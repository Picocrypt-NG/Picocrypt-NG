package pcv3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
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
	digest  hash.Hash
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
	_, _ = sink.digest.Write(plaintext)
	return nil
}

func (sink *normalFuzzSink) abortUncommitted() {
	sink.records = 0
	sink.bytes = 0
	sink.aborted = true
	sink.digest.Reset()
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
	volumes := make([][]byte, len(manifest.Fixtures))
	for index, fixture := range manifest.Fixtures {
		volumes[index] = readNormalFixtureArtifact(f, fixture.Volume)
		f.Add(
			uint32(index), uint32(index), uint8(0), uint64(0), uint16(0),
			uint64(0), uint64(0), uint64(0), uint64(0),
		)
	}

	// Keep the multi-megabyte frozen artifacts outside the fuzz arguments. The
	// mutator supplies only compact selectors and a change descriptor; matching
	// selectors with zero changes still execute every frozen volume exactly.
	f.Fuzz(func(
		t *testing.T,
		volumeSelector uint32,
		credentialSelector uint32,
		shapeMode uint8,
		truncateAt uint64,
		appendLength uint16,
		firstOffset uint64,
		firstXOR uint64,
		secondOffset uint64,
		secondXOR uint64,
	) {
		fixtureCount := uint64(len(manifest.Fixtures))
		volumeIndex := uint64(volumeSelector) % fixtureCount
		credentialIndex := uint64(credentialSelector) % fixtureCount
		fixture := manifest.Fixtures[credentialIndex]
		baseVolume := volumes[volumeIndex]
		var volume []byte
		switch shapeMode % 3 {
		case 1:
			length := truncateAt % (uint64(len(baseVolume)) + 1)
			volume = bytes.Clone(baseVolume[:length])
		case 2:
			length := uint64(len(baseVolume)) + uint64(appendLength)
			volume = make([]byte, length)
			copy(volume, baseVolume)
		default:
			volume = bytes.Clone(baseVolume)
		}
		xorNormalFuzzWord(volume, firstOffset, firstXOR)
		xorNormalFuzzWord(volume, secondOffset, secondXOR)

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
		sink := &normalFuzzSink{digest: sha256.New()}
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
			// A repaired or otherwise accepted mutation must yield the exact
			// frozen plaintext, even when its length and record count still match.
			if hex.EncodeToString(sink.digest.Sum(nil)) != manifest.Fixtures[volumeIndex].Plaintext.SHA256 {
				t.Fatal("successful fuzz read changed frozen plaintext content")
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

func xorNormalFuzzWord(volume []byte, offset uint64, word uint64) {
	if len(volume) == 0 || word == 0 {
		return
	}
	length := uint64(len(volume))
	start := offset % length
	for byteIndex := range min(uint64(8), length-start) {
		position := start + byteIndex
		volume[position] ^= byte(word >> (byteIndex * 8))
	}
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
