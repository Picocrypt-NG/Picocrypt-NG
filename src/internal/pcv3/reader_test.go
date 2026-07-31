package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

type readerAtFunc func([]byte, int64) (int, error)

func (read readerAtFunc) ReadAt(dst []byte, offset int64) (int, error) {
	return read(dst, offset)
}

type readRequest struct {
	offset int64
	length int
	limit  int
}

type recordingReaderAt struct {
	data     []byte
	maxChunk int
	requests []readRequest
}

func (reader *recordingReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(reader.data)) {
		reader.requests = append(reader.requests, readRequest{offset: offset, limit: len(dst)})
		return 0, io.EOF
	}

	available := len(reader.data) - int(offset)
	count := len(dst)
	if reader.maxChunk > 0 && count > reader.maxChunk {
		count = reader.maxChunk
	}
	if count > available {
		count = available
	}
	copy(dst[:count], reader.data[offset:int(offset)+count])
	reader.requests = append(reader.requests, readRequest{offset: offset, length: count, limit: len(dst)})
	if count < len(dst) && count == available {
		return count, io.EOF
	}
	return count, nil
}

func TestReadExactAtMatrix(t *testing.T) {
	t.Run("short positive reads advance without repeating coordinates", func(t *testing.T) {
		payload := []byte("bounded")
		var requests []readRequest
		source := readerAtFunc(func(dst []byte, offset int64) (int, error) {
			requests = append(requests, readRequest{offset: offset, length: len(dst)})
			index := int(offset - 11)
			dst[0] = payload[index]
			return 1, nil
		})
		dst := make([]byte, len(payload))

		count, err := readExactAt(source, 11, dst, StageCapsuleRS)
		if err != nil {
			t.Fatalf("readExactAt() error = %v", err)
		}
		if count != len(payload) || !reflect.DeepEqual(dst, payload) {
			t.Fatalf("readExactAt() = (%d, %q); want (%d, %q)", count, dst, len(payload), payload)
		}
		if len(requests) > len(payload)+2 {
			t.Fatalf("ReadAt calls = %d; cap = %d", len(requests), len(payload)+2)
		}
		for index, request := range requests {
			if request.offset != int64(11+index) || request.length != len(payload)-index {
				t.Fatalf("request %d = %+v; want offset %d length %d", index, request, 11+index, len(payload)-index)
			}
		}
	})

	t.Run("one transient no-progress read is tolerated", func(t *testing.T) {
		calls := 0
		source := readerAtFunc(func(dst []byte, _ int64) (int, error) {
			calls++
			if calls == 1 {
				return 0, nil
			}
			copy(dst, "ok")
			return len(dst), nil
		})
		dst := make([]byte, 2)

		count, err := readExactAt(source, 0, dst, StagePreamble)
		if err != nil || count != 2 || string(dst) != "ok" || calls != 2 {
			t.Fatalf("readExactAt() = (%d, %q, %v), calls = %d; want (2, ok, nil), calls = 2", count, dst, err, calls)
		}
	})

	t.Run("two consecutive no-progress reads fail operationally", func(t *testing.T) {
		calls := 0
		source := readerAtFunc(func([]byte, int64) (int, error) {
			calls++
			return 0, nil
		})
		count, err := readExactAt(source, 0, make([]byte, 4), StagePreamble)
		assertInputFailure(t, err)
		if count != 0 || calls != 2 {
			t.Fatalf("readExactAt() count/calls = %d/%d; want 0/2", count, calls)
		}
	})

	t.Run("full buffer with EOF succeeds", func(t *testing.T) {
		source := readerAtFunc(func(dst []byte, _ int64) (int, error) {
			copy(dst, "done")
			return len(dst), io.EOF
		})
		dst := make([]byte, 4)
		count, err := readExactAt(source, 0, dst, StagePreamble)
		if err != nil || count != 4 || string(dst) != "done" {
			t.Fatalf("readExactAt() = (%d, %q, %v); want (4, done, nil)", count, dst, err)
		}
	})

	for _, endError := range []error{io.EOF, io.ErrUnexpectedEOF} {
		name := strings.ReplaceAll(endError.Error(), " ", "_")
		t.Run("incomplete_"+name+"_is_structural", func(t *testing.T) {
			source := readerAtFunc(func(dst []byte, _ int64) (int, error) {
				copy(dst, "x")
				return 1, endError
			})
			count, err := readExactAt(source, 0, make([]byte, 4), StageCapsuleRS)
			assertStructuralFailure(t, err, StageCapsuleRS)
			if count != 1 {
				t.Fatalf("readExactAt() count = %d; want 1", count)
			}
		})
	}

	t.Run("non-EOF cause remains inspectable but redacted", func(t *testing.T) {
		cause := errors.New("private backend path")
		source := readerAtFunc(func(dst []byte, _ int64) (int, error) {
			dst[0] = 'x'
			return 1, cause
		})
		count, err := readExactAt(source, 0, make([]byte, 4), StageCapsuleRS)
		assertInputFailure(t, err)
		if count != 1 || !errors.Is(err, cause) {
			t.Fatalf("readExactAt() = (%d, %v); want count 1 and wrapped cause", count, err)
		}
		if strings.Contains(err.Error(), cause.Error()) {
			t.Fatalf("public error %q leaked source cause", err)
		}
	})

	for _, impossible := range []int{-1, 5} {
		name := "negative_count"
		if impossible > 0 {
			name = "count_larger_than_remaining_buffer"
		}
		t.Run(name, func(t *testing.T) {
			source := readerAtFunc(func([]byte, int64) (int, error) {
				return impossible, nil
			})
			count, err := readExactAt(source, 0, make([]byte, 4), StagePreamble)
			assertInputFailure(t, err)
			if count != 0 {
				t.Fatalf("readExactAt() count = %d; want 0", count)
			}
		})
	}
}

func TestProbeOwnsPrefixOnce(t *testing.T) {
	fixture := readReaderFixture(t)
	source := &recordingReaderAt{data: fixture, maxChunk: 2}

	route, _, err := Probe(source, int64(len(fixture)))
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if route != RouteNormalPCV {
		t.Fatalf("Probe() route = %v; want normal PCV", route)
	}
	accesses := [4]int{}
	for _, request := range source.requests {
		for offset := request.offset; offset < request.offset+int64(request.length); offset++ {
			if offset >= 0 && offset < 4 {
				accesses[offset]++
			}
		}
	}
	if accesses != [4]int{1, 1, 1, 1} {
		t.Fatalf("prefix byte request counts = %v; want each coordinate requested once", accesses)
	}
	if len(source.requests) < 3 || source.requests[2].offset != 4 {
		t.Fatalf("first Inspect request = %+v; want offset 4", source.requests[2])
	}

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "short EOF", data: []byte{'P', 'C', 'V'}},
		{name: "non-matching full prefix", data: []byte("NOPE")},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &recordingReaderAt{data: test.data, maxChunk: 2}
			route, _, err := Probe(source, int64(len(test.data)))
			if err != nil {
				t.Fatalf("Probe() error = %v", err)
			}
			if route != RouteLegacyEligible {
				t.Fatalf("Probe() route = %v; want legacy eligible", route)
			}
			for _, request := range source.requests {
				if request.offset >= 4 {
					t.Fatalf("legacy-eligible Probe requested Inspect coordinate: %+v", request)
				}
			}
		})
	}
}

func TestProbeFixedRegionBudget(t *testing.T) {
	fixture := readReaderFixture(t)
	source := &recordingReaderAt{data: fixture, maxChunk: 31}

	route, _, err := Probe(source, int64(len(fixture)))
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if route != RouteNormalPCV {
		t.Fatalf("Probe() route = %v; want normal PCV", route)
	}

	allowed := make(map[int64]bool, 1984)
	for _, region := range []struct {
		offset int64
		length int
	}{
		{offset: 0, length: 4},
		{offset: 4, length: 12},
		{offset: 16, length: 960},
		{offset: int64(len(fixture) - 48), length: 48},
		{offset: int64(len(fixture) - 1008), length: 960},
	} {
		for offset := region.offset; offset < region.offset+int64(region.length); offset++ {
			allowed[offset] = true
		}
	}
	requested := make(map[int64]int, len(allowed))
	for _, request := range source.requests {
		for offset := request.offset; offset < request.offset+int64(request.length); offset++ {
			if !allowed[offset] {
				t.Fatalf("Probe requested coordinate %d outside the five fixed regions", offset)
			}
			requested[offset]++
		}
	}
	if len(requested) != 1984 {
		t.Fatalf("requested coordinate union = %d; want 1984", len(requested))
	}
	for offset, count := range requested {
		if count != 1 {
			t.Fatalf("coordinate %d requested %d times; want once", offset, count)
		}
	}
}

func TestInspectLiteralFixture(t *testing.T) {
	fixture := readReaderFixture(t)
	corrected := append([]byte(nil), fixture...)
	backupOffset := len(corrected) - int(fixedSuffixLength)
	for lane := range 5 {
		corrected[int(primaryCapsuleOffset)+lane*192+7] ^= byte(lane + 1)
		corrected[backupOffset+lane*192+7] ^= byte(lane + 11)
	}
	corrected[len(corrected)-int(trailerLength)+7] ^= 0x5a

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "literal", data: fixture},
		{name: "one corrected error in every RS lane", data: corrected},
	} {
		t.Run(test.name, func(t *testing.T) {
			route, structure, err := Probe(bytes.NewReader(test.data), int64(len(test.data)))
			if err != nil {
				t.Fatalf("Probe() error = %v", err)
			}
			if route != RouteNormalPCV {
				t.Fatalf("Probe() route = %v; want normal PCV", route)
			}
			assertCandidateRoles(t, structure, CapsuleRolePrimary, CapsuleRoleBackup)
			for _, component := range []Component{ComponentPrimary, ComponentTrailer, ComponentBackup} {
				if stage, ok := structure.Issue(component); ok {
					t.Fatalf("Issue(%v) = %v; want none", component, stage)
				}
			}
			for index := 0; index < structure.CandidateCount(); index++ {
				geometry, ok := structure.GeometryAt(index)
				if !ok || geometry.FileSize() != int64(len(test.data)) {
					t.Fatalf("GeometryAt(%d) = (%+v, %v); want canonical file size %d", index, geometry, ok, len(test.data))
				}
			}
		})
	}
}

func TestInspectDiscardsPartialRS(t *testing.T) {
	fixture := readReaderFixture(t)
	corruptedCapsule := append([]byte(nil), fixture[primaryCapsuleOffset:primaryCapsuleOffset+int64(backupCapsuleLength)]...)
	corruptFirstLaneParity(corruptedCapsule)

	codecs := mustReaderCodecs(t)
	partial, decodeErr := pcencoding.Decode(codecs.RS64, corruptedCapsule[:192], false)
	if decodeErr == nil {
		t.Fatal("test mutation did not make the first RS64 lane uncorrectable")
	}
	if len(partial) != 64 || string(partial[:4]) != "PCVC" {
		t.Fatalf("Decode() partial output does not preserve a plausible capsule prefix: len=%d prefix=%q", len(partial), partial[:min(4, len(partial))])
	}
	clear(partial)

	corruptedCapsule = append([]byte(nil), fixture[primaryCapsuleOffset:primaryCapsuleOffset+int64(backupCapsuleLength)]...)
	corruptFirstLaneParity(corruptedCapsule)
	decoded, err := decodeCapsule(codecs, corruptedCapsule)
	assertStructuralFailure(t, err, StageCapsuleRS)
	if decoded != [decodedCapsuleLength]byte{} {
		t.Fatal("decodeCapsule() retained partial decoded bytes after an RS error")
	}
	if !allZero(corruptedCapsule) {
		t.Fatal("decodeCapsule() retained encoded component bytes after an RS error")
	}

	mutated := append([]byte(nil), fixture...)
	corruptFirstLaneParity(mutated[primaryCapsuleOffset : primaryCapsuleOffset+int64(backupCapsuleLength)])
	_, structure, err := Probe(bytes.NewReader(mutated), int64(len(mutated)))
	if err != nil {
		t.Fatalf("Probe() discarded the independent backup candidate: %v", err)
	}
	assertCandidateRoles(t, structure, CapsuleRoleBackup)
	assertComponentIssue(t, structure, ComponentPrimary, StageCapsuleRS)
}

func TestInspectRetainsIndependentCandidates(t *testing.T) {
	fixture := readReaderFixture(t)

	t.Run("invalid primary keeps backup and its primary issue", func(t *testing.T) {
		mutated := append([]byte(nil), fixture...)
		rewriteCapsule(t, mutated, int(primaryCapsuleOffset), func(decoded []byte) {
			copy(decoded[:4], "BAD!")
		})

		_, structure, err := Probe(bytes.NewReader(mutated), int64(len(mutated)))
		if err != nil {
			t.Fatalf("Probe() error = %v", err)
		}
		assertCandidateRoles(t, structure, CapsuleRoleBackup)
		assertComponentIssue(t, structure, ComponentPrimary, StageCapsuleStructure)
	})

	t.Run("invalid backup keeps primary", func(t *testing.T) {
		mutated := append([]byte(nil), fixture...)
		rewriteCapsule(t, mutated, len(mutated)-int(fixedSuffixLength), func(decoded []byte) {
			copy(decoded[:4], "BAD!")
		})

		_, structure, err := Probe(bytes.NewReader(mutated), int64(len(mutated)))
		if err != nil {
			t.Fatalf("Probe() error = %v", err)
		}
		assertCandidateRoles(t, structure, CapsuleRolePrimary)
		assertComponentIssue(t, structure, ComponentBackup, StageCapsuleStructure)
	})

	t.Run("invalid trailer neither erases nor relocates candidates", func(t *testing.T) {
		mutated := append([]byte(nil), fixture...)
		rewriteTrailer(t, mutated, func(decoded []byte) {
			copy(decoded[:4], "BAD!")
		})
		source := &recordingReaderAt{data: mutated}

		_, structure, err := Probe(source, int64(len(mutated)))
		if err != nil {
			t.Fatalf("Probe() error = %v", err)
		}
		assertCandidateRoles(t, structure, CapsuleRolePrimary, CapsuleRoleBackup)
		assertComponentIssue(t, structure, ComponentTrailer, StageTailGeometry)
		wantBackupOffset := int64(len(mutated)) - int64(fixedSuffixLength)
		seenCanonicalBackup := false
		for _, request := range source.requests {
			if request.offset == wantBackupOffset && request.limit == int(backupCapsuleLength) {
				seenCanonicalBackup = true
			}
		}
		if !seenCanonicalBackup {
			t.Fatalf("backup was not read at canonical offset %d after trailer damage", wantBackupOffset)
		}
	})

	t.Run("no viable capsule reports earliest structural stage", func(t *testing.T) {
		mutated := append([]byte(nil), fixture...)
		corruptFirstLaneParity(mutated[primaryCapsuleOffset : primaryCapsuleOffset+int64(backupCapsuleLength)])
		rewriteCapsule(t, mutated, len(mutated)-int(fixedSuffixLength), func(decoded []byte) {
			copy(decoded[:4], "BAD!")
		})

		_, structure, err := Probe(bytes.NewReader(mutated), int64(len(mutated)))
		assertStructuralFailure(t, err, StageCapsuleRS)
		if structure.CandidateCount() != 0 {
			t.Fatalf("CandidateCount() = %d; want 0", structure.CandidateCount())
		}
		assertComponentIssue(t, structure, ComponentPrimary, StageCapsuleRS)
		assertComponentIssue(t, structure, ComponentBackup, StageCapsuleStructure)
	})
}

func TestInspectHostileLengthBound(t *testing.T) {
	fixture := readReaderFixture(t)
	source := &recordingReaderAt{data: fixture}
	maxInt64 := int64(^uint64(0) >> 1)

	route, structure, err := Probe(source, maxInt64)
	if route != RouteNormalPCV {
		t.Fatalf("Probe() route = %v; want normal PCV", route)
	}
	assertStructuralFailure(t, err, StageTailGeometry)
	if structure.CandidateCount() != 0 {
		t.Fatalf("CandidateCount() = %d; want 0 for impossible whole-file geometry", structure.CandidateCount())
	}
	if len(source.requests) > 5 {
		t.Fatalf("ReadAt calls = %d; want at most the five fixed logical regions", len(source.requests))
	}
	for _, request := range source.requests {
		if request.offset < 0 || request.limit > int(backupCapsuleLength) {
			t.Fatalf("hostile-size request = %+v; want non-negative fixed-size request", request)
		}
	}

	frontOnly := readerAtFunc(func(dst []byte, offset int64) (int, error) {
		if offset < 0 || offset >= 976 {
			return 0, io.EOF
		}
		count := copy(dst, fixture[offset:min(int64(len(fixture)), offset+int64(len(dst)))])
		if count < len(dst) {
			return count, io.EOF
		}
		return count, nil
	})
	admitted := [4]byte{'P', 'C', 'V', 0}
	baselineAllocs := testing.AllocsPerRun(20, func() {
		_, _ = Inspect(frontOnly, int64(len(fixture)), admitted)
	})
	hostileAllocs := testing.AllocsPerRun(20, func() {
		_, _ = Inspect(frontOnly, maxInt64, admitted)
	})
	if hostileAllocs > baselineAllocs+2 {
		t.Fatalf("hostile source size allocations = %.0f; fixed-size baseline = %.0f", hostileAllocs, baselineAllocs)
	}
}

func corruptFirstLaneParity(capsule []byte) {
	for index := 64; index < 192; index++ {
		capsule[index] ^= byte(index*17 + 3)
	}
}

func rewriteCapsule(t *testing.T, fixture []byte, offset int, mutate func([]byte)) {
	t.Helper()
	codecs := mustReaderCodecs(t)
	decoded := make([]byte, 0, decodedCapsuleLength)
	for lane := range 5 {
		laneStart := offset + lane*192
		laneDecoded, err := pcencoding.Decode(codecs.RS64, fixture[laneStart:laneStart+192], false)
		if err != nil {
			t.Fatalf("decode capsule lane %d: %v", lane, err)
		}
		decoded = append(decoded, laneDecoded...)
		clear(laneDecoded)
	}
	mutate(decoded)
	for lane := range 5 {
		encoded, err := pcencoding.Encode(codecs.RS64, decoded[lane*64:(lane+1)*64])
		if err != nil {
			t.Fatalf("encode capsule lane %d: %v", lane, err)
		}
		copy(fixture[offset+lane*192:offset+(lane+1)*192], encoded)
		clear(encoded)
	}
	clear(decoded)
}

func rewriteTrailer(t *testing.T, fixture []byte, mutate func([]byte)) {
	t.Helper()
	codecs := mustReaderCodecs(t)
	offset := len(fixture) - int(trailerLength)
	decoded, err := pcencoding.Decode(codecs.RS16, fixture[offset:], false)
	if err != nil {
		t.Fatalf("decode trailer: %v", err)
	}
	mutate(decoded)
	encoded, err := pcencoding.Encode(codecs.RS16, decoded)
	if err != nil {
		t.Fatalf("encode trailer: %v", err)
	}
	copy(fixture[offset:], encoded)
	clear(decoded)
	clear(encoded)
}

func mustReaderCodecs(t *testing.T) *pcencoding.RSCodecs {
	t.Helper()
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("initialize RS codecs: %v", err)
	}
	return codecs
}

func assertCandidateRoles(t *testing.T, structure Structure, want ...CapsuleRole) {
	t.Helper()
	if structure.CandidateCount() != len(want) {
		t.Fatalf("CandidateCount() = %d; want %d", structure.CandidateCount(), len(want))
	}
	for index, role := range want {
		candidate, ok := structure.CandidateAt(index)
		if !ok || candidate.Role() != role {
			t.Fatalf("CandidateAt(%d) = (%v, %v); want role %v", index, candidate.Role(), ok, role)
		}
	}
}

func assertComponentIssue(t *testing.T, structure Structure, component Component, want Stage) {
	t.Helper()
	stage, ok := structure.Issue(component)
	if !ok || stage != want {
		t.Fatalf("Issue(%v) = (%v, %v); want (%v, true)", component, stage, ok, want)
	}
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func readReaderFixture(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile("testdata/schema1-minimal.pcv")
	if err != nil {
		t.Fatalf("read literal fixture: %v", err)
	}
	return fixture
}

func assertInputFailure(t *testing.T, err error) {
	t.Helper()
	var failure Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T; want pcv3.Failure", err)
	}
	if failure.Outcome() != OutcomeOperationFailed || failure.Stage() != StageInputIO || failure.Code() != CodeOperationFailed {
		t.Fatalf("failure = %v/%v/%v; want operation-failed/input-io", failure.Outcome(), failure.Stage(), failure.Code())
	}
}

func assertStructuralFailure(t *testing.T, err error, stage Stage) {
	t.Helper()
	var failure Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T; want pcv3.Failure", err)
	}
	if failure.Outcome() != OutcomeInvalidStructurePreKDF || failure.Stage() != stage || failure.Code() != CodeInvalidStructure {
		t.Fatalf("failure = %v/%v/%v; want invalid-structure/%v", failure.Outcome(), failure.Stage(), failure.Code(), stage)
	}
}
