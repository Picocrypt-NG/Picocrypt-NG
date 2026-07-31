package pcv3

import (
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
}

type recordingReaderAt struct {
	data     []byte
	maxChunk int
	requests []readRequest
}

func (reader *recordingReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	reader.requests = append(reader.requests, readRequest{offset: offset, length: len(dst)})
	if offset < 0 || offset >= int64(len(reader.data)) {
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
