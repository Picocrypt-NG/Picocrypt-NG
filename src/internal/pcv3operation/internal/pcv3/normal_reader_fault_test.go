package pcv3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

var errNormalReaderFault = errors.New("TEST ONLY normal ReaderAt fault")

type normalPanicCloseProvider struct {
	*normalFixtureCredentialProvider
	panicValue any
}

func (provider *normalPanicCloseProvider) close() {
	provider.normalFixtureCredentialProvider.close()
	panic(provider.panicValue)
}

type normalFaultReaderAt struct {
	reader     io.ReaderAt
	offset     int64
	length     int
	occurrence int
	calls      int
	closeCalls int
}

func (reader *normalFaultReaderAt) Close() error {
	reader.closeCalls++
	return nil
}

func (reader *normalFaultReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	if offset == reader.offset && len(destination) == reader.length {
		reader.calls++
		if reader.calls == reader.occurrence {
			return 0, errNormalReaderFault
		}
	}
	return reader.reader.ReadAt(destination, offset)
}

func TestReadNormalVolumeFaultCleanupAndInputClassification(t *testing.T) {
	fixture := requireNormalFixture(
		t,
		loadNormalFixtureManifest(t).FixturesByID(),
		"normal-standard-combined-ordered-one",
	)
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)

	t.Run("provider cleanup panic aborts staged plaintext before repanic", func(t *testing.T) {
		source := &normalBorrowedSource{reader: bytes.NewReader(volume)}
		_, structure, err := Probe(source, int64(len(volume)))
		if err != nil {
			t.Fatalf("Probe(TEST ONLY volume): %v", err)
		}
		base := newNormalFixtureCredentialProvider(t, fixture.Keys)
		panicValue := &struct{ label string }{label: "TEST ONLY provider cleanup panic"}
		provider := &normalPanicCloseProvider{normalFixtureCredentialProvider: base, panicValue: panicValue}
		sink := &normalFixtureSink{}
		returned := false
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			_, completion := readNormalVolumeWithProvider(
				context.Background(), source, int64(len(volume)), structure, provider, sink,
			)
			returned = completion != nil
		}()
		if recovered != panicValue {
			t.Fatalf("cleanup panic = %#v; want original %#v", recovered, panicValue)
		}
		if returned {
			t.Fatal("panic cleanup delivered a normal completion")
		}
		assertNormalFaultSinkDiscarded(t, sink, len(plaintext))
		if source.closeCalls != 0 {
			t.Fatalf("borrowed source close calls = %d; want zero", source.closeCalls)
		}
	})

	for _, test := range []struct {
		name       string
		offset     func(Geometry, int64) int64
		length     int
		occurrence int
		staged     int
	}{
		{
			name: "initial suffix capture", offset: func(geometry Geometry, _ int64) int64 {
				return geometry.backupCapsuleOffset
			}, length: int(fixedSuffixLength), occurrence: 1, staged: 0,
		},
		{
			name: "post-record suffix reread", offset: func(geometry Geometry, _ int64) int64 {
				return geometry.backupCapsuleOffset
			}, length: int(fixedSuffixLength), occurrence: 2, staged: len(plaintext),
		},
		{
			name: "physical EOF", offset: func(_ Geometry, sourceSize int64) int64 {
				return sourceSize
			}, length: 1, occurrence: 1, staged: len(plaintext),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &normalBorrowedSource{reader: bytes.NewReader(volume)}
			_, structure, err := Probe(source, int64(len(volume)))
			if err != nil {
				t.Fatalf("Probe(TEST ONLY volume): %v", err)
			}
			geometry, ok := structure.GeometryAt(0)
			if !ok {
				t.Fatal("Probe(TEST ONLY volume) returned no primary geometry")
			}
			faulted := &normalFaultReaderAt{
				reader:     source,
				offset:     test.offset(geometry, int64(len(volume))),
				length:     test.length,
				occurrence: test.occurrence,
			}
			provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
			t.Cleanup(func() {
				if provider.closeCalls == 0 {
					provider.close()
				}
			})
			sink := &normalFixtureSink{}
			result, completion := readNormalVolumeWithProvider(
				context.Background(), faulted, int64(len(volume)), structure, provider, sink,
			)
			if result == nil || result.Outcome() != OutcomeOperationFailed || result.Stage() != StageInputIO ||
				result.Code() != CodeOperationFailed {
				t.Fatalf("non-EOF ReaderAt result = %v/%v/%v; want operation-failed/input-io/operation-failed", result.Outcome(), result.Stage(), result.Code())
			}
			result.Close()
			if completion != nil {
				t.Fatal("non-EOF ReaderAt fault delivered a completion")
			}
			assertNormalFaultSinkDiscarded(t, sink, test.staged)
			if faulted.closeCalls != 0 {
				t.Fatalf("borrowed fault-injecting source close calls = %d; want zero", faulted.closeCalls)
			}
		})
	}
}

func assertNormalFaultSinkDiscarded(t *testing.T, sink *normalFixtureSink, staged int) {
	t.Helper()
	if !sink.aborted || sink.records != nil || !sink.stagedBytesAreZero() ||
		sink.preAbortPlaintextLen != staged {
		t.Fatalf("sink after failed session = aborted %v, records %d, staged %d; want discarded %d bytes", sink.aborted, len(sink.records), sink.preAbortPlaintextLen, staged)
	}
	wantRecords := 0
	if staged != 0 {
		wantRecords = 1
	}
	if sink.preAbortRecordCount != wantRecords {
		t.Fatalf("sink pre-abort records = %d; want %d", sink.preAbortRecordCount, wantRecords)
	}
}

func (manifest normalFixtureManifest) FixturesByID() map[string]normalFixture {
	fixtures := make(map[string]normalFixture, len(manifest.Fixtures))
	for _, fixture := range manifest.Fixtures {
		fixtures[fixture.ID] = fixture
	}
	return fixtures
}
