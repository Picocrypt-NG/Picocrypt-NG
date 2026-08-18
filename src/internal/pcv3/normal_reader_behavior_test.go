package pcv3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

type normalFixtureMutation struct {
	Name        string  `json:"name"`
	Kind        string  `json:"kind"`
	Offsets     []int64 `json:"offsets"`
	XORMasksHex string  `json:"xor_masks_hex"`
}

var errNormalBehaviorSink = errors.New("TEST ONLY normal sink fault")

type normalCancelReadSource struct {
	reader     io.ReaderAt
	offset     int64
	length     int
	occurrence int
	calls      int
	cancel     context.CancelFunc
	closeCalls int
}

func (source *normalCancelReadSource) Close() error {
	source.closeCalls++
	return nil
}

func (source *normalCancelReadSource) ReadAt(destination []byte, offset int64) (int, error) {
	if offset == source.offset && len(destination) == source.length {
		source.calls++
		if source.calls == source.occurrence {
			source.cancel()
		}
	}
	return source.reader.ReadAt(destination, offset)
}

// normalBetweenPassTailSource returns the canonical bytes on the first
// canonical-suffix read and flips one trailer byte inside the second read,
// simulating a source whose tail changes after payload authentication.
type normalBetweenPassTailSource struct {
	reader           io.ReaderAt
	offset           int64
	length           int
	suffixReads      int
	mutateSecondPass bool
	closeCalls       int
}

func (source *normalBetweenPassTailSource) ReadAt(destination []byte, offset int64) (int, error) {
	count, err := source.reader.ReadAt(destination, offset)
	if offset == source.offset && len(destination) == source.length {
		source.suffixReads++
		if source.mutateSecondPass && source.suffixReads == 2 && count == len(destination) {
			destination[len(destination)-1] ^= 0x40
		}
	}
	return count, err
}

func (source *normalBetweenPassTailSource) Close() error {
	source.closeCalls++
	return nil
}

type normalFailingSink struct {
	normalFixtureSink
	calls int
}

func (sink *normalFailingSink) writeVerifiedRecord(
	_ context.Context,
	_ uint64,
	_ []byte,
) error {
	sink.calls++
	return errNormalBehaviorSink
}

type normalPanicSink struct {
	normalFixtureSink
	panicValue any
}

func (sink *normalPanicSink) writeVerifiedRecord(
	ctx context.Context,
	index uint64,
	plaintext []byte,
) error {
	if err := sink.normalFixtureSink.writeVerifiedRecord(ctx, index, plaintext); err != nil {
		return err
	}
	panic(sink.panicValue)
}

func TestReadNormalVolumeBehavioralClosure(t *testing.T) {
	fixtures := loadNormalFixtureManifest(t).FixturesByID()

	t.Run("combined metadata and trailer damage reports metadata precedence after exact recovery", func(t *testing.T) {
		metadataFixture := requireNormalFixture(t, fixtures, "normal-degraded-metadata")
		trailerFixture := requireNormalFixture(t, fixtures, "normal-degraded-trailer")
		restored := readNormalFixtureArtifact(t, metadataFixture.Volume)
		applyNormalFrozenXOR(t, restored, metadataFixture.Mutations)
		combined := append([]byte(nil), restored...)
		applyNormalFrozenXOR(t, combined, metadataFixture.Mutations)
		applyNormalFrozenXOR(t, combined, trailerFixture.Mutations)

		source := &normalBorrowedSource{reader: bytes.NewReader(combined)}
		sink := &normalFixtureSink{}
		result, completion, provider := runNormalBehaviorRead(
			t, context.Background(), metadataFixture, source, int64(len(combined)), sink,
		)
		checkNormalBehaviorResult(
			t, result, OutcomeAuthenticatedDegraded, StageMetadata, 2, CodeAuthenticatedDegraded,
		)
		checkNormalBehaviorCompletion(t, completion, true)
		plaintext := readNormalFixturePlaintext(t, metadataFixture.Plaintext)
		if sink.aborted || !bytes.Equal(sink.plaintext(), plaintext) {
			t.Errorf(
				"combined degradation staging = aborted %v, plaintext %d bytes; want retained exact %d-byte plaintext",
				sink.aborted, len(sink.plaintext()), len(plaintext),
			)
		}
		if comment := result.commentBytes(); comment != nil {
			t.Errorf("combined degradation exposed %d unauthenticated metadata bytes; want none", len(comment))
		}
		closeNormalBehaviorResult(result)
		checkNormalBehaviorOwnership(t, provider, source.closeCalls)
	})

	t.Run("one-byte shifted canonical suffix never publishes verified plaintext", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		structure := probeNormalBehavior(t, bytes.NewReader(volume), int64(len(volume)))
		geometry := requireNormalBehaviorGeometry(t, structure)
		shifted := insertNormalBehaviorBytes(
			t,
			volume,
			geometry.backupCapsuleOffset,
			[]byte{0xa5},
		)
		source := &normalBorrowedSource{reader: bytes.NewReader(shifted)}
		sink := &normalFixtureSink{}
		result, completion, provider := runNormalBehaviorRead(
			t, context.Background(), fixture, source, int64(len(shifted)), sink,
		)
		checkNormalBehaviorResult(
			t, result, OutcomeAuthenticationFailed, StageTailGeometry, 1, CodeAuthenticationFailed,
		)
		checkNormalBehaviorCompletion(t, completion, false)
		plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
		checkNormalBehaviorDiscarded(t, sink, plaintext, 1)
		closeNormalBehaviorResult(result)
		checkNormalBehaviorOwnership(t, provider, source.closeCalls)
	})

	t.Run("tail bytes mutated between authenticated passes never complete or publish", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		structure := probeNormalBehavior(t, bytes.NewReader(volume), int64(len(volume)))
		geometry := requireNormalBehaviorGeometry(t, structure)
		source := &normalBetweenPassTailSource{
			reader:           bytes.NewReader(volume),
			offset:           geometry.backupCapsuleOffset,
			length:           int(fixedSuffixLength),
			mutateSecondPass: true,
		}
		sink := &normalFixtureSink{}
		result, completion, provider := runNormalBehaviorRead(
			t, context.Background(), fixture, source, int64(len(volume)), sink,
		)
		checkNormalBehaviorResult(
			t, result, OutcomeAuthenticationFailed, StageTailGeometry, 2, CodeAuthenticationFailed,
		)
		checkNormalBehaviorCompletion(t, completion, false)
		plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
		checkNormalBehaviorDiscarded(t, sink, plaintext, 1)
		if source.suffixReads != 2 {
			t.Errorf("canonical suffix reads = %d; want initial capture plus one post-record reread", source.suffixReads)
		}
		closeNormalBehaviorResult(result)
		checkNormalBehaviorOwnership(t, provider, source.closeCalls)
	})

	t.Run("stable canonical suffix completes with exact plaintext and comment", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		structure := probeNormalBehavior(t, bytes.NewReader(volume), int64(len(volume)))
		geometry := requireNormalBehaviorGeometry(t, structure)
		source := &normalBetweenPassTailSource{
			reader: bytes.NewReader(volume),
			offset: geometry.backupCapsuleOffset,
			length: int(fixedSuffixLength),
		}
		sink := &normalFixtureSink{}
		result, completion, provider := runNormalBehaviorRead(
			t, context.Background(), fixture, source, int64(len(volume)), sink,
		)
		checkNormalBehaviorResult(t, result, OutcomeSuccess, StageNone, 2, CodeSuccess)
		checkNormalBehaviorCompletion(t, completion, true)
		plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
		if sink.aborted || !bytes.Equal(sink.plaintext(), plaintext) {
			t.Errorf(
				"healthy staging = aborted %v, plaintext %d bytes; want retained exact %d-byte plaintext",
				sink.aborted, len(sink.plaintext()), len(plaintext),
			)
		}
		wantComment := decodeNormalFixtureHex(t, fixture.CommentHex, len(fixture.CommentHex)/2)
		if !bytes.Equal(result.commentBytes(), wantComment) {
			t.Errorf(
				"published comment = %d bytes; want exact frozen %d-byte comment",
				len(result.commentBytes()), len(wantComment),
			)
		}
		if source.suffixReads != 2 {
			t.Errorf("canonical suffix reads = %d; want initial capture plus one post-record reread", source.suffixReads)
		}
		closeNormalBehaviorResult(result)
		checkNormalBehaviorOwnership(t, provider, source.closeCalls)
	})

	t.Run("authenticated record sequence rejects reorder duplicate splice and final anomalies", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-two-mib")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
		structure := probeNormalBehavior(t, bytes.NewReader(volume), int64(len(volume)))
		candidate, ok := structure.CandidateAt(0)
		if !ok {
			t.Fatal("Probe(TEST ONLY record volume) returned no primary candidate")
		}
		geometry := requireNormalBehaviorGeometry(t, structure)
		records := make([]recordExpectation, 3)
		for index := range records {
			record, err := expectedRecord(candidate.core, geometry, uint64(index))
			if err != nil {
				t.Fatalf("locate TEST ONLY record %d fault range: %v", index, err)
			}
			records[index] = record
		}
		firstStart, firstEnd := normalBehaviorRecordExtent(t, records[0], len(volume))
		secondStart, secondEnd := normalBehaviorRecordExtent(t, records[1], len(volume))
		finalStart, finalEnd := normalBehaviorRecordExtent(t, records[2], len(volume))
		if firstEnd-firstStart != secondEnd-secondStart {
			t.Fatal("TEST ONLY data-record fault ranges are not interchangeable")
		}

		tests := []struct {
			name          string
			mutate        func(*testing.T, []byte) []byte
			stage         Stage
			authenticated int
			prefixLength  int
			stagedRecords int
		}{
			{
				name: "reordered data records",
				mutate: func(_ *testing.T, data []byte) []byte {
					first := append([]byte(nil), data[firstStart:firstEnd]...)
					copy(data[firstStart:firstEnd], data[secondStart:secondEnd])
					copy(data[secondStart:secondEnd], first)
					return data
				},
				stage: StageDescriptor, authenticated: 2,
			},
			{
				name: "duplicated first data record",
				mutate: func(_ *testing.T, data []byte) []byte {
					copy(data[secondStart:secondEnd], data[firstStart:firstEnd])
					return data
				},
				stage: StageDescriptor, authenticated: 2,
				prefixLength: 1 << 20, stagedRecords: 1,
			},
			{
				name: "body spliced across authenticated indices",
				mutate: func(_ *testing.T, data []byte) []byte {
					firstBodyStart := int(records[0].bodyOffset)
					secondBodyStart := int(records[1].bodyOffset)
					copy(
						data[secondBodyStart:secondEnd],
						data[firstBodyStart:firstEnd],
					)
					return data
				},
				stage: StageRecordAuth, authenticated: 2,
				prefixLength: 1 << 20, stagedRecords: 1,
			},
			{
				name: "missing or corrupted final record",
				mutate: func(_ *testing.T, data []byte) []byte {
					clear(data[finalStart:finalEnd])
					return data
				},
				stage: StageFinalRecord, authenticated: 2,
				prefixLength: 2 << 20, stagedRecords: 2,
			},
			{
				name: "extra duplicated final record",
				mutate: func(t *testing.T, data []byte) []byte {
					return insertNormalBehaviorBytes(
						t,
						data,
						geometry.backupCapsuleOffset,
						data[finalStart:finalEnd],
					)
				},
				stage: StageTailGeometry, authenticated: 1,
				prefixLength: 2 << 20, stagedRecords: 2,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				mutated := test.mutate(t, append([]byte(nil), volume...))
				source := &normalBorrowedSource{reader: bytes.NewReader(mutated)}
				sink := &normalFixtureSink{}
				result, completion, provider := runNormalBehaviorRead(
					t, context.Background(), fixture, source, int64(len(mutated)), sink,
				)
				checkNormalBehaviorResult(
					t, result, OutcomeAuthenticationFailed, test.stage,
					test.authenticated, CodeAuthenticationFailed,
				)
				checkNormalBehaviorCompletion(t, completion, false)
				checkNormalBehaviorDiscarded(
					t, sink, plaintext[:test.prefixLength], test.stagedRecords,
				)
				closeNormalBehaviorResult(result)
				checkNormalBehaviorOwnership(t, provider, source.closeCalls)
			})
		}
	})

	t.Run("cancellation after final authentication but before tail closure discards plaintext", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		structure := probeNormalBehavior(t, bytes.NewReader(volume), int64(len(volume)))
		geometry := requireNormalBehaviorGeometry(t, structure)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		source := &normalCancelReadSource{
			reader: bytes.NewReader(volume), offset: geometry.backupCapsuleOffset,
			length: int(fixedSuffixLength), occurrence: 2, cancel: cancel,
		}
		sink := &normalFixtureSink{}
		result, completion, provider := runNormalBehaviorRead(
			t, ctx, fixture, source, int64(len(volume)), sink,
		)
		checkNormalBehaviorResult(
			t, result, OutcomeOperationFailed, StageCancellation, 2, CodeOperationFailed,
		)
		checkNormalBehaviorCompletion(t, completion, false)
		plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
		checkNormalBehaviorDiscarded(t, sink, plaintext, 1)
		if source.calls != 2 {
			t.Errorf("canonical suffix reads before cancellation = %d; want exactly initial capture plus post-final reread", source.calls)
		}
		closeNormalBehaviorResult(result)
		checkNormalBehaviorOwnership(t, provider, source.closeCalls)
	})

	t.Run("record source fault remains input failure and never publishes", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		structure := probeNormalBehavior(t, bytes.NewReader(volume), int64(len(volume)))
		candidate, ok := structure.CandidateAt(0)
		if !ok {
			t.Fatal("Probe(TEST ONLY source-fault volume) returned no primary candidate")
		}
		geometry := requireNormalBehaviorGeometry(t, structure)
		first, err := expectedRecord(candidate.core, geometry, 0)
		if err != nil {
			t.Fatalf("locate TEST ONLY record source-fault range: %v", err)
		}
		source := &normalFaultReaderAt{
			reader: bytes.NewReader(volume), offset: first.descriptorOffset,
			length: int(recordDescriptorSize), occurrence: 1,
		}
		sink := &normalFixtureSink{}
		result, completion, provider := runNormalBehaviorRead(
			t, context.Background(), fixture, source, int64(len(volume)), sink,
		)
		checkNormalBehaviorResult(
			t, result, OutcomeOperationFailed, StageInputIO, 2, CodeOperationFailed,
		)
		checkNormalBehaviorCompletion(t, completion, false)
		checkNormalBehaviorDiscarded(t, sink, nil, 0)
		closeNormalBehaviorResult(result)
		checkNormalBehaviorOwnership(t, provider, source.closeCalls)
	})

	t.Run("sink write fault remains output failure and discards staging", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		source := &normalBorrowedSource{reader: bytes.NewReader(volume)}
		sink := &normalFailingSink{}
		result, completion, provider := runNormalBehaviorRead(
			t, context.Background(), fixture, source, int64(len(volume)), sink,
		)
		checkNormalBehaviorResult(
			t, result, OutcomeOperationFailed, StageOutputWrite, 2, CodeOperationFailed,
		)
		checkNormalBehaviorCompletion(t, completion, false)
		checkNormalBehaviorDiscarded(t, &sink.normalFixtureSink, nil, 0)
		if sink.calls != 1 {
			t.Errorf("sink write calls = %d; want the first verified record boundary", sink.calls)
		}
		closeNormalBehaviorResult(result)
		checkNormalBehaviorOwnership(t, provider, source.closeCalls)
	})

	t.Run("sink panic after staging aborts and preserves original panic", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		source := &normalBorrowedSource{reader: bytes.NewReader(volume)}
		structure := probeNormalBehavior(t, source, int64(len(volume)))
		provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
		t.Cleanup(func() {
			if provider.closeCalls == 0 {
				provider.close()
			}
		})
		panicValue := &struct{ label string }{label: "TEST ONLY sink panic"}
		sink := &normalPanicSink{panicValue: panicValue}
		var result *normalReadResult
		var completion *normalCompletion
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			result, completion = readNormalVolumeWithProvider(
				context.Background(), source, int64(len(volume)), structure, provider, sink,
			)
		}()
		if recovered != panicValue {
			t.Errorf("sink panic = %#v; want original %#v", recovered, panicValue)
		}
		if result != nil || completion != nil {
			t.Errorf("sink panic returned result/completion = %v/%v; want neither", result, completion)
		}
		plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
		checkNormalBehaviorDiscarded(t, &sink.normalFixtureSink, plaintext, 1)
		closeNormalBehaviorResult(result)
		checkNormalBehaviorOwnership(t, provider, source.closeCalls)
	})
}

func TestNormalReaderSemanticAuthorityFromFrozenFixtures(t *testing.T) {
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	tests := []struct {
		fixtureID   string
		outcome     Outcome
		stage       Stage
		archiveSeal bool
	}{
		{
			fixtureID: normalArchiveFixtureID,
			outcome:   OutcomeSuccess, stage: StageNone, archiveSeal: true,
		},
		{
			fixtureID: "normal-degraded-capsule",
			outcome:   OutcomeAuthenticatedDegraded, stage: StageCapsuleRS,
		},
		{
			fixtureID: "normal-degraded-metadata",
			outcome:   OutcomeAuthenticatedDegraded, stage: StageMetadata,
		},
		{
			fixtureID: "normal-degraded-trailer",
			outcome:   OutcomeAuthenticatedDegraded, stage: StageTailGeometry,
		},
	}

	for _, test := range tests {
		t.Run(test.fixtureID, func(t *testing.T) {
			fixture := requireNormalFixture(t, fixtures, test.fixtureID)
			volume := readNormalFixtureArtifact(t, fixture.Volume)
			source := newNormalFixtureSource(t, fixture, volume)
			sink := &normalFixtureSink{}
			result, completion, _ := runNormalBehaviorRead(
				t, context.Background(), fixture, source, int64(len(volume)), sink,
			)
			if result == nil || completion == nil {
				t.Fatalf("reader result/completion = %v/%v; want authenticated semantic state", result, completion)
			}
			t.Cleanup(result.Close)

			semantic, err := newRecoveryResultFromNormal(result)
			if err != nil {
				t.Fatalf("adapt real normal-reader result: %v", err)
			}
			t.Cleanup(semantic.Close)
			if semantic.Outcome() != test.outcome || semantic.Stage() != test.stage ||
				semantic.ForceProvenance() != ForceProvenanceNone || semantic.Code() != result.Code() {
				t.Fatalf(
					"semantic result = %v/%v/%v/%v; want %v/%v/no Force/%v",
					semantic.Outcome(), semantic.Stage(), semantic.ForceProvenance(), semantic.Code(),
					test.outcome, test.stage, result.Code(),
				)
			}

			kind, archiveAuthorized := completion.authenticatedPayloadKind()
			gotArchiveSeal := archiveAuthorized && kind == PayloadKindArchive
			if gotArchiveSeal != test.archiveSeal {
				t.Fatalf(
					"archive authority = %v/%v; want archive seal %v for semantic outcome %v",
					archiveAuthorized, kind, test.archiveSeal, semantic.Outcome(),
				)
			}
		})
	}
}

func runNormalBehaviorRead(
	t *testing.T,
	ctx context.Context,
	fixture normalFixture,
	source io.ReaderAt,
	sourceSize int64,
	sink normalVolumeSink,
) (*normalReadResult, *normalCompletion, *normalFixtureCredentialProvider) {
	t.Helper()
	structure := probeNormalBehavior(t, source, sourceSize)
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	t.Cleanup(func() {
		if provider.closeCalls == 0 {
			provider.close()
		}
	})
	result, completion := readNormalVolumeWithProvider(
		ctx, source, sourceSize, structure, provider, sink,
	)
	return result, completion, provider
}

func probeNormalBehavior(t *testing.T, source io.ReaderAt, sourceSize int64) Structure {
	t.Helper()
	route, structure, err := Probe(source, sourceSize)
	if err != nil || route != RouteNormalPCV {
		t.Fatalf("Probe(TEST ONLY behavioral source) = %v, %v; want normal PCV admission", route, err)
	}
	return structure
}

func requireNormalBehaviorGeometry(t *testing.T, structure Structure) Geometry {
	t.Helper()
	geometry, ok := structure.GeometryAt(0)
	if !ok {
		t.Fatal("Probe(TEST ONLY behavioral source) returned no primary geometry")
	}
	return geometry
}

func applyNormalFrozenXOR(t *testing.T, data []byte, mutations []normalFixtureMutation) {
	t.Helper()
	if len(mutations) == 0 {
		t.Fatal("TEST ONLY frozen XOR mutation set is empty")
	}
	for _, mutation := range mutations {
		if mutation.Kind != "already-applied-xor" {
			t.Fatalf("unsupported TEST ONLY mutation %q kind %q", mutation.Name, mutation.Kind)
		}
		masks, err := hex.DecodeString(mutation.XORMasksHex)
		if err != nil || len(masks) != len(mutation.Offsets) {
			t.Fatalf(
				"decode TEST ONLY mutation %q masks: bytes %d, offsets %d, error %v",
				mutation.Name, len(masks), len(mutation.Offsets), err,
			)
		}
		for index, offset := range mutation.Offsets {
			if offset < 0 || offset >= int64(len(data)) {
				t.Fatalf("TEST ONLY mutation %q offset %d outside %d-byte volume", mutation.Name, offset, len(data))
			}
			data[offset] ^= masks[index]
		}
	}
}

func normalBehaviorRecordExtent(
	t *testing.T,
	record recordExpectation,
	volumeLength int,
) (int, int) {
	t.Helper()
	start := int(record.descriptorOffset)
	end := int(record.bodyOffset) + record.encodedBodyLength
	if start < 0 || end < start || end > volumeLength {
		t.Fatalf("TEST ONLY record fault range [%d,%d) outside %d-byte volume", start, end, volumeLength)
	}
	return start, end
}

func insertNormalBehaviorBytes(t *testing.T, data []byte, offset int64, inserted []byte) []byte {
	t.Helper()
	if offset < 0 || offset > int64(len(data)) {
		t.Fatalf("TEST ONLY insertion offset %d outside %d-byte volume", offset, len(data))
	}
	result := make([]byte, 0, len(data)+len(inserted))
	result = append(result, data[:offset]...)
	result = append(result, inserted...)
	result = append(result, data[offset:]...)
	return result
}

func checkNormalBehaviorResult(
	t *testing.T,
	result *normalReadResult,
	wantOutcome Outcome,
	wantStage Stage,
	wantAuthenticated int,
	wantCode Code,
) {
	t.Helper()
	if result == nil {
		t.Error("normal reader returned no typed result")
		return
	}
	if result.Outcome() != wantOutcome || result.Stage() != wantStage ||
		result.AuthenticatedCapsules() != wantAuthenticated || result.Code() != wantCode {
		t.Errorf(
			"normal result = %v/%v/%d/%v; want %v/%v/%d/%v",
			result.Outcome(), result.Stage(), result.AuthenticatedCapsules(), result.Code(),
			wantOutcome, wantStage, wantAuthenticated, wantCode,
		)
	}
}

func checkNormalBehaviorCompletion(t *testing.T, completion *normalCompletion, want bool) {
	t.Helper()
	if (completion != nil) != want {
		t.Errorf("sealed completion present = %v; want %v", completion != nil, want)
	}
}

func checkNormalBehaviorDiscarded(
	t *testing.T,
	sink *normalFixtureSink,
	wantPrefix []byte,
	wantRecords int,
) {
	t.Helper()
	wantDigest := sha256.Sum256(wantPrefix)
	digestMatches := sink.preAbortPlaintextSHA256Set &&
		sink.preAbortPlaintextSHA256 == wantDigest
	if !sink.aborted || sink.records != nil || !sink.stagedBytesAreZero() ||
		sink.preAbortPlaintextLen != len(wantPrefix) ||
		sink.preAbortRecordCount != wantRecords || !digestMatches {
		t.Errorf(
			"failed session sink = aborted %v, live records %d, staged %d bytes/%d records, exact prefix %v, zeroed %v; want discarded exact %d-byte/%d-record fixture prefix",
			sink.aborted, len(sink.records), sink.preAbortPlaintextLen,
			sink.preAbortRecordCount, digestMatches, sink.stagedBytesAreZero(),
			len(wantPrefix), wantRecords,
		)
		if !sink.aborted {
			sink.abortUncommitted()
		}
	}
}

func checkNormalBehaviorOwnership(
	t *testing.T,
	provider *normalFixtureCredentialProvider,
	sourceCloseCalls int,
) {
	t.Helper()
	if provider.closeCalls != 1 {
		t.Errorf("literal credential-provider close calls = %d; want one", provider.closeCalls)
	}
	if sourceCloseCalls != 0 {
		t.Errorf("borrowed source close calls = %d; want zero", sourceCloseCalls)
	}
}

func closeNormalBehaviorResult(result *normalReadResult) {
	if result != nil {
		result.Close()
	}
}
