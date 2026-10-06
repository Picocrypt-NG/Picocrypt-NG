package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const (
	recordFixtureRoot        = "testdata/records"
	literalMaximumRecordBody = 1_114_248
)

type requiredRecordFixture struct {
	name            string
	suite           uint16
	payloadBodyRS   bool
	plaintextLength uint64
	recordCount     uint64
}

var requiredBoundaryRecordFixtures = [...]requiredRecordFixture{
	{name: "empty_standard_no_rs", suite: 1, plaintextLength: 0, recordCount: 0},
	{name: "one_paranoid_no_rs", suite: 2, plaintextLength: 1, recordCount: 1},
	{name: "minus_one_standard_rs", suite: 1, payloadBodyRS: true, plaintextLength: 1_048_575, recordCount: 1},
	{name: "exact_one_paranoid_rs", suite: 2, payloadBodyRS: true, plaintextLength: 1_048_576, recordCount: 1},
	{name: "plus_one_standard_no_rs", suite: 1, plaintextLength: 1_048_577, recordCount: 2},
	{name: "exact_two_paranoid_rs", suite: 2, payloadBodyRS: true, plaintextLength: 2_097_152, recordCount: 2},
}

type recordFixtureRecord struct {
	Index                uint64 `json:"index"`
	Final                bool   `json:"final"`
	PlaintextLength      int    `json:"plaintext_length"`
	DescriptorOffset     uint64 `json:"descriptor_offset"`
	BodyOffset           uint64 `json:"body_offset"`
	EncodedBodyLength    uint64 `json:"encoded_body_length"`
	DescriptorDecodedHex string `json:"descriptor_decoded_hex"`
	DescriptorEncodedHex string `json:"descriptor_encoded_hex"`
	NonceHex             string `json:"nonce_hex"`
	SerpentIVHex         string `json:"serpent_iv_hex"`
	CiphertextFile       string `json:"ciphertext_file"`
	TagFile              string `json:"tag_file"`
	BodyFile             string `json:"body_file"`
	CiphertextSHA256     string `json:"ciphertext_sha256"`
	TagHex               string `json:"tag_hex"`
}

type recordFixtureCase struct {
	Name              string                `json:"name"`
	Suite             uint16                `json:"suite"`
	PayloadBodyRS     bool                  `json:"payload_body_rs"`
	PatternMul        byte                  `json:"pattern_mul"`
	PatternAdd        byte                  `json:"pattern_add"`
	PlaintextLength   uint64                `json:"plaintext_length"`
	RecordCount       uint64                `json:"record_count"`
	FrontHeaderLength uint64                `json:"front_header_length"`
	PayloadLength     uint64                `json:"payload_length"`
	CanonicalFileSize uint64                `json:"canonical_file_size"`
	CoreFile          string                `json:"core_file"`
	KeysFile          string                `json:"keys_file"`
	PlaintextFile     string                `json:"plaintext_file"`
	PlaintextSHA256   string                `json:"plaintext_sha256"`
	Records           []recordFixtureRecord `json:"records"`
}

type recordFixtureManifest struct {
	Format string              `json:"format"`
	Cases  []recordFixtureCase `json:"cases"`
}

type recordReadSpan struct {
	offset    int64
	requested int
	delivered int
}

type recordTrackingReader struct {
	base       int64
	data       []byte
	maxChunk   int
	failOffset int64
	failErr    error
	spans      []recordReadSpan
}

func (reader *recordTrackingReader) ReadAt(destination []byte, offset int64) (int, error) {
	requested := len(destination)
	if reader.failErr != nil && offset >= reader.failOffset {
		reader.spans = append(reader.spans, recordReadSpan{offset: offset, requested: requested})
		return 0, reader.failErr
	}
	if offset < reader.base {
		reader.spans = append(reader.spans, recordReadSpan{offset: offset, requested: requested})
		return 0, io.EOF
	}
	relative := offset - reader.base
	if relative >= int64(len(reader.data)) {
		reader.spans = append(reader.spans, recordReadSpan{offset: offset, requested: requested})
		return 0, io.EOF
	}
	limit := requested
	if reader.maxChunk > 0 && limit > reader.maxChunk {
		limit = reader.maxChunk
	}
	remaining := len(reader.data) - int(relative)
	if limit > remaining {
		limit = remaining
	}
	count := copy(destination[:limit], reader.data[relative:int(relative)+limit])
	reader.spans = append(reader.spans, recordReadSpan{
		offset:    offset,
		requested: requested,
		delivered: count,
	})
	if count < requested && int(relative)+count == len(reader.data) {
		return count, io.EOF
	}
	return count, nil
}

type recordCollectingSink struct {
	indexes  []uint64
	copied   []byte
	borrowed [][]byte
	failAt   int
	failErr  error
}

func (sink *recordCollectingSink) writeVerifiedRecord(
	ctx context.Context,
	index uint64,
	plaintext []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sink.borrowed = append(sink.borrowed, plaintext)
	if sink.failErr != nil && len(sink.indexes) == sink.failAt {
		return sink.failErr
	}
	sink.indexes = append(sink.indexes, index)
	sink.copied = append(sink.copied, plaintext...)
	return nil
}

func (sink *recordCollectingSink) assertBorrowsCleared(t *testing.T) {
	t.Helper()
	for index, borrowed := range sink.borrowed {
		if !allRecordBytesZero(borrowed) {
			t.Fatalf("sink plaintext borrow %d retained nonzero bytes after record engine return", index)
		}
	}
}

type recordLiteralKeyBorrower struct {
	keys     map[pcv3credential.KeyRequest][32]byte
	requests []pcv3credential.KeyRequest
}

func (borrower *recordLiteralKeyBorrower) withKey(
	ctx context.Context,
	request pcv3credential.KeyRequest,
	callback func([]byte) error,
) error {
	if borrower == nil || ctx == nil || callback == nil {
		return errors.New("TEST ONLY invalid record key borrow")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	borrower.requests = append(borrower.requests, request)
	key, ok := borrower.keys[request]
	if !ok {
		return errors.New("TEST ONLY unknown record key request")
	}
	defer pcv3crypto.SecureZero(key[:])
	return callback(key[:])
}

func (borrower *recordLiteralKeyBorrower) close() {
	if borrower == nil {
		return
	}
	for request, key := range borrower.keys {
		pcv3crypto.SecureZero(key[:])
		delete(borrower.keys, request)
	}
}

func TestExpectedRecord(t *testing.T) {
	manifest := loadRecordFixtureManifest(t)
	for _, required := range requiredBoundaryRecordFixtures {
		fixture := requiredBoundaryRecordFixture(t, manifest, required)
		t.Run(fixture.Name, func(t *testing.T) {
			core := loadRecordFixtureCore(t, fixture)
			geometry := recordFixtureGeometry(t, fixture, core)
			plaintextOffset := uint64(0)
			for _, literal := range fixture.Records {
				got, err := expectedRecord(core, geometry, literal.Index)
				if err != nil {
					t.Fatalf("expectedRecord(%d): %v", literal.Index, err)
				}
				wantDescriptor := recordFixtureHex(t, literal.DescriptorDecodedHex)
				wantNonce := recordFixtureHex(t, literal.NonceHex)
				wantIV := recordFixtureHex(t, literal.SerpentIVHex)
				if got.index != literal.Index || got.final != literal.Final ||
					got.plaintextOffset != plaintextOffset ||
					got.ciphertextLength != uint64(literal.PlaintextLength) ||
					!bytes.Equal(got.descriptor[:], wantDescriptor) ||
					got.descriptorOffset != int64(fixture.FrontHeaderLength+literal.DescriptorOffset) ||
					got.bodyOffset != int64(fixture.FrontHeaderLength+literal.BodyOffset) ||
					got.encodedBodyLength != int(literal.EncodedBodyLength) ||
					!bytes.Equal(got.nonce[:], wantNonce) ||
					!bytes.Equal(got.serpentIV[:], wantIV) {
					t.Fatalf("expectedRecord(%d) = %+v; want literal descriptor/geometry/nonce/IV from fixture", literal.Index, got)
				}
				plaintextOffset += uint64(literal.PlaintextLength)
			}
			if _, err := expectedRecord(core, geometry, fixture.RecordCount+1); err == nil {
				t.Fatal("expectedRecord accepted an index after the mandatory final record")
			}
		})
	}

	fixture := recordFixtureByName(t, manifest, "one_paranoid_no_rs")
	core := loadRecordFixtureCore(t, fixture)
	overflowGeometry := Geometry{
		payloadBodyRS:       false,
		recordCount:         1,
		frontHeaderLength:   math.MaxInt64,
		payloadLength:       225,
		backupCapsuleOffset: math.MaxInt64,
	}
	if _, err := expectedRecord(core, overflowGeometry, 0); err == nil {
		t.Fatal("expectedRecord accepted a body offset beyond signed host representation")
	}
	core.recordCount = maximumRecordCount
	if _, err := expectedRecord(core, Geometry{}, maximumRecordCount); err == nil {
		t.Fatal("expectedRecord accepted the forbidden 2^48 record index")
	}
}

func TestReadNormalRecords(t *testing.T) {
	manifest := loadRecordFixtureManifest(t)
	codecs := recordTestCodecs(t)
	for _, required := range requiredBoundaryRecordFixtures {
		fixture := requiredBoundaryRecordFixture(t, manifest, required)
		t.Run(fixture.Name, func(t *testing.T) {
			payload := assembleRecordFixturePayload(t, fixture)
			plaintext := recordFixturePlaintext(t, fixture)
			auth, borrower := recordFixtureAuthority(t, fixture)
			defer borrower.close()
			defer auth.Close()
			reader := &recordTrackingReader{
				base:     int64(fixture.FrontHeaderLength),
				data:     payload,
				maxChunk: 32_749,
			}
			sink := &recordCollectingSink{}
			verified, err := readNormalRecords(context.Background(), reader, auth, codecs, sink)
			if err != nil {
				t.Fatalf("readNormalRecords: %v", err)
			}
			if verified.dataRecords != fixture.RecordCount ||
				verified.plaintextBytes != fixture.PlaintextLength {
				t.Fatalf("record verification = %+v; want %d records/%d bytes", verified, fixture.RecordCount, fixture.PlaintextLength)
			}
			if !bytes.Equal(sink.copied, plaintext) {
				t.Fatalf("verified plaintext differs from independent literal: got %d bytes, want %d", len(sink.copied), len(plaintext))
			}
			if len(sink.indexes) != int(fixture.RecordCount) {
				t.Fatalf("sink writes = %d; want one per %d data records", len(sink.indexes), fixture.RecordCount)
			}
			for index, got := range sink.indexes {
				if got != uint64(index) {
					t.Fatalf("sink index %d = %d; want %d", index, got, index)
				}
			}
			requireRecordKeyBorrows(t, borrower, Suite(required.suite))
			assertRecordReadBounds(t, reader, fixture)
			sink.assertBorrowsCleared(t)
		})
	}

	retry := recordFixtureByName(t, manifest, "retry_standard_rs")
	plaintext := recordFixturePlaintext(t, retry)
	t.Run("descriptor RS16 repairs at budget", func(t *testing.T) {
		auth, borrower := recordFixtureAuthority(t, retry)
		defer borrower.close()
		defer auth.Close()
		sink := &recordCollectingSink{}
		verified, err := readNormalRecords(
			context.Background(),
			&recordTrackingReader{base: int64(retry.FrontHeaderLength), data: recordMutationFile(t, "descriptor_repair_16.bin")},
			auth,
			codecs,
			sink,
		)
		if err != nil || verified.dataRecords != 1 || !bytes.Equal(sink.copied, plaintext) {
			t.Fatalf("correctable descriptor result = %+v, err %v, plaintext %x", verified, err, sink.copied)
		}
		requireRecordKeyBorrows(t, borrower, SuiteStandard)
		sink.assertBorrowsCleared(t)
	})

	t.Run("descriptor beyond RS16 budget fails before body read", func(t *testing.T) {
		auth, borrower := recordFixtureAuthority(t, retry)
		defer borrower.close()
		defer auth.Close()
		seams := defaultRecordEngineSeams()
		decryptCalls := 0
		realDecrypt := seams.decryptStandard
		seams.decryptStandard = func(destination, source, key, nonce []byte) error {
			decryptCalls++
			return realDecrypt(destination, source, key, nonce)
		}
		reader := &recordTrackingReader{base: int64(retry.FrontHeaderLength), data: recordMutationFile(t, "descriptor_damage_33.bin")}
		sink := &recordCollectingSink{}
		verified, err := readNormalRecordsWithSeams(context.Background(), reader, auth, codecs, sink, seams)
		requireRecordFailureStage(t, err, StageDescriptor)
		if verified != (recordVerification{}) || len(sink.indexes) != 0 || len(reader.spans) == 0 {
			t.Fatalf("uncorrectable descriptor produced verification/sink or no real read: %+v/%v/%v", verified, sink.indexes, reader.spans)
		}
		if decryptCalls != 0 {
			t.Fatalf("uncorrectable descriptor reached decrypt %d times", decryptCalls)
		}
		requireRecordKeyBorrows(t, borrower, SuiteStandard)
		for _, span := range reader.spans {
			if span.offset+int64(span.delivered) > int64(retry.FrontHeaderLength)+48 {
				t.Fatalf("descriptor failure reached body at span %+v", span)
			}
		}
	})

	t.Run("re-encoded attacker length cannot control body geometry", func(t *testing.T) {
		auth, borrower := recordFixtureAuthority(t, retry)
		defer borrower.close()
		defer auth.Close()
		seams := defaultRecordEngineSeams()
		decryptCalls := 0
		realDecrypt := seams.decryptStandard
		seams.decryptStandard = func(destination, source, key, nonce []byte) error {
			decryptCalls++
			return realDecrypt(destination, source, key, nonce)
		}
		reader := &recordTrackingReader{base: int64(retry.FrontHeaderLength), data: recordMutationFile(t, "descriptor_wrong_length.bin")}
		sink := &recordCollectingSink{}
		verified, err := readNormalRecordsWithSeams(context.Background(), reader, auth, codecs, sink, seams)
		requireRecordFailureStage(t, err, StageDescriptor)
		if verified != (recordVerification{}) || len(sink.indexes) != 0 {
			t.Fatalf("attacker descriptor produced verification/sink: %+v/%v", verified, sink.indexes)
		}
		if decryptCalls != 0 {
			t.Fatalf("attacker descriptor reached decrypt %d times", decryptCalls)
		}
		requireRecordKeyBorrows(t, borrower, SuiteStandard)
		for _, span := range reader.spans {
			if span.offset+int64(span.delivered) > int64(retry.FrontHeaderLength)+48 {
				t.Fatalf("attacker descriptor selected a body read: %+v", span)
			}
		}
	})

	t.Run("source error has no completion or plaintext", func(t *testing.T) {
		auth, borrower := recordFixtureAuthority(t, retry)
		defer borrower.close()
		defer auth.Close()
		payload := recordMutationFile(t, "retry_base.bin")
		sourceFailure := errors.New("TEST ONLY record source failure")
		reader := &recordTrackingReader{
			base:       int64(retry.FrontHeaderLength),
			data:       payload,
			failOffset: int64(retry.FrontHeaderLength) + 48,
			failErr:    sourceFailure,
		}
		sink := &recordCollectingSink{}
		verified, err := readNormalRecords(context.Background(), reader, auth, codecs, sink)
		requireRecordFailureStage(t, err, StageInputIO)
		if !errors.Is(err, sourceFailure) || verified != (recordVerification{}) || len(sink.indexes) != 0 {
			t.Fatalf("source failure result = %+v/%v/%v", verified, err, sink.indexes)
		}
	})

	t.Run("cancellation before read has no completion", func(t *testing.T) {
		auth, borrower := recordFixtureAuthority(t, retry)
		defer borrower.close()
		defer auth.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		reader := &recordTrackingReader{base: int64(retry.FrontHeaderLength), data: recordMutationFile(t, "retry_base.bin")}
		verified, err := readNormalRecords(ctx, reader, auth, codecs, &recordCollectingSink{})
		requireRecordFailureStage(t, err, StageCancellation)
		if verified != (recordVerification{}) || len(reader.spans) != 0 {
			t.Fatalf("pre-cancel result = %+v with %d reads", verified, len(reader.spans))
		}
	})

	t.Run("sink failure clears plaintext and withholds completion", func(t *testing.T) {
		auth, borrower := recordFixtureAuthority(t, retry)
		defer borrower.close()
		defer auth.Close()
		sinkFailure := errors.New("TEST ONLY sink failure")
		sink := &recordCollectingSink{failAt: 0, failErr: sinkFailure}
		verified, err := readNormalRecords(
			context.Background(),
			&recordTrackingReader{base: int64(retry.FrontHeaderLength), data: recordMutationFile(t, "retry_base.bin")},
			auth,
			codecs,
			sink,
		)
		requireRecordFailureStage(t, err, StageOutputWrite)
		if !errors.Is(err, sinkFailure) || verified != (recordVerification{}) || len(sink.indexes) != 0 {
			t.Fatalf("sink failure result = %+v/%v/%v", verified, err, sink.indexes)
		}
		sink.assertBorrowsCleared(t)
	})
}

func TestRecordAuthBeforeDecrypt(t *testing.T) {
	manifest := loadRecordFixtureManifest(t)
	fixture := recordFixtureByName(t, manifest, "retry_standard_rs")
	auth, borrower := recordFixtureAuthority(t, fixture)
	defer borrower.close()
	defer auth.Close()
	codecs := recordTestCodecs(t)
	seams := defaultRecordEngineSeams()
	decryptCalls := 0
	realDecrypt := seams.decryptStandard
	seams.decryptStandard = func(destination, source, key, nonce []byte) error {
		decryptCalls++
		return realDecrypt(destination, source, key, nonce)
	}
	sink := &recordCollectingSink{}
	reader := &recordTrackingReader{
		base: int64(fixture.FrontHeaderLength),
		data: recordMutationFile(t, "body_bad_tag_reencoded.bin"),
	}
	verified, err := readNormalRecordsWithSeams(
		context.Background(),
		reader,
		auth,
		codecs,
		sink,
		seams,
	)
	requireRecordFailureStage(t, err, StageRecordAuth)
	if decryptCalls != 0 || len(sink.indexes) != 0 || verified != (recordVerification{}) {
		t.Fatalf("bad tag reached decrypt/sink/completion: decrypt=%d sink=%v verified=%+v", decryptCalls, sink.indexes, verified)
	}
	requireRecordKeyBorrows(t, borrower, SuiteStandard)
	// The unauthenticated candidate may cost exactly one descriptor read and
	// one body read of the frozen first record; no byte of any later record
	// may be touched and no retry may reread the source.
	requireRecordReadSpans(t, reader, []recordReadSpan{
		{
			offset:    int64(fixture.FrontHeaderLength + fixture.Records[0].DescriptorOffset),
			requested: int(recordDescriptorSize),
			delivered: int(recordDescriptorSize),
		},
		{
			offset:    int64(fixture.FrontHeaderLength + fixture.Records[0].BodyOffset),
			requested: int(fixture.Records[0].EncodedBodyLength),
			delivered: int(fixture.Records[0].EncodedBodyLength),
		},
	})
}

func TestCanonicalRecordEvaluatorRecoveryAuthority(t *testing.T) {
	manifest := loadRecordFixtureManifest(t)
	fixture := recordFixtureByName(t, manifest, "retry_standard_rs")
	auth, borrower := recordFixtureAuthority(t, fixture)
	defer borrower.close()
	defer auth.Close()
	core, geometry, ok := authenticatedRecordAuthority(auth)
	if !ok {
		t.Fatal("independent fixture did not produce authenticated record authority")
	}

	seams := defaultRecordEngineSeams()
	decryptCalls := 0
	realDecrypt := seams.decryptStandard
	seams.decryptStandard = func(destination, source, key, nonce []byte) error {
		decryptCalls++
		return realDecrypt(destination, source, key, nonce)
	}
	evaluator, err := newRecordEvaluator(
		context.Background(),
		&recordTrackingReader{
			base: int64(fixture.FrontHeaderLength),
			data: recordMutationFile(t, "body_bad_tag_reencoded.bin"),
		},
		core,
		geometry,
		recordTestCodecs(t),
		auth,
		seams,
	)
	if err != nil {
		t.Fatalf("newRecordEvaluator: %v", err)
	}
	defer evaluator.close()

	callbackCalls := 0
	assertDenied := func(name string, request recoveryRequest, role CapsuleRole) {
		t.Helper()
		err := evaluator.evaluateCanonicalRecord(
			0,
			request,
			role,
			func(recordEvidence, []byte) error {
				callbackCalls++
				return nil
			},
		)
		requireRecordFailureStage(t, err, StageRecordAuth)
		if decryptCalls != 0 || callbackCalls != 0 {
			t.Fatalf("%s authority reached decrypt/callback: decrypt=%d callback=%d", name, decryptCalls, callbackCalls)
		}
	}

	assertDenied("zero", recoveryRequest{}, CapsuleRolePrimary)
	ordinary, err := newRecoveryRequest(RecoveryModeForce)
	if err != nil {
		t.Fatalf("newRecoveryRequest(Force): %v", err)
	}
	assertDenied("ordinary Force", ordinary, CapsuleRolePrimary)

	var expired recoveryRequest
	if err := withUnverifiedRecoveryRequest(CapsuleRolePrimary, func(request recoveryRequest) error {
		expired = request
		return nil
	}); err != nil {
		t.Fatalf("capture expiring recovery request: %v", err)
	}
	assertDenied("expired unverified", expired, CapsuleRolePrimary)

	if err := withUnverifiedRecoveryRequest(CapsuleRoleBackup, func(request recoveryRequest) error {
		assertDenied("wrong role", request, CapsuleRolePrimary)
		return nil
	}); err != nil {
		t.Fatalf("wrong-role recovery request: %v", err)
	}

	wantPlaintext := recordFixturePlaintext(t, fixture)
	var retained []byte
	var copied []byte
	var evidence recordEvidence
	err = withUnverifiedRecoveryRequest(CapsuleRolePrimary, func(request recoveryRequest) error {
		return evaluator.evaluateCanonicalRecord(
			0,
			request,
			CapsuleRolePrimary,
			func(got recordEvidence, plaintext []byte) error {
				callbackCalls++
				evidence = got
				retained = plaintext
				copied = append(copied, plaintext...)
				return nil
			},
		)
	})
	if err != nil {
		t.Fatalf("authorized unverified evaluation: %v", err)
	}
	if decryptCalls != 1 || callbackCalls != 1 {
		t.Fatalf("authorized unverified work = decrypt %d/callback %d; want 1/1", decryptCalls, callbackCalls)
	}
	if evidence.index != 0 || evidence.final || evidence.plaintextOffset != 0 ||
		evidence.plaintextLength != fixture.PlaintextLength ||
		evidence.authentication != recordAuthenticationUnverified {
		t.Fatalf("unverified evidence = %+v; want canonical record 0 range", evidence)
	}
	if !bytes.Equal(copied, wantPlaintext) {
		t.Fatal("authorized unverified plaintext differs from independent literal")
	}
	if len(retained) != len(wantPlaintext) || !allRecordBytesZero(retained) {
		t.Fatal("evaluator retained plaintext borrow after callback")
	}

	assertUnreadable := func(name string, payload []byte, wantStage Stage) {
		t.Helper()
		evaluator.source = &recordTrackingReader{
			base: int64(fixture.FrontHeaderLength),
			data: payload,
		}
		beforeDecrypt := decryptCalls
		beforeCallback := callbackCalls
		err := withUnverifiedRecoveryRequest(CapsuleRolePrimary, func(request recoveryRequest) error {
			return evaluator.evaluateCanonicalRecord(
				0,
				request,
				CapsuleRolePrimary,
				func(recordEvidence, []byte) error {
					callbackCalls++
					return nil
				},
			)
		})
		requireRecordFailureStage(t, err, wantStage)
		if decryptCalls != beforeDecrypt || callbackCalls != beforeCallback {
			t.Fatalf("%s reached decrypt/callback under unverified authority", name)
		}
	}
	assertUnreadable(
		"uncorrectable body",
		recordMutationFile(t, "body_damage_9.bin"),
		StageRecordBodyRS,
	)
	basePayload := recordMutationFile(t, "retry_base.bin")
	truncatedAt := fixture.Records[0].BodyOffset + fixture.Records[0].EncodedBodyLength - 1
	assertUnreadable(
		"truncated body",
		basePayload[:int(truncatedAt)],
		StageRecordBodyRS,
	)

	evaluator.source = &recordTrackingReader{
		base: int64(fixture.FrontHeaderLength),
		data: recordMutationFile(t, "body_bad_tag_reencoded.bin"),
	}
	panicValue := &struct{ label string }{label: "TEST ONLY evaluator callback panic"}
	var panicRetained []byte
	recovered := func() (recovered any) {
		defer func() {
			recovered = recover()
		}()
		_ = withUnverifiedRecoveryRequest(CapsuleRolePrimary, func(request recoveryRequest) error {
			return evaluator.evaluateCanonicalRecord(
				0,
				request,
				CapsuleRolePrimary,
				func(_ recordEvidence, plaintext []byte) error {
					callbackCalls++
					panicRetained = plaintext
					panic(panicValue)
				},
			)
		})
		return nil
	}()
	if recovered != panicValue {
		t.Fatalf("evaluator callback panic = %#v; want original %#v", recovered, panicValue)
	}
	if decryptCalls != 2 || callbackCalls != 2 ||
		len(panicRetained) != len(wantPlaintext) || !allRecordBytesZero(panicRetained) {
		t.Fatal("evaluator callback panic retained plaintext or changed callback bounds")
	}
}

func TestRecordRSRetryBound(t *testing.T) {
	manifest := loadRecordFixtureManifest(t)
	fixture := recordFixtureByName(t, manifest, "retry_standard_rs")
	codecs := recordTestCodecs(t)
	tests := []struct {
		name           string
		mutation       string
		wantStage      Stage
		wantFullPasses int
		wantDecrypt    int
		wantPlaintext  bool
	}{
		{name: "four data errors repair once", mutation: "body_repair_4.bin", wantFullPasses: 1, wantDecrypt: 1, wantPlaintext: true},
		{name: "nine data errors fail after one full pass", mutation: "body_damage_9.bin", wantStage: StageRecordBodyRS, wantFullPasses: 1},
		{name: "valid malicious tag gets no second full pass", mutation: "body_bad_tag_reencoded.bin", wantStage: StageRecordAuth, wantFullPasses: 1},
		{name: "reencoded nonzero padding fails after one full pass", mutation: "body_bad_padding_reencoded.bin", wantStage: StageRecordBodyRS, wantFullPasses: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth, borrower := recordFixtureAuthority(t, fixture)
			defer borrower.close()
			defer auth.Close()
			seams := defaultRecordEngineSeams()
			fullPasses := 0
			realDecode := seams.decodeBody
			seams.decodeBody = func(codecs *pcencoding.RSCodecs, encoded, decoded []byte, fullCorrection bool) error {
				if fullCorrection {
					fullPasses++
				}
				return realDecode(codecs, encoded, decoded, fullCorrection)
			}
			decryptCalls := 0
			realDecrypt := seams.decryptStandard
			seams.decryptStandard = func(destination, source, key, nonce []byte) error {
				decryptCalls++
				return realDecrypt(destination, source, key, nonce)
			}
			sink := &recordCollectingSink{}
			verified, err := readNormalRecordsWithSeams(
				context.Background(),
				&recordTrackingReader{base: int64(fixture.FrontHeaderLength), data: recordMutationFile(t, test.mutation)},
				auth,
				codecs,
				sink,
				seams,
			)
			if fullPasses != test.wantFullPasses {
				t.Fatalf("full RS correction passes = %d; want %d", fullPasses, test.wantFullPasses)
			}
			if decryptCalls != test.wantDecrypt {
				t.Fatalf("decrypt calls = %d; want %d", decryptCalls, test.wantDecrypt)
			}
			requireRecordKeyBorrows(t, borrower, SuiteStandard)
			if test.wantStage != StageNone {
				requireRecordFailureStage(t, err, test.wantStage)
				if verified != (recordVerification{}) || len(sink.indexes) != 0 {
					t.Fatalf("damaged body produced completion/sink: %+v/%v", verified, sink.indexes)
				}
				return
			}
			if err != nil {
				t.Fatalf("correctable body: %v", err)
			}
			want := recordFixturePlaintext(t, fixture)
			if !test.wantPlaintext || verified.dataRecords != 1 || !bytes.Equal(sink.copied, want) {
				t.Fatalf("correctable body result = %+v/plaintext %x", verified, sink.copied)
			}
			sink.assertBorrowsCleared(t)
		})
	}
}

func TestRecordRSRepairsCiphertextTagAndPadding(t *testing.T) {
	manifest := loadRecordFixtureManifest(t)
	fixture := recordFixtureByName(t, manifest, "retry_standard_rs")
	codecs := recordTestCodecs(t)
	base := recordMutationFile(t, "retry_base.bin")
	wantPlaintext := recordFixturePlaintext(t, fixture)
	// The frozen data record has 65 ciphertext bytes and a 64-byte tag:
	// its padding begins at byte 1 of the second 136-byte codeword. The
	// final record has only its 64-byte tag, followed by padding.
	tests := []struct {
		name    string
		record  int
		offsets []int
	}{
		{name: "frozen undamaged payload"},
		{name: "data ciphertext symbol", offsets: []int{0}},
		{name: "data tag symbol", offsets: []int{65}},
		{name: "data padding symbol", offsets: []int{137}},
		{name: "data padding correction budget", offsets: []int{137, 138, 139, 140}},
		{name: "final tag symbol", record: 1, offsets: []int{0}},
		{name: "final padding symbol", record: 1, offsets: []int{64}},
		{name: "final padding correction budget", record: 1, offsets: []int{64, 65, 66, 67}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := bytes.Clone(base)
			bodyOffset := int(fixture.Records[test.record].BodyOffset)
			for _, offset := range test.offsets {
				payload[bodyOffset+offset] ^= 1
			}
			auth, borrower := recordFixtureAuthority(t, fixture)
			defer borrower.close()
			defer auth.Close()
			seams := defaultRecordEngineSeams()
			fullPasses := 0
			realDecode := seams.decodeBody
			seams.decodeBody = func(codecs *pcencoding.RSCodecs, encoded, decoded []byte, fullCorrection bool) error {
				if fullCorrection {
					fullPasses++
				}
				return realDecode(codecs, encoded, decoded, fullCorrection)
			}
			sink := &recordCollectingSink{}
			verified, err := readNormalRecordsWithSeams(
				context.Background(),
				&recordTrackingReader{base: int64(fixture.FrontHeaderLength), data: payload},
				auth,
				codecs,
				sink,
				seams,
			)
			if err != nil {
				t.Fatalf("correctable record failed authentication: %v", err)
			}
			if verified != (recordVerification{dataRecords: 1, plaintextBytes: 65}) ||
				!slices.Equal(sink.indexes, []uint64{0}) || !bytes.Equal(sink.copied, wantPlaintext) {
				t.Fatalf("correctable record changed frozen plaintext or completion: %+v/%v", verified, sink.indexes)
			}
			wantFullPasses := 0
			if len(test.offsets) != 0 {
				wantFullPasses = 1
			}
			if fullPasses != wantFullPasses {
				t.Fatalf("full RS correction passes = %d; want %d", fullPasses, wantFullPasses)
			}
			sink.assertBorrowsCleared(t)
		})
	}
}

func TestRecordRSInvalidPaddingCannotReachPlaintextOrFinalCallback(t *testing.T) {
	manifest := loadRecordFixtureManifest(t)
	fixture := recordFixtureByName(t, manifest, "retry_standard_rs")
	codecs := recordTestCodecs(t)
	tests := []struct {
		name         string
		record       uint64
		paddingStart int
		reencode     bool
		wantStage    Stage
	}{
		{name: "data reencoded padding", paddingStart: 137, reencode: true, wantStage: StageRecordBodyRS},
		{name: "data uncorrectable padding", paddingStart: 137, wantStage: StageRecordBodyRS},
		{name: "final reencoded padding", record: 1, paddingStart: 64, reencode: true, wantStage: StageFinalRecord},
		{name: "final uncorrectable padding", record: 1, paddingStart: 64, wantStage: StageFinalRecord},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := recordMutationFile(t, "retry_base.bin")
			bodyOffset := int(fixture.Records[test.record].BodyOffset)
			if test.reencode {
				// A valid RS codeword containing noncanonical padding must
				// remain invalid even though the original MAC still matches.
				payload[bodyOffset+test.paddingStart] ^= 1
				blockStart := bodyOffset + test.paddingStart/136*136
				encoded, err := pcencoding.Encode(codecs.RS128, payload[blockStart:blockStart+128])
				if err != nil {
					t.Fatalf("encode invalid padding: %v", err)
				}
				copy(payload[blockStart:blockStart+136], encoded)
			} else {
				for offset := range 9 {
					payload[bodyOffset+test.paddingStart+offset] ^= 1
				}
			}
			for _, mode := range []string{"normal", "Force", "unverified Force"} {
				t.Run(mode, func(t *testing.T) {
					auth, borrower := recordFixtureAuthority(t, fixture)
					defer borrower.close()
					defer auth.Close()
					core, geometry, ok := authenticatedRecordAuthority(auth)
					if !ok {
						t.Fatal("independent fixture did not produce authenticated record authority")
					}
					seams := defaultRecordEngineSeams()
					fullPasses, decryptCalls, callbackCalls := 0, 0, 0
					realDecode := seams.decodeBody
					seams.decodeBody = func(codecs *pcencoding.RSCodecs, encoded, decoded []byte, fullCorrection bool) error {
						if fullCorrection {
							fullPasses++
						}
						return realDecode(codecs, encoded, decoded, fullCorrection)
					}
					realDecrypt := seams.decryptStandard
					seams.decryptStandard = func(destination, source, key, nonce []byte) error {
						decryptCalls++
						return realDecrypt(destination, source, key, nonce)
					}
					evaluator, err := newRecordEvaluator(
						context.Background(),
						&recordTrackingReader{base: int64(fixture.FrontHeaderLength), data: payload},
						core, geometry, codecs, auth, seams,
					)
					if err != nil {
						t.Fatalf("newRecordEvaluator: %v", err)
					}
					defer evaluator.close()
					evaluate := func(request recoveryRequest) error {
						return evaluator.evaluateCanonicalRecord(
							test.record, request, CapsuleRolePrimary,
							func(recordEvidence, []byte) error {
								callbackCalls++
								return nil
							},
						)
					}
					switch mode {
					case "normal":
						err = evaluate(recoveryRequest{})
					case "Force":
						request, requestErr := newRecoveryRequest(RecoveryModeForce)
						if requestErr != nil {
							t.Fatalf("newRecoveryRequest(Force): %v", requestErr)
						}
						err = evaluate(request)
					case "unverified Force":
						err = withUnverifiedRecoveryRequest(CapsuleRolePrimary, evaluate)
					}
					requireRecordFailureStage(t, err, test.wantStage)
					if decryptCalls != 0 || callbackCalls != 0 {
						t.Fatalf("invalid padding reached decrypt/callback: %d/%d", decryptCalls, callbackCalls)
					}
					if fullPasses != 1 {
						t.Fatalf("full RS correction passes = %d; want one bounded retry", fullPasses)
					}
				})
			}
		})
	}
}

func TestFinalRecordRequired(t *testing.T) {
	manifest := loadRecordFixtureManifest(t)
	codecs := recordTestCodecs(t)
	tests := []struct {
		name        string
		fixture     string
		payload     func(*testing.T, recordFixtureCase) []byte
		suite       Suite
		wantData    bool
		wantDecrypt int
	}{
		{
			name:    "empty payload still needs final",
			fixture: "empty_standard_no_rs",
			payload: func(*testing.T, recordFixtureCase) []byte { return nil },
			suite:   SuiteStandard,
		},
		{
			name:    "exact multiple cannot end after data record",
			fixture: "exact_one_paranoid_rs",
			payload: func(t *testing.T, fixture recordFixtureCase) []byte {
				payload := assembleRecordFixturePayload(t, fixture)
				return payload[:fixture.Records[len(fixture.Records)-1].DescriptorOffset]
			},
			suite:       SuiteParanoid,
			wantData:    true,
			wantDecrypt: 1,
		},
		{
			name:    "damaged final tag is not completion",
			fixture: "retry_standard_rs",
			payload: func(t *testing.T, _ recordFixtureCase) []byte {
				return recordMutationFile(t, "bad_final_tag_reencoded.bin")
			},
			suite:       SuiteStandard,
			wantData:    true,
			wantDecrypt: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := recordFixtureByName(t, manifest, test.fixture)
			auth, borrower := recordFixtureAuthority(t, fixture)
			defer borrower.close()
			defer auth.Close()
			seams := defaultRecordEngineSeams()
			decryptCalls := 0
			realStandard := seams.decryptStandard
			seams.decryptStandard = func(destination, source, key, nonce []byte) error {
				decryptCalls++
				return realStandard(destination, source, key, nonce)
			}
			realParanoid := seams.decryptParanoid
			seams.decryptParanoid = func(destination, source, xKey, nonce, serpentKey, iv []byte) error {
				decryptCalls++
				return realParanoid(destination, source, xKey, nonce, serpentKey, iv)
			}
			sink := &recordCollectingSink{}
			verified, err := readNormalRecordsWithSeams(
				context.Background(),
				&recordTrackingReader{base: int64(fixture.FrontHeaderLength), data: test.payload(t, fixture)},
				auth,
				codecs,
				sink,
				seams,
			)
			requireRecordFailureStage(t, err, StageFinalRecord)
			if verified != (recordVerification{}) {
				t.Fatalf("missing/damaged final produced record verification %+v", verified)
			}
			if test.wantData != (len(sink.indexes) != 0) {
				t.Fatalf("verified data staging presence = %t; want %t", len(sink.indexes) != 0, test.wantData)
			}
			if decryptCalls != test.wantDecrypt {
				t.Fatalf("decrypt calls before final failure = %d; want %d", decryptCalls, test.wantDecrypt)
			}
			requireRecordKeyBorrows(t, borrower, test.suite)
			if test.wantData {
				// Verified data records staged before the final failure must
				// be exactly the frozen plaintext prefix; partial verified
				// bytes never become completion.
				if want := recordFixturePlaintext(t, fixture); !bytes.Equal(sink.copied, want) {
					t.Fatalf("staged verified prefix = %d bytes; want exact frozen %d-byte plaintext", len(sink.copied), len(want))
				}
			}
			sink.assertBorrowsCleared(t)
		})
	}

	empty := recordFixtureByName(t, manifest, "empty_standard_no_rs")
	auth, borrower := recordFixtureAuthority(t, empty)
	defer borrower.close()
	defer auth.Close()
	sink := &recordCollectingSink{}
	verified, err := readNormalRecords(
		context.Background(),
		&recordTrackingReader{base: int64(empty.FrontHeaderLength), data: assembleRecordFixturePayload(t, empty)},
		auth,
		codecs,
		sink,
	)
	if err != nil || verified != (recordVerification{dataRecords: 0, plaintextBytes: 0}) || len(sink.indexes) != 0 {
		t.Fatalf("authenticated empty final result = %+v/%v/%v", verified, err, sink.indexes)
	}
	requireRecordKeyBorrows(t, borrower, SuiteStandard)
}

func loadRecordFixtureManifest(t *testing.T) recordFixtureManifest {
	t.Helper()
	contents := recordFixtureFile(t, "manifest.json")
	var manifest recordFixtureManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode independent record manifest: %v", err)
	}
	if manifest.Format != "PCV3 record fixtures v1" {
		t.Fatalf("independent record manifest identity = %q", manifest.Format)
	}
	return manifest
}

func recordFixtureByName(t *testing.T, manifest recordFixtureManifest, name string) recordFixtureCase {
	t.Helper()
	for _, fixture := range manifest.Cases {
		if fixture.Name == name {
			return fixture
		}
	}
	t.Fatalf("required independent record fixture %q is absent", name)
	return recordFixtureCase{}
}

func requiredBoundaryRecordFixture(
	t *testing.T,
	manifest recordFixtureManifest,
	required requiredRecordFixture,
) recordFixtureCase {
	t.Helper()
	fixture := recordFixtureByName(t, manifest, required.name)
	if fixture.Suite != required.suite ||
		fixture.PayloadBodyRS != required.payloadBodyRS ||
		fixture.PlaintextLength != required.plaintextLength ||
		fixture.RecordCount != required.recordCount {
		t.Fatalf(
			"required boundary fixture %q semantics = suite %d, RS %t, length %d, records %d; want %d/%t/%d/%d",
			fixture.Name,
			fixture.Suite,
			fixture.PayloadBodyRS,
			fixture.PlaintextLength,
			fixture.RecordCount,
			required.suite,
			required.payloadBodyRS,
			required.plaintextLength,
			required.recordCount,
		)
	}
	return fixture
}

func recordFixtureFile(t *testing.T, relative string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(recordFixtureRoot, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read independent record fixture %q: %v", relative, err)
	}
	return contents
}

func recordFixturePlaintext(t *testing.T, fixture recordFixtureCase) []byte {
	t.Helper()
	var plaintext []byte
	if fixture.PlaintextFile != "" {
		plaintext = recordFixtureFile(t, fixture.PlaintextFile)
	} else {
		if fixture.PlaintextLength > uint64(math.MaxInt) {
			t.Fatalf("fixture plaintext %q exceeds host representation", fixture.Name)
		}
		plaintext = make([]byte, int(fixture.PlaintextLength))
		for index := range plaintext {
			plaintext[index] = byte(index)*fixture.PatternMul + fixture.PatternAdd
		}
	}
	if uint64(len(plaintext)) != fixture.PlaintextLength {
		t.Fatalf("fixture plaintext %q length = %d; want %d", fixture.Name, len(plaintext), fixture.PlaintextLength)
	}
	digest := sha256.Sum256(plaintext)
	if got := hex.EncodeToString(digest[:]); got != fixture.PlaintextSHA256 {
		t.Fatalf("fixture plaintext %q SHA-256 = %s; want frozen %s", fixture.Name, got, fixture.PlaintextSHA256)
	}
	return plaintext
}

func recordMutationFile(t *testing.T, name string) []byte {
	t.Helper()
	return recordFixtureFile(t, filepath.ToSlash(filepath.Join("mutations", name)))
}

func TestCheckedRecordCiphertextLengthRejectsHostNarrowingAndSliceOverflow(t *testing.T) {
	tests := []struct {
		name                     string
		length                   uint64
		decodedLength, plainSize int
		want                     int
		wantOK                   bool
	}{
		{name: "canonical record", length: 17, decodedLength: 33, plainSize: 1 << 20, want: 17, wantOK: true},
		{name: "decoded slice overflow", length: 18, decodedLength: 17, plainSize: 1 << 20},
		{name: "plaintext scratch overflow", length: (1 << 20) + 1, decodedLength: (1 << 20) + 1, plainSize: 1 << 20},
		{name: "host integer overflow", length: math.MaxUint64, decodedLength: 33, plainSize: 1 << 20},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := checkedRecordCiphertextLength(test.length, test.decodedLength, test.plainSize)
			if got != test.want || ok != test.wantOK {
				t.Fatalf("checked ciphertext length = %d/%v; want %d/%v", got, ok, test.want, test.wantOK)
			}
		})
	}
}

func recordFixtureHex(t *testing.T, literal string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatalf("decode independent fixture hex: %v", err)
	}
	return decoded
}

func loadRecordFixtureCore(t *testing.T, fixture recordFixtureCase) logicalCore {
	t.Helper()
	encoded := recordFixtureFile(t, fixture.CoreFile)
	if len(encoded) != 96 {
		t.Fatalf("fixture core length = %d; want 96", len(encoded))
	}
	decodedCandidate := make([]byte, decodedCapsuleLength)
	copy(decodedCandidate, encoded)
	return decodeCandidate(decodedCandidate).core
}

func recordFixtureGeometry(t *testing.T, fixture recordFixtureCase, core logicalCore) Geometry {
	t.Helper()
	geometry, err := DeriveGeometry(Candidate{core: core}, fixture.CanonicalFileSize)
	if err != nil {
		t.Fatalf("derive geometry for independent fixture %q: %v", fixture.Name, err)
	}
	return geometry
}

func recordFixtureAuthority(t *testing.T, fixture recordFixtureCase) (*normalAuthResult, *recordLiteralKeyBorrower) {
	t.Helper()
	core := loadRecordFixtureCore(t, fixture)
	geometry := recordFixtureGeometry(t, fixture, core)
	keyBytes := recordFixtureFile(t, fixture.KeysFile)
	if len(keyBytes) != 96 {
		t.Fatalf("fixture key file length = %d; want 96", len(keyBytes))
	}
	borrower := &recordLiteralKeyBorrower{keys: make(map[pcv3credential.KeyRequest][32]byte)}
	add := func(label pcv3credential.KeyLabel, source []byte) {
		var key [32]byte
		copy(key[:], source)
		borrower.keys[pcv3credential.KeyRequest{
			Label:       label,
			Role:        pcv3credential.KeyRoleNotReplica,
			OutputBytes: 32,
		}] = key
	}
	add(pcv3credential.KeyLabelVolumePayloadXChaCha20, keyBytes[:32])
	if core.suite == SuiteParanoid {
		add(pcv3credential.KeyLabelVolumePayloadSerpent, keyBytes[32:64])
	}
	add(pcv3credential.KeyLabelVolumePayloadMAC, keyBytes[64:96])
	pcv3crypto.SecureZero(keyBytes)
	auth := newNormalAuthResult(OutcomeSuccess, StageNone, 1)
	auth.candidate = Candidate{core: core}
	auth.geometry = geometry
	auth.keyBorrower = borrower
	return auth, borrower
}

func assembleRecordFixturePayload(t *testing.T, fixture recordFixtureCase) []byte {
	t.Helper()
	payload := make([]byte, 0, fixture.PayloadLength)
	for _, record := range fixture.Records {
		descriptor := recordFixtureHex(t, record.DescriptorEncodedHex)
		if uint64(len(payload)) != record.DescriptorOffset || len(descriptor) != 48 {
			t.Fatalf("fixture %q record %d descriptor placement drift", fixture.Name, record.Index)
		}
		payload = append(payload, descriptor...)
		if uint64(len(payload)) != record.BodyOffset {
			t.Fatalf("fixture %q record %d body placement drift", fixture.Name, record.Index)
		}
		if fixture.PayloadBodyRS {
			payload = append(payload, recordFixtureFile(t, record.BodyFile)...)
		} else {
			payload = append(payload, recordFixtureFile(t, record.CiphertextFile)...)
			payload = append(payload, recordFixtureFile(t, record.TagFile)...)
		}
		if uint64(len(payload)) != record.BodyOffset+record.EncodedBodyLength {
			t.Fatalf("fixture %q record %d body length drift", fixture.Name, record.Index)
		}
	}
	if uint64(len(payload)) != fixture.PayloadLength {
		t.Fatalf("fixture %q payload length = %d; want %d", fixture.Name, len(payload), fixture.PayloadLength)
	}
	return payload
}

func recordTestCodecs(t *testing.T) *pcencoding.RSCodecs {
	t.Helper()
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	return codecs
}

func assertRecordReadBounds(t *testing.T, reader *recordTrackingReader, fixture recordFixtureCase) {
	t.Helper()
	if len(reader.spans) == 0 {
		t.Fatal("record engine made no source reads")
	}
	payloadEnd := int64(fixture.FrontHeaderLength + fixture.PayloadLength)
	for _, span := range reader.spans {
		if span.requested <= 0 || span.requested > literalMaximumRecordBody {
			t.Fatalf("ReaderAt requested unbounded length %d", span.requested)
		}
		if span.offset < int64(fixture.FrontHeaderLength) || span.offset+int64(span.delivered) > payloadEnd {
			t.Fatalf("ReaderAt escaped authenticated payload geometry: %+v", span)
		}
	}
}

func requireRecordFailureStage(t *testing.T, err error, want Stage) {
	t.Helper()
	var failure *recordFailure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T, want *recordFailure (err %v)", err, err)
	}
	if failure.stage != want {
		t.Fatalf("record failure stage = %v; want %v", failure.stage, want)
	}
}

// requireRecordKeyBorrows pins the exact ordered key-borrow transcript: the
// record engine must derive exactly the suite's payload keys, each exactly
// once, in the canonical label order, and nothing else.
func requireRecordKeyBorrows(t *testing.T, borrower *recordLiteralKeyBorrower, suite Suite) {
	t.Helper()
	want := []pcv3credential.KeyRequest{
		{Label: pcv3credential.KeyLabelVolumePayloadXChaCha20, Role: pcv3credential.KeyRoleNotReplica, OutputBytes: 32},
	}
	if suite == SuiteParanoid {
		want = append(want, pcv3credential.KeyRequest{
			Label: pcv3credential.KeyLabelVolumePayloadSerpent, Role: pcv3credential.KeyRoleNotReplica, OutputBytes: 32,
		})
	}
	want = append(want, pcv3credential.KeyRequest{
		Label: pcv3credential.KeyLabelVolumePayloadMAC, Role: pcv3credential.KeyRoleNotReplica, OutputBytes: 32,
	})
	if !slices.Equal(borrower.requests, want) {
		t.Fatalf("record key borrows = %v; want exact %v", borrower.requests, want)
	}
}

// requireRecordReadSpans pins the exact physical read transcript against the
// independently frozen fixture offsets: no more and no fewer source reads than
// the canonical descriptor/body extents.
func requireRecordReadSpans(t *testing.T, reader *recordTrackingReader, want []recordReadSpan) {
	t.Helper()
	if !slices.Equal(reader.spans, want) {
		t.Fatalf("record source reads = %+v; want exact %+v", reader.spans, want)
	}
}

func allRecordBytesZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
