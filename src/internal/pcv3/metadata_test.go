package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	metadataTestUnicodeComment = "TEST ONLY — 한국어 공개 메타데이터 🚀"
	metadataTestStandardCore   = "504356000003000100010000000004e0606162636465666768696a6b6c6d6e6f" +
		"707172737475767778797a7b7c7d7e7f01010100000000000000000000000000" +
		"00000000909192939495969798999a9b9c9d9e9f000000000000000000000033"
	metadataTestParanoidEmptyCore = "50435600000300010002000000000458808182838485868788898a8b8c8d8e8f" +
		"909192939495969798999a9b9c9d9e9f01010100000000000000000000000000" +
		"00000000a0a1a2a3a4a5a6a7a8a9aaabacadaeafc0c1c2c3c4c5c6c700000000"
	metadataTestMaximumCore = "5043560000030001000100000001a340606162636465666768696a6b6c6d6e6f" +
		"707172737475767778797a7b7c7d7e7f01010100000000000000000000000000" +
		"00000000909192939495969798999a9b9c9d9e9f00000000000000000001869f"
	metadataTestInvalidCore = "50435600000300010001000000000458606162636465666768696a6b6c6d6e6f" +
		"707172737475767778797a7b7c7d7e7f01010100000000000000000000000000" +
		"00000000909192939495969798999a9b9c9d9e9f00000000000000000000001b"
	metadataTestStandardKey = "000102030405060708090a0b0c0d0e0f" +
		"101112131415161718191a1b1c1d1e1f"
	metadataTestParanoidKey = "202122232425262728292a2b2c2d2e2f" +
		"303132333435363738393a3b3c3d3e3f"
	metadataTestPayloadKey = "404142434445464748494a4b4c4d4e4f" +
		"505152535455565758595a5b5c5d5e5f"
)

type metadataReadSpan struct {
	offset    int64
	requested int
	delivered int
}

type metadataTrackingReader struct {
	base       int64
	data       []byte
	maxChunk   int
	failOffset int64
	failErr    error
	spans      []metadataReadSpan
}

type metadataGapReader struct {
	metadata *metadataTrackingReader
	front    int64
	sentinel byte
}

func (reader *metadataGapReader) ReadAt(destination []byte, offset int64) (int, error) {
	if offset == reader.front && len(destination) != 0 {
		destination[0] = reader.sentinel
		if len(destination) == 1 {
			return 1, nil
		}
		return 1, io.EOF
	}
	return reader.metadata.ReadAt(destination, offset)
}

type metadataLiteralKeyBorrower struct {
	keys        map[pcv3credential.KeyRequest][32]byte
	afterBorrow func()
}

func (borrower *metadataLiteralKeyBorrower) withKey(
	ctx context.Context,
	request pcv3credential.KeyRequest,
	callback func([]byte) error,
) error {
	if borrower == nil || ctx == nil || callback == nil || ctx.Err() != nil {
		return context.Canceled
	}
	key, ok := borrower.keys[request]
	if !ok {
		return errors.New("TEST ONLY unknown key request")
	}
	defer pcv3crypto.SecureZero(key[:])
	err := callback(key[:])
	if borrower.afterBorrow != nil {
		borrower.afterBorrow()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (borrower *metadataLiteralKeyBorrower) close() {
	if borrower == nil {
		return
	}
	for request, key := range borrower.keys {
		pcv3crypto.SecureZero(key[:])
		delete(borrower.keys, request)
	}
	borrower.afterBorrow = nil
}

func (reader *metadataTrackingReader) ReadAt(destination []byte, offset int64) (int, error) {
	requested := len(destination)
	if reader.failErr != nil && offset >= reader.failOffset {
		reader.spans = append(reader.spans, metadataReadSpan{offset: offset, requested: requested})
		return 0, reader.failErr
	}
	if offset < reader.base {
		reader.spans = append(reader.spans, metadataReadSpan{offset: offset, requested: requested})
		return 0, io.EOF
	}
	relative := offset - reader.base
	if relative >= int64(len(reader.data)) {
		reader.spans = append(reader.spans, metadataReadSpan{offset: offset, requested: requested})
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
	reader.spans = append(reader.spans, metadataReadSpan{
		offset:    offset,
		requested: requested,
		delivered: count,
	})
	if count < requested && int(relative)+count == len(reader.data) {
		return count, io.EOF
	}
	return count, nil
}

func TestReadMetadataFrozenCases(t *testing.T) {
	codecs := metadataTestCodecs(t)
	tests := []struct {
		name      string
		fixture   string
		core      string
		blocks    uint64
		front     int64
		maxChunk  int
		want      []byte
		wantEmpty bool
	}{
		{
			name:     "Standard-1 Unicode crosses two RS blocks",
			fixture:  "standard_unicode.bin",
			core:     metadataTestStandardCore,
			blocks:   2,
			front:    1248,
			maxChunk: 17,
			want:     []byte(metadataTestUnicodeComment),
		},
		{
			name:      "Paranoid-1 authenticatable empty value",
			fixture:   "paranoid_empty.bin",
			core:      metadataTestParanoidEmptyCore,
			blocks:    1,
			front:     1112,
			want:      []byte{},
			wantEmpty: true,
		},
		{
			name:    "maximum public comment boundary",
			fixture: "standard_max.bin",
			core:    metadataTestMaximumCore,
			blocks:  782,
			front:   107328,
			want:    metadataMaximumComment(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := metadataFixture(t, test.fixture)
			auth := metadataTestAuthority(t, test.core, test.blocks, test.front)
			source := &metadataTrackingReader{
				base:     int64(frontHeaderBase),
				data:     encoded,
				maxChunk: test.maxChunk,
			}

			recovered, err := readMetadata(context.Background(), source, auth, codecs)
			if err != nil {
				t.Fatalf("read TEST ONLY metadata: %v", err)
			}
			defer recovered.close()
			if recovered.state != metadataRecoveryCanonical {
				t.Fatalf("metadata state = %v; want canonical", recovered.state)
			}
			if !bytes.Equal(recovered.comment, test.want) {
				t.Fatalf("comment mismatch: got %d bytes, want %d", len(recovered.comment), len(test.want))
			}
			if test.wantEmpty && recovered.comment == nil {
				t.Fatal("valid empty metadata was represented as damaged nil comment")
			}
			assertMetadataReadExtent(t, source.spans, test.front)
		})
	}
}

func TestReadMetadataRejectsCanonicalViolations(t *testing.T) {
	codecs := metadataTestCodecs(t)
	tests := []struct {
		name    string
		fixture string
	}{
		{name: "unknown magic", fixture: "invalid_magic.bin"},
		{name: "unknown schema", fixture: "invalid_schema.bin"},
		{name: "unknown encoding", fixture: "invalid_encoding.bin"},
		{name: "nonzero reserved bytes", fixture: "invalid_reserved.bin"},
		{name: "hostile raw comment length", fixture: "invalid_length.bin"},
		{name: "invalid UTF-8", fixture: "invalid_utf8.bin"},
		{name: "nonzero padding", fixture: "invalid_padding.bin"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := metadataTestAuthority(t, metadataTestInvalidCore, 1, 1112)
			source := &metadataTrackingReader{
				base: int64(frontHeaderBase),
				data: metadataFixture(t, test.fixture),
			}
			recovered, err := readMetadata(context.Background(), source, auth, codecs)
			if err != nil {
				t.Fatalf("canonical rejection returned operational error: %v", err)
			}
			defer recovered.close()
			assertMetadataRecoveryDamaged(t, recovered)
			assertMetadataReadExtent(t, source.spans, 1112)
		})
	}
}

func TestReadMetadataRepairsSystematicDamage(t *testing.T) {
	codecs := metadataTestCodecs(t)
	auth := metadataTestAuthority(t, metadataTestStandardCore, 2, 1248)
	source := &metadataTrackingReader{
		base: int64(frontHeaderBase),
		data: metadataFixture(t, "repair4.bin"),
	}

	recovered, err := readMetadata(context.Background(), source, auth, codecs)
	if err != nil {
		t.Fatalf("repair TEST ONLY metadata: %v", err)
	}
	defer recovered.close()
	if recovered.state != metadataRecoveryCanonical ||
		!bytes.Equal(recovered.comment, []byte(metadataTestUnicodeComment)) {
		t.Fatal("four systematic symbol errors did not recover the exact comment")
	}
	assertMetadataReadExtent(t, source.spans, 1248)
}

func TestReadMetadataRejectsUnrecoverableOrMiscorrectedDamage(t *testing.T) {
	codecs := metadataTestCodecs(t)
	auth := metadataTestAuthority(t, metadataTestStandardCore, 2, 1248)
	source := &metadataTrackingReader{
		base: int64(frontHeaderBase),
		data: metadataFixture(t, "damage5.bin"),
	}

	recovered, err := readMetadata(context.Background(), source, auth, codecs)
	if err != nil {
		t.Fatalf("beyond-budget metadata returned operational error: %v", err)
	}
	defer recovered.close()
	assertMetadataRecoveryDamaged(t, recovered)
}

func TestReadMetadataClassifiesTruncationSourceFailureAndCancellation(t *testing.T) {
	codecs := metadataTestCodecs(t)
	auth := metadataTestAuthority(t, metadataTestStandardCore, 2, 1248)
	encoded := metadataFixture(t, "standard_unicode.bin")

	t.Run("EOF inside authenticated extent is metadata damage", func(t *testing.T) {
		source := &metadataTrackingReader{
			base: int64(frontHeaderBase),
			data: encoded[:len(encoded)-1],
		}
		recovered, err := readMetadata(context.Background(), source, auth, codecs)
		if err != nil {
			t.Fatalf("truncation returned operational error: %v", err)
		}
		defer recovered.close()
		assertMetadataRecoveryDamaged(t, recovered)
		assertMetadataRequestsBounded(t, source.spans, 1248)
	})

	t.Run("non-EOF source failure remains input IO", func(t *testing.T) {
		sourceFailure := errors.New("TEST ONLY source canary")
		source := &metadataTrackingReader{
			base:       int64(frontHeaderBase),
			data:       encoded,
			failOffset: int64(frontHeaderBase),
			failErr:    sourceFailure,
		}
		recovered, err := readMetadata(context.Background(), source, auth, codecs)
		if recovered != nil {
			recovered.close()
			t.Fatal("source failure returned metadata state")
		}
		assertMetadataOperationFailure(t, err, StageInputIO)
		if !errors.Is(err, sourceFailure) {
			t.Fatal("source failure cause was not available through errors.Is")
		}
	})

	t.Run("cancellation is terminal operation state", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		source := &metadataTrackingReader{
			base: int64(frontHeaderBase),
			data: encoded,
		}
		recovered, err := readMetadata(ctx, source, auth, codecs)
		if recovered != nil {
			recovered.close()
			t.Fatal("cancellation returned metadata state")
		}
		assertMetadataOperationFailure(t, err, StageCancellation)
		if len(source.spans) != 0 {
			t.Fatal("pre-cancelled metadata read touched the source")
		}
	})
}

func TestAuthenticateMetadata(t *testing.T) {
	codecs := metadataTestCodecs(t)

	t.Run("binds both suites and releases only an owned public copy", func(t *testing.T) {
		tests := []struct {
			name    string
			fixture string
			core    string
			blocks  uint64
			front   int64
			key     string
			want    []byte
			empty   bool
		}{
			{
				name:    "Standard-1 Unicode",
				fixture: "standard_unicode.bin",
				core:    metadataTestStandardCore,
				blocks:  2,
				front:   1248,
				key:     metadataTestStandardKey,
				want:    []byte(metadataTestUnicodeComment),
			},
			{
				name:    "Paranoid-1 empty",
				fixture: "paranoid_empty.bin",
				core:    metadataTestParanoidEmptyCore,
				blocks:  1,
				front:   1112,
				key:     metadataTestParanoidKey,
				want:    []byte{},
				empty:   true,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				auth := metadataTestAuthority(t, test.core, test.blocks, test.front)
				borrower := metadataTestBorrower(t, auth, test.key)
				defer borrower.close()
				encoded := metadataFixture(t, test.fixture)
				source := &metadataTrackingReader{
					base: int64(frontHeaderBase),
					data: encoded,
				}
				result, err := authenticateMetadata(context.Background(), source, auth, codecs)
				if err != nil {
					t.Fatalf("authenticate TEST ONLY metadata: %v", err)
				}
				defer result.close()
				if result.state != metadataAuthenticatedPublic {
					t.Fatalf("metadata result state = %v; want authenticated-public", result.state)
				}
				comment := result.commentBytes()
				if !bytes.Equal(comment, test.want) {
					t.Fatalf("authenticated comment mismatch: got %d bytes, want %d", len(comment), len(test.want))
				}
				if test.empty && comment == nil {
					t.Fatal("authenticated empty comment collapsed into damaged nil")
				}
				if len(comment) != 0 {
					comment[0] ^= 0xff
					if bytes.Equal(comment, result.commentBytes()) {
						t.Fatal("returned comment aliases the result owner")
					}
					encoded[0] ^= 0xff
					if !bytes.Equal(result.commentBytes(), test.want) {
						t.Fatal("authenticated comment aliases source or decode scratch")
					}
				}
			})
		}
	})

	t.Run("valid RS re-encoding cannot replace authentication", func(t *testing.T) {
		for _, fixture := range []string{"bad_tag.bin", "stale_comment.bin"} {
			t.Run(fixture, func(t *testing.T) {
				auth := metadataTestAuthority(t, metadataTestInvalidCore, 1, 1112)
				borrower := metadataTestBorrower(t, auth, metadataTestStandardKey)
				defer borrower.close()
				result, err := authenticateMetadata(
					context.Background(),
					&metadataTrackingReader{base: int64(frontHeaderBase), data: metadataFixture(t, fixture)},
					auth,
					codecs,
				)
				if err != nil {
					t.Fatalf("authenticate re-encoded metadata: %v", err)
				}
				defer result.close()
				assertMetadataResultDamaged(t, result)
			})
		}
	})

	t.Run("tag binds the complete authenticated core", func(t *testing.T) {
		auth := metadataTestAuthority(t, metadataTestStandardCore, 2, 1248)
		auth.candidate.core.volumeID[0] ^= 0x01
		borrower := metadataTestBorrower(t, auth, metadataTestStandardKey)
		defer borrower.close()
		result, err := authenticateMetadata(
			context.Background(),
			&metadataTrackingReader{base: int64(frontHeaderBase), data: metadataFixture(t, "standard_unicode.bin")},
			auth,
			codecs,
		)
		if err != nil {
			t.Fatalf("authenticate core-bound metadata: %v", err)
		}
		defer result.close()
		assertMetadataResultDamaged(t, result)
	})

	t.Run("missing authenticated key owner is an internal request failure", func(t *testing.T) {
		auth := metadataTestAuthority(t, metadataTestStandardCore, 2, 1248)
		result, err := authenticateMetadata(
			context.Background(),
			&metadataTrackingReader{base: int64(frontHeaderBase), data: metadataFixture(t, "standard_unicode.bin")},
			auth,
			codecs,
		)
		if result != nil {
			result.close()
			t.Fatal("missing key owner produced metadata state")
		}
		if !errors.Is(err, errInvalidMetadataRequest) {
			t.Fatalf("missing key owner error = %v; want fixed internal request sentinel", err)
		}
		var failure Failure
		if errors.As(err, &failure) {
			t.Fatalf("missing key owner became public outcome %v/%v", failure.Outcome(), failure.Stage())
		}
	})

	t.Run("post-borrow cancellation cannot release comment", func(t *testing.T) {
		auth := metadataTestAuthority(t, metadataTestStandardCore, 2, 1248)
		borrower := metadataTestBorrower(t, auth, metadataTestStandardKey)
		defer borrower.close()
		ctx, cancel := context.WithCancel(context.Background())
		borrower.afterBorrow = cancel
		result, err := authenticateMetadata(
			ctx,
			&metadataTrackingReader{base: int64(frontHeaderBase), data: metadataFixture(t, "standard_unicode.bin")},
			auth,
			codecs,
		)
		if result != nil {
			result.close()
			t.Fatal("post-borrow cancellation released metadata state")
		}
		assertMetadataOperationFailure(t, err, StageCancellation)
	})
}

func TestMetadataDamagePreservesAuthenticatedSession(t *testing.T) {
	codecs := metadataTestCodecs(t)
	tests := []struct {
		name        string
		fixture     string
		core        string
		blocks      uint64
		front       int64
		truncate    bool
		metadataKey string
	}{
		{
			name:        "canonical schema damage",
			fixture:     "invalid_schema.bin",
			core:        metadataTestInvalidCore,
			blocks:      1,
			front:       1112,
			metadataKey: metadataTestStandardKey,
		},
		{
			name:        "invalid UTF-8",
			fixture:     "invalid_utf8.bin",
			core:        metadataTestInvalidCore,
			blocks:      1,
			front:       1112,
			metadataKey: metadataTestStandardKey,
		},
		{
			name:        "hostile raw comment length",
			fixture:     "invalid_length.bin",
			core:        metadataTestInvalidCore,
			blocks:      1,
			front:       1112,
			metadataKey: metadataTestStandardKey,
		},
		{
			name:        "RS damage beyond correction budget",
			fixture:     "damage5.bin",
			core:        metadataTestStandardCore,
			blocks:      2,
			front:       1248,
			metadataKey: metadataTestStandardKey,
		},
		{
			name:        "metadata tag damage",
			fixture:     "bad_tag.bin",
			core:        metadataTestInvalidCore,
			blocks:      1,
			front:       1112,
			metadataKey: metadataTestStandardKey,
		},
		{
			name:        "metadata truncation",
			fixture:     "standard_unicode.bin",
			core:        metadataTestStandardCore,
			blocks:      2,
			front:       1248,
			truncate:    true,
			metadataKey: metadataTestStandardKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := metadataTestAuthority(t, test.core, test.blocks, test.front)
			borrower := metadataTestBorrower(t, auth, test.metadataKey)
			defer borrower.close()
			beforeCandidate := auth.candidate
			beforeGeometry := auth.geometry
			encoded := metadataFixture(t, test.fixture)
			const sentinel = byte(0xa7)
			var source io.ReaderAt
			if test.truncate {
				source = &metadataGapReader{
					metadata: &metadataTrackingReader{
						base: int64(frontHeaderBase),
						data: encoded[:len(encoded)-1],
					},
					front:    test.front,
					sentinel: sentinel,
				}
			} else {
				data := append(append([]byte(nil), encoded...), sentinel)
				source = &metadataTrackingReader{base: int64(frontHeaderBase), data: data}
			}

			result, err := authenticateMetadata(context.Background(), source, auth, codecs)
			if err != nil {
				t.Fatalf("metadata damage became operational: %v", err)
			}
			defer result.close()
			assertMetadataResultDamaged(t, result)
			if auth.candidate != beforeCandidate || auth.geometry != beforeGeometry {
				t.Fatal("metadata damage changed authenticated core or geometry")
			}

			var next [1]byte
			if _, err := readExactAt(source, auth.geometry.FrontHeaderLength(), next[:], StageDescriptor); err != nil {
				t.Fatalf("continue at authenticated payload boundary: %v", err)
			}
			if next[0] != sentinel {
				t.Fatalf("next-region byte = 0x%02x; want 0x%02x", next[0], sentinel)
			}

			var payloadKey [32]byte
			err = auth.withKey(
				context.Background(),
				pcv3credential.KeyRequest{
					Label:       pcv3credential.KeyLabelVolumePayloadMAC,
					Role:        pcv3credential.KeyRoleNotReplica,
					OutputBytes: 32,
				},
				func(key []byte) error {
					copy(payloadKey[:], key)
					return nil
				},
			)
			if err != nil {
				t.Fatalf("borrow existing payload key after metadata damage: %v", err)
			}
			wantPayloadKey := metadataTestKey(t, metadataTestPayloadKey)
			if payloadKey != wantPayloadKey {
				t.Fatal("metadata damage changed existing payload key access")
			}
			pcv3crypto.SecureZero(payloadKey[:])
			pcv3crypto.SecureZero(wantPayloadKey[:])
		})
	}
}

func metadataFixture(t *testing.T, name string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("testdata", "metadata", name))
	if err != nil {
		t.Fatalf("read TEST ONLY fixture %s: %v", name, err)
	}
	return encoded
}

func metadataTestCodecs(t *testing.T) *pcencoding.RSCodecs {
	t.Helper()
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("initialize production RS decoder: %v", err)
	}
	return codecs
}

func metadataTestAuthority(
	t *testing.T,
	coreHex string,
	blocks uint64,
	front int64,
) *normalAuthResult {
	t.Helper()
	coreBytes, err := hex.DecodeString(coreHex)
	if err != nil || len(coreBytes) != 96 {
		t.Fatalf("decode TEST ONLY logical core: length %d, error %v", len(coreBytes), err)
	}
	decodedCapsule := make([]byte, decodedCapsuleLength)
	copy(decodedCapsule, coreBytes)
	candidate := decodeCandidate(decodedCapsule)
	clear(coreBytes)
	clear(decodedCapsule)
	return &normalAuthResult{
		outcome:       OutcomeSuccess,
		stage:         StageNone,
		authenticated: 2,
		candidate:     candidate,
		geometry: Geometry{
			metadataBlocks:    blocks,
			frontHeaderLength: front,
		},
	}
}

func metadataTestBorrower(
	t *testing.T,
	auth *normalAuthResult,
	metadataKeyHex string,
) *metadataLiteralKeyBorrower {
	t.Helper()
	borrower := &metadataLiteralKeyBorrower{
		keys: map[pcv3credential.KeyRequest][32]byte{
			{
				Label:       pcv3credential.KeyLabelVolumeMetadataMAC,
				Role:        pcv3credential.KeyRoleNotReplica,
				OutputBytes: 32,
			}: metadataTestKey(t, metadataKeyHex),
			{
				Label:       pcv3credential.KeyLabelVolumePayloadMAC,
				Role:        pcv3credential.KeyRoleNotReplica,
				OutputBytes: 32,
			}: metadataTestKey(t, metadataTestPayloadKey),
		},
	}
	auth.keyBorrower = borrower
	return borrower
}

func metadataTestKey(t *testing.T, encoded string) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decode TEST ONLY key: length %d, error %v", len(decoded), err)
	}
	var key [32]byte
	copy(key[:], decoded)
	pcv3crypto.SecureZero(decoded)
	return key
}

func metadataMaximumComment() []byte {
	const pattern = "TEST ONLY PUBLIC COMMENT|"
	comment := make([]byte, maximumCommentLength)
	for offset := 0; offset < len(comment); {
		offset += copy(comment[offset:], pattern)
	}
	return comment
}

func assertMetadataRecoveryDamaged(t *testing.T, recovered *metadataRecovery) {
	t.Helper()
	if recovered == nil || recovered.state != metadataRecoveryDamaged {
		t.Fatalf("metadata state = %v; want damaged", recovered)
	}
	if recovered.comment != nil {
		t.Fatalf("damaged metadata released %d comment bytes", len(recovered.comment))
	}
}

func assertMetadataResultDamaged(t *testing.T, result *metadataResult) {
	t.Helper()
	if result == nil || result.state != metadataDamaged {
		t.Fatalf("metadata result = %v; want metadata-damaged", result)
	}
	if result.commentBytes() != nil {
		t.Fatal("metadata-damaged result released comment bytes")
	}
}

func assertMetadataReadExtent(t *testing.T, spans []metadataReadSpan, front int64) {
	t.Helper()
	assertMetadataRequestsBounded(t, spans, front)
	extent := int(front - int64(frontHeaderBase))
	covered := make([]bool, extent)
	for _, span := range spans {
		start := int(span.offset - int64(frontHeaderBase))
		for index := 0; index < span.delivered; index++ {
			covered[start+index] = true
		}
	}
	for index, ok := range covered {
		if !ok {
			t.Fatalf("authenticated metadata byte %d was not read", index)
		}
	}
}

func assertMetadataRequestsBounded(t *testing.T, spans []metadataReadSpan, front int64) {
	t.Helper()
	for _, span := range spans {
		if span.requested <= 0 || span.requested > int(rs128CodewordLength) {
			t.Fatalf("metadata request size = %d; want 1..136", span.requested)
		}
		if span.offset < int64(frontHeaderBase) ||
			span.offset+int64(span.requested) > front {
			t.Fatalf("metadata request [%d,%d) escaped authenticated extent [%d,%d)",
				span.offset,
				span.offset+int64(span.requested),
				frontHeaderBase,
				front,
			)
		}
	}
}

func assertMetadataOperationFailure(t *testing.T, err error, stage Stage) {
	t.Helper()
	var failure Failure
	if !errors.As(err, &failure) ||
		failure.Outcome() != OutcomeOperationFailed || failure.Stage() != stage {
		t.Fatalf("operation failure = %v; want operation-failed/%v", err, stage)
	}
}
