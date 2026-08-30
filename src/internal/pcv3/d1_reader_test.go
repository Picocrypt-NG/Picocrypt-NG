package pcv3

import (
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func newTestD1InnerReader(
	ctx context.Context,
	source io.ReaderAt,
	bodyLength uint64,
	outerKeys d1OuterKeyAccess,
) (*d1InnerReader, error) {
	return newTestD1InnerReaderWithSeams(
		ctx,
		source,
		bodyLength,
		outerKeys,
		defaultD1InnerReaderSeams(),
	)
}

func newTestD1InnerReaderWithSeams(
	ctx context.Context,
	source io.ReaderAt,
	bodyLength uint64,
	outerKeys d1OuterKeyAccess,
	seams d1InnerReaderSeams,
) (*d1InnerReader, error) {
	return newD1InnerReaderConfigured(
		ctx,
		source,
		bodyLength,
		outerKeys,
		seams,
		nil,
		nil,
	)
}

func TestD1ReaderAuthenticatesBeforeInnerCapability(t *testing.T) {
	access, owner := newD1TestOuterAccess(t, 0x63)
	defer owner.Close()
	inner := bytes.Repeat([]byte{0x39}, 2*d1OuterChunkSize+1-d1OuterPrefixLength)
	body := encodeD1TestBody(t, access, inner)
	unit := int(d1OuterChunkSize + d1OuterTagSize)

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "tamper",
			mutate: func(source []byte) []byte {
				source[len(source)-1] ^= 0x01
				return source
			},
		},
		{
			name: "reorder",
			mutate: func(source []byte) []byte {
				first := append([]byte(nil), source[:unit]...)
				copy(source[:unit], source[unit:2*unit])
				copy(source[unit:2*unit], first)
				return source
			},
		},
		{
			name: "truncation",
			mutate: func(source []byte) []byte {
				return source[:len(source)-1]
			},
		},
		{
			name: "omitted final",
			mutate: func(source []byte) []byte {
				return source[:2*unit]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := test.mutate(append([]byte(nil), body...))
			reader, err := newTestD1InnerReader(
				context.Background(),
				bytes.NewReader(mutated),
				uint64(len(body)),
				access,
			)
			if reader != nil {
				reader.Close()
				t.Fatal("damaged body minted an inner ReaderAt capability")
			}
			var failure *d1OuterFailure
			if !errors.As(err, &failure) || failure.Stage() != StageD1Body ||
				!errors.Is(err, errD1OuterAuthentication) {
				t.Fatalf("damaged body failure = %T %v; want closed D1 body authentication failure", err, err)
			}
		})
	}
}

func TestD1ReaderLateTagFailureInvokesNoDecrypt(t *testing.T) {
	access, owner := newD1TestOuterAccess(t, 0x69)
	defer owner.Close()
	inner := bytes.Repeat([]byte{0x3d}, 2*d1OuterChunkSize+1-d1OuterPrefixLength)
	body := encodeD1TestBody(t, access, inner)
	damagedBody := append([]byte(nil), body...)
	damagedBody[len(damagedBody)-1] ^= 0x01
	openCalls := 0

	reader, err := newTestD1InnerReaderWithSeams(
		context.Background(),
		bytes.NewReader(damagedBody),
		uint64(len(damagedBody)),
		access,
		d1InnerReaderSeams{
			openRecord: func(
				codec *d1OuterCodec,
				ctx context.Context,
				index uint64,
				final bool,
				ciphertext []byte,
				tag []byte,
				plaintext []byte,
			) error {
				openCalls++
				return codec.openRecord(ctx, index, final, ciphertext, tag, plaintext)
			},
		},
	)
	if reader != nil {
		reader.Close()
		t.Fatal("late-tag damage minted an inner ReaderAt capability")
	}
	var failure *d1OuterFailure
	if !errors.As(err, &failure) || failure.Stage() != StageD1Body ||
		!errors.Is(err, errD1OuterAuthentication) {
		t.Fatalf("late-tag failure = %T %v; want closed D1 body authentication failure", err, err)
	}
	if openCalls != 0 {
		t.Fatalf("late-tag damage invoked decrypt %d times before complete authentication", openCalls)
	}

	reader, err = newTestD1InnerReaderWithSeams(
		context.Background(),
		bytes.NewReader(body),
		uint64(len(body)),
		access,
		d1InnerReaderSeams{
			openRecord: func(
				codec *d1OuterCodec,
				ctx context.Context,
				index uint64,
				final bool,
				ciphertext []byte,
				tag []byte,
				plaintext []byte,
			) error {
				openCalls++
				return codec.openRecord(ctx, index, final, ciphertext, tag, plaintext)
			},
		},
	)
	if err != nil {
		t.Fatalf("authenticate valid body through decrypt seam: %v", err)
	}
	reader.Close()
	if openCalls != 1 {
		t.Fatalf("valid body invoked decrypt seam %d times; want 1 after complete authentication", openCalls)
	}
}

func TestD1ReaderBoundedScratchAndReauthenticates(t *testing.T) {
	access, owner := newD1TestOuterAccess(t, 0x74)
	defer owner.Close()
	inner := make([]byte, d1OuterChunkSize+257)
	for index := range inner {
		inner[index] = byte(index*29 + 7)
	}
	body := encodeD1TestBody(t, access, inner)
	reader, err := newTestD1InnerReader(
		context.Background(),
		bytes.NewReader(body),
		uint64(len(body)),
		access,
	)
	if err != nil {
		t.Fatalf("authenticate body: %v", err)
	}
	defer reader.Close()
	if reader.Size() != int64(len(inner)) {
		t.Fatalf("inner size = %d; want %d", reader.Size(), len(inner))
	}
	if cap(reader.ciphertextScratch) > d1OuterChunkSize || cap(reader.plaintextScratch) > d1OuterChunkSize {
		t.Fatalf("reader scratch capacities = %d/%d; want at most one outer chunk each", cap(reader.ciphertextScratch), cap(reader.plaintextScratch))
	}

	recovered := make([]byte, len(inner))
	count, err := reader.ReadAt(recovered, 0)
	if err != nil || count != len(recovered) || !bytes.Equal(recovered, inner) {
		t.Fatalf("bounded read = %d, %v, equal=%v", count, err, bytes.Equal(recovered, inner))
	}

	mutable := append([]byte(nil), body...)
	reauth, err := newTestD1InnerReader(
		context.Background(),
		bytes.NewReader(mutable),
		uint64(len(mutable)),
		access,
	)
	if err != nil {
		t.Fatalf("authenticate mutable body: %v", err)
	}
	defer reauth.Close()
	mutable[d1OuterChunkSize] ^= 0x40 // First-record tag, after construction.
	destination := bytes.Repeat([]byte{0xa6}, 32)
	count, err = reauth.ReadAt(destination, 0)
	var failure *d1OuterFailure
	if count != 0 || !errors.As(err, &failure) || failure.Stage() != StageD1Body ||
		!errors.Is(err, errD1OuterAuthentication) {
		t.Fatalf("post-auth mutation read = %d, %T %v; want zero-byte closed D1 body authentication failure", count, err, err)
	}
	if !bytes.Equal(destination, make([]byte, len(destination))) {
		t.Fatal("failed reauthentication retained caller-visible plaintext")
	}
}

// d1SecondPassMutationSource serves canonical body bytes until the final
// record's tag is read for the third time: constructor-wide authentication,
// the per-read authentication pass, and the decrypt pass each read it once.
// The third read flips one tag byte, so the tag fails only after an earlier
// record's plaintext has already reached the caller's destination.
type d1SecondPassMutationSource struct {
	body          []byte
	mutationPoint int64
	coveringReads int
	flips         int
}

func (source *d1SecondPassMutationSource) ReadAt(destination []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative offset")
	}
	if offset <= source.mutationPoint && source.mutationPoint < offset+int64(len(destination)) {
		source.coveringReads++
		if source.coveringReads == 3 {
			source.body[source.mutationPoint] ^= 0x80
			source.flips++
		}
	}
	if offset >= int64(len(source.body)) {
		return 0, io.EOF
	}
	count := copy(destination, source.body[offset:])
	if count < len(destination) {
		return count, io.EOF
	}
	return count, nil
}

func TestD1ReaderSecondPassMutationScrubsPartialPlaintext(t *testing.T) {
	access, owner := newD1TestOuterAccess(t, 0x9b)
	defer owner.Close()
	inner := make([]byte, d1OuterChunkSize+100)
	for index := range inner {
		inner[index] = byte(index*31 + 5)
	}
	body := encodeD1TestBody(t, access, inner)
	// Two records: one full chunk plus a 116-byte final record. The final
	// record's tag begins one full record unit after its ciphertext start.
	mutationPoint := int64(d1OuterChunkSize + d1OuterTagSize + d1OuterPrefixLength + 100)

	source := &d1SecondPassMutationSource{
		body:          append([]byte(nil), body...),
		mutationPoint: mutationPoint,
	}
	reader, err := newTestD1InnerReader(
		context.Background(),
		source,
		uint64(len(body)),
		access,
	)
	if err != nil {
		t.Fatalf("authenticate two-record body: %v", err)
	}
	defer reader.Close()

	destination := make([]byte, len(inner))
	count, err := reader.ReadAt(destination, 0)
	var failure *d1OuterFailure
	if count != 0 || !errors.As(err, &failure) || failure.Stage() != StageD1Body ||
		!errors.Is(err, errD1OuterAuthentication) {
		t.Fatalf("second-pass mutation read = %d, %T %v; want zero-byte closed D1 body authentication failure", count, err, err)
	}
	if source.flips != 1 || source.coveringReads != 3 {
		t.Fatalf("second-pass mutation = %d flips over %d covering reads; want exactly one flip on the third read", source.flips, source.coveringReads)
	}
	if !allZero(destination) {
		t.Fatal("second-pass failure retained partial plaintext in the caller destination")
	}

	// Positive control: the same body without mutation reads back exactly.
	control, err := newTestD1InnerReader(
		context.Background(),
		bytes.NewReader(body),
		uint64(len(body)),
		access,
	)
	if err != nil {
		t.Fatalf("authenticate control body: %v", err)
	}
	defer control.Close()
	recovered := make([]byte, len(inner))
	count, err = control.ReadAt(recovered, 0)
	if err != nil || count != len(inner) || !bytes.Equal(recovered, inner) {
		t.Fatalf("control read = %d, %v, equal=%v", count, err, bytes.Equal(recovered, inner))
	}
}

func TestD1ReaderCloseZerosKeysAndScratches(t *testing.T) {
	access, owner := newD1TestOuterAccess(t, 0x8d)
	defer owner.Close()
	inner := make([]byte, 100)
	for index := range inner {
		inner[index] = byte(index*17 + 3)
	}
	body := encodeD1TestBody(t, access, inner)
	// Frozen single-record layout (spec §20.6): the 16-byte outer prefix plus
	// the inner bytes form the only ciphertext, followed by its 64-byte tag.
	ciphertextLength := d1OuterPrefixLength + len(inner)
	if len(body) != ciphertextLength+d1OuterTagSize {
		t.Fatalf("single-record body length = %d; want %d", len(body), ciphertextLength+d1OuterTagSize)
	}

	reader, err := newTestD1InnerReader(
		context.Background(),
		bytes.NewReader(body),
		uint64(len(body)),
		access,
	)
	if err != nil {
		t.Fatalf("authenticate single-record body: %v", err)
	}
	recovered := make([]byte, len(inner))
	count, err := reader.ReadAt(recovered, 0)
	if err != nil || count != len(inner) || !bytes.Equal(recovered, inner) {
		t.Fatalf("single-record read = %d, %v, equal=%v", count, err, bytes.Equal(recovered, inner))
	}

	// Anti-vacuity: before close the owned scratches and key material are live,
	// and the ciphertext/tag scratches hold the exact source record bytes.
	codec := reader.codec
	ciphertextAlias := reader.ciphertextScratch
	plaintextAlias := reader.plaintextScratch
	tagAlias := reader.tagScratch[:]
	if !bytes.Equal(ciphertextAlias[:ciphertextLength], body[:ciphertextLength]) ||
		!allZero(ciphertextAlias[ciphertextLength:]) {
		t.Fatal("ciphertext scratch does not hold the exact source record bytes")
	}
	if !bytes.Equal(tagAlias, body[ciphertextLength:]) {
		t.Fatal("tag scratch does not hold the exact source tag bytes")
	}
	if !allZero(plaintextAlias) {
		t.Fatal("plaintext scratch retained record plaintext after the read")
	}
	keyAliases := [][]byte{
		codec.keys.xChaCha20[:],
		codec.keys.serpent[:],
		codec.keys.mac[:],
		codec.keys.xNoncePrefix[:],
		codec.keys.serpentPrefix[:],
	}
	for index, alias := range keyAliases {
		if allZero(alias) {
			t.Fatalf("outer key %d was zero before owner close", index)
		}
	}

	reader.Close()

	if !reader.closed || reader.codec != nil || reader.ctx != nil || reader.source != nil ||
		reader.ciphertextScratch != nil || reader.plaintextScratch != nil || reader.force != nil {
		t.Fatal("reader close retained live references")
	}
	if !allZero(ciphertextAlias) || !allZero(plaintextAlias) || !allZero(tagAlias) {
		t.Fatal("reader close retained scratch bytes")
	}
	if !codec.closed {
		t.Fatal("reader close left the outer codec open")
	}
	for index, alias := range keyAliases {
		if !allZero(alias) {
			t.Fatalf("outer key %d survived owner close", index)
		}
	}
	if got := reader.Size(); got != 0 {
		t.Fatalf("closed reader size = %d; want 0", got)
	}
	destination := bytes.Repeat([]byte{0xa5}, 32)
	count, err = reader.ReadAt(destination, 0)
	var failure *d1OuterFailure
	if count != 0 || !errors.As(err, &failure) || failure.Stage() != StageD1Body ||
		!errors.Is(err, errD1ReaderProgress) {
		t.Fatalf("closed reader read = %d, %T %v; want zero-byte closed-body failure", count, err, err)
	}
	if !allZero(destination) {
		t.Fatal("closed reader read retained caller-visible bytes")
	}
	reader.Close() // A second close is a no-op.

	// The caller-owned outer key owner outlives its reader.
	if err := owner.WithKeys(context.Background(), func(*pcv3credential.BorrowedD1OuterKeys) error {
		return nil
	}); err != nil {
		t.Fatalf("outer key owner closed with its reader: %v", err)
	}
}

func encodeD1TestBody(t *testing.T, access d1OuterKeyAccess, inner []byte) []byte {
	t.Helper()
	geometry, err := deriveD1OuterGeometry(uint64(len(inner)))
	if err != nil {
		t.Fatalf("derive test geometry: %v", err)
	}
	codec, err := newD1OuterCodec(context.Background(), access)
	if err != nil {
		t.Fatalf("create test codec: %v", err)
	}
	defer codec.Close()
	var destination bytes.Buffer
	writer, err := newD1OuterStreamWriter(context.Background(), &destination, codec, geometry)
	if err != nil {
		t.Fatalf("create test outer writer: %v", err)
	}
	prefix := make([]byte, d1OuterPrefixLength)
	copy(prefix, []byte("PCVOUT3\x00"))
	binary.BigEndian.PutUint64(prefix[8:], uint64(len(inner)))
	if _, err := writer.Write(prefix); err != nil {
		t.Fatalf("write test prefix: %v", err)
	}
	if _, err := writer.Write(inner); err != nil {
		t.Fatalf("write test inner: %v", err)
	}
	if err := writer.Finish(); err != nil {
		t.Fatalf("finish test body: %v", err)
	}
	if uint64(destination.Len()) != geometry.bodyLength {
		t.Fatalf("test body length = %d; want %d", destination.Len(), geometry.bodyLength)
	}
	return destination.Bytes()
}

var _ io.ReaderAt = (*d1InnerReader)(nil)
