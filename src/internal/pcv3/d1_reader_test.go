package pcv3

import (
	bytes "bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
)

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
			reader, err := newD1InnerReader(
				context.Background(),
				bytes.NewReader(mutated),
				uint64(len(body)),
				access,
			)
			if reader != nil {
				reader.Close()
				t.Fatal("damaged body minted an inner ReaderAt capability")
			}
			if err == nil {
				t.Fatal("damaged body authenticated")
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

	reader, err := newD1InnerReaderWithSeams(
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
	if err == nil {
		t.Fatal("late-tag damage authenticated")
	}
	if openCalls != 0 {
		t.Fatalf("late-tag damage invoked decrypt %d times before complete authentication", openCalls)
	}

	reader, err = newD1InnerReaderWithSeams(
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
	reader, err := newD1InnerReader(
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
	reauth, err := newD1InnerReader(
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
	if count, err := reauth.ReadAt(destination, 0); err == nil || count != 0 {
		t.Fatalf("post-auth mutation read = %d, %v; want zero-byte failure", count, err)
	}
	if !bytes.Equal(destination, make([]byte, len(destination))) {
		t.Fatal("failed reauthentication retained caller-visible plaintext")
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
