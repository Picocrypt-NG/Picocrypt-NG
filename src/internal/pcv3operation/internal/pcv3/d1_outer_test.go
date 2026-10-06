package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	pcv3stream "Picocrypt-NG/internal/pcv3operation/internal/pcv3crypto"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha3"
	"encoding/binary"
	"hash"
	"testing"
)

func TestD1OuterGeometryAndFinalFraming(t *testing.T) {
	geometry, err := deriveD1OuterGeometry(0)
	if err != nil {
		t.Fatalf("derive empty-inner geometry: %v", err)
	}
	if geometry.plaintextLength != 16 || geometry.bodyLength != 80 ||
		geometry.fullRecords != 0 || geometry.finalCiphertextLength != 16 ||
		geometry.recordCount != 1 {
		t.Fatalf("empty-inner geometry = %+v; want plaintext=16 body=80 one final record", geometry)
	}

	exactFullInner := uint64(d1OuterChunkSize - d1OuterPrefixLength)
	geometry, err = deriveD1OuterGeometry(exactFullInner)
	if err != nil {
		t.Fatalf("derive exact-full geometry: %v", err)
	}
	if geometry.fullRecords != 1 || geometry.finalCiphertextLength != 0 ||
		geometry.recordCount != 2 ||
		geometry.bodyLength != d1OuterChunkSize+2*d1OuterTagSize {
		t.Fatalf("exact-full geometry = %+v; mandatory zero-length final missing", geometry)
	}

	parsed, err := parseD1OuterGeometry(geometry.bodyLength)
	if err != nil || parsed != geometry {
		t.Fatalf("parse canonical body geometry = %+v, %v; want %+v", parsed, err, geometry)
	}
	for _, bodyLength := range []uint64{0, d1OuterTagSize - 1, d1OuterTagSize + d1OuterChunkSize + d1OuterTagSize - 1} {
		if _, err := parseD1OuterGeometry(bodyLength); err == nil {
			t.Fatalf("noncanonical body length %d was accepted", bodyLength)
		}
	}
}

func TestD1OuterCodecMatchesIndependentRecordLayout(t *testing.T) {
	access, owner := newD1TestOuterAccess(t, 0x41)
	defer owner.Close()
	codec, err := newD1OuterCodec(context.Background(), access)
	if err != nil {
		t.Fatalf("create outer codec: %v", err)
	}
	defer codec.Close()

	plaintext := []byte("authenticated outer record")
	ciphertext := make([]byte, len(plaintext))
	tag, err := codec.sealRecord(context.Background(), 7, true, plaintext, ciphertext)
	if err != nil {
		t.Fatalf("seal outer record: %v", err)
	}

	keys := copyD1TestOuterKeys(t, owner)
	defer keys.close()
	var nonce [24]byte
	copy(nonce[:16], keys.xNoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[16:], 7)
	var serpentIV [16]byte
	copy(serpentIV[:8], keys.serpentPrefix[:])
	binary.BigEndian.PutUint64(serpentIV[8:], 7<<16)
	expectedCiphertext := make([]byte, len(plaintext))
	if err := pcv3stream.PCV3WrapParanoid1(
		expectedCiphertext,
		plaintext,
		keys.xChaCha20[:],
		nonce[:],
		keys.serpent[:],
		serpentIV[:],
	); err != nil {
		t.Fatalf("independent outer transform: %v", err)
	}
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Fatal("outer codec ciphertext did not use the canonical nonce/IV transform")
	}

	mac := hmac.New(func() hash.Hash { return sha3.New512() }, keys.mac[:])
	_, _ = mac.Write([]byte("Picocrypt-NG/PCV3/outer/record\x00"))
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], 7)
	_, _ = mac.Write(index[:])
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(ciphertext)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write([]byte{1})
	_, _ = mac.Write(ciphertext)
	if !hmac.Equal(tag[:], mac.Sum(nil)) {
		t.Fatal("outer codec tag did not bind domain/index/length/final/ciphertext")
	}

	recovered := bytes.Repeat([]byte{0xa5}, len(plaintext))
	if err := codec.openRecord(context.Background(), 7, true, ciphertext, tag[:], recovered); err != nil {
		t.Fatalf("open canonical record: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("opened plaintext = %q; want %q", recovered, plaintext)
	}
}

func TestD1OuterRejectsTamperBeforePlaintext(t *testing.T) {
	access, owner := newD1TestOuterAccess(t, 0x52)
	defer owner.Close()
	codec, err := newD1OuterCodec(context.Background(), access)
	if err != nil {
		t.Fatalf("create outer codec: %v", err)
	}
	defer codec.Close()

	plaintext := []byte("marker and inner bytes stay hidden")
	ciphertext := make([]byte, len(plaintext))
	tag, err := codec.sealRecord(context.Background(), 0, true, plaintext, ciphertext)
	if err != nil {
		t.Fatalf("seal record: %v", err)
	}

	for _, mutation := range []struct {
		name  string
		index uint64
		final bool
		body  []byte
		tag   []byte
	}{
		{name: "ciphertext", final: true, body: mutateD1TestByte(ciphertext, 0), tag: tag[:]},
		{name: "tag", final: true, body: ciphertext, tag: mutateD1TestByte(tag[:], 0)},
		{name: "reordered index", index: 1, final: true, body: ciphertext, tag: tag[:]},
		{name: "wrong final", body: ciphertext, tag: tag[:]},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			destination := bytes.Repeat([]byte{0x7d}, len(plaintext))
			before := append([]byte(nil), destination...)
			if err := codec.openRecord(
				context.Background(),
				mutation.index,
				mutation.final,
				mutation.body,
				mutation.tag,
				destination,
			); err == nil {
				t.Fatal("mutated outer record authenticated")
			}
			if !bytes.Equal(destination, before) {
				t.Fatal("failed authentication modified plaintext destination")
			}
		})
	}
}

func newD1TestOuterAccess(
	t *testing.T,
	fill byte,
) (*d1OuterOwnerAccess, *pcv3credential.D1OuterKeyOwner) {
	t.Helper()
	outerKey := bytes.Repeat([]byte{fill}, 32)
	owner, err := pcv3credential.NewD1OuterKeyOwner(outerKey)
	if err != nil {
		t.Fatalf("create test outer-key owner: %v", err)
	}
	return &d1OuterOwnerAccess{owner: owner}, owner
}

func copyD1TestOuterKeys(
	t *testing.T,
	owner *pcv3credential.D1OuterKeyOwner,
) d1OuterKeys {
	t.Helper()
	var copied d1OuterKeys
	err := owner.WithKeys(context.Background(), func(keys *pcv3credential.BorrowedD1OuterKeys) error {
		for _, request := range []struct {
			label       pcv3credential.D1OuterKeyLabel
			destination []byte
		}{
			{pcv3credential.D1OuterPayloadXChaCha20, copied.xChaCha20[:]},
			{pcv3credential.D1OuterPayloadSerpent, copied.serpent[:]},
			{pcv3credential.D1OuterPayloadMAC, copied.mac[:]},
			{pcv3credential.D1OuterPayloadXNoncePrefix, copied.xNoncePrefix[:]},
			{pcv3credential.D1OuterPayloadSerpentPrefix, copied.serpentPrefix[:]},
		} {
			if err := keys.CopyKey(request.label, pcv3credential.KeyRoleNotReplica, request.destination); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("copy test outer keys: %v", err)
	}
	return copied
}

func mutateD1TestByte(source []byte, index int) []byte {
	mutated := append([]byte(nil), source...)
	mutated[index] ^= 0x80
	return mutated
}
