package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	d1OuterChunkSize    = 1_048_576
	d1OuterTagSize      = 64
	d1OuterPrefixLength = 16
	d1OuterRecordLimit  = uint64(1) << 48
	d1OuterRecordDomain = "Picocrypt-NG/PCV3/outer/record\x00"
)

var (
	errInvalidD1OuterGeometry = errors.New("pcv3: invalid D1 outer geometry")
	errInvalidD1OuterRecord   = errors.New("pcv3: invalid D1 outer record")
	errD1OuterAuthentication  = errors.New("pcv3: D1 outer authentication failed")
	errD1OuterCrypto          = errors.New("pcv3: D1 outer cryptographic operation failed")
)

type d1OuterGeometry struct {
	innerLength           uint64
	plaintextLength       uint64
	bodyLength            uint64
	fullRecords           uint64
	finalCiphertextLength uint64
	recordCount           uint64
}

func deriveD1OuterGeometry(innerLength uint64) (d1OuterGeometry, error) {
	plaintextLength, ok := checkedAdd64(d1OuterPrefixLength, innerLength)
	if !ok {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	fullRecords := plaintextLength / d1OuterChunkSize
	if fullRecords >= d1OuterRecordLimit {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	finalCiphertextLength := plaintextLength % d1OuterChunkSize
	recordCount, ok := checkedAdd64(fullRecords, 1)
	if !ok {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	tagBytes, ok := checkedMul64(recordCount, d1OuterTagSize)
	if !ok {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	bodyLength, ok := checkedAdd64(plaintextLength, tagBytes)
	if !ok {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	return d1OuterGeometry{
		innerLength:           innerLength,
		plaintextLength:       plaintextLength,
		bodyLength:            bodyLength,
		fullRecords:           fullRecords,
		finalCiphertextLength: finalCiphertextLength,
		recordCount:           recordCount,
	}, nil
}

func parseD1OuterGeometry(bodyLength uint64) (d1OuterGeometry, error) {
	if bodyLength < d1OuterTagSize {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	remaining := bodyLength - d1OuterTagSize
	outerUnit := uint64(d1OuterChunkSize + d1OuterTagSize)
	fullRecords := remaining / outerUnit
	consumed, ok := checkedMul64(fullRecords, outerUnit)
	if !ok || consumed > remaining {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	finalCiphertextLength := remaining - consumed
	if finalCiphertextLength >= d1OuterChunkSize || fullRecords >= d1OuterRecordLimit {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	fullPlaintext, ok := checkedMul64(fullRecords, d1OuterChunkSize)
	if !ok {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	plaintextLength, ok := checkedAdd64(fullPlaintext, finalCiphertextLength)
	if !ok || plaintextLength < d1OuterPrefixLength {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	geometry, err := deriveD1OuterGeometry(plaintextLength - d1OuterPrefixLength)
	if err != nil || geometry.bodyLength != bodyLength {
		return d1OuterGeometry{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	return geometry, nil
}

type d1OuterRecordExpectation struct {
	index            uint64
	offset           uint64
	ciphertextLength int
	final            bool
}

func expectedD1OuterRecord(
	geometry d1OuterGeometry,
	index uint64,
) (d1OuterRecordExpectation, error) {
	if index >= geometry.recordCount || index >= d1OuterRecordLimit {
		return d1OuterRecordExpectation{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterRecord)
	}
	offset, ok := checkedMul64(index, d1OuterChunkSize+d1OuterTagSize)
	if !ok {
		return d1OuterRecordExpectation{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterRecord)
	}
	expected := d1OuterRecordExpectation{
		index:  index,
		offset: offset,
		final:  index == geometry.fullRecords,
	}
	if expected.final {
		expected.ciphertextLength = int(geometry.finalCiphertextLength)
	} else {
		expected.ciphertextLength = d1OuterChunkSize
	}
	end, ok := checkedAdd64(offset, uint64(expected.ciphertextLength)+d1OuterTagSize)
	if !ok || end > geometry.bodyLength || (expected.final && end != geometry.bodyLength) {
		return d1OuterRecordExpectation{}, newD1OuterFailure(StageD1Body, errInvalidD1OuterRecord)
	}
	return expected, nil
}

type d1OuterKeyAccess interface {
	withOuterKeys(context.Context, func(*pcv3credential.BorrowedD1OuterKeys) error) error
}

type d1OuterOwnerAccess struct {
	owner *pcv3credential.D1OuterKeyOwner
}

func (access *d1OuterOwnerAccess) withOuterKeys(
	ctx context.Context,
	callback func(*pcv3credential.BorrowedD1OuterKeys) error,
) error {
	if access == nil || access.owner == nil || ctx == nil || callback == nil {
		return errInvalidD1OuterRecord
	}
	return access.owner.WithKeys(ctx, callback)
}

type d1OuterKeys struct {
	xChaCha20     [32]byte
	serpent       [32]byte
	mac           [32]byte
	xNoncePrefix  [16]byte
	serpentPrefix [8]byte
}

func (keys *d1OuterKeys) close() {
	if keys == nil {
		return
	}
	pcv3crypto.SecureZero(keys.xChaCha20[:])
	pcv3crypto.SecureZero(keys.serpent[:])
	pcv3crypto.SecureZero(keys.mac[:])
	pcv3crypto.SecureZero(keys.xNoncePrefix[:])
	pcv3crypto.SecureZero(keys.serpentPrefix[:])
}

type d1OuterCodec struct {
	keys   d1OuterKeys
	closed bool
}

func newD1OuterCodec(ctx context.Context, access d1OuterKeyAccess) (*d1OuterCodec, error) {
	if ctx == nil || access == nil {
		return nil, newD1OuterFailure(StageCredentialPolicy, errInvalidD1OuterRecord)
	}
	if err := ctx.Err(); err != nil {
		return nil, newD1OuterFailure(StageCancellation, err)
	}
	codec := &d1OuterCodec{}
	success := false
	defer func() {
		if !success {
			codec.Close()
		}
	}()
	err := access.withOuterKeys(ctx, func(keys *pcv3credential.BorrowedD1OuterKeys) error {
		for _, request := range []struct {
			label       pcv3credential.D1OuterKeyLabel
			destination []byte
		}{
			{pcv3credential.D1OuterPayloadXChaCha20, codec.keys.xChaCha20[:]},
			{pcv3credential.D1OuterPayloadSerpent, codec.keys.serpent[:]},
			{pcv3credential.D1OuterPayloadMAC, codec.keys.mac[:]},
			{pcv3credential.D1OuterPayloadXNoncePrefix, codec.keys.xNoncePrefix[:]},
			{pcv3credential.D1OuterPayloadSerpentPrefix, codec.keys.serpentPrefix[:]},
		} {
			if err := keys.CopyKey(
				request.label,
				pcv3credential.KeyRoleNotReplica,
				request.destination,
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, newD1OuterFailure(StageCancellation, ctx.Err())
		}
		return nil, newD1OuterFailure(StageCredentialPolicy, err)
	}
	success = true
	return codec, nil
}

func (codec *d1OuterCodec) Close() {
	if codec == nil || codec.closed {
		return
	}
	codec.closed = true
	codec.keys.close()
}

func (codec *d1OuterCodec) sealRecord(
	ctx context.Context,
	index uint64,
	final bool,
	plaintext, ciphertext []byte,
) ([d1OuterTagSize]byte, error) {
	var tag [d1OuterTagSize]byte
	if err := codec.validateRecord(ctx, index, final, plaintext, ciphertext); err != nil {
		return tag, err
	}
	nonce, serpentIV := codec.recordParameters(index)
	defer pcv3crypto.SecureZero(nonce[:])
	defer pcv3crypto.SecureZero(serpentIV[:])
	if err := pcv3crypto.PCV3WrapParanoid1(
		ciphertext,
		plaintext,
		codec.keys.xChaCha20[:],
		nonce[:],
		codec.keys.serpent[:],
		serpentIV[:],
	); err != nil {
		pcv3crypto.SecureZero(ciphertext)
		return tag, newD1OuterFailure(StageD1Body, errD1OuterCrypto)
	}
	tag, err := codec.recordTag(index, final, ciphertext)
	if err != nil {
		pcv3crypto.SecureZero(ciphertext)
		return [d1OuterTagSize]byte{}, err
	}
	return tag, nil
}

func (codec *d1OuterCodec) authenticateRecord(
	ctx context.Context,
	index uint64,
	final bool,
	ciphertext, expectedTag []byte,
) error {
	if err := codec.validateRecord(ctx, index, final, ciphertext, ciphertext); err != nil {
		return err
	}
	if len(expectedTag) != d1OuterTagSize {
		return newD1OuterFailure(StageD1Body, errD1OuterAuthentication)
	}
	actual, err := codec.recordTag(index, final, ciphertext)
	if err != nil {
		return err
	}
	defer pcv3crypto.SecureZero(actual[:])
	if subtle.ConstantTimeCompare(actual[:], expectedTag) != 1 {
		return newD1OuterFailure(StageD1Body, errD1OuterAuthentication)
	}
	return nil
}

func (codec *d1OuterCodec) openRecord(
	ctx context.Context,
	index uint64,
	final bool,
	ciphertext, expectedTag, plaintext []byte,
) error {
	if err := codec.validateRecord(ctx, index, final, ciphertext, plaintext); err != nil {
		return err
	}
	if err := codec.authenticateRecord(ctx, index, final, ciphertext, expectedTag); err != nil {
		return err
	}
	nonce, serpentIV := codec.recordParameters(index)
	defer pcv3crypto.SecureZero(nonce[:])
	defer pcv3crypto.SecureZero(serpentIV[:])
	if err := pcv3crypto.PCV3UnwrapParanoid1(
		plaintext,
		ciphertext,
		codec.keys.xChaCha20[:],
		nonce[:],
		codec.keys.serpent[:],
		serpentIV[:],
	); err != nil {
		pcv3crypto.SecureZero(plaintext)
		return newD1OuterFailure(StageD1Body, errD1OuterCrypto)
	}
	return nil
}

func (codec *d1OuterCodec) validateRecord(
	ctx context.Context,
	index uint64,
	final bool,
	source, destination []byte,
) error {
	if codec == nil || codec.closed || ctx == nil || index >= d1OuterRecordLimit ||
		len(source) != len(destination) || len(source) > d1OuterChunkSize ||
		(final && len(source) >= d1OuterChunkSize) ||
		(!final && len(source) != d1OuterChunkSize) {
		return newD1OuterFailure(StageD1Body, errInvalidD1OuterRecord)
	}
	if err := ctx.Err(); err != nil {
		return newD1OuterFailure(StageCancellation, err)
	}
	return nil
}

func (codec *d1OuterCodec) recordParameters(index uint64) ([24]byte, [16]byte) {
	var nonce [24]byte
	var serpentIV [16]byte
	copy(nonce[:16], codec.keys.xNoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[16:], index)
	copy(serpentIV[:8], codec.keys.serpentPrefix[:])
	binary.BigEndian.PutUint64(serpentIV[8:], index<<16)
	return nonce, serpentIV
}

func (codec *d1OuterCodec) recordTag(
	index uint64,
	final bool,
	ciphertext []byte,
) ([d1OuterTagSize]byte, error) {
	var indexBytes [8]byte
	var lengthBytes [4]byte
	var finalByte [1]byte
	binary.BigEndian.PutUint64(indexBytes[:], index)
	binary.BigEndian.PutUint32(lengthBytes[:], uint32(len(ciphertext))) //nolint:gosec // Record length is at most 1 MiB.
	if final {
		finalByte[0] = 1
	}
	tag, err := suiteMACTag(
		SuiteParanoid,
		codec.keys.mac[:],
		[]byte(d1OuterRecordDomain),
		indexBytes[:],
		lengthBytes[:],
		finalByte[:],
		ciphertext,
	)
	if err != nil {
		return [d1OuterTagSize]byte{}, newD1OuterFailure(StageD1Body, errD1OuterCrypto)
	}
	return tag, nil
}

type d1OuterFailure struct {
	stage Stage
	cause error
}

func (*d1OuterFailure) Error() string {
	return "pcv3: D1 outer operation failed"
}

func (failure *d1OuterFailure) String() string { return failure.Error() }

func (failure *d1OuterFailure) GoString() string { return failure.Error() }

func (failure *d1OuterFailure) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, failure.Error())
}

func (failure *d1OuterFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (failure *d1OuterFailure) Stage() Stage {
	if failure == nil {
		return StageNone
	}
	return failure.stage
}

func newD1OuterFailure(stage Stage, cause error) error {
	return &d1OuterFailure{stage: stage, cause: cause}
}
