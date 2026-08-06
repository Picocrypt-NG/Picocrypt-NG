package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
)

var errD1ReaderProgress = errors.New("pcv3: invalid D1 reader progress")

type d1InnerReaderSeams struct {
	openRecord func(
		*d1OuterCodec,
		context.Context,
		uint64,
		bool,
		[]byte,
		[]byte,
		[]byte,
	) error
}

func defaultD1InnerReaderSeams() d1InnerReaderSeams {
	return d1InnerReaderSeams{
		openRecord: func(
			codec *d1OuterCodec,
			ctx context.Context,
			index uint64,
			final bool,
			ciphertext []byte,
			tag []byte,
			plaintext []byte,
		) error {
			return codec.openRecord(ctx, index, final, ciphertext, tag, plaintext)
		},
	}
}

type d1InnerReader struct {
	mu                sync.Mutex
	ctx               context.Context
	source            io.ReaderAt
	geometry          d1OuterGeometry
	codec             *d1OuterCodec
	ciphertextScratch []byte
	plaintextScratch  []byte
	tagScratch        [d1OuterTagSize]byte
	seams             d1InnerReaderSeams
	closed            bool
}

// newD1InnerReader is a private authenticated-body component. Plan 07-03 owns
// composing it into the production D1 reader after bootstrap authentication.
func newD1InnerReader(
	ctx context.Context,
	source io.ReaderAt,
	bodyLength uint64,
	outerKeys d1OuterKeyAccess,
) (*d1InnerReader, error) {
	return newD1InnerReaderWithSeams(
		ctx,
		source,
		bodyLength,
		outerKeys,
		defaultD1InnerReaderSeams(),
	)
}

func newD1InnerReaderWithSeams(
	ctx context.Context,
	source io.ReaderAt,
	bodyLength uint64,
	outerKeys d1OuterKeyAccess,
	seams d1InnerReaderSeams,
) (*d1InnerReader, error) {
	if ctx == nil || source == nil || outerKeys == nil || seams.openRecord == nil {
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	if err := ctx.Err(); err != nil {
		return nil, newD1OuterFailure(StageCancellation, err)
	}
	geometry, err := parseD1OuterGeometry(bodyLength)
	if err != nil || bodyLength > math.MaxInt64 {
		return nil, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	codec, err := newD1OuterCodec(ctx, outerKeys)
	if err != nil {
		return nil, err
	}
	reader := &d1InnerReader{
		ctx:               ctx,
		source:            source,
		geometry:          geometry,
		codec:             codec,
		ciphertextScratch: make([]byte, d1OuterChunkSize),
		plaintextScratch:  make([]byte, d1OuterChunkSize),
		seams:             seams,
	}
	success := false
	defer func() {
		if !success {
			reader.Close()
		}
	}()
	if err := reader.authenticateAll(); err != nil {
		return nil, err
	}
	first, err := expectedD1OuterRecord(geometry, 0)
	if err != nil {
		return nil, err
	}
	plaintext, err := reader.openExpected(first)
	if err != nil {
		return nil, err
	}
	defer pcv3crypto.SecureZero(plaintext)
	if len(plaintext) < d1OuterPrefixLength ||
		!bytes.Equal(plaintext[:8], []byte(d1OuterMarker)) ||
		binary.BigEndian.Uint64(plaintext[8:16]) != geometry.innerLength {
		return nil, newD1OuterFailure(StageD1Body, errD1OuterAuthentication)
	}
	success = true
	return reader, nil
}

func (reader *d1InnerReader) Size() int64 {
	if reader == nil || reader.closed || reader.geometry.innerLength > math.MaxInt64 {
		return 0
	}
	return int64(reader.geometry.innerLength)
}

func (reader *d1InnerReader) ReadAt(destination []byte, offset int64) (int, error) {
	if reader == nil {
		return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed || reader.ctx == nil || reader.source == nil || reader.codec == nil ||
		reader.seams.openRecord == nil || offset < 0 {
		return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	if len(destination) == 0 {
		return 0, nil
	}
	if err := reader.ctx.Err(); err != nil {
		pcv3crypto.SecureZero(destination)
		return 0, newD1OuterFailure(StageCancellation, err)
	}
	innerLength := reader.geometry.innerLength
	if uint64(offset) >= innerLength {
		pcv3crypto.SecureZero(destination)
		return 0, io.EOF
	}
	remaining := innerLength - uint64(offset)
	target := uint64(len(destination))
	if target > remaining {
		target = remaining
	}
	outerStart, ok := checkedAdd64(d1OuterPrefixLength, uint64(offset))
	if !ok {
		pcv3crypto.SecureZero(destination)
		return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	outerEnd, ok := checkedAdd64(outerStart, target)
	if !ok || outerEnd == 0 {
		pcv3crypto.SecureZero(destination)
		return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	firstIndex := outerStart / d1OuterChunkSize
	lastIndex := (outerEnd - 1) / d1OuterChunkSize

	for index := firstIndex; index <= lastIndex; index++ {
		expected, err := expectedD1OuterRecord(reader.geometry, index)
		if err != nil {
			pcv3crypto.SecureZero(destination)
			return 0, err
		}
		ciphertext, tag, err := reader.loadExpected(expected)
		if err != nil {
			pcv3crypto.SecureZero(destination)
			return 0, err
		}
		if err := reader.codec.authenticateRecord(
			reader.ctx,
			expected.index,
			expected.final,
			ciphertext,
			tag,
		); err != nil {
			pcv3crypto.SecureZero(destination)
			return 0, err
		}
	}

	written := 0
	for index := firstIndex; index <= lastIndex; index++ {
		expected, err := expectedD1OuterRecord(reader.geometry, index)
		if err != nil {
			pcv3crypto.SecureZero(destination)
			return 0, err
		}
		plaintext, err := reader.openExpected(expected)
		if err != nil {
			pcv3crypto.SecureZero(destination)
			return 0, err
		}
		recordStart, ok := checkedMul64(index, d1OuterChunkSize)
		if !ok {
			pcv3crypto.SecureZero(destination)
			return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
		}
		copyStart := max(outerStart, recordStart) - recordStart
		recordEnd, ok := checkedAdd64(recordStart, uint64(len(plaintext)))
		if !ok {
			pcv3crypto.SecureZero(destination)
			return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
		}
		copyEnd := min(outerEnd, recordEnd) - recordStart
		if copyEnd < copyStart || copyEnd > uint64(len(plaintext)) {
			pcv3crypto.SecureZero(destination)
			return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
		}
		written += copy(destination[written:], plaintext[copyStart:copyEnd])
		pcv3crypto.SecureZero(plaintext)
	}
	if uint64(written) != target {
		pcv3crypto.SecureZero(destination)
		return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	if err := reader.ctx.Err(); err != nil {
		pcv3crypto.SecureZero(destination)
		return 0, newD1OuterFailure(StageCancellation, err)
	}
	if target < uint64(len(destination)) {
		return written, io.EOF
	}
	return written, nil
}

func (reader *d1InnerReader) Close() {
	if reader == nil {
		return
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return
	}
	reader.closed = true
	pcv3crypto.SecureZero(reader.ciphertextScratch)
	pcv3crypto.SecureZero(reader.plaintextScratch)
	pcv3crypto.SecureZero(reader.tagScratch[:])
	reader.ciphertextScratch = nil
	reader.plaintextScratch = nil
	if reader.codec != nil {
		reader.codec.Close()
		reader.codec = nil
	}
	reader.ctx = nil
	reader.source = nil
	reader.geometry = d1OuterGeometry{}
	reader.seams = d1InnerReaderSeams{}
}

func (reader *d1InnerReader) authenticateAll() error {
	for index := range reader.geometry.recordCount {
		if err := reader.ctx.Err(); err != nil {
			return newD1OuterFailure(StageCancellation, err)
		}
		expected, err := expectedD1OuterRecord(reader.geometry, index)
		if err != nil {
			return err
		}
		ciphertext, tag, err := reader.loadExpected(expected)
		if err != nil {
			return err
		}
		if err := reader.codec.authenticateRecord(
			reader.ctx,
			expected.index,
			expected.final,
			ciphertext,
			tag,
		); err != nil {
			return err
		}
	}
	return nil
}

func (reader *d1InnerReader) openExpected(
	expected d1OuterRecordExpectation,
) ([]byte, error) {
	ciphertext, tag, err := reader.loadExpected(expected)
	if err != nil {
		return nil, err
	}
	plaintext := reader.plaintextScratch[:expected.ciphertextLength]
	pcv3crypto.SecureZero(plaintext)
	if err := reader.seams.openRecord(
		reader.codec,
		reader.ctx,
		expected.index,
		expected.final,
		ciphertext,
		tag,
		plaintext,
	); err != nil {
		pcv3crypto.SecureZero(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func (reader *d1InnerReader) loadExpected(
	expected d1OuterRecordExpectation,
) ([]byte, []byte, error) {
	if expected.ciphertextLength < 0 || expected.ciphertextLength > len(reader.ciphertextScratch) {
		return nil, nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	ciphertext := reader.ciphertextScratch[:expected.ciphertextLength]
	pcv3crypto.SecureZero(ciphertext)
	pcv3crypto.SecureZero(reader.tagScratch[:])
	relativeTagOffset, ok := checkedAdd64(expected.offset, uint64(expected.ciphertextLength))
	if !ok {
		return nil, nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	if err := reader.readExactAt(expected.offset, ciphertext); err != nil {
		return nil, nil, err
	}
	if err := reader.readExactAt(relativeTagOffset, reader.tagScratch[:]); err != nil {
		pcv3crypto.SecureZero(ciphertext)
		return nil, nil, err
	}
	return ciphertext, reader.tagScratch[:], nil
}

func (reader *d1InnerReader) readExactAt(relativeOffset uint64, destination []byte) error {
	if relativeOffset > math.MaxInt64 {
		return newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	read := 0
	for read < len(destination) {
		if err := reader.ctx.Err(); err != nil {
			return newD1OuterFailure(StageCancellation, err)
		}
		offset, ok := checkedAdd64(relativeOffset, uint64(read))
		if !ok || offset > math.MaxInt64 {
			return newD1OuterFailure(StageD1Body, errD1ReaderProgress)
		}
		count, err := reader.source.ReadAt(destination[read:], int64(offset))
		if count < 0 || count > len(destination)-read {
			return newD1OuterFailure(StageInputIO, errD1ReaderProgress)
		}
		read += count
		if read == len(destination) {
			if cancellation := reader.ctx.Err(); cancellation != nil {
				return newD1OuterFailure(StageCancellation, cancellation)
			}
			return nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return newD1OuterFailure(StageD1Body, errD1OuterAuthentication)
		}
		if err != nil {
			return newD1OuterFailure(StageInputIO, err)
		}
		if count == 0 {
			return newD1OuterFailure(StageInputIO, errD1ReaderProgress)
		}
	}
	return nil
}
