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

type d1ForceReaderPolicy struct {
	request   d1RecoveryRequest
	candidate *d1ForceCandidate
	seams     d1ForceSeams
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
	force             *d1ForceReaderPolicy
	closed            bool
}

func newD1InnerReaderFromCompleteAnalysis(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	analysis *d1ForceCandidateAnalysis,
) (*d1InnerReader, error) {
	if source == nil || sourceSize < 0 || analysis == nil || analysis.candidate == nil ||
		!analysis.candidate.valid() || !analysis.outerAnchored ||
		!analysis.outerFullyAuthenticated || analysis.bodyWindow.offset < 0 ||
		analysis.bodyWindow.length < 0 ||
		uint64(analysis.bodyWindow.length) != analysis.candidate.bodyLength { //nolint:gosec // The non-negative guard proves the conversion.
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	if !normalD1Geometry(sourceSize, analysis.candidate.bodyLength) {
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	wantWindow, err := deriveD1ForceBodyWindow(
		sourceSize,
		analysis.candidate.bodyLength,
		analysis.candidate.role,
	)
	if err != nil || wantWindow != analysis.bodyWindow {
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	geometry, err := parseD1OuterGeometry(analysis.candidate.bodyLength)
	if err != nil || geometry != analysis.geometry {
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	body := io.NewSectionReader(
		source,
		analysis.bodyWindow.offset,
		analysis.bodyWindow.length,
	)
	return newD1InnerReaderConfigured(
		ctx,
		body,
		analysis.candidate.bodyLength,
		analysis.candidate,
		defaultD1InnerReaderSeams(),
		nil,
		analysis,
	)
}

func newD1ForceInnerReader(
	ctx context.Context,
	source io.ReaderAt,
	request d1RecoveryRequest,
	analysis *d1ForceCandidateAnalysis,
	seams d1ForceSeams,
) (*d1InnerReader, error) {
	if source == nil || analysis == nil || analysis.candidate == nil ||
		analysis.bodyWindow.offset < 0 || analysis.bodyWindow.length < 0 {
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	body := io.NewSectionReader(
		source,
		analysis.bodyWindow.offset,
		analysis.bodyWindow.length,
	)
	return newD1InnerReaderConfigured(
		ctx,
		body,
		analysis.candidate.bodyLength,
		analysis.candidate,
		defaultD1InnerReaderSeams(),
		&d1ForceReaderPolicy{
			request:   request,
			candidate: analysis.candidate,
			seams:     seams,
		},
		nil,
	)
}

func newD1InnerReaderConfigured(
	ctx context.Context,
	source io.ReaderAt,
	bodyLength uint64,
	outerKeys d1OuterKeyAccess,
	seams d1InnerReaderSeams,
	force *d1ForceReaderPolicy,
	completeAnalysis *d1ForceCandidateAnalysis,
) (*d1InnerReader, error) {
	if ctx == nil || source == nil || outerKeys == nil || seams.openRecord == nil {
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	if completeAnalysis != nil {
		candidate, ok := outerKeys.(*d1ForceCandidate)
		if force != nil || !ok || candidate != completeAnalysis.candidate ||
			!completeAnalysis.outerAnchored || !completeAnalysis.outerFullyAuthenticated {
			return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
		}
	}
	if force != nil && (!force.request.valid() || force.candidate == nil ||
		!force.candidate.valid() || force.seams.authenticateRecord == nil ||
		force.seams.decryptRecord == nil) {
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	if err := ctx.Err(); err != nil {
		return nil, newD1OuterFailure(StageCancellation, err)
	}
	geometry, err := parseD1OuterGeometry(bodyLength)
	if err != nil || bodyLength > math.MaxInt64 {
		return nil, newD1OuterFailure(StageD1Body, errInvalidD1OuterGeometry)
	}
	if completeAnalysis != nil && completeAnalysis.geometry != geometry {
		return nil, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
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
		force:             force,
	}
	success := false
	defer func() {
		if !success {
			reader.Close()
		}
	}()
	if force == nil && completeAnalysis == nil {
		if err := reader.authenticateAll(); err != nil {
			return nil, err
		}
	}
	first, err := expectedD1OuterRecord(geometry, 0)
	if err != nil {
		return nil, err
	}
	plaintext, authenticated, err := reader.openExpectedWithState(first)
	if err != nil {
		return nil, err
	}
	defer pcv3crypto.SecureZero(plaintext)
	prefixValid := len(plaintext) >= d1OuterPrefixLength &&
		bytes.Equal(plaintext[:8], []byte(d1OuterMarker)) &&
		binary.BigEndian.Uint64(plaintext[8:16]) == geometry.innerLength
	if !prefixValid && (force == nil || authenticated) {
		return nil, newD1OuterFailure(StageD1Body, errD1OuterAuthentication)
	}
	success = true
	return reader, nil
}

func (reader *d1InnerReader) Size() int64 {
	if reader == nil {
		return 0
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed || reader.geometry.innerLength > math.MaxInt64 {
		return 0
	}
	return int64(reader.geometry.innerLength)
}

func (reader *d1InnerReader) ReadAt(destination []byte, offset int64) (int, error) {
	if reader == nil {
		pcv3crypto.SecureZero(destination)
		return 0, newD1OuterFailure(StageD1Body, errD1ReaderProgress)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed || reader.ctx == nil || reader.source == nil || reader.codec == nil ||
		reader.seams.openRecord == nil || offset < 0 {
		pcv3crypto.SecureZero(destination)
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

	if reader.force == nil {
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
	reader.force = nil
}

func (reader *d1InnerReader) authenticateAll() error {
	return evaluateD1OuterRecords(
		reader.ctx,
		reader.source,
		reader.geometry,
		reader.codec,
		reader.ciphertextScratch,
		reader.tagScratch[:],
		func(_ d1OuterRecordExpectation, authenticationErr error) error {
			return authenticationErr
		},
	)
}

func (reader *d1InnerReader) openExpected(
	expected d1OuterRecordExpectation,
) ([]byte, error) {
	plaintext, _, err := reader.openExpectedWithState(expected)
	return plaintext, err
}

func (reader *d1InnerReader) openExpectedWithState(
	expected d1OuterRecordExpectation,
) ([]byte, bool, error) {
	ciphertext, tag, err := reader.loadExpected(expected)
	if err != nil {
		return nil, false, err
	}
	plaintext := reader.plaintextScratch[:expected.ciphertextLength]
	pcv3crypto.SecureZero(plaintext)
	authenticated := true
	if reader.force == nil {
		err = reader.seams.openRecord(
			reader.codec,
			reader.ctx,
			expected.index,
			expected.final,
			ciphertext,
			tag,
			plaintext,
		)
	} else {
		authenticated, err = openD1ForceRecord(
			reader.ctx,
			reader.force.request,
			reader.force.candidate,
			reader.codec,
			expected,
			ciphertext,
			tag,
			plaintext,
			reader.force.seams,
		)
	}
	if err != nil {
		pcv3crypto.SecureZero(plaintext)
		return nil, false, err
	}
	return plaintext, authenticated, nil
}

func (reader *d1InnerReader) loadExpected(
	expected d1OuterRecordExpectation,
) ([]byte, []byte, error) {
	return loadD1OuterRecord(
		reader.ctx,
		reader.source,
		expected,
		reader.ciphertextScratch,
		reader.tagScratch[:],
	)
}
