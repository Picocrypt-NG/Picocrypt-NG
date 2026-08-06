package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

const d1OuterMarker = "PCVOUT3\x00"

var (
	errInvalidD1WritePlan = errors.New("pcv3: invalid D1 write plan")
	errD1WriterProgress   = errors.New("pcv3: invalid D1 writer progress")
)

type d1WritePlan struct {
	normal   normalWritePlan
	outer    d1OuterGeometry
	fileSize uint64
}

func planD1Write(request normalWriteRequest) (d1WritePlan, error) {
	normal, err := planNormalWrite(request)
	if err != nil || normal.geometry.fileSize < 0 {
		return d1WritePlan{}, newD1OuterFailure(StageD1Body, errInvalidD1WritePlan)
	}
	outer, err := deriveD1OuterGeometry(uint64(normal.geometry.fileSize))
	if err != nil {
		return d1WritePlan{}, err
	}
	fileSize, ok := checkedAdd64(outer.bodyLength, 2*d1BootstrapLength)
	if !ok || fileSize > math.MaxInt64 {
		return d1WritePlan{}, newD1OuterFailure(StageD1Body, errInvalidD1WritePlan)
	}
	return d1WritePlan{normal: normal, outer: outer, fileSize: fileSize}, nil
}

type d1BodyWriteCompletion struct {
	bodyLength uint64
}

type d1OuterStreamWriter struct {
	ctx         context.Context
	destination io.Writer
	codec       *d1OuterCodec
	geometry    d1OuterGeometry
	scratch     []byte
	written     uint64
	index       uint64
	finished    bool
	closed      bool
}

func newD1OuterStreamWriter(
	ctx context.Context,
	destination io.Writer,
	codec *d1OuterCodec,
	geometry d1OuterGeometry,
) (*d1OuterStreamWriter, error) {
	if ctx == nil || destination == nil || codec == nil || codec.closed {
		return nil, newD1OuterFailure(StageD1Body, errD1WriterProgress)
	}
	canonical, err := deriveD1OuterGeometry(geometry.innerLength)
	if err != nil || canonical != geometry {
		return nil, newD1OuterFailure(StageD1Body, errD1WriterProgress)
	}
	return &d1OuterStreamWriter{
		ctx:         ctx,
		destination: destination,
		codec:       codec,
		geometry:    geometry,
		scratch:     make([]byte, 0, d1OuterChunkSize),
	}, nil
}

func (writer *d1OuterStreamWriter) Write(source []byte) (int, error) {
	if writer == nil || writer.closed || writer.finished || writer.ctx == nil ||
		writer.destination == nil || writer.codec == nil {
		return 0, newD1OuterFailure(StageD1Body, errD1WriterProgress)
	}
	if err := writer.ctx.Err(); err != nil {
		return 0, newD1OuterFailure(StageCancellation, err)
	}
	requested, ok := checkedAdd64(writer.written, uint64(len(source)))
	if !ok || requested > writer.geometry.plaintextLength {
		return 0, newD1OuterFailure(StageD1Body, errD1WriterProgress)
	}

	consumed := 0
	for len(source) != 0 {
		available := d1OuterChunkSize - len(writer.scratch)
		copied := min(available, len(source))
		writer.scratch = append(writer.scratch, source[:copied]...)
		source = source[copied:]
		consumed += copied
		writer.written += uint64(copied)
		if len(writer.scratch) == d1OuterChunkSize {
			if err := writer.emit(false); err != nil {
				return consumed, err
			}
		}
	}
	if err := writer.ctx.Err(); err != nil {
		return consumed, newD1OuterFailure(StageCancellation, err)
	}
	return consumed, nil
}

func (writer *d1OuterStreamWriter) Finish() error {
	if writer == nil || writer.closed || writer.finished ||
		writer.written != writer.geometry.plaintextLength ||
		writer.index != writer.geometry.fullRecords ||
		uint64(len(writer.scratch)) != writer.geometry.finalCiphertextLength {
		return newD1OuterFailure(StageD1Body, errD1WriterProgress)
	}
	if err := writer.ctx.Err(); err != nil {
		return newD1OuterFailure(StageCancellation, err)
	}
	if err := writer.emit(true); err != nil {
		return err
	}
	writer.finished = true
	return nil
}

func (writer *d1OuterStreamWriter) Close() {
	if writer == nil || writer.closed {
		return
	}
	writer.closed = true
	pcv3crypto.SecureZero(writer.scratch)
	writer.scratch = nil
	writer.ctx = nil
	writer.destination = nil
	writer.codec = nil
	writer.geometry = d1OuterGeometry{}
	writer.written = 0
	writer.index = 0
}

func (writer *d1OuterStreamWriter) emit(final bool) error {
	if writer.index >= writer.geometry.recordCount ||
		final != (writer.index == writer.geometry.fullRecords) {
		return newD1OuterFailure(StageD1Body, errD1WriterProgress)
	}
	tag, err := writer.codec.sealRecord(
		writer.ctx,
		writer.index,
		final,
		writer.scratch,
		writer.scratch,
	)
	if err != nil {
		pcv3crypto.SecureZero(writer.scratch)
		return err
	}
	defer pcv3crypto.SecureZero(tag[:])
	if err := writer.writeExact(writer.scratch); err != nil {
		pcv3crypto.SecureZero(writer.scratch)
		return err
	}
	if err := writer.writeExact(tag[:]); err != nil {
		pcv3crypto.SecureZero(writer.scratch)
		return err
	}
	pcv3crypto.SecureZero(writer.scratch)
	writer.scratch = writer.scratch[:0]
	writer.index++
	return nil
}

func (writer *d1OuterStreamWriter) writeExact(source []byte) error {
	if err := writer.ctx.Err(); err != nil {
		return newD1OuterFailure(StageCancellation, err)
	}
	count, err := writer.destination.Write(source)
	if count < 0 || count > len(source) {
		return newD1OuterFailure(StageOutputWrite, errD1WriterProgress)
	}
	if err != nil {
		return newD1OuterFailure(StageOutputWrite, err)
	}
	if count != len(source) {
		return newD1OuterFailure(StageOutputWrite, io.ErrShortWrite)
	}
	if err := writer.ctx.Err(); err != nil {
		return newD1OuterFailure(StageCancellation, err)
	}
	return nil
}

func writeD1NormalBody(
	ctx context.Context,
	request normalWriteRequest,
	source io.Reader,
	destination io.Writer,
	material normalWriteMaterial,
	seams normalWriteSeams,
	outerKeys d1OuterKeyAccess,
) (*d1BodyWriteCompletion, error) {
	if ctx == nil || source == nil || destination == nil || material == nil || outerKeys == nil {
		return nil, newD1OuterFailure(StageCredentialPolicy, errD1WriterProgress)
	}
	plan, err := planD1Write(request)
	if err != nil {
		return nil, err
	}
	codec, err := newD1OuterCodec(ctx, outerKeys)
	if err != nil {
		return nil, err
	}
	defer codec.Close()
	writer, err := newD1OuterStreamWriter(ctx, destination, codec, plan.outer)
	if err != nil {
		return nil, err
	}
	defer writer.Close()

	var prefix [d1OuterPrefixLength]byte
	defer pcv3crypto.SecureZero(prefix[:])
	copy(prefix[:8], d1OuterMarker)
	binary.BigEndian.PutUint64(prefix[8:], uint64(plan.normal.geometry.fileSize))
	if count, err := writer.Write(prefix[:]); err != nil || count != len(prefix) {
		if err == nil {
			err = newD1OuterFailure(StageOutputWrite, io.ErrShortWrite)
		}
		return nil, err
	}
	if _, err := serializeNormalVolume(
		ctx,
		request,
		source,
		writer,
		material,
		seams,
	); err != nil {
		return nil, err
	}
	if err := writer.Finish(); err != nil {
		return nil, err
	}
	return &d1BodyWriteCompletion{bodyLength: plan.outer.bodyLength}, nil
}
