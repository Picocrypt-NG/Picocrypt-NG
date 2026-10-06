package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	pcv3stream "Picocrypt-NG/internal/pcv3operation/internal/pcv3crypto"
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
	errInvalidD1Creation  = errors.New("pcv3: invalid D1 creation request")
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

type d1CreationBoundary uint8

const (
	d1BoundaryStageCreated d1CreationBoundary = iota + 1
	d1BoundaryOuterEntropy
	d1BoundaryFactors
	d1BoundaryFrontBootstrap
	d1BoundaryBody
	d1BoundaryInnerEntropy
	d1BoundaryTailBootstrap
	d1BoundaryFlush
	d1BoundaryPublish
)

func (boundary d1CreationBoundary) String() string {
	switch boundary {
	case d1BoundaryStageCreated:
		return "stage-created"
	case d1BoundaryOuterEntropy:
		return "outer-entropy"
	case d1BoundaryFactors:
		return "factors"
	case d1BoundaryFrontBootstrap:
		return "front-bootstrap"
	case d1BoundaryBody:
		return "body"
	case d1BoundaryInnerEntropy:
		return "inner-entropy"
	case d1BoundaryTailBootstrap:
		return "tail-bootstrap"
	case d1BoundaryFlush:
		return "flush"
	case d1BoundaryPublish:
		return "publish"
	default:
		return "unknown-boundary"
	}
}

type d1BootstrapWriteParameters struct {
	argonSalt     [16]byte
	wrapNonce     [24]byte
	wrapSerpentIV [16]byte
}

type d1CreationSecrets struct {
	front     d1BootstrapWriteParameters
	tail      d1BootstrapWriteParameters
	innerSalt [16]byte
	volumeID  [32]byte
	volumeKey []byte
	outerKey  []byte
}

func (secrets *d1CreationSecrets) close() {
	if secrets == nil {
		return
	}
	pcv3crypto.SecureZero(secrets.front.argonSalt[:])
	pcv3crypto.SecureZero(secrets.front.wrapNonce[:])
	pcv3crypto.SecureZero(secrets.front.wrapSerpentIV[:])
	pcv3crypto.SecureZero(secrets.tail.argonSalt[:])
	pcv3crypto.SecureZero(secrets.tail.wrapNonce[:])
	pcv3crypto.SecureZero(secrets.tail.wrapSerpentIV[:])
	pcv3crypto.SecureZero(secrets.innerSalt[:])
	pcv3crypto.SecureZero(secrets.volumeID[:])
	pcv3crypto.SecureZero(secrets.volumeKey)
	pcv3crypto.SecureZero(secrets.outerKey)
	secrets.volumeKey = nil
	secrets.outerKey = nil
}

type d1CreationCredentialSession func(
	context.Context,
	*pcv3credential.FactorRequest,
	*d1CreationSecrets,
	pcv3credential.Admitter,
	func(d1CreationBoundary) error,
	func(
		d1BootstrapCredentialAccess,
		d1BootstrapCredentialAccess,
		d1OuterKeyAccess,
		normalWriteMaterial,
	) error,
) error

func newD1CreationSecrets(
	ctx context.Context,
	entropy io.Reader,
	observe func(d1CreationBoundary) error,
) (*d1CreationSecrets, error) {
	if ctx == nil || entropy == nil || observe == nil {
		return nil, newD1OuterFailure(StageRNG, errInvalidD1Creation)
	}
	secrets := &d1CreationSecrets{
		volumeKey: make([]byte, 32),
		outerKey:  make([]byte, 32),
	}
	success := false
	defer func() {
		if !success {
			secrets.close()
		}
	}()
	for _, destination := range [][]byte{
		secrets.front.argonSalt[:],
		secrets.tail.argonSalt[:],
		secrets.front.wrapNonce[:],
		secrets.tail.wrapNonce[:],
		secrets.front.wrapSerpentIV[:],
		secrets.tail.wrapSerpentIV[:],
		secrets.innerSalt[:],
		secrets.volumeID[:],
		secrets.volumeKey,
		secrets.outerKey,
	} {
		if err := observe(d1BoundaryOuterEntropy); err != nil {
			return nil, err
		}
		if err := readD1CreationEntropy(ctx, entropy, destination); err != nil {
			return nil, err
		}
	}
	if secrets.front.argonSalt == secrets.tail.argonSalt ||
		secrets.front.wrapNonce == secrets.tail.wrapNonce ||
		secrets.front.wrapSerpentIV == secrets.tail.wrapSerpentIV {
		return nil, newD1OuterFailure(StageRNG, errInvalidD1Creation)
	}
	success = true
	return secrets, nil
}

func readD1CreationEntropy(
	ctx context.Context,
	reader io.Reader,
	destination []byte,
) error {
	if err := ctx.Err(); err != nil {
		return newD1OuterFailure(StageCancellation, err)
	}
	count, err := io.ReadFull(reader, destination)
	if ctxErr := ctx.Err(); ctxErr != nil {
		pcv3crypto.SecureZero(destination)
		return newD1OuterFailure(StageCancellation, ctxErr)
	}
	if err != nil || count != len(destination) {
		pcv3crypto.SecureZero(destination)
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return newD1OuterFailure(StageRNG, err)
	}
	return nil
}

type d1CreationEntropyReader struct {
	ctx      context.Context
	reader   io.Reader
	observe  func(d1CreationBoundary) error
	boundary d1CreationBoundary
}

func (reader *d1CreationEntropyReader) Read(destination []byte) (int, error) {
	if reader == nil || reader.ctx == nil || reader.reader == nil || reader.observe == nil {
		return 0, errInvalidD1Creation
	}
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if err := reader.observe(reader.boundary); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(destination)
	if ctxErr := reader.ctx.Err(); ctxErr != nil {
		return count, ctxErr
	}
	return count, err
}

func withD1ProductionCredentialSession(
	ctx context.Context,
	request *pcv3credential.FactorRequest,
	secrets *d1CreationSecrets,
	admitter pcv3credential.Admitter,
	observe func(d1CreationBoundary) error,
	callback func(
		d1BootstrapCredentialAccess,
		d1BootstrapCredentialAccess,
		d1OuterKeyAccess,
		normalWriteMaterial,
	) error,
) error {
	if ctx == nil || request == nil || secrets == nil || admitter == nil ||
		observe == nil || callback == nil {
		return errInvalidD1Creation
	}
	if err := observe(d1BoundaryFactors); err != nil {
		return err
	}
	return pcv3credential.WithValidatedFactors(
		ctx,
		request,
		func(factors *pcv3credential.ValidatedFactors) error {
			transcript, err := pcv3credential.NewCanonicalTranscript(factors)
			if err != nil {
				return err
			}
			defer transcript.Close()
			normalInput, outerInput, err := pcv3credential.NewD1CredentialInputs(transcript)
			if err != nil {
				return err
			}
			defer normalInput.Close()
			defer outerInput.Close()

			outerKeyTransfer := secrets.outerKey
			secrets.outerKey = nil
			outerOwner, err := pcv3credential.NewD1OuterKeyOwner(outerKeyTransfer)
			if err != nil {
				return err
			}
			defer outerOwner.Close()
			return pcv3credential.WithD1CreationCredentialRoots(
				ctx,
				normalInput,
				outerInput,
				pcv3credential.D1CreationSalts{
					Front: secrets.front.argonSalt,
					Tail:  secrets.tail.argonSalt,
				},
				admitter,
				func(
					front *pcv3credential.D1OuterCredentialOwner,
					tail *pcv3credential.D1OuterCredentialOwner,
					innerInput *pcv3credential.CredentialInputNormal,
				) error {
					volumeKeyTransfer := secrets.volumeKey
					secrets.volumeKey = nil
					return pcv3credential.WithD1NormalCredentialOwner(
						ctx,
						innerInput,
						factors,
						secrets.innerSalt,
						secrets.volumeID,
						volumeKeyTransfer,
						admitter,
						func(normal *pcv3credential.Owner) error {
							return callback(
								&d1BootstrapOwnerAccess{owner: front},
								&d1BootstrapOwnerAccess{owner: tail},
								&d1OuterOwnerAccess{owner: outerOwner},
								ownerNormalWriteMaterial{owner: normal},
							)
						},
					)
				},
			)
		},
	)
}

func encodeD1Bootstrap(
	ctx context.Context,
	role D1BootstrapRole,
	bodyLength uint64,
	parameters d1BootstrapWriteParameters,
	credentials d1BootstrapCredentialAccess,
	outer d1OuterKeyAccess,
) (encoded [d1BootstrapLength]byte, returnErr error) {
	if ctx == nil || ctx.Err() != nil || !validD1BootstrapRole(role) ||
		credentials == nil || credentials.role() != role || outer == nil || bodyLength == 0 {
		if ctx != nil && ctx.Err() != nil {
			return encoded, newD1OuterFailure(StageCancellation, ctx.Err())
		}
		return encoded, newD1OuterFailure(StageD1Bootstrap, errInvalidD1Creation)
	}
	candidate := d1BootstrapCandidate{
		role:          role,
		argonSalt:     parameters.argonSalt,
		wrapNonce:     parameters.wrapNonce,
		wrapSerpentIV: parameters.wrapSerpentIV,
	}
	defer clearD1BootstrapCandidate(&candidate)
	var outerSecret [d1OuterSecretLength]byte
	var replicaKey [32]byte
	defer pcv3crypto.SecureZero(outerSecret[:])
	defer pcv3crypto.SecureZero(replicaKey[:])
	binary.BigEndian.PutUint64(outerSecret[32:], bodyLength)
	if err := outer.withOuterKeys(
		ctx,
		func(keys *pcv3credential.BorrowedD1OuterKeys) error {
			if keys == nil {
				return errInvalidD1Creation
			}
			if err := keys.CopyOuterKey(outerSecret[:32]); err != nil {
				return err
			}
			return keys.CopyKey(
				pcv3credential.D1OuterReplicaMAC,
				keyRoleForD1Bootstrap(role),
				replicaKey[:],
			)
		},
	); err != nil {
		return encoded, newD1OuterFailure(StageD1Bootstrap, err)
	}
	if err := credentials.withWrapKeys(ctx, func(keys *d1BootstrapWrapKeys) error {
		if keys == nil {
			return errInvalidD1Creation
		}
		if err := pcv3stream.PCV3WrapParanoid1(
			candidate.wrappedSecret[:],
			outerSecret[:],
			keys.xChaCha20[:],
			candidate.wrapNonce[:],
			keys.serpent[:],
			candidate.wrapSerpentIV[:],
		); err != nil {
			return err
		}
		replicaMessage := d1BootstrapReplicaMessage(candidate)
		defer pcv3crypto.SecureZero(replicaMessage)
		replicaTag, err := suiteMACTag(SuiteParanoid, replicaKey[:], replicaMessage)
		if err != nil {
			return err
		}
		candidate.replicaTag = replicaTag
		pcv3crypto.SecureZero(replicaTag[:])
		wrapMessage := d1BootstrapWrapMessage(candidate)
		defer pcv3crypto.SecureZero(wrapMessage)
		wrapTag, err := suiteMACTag(SuiteParanoid, keys.mac[:], wrapMessage)
		if err != nil {
			return err
		}
		candidate.wrapTag = wrapTag
		pcv3crypto.SecureZero(wrapTag[:])
		return nil
	}); err != nil {
		return encoded, newD1OuterFailure(StageD1Bootstrap, err)
	}
	copy(encoded[0:16], candidate.argonSalt[:])
	copy(encoded[16:40], candidate.wrapNonce[:])
	copy(encoded[40:56], candidate.wrapSerpentIV[:])
	copy(encoded[56:96], candidate.wrappedSecret[:])
	copy(encoded[96:160], candidate.replicaTag[:])
	copy(encoded[160:224], candidate.wrapTag[:])
	return encoded, nil
}

func clearD1BootstrapCandidate(candidate *d1BootstrapCandidate) {
	if candidate == nil {
		return
	}
	pcv3crypto.SecureZero(candidate.argonSalt[:])
	pcv3crypto.SecureZero(candidate.wrapNonce[:])
	pcv3crypto.SecureZero(candidate.wrapSerpentIV[:])
	pcv3crypto.SecureZero(candidate.wrappedSecret[:])
	pcv3crypto.SecureZero(candidate.replicaTag[:])
	pcv3crypto.SecureZero(candidate.wrapTag[:])
	candidate.role = 0
}

func writeD1CreationExact(
	ctx context.Context,
	destination io.Writer,
	source []byte,
) error {
	if ctx == nil || destination == nil {
		return newD1OuterFailure(StageOutputWrite, errInvalidD1Creation)
	}
	if err := ctx.Err(); err != nil {
		return newD1OuterFailure(StageCancellation, err)
	}
	count, err := destination.Write(source)
	if count < 0 || count > len(source) {
		return newD1OuterFailure(StageOutputWrite, errD1WriterProgress)
	}
	if err != nil {
		return newD1OuterFailure(StageOutputWrite, err)
	}
	if count != len(source) {
		return newD1OuterFailure(StageOutputWrite, io.ErrShortWrite)
	}
	if err := ctx.Err(); err != nil {
		return newD1OuterFailure(StageCancellation, err)
	}
	return nil
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
		writer.written += uint64(copied) //nolint:gosec // copied is min of two non-negative slice lengths and requested was checked above.
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
	binary.BigEndian.PutUint64(prefix[8:], uint64(plan.normal.geometry.fileSize)) //nolint:gosec // planD1Write rejects a negative normal geometry before returning this plan.
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
