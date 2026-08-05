package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/util"
	"context"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const recordMACDomain = "Picocrypt-NG/PCV3/record\x00"

var (
	errInvalidRecordRequest       = errors.New("pcv3: invalid record request")
	errRecordDescriptorRecovery   = errors.New("pcv3: record descriptor recovery failed")
	errRecordBodyRecovery         = errors.New("pcv3: record body recovery failed")
	errRecordAuthentication       = errors.New("pcv3: record authentication failed")
	errRecordAccounting           = errors.New("pcv3: record accounting failed")
	errRecordCipher               = errors.New("pcv3: record cipher failed")
	errRecordUnexpectedTruncation = errors.New("pcv3: record truncated")
)

// normalRecordSink receives only authenticated data-record plaintext. The
// supplied slice is a callback-scoped borrow and is cleared when the call
// returns. The final record is authenticated but is never emitted.
type normalRecordSink interface {
	writeVerifiedRecord(context.Context, uint64, []byte) error
}

// recordVerification is created only after every canonical data record and the
// mandatory final record have authenticated. It is not whole-volume completion;
// the normal reader still owns suffix and EOF closure.
type recordVerification struct {
	dataRecords    uint64
	plaintextBytes uint64
}

// recordFailure keeps post-authentication record classification package-local.
// Its fixed formatting never includes source, sink, key, descriptor, or tag
// material. Operational causes remain available only through errors.Is/As.
type recordFailure struct {
	stage Stage
	cause error
}

func (failure *recordFailure) Error() string {
	return "pcv3: record verification failed"
}

func (failure *recordFailure) String() string {
	return failure.Error()
}

func (failure *recordFailure) GoString() string {
	return failure.Error()
}

func (failure *recordFailure) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, failure.Error())
}

func (failure *recordFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

type recordExpectation struct {
	index             uint64
	final             bool
	plaintextOffset   uint64
	ciphertextLength  uint64
	descriptor        [16]byte
	descriptorOffset  int64
	bodyOffset        int64
	encodedBodyLength int
	nonce             [24]byte
	serpentIV         [16]byte
}

type recordAuthenticationState uint8

const (
	recordAuthenticationVerified recordAuthenticationState = iota + 1
	recordAuthenticationUnverified
)

// recordEvidence contains only canonical identity and authentication state.
// Plaintext is lent separately and never becomes part of retained evidence.
type recordEvidence struct {
	index           uint64
	final           bool
	plaintextOffset uint64
	plaintextLength uint64
	authentication  recordAuthenticationState
}

type recordEngineSeams struct {
	decodeDescriptor func(*pcencoding.RSCodecs, []byte, []byte) error
	decodeBody       func(*pcencoding.RSCodecs, []byte, []byte, bool) error
	decryptStandard  func([]byte, []byte, []byte, []byte) error
	decryptParanoid  func([]byte, []byte, []byte, []byte, []byte, []byte) error
}

type recordKeys struct {
	xChaCha20 [32]byte
	serpent   [32]byte
	mac       [32]byte
}

func (keys *recordKeys) close() {
	if keys == nil {
		return
	}
	pcv3crypto.SecureZero(keys.xChaCha20[:])
	pcv3crypto.SecureZero(keys.serpent[:])
	pcv3crypto.SecureZero(keys.mac[:])
}

// recordEvaluator owns the one-record scratch and key material shared by
// normal and recovery record traversal. Policy remains with its callers.
type recordEvaluator struct {
	ctx               context.Context
	source            io.ReaderAt
	core              logicalCore
	geometry          Geometry
	codecs            *pcencoding.RSCodecs
	keys              *recordKeys
	commitment        [32]byte
	seams             recordEngineSeams
	encodedDescriptor [recordDescriptorSize]byte
	decodedDescriptor [16]byte
	encodedBody       []byte
	decodedBody       []byte
	plaintext         []byte
	closed            bool
}

func (evaluator *recordEvaluator) close() {
	if evaluator == nil || evaluator.closed {
		return
	}
	evaluator.closed = true
	if evaluator.keys != nil {
		evaluator.keys.close()
		evaluator.keys = nil
	}
	pcv3crypto.SecureZero(evaluator.commitment[:])
	pcv3crypto.SecureZero(evaluator.encodedDescriptor[:])
	pcv3crypto.SecureZero(evaluator.decodedDescriptor[:])
	pcv3crypto.SecureZero(evaluator.encodedBody)
	pcv3crypto.SecureZero(evaluator.decodedBody)
	pcv3crypto.SecureZero(evaluator.plaintext)
	evaluator.encodedBody = nil
	evaluator.decodedBody = nil
	evaluator.plaintext = nil
	evaluator.ctx = nil
	evaluator.source = nil
	evaluator.core = logicalCore{}
	evaluator.geometry = Geometry{}
	evaluator.codecs = nil
	evaluator.seams = recordEngineSeams{}
}

// expectedRecord derives one data/final descriptor and its physical extent
// exclusively from canonical core geometry and the expected index.
func expectedRecord(
	core logicalCore,
	geometry Geometry,
	index uint64,
) (recordExpectation, error) {
	if geometry.frontHeaderLength < 0 || geometry.backupCapsuleOffset < 0 ||
		!recordGeometryMatchesCore(core, geometry) ||
		index > core.recordCount || index >= maximumRecordCount {
		return recordExpectation{}, errInvalidRecordRequest
	}

	expected := recordExpectation{
		index: index,
		final: index == core.recordCount,
	}
	if expected.final {
		expected.plaintextOffset = core.plaintextLength
	} else {
		offset, ok := checkedMul64(index, recordPlaintextMax)
		if !ok || offset >= core.plaintextLength {
			return recordExpectation{}, errInvalidRecordRequest
		}
		expected.plaintextOffset = offset
		remaining := core.plaintextLength - offset
		expected.ciphertextLength = min(uint64(recordPlaintextMax), remaining)
	}

	binary.BigEndian.PutUint64(expected.descriptor[0:8], index)
	binary.BigEndian.PutUint32(
		expected.descriptor[8:12],
		uint32(expected.ciphertextLength), //nolint:gosec // Canonical length is at most 1 MiB.
	)
	if expected.final {
		expected.descriptor[12] = 1
	}

	relativeOffset, ok := recordOffsetWithinPayload(core, geometry.payloadBodyRS, index)
	if !ok {
		return recordExpectation{}, errInvalidRecordRequest
	}
	frontHeaderLength := uint64(geometry.frontHeaderLength)
	backupCapsuleOffset := uint64(geometry.backupCapsuleOffset)
	descriptorOffset, ok := checkedAdd64(frontHeaderLength, relativeOffset)
	if !ok {
		return recordExpectation{}, errInvalidRecordRequest
	}
	bodyOffset, ok := checkedAdd64(descriptorOffset, recordDescriptorSize)
	if !ok {
		return recordExpectation{}, errInvalidRecordRequest
	}
	encodedBodyLength, ok := encodedRecordBodyLength(
		expected.ciphertextLength,
		geometry.payloadBodyRS,
	)
	if !ok {
		return recordExpectation{}, errInvalidRecordRequest
	}
	recordEnd, ok := checkedAdd64(bodyOffset, encodedBodyLength)
	if !ok || recordEnd > backupCapsuleOffset ||
		(expected.final && recordEnd != backupCapsuleOffset) {
		return recordExpectation{}, errInvalidRecordRequest
	}

	expected.descriptorOffset, ok = util.SafeUint64ToInt64(descriptorOffset)
	if !ok {
		return recordExpectation{}, errInvalidRecordRequest
	}
	expected.bodyOffset, ok = util.SafeUint64ToInt64(bodyOffset)
	if !ok || encodedBodyLength > uint64(math.MaxInt) {
		return recordExpectation{}, errInvalidRecordRequest
	}
	expected.encodedBodyLength = int(encodedBodyLength)

	copy(expected.nonce[:16], core.xChaChaNoncePrefix[:])
	binary.BigEndian.PutUint64(expected.nonce[16:24], index)
	if core.suite == SuiteParanoid {
		copy(expected.serpentIV[:8], core.serpentIVPrefix[:])
		binary.BigEndian.PutUint64(expected.serpentIV[8:16], index<<16)
	}
	return expected, nil
}

func recordGeometryMatchesCore(core logicalCore, geometry Geometry) bool {
	if !validLogicalCore(core) ||
		geometry.frontHeaderLength < 0 || geometry.payloadLength < 0 ||
		geometry.backupCapsuleOffset < 0 ||
		geometry.recordCount != core.recordCount ||
		geometry.payloadBodyRS != (core.featureFlags&payloadBodyRSFeatureMask != 0) ||
		uint64(geometry.frontHeaderLength) != uint64(core.frontHeaderLength) {
		return false
	}
	payloadLength, ok := canonicalPayloadLength(
		core.plaintextLength,
		core.recordCount,
		geometry.payloadBodyRS,
	)
	if !ok || uint64(geometry.payloadLength) != payloadLength {
		return false
	}
	backupOffset, ok := checkedAdd64(uint64(geometry.frontHeaderLength), payloadLength)
	return ok && uint64(geometry.backupCapsuleOffset) == backupOffset
}

func recordOffsetWithinPayload(
	core logicalCore,
	payloadBodyRS bool,
	index uint64,
) (uint64, bool) {
	if !payloadBodyRS {
		plaintextBefore := core.plaintextLength
		if index < core.recordCount {
			var ok bool
			plaintextBefore, ok = checkedMul64(index, recordPlaintextMax)
			if !ok {
				return 0, false
			}
		}
		overheadBefore, ok := checkedMul64(index, nonRSPayloadOverhead)
		if !ok {
			return 0, false
		}
		return checkedAdd64(plaintextBefore, overheadBefore)
	}

	if index < core.recordCount {
		return checkedMul64(index, fullRSPayloadRecord)
	}
	fullRecords := core.plaintextLength / recordPlaintextMax
	offset, ok := checkedMul64(fullRecords, fullRSPayloadRecord)
	if !ok {
		return 0, false
	}
	partialLength := core.plaintextLength % recordPlaintextMax
	if partialLength == 0 {
		return offset, true
	}
	partialBodyLength, ok := encodedRecordBodyLength(partialLength, true)
	if !ok {
		return 0, false
	}
	partialRecordLength, ok := checkedAdd64(recordDescriptorSize, partialBodyLength)
	if !ok {
		return 0, false
	}
	return checkedAdd64(offset, partialRecordLength)
}

func encodedRecordBodyLength(ciphertextLength uint64, payloadBodyRS bool) (uint64, bool) {
	semanticLength, ok := checkedAdd64(ciphertextLength, recordTagSize)
	if !ok {
		return 0, false
	}
	if !payloadBodyRS {
		return semanticLength, true
	}
	blocks, ok := checkedCeilDiv64(semanticLength, rs128DataLength)
	if !ok {
		return 0, false
	}
	return checkedMul64(blocks, rs128CodewordLength)
}

func newRecordEvaluator(
	ctx context.Context,
	source io.ReaderAt,
	core logicalCore,
	geometry Geometry,
	codecs *pcencoding.RSCodecs,
	keyBorrower normalKeyBorrower,
	seams recordEngineSeams,
) (*recordEvaluator, error) {
	if ctx == nil || keyBorrower == nil {
		return nil, newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
	}
	if err := ctx.Err(); err != nil {
		return nil, newRecordFailure(StageCancellation, err)
	}
	if source == nil {
		return nil, newRecordFailure(StageInputIO, errInvalidReader)
	}
	if !recordGeometryMatchesCore(core, geometry) ||
		!validRecordCodecs(codecs, geometry.payloadBodyRS) || !validRecordSeams(seams) {
		return nil, newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
	}

	maximum, err := expectedRecord(core, geometry, 0)
	if err != nil {
		return nil, newRecordFailure(StageCredentialPolicy, err)
	}
	final, err := expectedRecord(core, geometry, core.recordCount)
	if err != nil {
		return nil, newRecordFailure(StageCredentialPolicy, err)
	}
	if final.encodedBodyLength > maximum.encodedBodyLength {
		maximum = final
	}
	decodedBodyLength, ok := decodedRecordBodyLength(maximum, geometry.payloadBodyRS)
	if !ok || maximum.ciphertextLength > uint64(math.MaxInt) {
		return nil, newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
	}

	evaluator := &recordEvaluator{
		ctx:         ctx,
		source:      source,
		core:        core,
		geometry:    geometry,
		codecs:      codecs,
		seams:       seams,
		encodedBody: make([]byte, maximum.encodedBodyLength),
		decodedBody: make([]byte, decodedBodyLength),
		plaintext:   make([]byte, int(maximum.ciphertextLength)),
	}
	success := false
	defer func() {
		if !success {
			evaluator.close()
		}
	}()
	evaluator.keys, err = loadRecordKeys(ctx, keyBorrower, core.suite)
	if err != nil {
		return nil, err
	}
	evaluator.commitment = coreCommitment(core)
	success = true
	return evaluator, nil
}

// evaluateCanonicalRecord is the single descriptor/RS/MAC/cipher boundary.
// It derives every record parameter internally and lends plaintext only for
// the callback duration. Unauthenticated bytes require live role-bound
// unverified authority; all other requests fail before decryption.
func (evaluator *recordEvaluator) evaluateCanonicalRecord(
	index uint64,
	request recoveryRequest,
	role CapsuleRole,
	callback func(recordEvidence, []byte) error,
) error {
	if evaluator == nil || evaluator.closed || evaluator.ctx == nil ||
		evaluator.source == nil || evaluator.keys == nil || callback == nil {
		return newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
	}
	if err := evaluator.ctx.Err(); err != nil {
		return newRecordFailure(StageCancellation, err)
	}
	expected, err := expectedRecord(evaluator.core, evaluator.geometry, index)
	if err != nil {
		return newRecordFailure(StageCredentialPolicy, err)
	}
	recordStage := StageDescriptor
	if expected.final {
		recordStage = StageFinalRecord
	}

	pcv3crypto.SecureZero(evaluator.encodedDescriptor[:])
	pcv3crypto.SecureZero(evaluator.decodedDescriptor[:])
	if err := readRecordExactAt(
		evaluator.ctx,
		evaluator.source,
		expected.descriptorOffset,
		evaluator.encodedDescriptor[:],
		recordStage,
	); err != nil {
		return err
	}
	if err := evaluator.seams.decodeDescriptor(
		evaluator.codecs,
		evaluator.encodedDescriptor[:],
		evaluator.decodedDescriptor[:],
	); err != nil {
		return newRecordFailure(recordStage, err)
	}
	if subtle.ConstantTimeCompare(
		evaluator.decodedDescriptor[:],
		expected.descriptor[:],
	) != 1 {
		return newRecordFailure(recordStage, errRecordDescriptorRecovery)
	}

	encoded := evaluator.encodedBody[:expected.encodedBodyLength]
	pcv3crypto.SecureZero(evaluator.encodedBody)
	pcv3crypto.SecureZero(evaluator.decodedBody)
	bodyStage := StageRecordAuth
	if evaluator.geometry.payloadBodyRS {
		bodyStage = StageRecordBodyRS
	}
	if expected.final {
		bodyStage = StageFinalRecord
	}
	if err := readRecordExactAt(
		evaluator.ctx,
		evaluator.source,
		expected.bodyOffset,
		encoded,
		bodyStage,
	); err != nil {
		return err
	}

	decodedLength, ok := decodedRecordBodyLength(expected, evaluator.geometry.payloadBodyRS)
	if !ok || decodedLength > len(evaluator.decodedBody) {
		return newRecordFailure(bodyStage, errInvalidRecordRequest)
	}
	decoded := evaluator.decodedBody[:decodedLength]
	if evaluator.geometry.payloadBodyRS {
		if err := evaluator.seams.decodeBody(
			evaluator.codecs,
			encoded,
			decoded,
			false,
		); err != nil {
			return newRecordFailure(bodyStage, err)
		}
	} else {
		copy(decoded, encoded)
	}

	valid, err := authenticateDecodedRecord(
		evaluator.core.suite,
		evaluator.keys.mac[:],
		evaluator.commitment,
		expected,
		decoded,
	)
	if err != nil {
		return newRecordFailure(bodyStage, err)
	}
	if !valid && evaluator.geometry.payloadBodyRS {
		pcv3crypto.SecureZero(decoded)
		if err := evaluator.seams.decodeBody(
			evaluator.codecs,
			encoded,
			decoded,
			true,
		); err != nil {
			return newRecordFailure(bodyStage, err)
		}
		valid, err = authenticateDecodedRecord(
			evaluator.core.suite,
			evaluator.keys.mac[:],
			evaluator.commitment,
			expected,
			decoded,
		)
		if err != nil {
			return newRecordFailure(bodyStage, err)
		}
	}

	authentication := recordAuthenticationVerified
	if !valid {
		if !request.authorizesUnverified(role) {
			authStage := StageRecordAuth
			if expected.final {
				authStage = StageFinalRecord
			}
			return newRecordFailure(authStage, errRecordAuthentication)
		}
		authentication = recordAuthenticationUnverified
	}
	evidence := recordEvidence{
		index:           expected.index,
		final:           expected.final,
		plaintextOffset: expected.plaintextOffset,
		plaintextLength: expected.ciphertextLength,
		authentication:  authentication,
	}
	if expected.final {
		return callback(evidence, nil)
	}

	ciphertextLength := int(expected.ciphertextLength)
	ciphertext := decoded[:ciphertextLength]
	plain := evaluator.plaintext[:ciphertextLength]
	pcv3crypto.SecureZero(plain)
	defer pcv3crypto.SecureZero(plain)
	switch evaluator.core.suite {
	case SuiteStandard:
		err = evaluator.seams.decryptStandard(
			plain,
			ciphertext,
			evaluator.keys.xChaCha20[:],
			expected.nonce[:],
		)
	case SuiteParanoid:
		err = evaluator.seams.decryptParanoid(
			plain,
			ciphertext,
			evaluator.keys.xChaCha20[:],
			expected.nonce[:],
			evaluator.keys.serpent[:],
			expected.serpentIV[:],
		)
	default:
		err = errRecordCipher
	}
	if err != nil {
		return newRecordFailure(StageRecordAuth, errRecordCipher)
	}
	if err := evaluator.ctx.Err(); err != nil {
		return newRecordFailure(StageCancellation, err)
	}
	if err := callback(evidence, plain); err != nil {
		return err
	}
	if err := evaluator.ctx.Err(); err != nil {
		return newRecordFailure(StageCancellation, err)
	}
	return nil
}

// readNormalRecords authenticates and decrypts the canonical data/final
// sequence into an operation-owned nonpublishing sink. A nonzero summary is
// returned only after the final tag verifies.
func readNormalRecords(
	ctx context.Context,
	source io.ReaderAt,
	auth *normalAuthResult,
	codecs *pcencoding.RSCodecs,
	sink normalRecordSink,
) (recordVerification, error) {
	return readNormalRecordsWithSeams(
		ctx,
		source,
		auth,
		codecs,
		sink,
		defaultRecordEngineSeams(),
	)
}

func readNormalRecordsWithSeams(
	ctx context.Context,
	source io.ReaderAt,
	auth *normalAuthResult,
	codecs *pcencoding.RSCodecs,
	sink normalRecordSink,
	seams recordEngineSeams,
) (recordVerification, error) {
	if ctx == nil || sink == nil {
		return recordVerification{}, newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
	}
	if err := ctx.Err(); err != nil {
		return recordVerification{}, newRecordFailure(StageCancellation, err)
	}
	if source == nil {
		return recordVerification{}, newRecordFailure(StageInputIO, errInvalidReader)
	}
	core, geometry, ok := authenticatedRecordAuthority(auth)
	if !ok || !validRecordCodecs(codecs, geometry.payloadBodyRS) || !validRecordSeams(seams) {
		return recordVerification{}, newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
	}
	evaluator, err := newRecordEvaluator(
		ctx,
		source,
		core,
		geometry,
		codecs,
		auth,
		seams,
	)
	if err != nil {
		return recordVerification{}, err
	}
	defer evaluator.close()

	var dataRecords uint64
	var plaintextBytes uint64
	for index := uint64(0); ; index++ {
		var evidence recordEvidence
		var sinkErr error
		invalidEvidence := false
		err := evaluator.evaluateCanonicalRecord(
			index,
			recoveryRequest{},
			0,
			func(got recordEvidence, plaintext []byte) error {
				evidence = got
				if got.authentication != recordAuthenticationVerified {
					invalidEvidence = true
					return errInvalidRecordRequest
				}
				if got.final {
					return nil
				}
				sinkErr = sink.writeVerifiedRecord(ctx, got.index, plaintext)
				return sinkErr
			},
		)
		if invalidEvidence {
			return recordVerification{}, newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
		}
		if sinkErr != nil {
			if cancellation := recordCancellationCause(ctx, sinkErr); cancellation != nil {
				return recordVerification{}, newRecordFailure(StageCancellation, cancellation)
			}
			return recordVerification{}, newRecordFailure(StageOutputWrite, sinkErr)
		}
		if err != nil {
			return recordVerification{}, err
		}
		if evidence.final {
			if dataRecords != core.recordCount || plaintextBytes != core.plaintextLength {
				return recordVerification{}, newRecordFailure(StageFinalRecord, errRecordAccounting)
			}
			return recordVerification{
				dataRecords:    dataRecords,
				plaintextBytes: plaintextBytes,
			}, nil
		}
		dataRecords, ok = checkedAdd64(dataRecords, 1)
		if !ok {
			return recordVerification{}, newRecordFailure(StageRecordAuth, errRecordAccounting)
		}
		plaintextBytes, ok = checkedAdd64(plaintextBytes, evidence.plaintextLength)
		if !ok || plaintextBytes > core.plaintextLength {
			return recordVerification{}, newRecordFailure(StageRecordAuth, errRecordAccounting)
		}
	}
}

func authenticatedRecordAuthority(
	auth *normalAuthResult,
) (logicalCore, Geometry, bool) {
	if auth == nil || auth.authenticated == 0 ||
		(auth.outcome != OutcomeSuccess && auth.outcome != OutcomeAuthenticatedDegraded) ||
		auth.geometry.fileSize < 0 || !validLogicalCore(auth.candidate.core) {
		return logicalCore{}, Geometry{}, false
	}
	expected, err := DeriveGeometry(
		auth.candidate,
		uint64(auth.geometry.fileSize),
	)
	if err != nil || expected != auth.geometry {
		return logicalCore{}, Geometry{}, false
	}
	return auth.candidate.core, auth.geometry, true
}

func validRecordCodecs(codecs *pcencoding.RSCodecs, payloadBodyRS bool) bool {
	if codecs == nil || codecs.RS16 == nil ||
		codecs.RS16.Required() != 16 || codecs.RS16.Total() != int(recordDescriptorSize) {
		return false
	}
	return !payloadBodyRS ||
		(codecs.RS128 != nil &&
			codecs.RS128.Required() == int(rs128DataLength) &&
			codecs.RS128.Total() == int(rs128CodewordLength))
}

func validRecordSeams(seams recordEngineSeams) bool {
	return seams.decodeDescriptor != nil && seams.decodeBody != nil &&
		seams.decryptStandard != nil && seams.decryptParanoid != nil
}

func decodedRecordBodyLength(expected recordExpectation, payloadBodyRS bool) (int, bool) {
	if !payloadBodyRS {
		return expected.encodedBodyLength, true
	}
	if expected.encodedBodyLength <= 0 ||
		expected.encodedBodyLength%int(rs128CodewordLength) != 0 {
		return 0, false
	}
	blocks := expected.encodedBodyLength / int(rs128CodewordLength)
	if blocks > math.MaxInt/int(rs128DataLength) {
		return 0, false
	}
	return blocks * int(rs128DataLength), true
}

func loadRecordKeys(
	ctx context.Context,
	borrower normalKeyBorrower,
	suite Suite,
) (*recordKeys, error) {
	keys := &recordKeys{}
	success := false
	defer func() {
		if !success {
			keys.close()
		}
	}()
	borrow := func(label pcv3credential.KeyLabel, destination []byte) error {
		return borrower.withKey(
			ctx,
			pcv3credential.KeyRequest{
				Label:       label,
				Role:        pcv3credential.KeyRoleNotReplica,
				OutputBytes: 32,
			},
			func(key []byte) error {
				if len(key) != len(destination) {
					return errInvalidRecordRequest
				}
				copy(destination, key)
				return nil
			},
		)
	}
	if err := borrow(
		pcv3credential.KeyLabelVolumePayloadXChaCha20,
		keys.xChaCha20[:],
	); err != nil {
		return nil, classifyRecordKeyFailure(ctx, err)
	}
	if suite == SuiteParanoid {
		if err := borrow(
			pcv3credential.KeyLabelVolumePayloadSerpent,
			keys.serpent[:],
		); err != nil {
			return nil, classifyRecordKeyFailure(ctx, err)
		}
	} else if suite != SuiteStandard {
		return nil, newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
	}
	if err := borrow(
		pcv3credential.KeyLabelVolumePayloadMAC,
		keys.mac[:],
	); err != nil {
		return nil, classifyRecordKeyFailure(ctx, err)
	}
	success = true
	return keys, nil
}

func classifyRecordKeyFailure(ctx context.Context, cause error) error {
	if cancellation := recordCancellationCause(ctx, cause); cancellation != nil {
		return newRecordFailure(StageCancellation, cancellation)
	}
	return newRecordFailure(StageCredentialPolicy, cause)
}

func recordCancellationCause(ctx context.Context, cause error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	return nil
}

// coreCommitment is the single package-private serializer/hash boundary shared
// by metadata and record authentication.
func coreCommitment(core logicalCore) [32]byte {
	encoded := logicalCoreBytes(core)
	defer pcv3crypto.SecureZero(encoded[:])
	hasher := sha3.New256()
	_, _ = hasher.Write([]byte(coreCommitmentDomain))
	_, _ = hasher.Write(encoded[:])
	sum := hasher.Sum(nil)
	defer pcv3crypto.SecureZero(sum)
	var commitment [32]byte
	copy(commitment[:], sum)
	return commitment
}

func authenticateDecodedRecord(
	suite Suite,
	macKey []byte,
	commitment [32]byte,
	expected recordExpectation,
	decoded []byte,
) (bool, error) {
	semanticLength, ok := checkedAdd64(expected.ciphertextLength, recordTagSize)
	if !ok || semanticLength > uint64(len(decoded)) ||
		expected.ciphertextLength > uint64(math.MaxInt) || semanticLength > uint64(math.MaxInt) {
		return false, errRecordBodyRecovery
	}
	ciphertextLength := int(expected.ciphertextLength)
	semanticLengthInt := int(semanticLength)
	if !recordPaddingIsZero(decoded[semanticLengthInt:]) {
		return false, errRecordBodyRecovery
	}
	return verifyRecordTag(
		suite,
		macKey,
		commitment,
		expected.descriptor,
		decoded[:ciphertextLength],
		decoded[ciphertextLength:semanticLengthInt],
	)
}

func verifyRecordTag(
	suite Suite,
	key []byte,
	commitment [32]byte,
	descriptor [16]byte,
	ciphertext []byte,
	expectedTag []byte,
) (bool, error) {
	if len(expectedTag) != pcv3crypto.MACSize {
		return false, errRecordAuthentication
	}
	actual, err := recordTag(suite, key, commitment, descriptor, ciphertext)
	if err != nil {
		return false, err
	}
	defer pcv3crypto.SecureZero(actual[:])
	return subtle.ConstantTimeCompare(actual[:], expectedTag) == 1, nil
}

func recordTag(
	suite Suite,
	key []byte,
	commitment [32]byte,
	descriptor [16]byte,
	ciphertext []byte,
) ([pcv3crypto.MACSize]byte, error) {
	if len(key) != 32 || !isSupportedSuite(suite) {
		return [pcv3crypto.MACSize]byte{}, errRecordAuthentication
	}
	tag, err := suiteMACTag(
		suite,
		key,
		[]byte(recordMACDomain),
		commitment[:],
		descriptor[:],
		ciphertext,
	)
	if err != nil {
		return [pcv3crypto.MACSize]byte{}, errRecordAuthentication
	}
	return tag, nil
}

func recordPaddingIsZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func defaultRecordEngineSeams() recordEngineSeams {
	return recordEngineSeams{
		decodeDescriptor: decodeRecordDescriptor,
		decodeBody:       decodeRecordBody,
		decryptStandard:  pcv3crypto.PCV3UnwrapStandard1,
		decryptParanoid:  pcv3crypto.PCV3UnwrapParanoid1,
	}
}

func decodeRecordDescriptor(
	codecs *pcencoding.RSCodecs,
	encoded []byte,
	destination []byte,
) error {
	if codecs == nil || codecs.RS16 == nil ||
		len(encoded) != int(recordDescriptorSize) || len(destination) != 16 {
		return errRecordDescriptorRecovery
	}
	decoded, err := pcencoding.Decode(codecs.RS16, encoded, false)
	if err != nil || len(decoded) != len(destination) {
		return errRecordDescriptorRecovery
	}
	defer pcv3crypto.SecureZero(decoded)
	copy(destination, decoded)
	return nil
}

func decodeRecordBody(
	codecs *pcencoding.RSCodecs,
	encoded []byte,
	destination []byte,
	fullCorrection bool,
) error {
	if codecs == nil || codecs.RS128 == nil || len(encoded) == 0 ||
		len(encoded)%int(rs128CodewordLength) != 0 ||
		len(destination) != len(encoded)/int(rs128CodewordLength)*int(rs128DataLength) {
		return errRecordBodyRecovery
	}
	pcv3crypto.SecureZero(destination)
	blocks := len(encoded) / int(rs128CodewordLength)
	for block := range blocks {
		encodedStart := block * int(rs128CodewordLength)
		decodedStart := block * int(rs128DataLength)
		decoded, err := pcencoding.Decode(
			codecs.RS128,
			encoded[encodedStart:encodedStart+int(rs128CodewordLength)],
			!fullCorrection,
		)
		if err != nil || len(decoded) != int(rs128DataLength) {
			pcv3crypto.SecureZero(decoded)
			pcv3crypto.SecureZero(destination)
			return errRecordBodyRecovery
		}
		copy(destination[decodedStart:decodedStart+int(rs128DataLength)], decoded)
		if fullCorrection {
			pcv3crypto.SecureZero(decoded)
		}
	}
	return nil
}

func readRecordExactAt(
	ctx context.Context,
	source io.ReaderAt,
	offset int64,
	destination []byte,
	truncationStage Stage,
) error {
	if ctx == nil {
		return newRecordFailure(StageCredentialPolicy, errInvalidRecordRequest)
	}
	if source == nil || offset < 0 ||
		uint64(offset) > uint64(math.MaxInt64)-uint64(len(destination)) {
		return newRecordFailure(StageInputIO, errInvalidReader)
	}
	if err := ctx.Err(); err != nil {
		return newRecordFailure(StageCancellation, err)
	}
	if len(destination) == 0 {
		return nil
	}

	read := 0
	consecutiveNoProgress := 0
	callLimit := len(destination) + 2
	for range callLimit {
		if err := ctx.Err(); err != nil {
			return newRecordFailure(StageCancellation, err)
		}
		count, err := source.ReadAt(destination[read:], offset+int64(read))
		if cancellation := ctx.Err(); cancellation != nil {
			return newRecordFailure(StageCancellation, cancellation)
		}
		if count < 0 || count > len(destination)-read {
			return newRecordFailure(StageInputIO, errInvalidReadProgress)
		}
		if count > 0 {
			read += count
			consecutiveNoProgress = 0
		} else if err == nil {
			consecutiveNoProgress++
			if consecutiveNoProgress == 2 {
				return newRecordFailure(StageInputIO, errReaderNoProgress)
			}
		}

		if read == len(destination) {
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return newRecordFailure(StageInputIO, err)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return newRecordFailure(truncationStage, errRecordUnexpectedTruncation)
			}
			return newRecordFailure(StageInputIO, err)
		}
	}
	return newRecordFailure(StageInputIO, errReaderCallLimit)
}

func newRecordFailure(stage Stage, cause error) error {
	return &recordFailure{stage: stage, cause: cause}
}
