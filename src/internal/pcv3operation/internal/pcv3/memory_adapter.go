package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
)

var errMemoryOutputLimit = errors.New("pcv3: memory output limit exceeded")

// MemoryWriteRequest transfers Factors and Comment on every path; Data must not alias their storage.
// Data is borrowed read-only. MaxOutputBytes comes from the application resource policy.
type MemoryWriteRequest struct {
	Suite          Suite
	PayloadKind    PayloadKind
	PayloadBodyRS  bool
	Comment        []byte
	Factors        *pcv3credential.FactorRequest
	Admitter       pcv3credential.Admitter
	Data           []byte
	Deniability    bool
	MaxOutputBytes uint64
}

// RunMemoryWrite reuses the native credential and serialization engines without
// creating a filesystem stage. It returns no bytes after any incomplete write.
func RunMemoryWrite(ctx context.Context, request *MemoryWriteRequest) ([]byte, error) {
	return runMemoryWrite(ctx, request, memoryD1WriteSeams{})
}

func runMemoryWrite(ctx context.Context, request *MemoryWriteRequest, seams memoryD1WriteSeams) ([]byte, error) {
	if request == nil {
		return nil, newNormalWriteFailure(StageCredentialPolicy, errInvalidNormalWriteRequest)
	}
	owned := *request
	*request = MemoryWriteRequest{}
	defer pcv3crypto.SecureZero(owned.Comment)
	defer closeRecoveryFactors(owned.Factors)
	owned.Factors.RequireNonemptyKeyfiles()
	normal := normalWriteRequest{
		suite: owned.Suite, payloadKind: owned.PayloadKind,
		payloadBodyRS: owned.PayloadBodyRS, plaintextLength: uint64(len(owned.Data)), comment: owned.Comment,
	}
	if ctx == nil || owned.Factors == nil || owned.Admitter == nil || !validNormalWriteRequest(normal) {
		return nil, newNormalWriteFailure(StageCredentialPolicy, errInvalidNormalWriteRequest)
	}
	if err := ctx.Err(); err != nil {
		return nil, newNormalWriteFailure(StageCancellation, err)
	}
	mode := WriteSizeNormal
	if owned.Deniability {
		mode = WriteSizeD1
	}
	length, err := WriteCiphertextLength(mode, uint64(len(owned.Data)), uint32(len(owned.Comment)), owned.PayloadBodyRS) //nolint:gosec // Comment length was validated above.
	if err != nil || !memoryLengthAllowed(length, owned.MaxOutputBytes) {
		return nil, newNormalWriteFailure(StageResourceBudget, errMemoryOutputLimit)
	}
	sink := &memoryExactWriter{data: make([]byte, int(length))} //nolint:gosec // memoryLengthAllowed checked the host-int bound above.
	completed := false
	defer func() {
		if !completed {
			pcv3crypto.SecureZero(sink.data)
		}
	}()
	if owned.Deniability {
		if seams.entropy == nil {
			seams.entropy = cryptorand.Reader
		}
		if seams.credentials == nil {
			seams.credentials = withD1ProductionCredentialSession
		}
		if seams.codecs == nil {
			var codecErr error
			seams.codecs, codecErr = pcencoding.NewRSCodecs()
			if codecErr != nil {
				return nil, newD1OuterFailure(StageD1Body, codecErr)
			}
		}
		err = writeMemoryD1(ctx, normal, bytes.NewReader(owned.Data), sink, owned.Factors, owned.Admitter,
			seams)
	} else {
		err = RunNativeNormalWrite(ctx, &NativeNormalWriteRequest{
			Suite: owned.Suite, PayloadKind: owned.PayloadKind,
			PayloadBodyRS: owned.PayloadBodyRS, PlaintextLength: uint64(len(owned.Data)), Comment: owned.Comment,
			Factors: owned.Factors, Admitter: owned.Admitter, Source: bytes.NewReader(owned.Data), Destination: sink,
		})
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, newNormalWriteFailure(StageCancellation, err)
	}
	if sink.written != len(sink.data) {
		return nil, newNormalWriteFailure(StageOutputWrite, errNormalWriteSinkProgress)
	}
	completed = true
	return sink.data, nil
}

type memoryExactWriter struct {
	data    []byte
	written int
}

func (sink *memoryExactWriter) Write(data []byte) (int, error) {
	if sink == nil || len(data) > len(sink.data)-sink.written {
		return 0, errMemoryOutputLimit
	}
	copy(sink.data[sink.written:], data)
	sink.written += len(data)
	return len(data), nil
}

type memoryD1WriteSeams struct {
	entropy     io.Reader
	codecs      *pcencoding.RSCodecs
	credentials d1CreationCredentialSession
}

// writeMemoryD1 composes the same front/body/tail serializers in the same order
// as the native publication adapter. Its only destination is the borrowed writer.
func writeMemoryD1(ctx context.Context, request normalWriteRequest, source io.Reader, destination io.Writer,
	factors *pcv3credential.FactorRequest, admitter pcv3credential.Admitter, seams memoryD1WriteSeams,
) error {
	if ctx == nil || source == nil || destination == nil || factors == nil || admitter == nil ||
		seams.credentials == nil || !validNormalWriteSeams(normalWriteSeams{entropy: seams.entropy, codecs: seams.codecs}) {
		return newD1OuterFailure(StageCredentialPolicy, errInvalidD1Creation)
	}
	plan, err := planD1Write(request)
	if err != nil {
		return err
	}
	observe := func(d1CreationBoundary) error {
		if err := ctx.Err(); err != nil {
			return newD1OuterFailure(StageCancellation, err)
		}
		return nil
	}
	secrets, err := newD1CreationSecrets(ctx, seams.entropy, observe)
	if err != nil {
		return err
	}
	defer secrets.close()
	secrets.profile = pcv3credential.D1ProfileForSuite(credentialSuite(request.suite))
	return seams.credentials(ctx, factors, secrets, admitter, observe,
		func(front, tail d1BootstrapCredentialAccess, outer d1OuterKeyAccess, normal normalWriteMaterial) error {
			frontBytes, err := encodeD1Bootstrap(ctx, D1BootstrapFront, plan.outer.bodyLength, secrets.front, front, outer)
			if err != nil {
				return err
			}
			defer pcv3crypto.SecureZero(frontBytes[:])
			if err := writeD1CreationExact(ctx, destination, frontBytes[:]); err != nil {
				return err
			}
			completion, err := writeD1NormalBody(ctx, request, source, destination, normal,
				normalWriteSeams{entropy: seams.entropy, codecs: seams.codecs}, outer)
			if err != nil {
				return err
			}
			if completion == nil || completion.bodyLength != plan.outer.bodyLength {
				return newD1OuterFailure(StageD1Body, errD1WriterProgress)
			}
			tailBytes, err := encodeD1Bootstrap(ctx, D1BootstrapTail, plan.outer.bodyLength, secrets.tail, tail, outer)
			if err != nil {
				return err
			}
			defer pcv3crypto.SecureZero(tailBytes[:])
			return writeD1CreationExact(ctx, destination, tailBytes[:])
		})
}

type MemoryReadMode uint8

const (
	MemoryReadNormal MemoryReadMode = iota + 1
	MemoryReadD1
	MemoryRecoverNormal
	MemoryRecoverD1
	MemoryForceNormal
	MemoryForceD1
	MemoryForceUnverifiedNormal
	MemoryForceUnverifiedD1
)

// MemoryReadRequest transfers Factors and borrows immutable Source until return.
// Role, D1Role, and SuiteHint are used only by explicit unverified Force modes.
type MemoryReadRequest struct {
	Source         []byte
	Factors        *pcv3credential.FactorRequest
	Admitter       pcv3credential.Admitter
	Mode           MemoryReadMode
	Role           CapsuleRole
	D1Role         D1BootstrapRole
	SuiteHint      Suite
	MaxOutputBytes uint64
}

// MemoryReadResult owns its byte slice and recovery evidence until Close.
// The result never grants filesystem publication, archive, or deletion authority.
type MemoryReadResult struct {
	outcome  Outcome
	stage    Stage
	code     Code
	comment  []byte
	data     []byte
	recovery *RecoveryResult
}

func (result *MemoryReadResult) Outcome() Outcome {
	if result == nil {
		return 0
	}
	return result.outcome
}

func (result *MemoryReadResult) Stage() Stage {
	if result == nil {
		return 0
	}
	return result.stage
}

func (result *MemoryReadResult) Code() Code {
	if result == nil {
		return 0
	}
	return result.code
}

func (result *MemoryReadResult) AuthenticatedComment() string {
	if result == nil {
		return ""
	}
	return string(result.comment)
}

// Bytes borrows read-only plaintext or explicit Force output until Close.
func (result *MemoryReadResult) Bytes() []byte {
	if result == nil {
		return nil
	}
	return result.data
}

// Recovery borrows immutable canonical evidence until Close.
func (result *MemoryReadResult) Recovery() *RecoveryResult {
	if result == nil {
		return nil
	}
	return result.recovery
}

func (result *MemoryReadResult) Close() {
	if result == nil {
		return
	}
	pcv3crypto.SecureZero(result.data)
	pcv3crypto.SecureZero(result.comment)
	if result.recovery != nil {
		result.recovery.Close()
	}
	*result = MemoryReadResult{}
}

func (*MemoryReadResult) String() string          { return "pcv3: memory read result" }
func (result *MemoryReadResult) GoString() string { return result.String() }
func (result *MemoryReadResult) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, result.String())
}

func memoryLengthAllowed(length, limit uint64) bool {
	return limit != 0 && length <= limit && length <= uint64(^uint(0)>>1)
}

func memoryReadFailure(outcome Outcome, stage Stage, cause error) (*MemoryReadResult, error) {
	code, _ := codeFor(outcome, stage)
	return &MemoryReadResult{outcome: outcome, stage: stage, code: code}, newError(outcome, stage, cause)
}

// RunMemoryRead preserves ordinary Normal routing separately from explicit
// recovery. Only explicit Force modes can retain unauthenticated or missing data.
func RunMemoryRead(ctx context.Context, request *MemoryReadRequest) (*MemoryReadResult, error) {
	if request == nil {
		return memoryReadFailure(OutcomeOperationFailed, StageCredentialPolicy, errInvalidReader)
	}
	owned := *request
	*request = MemoryReadRequest{}
	defer closeRecoveryFactors(owned.Factors)
	owned.Factors.RequireNonemptyKeyfiles()
	if ctx == nil || owned.Factors == nil || owned.Admitter == nil || !validMemoryReadMode(owned) {
		return memoryReadFailure(OutcomeOperationFailed, StageCredentialPolicy, errInvalidReader)
	}
	if err := ctx.Err(); err != nil {
		return memoryReadFailure(OutcomeOperationFailed, StageCancellation, err)
	}
	if !memoryLengthAllowed(0, owned.MaxOutputBytes) {
		return memoryReadFailure(OutcomeOperationFailed, StageResourceBudget, errMemoryOutputLimit)
	}
	source := bytes.NewReader(owned.Source)
	sourceSize := int64(len(owned.Source))
	if owned.Mode == MemoryReadNormal {
		provider := &nativeCredentialProvider{readerCredentialProvider: readerCredentialProvider{factors: owned.Factors, admitter: owned.Admitter}}
		return runMemoryNormalRead(ctx, source, sourceSize, provider, owned.MaxOutputBytes)
	}
	return runMemoryRecovery(ctx, source, sourceSize, owned)
}

func validMemoryReadMode(request MemoryReadRequest) bool {
	switch request.Mode {
	case MemoryReadNormal, MemoryReadD1, MemoryRecoverNormal, MemoryRecoverD1, MemoryForceNormal, MemoryForceD1:
		return request.Role == 0 && request.D1Role == 0 && request.SuiteHint == 0
	case MemoryForceUnverifiedNormal:
		return isSupportedCapsuleRole(request.Role) && request.D1Role == 0 && request.SuiteHint == 0
	case MemoryForceUnverifiedD1:
		return request.Role == 0 && validD1BootstrapRole(request.D1Role) && (request.SuiteHint == 0 || isSupportedSuite(request.SuiteHint))
	default:
		return false
	}
}

func runMemoryNormalRead(ctx context.Context, source io.ReaderAt, sourceSize int64, provider capsuleCredentialProvider, limit uint64) (*MemoryReadResult, error) {
	if closer, ok := provider.(capsuleCredentialProviderCloser); ok {
		defer closer.close()
	}
	route, structure, err := Probe(source, sourceSize)
	if err != nil {
		var failure Failure
		if errors.As(err, &failure) {
			return memoryReadFailure(failure.Outcome(), failure.Stage(), err)
		}
		return memoryReadFailure(OutcomeOperationFailed, StageInputIO, err)
	}
	if route != RouteNormalPCV {
		return memoryReadFailure(OutcomeUnsupportedRoutingPreKDF, StageRouting, nil)
	}
	var length uint64
	for index := range structure.CandidateCount() {
		candidate, _ := structure.CandidateAt(index)
		if !memoryLengthAllowed(candidate.PlaintextLength(), limit) {
			return memoryReadFailure(OutcomeOperationFailed, StageResourceBudget, errMemoryOutputLimit)
		}
		if candidate.PlaintextLength() > length {
			length = candidate.PlaintextLength()
		}
	}
	sink := &memoryNormalSink{limit: length}
	defer sink.abortUncommitted()
	semantic, completion := readNormalVolumeWithProvider(ctx, source, sourceSize, structure, provider, sink)
	if semantic == nil {
		return memoryReadFailure(OutcomeOperationFailed, StageCredentialPolicy, errInvalidReader)
	}
	defer semantic.Close()
	if ctx != nil && ctx.Err() != nil {
		return memoryReadFailure(OutcomeOperationFailed, StageCancellation, ctx.Err())
	}
	result := &MemoryReadResult{outcome: semantic.Outcome(), stage: semantic.Stage(), code: semantic.Code()}
	if completion != nil && (result.outcome == OutcomeSuccess || result.outcome == OutcomeAuthenticatedDegraded) {
		result.comment = semantic.commentBytes()
		result.data, sink.data = sink.data, nil
	}
	return result, nil
}

type memoryNormalSink struct {
	limit uint64
	next  uint64
	data  []byte
}

func (sink *memoryNormalSink) writeVerifiedRecord(ctx context.Context, index uint64, data []byte) error {
	if ctx == nil || sink == nil || index != sink.next || uint64(len(data)) > sink.limit-uint64(len(sink.data)) {
		return errMemoryOutputLimit
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if sink.data == nil {
		sink.data = make([]byte, 0, int(sink.limit)) //nolint:gosec // runMemoryNormalRead bounded every candidate against the host-int maximum.
	}
	sink.data = append(sink.data, data...)
	sink.next++
	return nil
}

func (sink *memoryNormalSink) abortUncommitted() {
	if sink == nil {
		return
	}
	pcv3crypto.SecureZero(sink.data)
	sink.data = nil
}

func runMemoryRecovery(ctx context.Context, source io.ReaderAt, sourceSize int64, request MemoryReadRequest) (*MemoryReadResult, error) {
	var data, comment []byte
	complete := false
	defer func() {
		if !complete {
			pcv3crypto.SecureZero(data)
			pcv3crypto.SecureZero(comment)
		}
	}()
	force := request.Mode >= MemoryForceNormal
	var outputStage Stage
	emit := func(result *RecoveryResult, plan RecoveryOutputPlan, emitter RecoveryEmitter) error {
		if result == nil || emitter == nil || data != nil ||
			(!force && result.Outcome() != OutcomeSuccess && result.Outcome() != OutcomeAuthenticatedDegraded) {
			outputStage = StageOutputWrite
			return errInvalidRecoveryResult
		}
		if !memoryLengthAllowed(plan.PlaintextLength(), request.MaxOutputBytes) {
			outputStage = StageResourceBudget
			return errMemoryOutputLimit
		}
		data = make([]byte, int(plan.PlaintextLength())) //nolint:gosec // memoryLengthAllowed checked the selected plan against the host-int maximum.
		var end uint64
		err := emitter(func(r RecoveryRange, segment []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if r.Start() < end || r.End() < r.Start() || r.End() > uint64(len(data)) || r.End()-r.Start() != uint64(len(segment)) ||
				(!force && (r.Start() != end || r.State() != RecoveryRangeVerified)) {
				return errInvalidRecoveryResult
			}
			copy(data[int(r.Start()):int(r.End())], segment) //nolint:gosec // Both endpoints were checked against the allocated slice length above.
			end = r.End()
			return nil
		})
		if err == nil && !force && end != uint64(len(data)) {
			err = errInvalidRecoveryResult
		}
		return err
	}
	mode := RecoveryModeNormalV3
	if force {
		mode = RecoveryModeForce
	}
	normalOutput := func(result *RecoveryResult, _ CapsuleRole, plan RecoveryOutputPlan, emitter RecoveryEmitter) error {
		if err := emit(result, plan, emitter); err != nil {
			return err
		}
		comment = []byte(plan.authenticatedComment)
		return nil
	}
	d1Output := func(result *RecoveryResult, _ D1BootstrapRole, publicComment string, plan RecoveryOutputPlan, emitter RecoveryEmitter) error {
		if err := emit(result, plan, emitter); err != nil {
			return err
		}
		comment = []byte(publicComment)
		return nil
	}
	var semantic *RecoveryResult
	var err error
	switch request.Mode {
	case MemoryRecoverNormal, MemoryForceNormal:
		semantic, err = Recover(ctx, source, sourceSize, request.Factors, request.Admitter, mode, normalOutput)
	case MemoryReadD1, MemoryRecoverD1, MemoryForceD1:
		semantic, err = RecoverD1(ctx, source, sourceSize, request.Factors, request.Admitter, mode, d1Output)
	case MemoryForceUnverifiedNormal:
		semantic, err = RecoverUnverified(ctx, source, sourceSize, request.Factors, request.Admitter, request.Role, normalOutput)
	case MemoryForceUnverifiedD1:
		semantic, err = RecoverD1UnverifiedWithSuite(ctx, source, sourceSize, request.Factors, request.Admitter, request.D1Role, request.SuiteHint, d1Output)
	}
	if ctx.Err() != nil {
		outputStage = StageCancellation
	}
	if outputStage != StageNone {
		if semantic != nil {
			semantic.Close()
		}
		return memoryReadFailure(OutcomeOperationFailed, outputStage, err)
	}
	if semantic == nil {
		return memoryReadFailure(OutcomeOperationFailed, StageCredentialPolicy, err)
	}
	result := &MemoryReadResult{outcome: semantic.Outcome(), stage: semantic.Stage(), code: semantic.Code(), recovery: semantic}
	if err != nil {
		return result, err
	}
	if result.outcome == OutcomeSuccess || result.outcome == OutcomeAuthenticatedDegraded ||
		(force && (result.outcome == OutcomeForcePartial || result.outcome == OutcomeForceUnverified)) {
		result.data, result.comment = data, comment
		complete = true
	}
	return result, nil
}
