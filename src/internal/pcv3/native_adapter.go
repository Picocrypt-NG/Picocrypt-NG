package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3governance"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"io"
	"os"
	"sync"
)

// NativeNormalWriteRequest is the narrow internal-module bridge from the
// operation-owned migration stream to the sole canonical normal serializer.
// Source and Destination are borrowed for the call; Factors transfers only
// after a genuine emission authorization has passed.
type NativeNormalWriteRequest struct {
	Suite           Suite
	PayloadKind     PayloadKind
	PayloadBodyRS   bool
	PlaintextLength uint64
	Comment         []byte
	Factors         *pcv3credential.FactorRequest
	Admitter        pcv3credential.Admitter
	Source          io.Reader
	Destination     io.Writer
}

// RunNativeNormalWrite repeats the opaque governance check as its first
// operation. The current review-candidate baseline cannot reach the
// credential pipeline, entropy, source, or destination through this adapter.
func RunNativeNormalWrite(
	ctx context.Context,
	authorization *pcv3governance.EmissionAuthorization,
	request *NativeNormalWriteRequest,
) error {
	if err := pcv3governance.RequireEmissionAuthorization(authorization); err != nil {
		return newNormalWriteFailure(StageOutputPublication, err)
	}
	if request == nil {
		return newNormalWriteFailure(StageCredentialPolicy, errInvalidNormalWriteRequest)
	}

	suite := request.Suite
	payloadKind := request.PayloadKind
	payloadBodyRS := request.PayloadBodyRS
	plaintextLength := request.PlaintextLength
	comment := append([]byte(nil), request.Comment...)
	factors := request.Factors
	admitter := request.Admitter
	source := request.Source
	destination := request.Destination
	request.Suite = 0
	request.PayloadKind = 0
	request.PayloadBodyRS = false
	request.PlaintextLength = 0
	clear(request.Comment)
	request.Comment = nil
	request.Factors = nil
	request.Admitter = nil
	request.Source = nil
	request.Destination = nil
	defer clear(comment)
	defer func() {
		if factors != nil {
			_ = factors.Close()
		}
	}()

	credentialSuite, ok := normalCredentialSuite(suite)
	keyRequests, requestsOK := normalWriteKeyRequests(suite)
	writeRequest := normalWriteRequest{
		suite:           suite,
		payloadKind:     payloadKind,
		payloadBodyRS:   payloadBodyRS,
		plaintextLength: plaintextLength,
		comment:         comment,
	}
	if ctx == nil || ctx.Err() != nil || !ok || !requestsOK ||
		!validNormalWriteRequest(writeRequest) || factors == nil || admitter == nil ||
		source == nil || destination == nil {
		return newNormalWriteFailure(StageCredentialPolicy, errInvalidNormalWriteRequest)
	}

	credentialRequest := &pcv3credential.CredentialRequest{
		Suite:       credentialSuite,
		Factors:     factors,
		KeyRequests: keyRequests,
	}
	factors = nil
	owner, err := pcv3credential.NewCredential(ctx, credentialRequest, admitter)
	if err != nil {
		if ctx.Err() != nil {
			return newNormalWriteFailure(StageCancellation, ctx.Err())
		}
		return newNormalWriteFailure(StageCredentialPolicy, err)
	}
	defer owner.Close()
	_, err = writeNormalVolume(ctx, authorization, writeRequest, source, destination, owner)
	return err
}

func normalCredentialSuite(suite Suite) (pcv3credential.Suite, bool) {
	switch suite {
	case SuiteStandard:
		return pcv3credential.SuiteStandard1, true
	case SuiteParanoid:
		return pcv3credential.SuiteParanoid1, true
	default:
		return 0, false
	}
}

// NativeReadRequest is the narrow internal-module input to the ordinary
// authenticated reader. Source is borrowed. Factors transfer to RunNativeRead.
// No frontend imports this package-level bridge directly.
type NativeReadRequest struct {
	Source              io.ReaderAt
	SourceSize          int64
	Factors             *pcv3credential.FactorRequest
	Admitter            pcv3credential.Admitter
	Target              string
	Protected           []string
	JournalPrivateStage bool
}

// NativePayloadDisposition tells the operation whether the completed stage is
// ordinary publishable plaintext or an exact-success archive awaiting the
// separate sealed follow-up introduced in Task 4.
type NativePayloadDisposition uint8

const (
	NativePayloadPublish NativePayloadDisposition = iota + 1
	NativePayloadArchive
)

// NativeReadCallback receives only a callback-scoped, opaque output action.
// Retaining the value after callback return grants no authority.
type NativeReadCallback func(*NativeReadOutput) error

// NativeReadOutput exposes neither a stage, file, sink, provider, completion,
// nor key. Archive returns only a sealed one-shot handoff.
type NativeReadOutput struct {
	state *nativeReadOutputState
}

type nativeReadOutputState struct {
	mu          sync.Mutex
	active      bool
	consumed    bool
	disposition NativePayloadDisposition
	sink        *nativeReadSink
	completion  *normalCompletion
}

func (output *NativeReadOutput) Disposition() NativePayloadDisposition {
	if output == nil || output.state == nil {
		return 0
	}
	output.state.mu.Lock()
	defer output.state.mu.Unlock()
	if !output.state.active {
		return 0
	}
	return output.state.disposition
}

// Publish consumes the callback-scoped ordinary-output action. Exact-success
// archive output is never raw-published through this method.
func (output *NativeReadOutput) Publish(ctx context.Context) pcv3publication.Result {
	if output == nil || output.state == nil {
		return nil
	}
	output.state.mu.Lock()
	defer output.state.mu.Unlock()
	if !output.state.active || output.state.consumed ||
		output.state.disposition != NativePayloadPublish || output.state.sink == nil {
		return nil
	}
	output.state.consumed = true
	return output.state.sink.publish(ctx)
}

// PublishRetained consumes the callback-scoped ordinary-output action and
// returns an opaque exact-file owner only after durable publication. Archive
// output and every non-durable publication grant no retained authority.
func (output *NativeReadOutput) PublishRetained(
	ctx context.Context,
) *pcv3publication.RetainedFile {
	if output == nil || output.state == nil {
		return nil
	}
	output.state.mu.Lock()
	defer output.state.mu.Unlock()
	if !output.state.active || output.state.consumed ||
		output.state.disposition != NativePayloadPublish || output.state.sink == nil {
		return nil
	}
	output.state.consumed = true
	return output.state.sink.publishRetained(ctx)
}

// Archive consumes the callback-scoped archive action and returns an opaque
// handoff that owns the original private stage. It never exposes the stage,
// completion seal, or a path.
func (output *NativeReadOutput) Archive() *NativeArchiveHandoff {
	if output == nil || output.state == nil {
		return nil
	}
	output.state.mu.Lock()
	defer output.state.mu.Unlock()
	if !output.state.active || output.state.consumed ||
		output.state.disposition != NativePayloadArchive {
		return nil
	}
	handoff := newNativeArchiveHandoff(output.state.completion, output.state.sink)
	if handoff == nil {
		return nil
	}
	output.state.consumed = true
	return handoff
}

// NativeArchiveResult is the closed extractor projection returned by the
// opaque archive handoff. It contains no path or raw error.
type NativeArchiveResult struct {
	state             fileops.UnpackState
	cleanupIncomplete bool
}

func (result *NativeArchiveResult) State() fileops.UnpackState {
	if result == nil {
		return 0
	}
	return result.state
}

func (result *NativeArchiveResult) CleanupIncomplete() bool {
	return result != nil && result.cleanupIncomplete
}

// NativeArchiveHandoff is minted only by exact fully authenticated normal
// archive success. Copies share one consumption state.
type NativeArchiveHandoff struct {
	state *nativeArchiveHandoffState
}

type nativeArchiveHandoffState struct {
	mu         sync.Mutex
	active     bool
	completion *normalCompletion
	stage      *pcv3publication.Stage
}

func newNativeArchiveHandoff(
	completion *normalCompletion,
	sink *nativeReadSink,
) *NativeArchiveHandoff {
	kind, authenticated := completion.authenticatedPayloadKind()
	if !authenticated || kind != PayloadKindArchive || sink == nil {
		return nil
	}
	stage := sink.takeArchiveStage()
	if stage == nil {
		return nil
	}
	return &NativeArchiveHandoff{state: &nativeArchiveHandoffState{
		active: true, completion: completion, stage: stage,
	}}
}

func (handoff *NativeArchiveHandoff) Live() bool {
	if handoff == nil || handoff.state == nil {
		return false
	}
	handoff.state.mu.Lock()
	defer handoff.state.mu.Unlock()
	return handoff.state.active && handoff.state.completion != nil &&
		handoff.state.stage != nil
}

// Extract consumes the handoff before effects and takes ownership of root.
// The same still-open stage descriptor is passed to the authenticated unpack
// gate and then cleaned on every return.
func (handoff *NativeArchiveHandoff) Extract(
	ctx context.Context,
	root *os.Root,
) *NativeArchiveResult {
	completion, stage, ok := handoff.consume()
	if !ok {
		if root != nil {
			_ = root.Close()
		}
		return nil
	}
	result := &NativeArchiveResult{state: fileops.UnpackStateNotPublished}
	defer func() {
		if stage.Cleanup() != nil {
			result.cleanupIncomplete = true
		}
		if root != nil && root.Close() != nil {
			result.cleanupIncomplete = true
		}
	}()
	if root == nil {
		return result
	}
	if ctx == nil {
		ctx = context.Background()
	}
	expectedRoot, err := root.Stat(".")
	if err != nil || expectedRoot == nil || !expectedRoot.IsDir() {
		return result
	}
	unpack := unpackAuthenticatedArchiveWithResult(
		ctx,
		completion,
		stage.File(),
		root,
		expectedRoot,
	)
	if unpack == nil {
		return result
	}
	result.state = unpack.State()
	if errors.Is(unpack, fileops.ErrUnpackCleanupIncomplete) {
		result.cleanupIncomplete = true
	}
	return result
}

// Close consumes the handoff without extraction and reports only whether
// cleanup of the private stage could be proven.
func (handoff *NativeArchiveHandoff) Close() bool {
	_, stage, ok := handoff.consume()
	return ok && stage.Cleanup() != nil
}

func (handoff *NativeArchiveHandoff) consume() (
	*normalCompletion,
	*pcv3publication.Stage,
	bool,
) {
	if handoff == nil || handoff.state == nil {
		return nil, nil, false
	}
	handoff.state.mu.Lock()
	defer handoff.state.mu.Unlock()
	if !handoff.state.active || handoff.state.completion == nil ||
		handoff.state.stage == nil {
		return nil, nil, false
	}
	handoff.state.active = false
	completion := handoff.state.completion
	stage := handoff.state.stage
	handoff.state.completion = nil
	handoff.state.stage = nil
	return completion, stage, true
}

// NativeReadResult is the closed operation-facing projection of the ordinary
// reader. It retains no raw error, path, source, credential, or callback.
type NativeReadResult struct {
	outcome              Outcome
	stage                Stage
	code                 Code
	publicationAttempted bool
	publicationState     pcv3publication.State
	publicationStage     Stage
	publicationCode      pcv3publication.Code
	cleanupIncomplete    bool
	callbackFailed       bool
}

func (result *NativeReadResult) Outcome() Outcome {
	if result == nil {
		return 0
	}
	return result.outcome
}

func (result *NativeReadResult) Stage() Stage {
	if result == nil {
		return 0
	}
	return result.stage
}

func (result *NativeReadResult) Code() Code {
	if result == nil {
		return 0
	}
	return result.code
}

func (result *NativeReadResult) PublicationAttempted() bool {
	return result != nil && result.publicationAttempted
}

func (result *NativeReadResult) PublicationState() pcv3publication.State {
	if result == nil {
		return 0
	}
	return result.publicationState
}

func (result *NativeReadResult) PublicationStage() Stage {
	if result == nil {
		return StageNone
	}
	return result.publicationStage
}

func (result *NativeReadResult) PublicationCode() pcv3publication.Code {
	if result == nil {
		return 0
	}
	return result.publicationCode
}

func (result *NativeReadResult) CleanupIncomplete() bool {
	return result != nil && result.cleanupIncomplete
}

func (result *NativeReadResult) CallbackFailed() bool {
	return result != nil && result.callbackFailed
}

// RunNativeRead enters the sole ordinary normal-volume reader with production
// credential composition and a private lazy publication sink. The stage is not
// created until factor validation and record authentication reach real output.
func RunNativeRead(
	ctx context.Context,
	request *NativeReadRequest,
	callback NativeReadCallback,
) *NativeReadResult {
	if request == nil {
		return nativeReadFailure(OutcomeOperationFailed, StageCredentialPolicy, CodeOperationFailed)
	}
	source := request.Source
	sourceSize := request.SourceSize
	factors := request.Factors
	admitter := request.Admitter
	target := request.Target
	protected := append([]string(nil), request.Protected...)
	journalPrivateStage := request.JournalPrivateStage
	request.Source = nil
	request.SourceSize = 0
	request.Factors = nil
	request.Admitter = nil
	request.Target = ""
	request.JournalPrivateStage = false
	for index := range request.Protected {
		request.Protected[index] = ""
	}
	request.Protected = nil
	defer func() {
		closeNativeReadFactors(factors)
	}()

	if ctx == nil || source == nil || sourceSize < 0 || factors == nil ||
		target == "" || callback == nil {
		closeNativeReadFactors(factors)
		factors = nil
		return nativeReadFailure(OutcomeOperationFailed, StageCredentialPolicy, CodeOperationFailed)
	}
	if ctx.Err() != nil {
		closeNativeReadFactors(factors)
		factors = nil
		return nativeReadFailure(OutcomeOperationFailed, StageCancellation, CodeOperationFailed)
	}

	route, structure, err := Probe(source, sourceSize)
	if err != nil {
		closeNativeReadFactors(factors)
		factors = nil
		return nativeReadFailureFromError(err)
	}
	if route != RouteNormalPCV {
		closeNativeReadFactors(factors)
		factors = nil
		return nativeReadFailure(OutcomeUnsupportedRoutingPreKDF, StageRouting, CodeUnsupported)
	}
	if admitter == nil {
		closeNativeReadFactors(factors)
		factors = nil
		return nativeReadFailure(OutcomeOperationFailed, StageCredentialPolicy, CodeOperationFailed)
	}

	sink := &nativeReadSink{
		target:              target,
		protected:           protected,
		journalPrivateStage: journalPrivateStage,
	}
	provider := &nativeCredentialProvider{readerCredentialProvider: readerCredentialProvider{
		factors:  factors,
		admitter: admitter,
	}}
	factors = nil
	return runNativeReadSession(
		ctx,
		source,
		sourceSize,
		structure,
		provider,
		sink,
		callback,
	)
}

// runNativeReadSession is the one adapter session shared by the production
// factor owner and frozen same-package codec fixtures. It contains the real
// output-disposition, callback lifetime, and stage-transfer logic.
func runNativeReadSession(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	structure Structure,
	provider capsuleCredentialProvider,
	sink *nativeReadSink,
	callback NativeReadCallback,
) *NativeReadResult {
	if sink == nil || callback == nil {
		if closer, ok := provider.(capsuleCredentialProviderCloser); ok {
			closer.close()
		}
		return nativeReadFailure(OutcomeOperationFailed, StageCredentialPolicy, CodeOperationFailed)
	}
	defer sink.abortUncommitted()
	semantic, completion := readNormalVolumeWithProvider(
		ctx,
		source,
		sourceSize,
		structure,
		provider,
		sink,
	)
	result := nativeReadResultFromSemantic(semantic)
	if semantic != nil {
		semantic.Close()
	}
	if completion == nil ||
		(result.outcome != OutcomeSuccess && result.outcome != OutcomeAuthenticatedDegraded) {
		sink.snapshot(result)
		return result
	}
	if err := sink.ensureStage(); err != nil {
		result.outcome = OutcomeOperationFailed
		result.stage = StageOutputWrite
		result.code = CodeOperationFailed
		sink.snapshot(result)
		return result
	}

	disposition := NativePayloadPublish
	if kind, authenticated := completion.authenticatedPayloadKind(); authenticated && kind == PayloadKindArchive && result.outcome == OutcomeSuccess {
		disposition = NativePayloadArchive
	}
	outputState := &nativeReadOutputState{
		active:      true,
		disposition: disposition,
		sink:        sink,
		completion:  completion,
	}
	output := &NativeReadOutput{state: outputState}
	var callbackErr error
	func() {
		defer func() {
			outputState.mu.Lock()
			defer outputState.mu.Unlock()
			outputState.active = false
			outputState.sink = nil
			outputState.completion = nil
		}()
		callbackErr = callback(output)
	}()
	if callbackErr != nil {
		result.callbackFailed = true
	}
	sink.abortUncommitted()
	sink.snapshot(result)
	return result
}

func closeNativeReadFactors(factors *pcv3credential.FactorRequest) {
	if factors != nil {
		_ = factors.Close()
	}
}

func nativeReadFailure(outcome Outcome, stage Stage, code Code) *NativeReadResult {
	return &NativeReadResult{outcome: outcome, stage: stage, code: code}
}

func nativeReadFailureFromError(err error) *NativeReadResult {
	var failure Failure
	if errors.As(err, &failure) {
		return nativeReadFailure(failure.Outcome(), failure.Stage(), failure.Code())
	}
	return nativeReadFailure(OutcomeOperationFailed, StageInputIO, CodeOperationFailed)
}

func nativeReadResultFromSemantic(semantic *normalReadResult) *NativeReadResult {
	if semantic == nil {
		return nativeReadFailure(OutcomeOperationFailed, StageCredentialPolicy, CodeOperationFailed)
	}
	return &NativeReadResult{
		outcome: semantic.Outcome(),
		stage:   semantic.Stage(),
		code:    semantic.Code(),
	}
}

type nativeReadSink struct {
	target              string
	protected           []string
	journalPrivateStage bool
	stage               *pcv3publication.Stage
	stageWriter         func(io.Writer) io.Writer
	nextRecord          uint64
	closed              bool

	publicationAttempted bool
	publishCalled        bool
	publicationState     pcv3publication.State
	publicationStage     Stage
	publicationCode      pcv3publication.Code
	cleanupIncomplete    bool
}

func (sink *nativeReadSink) ensureStage() error {
	if sink == nil || sink.closed {
		return errors.New("pcv3: native output unavailable")
	}
	if sink.stage != nil {
		return nil
	}
	stage, err := pcv3publication.Create(
		sink.target,
		append([]string(nil), sink.protected...),
		pcv3publication.PolicyNoReplace,
	)
	if err == nil && sink.journalPrivateStage {
		if journalErr := stage.PersistCleanupJournal(); journalErr != nil {
			err = errors.Join(
				journalErr,
				pcv3publication.ErrCleanupIncomplete,
				stage.Cleanup(),
			)
			stage = nil
		}
	}
	if err != nil {
		if sink.publicationAttempted {
			sink.retainPublicationError(err)
		} else if errors.Is(err, pcv3publication.ErrCleanupIncomplete) {
			sink.cleanupIncomplete = true
		}
		return err
	}
	sink.stage = stage
	return nil
}

func (sink *nativeReadSink) writeVerifiedRecord(
	ctx context.Context,
	index uint64,
	plaintext []byte,
) error {
	if sink == nil || sink.closed || ctx == nil || index != sink.nextRecord {
		return errors.New("pcv3: native output write refused")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sink.ensureStage(); err != nil {
		return err
	}
	file := sink.stage.File()
	if file == nil {
		return errors.New("pcv3: native output stage unavailable")
	}
	destination := io.Writer(file)
	if sink.stageWriter != nil {
		destination = sink.stageWriter(file)
		if destination == nil {
			return errors.New("pcv3: native output stage writer unavailable")
		}
	}
	for len(plaintext) != 0 {
		written, err := destination.Write(plaintext)
		if written < 0 || written > len(plaintext) {
			return errors.New("pcv3: native output writer contract violated")
		}
		plaintext = plaintext[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	sink.nextRecord++
	return nil
}

func (sink *nativeReadSink) publish(ctx context.Context) pcv3publication.Result {
	if !sink.beginPublication() {
		return nil
	}
	publication := sink.stage.Publish(ctx)
	sink.retainPublication(publication)
	return publication
}

func (sink *nativeReadSink) publishRetained(
	ctx context.Context,
) *pcv3publication.RetainedFile {
	if !sink.beginPublication() {
		return nil
	}
	publication, retained := sink.stage.PublishRetained(ctx)
	sink.retainPublication(publication)
	if retained != nil {
		sink.stage = nil
	}
	return retained
}

func (sink *nativeReadSink) beginPublication() bool {
	if sink == nil || sink.closed || sink.publishCalled {
		return false
	}
	sink.publishCalled = true
	sink.publicationAttempted = true
	if err := sink.ensureStage(); err != nil {
		return false
	}
	return true
}

func (sink *nativeReadSink) takeArchiveStage() *pcv3publication.Stage {
	if sink == nil || sink.closed || sink.publishCalled || sink.stage == nil {
		return nil
	}
	stage := sink.stage
	sink.stage = nil
	return stage
}

// nativeCredentialProvider pins the caller's already-declared factor mode,
// order mode, and count to the structurally admitted capsule tuple before the
// credential package reaches admission. The credential package remains the
// sole owner of shape validation, keyfile reads/order/digests, duplicate
// detection, canonicalization, policy validation, and factor cleanup.
type nativeCredentialProvider struct {
	readerCredentialProvider
}

func (provider *nativeCredentialProvider) withCredential(
	ctx context.Context,
	tuple credentialTuple,
	callback func(capsuleCredentialAccess) error,
) error {
	mode, keyfileMode, ok := credentialRecoveryModes(tuple.credentialMode, tuple.keyfileMode)
	if provider == nil || provider.factors == nil || !ok ||
		provider.factors.Mode != mode || provider.factors.KeyfileMode != keyfileMode ||
		len(provider.factors.Keyfiles) != int(tuple.keyfileCount) {
		return &capsuleAuthError{stage: StageCredentialPolicy}
	}
	return provider.readerCredentialProvider.withCredential(ctx, tuple, callback)
}

func (sink *nativeReadSink) abortUncommitted() {
	if sink == nil || sink.closed {
		return
	}
	sink.closed = true
	if sink.stage != nil {
		if err := sink.stage.Cleanup(); err != nil {
			sink.cleanupIncomplete = true
		}
		sink.stage = nil
	}
	for index := range sink.protected {
		sink.protected[index] = ""
	}
	sink.protected = nil
	sink.target = ""
	sink.journalPrivateStage = false
	sink.stageWriter = nil
}

func (sink *nativeReadSink) retainPublication(publication pcv3publication.Result) {
	if sink == nil || publication == nil {
		return
	}
	sink.publicationState = publication.State()
	sink.publicationStage = publication.Stage()
	sink.publicationCode = publication.Code()
}

func (sink *nativeReadSink) retainPublicationError(err error) {
	var publication pcv3publication.Result
	if errors.As(err, &publication) {
		sink.retainPublication(publication)
	}
	if errors.Is(err, pcv3publication.ErrCleanupIncomplete) {
		sink.cleanupIncomplete = true
	}
}

func (sink *nativeReadSink) snapshot(result *NativeReadResult) {
	if sink == nil || result == nil {
		return
	}
	result.publicationAttempted = sink.publicationAttempted
	result.publicationState = sink.publicationState
	result.publicationStage = sink.publicationStage
	result.publicationCode = sink.publicationCode
	result.cleanupIncomplete = sink.cleanupIncomplete
}
