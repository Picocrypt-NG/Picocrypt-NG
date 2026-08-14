package pcv3operation

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3governance"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/volume"
	"context"
	"errors"
	"io"
	"sync"
	"unicode/utf8"
)

var (
	errInvalidMigrationRequest   = errors.New("pcv3 operation: invalid migration request")
	errMigrationConsumerStopped  = errors.New("pcv3 operation: migration consumer stopped")
	errMigrationProducerPanicked = errors.New("pcv3 operation: migration producer panicked")
	errMigrationConsumerPanicked = errors.New("pcv3 operation: migration consumer panicked")
)

// MigrationRequest transfers an already-routed legacy descriptor, its old
// credential request, and an independent new PCV3 factor owner. It is internal
// to the module; no native frontend projects this dormant writer request.
type MigrationRequest struct {
	Prepared      *volume.PreparedDecryptInput
	Legacy        *volume.DecryptRequest
	NewFactors    *pcv3credential.FactorRequest
	Suite         pcv3.Suite
	PayloadKind   pcv3.PayloadKind
	PayloadBodyRS bool
	Comment       []byte
}

func (request *MigrationRequest) close() error {
	if request == nil {
		return nil
	}
	var cleanup []error
	if request.Prepared != nil {
		cleanup = append(cleanup, request.Prepared.Close())
		request.Prepared = nil
	}
	if request.Legacy != nil {
		pcv3crypto.SecureZero(request.Legacy.Password)
		request.Legacy.Password = nil
		for index := range request.Legacy.Keyfiles {
			request.Legacy.Keyfiles[index] = ""
		}
		request.Legacy.Keyfiles = nil
		request.Legacy.InputFile = ""
		request.Legacy.OutputFile = ""
		request.Legacy.Reporter = nil
		request.Legacy.RSCodecs = nil
		request.Legacy.Kept = nil
		request.Legacy = nil
	}
	if request.NewFactors != nil {
		cleanup = append(cleanup, request.NewFactors.Close())
		request.NewFactors = nil
	}
	pcv3crypto.SecureZero(request.Comment)
	request.Comment = nil
	request.Suite = 0
	request.PayloadKind = 0
	request.PayloadBodyRS = false
	return errors.Join(cleanup...)
}

type migrationSource interface {
	Len() int64
	DecodeMode() volume.LegacyDecodeMode
	StreamTo(io.Writer) error
	Close() error
}

type migrationConsumer func(
	context.Context,
	io.Reader,
	int64,
	volume.LegacyDecodeMode,
	pcv3.PayloadKind,
) error

type migrationStreamFailure struct {
	producer bool
	cause    error
}

func (failure *migrationStreamFailure) Error() string {
	if failure != nil && failure.producer {
		return "pcv3 operation: authenticated legacy stream failed"
	}
	return "pcv3 operation: canonical writer stream failed"
}

func (failure *migrationStreamFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

type migrationFirstWriteWriter struct {
	destination io.Writer
	ready       chan struct{}
	once        sync.Once
}

func (writer *migrationFirstWriteWriter) Write(plaintext []byte) (int, error) {
	if len(plaintext) == 0 {
		return 0, nil
	}
	writer.once.Do(func() { close(writer.ready) })
	return writer.destination.Write(plaintext)
}

// streamVerifiedMigration is the sole plaintext connection between a frozen
// authenticated legacy owner and the canonical writer consumer. The consumer
// starts only when the producer reaches its first non-empty plaintext write,
// after legacy KDF state has been released, or after a successful zero-length
// producer completion. Every exit closes both pipe ends and joins the producer,
// so a final legacy MAC failure can never race publication.
func streamVerifiedMigration(
	ctx context.Context,
	source migrationSource,
	payloadKind pcv3.PayloadKind,
	consume migrationConsumer,
) error {
	if ctx == nil || source == nil || consume == nil ||
		(payloadKind != pcv3.PayloadKindRaw && payloadKind != pcv3.PayloadKindArchive) {
		return errInvalidMigrationRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	length := source.Len()
	decodeMode := source.DecodeMode()
	if length < 0 || decodeMode < volume.LegacyDecodePlain ||
		decodeMode > volume.LegacyDecodeRSFull {
		return errInvalidMigrationRequest
	}

	reader, writer := io.Pipe()
	producerReady := make(chan struct{})
	producerDone := make(chan error, 1)
	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		defer close(cancellationDone)
		err := ctx.Err()
		_ = reader.CloseWithError(err)
		_ = writer.CloseWithError(err)
	})
	go func() {
		var producerErr error
		defer func() {
			if recover() != nil {
				producerErr = errMigrationProducerPanicked
			}
			_ = writer.CloseWithError(producerErr)
			producerDone <- producerErr
		}()
		producerErr = source.StreamTo(&migrationFirstWriteWriter{
			destination: writer,
			ready:       producerReady,
		})
	}()

	var producerErr error
	producerJoined := false
	select {
	case <-producerReady:
	case producerErr = <-producerDone:
		producerJoined = true
	case <-ctx.Done():
		_ = reader.CloseWithError(ctx.Err())
		_ = writer.CloseWithError(ctx.Err())
		producerErr = <-producerDone
		producerJoined = true
	}

	var consumerErr error
	if (!producerJoined || producerErr == nil) && ctx.Err() == nil {
		func() {
			defer func() {
				if recover() != nil {
					consumerErr = errMigrationConsumerPanicked
				}
			}()
			consumerErr = consume(ctx, reader, length, decodeMode, payloadKind)
		}()
	}
	if stopCancellation() {
		close(cancellationDone)
	}
	if consumerErr != nil {
		_ = reader.CloseWithError(errMigrationConsumerStopped)
		_ = writer.CloseWithError(errMigrationConsumerStopped)
	} else {
		_ = reader.Close()
	}
	if !producerJoined {
		producerErr = <-producerDone
	}
	<-cancellationDone
	_ = writer.Close()

	if ctx.Err() != nil && (errors.Is(producerErr, ctx.Err()) ||
		errors.Is(producerErr, io.ErrClosedPipe)) {
		return ctx.Err()
	}
	if consumerErr != nil && (errors.Is(producerErr, errMigrationConsumerStopped) ||
		errors.Is(producerErr, io.ErrClosedPipe)) {
		return &migrationStreamFailure{cause: consumerErr}
	}
	if producerErr != nil {
		if ctx.Err() != nil && errors.Is(producerErr, ctx.Err()) {
			return ctx.Err()
		}
		return &migrationStreamFailure{producer: true, cause: producerErr}
	}
	if consumerErr != nil {
		if ctx.Err() != nil && errors.Is(consumerErr, ctx.Err()) {
			return ctx.Err()
		}
		return &migrationStreamFailure{cause: consumerErr}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func runMigration(
	ctx context.Context,
	owner *operationOwner,
	seams operationSeams,
	authorization *pcv3governance.EmissionAuthorization,
) (result *Result) {
	// This is deliberately the first operation: no request validation, status
	// callback, source authentication, KDF, stage, pipe, or goroutine precedes it.
	if err := pcv3governance.RequireEmissionAuthorization(authorization); err != nil {
		return closedFailure(
			pcv3.OutcomeUnsupportedRoutingPreKDF,
			pcv3.StageRouting,
			pcv3.CodeUnsupported,
			DiagnosticGovernanceRefusal,
		)
	}
	if ctx == nil || owner == nil || seams.admitter == nil ||
		!validMigrationRequest(owner.migration, owner.target) ||
		!owner.validProtected() || owner.source != nil || owner.factors != nil ||
		owner.consent != nil {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCredentialPolicy,
			pcv3.CodeOperationFailed,
			DiagnosticInvalidRequest,
		)
	}
	if err := ctx.Err(); err != nil {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCancellation,
			pcv3.CodeOperationFailed,
			DiagnosticCancellation,
		)
	}
	if !owner.report(StatusCheckingRequest) || !owner.report(StatusCheckingFactors) ||
		!owner.report(StatusVerifyingLegacy) {
		return owner.reportFailure()
	}

	migration := owner.migration
	var source migrationSource
	var err error
	if migration.Legacy.Deniability {
		source, err = volume.PrepareDeniableSource(ctx, migration.Legacy, migration.Prepared)
	} else {
		source, err = volume.PrepareVerifiedLegacyPayload(ctx, migration.Legacy, migration.Prepared)
	}
	if err != nil || source == nil {
		return migrationFailureResult(ctx, pcv3.StageRecordAuth, err)
	}
	defer func() {
		if source.Close() != nil {
			result.appendWarning(WarningCleanupIncomplete)
		}
	}()

	protected := append([]string(nil), owner.protected...)
	protected = append(protected, migration.Legacy.InputFile)
	protected = append(protected, migration.Legacy.Keyfiles...)
	stage, err := pcv3publication.Create(
		owner.target,
		protected,
		pcv3publication.PolicyNoReplace,
	)
	if err != nil {
		return migrationFailureResult(ctx, pcv3.StageOutputPublication, err)
	}
	defer func() {
		if stage.Cleanup() != nil {
			result.appendWarning(WarningCleanupIncomplete)
		}
	}()
	if !owner.report(StatusMigrating) {
		return owner.reportFailure()
	}

	newFactors := migration.NewFactors
	migration.NewFactors = nil
	defer func() {
		if newFactors != nil && newFactors.Close() != nil {
			result.appendWarning(WarningCleanupIncomplete)
		}
	}()
	comment := append([]byte(nil), migration.Comment...)
	defer pcv3crypto.SecureZero(comment)
	err = streamVerifiedMigration(
		ctx,
		source,
		migration.PayloadKind,
		func(
			streamCtx context.Context,
			plaintext io.Reader,
			length int64,
			_ volume.LegacyDecodeMode,
			payloadKind pcv3.PayloadKind,
		) error {
			if length < 0 {
				return errInvalidMigrationRequest
			}
			request := &pcv3.NativeNormalWriteRequest{
				Suite:           migration.Suite,
				PayloadKind:     payloadKind,
				PayloadBodyRS:   migration.PayloadBodyRS,
				PlaintextLength: uint64(length), //nolint:gosec // length is checked non-negative above.
				Comment:         comment,
				Factors:         newFactors,
				Admitter:        reportingAdmitter{owner: owner, next: seams.admitter},
				Source:          plaintext,
				Destination:     stage.File(),
			}
			err := pcv3.RunNativeNormalWrite(streamCtx, authorization, request)
			// Retain the outer owner until normal return so a panic before the
			// adapter transfer cannot leak it. The cleared request records a
			// completed transfer.
			newFactors = request.Factors
			return err
		},
	)
	if err != nil {
		return migrationStreamFailureResult(ctx, err)
	}
	if !owner.report(StatusPublishing) || !owner.report(StatusConfirmingDurability) {
		return owner.reportFailure()
	}
	publication := stage.Publish(ctx)
	if publication == nil {
		return migrationFailureResult(ctx, pcv3.StageOutputPublication, errInvalidMigrationRequest)
	}
	return newResult(resultData{
		outcome:              pcv3.OutcomeSuccess,
		stage:                pcv3.StageNone,
		code:                 pcv3.CodeSuccess,
		publicationAttempted: true,
		publicationState:     publication.State(),
		publicationStage:     publication.Stage(),
		publicationCode:      publication.Code(),
	})
}

func validMigrationRequest(request *MigrationRequest, target string) bool {
	if request == nil || request.Prepared == nil || request.Legacy == nil ||
		request.NewFactors == nil || target == "" || request.Legacy.InputFile == "" ||
		request.Legacy.RSCodecs == nil || request.Legacy.ForceDecrypt ||
		request.Legacy.AutoUnzip || !utf8.Valid(request.Comment) {
		return false
	}
	if request.Suite != pcv3.SuiteStandard && request.Suite != pcv3.SuiteParanoid {
		return false
	}
	return request.PayloadKind == pcv3.PayloadKindRaw ||
		request.PayloadKind == pcv3.PayloadKindArchive
}

func migrationStreamFailureResult(ctx context.Context, err error) *Result {
	if ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		return migrationFailureResult(ctx, pcv3.StageCancellation, err)
	}
	var streamFailure *migrationStreamFailure
	if errors.As(err, &streamFailure) && streamFailure.producer {
		return migrationFailureResult(ctx, pcv3.StageRecordAuth, err)
	}
	var staged interface{ Stage() pcv3.Stage }
	if errors.As(err, &staged) && staged.Stage() != pcv3.StageNone {
		return migrationFailureResult(ctx, staged.Stage(), err)
	}
	return migrationFailureResult(ctx, pcv3.StageOutputWrite, err)
}

func migrationFailureResult(ctx context.Context, stage pcv3.Stage, _ error) *Result {
	if ctx != nil && ctx.Err() != nil {
		stage = pcv3.StageCancellation
	}
	diagnostic := DiagnosticCoreFailure
	if stage == pcv3.StageCancellation {
		diagnostic = DiagnosticCancellation
	}
	return closedFailure(
		pcv3.OutcomeOperationFailed,
		stage,
		pcv3.CodeOperationFailed,
		diagnostic,
	)
}
