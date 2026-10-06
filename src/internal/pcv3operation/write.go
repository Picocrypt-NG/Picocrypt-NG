package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3resource"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

// WriteMode selects a distinct codec; its zero value never infers a format.
type WriteMode uint8

const (
	WriteModeNormal WriteMode = iota + 1
	WriteModeD1
)

// WriteSplitOptions describes the requested chunk set without accepting a
// caller-supplied source identity, digest, or publication policy.
type WriteSplitOptions struct {
	ChunkSize int
	Unit      fileops.SplitUnit
}

// WriteRequest transfers factors, comment and reporter to RunWrite. Source and
// SourceFile are borrowed: Source may decrypt a temporary ZIP while reading.
// SourceFile and SourcePath pin the D1 input identity; PlaintextLength describes
// the logical plaintext. No RNG, key, or resource-admission authority is accepted.
type WriteRequest struct {
	Mode            WriteMode
	Suite           pcv3.Suite
	PayloadKind     pcv3.PayloadKind
	PayloadBodyRS   bool
	PlaintextLength uint64
	Comment         []byte
	Factors         *pcv3credential.FactorRequest
	Source          io.Reader
	SourceFile      *os.File
	SourcePath      string
	Target          string
	Protected       []string
	Reporter        Reporter
	Split           *WriteSplitOptions
}

func (WriteRequest) String() string           { return "pcv3operation.WriteRequest([REDACTED])" }
func (request WriteRequest) GoString() string { return request.String() }
func (request WriteRequest) Format(state fmt.State, verb rune) {
	value := request.String()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = io.WriteString(state, value)
}

func RunWrite(ctx context.Context, request *WriteRequest) *Result {
	return RunWriteWithOptions(ctx, request, ExecutionOptions{})
}

func RunWriteWithOptions(ctx context.Context, request *WriteRequest, options ExecutionOptions) *Result {
	return runWriteWithSeams(ctx, request, options, operationSeams{admitter: pcv3resource.NewPlatformAdmitter()})
}

func runWriteWithSeams(ctx context.Context, request *WriteRequest, options ExecutionOptions, seams operationSeams) (result *Result) {
	var owned WriteRequest
	if request != nil {
		owned = *request
		owned.Protected = append([]string(nil), request.Protected...)
		if request.Split != nil {
			split := *request.Split
			owned.Split = &split
		}
		*request = WriteRequest{}
	}
	owner := &operationOwner{reporter: owned.Reporter}
	var stage *pcv3publication.Stage
	var retained *pcv3publication.RetainedFile
	defer func() {
		if recover() != nil {
			result = writeFailure(pcv3.StageCredentialPolicy, DiagnosticCallbackPanic)
		}
		if result == nil {
			result = writeFailure(pcv3.StageCredentialPolicy, DiagnosticCoreFailure)
		}
		if result.diagnostic == DiagnosticCancellation && ctx != nil {
			result.cancellationDeadline = errors.Is(ctx.Err(), context.DeadlineExceeded)
		}
		clear(owned.Comment)
		if safeCloseFactors(owned.Factors) {
			result.appendWarning(WarningCleanupIncomplete)
		}
		if stage != nil && stage.Cleanup() != nil {
			result.appendWarning(WarningCleanupIncomplete)
		}
		if retained != nil && retained.Close() != nil {
			result.appendWarning(WarningCleanupIncomplete)
		}
		if owner.reporterFailed || owner.reporterPanicked {
			result.appendWarning(WarningCallbackFailure)
			result.diagnostic = DiagnosticCallbackFailure
			if owner.reporterPanicked {
				result.diagnostic = DiagnosticCallbackPanic
			}
		}
		owner.reporter = nil
		if result.CompletionClass() != CompletionClean {
			result.writeLifecycleComplete = false
		}
	}()
	if ctx == nil || request == nil || options.ArchiveAction != ArchiveDefault || options.ArchiveReview != nil {
		return writeFailure(pcv3.StageCredentialPolicy, DiagnosticInvalidRequest)
	}
	if ctx.Err() != nil {
		return writeFailure(pcv3.StageCancellation, DiagnosticCancellation)
	}
	if !owner.report(StatusCheckingRequest) {
		return owner.reportFailure()
	}
	if (owned.Mode != WriteModeNormal && owned.Mode != WriteModeD1) || owned.Source == nil || owned.Factors == nil || owned.Target == "" || seams.admitter == nil ||
		(owned.Mode == WriteModeD1 && (owned.Suite != pcv3.SuiteParanoid || owned.SourceFile == nil || owned.SourcePath == "")) ||
		(options.RetainDurableOutput && owned.Split != nil) {
		return writeFailure(pcv3.StageCredentialPolicy, DiagnosticInvalidRequest)
	}
	if owned.Split != nil {
		if _, err := fileops.ChunkSizeToBytes(owned.Split.ChunkSize, owned.Split.Unit); err != nil || owned.Split.ChunkSize <= 0 || owned.Split.Unit < fileops.SplitUnitKiB || owned.Split.Unit > fileops.SplitUnitTotal {
			return writeFailure(pcv3.StageCredentialPolicy, DiagnosticInvalidRequest)
		}
	}
	if !owner.report(StatusCheckingFactors) {
		return owner.reportFailure()
	}
	admitter := reportingAdmitter{owner: owner, next: seams.admitter}
	retainOutput := options.RetainDurableOutput || owned.Split != nil
	source := &writeProgressReader{reader: owned.Source, owner: owner, total: owned.PlaintextLength}
	var publication pcv3publication.Result
	var err error
	if owned.Mode == WriteModeNormal {
		protected := append([]string(nil), owned.Protected...)
		if owned.SourcePath != "" {
			protected = append(protected, owned.SourcePath)
		}
		stage, err = pcv3publication.Create(owned.Target, protected, pcv3publication.PolicyNoReplace)
		if err == nil {
			err = stage.CheckCapability()
		}
		if err == nil && options.JournalPrivateStage {
			err = stage.PersistCleanupJournal()
		}
		if err == nil {
			native := &pcv3.NativeNormalWriteRequest{
				Suite:           owned.Suite,
				PayloadKind:     owned.PayloadKind,
				PayloadBodyRS:   owned.PayloadBodyRS,
				PlaintextLength: owned.PlaintextLength,
				Comment:         owned.Comment,
				Factors:         owned.Factors,
				Admitter:        admitter,
				Source:          source,
				Destination:     stage.File(),
			}
			err = pcv3.RunNativeNormalWrite(ctx, native)
		}
		if err == nil {
			if !owner.report(StatusPublishing) {
				return owner.reportFailure()
			}
			if retainOutput {
				publication, retained = stage.PublishWriteRetained(ctx)
			} else {
				publication = stage.PublishWrite(ctx)
			}
		}
	} else {
		native := &pcv3.NativeD1WriteRequest{
			Suite:               owned.Suite,
			PayloadKind:         owned.PayloadKind,
			PayloadBodyRS:       owned.PayloadBodyRS,
			PlaintextLength:     owned.PlaintextLength,
			Comment:             owned.Comment,
			Factors:             owned.Factors,
			Admitter:            admitter,
			SourcePath:          owned.SourcePath,
			Source:              owned.SourceFile,
			Plaintext:           source,
			DestinationPath:     owned.Target,
			Protected:           owned.Protected,
			JournalPrivateStage: options.JournalPrivateStage,
		}
		publication, retained, err = pcv3.RunNativeD1WriteWithPublication(ctx, native, retainOutput)
	}
	if publication == nil && err != nil {
		_ = errors.As(err, &publication)
	}
	// Publication returns its closed failure independently of the codec error.
	// Normalize only a proven noncommit; late cancellation must not relabel a
	// durable, uncertain, or indeterminate publication as an aborted write.
	if err == nil && publication != nil && publication.State() == pcv3publication.StateNotPublished {
		err = publication
	}
	result = writePublicationResult(publication)
	if err != nil || publication == nil {
		failureStage := pcv3.StageOutputPublication
		var staged interface{ Stage() pcv3.Stage }
		if errors.As(err, &staged) {
			failureStage = staged.Stage()
		}
		diagnostic := DiagnosticCoreFailure
		var factorErr *pcv3credential.FactorError
		if errors.As(err, &factorErr) {
			failureStage = pcv3.StageCredentialPolicy
			diagnostic = DiagnosticCredentialPolicy
		}
		if owner.resourceDiagnostic != DiagnosticNone {
			diagnostic = owner.resourceDiagnostic
			failureStage = pcv3.StageCredentialPolicy
		}
		if ctx.Err() != nil {
			failureStage = pcv3.StageCancellation
			diagnostic = DiagnosticCancellation
		}
		if owner.reporterFailed || owner.reporterPanicked {
			diagnostic = DiagnosticCallbackFailure
			if owner.reporterPanicked {
				diagnostic = DiagnosticCallbackPanic
			}
		}
		if publication == nil {
			result = writeFailure(failureStage, diagnostic)
		} else if publication.State() != pcv3publication.StatePublishedDurable && publication.State() != pcv3publication.StatePublishedDurabilityUncertain {
			result.outcome = pcv3.OutcomeOperationFailed
			result.stage = failureStage
			result.code = pcv3.CodeOperationFailed
			result.diagnostic = diagnostic
		} else {
			result.appendWarning(WarningCleanupIncomplete)
		}
		if errors.Is(err, pcv3publication.ErrCleanupIncomplete) {
			result.appendWarning(WarningCleanupIncomplete)
		}
		if publication == nil || retained == nil {
			return result
		}
	}
	output := retained
	retained = nil
	return owner.finishWriteOutput(ctx, result, output, owned.Split, options.RetainDurableOutput)
}

// finishWriteOutput owns the published-file follow-up independently of codec/KDF
// execution. Both proven publication states must honor the requested split.
func (owner *operationOwner) finishWriteOutput(ctx context.Context, result *Result, retained *pcv3publication.RetainedFile, split *WriteSplitOptions, retainOutput bool) *Result {
	defer func() {
		if retained != nil && retained.Close() != nil {
			result.appendWarning(WarningCleanupIncomplete)
		}
	}()
	if result.publicationState != pcv3publication.StatePublishedDurable && result.publicationState != pcv3publication.StatePublishedDurabilityUncertain {
		return result
	}
	if (retainOutput || split != nil) && retained == nil {
		result.appendWarning(WarningCleanupIncomplete)
		return result
	}
	result.writeOutput = true
	if split != nil {
		splitState, splitErr := pcv3publication.SplitRetainedWithResult(retained, fileops.SplitOptions{
			ChunkSize: split.ChunkSize, Unit: split.Unit,
			Cancel: func() bool { return ctx.Err() != nil || owner.reporterFailed || owner.reporterPanicked },
			Progress: func(progress float32, _ string) {
				progress = max(float32(0), min(float32(1), progress))
				owner.report(StatusSplitting, uint64(progress*10000), 10000)
			},
		})
		retained = nil
		result.recordWriteSplitCompletion(splitState)
		if splitErr != nil {
			result.outcome = pcv3.OutcomeOperationFailed
			result.stage = pcv3.StageOutputPublication
			result.code = pcv3.CodeOperationFailed
			result.diagnostic = DiagnosticCoreFailure
			if ctx.Err() != nil {
				result.stage = pcv3.StageCancellation
				result.diagnostic = DiagnosticCancellation
			}
			if errors.Is(splitErr, pcv3publication.ErrCleanupIncomplete) {
				result.appendWarning(WarningCleanupIncomplete)
			}
			return result
		}
	} else if retainOutput {
		result.outputFollowUp = newWriteOutputFollowUp(retained)
		retained = nil
	}
	result.writeLifecycleComplete = result.publicationState == pcv3publication.StatePublishedDurable && !result.splitOutputUncertain
	return result
}

func writeFailure(stage pcv3.Stage, diagnostic Diagnostic) *Result {
	return closedFailure(pcv3.OutcomeOperationFailed, stage, pcv3.CodeOperationFailed, diagnostic)
}

func writePublicationResult(publication pcv3publication.Result) *Result {
	if publication == nil {
		return nil
	}
	result := newResult(resultData{
		outcome:              pcv3.OutcomeSuccess,
		stage:                pcv3.StageNone,
		code:                 pcv3.CodeSuccess,
		publicationAttempted: true,
		publicationState:     publication.State(),
		publicationStage:     publication.Stage(),
		publicationCode:      publication.Code(),
	})
	if publication.State() == pcv3publication.StatePublishedDurabilityUncertain {
		result.appendWarning(WarningDurabilityUncertain)
	}
	if publication.State() == pcv3publication.StatePublicationIndeterminate {
		result.appendWarning(WarningPublicationIndeterminate)
	}
	return result
}

// writeProgressReader counts the existing logical read stream. It performs no
// extra source reads and never owns or closes the borrowed reader.
type writeProgressReader struct {
	reader    io.Reader
	owner     *operationOwner
	total     uint64
	processed uint64
	reported  uint64
}

func (reader *writeProgressReader) Read(buffer []byte) (int, error) {
	// A full-buffer read may legally return bytes and an error together. The
	// codec consumes those bytes before probing EOF, so callback failure must
	// stay visible on that next probe rather than disappear behind source EOF.
	if reader.owner.reporterFailed || reader.owner.reporterPanicked {
		return 0, errReporterCallback
	}
	n, err := reader.reader.Read(buffer)
	if n > 0 && n <= len(buffer) {
		reader.processed += uint64(n)
		if reader.processed-reader.reported >= 1<<20 || reader.processed >= reader.total {
			reader.reported = reader.processed
			if !reader.owner.report(StatusEncrypting, min(reader.processed, reader.total), reader.total) {
				return n, errReporterCallback
			}
		}
	}
	return n, err
}

func (result *Result) recordWriteSplitCompletion(state fileops.SplitState) {
	if state == fileops.SplitCompleteDurabilityUncertain {
		result.splitOutputUncertain = true
		result.writeLifecycleComplete = false
		result.publicationState = pcv3publication.StatePublishedDurabilityUncertain
		result.publicationStage = pcv3.StageDirectorySync
		result.publicationCode = pcv3publication.CodeDurabilityUncertain
		result.appendWarning(WarningDurabilityUncertain)
	}
}
