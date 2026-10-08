// Package pcv3recovery composes PCV3 recovery semantics with the existing
// no-replace publication state machine. It owns no cryptographic primitives
// or source-deletion behavior.
package pcv3recovery

import (
	"Picocrypt-NG/internal/diskspace"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3resource"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	recoveryRecordPlaintextMax    = uint64(1 << 20)
	artifactInspectionPageMaximum = uint64(128)
)

// ExecutionOptions selects internal output custody and crash cleanup without
// adding authority to Request. The zero value preserves terminal publication.
type ExecutionOptions struct {
	RetainDurableOutput bool
	JournalPrivateStage bool
	PrepareArchive      bool
}

var errInvalidRecoveryWriteProgress = errors.New("pcv3 recovery operation: invalid write progress")

// Request contains the operation-owned credential, source, and publication
// inputs transferred by the shared internal native operation.
type Request struct {
	Source         io.ReaderAt
	SourceSize     int64
	Factors        *pcv3credential.FactorRequest
	Admitter       pcv3credential.Admitter
	Mode           pcv3.RecoveryMode
	SelectedRole   pcv3.CapsuleRole
	Target         string
	Protected      []string
	createStage    func(string, []string, pcv3publication.Policy) (*pcv3publication.Stage, error)
	stageWriter    func(io.Writer) io.Writer
	availableSpace func(*os.File) (int64, error)
}

type operationRange struct {
	recordIndex uint64
	start       uint64
	end         uint64
	state       pcv3.RecoveryRangeState
}

type operationSemantic struct {
	outcome           pcv3.Outcome
	provenance        pcv3.ForceProvenance
	stage             pcv3.Stage
	code              pcv3.Code
	d1Provenance      pcv3.D1BootstrapProvenance
	d1OuterProvenance pcv3.D1OuterProvenance
	detailStage       pcv3.Stage
	plaintextLength   uint64
	ranges            *pcv3ranges.Map
	final             pcv3.RecoveryFinalState
}

// ArtifactInspectionMetadata is the path-free summary of one durably
// published Force recovery artifact.
type ArtifactInspectionMetadata struct {
	Kind                 pcv3artifact.State
	Role                 pcv3artifact.Role
	PlaintextLength      uint64
	Final                pcv3artifact.FinalStatus
	RangeCount           uint64
	VerifiedRangeCount   uint64
	UnverifiedRangeCount uint64
	MissingRangeCount    uint64
}

// ArtifactInspection is an immutable, in-memory view of the exact semantic
// descriptor accepted by the artifact encoder. It owns no file or operation
// authority.
type ArtifactInspection struct {
	metadata ArtifactInspectionMetadata
	ranges   *pcv3ranges.Map
}

// Metadata returns a copy of the bounded artifact summary.
func (inspection *ArtifactInspection) Metadata() ArtifactInspectionMetadata {
	if inspection == nil {
		return ArtifactInspectionMetadata{}
	}
	return inspection.metadata
}

// Page returns a defensive copy of at most 128 canonical range descriptors.
// An invalid, overflowing, or out-of-range request fails closed.
func (inspection *ArtifactInspection) Page(
	offset uint64,
	limit uint64,
) ([]pcv3artifact.Range, bool) {
	if inspection == nil || limit == 0 || limit > artifactInspectionPageMaximum {
		return nil, false
	}
	end := offset + limit
	if end < offset {
		return nil, false
	}
	rangeCount := inspection.ranges.Count()
	if offset >= rangeCount {
		return nil, false
	}
	if end > rangeCount {
		end = rangeCount
	}
	result := make([]pcv3artifact.Range, 0, end-offset)
	for i := offset; i < end; i++ {
		r, _ := inspection.ranges.At(i)
		result = append(result, pcv3artifact.Range{RecordIndex: r.Index, Start: r.Start, End: r.End, Status: pcv3artifact.RangeStatus(r.State)})
	}
	return result, true
}

func (semantic operationSemantic) outputCapable() bool {
	return semantic.outcome == pcv3.OutcomeSuccess ||
		semantic.outcome == pcv3.OutcomeAuthenticatedDegraded ||
		semantic.outcome == pcv3.OutcomeForcePartial ||
		semantic.outcome == pcv3.OutcomeForceUnverified
}

type (
	operationSegmentSink func(operationRange, []byte) error
	operationEmitter     func(operationSegmentSink) error
	operationOutput      func(operationSemantic, operationPhysicalRole, string, uint64, operationEmitter) error
	recoveryCoreRunner   func(context.Context, *Request, operationOutput) (operationSemantic, error)
)

type operationPhysicalRole uint8

const (
	operationRoleNone operationPhysicalRole = iota
	operationRoleCapsulePrimary
	operationRoleCapsuleBackup
	operationRoleD1Front
	operationRoleD1Tail
)

// Run executes the internal production recovery core and composes its output
// capability with one no-replace stage.
func Run(ctx context.Context, request *Request) *Result {
	return RunWithOptions(ctx, request, ExecutionOptions{})
}

// RunWithOptions executes normal recovery with optional retained-output and
// private-stage crash-cleanup custody.
func RunWithOptions(
	ctx context.Context,
	request *Request,
	options ExecutionOptions,
) *Result {
	if options.PrepareArchive {
		return runOperation(ctx, request, nil, options)
	}
	return runOperation(ctx, request, runProductionCore, options)
}

func runOperation(
	ctx context.Context,
	request *Request,
	run recoveryCoreRunner,
	options ExecutionOptions,
) *Result {
	if ctx == nil && request != nil && request.Factors != nil {
		_ = request.Factors.Close()
		request.Factors = nil
	}
	return runWithCoreOptions(ctx, request, run, options)
}

// RunD1 exposes the existing D1 recovery composition to the shared internal
// native operation. It adds no second core or publication path.
func RunD1(ctx context.Context, request *Request) *Result {
	return RunD1WithOptions(ctx, request, ExecutionOptions{})
}

// RunD1WithOptions executes D1 recovery with the same optional retained-output
// custody as RunWithOptions.
func RunD1WithOptions(
	ctx context.Context,
	request *Request,
	options ExecutionOptions,
) *Result {
	return runOperation(ctx, request, runD1ProductionCore, options)
}

// RunD1Unverified exposes the same composition under one exact physical D1
// role. The underlying core still owns its callback-scoped consent state.
func RunD1Unverified(
	ctx context.Context,
	request *Request,
	role pcv3.D1BootstrapRole,
) *Result {
	return RunD1UnverifiedWithOptions(ctx, request, role, ExecutionOptions{})
}

// RunD1UnverifiedWithOptions preserves the exact selected physical D1 role
// while optionally retaining a durably published output.
func RunD1UnverifiedWithOptions(
	ctx context.Context,
	request *Request,
	role pcv3.D1BootstrapRole,
	options ExecutionOptions,
) *Result {
	return runOperation(
		ctx,
		request,
		func(
			ctx context.Context,
			request *Request,
			output operationOutput,
		) (operationSemantic, error) {
			return runD1ProductionCoreWithRole(ctx, request, &role, output)
		},
		options,
	)
}

// Result keeps semantic recovery and transport publication as orthogonal
// dimensions. Its formatting never contains a path or wrapped error.
type Result struct {
	semantic             operationSemantic
	authenticatedComment string
	publicationAttempted bool
	publicationState     pcv3publication.State
	publicationStage     pcv3.Stage
	publicationCode      pcv3publication.Code
	cleanupIncomplete    bool
	artifactInspection   *ArtifactInspection
	retainedOutput       *pcv3publication.RetainedFile
	archiveHandoff       *ArchiveHandoff
}

func (result *Result) Outcome() pcv3.Outcome {
	if result == nil {
		return 0
	}
	return result.semantic.outcome
}

func (result *Result) ForceProvenance() pcv3.ForceProvenance {
	if result == nil {
		return 0
	}
	return result.semantic.provenance
}

func (result *Result) D1BootstrapProvenance() pcv3.D1BootstrapProvenance {
	if result == nil {
		return pcv3.D1BootstrapProvenanceNone
	}
	return result.semantic.d1Provenance
}

func (result *Result) DetailStage() pcv3.Stage {
	if result == nil {
		return pcv3.StageNone
	}
	return result.semantic.detailStage
}

func (result *Result) Stage() pcv3.Stage {
	if result == nil {
		return 0
	}
	return result.semantic.stage
}

func (result *Result) Code() pcv3.Code {
	if result == nil {
		return 0
	}
	return result.semantic.code
}

func (result *Result) PublicationAttempted() bool {
	return result != nil && result.publicationAttempted
}

func (result *Result) PublicationState() pcv3publication.State {
	if result == nil {
		return 0
	}
	return result.publicationState
}

func (result *Result) PublicationStage() pcv3.Stage {
	if result == nil {
		return 0
	}
	return result.publicationStage
}

func (result *Result) PublicationCode() pcv3publication.Code {
	if result == nil {
		return 0
	}
	return result.publicationCode
}

// AuthenticatedComment returns public D1 metadata only after the selected
// inner volume authenticated it. It is never populated by Force output.
func (result *Result) AuthenticatedComment() string {
	if result == nil {
		return ""
	}
	return result.authenticatedComment
}

// ArtifactInspection returns immutable artifact metadata only for a durably
// published Force result. It grants no access to the artifact path or bytes.
func (result *Result) ArtifactInspection() *ArtifactInspection {
	if result == nil || !result.publicationAttempted ||
		result.publicationState != pcv3publication.StatePublishedDurable ||
		(result.semantic.outcome != pcv3.OutcomeForcePartial &&
			result.semantic.outcome != pcv3.OutcomeForceUnverified) {
		return nil
	}
	return result.artifactInspection
}

// TakeRetainedOutput transfers the exact retained output at most once. Only a
// durable output-capable result can carry this internal capability.
func (result *Result) TakeRetainedOutput() *pcv3publication.RetainedFile {
	if result == nil || !result.publicationAttempted ||
		result.publicationState != pcv3publication.StatePublishedDurable ||
		result.publicationStage != pcv3.StageNone ||
		result.publicationCode != pcv3publication.CodePublishedDurable ||
		!validOperationSemantic(result.semantic) {
		return nil
	}
	retained := result.retainedOutput
	result.retainedOutput = nil
	return retained
}

// TakeArchiveHandoff transfers unpublished, fully authenticated D1 ZIP custody.
// The returned capability and any copies share one consuming operation.
func (result *Result) TakeArchiveHandoff() *ArchiveHandoff {
	if result == nil || result.publicationAttempted || result.cleanupIncomplete ||
		!archiveSemanticAllowed(result.semantic) {
		return nil
	}
	handoff := result.archiveHandoff
	result.archiveHandoff = nil
	return handoff
}

func (result *Result) Error() string {
	if result == nil {
		return "pcv3 recovery operation: unavailable"
	}
	return "pcv3 recovery operation: completed"
}

func (result *Result) String() string { return result.Error() }

func (result *Result) GoString() string { return result.Error() }

func (result *Result) Format(state fmt.State, verb rune) {
	value := result.Error()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	}
	_, _ = io.WriteString(state, value)
}

func (result *Result) Unwrap() error {
	if result == nil || !result.cleanupIncomplete {
		return nil
	}
	return pcv3publication.ErrCleanupIncomplete
}

func runWithCoreOptions(
	ctx context.Context,
	request *Request,
	run recoveryCoreRunner,
	options ExecutionOptions,
) (result *Result) {
	result = &Result{}
	defer func() {
		if recovered := recover(); recovered != nil {
			cleanupIncomplete := result.cleanupIncomplete
			if result.archiveHandoff != nil {
				cleanupIncomplete = result.archiveHandoff.Close() || cleanupIncomplete
				result.archiveHandoff = nil
			}
			if result.retainedOutput != nil {
				cleanupIncomplete = result.retainedOutput.RemoveExact() != nil || cleanupIncomplete
				result.retainedOutput = nil
			}
			if cleanupIncomplete {
				panic(pcv3publication.ErrCleanupIncomplete)
			}
			panic(recovered)
		}
	}()
	if ctx == nil || request == nil || run == nil ||
		(options.PrepareArchive && (request.Mode != pcv3.RecoveryModeNormalV3 || options.RetainDurableOutput)) {
		if request != nil && request.Factors != nil {
			_ = request.Factors.Close()
			request.Factors = nil
		}
		result.semantic = operationSemantic{
			outcome: pcv3.OutcomeOperationFailed,
			stage:   pcv3.StageCredentialPolicy,
			code:    pcv3.CodeOperationFailed,
		}
		return result
	}

	outputCalls := 0
	var pendingStage *pcv3publication.Stage
	defer func() {
		if pendingStage != nil {
			result.retainCleanupError(pendingStage.Cleanup())
		}
	}()
	var encodedArtifactDescriptor *pcv3artifact.Descriptor
	output := func(
		semantic operationSemantic,
		role operationPhysicalRole,
		authenticatedComment string,
		outputLength uint64,
		emit operationEmitter,
	) error {
		outputCalls++
		commentValid := authenticatedComment == "" ||
			(semantic.d1Provenance != pcv3.D1BootstrapProvenanceNone &&
				semantic.provenance == pcv3.ForceProvenanceNone &&
				(semantic.outcome == pcv3.OutcomeSuccess ||
					semantic.outcome == pcv3.OutcomeAuthenticatedDegraded))
		if outputCalls != 1 || !semantic.outputCapable() || !validOperationSemantic(semantic) ||
			!validOperationRole(semantic, role) ||
			!commentValid || emit == nil {
			return errors.New("pcv3 recovery operation: invalid core output")
		}
		semantic = cloneOperationSemantic(semantic)
		result.semantic = cloneOperationSemantic(semantic)
		result.authenticatedComment = authenticatedComment
		result.publicationAttempted = true

		createStage := request.createStage
		if createStage == nil {
			createStage = pcv3publication.Create
		}
		stage, err := createStage(
			request.Target,
			append([]string(nil), request.Protected...),
			pcv3publication.PolicyNoReplace,
		)
		if err != nil {
			result.retainPublicationError(err)
			return err
		}
		defer func() {
			if stage != nil {
				result.retainCleanupError(stage.Cleanup())
			}
		}()
		if options.JournalPrivateStage {
			if err := stage.PersistCleanupJournal(); err != nil {
				err = errors.Join(err, pcv3publication.ErrCleanupIncomplete)
				result.retainPublicationError(err)
				return err
			}
		}

		file := stage.File()
		if file == nil {
			result.retainNotPublished(pcv3.StageOutputPublication)
			return errors.New("pcv3 recovery operation: stage unavailable")
		}
		var descriptor pcv3artifact.Descriptor
		var plan *pcv3artifact.Plan
		forceArtifact := semantic.outcome == pcv3.OutcomeForcePartial || semantic.outcome == pcv3.OutcomeForceUnverified
		if forceArtifact {
			descriptor, err = artifactDescriptor(semantic, role)
			if err == nil {
				plan, err = pcv3artifact.Prepare(descriptor)
			}
			if err == nil {
				outputLength = plan.Metadata().TotalLength
			}
		}
		if err == nil {
			err = admitOutput(ctx, request, file, semantic, plan, outputLength)
		}
		if err != nil {
			result.retainNotPublished(pcv3.StageOutputWrite)
			return pcv3.NewOutputWriteError(err)
		}
		destination := io.Writer(file)
		if request.stageWriter != nil {
			destination = request.stageWriter(file)
			if destination == nil {
				result.retainNotPublished(pcv3.StageOutputWrite)
				return pcv3.NewOutputWriteError(errors.New("pcv3 recovery operation: stage writer unavailable"))
			}
		}
		destination = recoveryOutputWriter{destination: destination}
		if forceArtifact {
			err = pcv3artifact.Encode(ctx, destination, plan, func(yield func(uint64, io.Reader) error) error {
				return emit(func(r operationRange, plaintext []byte) error {
					return yield(r.recordIndex, bytes.NewReader(plaintext))
				})
			})
			if err == nil {
				encodedArtifactDescriptor = &descriptor
			}
		} else {
			err = emit(func(_ operationRange, plaintext []byte) error { return writeAll(destination, plaintext) })
		}
		if err != nil {
			result.retainNotPublished(pcv3.StageOutputWrite)
			return pcv3.NewOutputWriteError(err)
		}
		if options.PrepareArchive && archiveSemanticAllowed(semantic) {
			pendingStage = stage
			stage = nil
			return nil
		}
		var publication pcv3publication.Result
		if options.RetainDurableOutput {
			publication, result.retainedOutput = stage.PublishRetained(ctx)
		} else {
			publication = stage.Publish(ctx)
		}
		result.retainPublication(publication)
		if publication.State() != pcv3publication.StatePublishedDurable {
			return publication
		}
		return nil
	}

	semantic, coreErr := run(ctx, request, output)
	if pendingStage != nil {
		// The core's nil return proves its one-shot emitter completed, including
		// final-record verification. Non-Force results intentionally carry no
		// range/final descriptors; retain that existing closed evidence contract.
		if outputCalls != 1 || coreErr != nil || ctx.Err() != nil || result.cleanupIncomplete ||
			!archiveSemanticAllowed(semantic) || !archiveSemanticAllowed(result.semantic) ||
			semantic.d1Provenance != result.semantic.d1Provenance {
			result.semantic = operationSemantic{
				outcome: pcv3.OutcomeOperationFailed,
				stage:   pcv3.StageOutputWrite,
				code:    pcv3.CodeOperationFailed,
			}
			if semantic.outcome != 0 && !semantic.outputCapable() {
				result.semantic = cloneOperationSemantic(semantic)
			} else if ctx.Err() != nil {
				result.semantic.stage = pcv3.StageCancellation
			}
			result.retainNotPublished(result.semantic.stage)
			return result
		}
		file := pendingStage.File()
		if file == nil {
			result.retainNotPublished(pcv3.StageOutputWrite)
			return result
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			result.retainNotPublished(pcv3.StageOutputWrite)
			return result
		}
		budget := fileops.NewZIPResourceBudget()
		archiveErr := pcv3resource.AdmitZIPWorkingMemory(ctx, budget)
		if archiveErr != nil && ctx.Err() == nil {
			result.semantic = operationSemantic{
				outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageResourceBudget,
				code: pcv3.CodeOperationFailed,
			}
			result.publicationAttempted = false
			result.publicationState, result.publicationStage, result.publicationCode = 0, pcv3.StageNone, 0
			return result
		}
		var archiveReader *fileops.ZIPReader
		if archiveErr == nil {
			archiveReader, archiveErr = fileops.OpenZIPReader(file, info.Size(), fileops.ZIPReadOptions{Cancel: func() bool { return ctx.Err() != nil }, Budget: budget})
		}
		if archiveReader != nil {
			_ = archiveReader.Close()
		}
		if ctx.Err() != nil {
			result.semantic = operationSemantic{
				outcome: pcv3.OutcomeOperationFailed,
				stage:   pcv3.StageCancellation, code: pcv3.CodeOperationFailed,
			}
			result.retainNotPublished(pcv3.StageCancellation)
			return result
		}
		if archiveErr == nil {
			result.archiveHandoff = newArchiveHandoff(pendingStage)
			pendingStage = nil
			result.publicationAttempted = false
			return result
		}
		if errors.Is(archiveErr, fileops.ErrZIPMetadataLimit) {
			result.semantic = operationSemantic{
				outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageResourceBudget,
				code: pcv3.CodeOperationFailed,
			}
			result.publicationAttempted = false
			result.publicationState, result.publicationStage, result.publicationCode = 0, pcv3.StageNone, 0
			return result
		}
		var pathErr *os.PathError
		if errors.As(archiveErr, &pathErr) {
			result.retainNotPublished(pcv3.StageOutputWrite)
			return result
		}
		// Auto unzip is a no-op for authenticated non-ZIP plaintext. Publication
		// remains deferred until the complete core run has been accepted above.
		result.retainPublication(pendingStage.Publish(ctx))
		return result
	}
	if result.publicationAttempted && semantic.outcome != 0 && !semantic.outputCapable() {
		result.semantic = cloneOperationSemantic(semantic)
		result.retainNotPublished(semantic.stage)
	}
	if result.semantic.outcome == 0 {
		if semantic.outcome == 0 || semantic.outputCapable() {
			result.semantic = operationSemantic{
				outcome: pcv3.OutcomeOperationFailed,
				stage:   pcv3.StageCredentialPolicy,
				code:    pcv3.CodeOperationFailed,
			}
		} else {
			result.semantic = cloneOperationSemantic(semantic)
		}
	}
	if result.retainedOutput != nil &&
		(!result.publicationAttempted ||
			result.publicationState != pcv3publication.StatePublishedDurable ||
			result.publicationStage != pcv3.StageNone ||
			result.publicationCode != pcv3publication.CodePublishedDurable ||
			!validOperationSemantic(result.semantic)) {
		cleanupErr := result.retainedOutput.RemoveExact()
		result.retainedOutput = nil
		if cleanupErr != nil {
			result.publicationState = pcv3publication.StatePublicationIndeterminate
			result.publicationStage = pcv3.StageOutputPublication
			result.publicationCode = pcv3publication.CodePublicationIndeterminate
			result.cleanupIncomplete = true
		}
	}
	if outputCalls == 1 && result.publicationAttempted &&
		result.publicationState == pcv3publication.StatePublishedDurable &&
		(result.semantic.outcome == pcv3.OutcomeForcePartial ||
			result.semantic.outcome == pcv3.OutcomeForceUnverified) &&
		encodedArtifactDescriptor != nil {
		result.artifactInspection = artifactInspectionFromEncodedDescriptor(
			*encodedArtifactDescriptor,
		)
	}
	return result
}

func (result *Result) retainPublication(publication pcv3publication.Result) {
	if result == nil || publication == nil {
		return
	}
	result.publicationState = publication.State()
	result.publicationStage = publication.Stage()
	result.publicationCode = publication.Code()
}

func (result *Result) retainPublicationError(err error) {
	var publication pcv3publication.Result
	if errors.As(err, &publication) {
		result.retainPublication(publication)
	} else {
		result.retainNotPublished(pcv3.StageOutputPublication)
	}
	result.retainCleanupError(err)
}

func (result *Result) retainCleanupError(err error) {
	if result != nil && errors.Is(err, pcv3publication.ErrCleanupIncomplete) {
		result.cleanupIncomplete = true
	}
}

func (result *Result) retainNotPublished(stage pcv3.Stage) {
	result.publicationState = pcv3publication.StateNotPublished
	result.publicationStage = stage
	result.publicationCode = pcv3publication.CodeStageFailure
}

func cloneOperationSemantic(semantic operationSemantic) operationSemantic {
	if semantic.ranges != nil {
		frozen := *semantic.ranges
		semantic.ranges = &frozen
	}
	return semantic
}

func validOperationSemantic(semantic operationSemantic) bool {
	if !semantic.outputCapable() || !validOperationClassification(semantic) ||
		!validOperationEvidence(semantic) {
		return false
	}
	return true
}

func archiveSemanticAllowed(semantic operationSemantic) bool {
	return semantic.outcome == pcv3.OutcomeSuccess &&
		semantic.stage == pcv3.StageNone && semantic.code == pcv3.CodeSuccess &&
		semantic.provenance == pcv3.ForceProvenanceNone &&
		semantic.d1Provenance != pcv3.D1BootstrapProvenanceNone &&
		validOperationSemantic(semantic)
}

func validOperationClassification(semantic operationSemantic) bool {
	if semantic.code != operationCodeForOutcome(semantic.outcome) {
		return false
	}
	if semantic.d1OuterProvenance != pcv3.D1OuterProvenanceNone &&
		(semantic.d1OuterProvenance != pcv3.D1OuterProvenanceRawSelected ||
			semantic.outcome != pcv3.OutcomeForceUnverified ||
			semantic.provenance != pcv3.ForceProvenanceUnverified ||
			!isPhysicalD1Provenance(semantic.d1Provenance) ||
			(semantic.stage != pcv3.StageD1Bootstrap && semantic.stage != pcv3.StageD1Body)) {
		return false
	}
	if semantic.d1Provenance == pcv3.D1BootstrapProvenanceNone {
		if semantic.detailStage != pcv3.StageNone || semantic.stage == pcv3.StageD1Bootstrap ||
			semantic.stage == pcv3.StageD1Body || semantic.stage == pcv3.StageInnerVolume {
			return false
		}
		return validOperationInnerClassification(
			semantic.outcome,
			semantic.provenance,
			semantic.stage,
		)
	}
	if !validSelectedD1Provenance(semantic.d1Provenance) {
		return false
	}
	if semantic.detailStage != pcv3.StageNone {
		if semantic.stage != pcv3.StageD1Bootstrap && semantic.stage != pcv3.StageD1Body &&
			semantic.stage != pcv3.StageInnerVolume {
			return false
		}
		return validOperationD1ProvenanceForOutcome(semantic.outcome, semantic.d1Provenance) &&
			validOperationInnerClassification(
				semantic.outcome,
				semantic.provenance,
				semantic.detailStage,
			)
	}
	switch semantic.stage {
	case pcv3.StageNone:
		return semantic.outcome == pcv3.OutcomeSuccess &&
			semantic.provenance == pcv3.ForceProvenanceNone &&
			(semantic.d1Provenance == pcv3.D1BootstrapProvenanceFront ||
				semantic.d1Provenance == pcv3.D1BootstrapProvenanceMatching)
	case pcv3.StageD1Bootstrap:
		return (semantic.outcome == pcv3.OutcomeAuthenticatedDegraded &&
			semantic.provenance == pcv3.ForceProvenanceNone) ||
			(semantic.outcome == pcv3.OutcomeForcePartial &&
				semantic.provenance == pcv3.ForceProvenancePartial) ||
			(semantic.outcome == pcv3.OutcomeForceUnverified &&
				semantic.provenance == pcv3.ForceProvenanceUnverified &&
				isPhysicalD1Provenance(semantic.d1Provenance))
	case pcv3.StageD1Body:
		return (semantic.outcome == pcv3.OutcomeAuthenticatedDegraded &&
			semantic.provenance == pcv3.ForceProvenanceNone) ||
			(semantic.outcome == pcv3.OutcomeForcePartial &&
				semantic.provenance == pcv3.ForceProvenancePartial) ||
			(semantic.outcome == pcv3.OutcomeForceUnverified &&
				semantic.provenance == pcv3.ForceProvenanceUnverified &&
				isPhysicalD1Provenance(semantic.d1Provenance))
	default:
		return false
	}
}

func validOperationInnerClassification(
	outcome pcv3.Outcome,
	provenance pcv3.ForceProvenance,
	stage pcv3.Stage,
) bool {
	switch outcome {
	case pcv3.OutcomeSuccess:
		return provenance == pcv3.ForceProvenanceNone && stage == pcv3.StageNone
	case pcv3.OutcomeAuthenticatedDegraded:
		switch provenance {
		case pcv3.ForceProvenanceNone:
			return isNormalDegradedStage(stage)
		case pcv3.ForceProvenanceVerified:
			return isForceDamageStage(stage)
		default:
			return false
		}
	case pcv3.OutcomeForcePartial:
		return provenance == pcv3.ForceProvenancePartial && isForceDamageStage(stage)
	case pcv3.OutcomeForceUnverified:
		return provenance == pcv3.ForceProvenanceUnverified && isForceDamageStage(stage)
	default:
		return false
	}
}

func validOperationEvidence(semantic operationSemantic) bool {
	if semantic.provenance == pcv3.ForceProvenanceNone {
		return (semantic.outcome == pcv3.OutcomeSuccess ||
			semantic.outcome == pcv3.OutcomeAuthenticatedDegraded) &&
			semantic.plaintextLength == 0 && semantic.ranges.Count() == 0 && semantic.final == 0
	}
	if semantic.ranges == nil || semantic.ranges.PlaintextLength() != semantic.plaintextLength {
		return false
	}
	if semantic.final != pcv3.RecoveryFinalVerified &&
		semantic.final != pcv3.RecoveryFinalUnverified &&
		semantic.final != pcv3.RecoveryFinalMissing {
		return false
	}
	summary := semantic.ranges.Summary()
	hasVerified := semantic.final == pcv3.RecoveryFinalVerified || summary.Verified > 0
	hasUnverified := semantic.final == pcv3.RecoveryFinalUnverified || summary.Unverified > 0
	hasDamage := semantic.final != pcv3.RecoveryFinalVerified || summary.Unverified > 0 || summary.Missing > 0
	switch semantic.provenance {
	case pcv3.ForceProvenanceVerified:
		return semantic.outcome == pcv3.OutcomeAuthenticatedDegraded && !hasDamage
	case pcv3.ForceProvenancePartial:
		return semantic.outcome == pcv3.OutcomeForcePartial && hasVerified && hasDamage
	case pcv3.ForceProvenanceUnverified:
		if semantic.d1OuterProvenance == pcv3.D1OuterProvenanceRawSelected {
			return semantic.outcome == pcv3.OutcomeForceUnverified && (hasVerified || hasUnverified)
		}
		return semantic.outcome == pcv3.OutcomeForceUnverified && !hasVerified && hasUnverified
	default:
		return false
	}
}

func operationCodeForOutcome(outcome pcv3.Outcome) pcv3.Code {
	switch outcome {
	case pcv3.OutcomeSuccess:
		return pcv3.CodeSuccess
	case pcv3.OutcomeAuthenticatedDegraded:
		return pcv3.CodeAuthenticatedDegraded
	case pcv3.OutcomeForcePartial:
		return pcv3.CodeForcePartial
	case pcv3.OutcomeForceUnverified:
		return pcv3.CodeForceUnverified
	default:
		return 0
	}
}

func validSelectedD1Provenance(provenance pcv3.D1BootstrapProvenance) bool {
	return provenance == pcv3.D1BootstrapProvenanceFront ||
		provenance == pcv3.D1BootstrapProvenanceTail ||
		provenance == pcv3.D1BootstrapProvenanceMatching
}

func validOperationD1ProvenanceForOutcome(
	outcome pcv3.Outcome,
	provenance pcv3.D1BootstrapProvenance,
) bool {
	if outcome == pcv3.OutcomeForceUnverified {
		return isPhysicalD1Provenance(provenance)
	}
	return validSelectedD1Provenance(provenance)
}

func isPhysicalD1Provenance(provenance pcv3.D1BootstrapProvenance) bool {
	return provenance == pcv3.D1BootstrapProvenanceFront ||
		provenance == pcv3.D1BootstrapProvenanceTail
}

func isNormalDegradedStage(stage pcv3.Stage) bool {
	switch stage {
	case pcv3.StagePreamble, pcv3.StageCapsuleRS, pcv3.StageCapsuleStructure,
		pcv3.StageTailGeometry, pcv3.StageWrapAuth, pcv3.StageReplicaAuth,
		pcv3.StageMetadata:
		return true
	default:
		return false
	}
}

func isForceDamageStage(stage pcv3.Stage) bool {
	return isNormalDegradedStage(stage) || stage == pcv3.StageDescriptor ||
		stage == pcv3.StageRecordBodyRS || stage == pcv3.StageRecordAuth ||
		stage == pcv3.StageFinalRecord
}

func validOperationRole(semantic operationSemantic, role operationPhysicalRole) bool {
	switch semantic.d1Provenance {
	case pcv3.D1BootstrapProvenanceNone:
		return role == operationRoleCapsulePrimary || role == operationRoleCapsuleBackup
	case pcv3.D1BootstrapProvenanceFront:
		return role == operationRoleD1Front
	case pcv3.D1BootstrapProvenanceTail:
		return role == operationRoleD1Tail
	case pcv3.D1BootstrapProvenanceMatching:
		return role == operationRoleD1Front || role == operationRoleD1Tail
	default:
		return false
	}
}

func runProductionCore(
	ctx context.Context,
	request *Request,
	output operationOutput,
) (operationSemantic, error) {
	if request == nil {
		return operationSemantic{
			outcome: pcv3.OutcomeOperationFailed,
			stage:   pcv3.StageCredentialPolicy,
			code:    pcv3.CodeOperationFailed,
		}, errors.New("pcv3 recovery operation: invalid request")
	}
	factors := request.Factors
	request.Factors = nil
	coreOutput := func(
		result *pcv3.RecoveryResult,
		role pcv3.CapsuleRole,
		plan pcv3.RecoveryOutputPlan,
		emitter pcv3.RecoveryEmitter,
	) error {
		semantic := semanticFromCore(result)
		physicalRole, ok := operationRoleForCapsule(role)
		if !ok {
			return errors.New("pcv3 recovery operation: invalid capsule role")
		}
		return output(semantic, physicalRole, "", plan.PlaintextLength(), func(sink operationSegmentSink) error {
			return emitter(func(recoveryRange pcv3.RecoveryRange, plaintext []byte) error {
				return sink(operationRange{
					recordIndex: recoveryRange.RecordIndex(),
					start:       recoveryRange.Start(),
					end:         recoveryRange.End(),
					state:       recoveryRange.State(),
				}, plaintext)
			})
		})
	}

	var result *pcv3.RecoveryResult
	var err error
	if request.Mode == pcv3.RecoveryModeForceUnverified {
		result, err = pcv3.RecoverUnverified(
			ctx,
			request.Source,
			request.SourceSize,
			factors,
			request.Admitter,
			request.SelectedRole,
			coreOutput,
		)
	} else {
		result, err = pcv3.Recover(
			ctx,
			request.Source,
			request.SourceSize,
			factors,
			request.Admitter,
			request.Mode,
			coreOutput,
		)
	}
	semantic := semanticFromCore(result)
	if result != nil {
		result.Close()
	}
	return semantic, err
}

func runD1ProductionCore(
	ctx context.Context,
	request *Request,
	output operationOutput,
) (operationSemantic, error) {
	return runD1ProductionCoreWithRole(ctx, request, nil, output)
}

func runD1ProductionCoreWithRole(
	ctx context.Context,
	request *Request,
	selectedRole *pcv3.D1BootstrapRole,
	output operationOutput,
) (operationSemantic, error) {
	if request == nil {
		return operationSemantic{
			outcome: pcv3.OutcomeOperationFailed,
			stage:   pcv3.StageCredentialPolicy,
			code:    pcv3.CodeOperationFailed,
		}, errors.New("pcv3 recovery operation: invalid D1 request")
	}
	factors := request.Factors
	request.Factors = nil
	if (request.Mode == pcv3.RecoveryModeForceUnverified) != (selectedRole != nil) {
		if factors != nil {
			_ = factors.Close()
		}
		return operationSemantic{
			outcome: pcv3.OutcomeOperationFailed,
			stage:   pcv3.StageCredentialPolicy,
			code:    pcv3.CodeOperationFailed,
		}, errors.New("pcv3 recovery operation: invalid D1 mode")
	}
	coreOutput := func(
		result *pcv3.RecoveryResult,
		role pcv3.D1BootstrapRole,
		authenticatedComment string,
		plan pcv3.RecoveryOutputPlan,
		emitter pcv3.RecoveryEmitter,
	) error {
		semantic := semanticFromCore(result)
		physicalRole, ok := operationRoleForD1(role)
		if !ok {
			return errors.New("pcv3 recovery operation: invalid D1 role")
		}
		return output(semantic, physicalRole, authenticatedComment, plan.PlaintextLength(), func(sink operationSegmentSink) error {
			return emitter(func(recoveryRange pcv3.RecoveryRange, plaintext []byte) error {
				return sink(operationRange{
					recordIndex: recoveryRange.RecordIndex(),
					start:       recoveryRange.Start(),
					end:         recoveryRange.End(),
					state:       recoveryRange.State(),
				}, plaintext)
			})
		})
	}

	var result *pcv3.RecoveryResult
	var err error
	if selectedRole != nil {
		result, err = pcv3.RecoverD1Unverified(
			ctx,
			request.Source,
			request.SourceSize,
			factors,
			request.Admitter,
			*selectedRole,
			coreOutput,
		)
	} else {
		result, err = pcv3.RecoverD1(
			ctx,
			request.Source,
			request.SourceSize,
			factors,
			request.Admitter,
			request.Mode,
			coreOutput,
		)
	}
	semantic := semanticFromCore(result)
	if result != nil {
		result.Close()
	}
	return semantic, err
}

func semanticFromCore(result *pcv3.RecoveryResult) operationSemantic {
	if result == nil {
		return operationSemantic{
			outcome: pcv3.OutcomeOperationFailed,
			stage:   pcv3.StageCredentialPolicy,
			code:    pcv3.CodeOperationFailed,
		}
	}
	semantic := operationSemantic{
		outcome:           result.Outcome(),
		provenance:        result.ForceProvenance(),
		stage:             result.Stage(),
		code:              result.Code(),
		d1Provenance:      result.D1BootstrapProvenance(),
		d1OuterProvenance: result.D1OuterProvenance(),
		detailStage:       result.DetailStage(),
		plaintextLength:   result.PlaintextLength(),
		final:             result.FinalRecordState(),
	}
	semantic.ranges = result.Ranges()
	return semantic
}

func artifactDescriptor(
	semantic operationSemantic,
	role operationPhysicalRole,
) (pcv3artifact.Descriptor, error) {
	descriptor := pcv3artifact.Descriptor{
		PlaintextLength: semantic.plaintextLength,
	}
	switch semantic.outcome {
	case pcv3.OutcomeForcePartial:
		descriptor.State = pcv3artifact.StatePartial
	case pcv3.OutcomeForceUnverified:
		descriptor.State = pcv3artifact.StateUnverifiedForensic
	default:
		return pcv3artifact.Descriptor{}, errors.New("pcv3 recovery operation: artifact state unavailable")
	}
	descriptor.Ranges = semantic.ranges
	hasUnverified := semantic.final == pcv3.RecoveryFinalUnverified || semantic.ranges.Summary().Unverified > 0
	if hasUnverified || semantic.d1OuterProvenance == pcv3.D1OuterProvenanceRawSelected {
		switch role {
		case operationRoleCapsulePrimary:
			descriptor.Role = pcv3artifact.RolePrimary
		case operationRoleCapsuleBackup:
			descriptor.Role = pcv3artifact.RoleBackup
		case operationRoleD1Front:
			descriptor.Role = pcv3artifact.RoleD1Front
		case operationRoleD1Tail:
			descriptor.Role = pcv3artifact.RoleD1Tail
		default:
			return pcv3artifact.Descriptor{}, errors.New("pcv3 recovery operation: unverified role unavailable")
		}
	}
	descriptor.Final = artifactFinalState(semantic.final)
	return descriptor, nil
}

func artifactInspectionFromEncodedDescriptor(
	descriptor pcv3artifact.Descriptor,
) *ArtifactInspection {
	if descriptor.Ranges == nil {
		return nil
	}
	metadata := ArtifactInspectionMetadata{
		Kind:            descriptor.State,
		Role:            descriptor.Role,
		PlaintextLength: descriptor.PlaintextLength,
		Final:           descriptor.Final,
		RangeCount:      descriptor.Ranges.Count(),
	}
	switch metadata.Kind {
	case pcv3artifact.StatePartial, pcv3artifact.StateUnverifiedForensic:
	default:
		return nil
	}
	switch metadata.Role {
	case pcv3artifact.RoleNone, pcv3artifact.RolePrimary, pcv3artifact.RoleBackup,
		pcv3artifact.RoleD1Front, pcv3artifact.RoleD1Tail:
	default:
		return nil
	}
	switch metadata.Final {
	case pcv3artifact.FinalVerified, pcv3artifact.FinalUnverified, pcv3artifact.FinalMissing:
	default:
		return nil
	}

	summary := descriptor.Ranges.Summary()
	metadata.VerifiedRangeCount = summary.Verified
	metadata.UnverifiedRangeCount = summary.Unverified
	metadata.MissingRangeCount = summary.Missing
	frozen := *descriptor.Ranges
	return &ArtifactInspection{metadata: metadata, ranges: &frozen}
}

func operationRoleForCapsule(role pcv3.CapsuleRole) (operationPhysicalRole, bool) {
	switch role {
	case pcv3.CapsuleRolePrimary:
		return operationRoleCapsulePrimary, true
	case pcv3.CapsuleRoleBackup:
		return operationRoleCapsuleBackup, true
	default:
		return operationRoleNone, false
	}
}

func operationRoleForD1(role pcv3.D1BootstrapRole) (operationPhysicalRole, bool) {
	switch role {
	case pcv3.D1BootstrapFront:
		return operationRoleD1Front, true
	case pcv3.D1BootstrapTail:
		return operationRoleD1Tail, true
	default:
		return operationRoleNone, false
	}
}

func artifactFinalState(state pcv3.RecoveryFinalState) pcv3artifact.FinalStatus {
	switch state {
	case pcv3.RecoveryFinalVerified:
		return pcv3artifact.FinalVerified
	case pcv3.RecoveryFinalUnverified:
		return pcv3artifact.FinalUnverified
	case pcv3.RecoveryFinalMissing:
		return pcv3artifact.FinalMissing
	default:
		return 0
	}
}

type recoveryOutputWriter struct {
	destination io.Writer
}

func (writer recoveryOutputWriter) Write(data []byte) (int, error) {
	written, err := writer.destination.Write(data)
	if written < 0 || written > len(data) {
		return 0, pcv3.NewOutputWriteError(errInvalidRecoveryWriteProgress)
	}
	if err != nil {
		return written, pcv3.NewOutputWriteError(err)
	}
	if written == 0 && len(data) != 0 {
		return 0, pcv3.NewOutputWriteError(io.ErrNoProgress)
	}
	return written, nil
}

func writeAll(destination io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := destination.Write(data)
		if written < 0 || written > len(data) {
			return errInvalidRecoveryWriteProgress
		}
		data = data[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

const outputReserveBytes uint64 = 64 << 20

// admitOutput observes capacity on the held stage filesystem before any output
// write. This is a preflight observation, not a reservation; publication still
// checks every write, Sync and filesystem identity.
func admitOutput(ctx context.Context, request *Request, file *os.File, semantic operationSemantic, plan *pcv3artifact.Plan, length uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if length > math.MaxInt64-outputReserveBytes {
		return errors.New("pcv3 recovery operation: output cost overflow")
	}
	if semantic.outcome == pcv3.OutcomeForceUnverified {
		if plan == nil || request.SourceSize < 0 {
			return errors.New("pcv3 recovery operation: output cost unavailable")
		}
		allowance := outputReserveBytes
		if uint64(request.SourceSize) > allowance {
			allowance = uint64(request.SourceSize)
		}
		metadata := plan.Metadata()
		if metadata.DataOffset-metadata.HeaderLength > allowance {
			return errors.New("pcv3 recovery operation: unverified table budget exceeded")
		}
	}
	probe := request.availableSpace
	if probe == nil {
		probe = diskspace.AvailableFile
	}
	available, err := probe(file)
	if err != nil {
		return err
	}
	if available < 0 || uint64(available) < length+outputReserveBytes {
		return errors.New("pcv3 recovery operation: insufficient output space")
	}
	return ctx.Err()
}
