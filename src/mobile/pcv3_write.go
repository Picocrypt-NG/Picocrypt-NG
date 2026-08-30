package mobile

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/pcv3resource"
	"context"
	"errors"
	"os"
)

var (
	runPCV3NativeNormalWrite = pcv3.RunNativeNormalWrite
	runPCV3NativeD1Write     = pcv3.RunNativeD1Write
	newPCV3WriteAdmitter     = pcv3resource.NewPlatformAdmitter
)

// pcv3WriteRequest owns every mutable creation input until the worker
// goroutine releases it. Ownership mirrors the read path: the source
// descriptor, factor request, and comment buffer transfer from StartPCV3.
type pcv3WriteRequest struct {
	d1         bool
	suite      pcv3.Suite
	payloadRS  bool
	comment    []byte
	sourcePath string
	source     *os.File
	factors    *pcv3credential.FactorRequest
	target     string
	protected  []string
}

// pcv3WriteOutcome carries one terminal presentation and, only for a durably
// published normal creation, the retained-output action.
type pcv3WriteOutcome struct {
	presentation pcv3operation.Presentation
	action       pcv3OutputAction
}

func executePCV3WriteOperation(operation *PCV3Operation, request *pcv3WriteRequest) {
	var outcome pcv3WriteOutcome
	defer func() {
		recovered := recover()
		releasePCV3WriteRequest(request)
		if recovered != nil {
			if outcome.action != nil {
				_ = discardPCV3OutputAction(outcome.action)
			}
			completePCV3Panic(operation)
			return
		}
		completePCV3WriteOutcome(operation, outcome)
	}()
	ctx, ok := getContext(operation.id)
	if !ok {
		return
	}
	outcome = runPCV3Write(ctx, request)
}

func releasePCV3WriteRequest(request *pcv3WriteRequest) {
	if request == nil {
		return
	}
	if request.factors != nil {
		// FactorRequest.Close is idempotent; the native writer may already
		// have closed the transferred request.
		_ = request.factors.Close()
		request.factors = nil
	}
	if request.source != nil {
		_ = request.source.Close()
		request.source = nil
	}
	clear(request.comment)
	request.comment = nil
	request.d1 = false
	request.suite = 0
	request.payloadRS = false
	request.sourcePath = ""
	request.target = ""
	for index := range request.protected {
		request.protected[index] = ""
	}
	request.protected = nil
}

func completePCV3WriteOutcome(operation *PCV3Operation, outcome pcv3WriteOutcome) {
	presentation := outcome.presentation
	if presentation.CompletionClass() == pcv3operation.CompletionUnknown {
		presentation = fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	if outcome.action != nil {
		completePCV3PresentationWithOutputAndInspectionComment(
			operation, presentation, outcome.action, nil, "",
		)
		return
	}
	completePCV3PresentationForOperation(operation, presentation)
}

func runPCV3Write(ctx context.Context, request *pcv3WriteRequest) pcv3WriteOutcome {
	admitter := &pcv3WriteAdmitter{next: newPCV3WriteAdmitter()}
	if request.d1 {
		return runPCV3WriteD1(ctx, request, admitter)
	}
	return runPCV3WriteNormal(ctx, request, admitter)
}

// pcv3WriteAdmitter mirrors the operation package's admission wrapper for
// creation: admission is decided by the shared platform policy (the
// operation-scoped AndroidResourceSession challenge on Android) strictly
// before the KDF runs, and only the closed decision class is retained for the
// terminal diagnostic.
type pcv3WriteAdmitter struct {
	next       pcv3credential.Admitter
	diagnostic pcv3operation.Diagnostic
}

func (admitter *pcv3WriteAdmitter) AdmitKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	if admitter == nil || admitter.next == nil {
		return pcv3credential.KDFAdmissionDenied, errors.New("pcv3 mobile write: admission unavailable")
	}
	decision, err := admitter.next.AdmitKDF(ctx, profile)
	switch {
	case err != nil:
		admitter.diagnostic = pcv3operation.DiagnosticResourceUnknown
	case decision == pcv3credential.KDFAdmissionGranted:
		admitter.diagnostic = pcv3operation.DiagnosticNone
	case decision == pcv3credential.KDFAdmissionDeniedInsufficient:
		admitter.diagnostic = pcv3operation.DiagnosticResourceInsufficient
	default:
		admitter.diagnostic = pcv3operation.DiagnosticResourceUnknown
	}
	return decision, err
}

// runPCV3WriteNormal mirrors the desktop volume.encryptPCV3 core ordering:
// stage the no-replace journaled private output first, then run the native
// writer (credential composition, admission, KDF, serialization), then publish
// durably and retain the exact output for the Android SAF transfer.
func runPCV3WriteNormal(
	ctx context.Context,
	request *pcv3WriteRequest,
	admitter *pcv3WriteAdmitter,
) pcv3WriteOutcome {
	info, err := request.source.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return pcv3WriteOutcome{presentation: pcv3WriteStageFailure(pcv3.StageInputIO, false)}
	}

	stage, err := pcv3publication.Create(
		request.target,
		append([]string(nil), request.protected...),
		pcv3publication.PolicyNoReplace,
	)
	if err == nil {
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
		return pcv3WriteOutcome{presentation: pcv3WriteStageFailure(
			pcv3.StageOutputWrite,
			errors.Is(err, pcv3publication.ErrCleanupIncomplete),
		)}
	}

	writeRequest := &pcv3.NativeNormalWriteRequest{
		Suite:           request.suite,
		PayloadKind:     pcv3.PayloadKindRaw,
		PayloadBodyRS:   request.payloadRS,
		PlaintextLength: uint64(info.Size()), //nolint:gosec // Size is checked non-negative above.
		Comment:         request.comment,
		Factors:         request.factors,
		Admitter:        admitter,
		Source:          request.source,
		Destination:     stage.File(),
	}
	if err := runPCV3NativeNormalWrite(ctx, writeRequest); err != nil {
		cleanupIncomplete := stage.Cleanup() != nil
		return pcv3WriteOutcome{
			presentation: pcv3WriteFailurePresentation(err, admitter.diagnostic, cleanupIncomplete),
		}
	}

	publication, retained := stage.PublishRetained(ctx)
	defer func() {
		// A panic between durable publication and the capability handoff must
		// not orphan the exact retained output.
		if retained != nil {
			_ = retained.RemoveExact()
		}
	}()
	if publication == nil {
		cleanupIncomplete := cleanupPCV3RetainedAndStage(&retained, stage)
		return pcv3WriteOutcome{
			presentation: pcv3WriteStageFailure(pcv3.StageOutputPublication, cleanupIncomplete),
		}
	}
	if publication.State() != pcv3publication.StatePublishedDurable || retained == nil {
		cleanupIncomplete := cleanupPCV3RetainedAndStage(&retained, stage)
		return pcv3WriteOutcome{
			presentation: pcv3WritePublicationPresentation(publication, cleanupIncomplete),
		}
	}
	if err := stage.Cleanup(); err != nil {
		// Fail loud like the desktop path: post-publication stage cleanup
		// uncertainty drops the retained capability instead of handing out an
		// output whose private custody is uncertain.
		cleanupIncomplete := retained.RemoveExact() != nil
		retained = nil
		return pcv3WriteOutcome{
			presentation: pcv3WriteStageFailure(pcv3.StageOutputPublication, cleanupIncomplete),
		}
	}
	action := &pcv3WriteOutputAction{retained: retained}
	retained = nil
	return pcv3WriteOutcome{
		presentation: pcv3WritePublicationPresentation(publication, false),
		action:       action,
	}
}

// runPCV3WriteD1 delegates staging, publication, and cleanup to the native D1
// writer exactly like the desktop path. The paranoid suite is fixed by the
// envelope; keyfile-only creation is allowed.
func runPCV3WriteD1(
	ctx context.Context,
	request *pcv3WriteRequest,
	admitter *pcv3WriteAdmitter,
) pcv3WriteOutcome {
	info, err := request.source.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return pcv3WriteOutcome{presentation: pcv3WriteStageFailure(pcv3.StageInputIO, false)}
	}

	writeRequest := &pcv3.NativeD1WriteRequest{
		Suite:           pcv3.SuiteParanoid,
		PayloadKind:     pcv3.PayloadKindRaw,
		PayloadBodyRS:   request.payloadRS,
		PlaintextLength: uint64(info.Size()), //nolint:gosec // Size is checked non-negative above.
		Comment:         request.comment,
		Factors:         request.factors,
		Admitter:        admitter,
		SourcePath:      request.sourcePath,
		Source:          request.source,
		Plaintext:       request.source,
		DestinationPath: request.target,
		Protected:       append([]string(nil), request.protected...),
	}
	if err := runPCV3NativeD1Write(ctx, writeRequest); err != nil {
		return pcv3WriteOutcome{
			presentation: pcv3WriteFailurePresentation(err, admitter.diagnostic, false),
		}
	}
	// The native D1 writer returns only after durable publication; no retained
	// capability exists for D1, so the host copies the published staging file.
	return pcv3WriteOutcome{presentation: pcv3WritePublicationAxes(
		pcv3publication.StatePublishedDurable,
		pcv3.StageNone,
		pcv3publication.CodePublishedDurable,
		false,
	)}
}

func cleanupPCV3RetainedAndStage(
	retained **pcv3publication.RetainedFile,
	stage *pcv3publication.Stage,
) (cleanupIncomplete bool) {
	if retained != nil && *retained != nil {
		if (*retained).RemoveExact() != nil {
			cleanupIncomplete = true
		}
		*retained = nil
	}
	if stage.Cleanup() != nil {
		cleanupIncomplete = true
	}
	return cleanupIncomplete
}

func pcv3WritePresentation(spec pcv3operation.PresentationSpec) pcv3operation.Presentation {
	presentation, err := pcv3operation.NewPresentation(spec)
	if err != nil {
		return fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	return presentation
}

// pcv3WriteStageFailure reports a pre-publication creation failure.
func pcv3WriteStageFailure(stage pcv3.Stage, cleanupIncomplete bool) pcv3operation.Presentation {
	diagnostic := pcv3operation.DiagnosticCoreFailure
	if stage == pcv3.StageCancellation {
		diagnostic = pcv3operation.DiagnosticCancellation
	}
	var warnings []pcv3operation.Warning
	if cleanupIncomplete {
		warnings = []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete}
	}
	return pcv3WritePresentation(pcv3operation.PresentationSpec{
		Outcome:    pcv3.OutcomeOperationFailed,
		Stage:      stage,
		Code:       pcv3.CodeOperationFailed,
		Warnings:   warnings,
		Diagnostic: diagnostic,
	})
}

// pcv3WriteFailurePresentation maps a native writer failure to the closed
// presentation axes. A credential-stage failure carries the recorded resource
// admission diagnostic, mirroring the read path's reporting admitter.
func pcv3WriteFailurePresentation(
	err error,
	resourceDiagnostic pcv3operation.Diagnostic,
	cleanupIncomplete bool,
) pcv3operation.Presentation {
	stage := pcv3.StageCredentialPolicy
	var staged interface{ Stage() pcv3.Stage }
	if errors.As(err, &staged) && staged != nil &&
		staged.Stage() > pcv3.StageNone && staged.Stage() <= pcv3.StageDirectorySync {
		stage = staged.Stage()
	}
	cleanupIncomplete = cleanupIncomplete || errors.Is(err, pcv3publication.ErrCleanupIncomplete)

	diagnostic := pcv3operation.DiagnosticCoreFailure
	switch stage {
	case pcv3.StageCancellation:
		diagnostic = pcv3operation.DiagnosticCancellation
	case pcv3.StageCredentialPolicy:
		if resourceDiagnostic != pcv3operation.DiagnosticNone {
			diagnostic = resourceDiagnostic
		} else {
			diagnostic = pcv3operation.DiagnosticCredentialPolicy
		}
	}

	spec := pcv3operation.PresentationSpec{
		Outcome:    pcv3.OutcomeOperationFailed,
		Stage:      stage,
		Code:       pcv3.CodeOperationFailed,
		Diagnostic: diagnostic,
	}
	if cleanupIncomplete {
		spec.Warnings = []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete}
	}
	// A D1 publication failure carries the closed publication axes; resource
	// diagnostics are only ever pre-publication and never combine with them.
	if resourceDiagnostic == pcv3operation.DiagnosticNone {
		var publication pcv3publication.Result
		if errors.As(err, &publication) && publication != nil {
			spec.PublicationAttempted = true
			spec.PublicationState = publication.State()
			spec.PublicationStage = publication.Stage()
			spec.PublicationCode = publication.Code()
		}
	}
	presentation, presentationErr := pcv3operation.NewPresentation(spec)
	if presentationErr != nil {
		return pcv3WriteStageFailure(stage, cleanupIncomplete)
	}
	return presentation
}

// pcv3WritePublicationPresentation reports a completed native write whose
// publication did not prove durable output.
func pcv3WritePublicationPresentation(
	publication pcv3publication.Result,
	cleanupIncomplete bool,
) pcv3operation.Presentation {
	if publication == nil {
		return pcv3WriteStageFailure(pcv3.StageOutputPublication, cleanupIncomplete)
	}
	return pcv3WritePublicationAxes(
		publication.State(),
		publication.Stage(),
		publication.Code(),
		cleanupIncomplete,
	)
}

func pcv3WritePublicationAxes(
	state pcv3publication.State,
	stage pcv3.Stage,
	code pcv3publication.Code,
	cleanupIncomplete bool,
) pcv3operation.Presentation {
	var warnings []pcv3operation.Warning
	if cleanupIncomplete {
		warnings = []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete}
	}
	return pcv3WritePresentation(pcv3operation.PresentationSpec{
		Outcome:              pcv3.OutcomeSuccess,
		Stage:                pcv3.StageNone,
		Code:                 pcv3.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     state,
		PublicationStage:     stage,
		PublicationCode:      code,
		Warnings:             warnings,
	})
}

// pcv3WriteOutputAction adapts one retained created volume to the shared
// one-shot output capability. It mirrors pcv3operation.OutputFollowUp custody:
// a failed save removes the exact internal owner because the one-shot action
// cannot safely leave the output without remaining authority.
type pcv3WriteOutputAction struct {
	retained *pcv3publication.RetainedFile
}

func (action *pcv3WriteOutputAction) Discard() pcv3OutputActionResult {
	if action == nil || action.retained == nil {
		return pcv3OutputActionResult{code: pcv3operation.OutputActionExpired.String()}
	}
	retained := action.retained
	action.retained = nil
	if err := retained.RemoveExact(); err != nil {
		return pcv3OutputActionResult{
			code:              pcv3operation.OutputActionDiscardCleanupIncomplete.String(),
			cleanupIncomplete: true,
		}
	}
	return pcv3OutputActionResult{code: pcv3operation.OutputActionDiscarded.String()}
}

func (action *pcv3WriteOutputAction) SaveTo(destination *os.File) pcv3OutputActionResult {
	if action == nil || action.retained == nil {
		if destination != nil {
			_ = destination.Close()
		}
		return pcv3OutputActionResult{code: pcv3operation.OutputActionExpired.String()}
	}
	retained := action.retained
	action.retained = nil
	copyResult := retained.CopyTo(destination)
	if !copyResult.Copied() {
		cleanupIncomplete := copyResult.CleanupIncomplete() || retained.RemoveExact() != nil
		code := pcv3operation.OutputActionSaveFailed
		if cleanupIncomplete {
			code = pcv3operation.OutputActionSaveFailedCleanupIncomplete
		}
		return pcv3OutputActionResult{code: code.String(), cleanupIncomplete: cleanupIncomplete}
	}
	if err := retained.RemoveExact(); err != nil {
		return pcv3OutputActionResult{
			code:              pcv3operation.OutputActionSavedCleanupIncomplete.String(),
			cleanupIncomplete: true,
		}
	}
	return pcv3OutputActionResult{code: pcv3operation.OutputActionSaved.String()}
}
