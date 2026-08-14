package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/pcv3recovery"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

const (
	maxResultArgs     = 4
	maxResultWarnings = 8
)

// CompletionClass is derived from the closed semantic, publication, warning,
// and live-capability tuple. It is not an independent success flag.
type CompletionClass uint8

const (
	CompletionUnknown CompletionClass = iota
	CompletionRefused
	CompletionNoOutput
	CompletionClean
	CompletionWarning
	CompletionArchivePending
	CompletionDurabilityUncertain
	CompletionPublicationIndeterminate
)

// Warning is a bounded, non-sensitive operation warning.
type Warning uint8

const (
	WarningAuthenticatedDegraded Warning = iota + 1
	WarningForcePartial
	WarningForceUnverified
	WarningDurabilityUncertain
	WarningPublicationIndeterminate
	WarningCleanupIncomplete
	WarningCallbackFailure
)

// Diagnostic is a fixed, non-sensitive diagnostic class. Raw errors, paths,
// credentials, and callback text are never retained by Result.
type Diagnostic uint8

const (
	DiagnosticNone Diagnostic = iota
	DiagnosticInvalidRequest
	DiagnosticRoutingRefusal
	DiagnosticCredentialPolicy
	DiagnosticCancellation
	DiagnosticCoreFailure
	DiagnosticCallbackFailure
	DiagnosticCallbackPanic
	DiagnosticGovernanceRefusal
	DiagnosticResourceBusy
	DiagnosticResourceInsufficient
	DiagnosticResourceUnknown
)

// ErrInvalidPresentation rejects a malformed authority-free result snapshot.
// It deliberately carries no field value or caller-controlled text.
var ErrInvalidPresentation = errors.New("pcv3 operation: invalid presentation")

// PresentationSpec contains only closed, non-sensitive result axes. It cannot
// carry paths, callbacks, errors, credentials, or operation capabilities.
// ArchivePending describes a nonterminal state; it grants no archive authority.
type PresentationSpec struct {
	Outcome               pcv3.Outcome
	Stage                 pcv3.Stage
	Code                  pcv3.Code
	ForceProvenance       pcv3.ForceProvenance
	D1BootstrapProvenance pcv3.D1BootstrapProvenance
	DetailStage           pcv3.Stage
	PublicationAttempted  bool
	PublicationState      pcv3publication.State
	PublicationStage      pcv3.Stage
	PublicationCode       pcv3publication.Code
	Args                  []uint64
	Warnings              []Warning
	Diagnostic            Diagnostic
	ArchivePending        bool
}

// Presentation is an authority-free, defensively owned result snapshot for
// native surfaces. Its zero value is an unknown completion and grants nothing.
type Presentation struct {
	outcome               pcv3.Outcome
	stage                 pcv3.Stage
	code                  pcv3.Code
	forceProvenance       pcv3.ForceProvenance
	d1BootstrapProvenance pcv3.D1BootstrapProvenance
	detailStage           pcv3.Stage
	publicationAttempted  bool
	publicationState      pcv3publication.State
	publicationStage      pcv3.Stage
	publicationCode       pcv3publication.Code
	args                  [maxResultArgs]uint64
	argCount              uint8
	warnings              [maxResultWarnings]Warning
	warningCount          uint8
	diagnostic            Diagnostic
	archivePending        bool
}

// NewPresentation validates and owns one authority-free presentation tuple.
func NewPresentation(spec PresentationSpec) (Presentation, error) {
	if len(spec.Args) > maxResultArgs || len(spec.Warnings) > maxResultWarnings ||
		!validWarningSlice(spec.Warnings) {
		return Presentation{}, ErrInvalidPresentation
	}
	result := newResult(resultData{
		outcome:               spec.Outcome,
		stage:                 spec.Stage,
		code:                  spec.Code,
		forceProvenance:       spec.ForceProvenance,
		d1BootstrapProvenance: spec.D1BootstrapProvenance,
		detailStage:           spec.DetailStage,
		publicationAttempted:  spec.PublicationAttempted,
		publicationState:      spec.PublicationState,
		publicationStage:      spec.PublicationStage,
		publicationCode:       spec.PublicationCode,
		args:                  spec.Args,
		warnings:              spec.Warnings,
		diagnostic:            spec.Diagnostic,
	})
	presentation := presentationFromResult(result, spec.ArchivePending)
	if presentation.CompletionClass() == CompletionUnknown {
		return Presentation{}, ErrInvalidPresentation
	}
	return presentation, nil
}

func validWarningSlice(warnings []Warning) bool {
	var seen [maxResultWarnings + 1]bool
	for _, warning := range warnings {
		if warning < WarningAuthenticatedDegraded || warning > WarningCallbackFailure ||
			seen[warning] {
			return false
		}
		seen[warning] = true
	}
	return true
}

// archiveFollowUpState is implemented only by operation-owned, Go-minted
// follow-up state. Task 4 adds the concrete extraction lifecycle.
type archiveFollowUpState interface {
	live() bool
	extract(*os.Root) *Result
	close() *Result
}

// ArchiveFollowUp is an opaque operation-scoped capability. A zero value has
// no authority. Its effect methods are introduced with the archive lifecycle.
type ArchiveFollowUp struct {
	state archiveFollowUpState
}

// Result is the closed native operation result. Semantic and publication
// truth remain independent; completion is computed rather than stored.
type Result struct {
	outcome               pcv3.Outcome
	stage                 pcv3.Stage
	code                  pcv3.Code
	forceProvenance       pcv3.ForceProvenance
	d1BootstrapProvenance pcv3.D1BootstrapProvenance
	detailStage           pcv3.Stage
	publicationAttempted  bool
	publicationState      pcv3publication.State
	publicationStage      pcv3.Stage
	publicationCode       pcv3publication.Code
	args                  [maxResultArgs]uint64
	argCount              uint8
	warnings              [maxResultWarnings]Warning
	warningCount          uint8
	diagnostic            Diagnostic
	archiveFollowUp       *ArchiveFollowUp
	outputFollowUp        *OutputFollowUp
	artifactInspection    *pcv3recovery.ArtifactInspection
}

type resultData struct {
	outcome               pcv3.Outcome
	stage                 pcv3.Stage
	code                  pcv3.Code
	forceProvenance       pcv3.ForceProvenance
	d1BootstrapProvenance pcv3.D1BootstrapProvenance
	detailStage           pcv3.Stage
	publicationAttempted  bool
	publicationState      pcv3publication.State
	publicationStage      pcv3.Stage
	publicationCode       pcv3publication.Code
	args                  []uint64
	warnings              []Warning
	diagnostic            Diagnostic
}

func newResult(data resultData) *Result {
	result := &Result{
		outcome:               data.outcome,
		stage:                 data.stage,
		code:                  data.code,
		forceProvenance:       data.forceProvenance,
		d1BootstrapProvenance: data.d1BootstrapProvenance,
		detailStage:           data.detailStage,
		publicationAttempted:  data.publicationAttempted,
		publicationState:      data.publicationState,
		publicationStage:      data.publicationStage,
		publicationCode:       data.publicationCode,
		diagnostic:            data.diagnostic,
	}
	for _, arg := range data.args {
		result.appendArg(arg)
	}
	for _, warning := range data.warnings {
		result.appendWarning(warning)
	}
	switch result.outcome {
	case pcv3.OutcomeAuthenticatedDegraded:
		result.appendWarning(WarningAuthenticatedDegraded)
	case pcv3.OutcomeForcePartial:
		result.appendWarning(WarningForcePartial)
	case pcv3.OutcomeForceUnverified:
		result.appendWarning(WarningForceUnverified)
	}
	switch result.publicationState {
	case pcv3publication.StatePublishedDurabilityUncertain:
		result.appendWarning(WarningDurabilityUncertain)
	case pcv3publication.StatePublicationIndeterminate:
		result.appendWarning(WarningPublicationIndeterminate)
	}
	return result
}

func (result *Result) appendArg(arg uint64) {
	if result == nil || int(result.argCount) >= len(result.args) {
		return
	}
	result.args[result.argCount] = arg
	result.argCount++
}

func (result *Result) appendWarning(warning Warning) {
	if result == nil || warning == 0 {
		return
	}
	for index := uint8(0); index < result.warningCount; index++ {
		if result.warnings[index] == warning {
			return
		}
	}
	if int(result.warningCount) >= len(result.warnings) {
		return
	}
	result.warnings[result.warningCount] = warning
	result.warningCount++
}

func (result *Result) Outcome() pcv3.Outcome {
	if result == nil {
		return 0
	}
	return result.outcome
}

func (result *Result) Stage() pcv3.Stage {
	if result == nil {
		return 0
	}
	return result.stage
}

func (result *Result) Code() pcv3.Code {
	if result == nil {
		return 0
	}
	return result.code
}

func (result *Result) ForceProvenance() pcv3.ForceProvenance {
	if result == nil {
		return pcv3.ForceProvenanceNone
	}
	return result.forceProvenance
}

func (result *Result) D1BootstrapProvenance() pcv3.D1BootstrapProvenance {
	if result == nil {
		return pcv3.D1BootstrapProvenanceNone
	}
	return result.d1BootstrapProvenance
}

func (result *Result) DetailStage() pcv3.Stage {
	if result == nil {
		return pcv3.StageNone
	}
	return result.detailStage
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
		return pcv3.StageNone
	}
	return result.publicationStage
}

func (result *Result) PublicationCode() pcv3publication.Code {
	if result == nil {
		return 0
	}
	return result.publicationCode
}

func (result *Result) Args() []uint64 {
	if result == nil || result.argCount == 0 {
		return nil
	}
	args := make([]uint64, result.argCount)
	copy(args, result.args[:result.argCount])
	return args
}

func (result *Result) Warnings() []Warning {
	if result == nil || result.warningCount == 0 {
		return nil
	}
	warnings := make([]Warning, result.warningCount)
	copy(warnings, result.warnings[:result.warningCount])
	return warnings
}

func (result *Result) Diagnostic() Diagnostic {
	if result == nil {
		return DiagnosticNone
	}
	return result.diagnostic
}

// Presentation returns a detached snapshot. A live archive is represented
// only as a non-authoritative pending axis; its follow-up remains on Result.
func (result *Result) Presentation() Presentation {
	return presentationFromResult(result, result.hasActiveArchiveFollowUp())
}

// ArtifactInspection returns only immutable, path-free metadata minted by the
// recovery core for a durably published Force artifact. It grants no file,
// save, delete, or plaintext authority and is deliberately absent from
// Presentation.
func (result *Result) ArtifactInspection() *pcv3recovery.ArtifactInspection {
	if result == nil || !result.publicationAttempted ||
		result.publicationState != pcv3publication.StatePublishedDurable ||
		(result.outcome != pcv3.OutcomeForcePartial &&
			result.outcome != pcv3.OutcomeForceUnverified) {
		return nil
	}
	return result.artifactInspection
}

func presentationFromResult(result *Result, archivePending bool) Presentation {
	if result == nil {
		return Presentation{}
	}
	return Presentation{
		outcome:               result.outcome,
		stage:                 result.stage,
		code:                  result.code,
		forceProvenance:       result.forceProvenance,
		d1BootstrapProvenance: result.d1BootstrapProvenance,
		detailStage:           result.detailStage,
		publicationAttempted:  result.publicationAttempted,
		publicationState:      result.publicationState,
		publicationStage:      result.publicationStage,
		publicationCode:       result.publicationCode,
		args:                  result.args,
		argCount:              result.argCount,
		warnings:              result.warnings,
		warningCount:          result.warningCount,
		diagnostic:            result.diagnostic,
		archivePending:        archivePending,
	}
}

func (presentation Presentation) Outcome() pcv3.Outcome { return presentation.outcome }

func (presentation Presentation) Stage() pcv3.Stage { return presentation.stage }

func (presentation Presentation) Code() pcv3.Code { return presentation.code }

func (presentation Presentation) ForceProvenance() pcv3.ForceProvenance {
	return presentation.forceProvenance
}

func (presentation Presentation) D1BootstrapProvenance() pcv3.D1BootstrapProvenance {
	return presentation.d1BootstrapProvenance
}

func (presentation Presentation) DetailStage() pcv3.Stage { return presentation.detailStage }

func (presentation Presentation) PublicationAttempted() bool {
	return presentation.publicationAttempted
}

func (presentation Presentation) PublicationState() pcv3publication.State {
	return presentation.publicationState
}

func (presentation Presentation) PublicationStage() pcv3.Stage {
	return presentation.publicationStage
}

func (presentation Presentation) PublicationCode() pcv3publication.Code {
	return presentation.publicationCode
}

func (presentation Presentation) Args() []uint64 {
	if presentation.argCount == 0 || int(presentation.argCount) > len(presentation.args) {
		return nil
	}
	args := make([]uint64, presentation.argCount)
	copy(args, presentation.args[:presentation.argCount])
	return args
}

func (presentation Presentation) Warnings() []Warning {
	if presentation.warningCount == 0 ||
		int(presentation.warningCount) > len(presentation.warnings) {
		return nil
	}
	warnings := make([]Warning, presentation.warningCount)
	copy(warnings, presentation.warnings[:presentation.warningCount])
	return warnings
}

func (presentation Presentation) Diagnostic() Diagnostic { return presentation.diagnostic }

// ArchivePending reports presentation state only. It is never permission to
// extract or close an archive; those effects require Result.ArchiveFollowUp.
func (presentation Presentation) ArchivePending() bool { return presentation.archivePending }

// ArchiveFollowUp returns authority only for the exact live, fully
// authenticated, not-yet-published archive tuple.
func (result *Result) ArchiveFollowUp() *ArchiveFollowUp {
	if !result.hasLiveArchiveFollowUp() {
		return nil
	}
	return result.archiveFollowUp
}

// OutputFollowUp returns authority only for an exact live retained output
// whose publication was proven durable. Presentation cannot mint or restore
// this capability.
func (result *Result) OutputFollowUp() *OutputFollowUp {
	if !result.hasLiveOutputFollowUp() {
		return nil
	}
	return result.outputFollowUp
}

func (result *Result) hasActiveArchiveFollowUp() bool {
	return result != nil && result.archiveFollowUp != nil &&
		result.archiveFollowUp.state != nil && result.archiveFollowUp.state.live()
}

func (result *Result) hasLiveArchiveFollowUp() bool {
	return result.hasActiveArchiveFollowUp() &&
		result.CompletionClass() == CompletionArchivePending
}

func (result *Result) hasLiveOutputFollowUp() bool {
	if result == nil || result.outputFollowUp == nil || !result.outputFollowUp.live() ||
		result.hasActiveArchiveFollowUp() || !result.publicationAttempted ||
		result.publicationState != pcv3publication.StatePublishedDurable ||
		result.publicationStage != pcv3.StageNone ||
		result.publicationCode != pcv3publication.CodePublishedDurable ||
		!validSemanticPresentation(result.outcome, result.stage, result.code) {
		return false
	}
	switch result.outcome {
	case pcv3.OutcomeSuccess, pcv3.OutcomeAuthenticatedDegraded,
		pcv3.OutcomeForcePartial, pcv3.OutcomeForceUnverified:
		return true
	default:
		return false
	}
}

// CompletionClass computes one presentation class from authoritative axes.
func (result *Result) CompletionClass() CompletionClass {
	return result.Presentation().CompletionClass()
}

// CompletionClass derives presentation from the complete closed tuple. It is
// never accepted from a caller as a second success flag.
func (presentation Presentation) CompletionClass() CompletionClass {
	if !presentation.valid() {
		return CompletionUnknown
	}
	if presentation.archivePending {
		return CompletionArchivePending
	}
	switch presentation.publicationState {
	case pcv3publication.StatePublicationIndeterminate:
		return CompletionPublicationIndeterminate
	case pcv3publication.StatePublishedDurabilityUncertain:
		return CompletionDurabilityUncertain
	case pcv3publication.StatePublishedDurable:
		if presentation.outcome == pcv3.OutcomeSuccess &&
			presentation.warningCount == 0 {
			return CompletionClean
		}
		return CompletionWarning
	}
	if presentation.outcome == pcv3.OutcomeUnsupportedRoutingPreKDF ||
		(presentation.outcome == pcv3.OutcomeOperationFailed &&
			(presentation.stage == pcv3.StageCredentialPolicy ||
				presentation.stage == pcv3.StageCancellation)) {
		return CompletionRefused
	}
	return CompletionNoOutput
}

func (presentation Presentation) valid() bool {
	if presentation.argCount > maxResultArgs ||
		presentation.warningCount > maxResultWarnings ||
		presentation.diagnostic > DiagnosticResourceUnknown ||
		presentation.forceProvenance > pcv3.ForceProvenanceUnverified ||
		presentation.d1BootstrapProvenance > pcv3.D1BootstrapProvenanceMatching ||
		presentation.detailStage > pcv3.StageDirectorySync ||
		!validSemanticPresentation(
			presentation.outcome, presentation.stage, presentation.code,
		) || !validDiagnosticPresentation(presentation) ||
		!validPresentationWarnings(presentation) ||
		!validPublicationPresentation(presentation) {
		return false
	}
	if !presentation.archivePending {
		return true
	}
	return presentation.outcome == pcv3.OutcomeSuccess &&
		presentation.stage == pcv3.StageNone &&
		presentation.code == pcv3.CodeSuccess &&
		!presentation.publicationAttempted &&
		presentation.publicationState == 0 &&
		presentation.publicationStage == pcv3.StageNone &&
		presentation.publicationCode == 0 &&
		presentation.warningCount == 0
}

func validDiagnosticPresentation(presentation Presentation) bool {
	switch presentation.diagnostic {
	case DiagnosticResourceBusy, DiagnosticResourceInsufficient,
		DiagnosticResourceUnknown:
		return presentation.outcome == pcv3.OutcomeOperationFailed &&
			presentation.stage == pcv3.StageCredentialPolicy &&
			!presentation.publicationAttempted
	default:
		return true
	}
}

func validSemanticPresentation(outcome pcv3.Outcome, stage pcv3.Stage, code pcv3.Code) bool {
	if stage > pcv3.StageDirectorySync ||
		(outcome == pcv3.OutcomeSuccess) != (stage == pcv3.StageNone) {
		return false
	}
	var expected pcv3.Code
	switch outcome {
	case pcv3.OutcomeUnsupportedRoutingPreKDF:
		expected = pcv3.CodeUnsupported
	case pcv3.OutcomeInvalidStructurePreKDF:
		expected = pcv3.CodeInvalidStructure
	case pcv3.OutcomeOperationFailed:
		expected = pcv3.CodeOperationFailed
	case pcv3.OutcomeCredentialsOrDamage:
		expected = pcv3.CodeCredentialsOrDamage
	case pcv3.OutcomeAuthenticatedDegraded:
		expected = pcv3.CodeAuthenticatedDegraded
	case pcv3.OutcomeAmbiguousVolume:
		expected = pcv3.CodeAmbiguousVolume
	case pcv3.OutcomeSuccess:
		expected = pcv3.CodeSuccess
	case pcv3.OutcomeAuthenticationFailed:
		expected = pcv3.CodeAuthenticationFailed
	case pcv3.OutcomeForcePartial:
		expected = pcv3.CodeForcePartial
	case pcv3.OutcomeForceUnverified:
		expected = pcv3.CodeForceUnverified
	default:
		return false
	}
	return code == expected
}

func validPresentationWarnings(presentation Presentation) bool {
	var seen [maxResultWarnings + 1]bool
	for index := uint8(0); index < presentation.warningCount; index++ {
		warning := presentation.warnings[index]
		if warning < WarningAuthenticatedDegraded || warning > WarningCallbackFailure ||
			seen[warning] {
			return false
		}
		seen[warning] = true
	}
	return seen[WarningAuthenticatedDegraded] ==
		(presentation.outcome == pcv3.OutcomeAuthenticatedDegraded) &&
		seen[WarningForcePartial] ==
			(presentation.outcome == pcv3.OutcomeForcePartial) &&
		seen[WarningForceUnverified] ==
			(presentation.outcome == pcv3.OutcomeForceUnverified) &&
		seen[WarningDurabilityUncertain] ==
			(presentation.publicationState == pcv3publication.StatePublishedDurabilityUncertain) &&
		seen[WarningPublicationIndeterminate] ==
			(presentation.publicationState == pcv3publication.StatePublicationIndeterminate)
}

func validPublicationPresentation(presentation Presentation) bool {
	if !presentation.publicationAttempted {
		return presentation.publicationState == 0 &&
			presentation.publicationStage == pcv3.StageNone &&
			presentation.publicationCode == 0
	}
	switch presentation.publicationState {
	case pcv3publication.StateNotPublished:
		return presentation.publicationStage > pcv3.StageNone &&
			presentation.publicationStage <= pcv3.StageDirectorySync &&
			presentation.publicationCode >= pcv3publication.CodeInvalidRequest &&
			presentation.publicationCode <= pcv3publication.CodeAtomicFailed
	case pcv3publication.StatePublishedDurable:
		return presentation.publicationStage == pcv3.StageNone &&
			presentation.publicationCode == pcv3publication.CodePublishedDurable
	case pcv3publication.StatePublishedDurabilityUncertain:
		return presentation.publicationStage == pcv3.StageDirectorySync &&
			presentation.publicationCode == pcv3publication.CodeDurabilityUncertain
	case pcv3publication.StatePublicationIndeterminate:
		return presentation.publicationStage == pcv3.StageOutputPublication &&
			presentation.publicationCode == pcv3publication.CodePublicationIndeterminate
	default:
		return false
	}
}

func (result *Result) hasWarning(warning Warning) bool {
	if result == nil {
		return false
	}
	for index := uint8(0); index < result.warningCount; index++ {
		if result.warnings[index] == warning {
			return true
		}
	}
	return false
}

// Unwrap exposes only the fixed cleanup sentinel; no raw cleanup error is
// stored or formatted.
func (result *Result) Unwrap() error {
	if !result.hasWarning(WarningCleanupIncomplete) {
		return nil
	}
	return pcv3publication.ErrCleanupIncomplete
}

func (result *Result) Error() string {
	if result == nil {
		return "pcv3 operation: unavailable"
	}
	switch result.CompletionClass() {
	case CompletionClean:
		return "pcv3 operation: published durable"
	case CompletionWarning:
		return "pcv3 operation: published with warning"
	case CompletionArchivePending:
		return "pcv3 operation: archive follow-up pending"
	case CompletionDurabilityUncertain:
		return "pcv3 operation: published with uncertain durability"
	case CompletionPublicationIndeterminate:
		return "pcv3 operation: publication indeterminate"
	case CompletionRefused:
		return "pcv3 operation: refused"
	case CompletionNoOutput:
		return "pcv3 operation: no output"
	default:
		return "pcv3 operation: unavailable"
	}
}

func (result *Result) String() string { return result.Error() }

func (result *Result) GoString() string { return result.Error() }

func (result *Result) Format(state fmt.State, verb rune) {
	value := result.Error()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = io.WriteString(state, value)
}
