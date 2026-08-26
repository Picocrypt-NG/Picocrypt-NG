package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"slices"
	"testing"
)

type archiveExtractionFixture struct {
	state             fileops.UnpackState
	cleanupIncomplete bool
}

func (fixture archiveExtractionFixture) State() fileops.UnpackState {
	return fixture.state
}

func (fixture archiveExtractionFixture) CleanupIncomplete() bool {
	return fixture.cleanupIncomplete
}

func TestArchiveFollowUpReturnsCommonTerminalResult(t *testing.T) {
	tests := []struct {
		name           string
		extraction     archiveExtractionFixture
		wantOutcome    pcv3.Outcome
		wantState      pcv3publication.State
		wantStage      pcv3.Stage
		wantCode       pcv3publication.Code
		wantCompletion CompletionClass
		wantWarnings   []Warning
	}{
		{
			name:           "proven rollback is closed no-output",
			extraction:     archiveExtractionFixture{state: fileops.UnpackStateNotPublished},
			wantOutcome:    pcv3.OutcomeOperationFailed,
			wantState:      pcv3publication.StateNotPublished,
			wantStage:      pcv3.StageOutputPublication,
			wantCode:       pcv3publication.CodeAtomicFailed,
			wantCompletion: CompletionNoOutput,
		},
		{
			name:           "directory-synced tree is clean",
			extraction:     archiveExtractionFixture{state: fileops.UnpackStatePublishedDurable},
			wantOutcome:    pcv3.OutcomeSuccess,
			wantState:      pcv3publication.StatePublishedDurable,
			wantStage:      pcv3.StageNone,
			wantCode:       pcv3publication.CodePublishedDurable,
			wantCompletion: CompletionClean,
		},
		{
			name:           "post-commit sync uncertainty stays separate",
			extraction:     archiveExtractionFixture{state: fileops.UnpackStatePublishedDurabilityUncertain},
			wantOutcome:    pcv3.OutcomeSuccess,
			wantState:      pcv3publication.StatePublishedDurabilityUncertain,
			wantStage:      pcv3.StageDirectorySync,
			wantCode:       pcv3publication.CodeDurabilityUncertain,
			wantCompletion: CompletionDurabilityUncertain,
			wantWarnings:   []Warning{WarningDurabilityUncertain},
		},
		{
			name: "unproven rollback stays indeterminate with cleanup warning",
			extraction: archiveExtractionFixture{
				state:             fileops.UnpackStatePublicationIndeterminate,
				cleanupIncomplete: true,
			},
			wantOutcome:    pcv3.OutcomeSuccess,
			wantState:      pcv3publication.StatePublicationIndeterminate,
			wantStage:      pcv3.StageOutputPublication,
			wantCode:       pcv3publication.CodePublicationIndeterminate,
			wantCompletion: CompletionPublicationIndeterminate,
			wantWarnings:   []Warning{WarningPublicationIndeterminate, WarningCleanupIncomplete},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resultFromArchiveExtraction(test.extraction)
			if result.Outcome() != test.wantOutcome ||
				result.PublicationState() != test.wantState ||
				result.PublicationStage() != test.wantStage ||
				result.PublicationCode() != test.wantCode ||
				result.CompletionClass() != test.wantCompletion ||
				!slices.Equal(result.Warnings(), test.wantWarnings) ||
				result.ArchiveFollowUp() != nil {
				t.Fatalf(
					"terminal archive tuple = %v/%v/%v/%v class=%v warnings=%v follow-up=%v; want %v/%v/%v/%v class=%v warnings=%v and no authority",
					result.Outcome(), result.PublicationState(), result.PublicationStage(),
					result.PublicationCode(), result.CompletionClass(), result.Warnings(),
					result.ArchiveFollowUp(), test.wantOutcome, test.wantState,
					test.wantStage, test.wantCode, test.wantCompletion, test.wantWarnings,
				)
			}
		})
	}

	state := &operationTestArchiveState{active: true, cleanupIncomplete: true}
	followUp := &ArchiveFollowUp{state: state}
	closed := followUp.Close()
	if closed.CompletionClass() != CompletionNoOutput || state.active ||
		followUp.state.live() || !slices.Equal(closed.Warnings(), []Warning{WarningCleanupIncomplete}) ||
		!errors.Is(closed, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf("close tuple = class %v active=%v warnings=%v cleanup=%v; want consumed no-output with cleanup warning", closed.CompletionClass(), state.active, closed.Warnings(), errors.Is(closed, pcv3publication.ErrCleanupIncomplete))
	}
	if expired := followUp.Close(); expired == nil || expired.Diagnostic() != DiagnosticInvalidRequest {
		t.Fatalf("second close = %#v; want one-shot expired invalid-request result", expired)
	}
}
