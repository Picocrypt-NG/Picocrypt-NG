package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"slices"
	"testing"
)

type archiveSAFResultFixture struct {
	state             fileops.UnpackState
	attemptedEver     bool
	cleanupIncomplete bool
}

func (fixture archiveSAFResultFixture) State() fileops.UnpackState { return fixture.state }

func (fixture archiveSAFResultFixture) AttemptedEver() bool { return fixture.attemptedEver }

func (fixture archiveSAFResultFixture) CleanupIncomplete() bool {
	return fixture.cleanupIncomplete
}

func TestArchiveSAFResultMapsProviderAttemptAndCleanupTruthIndependently(t *testing.T) {
	tests := []struct {
		name           string
		native         archiveSAFResultFixture
		wantOutcome    pcv3.Outcome
		wantState      pcv3publication.State
		wantStage      pcv3.Stage
		wantCode       pcv3publication.Code
		wantCompletion CompletionClass
		wantWarnings   []Warning
	}{
		{
			name:           "no provider effect and exact cleanup",
			native:         archiveSAFResultFixture{state: fileops.UnpackStateNotPublished},
			wantOutcome:    pcv3.OutcomeOperationFailed,
			wantState:      pcv3publication.StateNotPublished,
			wantStage:      pcv3.StageOutputPublication,
			wantCode:       pcv3publication.CodeAtomicFailed,
			wantCompletion: CompletionNoOutput,
		},
		{
			name: "no provider effect but cleanup uncertain",
			native: archiveSAFResultFixture{
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
		{
			name: "provider effect possible",
			native: archiveSAFResultFixture{
				state:         fileops.UnpackStatePublicationIndeterminate,
				attemptedEver: true,
			},
			wantOutcome:    pcv3.OutcomeSuccess,
			wantState:      pcv3publication.StatePublicationIndeterminate,
			wantStage:      pcv3.StageOutputPublication,
			wantCode:       pcv3publication.CodePublicationIndeterminate,
			wantCompletion: CompletionPublicationIndeterminate,
			wantWarnings:   []Warning{WarningPublicationIndeterminate},
		},
		{
			name: "complete SAF tree never claims durable",
			native: archiveSAFResultFixture{
				state:         fileops.UnpackStatePublishedDurabilityUncertain,
				attemptedEver: true,
			},
			wantOutcome:    pcv3.OutcomeSuccess,
			wantState:      pcv3publication.StatePublishedDurabilityUncertain,
			wantStage:      pcv3.StageDirectorySync,
			wantCode:       pcv3publication.CodeDurabilityUncertain,
			wantCompletion: CompletionDurabilityUncertain,
			wantWarnings:   []Warning{WarningDurabilityUncertain},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resultFromArchiveSAF(test.native)
			if result == nil || !result.PublicationAttempted() ||
				result.Outcome() != test.wantOutcome ||
				result.PublicationState() != test.wantState ||
				result.PublicationStage() != test.wantStage ||
				result.PublicationCode() != test.wantCode ||
				result.CompletionClass() != test.wantCompletion ||
				!slices.Equal(result.Warnings(), test.wantWarnings) ||
				result.ArchiveFollowUp() != nil {
				t.Fatalf(
					"SAF result = %#v tuple=%v/%v/%v/%v class=%v warnings=%v; want %v/%v/%v/%v class=%v warnings=%v",
					result,
					result.Outcome(),
					result.PublicationState(),
					result.PublicationStage(),
					result.PublicationCode(),
					result.CompletionClass(),
					result.Warnings(),
					test.wantOutcome,
					test.wantState,
					test.wantStage,
					test.wantCode,
					test.wantCompletion,
					test.wantWarnings,
				)
			}
		})
	}
}

func TestArchiveFollowUpBeginSAFAlwaysReturnsAClosedVariant(t *testing.T) {
	begin := (*ArchiveFollowUp)(nil).BeginSAF()
	if begin == nil || begin.Kind() != ArchiveSAFBeginExpired ||
		begin.Session() != nil || begin.ReceiptArm() != nil || begin.Result() != nil {
		t.Fatalf("nil follow-up begin = %#v; want expired only", begin)
	}

	begin = (&ArchiveFollowUp{}).BeginSAF()
	if begin == nil || begin.Kind() != ArchiveSAFBeginExpired ||
		begin.Session() != nil || begin.ReceiptArm() != nil || begin.Result() != nil {
		t.Fatalf("zero follow-up begin = %#v; want expired only", begin)
	}
}
