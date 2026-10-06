package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3recovery"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"slices"
	"testing"
)

func TestPresentationClassifiesClosedResultsWithoutAuthority(t *testing.T) {
	tests := []struct {
		name string
		spec PresentationSpec
		want CompletionClass
	}{
		{
			name: "pre-KDF routing refusal",
			spec: PresentationSpec{
				Outcome:    pcv3.OutcomeUnsupportedRoutingPreKDF,
				Stage:      pcv3.StageRouting,
				Code:       pcv3.CodeUnsupported,
				Diagnostic: DiagnosticRoutingRefusal,
			},
			want: CompletionRefused,
		},
		{
			name: "closed failure without output",
			spec: PresentationSpec{
				Outcome: pcv3.OutcomeAuthenticationFailed,
				Stage:   pcv3.StageFinalRecord,
				Code:    pcv3.CodeAuthenticationFailed,
			},
			want: CompletionNoOutput,
		},
		{
			name: "busy operation is a typed resource refusal",
			spec: PresentationSpec{
				Outcome:    pcv3.OutcomeOperationFailed,
				Stage:      pcv3.StageCredentialPolicy,
				Code:       pcv3.CodeOperationFailed,
				Diagnostic: DiagnosticResourceBusy,
			},
			want: CompletionRefused,
		},
		{
			name: "insufficient resources are a typed refusal",
			spec: PresentationSpec{
				Outcome:    pcv3.OutcomeOperationFailed,
				Stage:      pcv3.StageCredentialPolicy,
				Code:       pcv3.CodeOperationFailed,
				Diagnostic: DiagnosticResourceInsufficient,
			},
			want: CompletionRefused,
		},
		{
			name: "unknown resources are a typed refusal",
			spec: PresentationSpec{
				Outcome:    pcv3.OutcomeOperationFailed,
				Stage:      pcv3.StageCredentialPolicy,
				Code:       pcv3.CodeOperationFailed,
				Diagnostic: DiagnosticResourceUnknown,
			},
			want: CompletionRefused,
		},
		{
			name: "durable authenticated output",
			spec: PresentationSpec{
				Outcome:              pcv3.OutcomeSuccess,
				Stage:                pcv3.StageNone,
				Code:                 pcv3.CodeSuccess,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurable,
				PublicationStage:     pcv3.StageNone,
				PublicationCode:      pcv3publication.CodePublishedDurable,
			},
			want: CompletionClean,
		},
		{
			name: "durable degraded output",
			spec: PresentationSpec{
				Outcome:              pcv3.OutcomeAuthenticatedDegraded,
				Stage:                pcv3.StageMetadata,
				Code:                 pcv3.CodeAuthenticatedDegraded,
				ForceProvenance:      pcv3.ForceProvenanceVerified,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurable,
				PublicationStage:     pcv3.StageNone,
				PublicationCode:      pcv3publication.CodePublishedDurable,
			},
			want: CompletionWarning,
		},
		{
			name: "authenticated archive awaiting an explicit decision",
			spec: PresentationSpec{
				Outcome:        pcv3.OutcomeSuccess,
				Stage:          pcv3.StageNone,
				Code:           pcv3.CodeSuccess,
				ArchivePending: true,
			},
			want: CompletionArchivePending,
		},
		{
			name: "committed output with uncertain durability",
			spec: PresentationSpec{
				Outcome:              pcv3.OutcomeSuccess,
				Stage:                pcv3.StageNone,
				Code:                 pcv3.CodeSuccess,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurabilityUncertain,
				PublicationStage:     pcv3.StageDirectorySync,
				PublicationCode:      pcv3publication.CodeDurabilityUncertain,
			},
			want: CompletionDurabilityUncertain,
		},
		{
			name: "indeterminate publication",
			spec: PresentationSpec{
				Outcome:              pcv3.OutcomeSuccess,
				Stage:                pcv3.StageNone,
				Code:                 pcv3.CodeSuccess,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublicationIndeterminate,
				PublicationStage:     pcv3.StageOutputPublication,
				PublicationCode:      pcv3publication.CodePublicationIndeterminate,
			},
			want: CompletionPublicationIndeterminate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			presentation, err := NewPresentation(test.spec)
			if err != nil {
				t.Fatalf("NewPresentation() error = %v", err)
			}

			result := newResult(resultData{
				outcome:               test.spec.Outcome,
				stage:                 test.spec.Stage,
				code:                  test.spec.Code,
				forceProvenance:       test.spec.ForceProvenance,
				d1BootstrapProvenance: test.spec.D1BootstrapProvenance,
				detailStage:           test.spec.DetailStage,
				publicationAttempted:  test.spec.PublicationAttempted,
				publicationState:      test.spec.PublicationState,
				publicationStage:      test.spec.PublicationStage,
				publicationCode:       test.spec.PublicationCode,
				args:                  test.spec.Args,
				warnings:              test.spec.Warnings,
				diagnostic:            test.spec.Diagnostic,
			})
			if test.spec.ArchivePending {
				result.archiveFollowUp = &ArchiveFollowUp{
					state: &operationTestArchiveState{active: true},
				}
			}
			projected := result.Presentation()

			if presentation.CompletionClass() != test.want ||
				projected.CompletionClass() != test.want ||
				result.CompletionClass() != test.want {
				t.Fatalf(
					"completion = constructor %v, projection %v, result %v; want %v",
					presentation.CompletionClass(), projected.CompletionClass(),
					result.CompletionClass(), test.want,
				)
			}
			if presentation.Outcome() != result.Outcome() ||
				presentation.PublicationState() != result.PublicationState() ||
				presentation.ArchivePending() != test.spec.ArchivePending ||
				!slices.Equal(presentation.Warnings(), result.Warnings()) {
				t.Fatalf(
					"presentation axes = %v/%v/pending=%v warnings=%v; result = %v/%v warnings=%v",
					presentation.Outcome(), presentation.PublicationState(),
					presentation.ArchivePending(), presentation.Warnings(),
					result.Outcome(), result.PublicationState(), result.Warnings(),
				)
			}

			type archiveAuthority interface {
				ArchiveFollowUp() *ArchiveFollowUp
			}
			if _, grantsAuthority := any(presentation).(archiveAuthority); grantsAuthority {
				t.Fatal("authority-free presentation grants an archive follow-up")
			}
		})
	}
}

func TestNewPresentationRejectsMalformedClosedTuples(t *testing.T) {
	tests := []struct {
		name   string
		spec   PresentationSpec
		result resultData
	}{
		{
			name: "state without publication attempt",
			spec: PresentationSpec{
				Outcome:          pcv3.OutcomeSuccess,
				Stage:            pcv3.StageNone,
				Code:             pcv3.CodeSuccess,
				PublicationState: pcv3publication.StateNotPublished,
				PublicationStage: pcv3.StageOutputPublication,
				PublicationCode:  pcv3publication.CodeAtomicFailed,
			},
			result: resultData{
				outcome:          pcv3.OutcomeSuccess,
				stage:            pcv3.StageNone,
				code:             pcv3.CodeSuccess,
				publicationState: pcv3publication.StateNotPublished,
				publicationStage: pcv3.StageOutputPublication,
				publicationCode:  pcv3publication.CodeAtomicFailed,
			},
		},
		{
			name: "attempt without state",
			spec: PresentationSpec{
				Outcome:              pcv3.OutcomeSuccess,
				Stage:                pcv3.StageNone,
				Code:                 pcv3.CodeSuccess,
				PublicationAttempted: true,
			},
			result: resultData{
				outcome:              pcv3.OutcomeSuccess,
				stage:                pcv3.StageNone,
				code:                 pcv3.CodeSuccess,
				publicationAttempted: true,
			},
		},
		{
			name: "semantic code contradicts outcome",
			spec: PresentationSpec{
				Outcome: pcv3.OutcomeSuccess,
				Stage:   pcv3.StageNone,
				Code:    pcv3.CodeOperationFailed,
			},
			result: resultData{
				outcome: pcv3.OutcomeSuccess,
				stage:   pcv3.StageNone,
				code:    pcv3.CodeOperationFailed,
			},
		},
		{
			name: "publication code contradicts durable state",
			spec: PresentationSpec{
				Outcome:              pcv3.OutcomeSuccess,
				Stage:                pcv3.StageNone,
				Code:                 pcv3.CodeSuccess,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurable,
				PublicationStage:     pcv3.StageNone,
				PublicationCode:      pcv3publication.CodeAtomicFailed,
			},
			result: resultData{
				outcome:              pcv3.OutcomeSuccess,
				stage:                pcv3.StageNone,
				code:                 pcv3.CodeSuccess,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				publicationStage:     pcv3.StageNone,
				publicationCode:      pcv3publication.CodeAtomicFailed,
			},
		},
		{
			name: "pending archive carries a warning",
			spec: PresentationSpec{
				Outcome:        pcv3.OutcomeSuccess,
				Stage:          pcv3.StageNone,
				Code:           pcv3.CodeSuccess,
				Warnings:       []Warning{WarningCleanupIncomplete},
				ArchivePending: true,
			},
			result: resultData{
				outcome:  pcv3.OutcomeSuccess,
				stage:    pcv3.StageNone,
				code:     pcv3.CodeSuccess,
				warnings: []Warning{WarningCleanupIncomplete},
			},
		},
		{
			name: "success cannot claim a Force warning",
			spec: PresentationSpec{
				Outcome:  pcv3.OutcomeSuccess,
				Stage:    pcv3.StageNone,
				Code:     pcv3.CodeSuccess,
				Warnings: []Warning{WarningForceUnverified},
			},
			result: resultData{
				outcome:  pcv3.OutcomeSuccess,
				stage:    pcv3.StageNone,
				code:     pcv3.CodeSuccess,
				warnings: []Warning{WarningForceUnverified},
			},
		},
		{
			name: "resource diagnostic cannot decorate success",
			spec: PresentationSpec{
				Outcome:    pcv3.OutcomeSuccess,
				Stage:      pcv3.StageNone,
				Code:       pcv3.CodeSuccess,
				Diagnostic: DiagnosticResourceUnknown,
			},
			result: resultData{
				outcome:    pcv3.OutcomeSuccess,
				stage:      pcv3.StageNone,
				code:       pcv3.CodeSuccess,
				diagnostic: DiagnosticResourceUnknown,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewPresentation(test.spec); !errors.Is(err, ErrInvalidPresentation) {
				t.Fatalf("NewPresentation() error = %v; want ErrInvalidPresentation", err)
			}
			result := newResult(test.result)
			if test.spec.ArchivePending {
				result.archiveFollowUp = &ArchiveFollowUp{
					state: &operationTestArchiveState{active: true},
				}
			}
			if got := result.CompletionClass(); got != CompletionUnknown {
				t.Fatalf("malformed result completion = %v; want CompletionUnknown", got)
			}
		})
	}
}

func TestPresentationDefensivelyOwnsBoundedSlices(t *testing.T) {
	args := []uint64{17, 29}
	warnings := []Warning{WarningCleanupIncomplete}
	presentation, err := NewPresentation(PresentationSpec{
		Outcome:              pcv3.OutcomeSuccess,
		Stage:                pcv3.StageNone,
		Code:                 pcv3.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublishedDurable,
		PublicationStage:     pcv3.StageNone,
		PublicationCode:      pcv3publication.CodePublishedDurable,
		Args:                 args,
		Warnings:             warnings,
	})
	if err != nil {
		t.Fatalf("NewPresentation() error = %v", err)
	}

	args[0] = 0
	warnings[0] = WarningForceUnverified
	returnedArgs := presentation.Args()
	returnedWarnings := presentation.Warnings()
	returnedArgs[1] = 0
	returnedWarnings[0] = WarningForceUnverified

	if got := presentation.Args(); !slices.Equal(got, []uint64{17, 29}) {
		t.Fatalf("owned args = %v; want [17 29] after caller mutations", got)
	}
	if got := presentation.Warnings(); !slices.Equal(got, []Warning{WarningCleanupIncomplete}) {
		t.Fatalf("owned warnings = %v; want cleanup-incomplete after caller mutations", got)
	}
}

func TestArtifactInspectionRequiresExactDurableForceTuple(t *testing.T) {
	inspection := new(pcv3recovery.ArtifactInspection)
	tests := []struct {
		name   string
		result *Result
		want   *pcv3recovery.ArtifactInspection
	}{
		{
			name: "durable partial Force result grants inspection",
			result: &Result{
				outcome:              pcv3.OutcomeForcePartial,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				artifactInspection:   inspection,
			},
			want: inspection,
		},
		{
			name: "durable unverified Force result grants inspection",
			result: &Result{
				outcome:              pcv3.OutcomeForceUnverified,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				artifactInspection:   inspection,
			},
			want: inspection,
		},
		{
			name: "non-Force warning result grants no inspection",
			result: &Result{
				outcome:              pcv3.OutcomeAuthenticatedDegraded,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				artifactInspection:   inspection,
			},
		},
		{
			name: "uncertain Force publication grants no inspection",
			result: &Result{
				outcome:              pcv3.OutcomeForcePartial,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurabilityUncertain,
				artifactInspection:   inspection,
			},
		},
		{
			name: "unattempted Force publication grants no inspection",
			result: &Result{
				outcome:            pcv3.OutcomeForcePartial,
				publicationState:   pcv3publication.StatePublishedDurable,
				artifactInspection: inspection,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.result.ArtifactInspection(); got != test.want {
				t.Fatalf("ArtifactInspection() = %p; want %p", got, test.want)
			}
		})
	}
}
