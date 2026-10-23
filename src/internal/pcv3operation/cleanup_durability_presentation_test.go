package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"testing"
)

func TestCleanupDurabilityWarningPreservesPublicationAndDeniesSourceDeletion(t *testing.T) {
	result := &Result{
		outcome:                pcv3.OutcomeSuccess,
		code:                   pcv3.CodeSuccess,
		publicationAttempted:   true,
		publicationState:       pcv3publication.StatePublishedDurable,
		publicationCode:        pcv3publication.CodePublishedDurable,
		writeOutput:            true,
		writeLifecycleComplete: true,
	}
	if !result.SourceDeletionAllowed() {
		t.Fatal("fixture must establish deletion eligibility before the warning")
	}
	// Warning 8 is append-only: existing bridge warning values must not move.
	result.appendWarning(Warning(8))
	if result.CompletionClass() != CompletionWarning {
		t.Fatalf("cleanup durability completion = %v; want warning", result.CompletionClass())
	}
	if result.SourceDeletionAllowed() {
		t.Fatal("unconfirmed cleanup durability allowed source deletion")
	}
	if result.PublicationState() != pcv3publication.StatePublishedDurable {
		t.Fatal("cleanup uncertainty changed the separately proven publication")
	}
	copy, err := NewPresentation(PresentationSpec{
		Outcome:              pcv3.OutcomeSuccess,
		Code:                 pcv3.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublishedDurable,
		PublicationCode:      pcv3publication.CodePublishedDurable,
		Warnings:             result.Warnings(),
	})
	if err != nil || copy.CompletionClass() != CompletionWarning {
		t.Fatalf("closed frontend presentation lost cleanup durability: %v/%v", copy.CompletionClass(), err)
	}
}
