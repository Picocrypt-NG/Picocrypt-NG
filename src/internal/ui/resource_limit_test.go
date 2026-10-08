package ui

import (
	"Picocrypt-NG/internal/pcv3operation"
	"testing"
)

func TestResourceBudgetRefusalUsesResourceNotice(t *testing.T) {
	resetLocalizationForTest(t)
	if err := loadTranslations(); err != nil {
		t.Fatal(err)
	}
	presentation, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome: pcv3operation.OutcomeOperationFailed,
		Stage:   pcv3operation.StageResourceBudget, Code: pcv3operation.CodeOperationFailed,
		Diagnostic: pcv3operation.DiagnosticResourceLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	copy := pcv3OutcomeCopy(presentation)
	if copy.Title != "Resource limit reached" || copy.Action != "Close resource notice" {
		t.Fatalf("resource refusal rendered as a different failure: %+v", copy)
	}
}
