package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
	"slices"
	"testing"
)

func TestPCV3MobileCleanupDurabilityWarningKeepsItsWireIdentity(t *testing.T) {
	warning := pcv3operation.WarningCleanupDurabilityUncertain
	if uint8(warning) != 8 || pcv3WarningCode(warning) != "cleanup-durability-uncertain" {
		t.Fatalf("cleanup durability warning = %d/%q; want appended wire value 8 and distinct code", warning, pcv3WarningCode(warning))
	}
}

func TestPCV3MobileArchiveFailurePreservesBothCleanupFacts(t *testing.T) {
	warnings := []pcv3operation.Warning{
		pcv3operation.WarningCleanupIncomplete,
		pcv3operation.WarningCleanupDurabilityUncertain,
	}
	closed, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome:    pcv3operation.OutcomeOperationFailed,
		Stage:      pcv3operation.StageOutputPublication,
		Code:       pcv3operation.CodeOperationFailed,
		Diagnostic: pcv3operation.DiagnosticCoreFailure,
		Warnings:   warnings,
	})
	if err != nil {
		t.Fatal(err)
	}
	projected := archiveFailurePCV3Presentation(closed)
	if !slices.Equal(projected.Warnings(), warnings) {
		t.Fatalf("archive failure warnings = %v; want both cleanup facts %v", projected.Warnings(), warnings)
	}
	snapshot := newPCV3Snapshot(projected, pcv3operation.Status{}, "op_cleanup", "", "")
	if snapshot.WarningCount() != 2 || snapshot.WarningAt(0) != "cleanup-incomplete" ||
		snapshot.WarningAt(1) != "cleanup-durability-uncertain" {
		t.Fatalf("mobile snapshot warnings = %q/%q (count %d); want distinct live and crash-durability cleanup states", snapshot.WarningAt(0), snapshot.WarningAt(1), snapshot.WarningCount())
	}
}

func TestPCV3MobileOutputArchiveFailureCombinesCleanupFacts(t *testing.T) {
	for _, test := range []struct {
		name    string
		archive pcv3operation.Warning
		output  pcv3OutputActionResult
	}{
		{"archive-removal-output-durability", pcv3operation.WarningCleanupIncomplete, pcv3OutputActionResult{cleanupDurabilityUncertain: true}},
		{"archive-durability-output-removal", pcv3operation.WarningCleanupDurabilityUncertain, pcv3OutputActionResult{cleanupIncomplete: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			closed := fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure, test.archive)
			got := outputArchiveFailurePCV3Presentation(closed, test.output)
			want := []pcv3operation.Warning{
				pcv3operation.WarningCleanupIncomplete,
				pcv3operation.WarningCleanupDurabilityUncertain,
			}
			if !slices.Equal(got.Warnings(), want) {
				t.Fatalf("combined archive/output warnings = %v; want distinct facts %v", got.Warnings(), want)
			}
		})
	}
}
