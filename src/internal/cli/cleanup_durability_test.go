package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"strings"
	"testing"
)

func TestPCV3CLIDistinguishesCleanupDurabilityAndReturnsWarningExit(t *testing.T) {
	result := &pcv3CLIFixedResult{
		outcome: pcv3operation.OutcomeSuccess, code: pcv3operation.CodeSuccess,
		publicationAttempted: true, publicationState: pcv3publication.StatePublishedDurable,
		publicationCode: pcv3publication.CodePublishedDurable,
		warnings:        []pcv3operation.Warning{pcv3operation.WarningCleanupDurabilityUncertain},
		class:           pcv3operation.CompletionWarning,
	}
	var output strings.Builder
	if code := renderPCV3CLIResult(&output, result); code != ExitPCV3Warning {
		t.Fatalf("cleanup durability exit = %d; want nonzero warning exit", code)
	}
	const warning = "Warning: The app could not confirm that deleted temporary files will stay deleted after a power loss. Keep the source files."
	if !strings.Contains(output.String(), warning) || strings.Contains(output.String(), "cleanup of operation-owned temporary files could not be confirmed") {
		t.Fatalf("cleanup durability was lost or conflated with live residue: %q", output.String())
	}
}
