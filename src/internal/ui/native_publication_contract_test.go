package ui

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"slices"
	"testing"
)

const (
	nativePCV3DurabilityWarningText  = "Output durability was not confirmed. Keep every source and the destination."
	nativePCV3UncertainBody          = "The destination may contain the output, but filesystem durability could not be confirmed. Keep every source and the destination. Do not retry, replace, delete, or clean up this operation."
	nativePCV3CleanupWarningTitle    = "Cleanup could not be confirmed"
	nativePCV3CleanupWarningText     = "The application could not confirm removal of all temporary files created by this operation. Keep the source files and do not delete files based on this result."
	nativePCV3CleanupDurabilityTitle = "Cleanup may not persist after a power loss"
	nativePCV3CleanupDurabilityText  = "The app could not confirm that deleted temporary files will stay deleted after a power loss. Keep the source files."
	nativePCV3CleanupDurabilityClose = "Close cleanup durability warning"
)

// These native GUI fixtures publish in testing.T.TempDir storage.
func requireNativePCV3Publication(t *testing.T, result *pcv3operation.Result) {
	t.Helper()
	class := pcv3operation.CompletionClean
	state := pcv3publication.StatePublishedDurable
	stage := pcv3operation.StageNone
	code := pcv3publication.CodePublishedDurable
	var warnings []pcv3operation.Warning
	if !nativeUIDirectorySyncSupported(t, t.TempDir()) {
		class = pcv3operation.CompletionDurabilityUncertain
		state = pcv3publication.StatePublishedDurabilityUncertain
		stage = pcv3operation.StageDirectorySync
		code = pcv3publication.CodeDurabilityUncertain
		warnings = []pcv3operation.Warning{pcv3operation.WarningDurabilityUncertain, pcv3operation.WarningCleanupDurabilityUncertain}
	}
	if result == nil || result.Outcome() != pcv3operation.OutcomeSuccess ||
		result.Stage() != pcv3operation.StageNone || result.Code() != pcv3operation.CodeSuccess ||
		result.Diagnostic() != pcv3operation.DiagnosticNone || result.CompletionClass() != class ||
		!result.PublicationAttempted() || result.PublicationState() != state ||
		result.PublicationStage() != stage || result.PublicationCode() != code ||
		!slices.Equal(result.Warnings(), warnings) || result.ArchiveFollowUp() != nil || result.OutputFollowUp() != nil {
		if result != nil {
			t.Logf("closed failure tuple: outcome=%v stage=%v code=%v diagnostic=%v completion=%v publicationAttempted=%v publicationState=%v publicationStage=%v publicationCode=%v", result.Outcome(), result.Stage(), result.Code(), result.Diagnostic(), result.CompletionClass(), result.PublicationAttempted(), result.PublicationState(), result.PublicationStage(), result.PublicationCode())
		}
		t.Fatalf("native PCV3 publication = %v; want exact %v/%v/%v warnings %v", result, class, state, code, warnings)
	}
	if class != pcv3operation.CompletionClean && result.SourceDeletionAllowed() {
		t.Fatal("uncertain native publication granted source deletion")
	}
}

func requireNativePCV3Operation(t *testing.T, result operationResult) {
	t.Helper()
	requireNativePCV3Publication(t, result.pcv3)
	if result.pcv3.CompletionClass() != pcv3operation.CompletionClean {
		if result.completed || !errors.Is(result.err, result.pcv3) {
			t.Fatalf("uncertain native operation lost its closed error: %+v", result)
		}
	} else if !result.completed || result.err != nil {
		t.Fatalf("durable native operation failed: %+v", result)
	}
}

func requireNativePCV3EncryptionError(t *testing.T, err error) {
	t.Helper()
	if !nativeUIDirectorySyncSupported(t, t.TempDir()) {
		var result *pcv3operation.Result
		if !errors.As(err, &result) {
			t.Fatalf("native writer error = %v; want closed durability warning", err)
		}
		requireNativePCV3Publication(t, result)
	} else if err != nil {
		t.Fatal(err)
	}
}

func requireNativePCV3DeletionSupport(t *testing.T) {
	t.Helper()
	if !nativeUIDirectorySyncSupported(t, t.TempDir()) {
		t.Skip("fixture storage cannot prove directory durability; native source preservation is covered separately")
	}
}
