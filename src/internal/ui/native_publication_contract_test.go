package ui

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"runtime"
	"slices"
	"testing"
)

const (
	nativePCV3DurabilityWarningText = "Output durability was not confirmed. Keep every source and the destination."
	nativePCV3UncertainBody         = "The destination may contain the output, but filesystem durability could not be confirmed. Keep every source and the destination. Do not retry, replace, delete, or clean up this operation."
)

// Windows commits the file but has no supported directory durability barrier.
// A warning must never be treated as clean completion or deletion authority.
func requireNativePCV3Publication(t *testing.T, result *pcv3operation.Result) {
	t.Helper()
	class := pcv3operation.CompletionClean
	state := pcv3publication.StatePublishedDurable
	stage := pcv3operation.StageNone
	code := pcv3publication.CodePublishedDurable
	var warnings []pcv3operation.Warning
	if runtime.GOOS == "windows" {
		class = pcv3operation.CompletionDurabilityUncertain
		state = pcv3publication.StatePublishedDurabilityUncertain
		stage = pcv3operation.StageDirectorySync
		code = pcv3publication.CodeDurabilityUncertain
		warnings = []pcv3operation.Warning{pcv3operation.WarningDurabilityUncertain}
	}
	if result == nil || result.Outcome() != pcv3operation.OutcomeSuccess ||
		result.Stage() != pcv3operation.StageNone || result.Code() != pcv3operation.CodeSuccess ||
		result.Diagnostic() != pcv3operation.DiagnosticNone || result.CompletionClass() != class ||
		!result.PublicationAttempted() || result.PublicationState() != state ||
		result.PublicationStage() != stage || result.PublicationCode() != code ||
		!slices.Equal(result.Warnings(), warnings) || result.ArchiveFollowUp() != nil || result.OutputFollowUp() != nil {
		t.Fatalf("native PCV3 publication = %v; want exact %v/%v/%v warnings %v", result, class, state, code, warnings)
	}
	if runtime.GOOS == "windows" && result.SourceDeletionAllowed() {
		t.Fatal("uncertain native publication granted source deletion")
	}
}

func requireNativePCV3Operation(t *testing.T, result operationResult) {
	t.Helper()
	requireNativePCV3Publication(t, result.pcv3)
	if runtime.GOOS == "windows" {
		if result.completed || !errors.Is(result.err, result.pcv3) {
			t.Fatalf("uncertain native operation lost its closed error: %+v", result)
		}
	} else if !result.completed || result.err != nil {
		t.Fatalf("durable native operation failed: %+v", result)
	}
}

func requireNativePCV3EncryptionError(t *testing.T, err error) {
	t.Helper()
	if runtime.GOOS == "windows" {
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
	if runtime.GOOS == "windows" {
		t.Skip("native Windows cannot prove directory durability and never grants source-deletion authority; native preservation is covered separately")
	}
}
