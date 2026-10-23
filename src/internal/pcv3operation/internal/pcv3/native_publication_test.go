package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"testing"
)

func nativePublicationState(t testing.TB) pcv3publication.State {
	if !nativeDirectorySyncSupported(t, t.TempDir()) {
		return pcv3publication.StatePublishedDurabilityUncertain
	}
	return pcv3publication.StatePublishedDurable
}

func nativeExtractionState(t testing.TB) fileops.UnpackState {
	if !nativeDirectorySyncSupported(t, t.TempDir()) {
		return fileops.UnpackStatePublishedDurabilityUncertain
	}
	return fileops.UnpackStatePublishedDurable
}

// Native publication follows the independently observed fixture storage contract.
func requireNativePublication(t *testing.T, result pcv3publication.Result) {
	t.Helper()
	state, stage, code, outcome := nativePublicationState(t), StageNone, pcv3publication.CodePublishedDurable, OutcomeSuccess
	if !nativeDirectorySyncSupported(t, t.TempDir()) {
		stage, code, outcome = StageDirectorySync, pcv3publication.CodeDurabilityUncertain, OutcomeCommittedDurabilityUncertain
	}
	if result == nil || result.State() != state || result.Stage() != stage || result.Code() != code || result.Outcome() != outcome {
		t.Fatalf("native publication = %v; want %v/%v/%v/%v", result, state, stage, code, outcome)
	}
}

func nativeCleanupMatches(
	t testing.TB,
	result interface {
		CleanupIncomplete() bool
		CleanupDurabilityUncertain() bool
	},
) bool {
	t.Helper()
	return !result.CleanupIncomplete() && result.CleanupDurabilityUncertain() == !nativeDirectorySyncSupported(t, t.TempDir())
}

func nativeCleanupErrorMatches(t testing.TB, err error) bool {
	t.Helper()
	uncertain := !nativeDirectorySyncSupported(t, t.TempDir())
	return (err != nil) == uncertain && !errors.Is(err, pcv3publication.ErrCleanupIncomplete) &&
		errors.Is(err, pcv3publication.ErrCleanupDurabilityUncertain) == uncertain
}
