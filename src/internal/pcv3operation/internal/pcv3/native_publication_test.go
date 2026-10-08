package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"runtime"
	"testing"
)

func nativePublicationState() pcv3publication.State {
	if runtime.GOOS == "windows" {
		return pcv3publication.StatePublishedDurabilityUncertain
	}
	return pcv3publication.StatePublishedDurable
}

func nativeExtractionState() fileops.UnpackState {
	if runtime.GOOS == "windows" {
		return fileops.UnpackStatePublishedDurabilityUncertain
	}
	return fileops.UnpackStatePublishedDurable
}

// Windows' documented lack of a directory flush proof must reach the caller.
func requireNativePublication(t *testing.T, result pcv3publication.Result) {
	t.Helper()
	state, stage, code, outcome := nativePublicationState(), StageNone, pcv3publication.CodePublishedDurable, OutcomeSuccess
	if runtime.GOOS == "windows" {
		stage, code, outcome = StageDirectorySync, pcv3publication.CodeDurabilityUncertain, OutcomeCommittedDurabilityUncertain
	}
	if result == nil || result.State() != state || result.Stage() != stage || result.Code() != code || result.Outcome() != outcome {
		t.Fatalf("native publication = %v; want %v/%v/%v/%v", result, state, stage, code, outcome)
	}
}
