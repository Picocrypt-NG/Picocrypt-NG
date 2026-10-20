package pcv3recovery

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func nativeRecoveryPublicationState() pcv3publication.State {
	if runtime.GOOS == "windows" {
		return pcv3publication.StatePublishedDurabilityUncertain
	}
	return pcv3publication.StatePublishedDurable
}

func nativeRecoveryExtractionState() fileops.UnpackState {
	if runtime.GOOS == "windows" {
		return fileops.UnpackStatePublishedDurabilityUncertain
	}
	return fileops.UnpackStatePublishedDurable
}

func requireNativeRecoveryPublication(t *testing.T, result *Result) {
	t.Helper()
	state, stage, code := nativeRecoveryPublicationState(), pcv3.StageNone, pcv3publication.CodePublishedDurable
	if runtime.GOOS == "windows" {
		stage, code = pcv3.StageDirectorySync, pcv3publication.CodeDurabilityUncertain
	}
	if result == nil || !result.PublicationAttempted() || result.PublicationState() != state ||
		result.PublicationStage() != stage || result.PublicationCode() != code || result.cleanupIncomplete != (runtime.GOOS == "windows") {
		t.Fatalf("native recovery publication = %v; want %v/%v/%v with exact cleanup", result, state, stage, code)
	}
}

func recoveryFileModeMatches(info os.FileInfo, want os.FileMode) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	// Windows mode bits represent writability, not POSIX permissions or ACLs.
	if runtime.GOOS == "windows" {
		return info.Mode().Perm()&0o200 == want.Perm()&0o200
	}
	return info.Mode().Perm() == want.Perm()
}

// Open through os.Root so Windows observers share the live DELETE-capable owner.
func openRecoveryCustodyFile(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	volumeRoot := filepath.VolumeName(absolute) + string(filepath.Separator)
	relative, err := filepath.Rel(volumeRoot, absolute)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(volumeRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(relative)
}

func readRecoveryCustodyDirectory(path string) ([]os.DirEntry, error) {
	file, err := openRecoveryCustodyFile(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := file.ReadDir(-1)
	return entries, errors.Join(readErr, file.Close())
}
