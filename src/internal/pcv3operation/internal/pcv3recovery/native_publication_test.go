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

func nativeRecoveryPublicationState(t testing.TB) pcv3publication.State {
	if !nativeRecoveryDirectorySyncSupported(t, t.TempDir()) {
		return pcv3publication.StatePublishedDurabilityUncertain
	}
	return pcv3publication.StatePublishedDurable
}

func nativeRecoveryExtractionState(t testing.TB) fileops.UnpackState {
	if !nativeRecoveryDirectorySyncSupported(t, t.TempDir()) {
		return fileops.UnpackStatePublishedDurabilityUncertain
	}
	return fileops.UnpackStatePublishedDurable
}

func requireNativeRecoveryPublication(t *testing.T, result *Result) {
	t.Helper()
	state, stage, code := nativeRecoveryPublicationState(t), pcv3.StageNone, pcv3publication.CodePublishedDurable
	if state == pcv3publication.StatePublishedDurabilityUncertain {
		stage, code = pcv3.StageDirectorySync, pcv3publication.CodeDurabilityUncertain
	}
	if result == nil || !result.PublicationAttempted() || result.PublicationState() != state ||
		result.PublicationStage() != stage || result.PublicationCode() != code || result.cleanupIncomplete ||
		result.cleanupDurabilityUncertain != (state == pcv3publication.StatePublishedDurabilityUncertain) {
		t.Fatalf("native recovery publication = %v; want %v/%v/%v with exact cleanup", result, state, stage, code)
	}
}

func requireNativeRecoveryCleanup(t testing.TB, directory string, err error) {
	t.Helper()
	if nativeRecoveryDirectorySyncSupported(t, directory) {
		if err != nil {
			t.Fatalf("durable native recovery cleanup = %v; want nil", err)
		}
		return
	}
	if !errors.Is(err, pcv3publication.ErrCleanupDurabilityUncertain) || errors.Is(err, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf("unsupported native recovery cleanup = %v; want only deletion durability uncertainty", err)
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
