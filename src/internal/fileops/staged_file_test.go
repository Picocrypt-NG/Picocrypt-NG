package fileops

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func windowsPreventedOpenHandleRename(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	// Windows can report either access denied or sharing violation when an
	// open file or directory handle prevents pathname replacement.
	return errors.Is(err, syscall.Errno(5)) || errors.Is(err, syscall.Errno(32))
}

func TestStagedFileKeepsTargetUntouchedUntilCommit(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "output.pcv")
	original := []byte("existing destination")
	replacement := []byte("complete staged replacement")
	if err := os.WriteFile(target, original, 0o640); err != nil {
		t.Fatalf("write existing target: %v", err)
	}

	stage, err := CreateSiblingTemp(target)
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	defer stage.Cleanup()
	if _, err := stage.File().Write(replacement); err != nil {
		t.Fatalf("write stage: %v", err)
	}

	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target before Commit: %v", err)
	}
	if !bytes.Equal(before, original) {
		t.Fatalf("target changed before Commit: got %q, want %q", before, original)
	}

	if err := stage.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target after Commit: %v", err)
	}
	if !bytes.Equal(after, replacement) {
		t.Fatalf("committed target = %q, want %q", after, replacement)
	}
}

func TestStagedFileRejectsChangedOutputDirectoryAndCleansOwnedStage(t *testing.T) {
	dir := t.TempDir()
	originalDir := filepath.Join(dir, "original")
	replacementDir := filepath.Join(dir, "replacement")
	if err := os.Mkdir(originalDir, 0o700); err != nil {
		t.Fatalf("create original directory: %v", err)
	}
	if err := os.Mkdir(replacementDir, 0o700); err != nil {
		t.Fatalf("create replacement directory: %v", err)
	}
	outputDir := filepath.Join(dir, "output-link")
	if err := os.Symlink(originalDir, outputDir); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	target := filepath.Join(outputDir, "output.pcv")
	stage, err := CreateSiblingTemp(target)
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	if _, err := stage.File().Write([]byte("owned staged bytes")); err != nil {
		stage.Cleanup()
		t.Fatalf("write stage: %v", err)
	}

	if err := os.Remove(outputDir); err != nil {
		stage.Cleanup()
		t.Fatalf("remove original directory link: %v", err)
	}
	if err := os.Symlink(replacementDir, outputDir); err != nil {
		stage.Cleanup()
		t.Fatalf("replace directory link: %v", err)
	}

	err = stage.Commit()
	if err == nil || !strings.Contains(err.Error(), "output directory changed") {
		stage.Cleanup()
		t.Fatalf("Commit error = %v, want changed-directory refusal", err)
	}
	stage.Cleanup()

	for _, path := range []string{
		filepath.Join(originalDir, "output.pcv"),
		filepath.Join(replacementDir, "output.pcv"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected published output %q: %v", path, err)
		}
	}
	entries, err := os.ReadDir(originalDir)
	if err != nil {
		t.Fatalf("read original output directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-") {
			t.Fatalf("owned stage leaked after directory swap: %s", entry.Name())
		}
	}
}

func TestStagedFileRefusesStageReplacementAndPreservesForeignFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "output.pcv")
	targetBytes := []byte("existing target")
	if err := os.WriteFile(target, targetBytes, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	stage, err := CreateSiblingTemp(target)
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	if _, err := stage.File().Write([]byte("operation-owned stage")); err != nil {
		stage.Cleanup()
		t.Fatalf("write stage: %v", err)
	}
	stagePath := stage.Path()
	if err := os.Remove(stagePath); err != nil {
		stage.Cleanup()
		t.Skipf("platform prevents replacing an open staged file: %v", err)
	}
	foreignBytes := []byte("foreign replacement at the random stage path")
	if err := os.WriteFile(stagePath, foreignBytes, 0o640); err != nil {
		stage.Cleanup()
		t.Fatalf("write foreign stage replacement: %v", err)
	}

	err = stage.Commit()
	if err == nil || !strings.Contains(err.Error(), "staged output path changed") {
		stage.Cleanup()
		t.Fatalf("Commit error = %v, want changed-stage refusal", err)
	}
	stage.Cleanup()

	gotTarget, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read preserved target: %v", err)
	}
	if !bytes.Equal(gotTarget, targetBytes) {
		t.Fatalf("target changed: got %q, want %q", gotTarget, targetBytes)
	}
	gotForeign, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatalf("read foreign stage replacement: %v", err)
	}
	if !bytes.Equal(gotForeign, foreignBytes) {
		t.Fatalf("foreign stage replacement = %q, want %q", gotForeign, foreignBytes)
	}
}

func TestStagedFileReservesAndRemovesTargetDirectoryThroughPinnedParent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "recovered")
	stage, err := CreateSiblingTemp(target)
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	defer stage.Cleanup()

	info, err := stage.ReserveTargetDirectory()
	if err != nil {
		t.Fatalf("ReserveTargetDirectory: %v", err)
	}
	current, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("inspect reserved directory: %v", err)
	}
	if !current.IsDir() || !os.SameFile(info, current) {
		t.Fatal("reserved target does not have the identity returned by ReserveTargetDirectory")
	}
	if runtime.GOOS != "windows" && current.Mode().Perm() != 0o700 {
		t.Fatalf("reserved directory mode = %04o, want 0700", current.Mode().Perm())
	}

	if err := stage.RemoveTargetDirectory(info); err != nil {
		t.Fatalf("RemoveTargetDirectory: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved directory still exists after removal: %v", err)
	}
}

func TestStagedFileRejectsTargetDirectoryReservationAfterParentSwap(t *testing.T) {
	dir := t.TempDir()
	originalDir := filepath.Join(dir, "original")
	replacementDir := filepath.Join(dir, "replacement")
	for _, path := range []string{originalDir, replacementDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create parent directory %s: %v", path, err)
		}
	}
	outputDir := filepath.Join(dir, "output-link")
	if err := os.Symlink(originalDir, outputDir); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	target := filepath.Join(outputDir, "recovered")
	stage, err := CreateSiblingTemp(target)
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	defer stage.Cleanup()
	if err := os.Remove(outputDir); err != nil {
		t.Fatalf("remove original parent link: %v", err)
	}
	if err := os.Symlink(replacementDir, outputDir); err != nil {
		t.Fatalf("replace parent link: %v", err)
	}

	_, err = stage.ReserveTargetDirectory()
	if err == nil || !strings.Contains(err.Error(), "output directory changed") {
		t.Fatalf("ReserveTargetDirectory error = %v, want changed-directory refusal", err)
	}
	for _, path := range []string{
		filepath.Join(originalDir, "recovered"),
		filepath.Join(replacementDir, "recovered"),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected reserved directory %s: %v", path, err)
		}
	}
}

func TestStagedFileRemovesReservedDirectoryOnlyThroughPinnedParent(t *testing.T) {
	dir := t.TempDir()
	originalDir := filepath.Join(dir, "original")
	replacementDir := filepath.Join(dir, "replacement")
	for _, path := range []string{originalDir, replacementDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create parent directory %s: %v", path, err)
		}
	}
	outputDir := filepath.Join(dir, "output-link")
	if err := os.Symlink(originalDir, outputDir); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	target := filepath.Join(outputDir, "recovered")
	stage, err := CreateSiblingTemp(target)
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	defer stage.Cleanup()
	ownedInfo, err := stage.ReserveTargetDirectory()
	if err != nil {
		t.Fatalf("ReserveTargetDirectory: %v", err)
	}

	if err := os.Remove(outputDir); err != nil {
		t.Fatalf("remove original parent link: %v", err)
	}
	if err := os.Symlink(replacementDir, outputDir); err != nil {
		t.Fatalf("replace parent link: %v", err)
	}
	foreignDir := filepath.Join(replacementDir, "recovered")
	if err := os.Mkdir(foreignDir, 0o700); err != nil {
		t.Fatalf("create foreign replacement directory: %v", err)
	}
	foreignPath := filepath.Join(foreignDir, "foreign.txt")
	foreignBytes := []byte("replacement directory must not be traversed or removed")
	if err := os.WriteFile(foreignPath, foreignBytes, 0o600); err != nil {
		t.Fatalf("write foreign replacement: %v", err)
	}

	if err := stage.RemoveTargetDirectory(ownedInfo); err != nil {
		t.Fatalf("RemoveTargetDirectory through pinned parent: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(originalDir, "recovered")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned directory was not removed from pinned parent: %v", err)
	}
	gotForeign, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatalf("read foreign replacement: %v", err)
	}
	if !bytes.Equal(gotForeign, foreignBytes) {
		t.Fatalf("foreign replacement = %q, want %q", gotForeign, foreignBytes)
	}
}

func TestStagedFileReservesAndRemovesDerivedSiblingDirectory(t *testing.T) {
	dir := t.TempDir()
	stage, err := CreateSiblingTemp(filepath.Join(dir, "archive.zip"))
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	defer stage.Cleanup()

	extractDir := filepath.Join(dir, "archive")
	info, err := stage.ReserveSiblingDirectory(extractDir)
	if err != nil {
		t.Fatalf("ReserveSiblingDirectory: %v", err)
	}
	current, err := os.Lstat(extractDir)
	if err != nil {
		t.Fatalf("inspect derived sibling directory: %v", err)
	}
	if !current.IsDir() || !os.SameFile(info, current) {
		t.Fatal("derived sibling does not have the identity returned by reservation")
	}
	if runtime.GOOS != "windows" && current.Mode().Perm() != 0o700 {
		t.Fatalf("derived sibling mode = %04o, want 0700", current.Mode().Perm())
	}
	if err := stage.RemoveSiblingDirectory(extractDir, info); err != nil {
		t.Fatalf("RemoveSiblingDirectory: %v", err)
	}
	if _, err := os.Lstat(extractDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("derived sibling still exists after removal: %v", err)
	}
}

func TestStagedFileRejectsSiblingDirectoryOutsidePinnedParent(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	otherParent := filepath.Join(dir, "other")
	for _, path := range []string{parent, otherParent} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create parent %s: %v", path, err)
		}
	}
	stage, err := CreateSiblingTemp(filepath.Join(parent, "archive.zip"))
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	defer stage.Cleanup()

	outside := filepath.Join(otherParent, "archive")
	if _, err := stage.ReserveSiblingDirectory(outside); err == nil ||
		!strings.Contains(err.Error(), "not beside") {
		t.Fatalf("ReserveSiblingDirectory error = %v, want non-sibling refusal", err)
	}
	if _, err := os.Lstat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reservation created an outside directory: %v", err)
	}
}

func TestStagedFileSiblingReservationRejectsOrPreventsOrdinaryParentReplacement(t *testing.T) {
	dir := t.TempDir()
	outputParent := filepath.Join(dir, "output")
	movedParent := filepath.Join(dir, "moved")
	if err := os.Mkdir(outputParent, 0o700); err != nil {
		t.Fatalf("create output parent: %v", err)
	}
	stage, err := CreateSiblingTemp(filepath.Join(outputParent, "archive.zip"))
	if err != nil {
		t.Fatalf("CreateSiblingTemp: %v", err)
	}
	defer stage.Cleanup()
	if err := os.Rename(outputParent, movedParent); err != nil {
		if windowsPreventedOpenHandleRename(err) {
			current, statErr := os.Stat(outputParent)
			if statErr != nil {
				t.Fatalf("inspect protected output parent: %v", statErr)
			}
			if !os.SameFile(stage.TargetParentInfo(), current) {
				t.Fatal("blocked rename still changed the output parent identity")
			}
			target := filepath.Join(outputParent, "archive")
			reserved, reserveErr := stage.ReserveSiblingDirectory(target)
			if reserveErr != nil {
				t.Fatalf("reserve through protected output parent: %v", reserveErr)
			}
			if removeErr := stage.RemoveSiblingDirectory(target, reserved); removeErr != nil {
				t.Fatalf("remove protected output reservation: %v", removeErr)
			}
			return
		}
		t.Fatalf("move original output parent: %v", err)
	}
	if err := os.Mkdir(outputParent, 0o700); err != nil {
		t.Fatalf("create replacement output parent: %v", err)
	}

	_, err = stage.ReserveSiblingDirectory(filepath.Join(outputParent, "archive"))
	if err == nil || !strings.Contains(err.Error(), "output directory changed") {
		t.Fatalf("ReserveSiblingDirectory error = %v, want changed-directory refusal", err)
	}
	for _, path := range []string{
		filepath.Join(movedParent, "archive"),
		filepath.Join(outputParent, "archive"),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected reserved directory %s: %v", path, err)
		}
	}
}

func TestStagedFileSiblingReservationPreservesOccupiedPaths(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			stage, err := CreateSiblingTemp(filepath.Join(dir, "archive.zip"))
			if err != nil {
				t.Fatalf("CreateSiblingTemp: %v", err)
			}
			defer stage.Cleanup()

			occupied := filepath.Join(dir, "archive")
			protectedBytes := []byte("occupied sibling must remain untouched")
			if kind == "file" {
				if err := os.WriteFile(occupied, protectedBytes, 0o600); err != nil {
					t.Fatalf("create occupied file: %v", err)
				}
			} else {
				if err := os.Mkdir(occupied, 0o700); err != nil {
					t.Fatalf("create occupied directory: %v", err)
				}
				if err := os.WriteFile(filepath.Join(occupied, "foreign.txt"), protectedBytes, 0o600); err != nil {
					t.Fatalf("write occupied directory entry: %v", err)
				}
			}
			occupiedInfo, err := os.Lstat(occupied)
			if err != nil {
				t.Fatalf("inspect occupied sibling: %v", err)
			}

			if _, err := stage.ReserveSiblingDirectory(occupied); !errors.Is(err, os.ErrExist) {
				t.Fatalf("ReserveSiblingDirectory error = %v, want os.ErrExist", err)
			}
			current, err := os.Lstat(occupied)
			if err != nil {
				t.Fatalf("inspect occupied sibling after refusal: %v", err)
			}
			if !os.SameFile(occupiedInfo, current) || current.IsDir() != (kind == "directory") {
				t.Fatal("occupied sibling changed identity or type")
			}
			if kind == "file" {
				got, err := os.ReadFile(occupied)
				if err != nil {
					t.Fatalf("read occupied file: %v", err)
				}
				if !bytes.Equal(got, protectedBytes) {
					t.Fatalf("occupied file = %q, want %q", got, protectedBytes)
				}
			} else {
				got, err := os.ReadFile(filepath.Join(occupied, "foreign.txt"))
				if err != nil {
					t.Fatalf("read occupied directory entry: %v", err)
				}
				if !bytes.Equal(got, protectedBytes) {
					t.Fatalf("occupied directory entry = %q, want %q", got, protectedBytes)
				}
			}
		})
	}
}
