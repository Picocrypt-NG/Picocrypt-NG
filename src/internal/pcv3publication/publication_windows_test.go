//go:build windows

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsNativeRenameReportsActualSyscallFailureAndPreservesCollision(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	payload := []byte("complete owned ciphertext")
	foreign := []byte("foreign target must survive")
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	err = windowsNoReplace(stage.parent, stage.stageName, stage.targetName, PolicyNoReplace)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("native collision error: %[1]T %[1]v (%[1]#v); want os.ErrExist", err)
	}
	requireFileBytes(t, target, foreign)
	requireFileBytes(t, stage.stagePath, payload)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := windowsNoReplace(stage.parent, stage.stageName, stage.targetName, PolicyNoReplace); err != nil {
		t.Fatalf("native pinned sibling rename: %[1]T %[1]v (%[1]#v)", err)
	}
	stage.cleanupDisposition = cleanupNotRequired
	requireFileBytes(t, target, payload)
	if _, err := os.Stat(stage.stagePath); !os.IsNotExist(err) {
		t.Fatalf("native rename retained stage pathname: %v", err)
	}
}

func TestWindowsNativeNoReplacePublishesWithUncertainDurability(t *testing.T) {
	testNativeNoReplacePublication(
		t,
		StatePublishedDurabilityUncertain,
		pcv3result.OutcomeCommittedDurabilityUncertain,
		pcv3result.StageDirectorySync,
		CodeDurabilityUncertain,
	)
}

func TestWindowsSetFileInformationRejectsLateCollision(t *testing.T) {
	testNativeLateCollision(t)
}

func TestWindowsSafeReplaceFailsBeforeStage(t *testing.T) {
	testNativeSafeReplaceFailsBeforeStage(t)
}
