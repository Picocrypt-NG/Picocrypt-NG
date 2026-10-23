//go:build windows

package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3result"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsNativeRenameReportsActualSyscallFailureAndPreservesCollision(t *testing.T) {
	for _, name := range []string{"target", "x", "output-данные-🔒"} {
		t.Run(name, func(t *testing.T) { testWindowsNativeRenamePreservesCollision(t, name) })
	}
}

func testWindowsNativeRenamePreservesCollision(t *testing.T, name string) {
	t.Helper()
	directory := t.TempDir()
	target := filepath.Join(directory, name)
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
	err = windowsNoReplace(stage.sourceParent, stage.parent, stage.identityPin, stage.stageName, stage.targetName, PolicyNoReplace)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("native collision error: %[1]T %[1]v (%#[1]v); want os.ErrExist", err)
	}
	requireFileBytes(t, target, foreign)
	requireFileBytes(t, stage.stagePath, payload)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := windowsNoReplace(stage.sourceParent, stage.parent, stage.identityPin, stage.stageName, stage.targetName, PolicyNoReplace); err != nil {
		t.Fatalf("native pinned sibling rename: %[1]T %[1]v (%#[1]v)", err)
	}
	stage.cleanupDisposition = cleanupNotRequired
	requireFileBytes(t, target, payload)
	if _, err := os.Stat(stage.stagePath); !os.IsNotExist(err) {
		t.Fatalf("native rename retained stage pathname: %v", err)
	}
}

func TestWindowsNativeNoReplaceHonorsDirectoryDurabilityContract(t *testing.T) {
	testNativeNoReplacePublication(
		t,
		StatePublishedDurable,
		pcv3result.OutcomeSuccess,
		pcv3result.StageNone,
		CodePublishedDurable,
	)
}

func TestWindowsNativeRenameRejectsLateCollision(t *testing.T) {
	testNativeLateCollision(t)
}

func TestWindowsSafeReplaceFailsBeforeStage(t *testing.T) {
	testNativeSafeReplaceFailsBeforeStage(t)
}

func TestWindowsNativePlaintextRetainedAuthorityRequiresSupportedDirectoryDurability(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "plaintext")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if _, err := stage.File().Write([]byte("authenticated plaintext")); err != nil {
		t.Fatal(err)
	}
	result, retained := stage.PublishRetained(context.Background())
	if retained != nil {
		defer retained.Close()
	}
	if nativeDirectorySyncSupported(t, directory) {
		requireResult(t, result, StatePublishedDurable, pcv3result.OutcomeSuccess, pcv3result.StageNone, CodePublishedDurable)
		if retained == nil || !retained.Live() {
			t.Fatalf("durable native plaintext lost retained authority: %v", retained)
		}
		if err := retained.Close(); err != nil || retained.Live() {
			t.Fatalf("release durable plaintext custody: %v, live=%v", err, retained.Live())
		}
	} else {
		requireResult(t, result, StatePublishedDurabilityUncertain, pcv3result.OutcomeCommittedDurabilityUncertain, pcv3result.StageDirectorySync, CodeDurabilityUncertain)
		if retained != nil {
			t.Fatal("unsupported directory durability granted plaintext retained authority")
		}
	}
	requireNativeDirectoryCleanup(t, directory, stage.Cleanup())
	requireFileBytes(t, target, []byte("authenticated plaintext"))
}

func TestWindowsNativeRetainedSplitRemovesSourceOnlyAfterDurableChunks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "ciphertext")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	payload := make([]byte, 3072)
	for index := range payload {
		payload[index] = byte(index)
	}
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatal(err)
	}
	result, retained := stage.PublishWriteRetained(context.Background())
	if retained != nil {
		defer retained.Close()
	}
	pcv3RequireNativeCommit(t, directory, result)
	if retained == nil || !retained.Live() {
		t.Fatalf("native Windows ciphertext lost retained custody: %v", retained)
	}
	state, splitErr := SplitRetainedWithResult(retained, fileops.SplitOptions{ChunkSize: 1, Unit: fileops.SplitUnitKiB})
	if nativeDirectorySyncSupported(t, directory) {
		if splitErr != nil || state != fileops.SplitCompleteDurable {
			t.Fatalf("native split completion = %v/%v; want durable chunks", state, splitErr)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("durable native split retained full source: %v", err)
		}
	} else {
		if !errors.Is(splitErr, ErrCleanupDurabilityUncertain) || errors.Is(splitErr, ErrCleanupIncomplete) || state != fileops.SplitCompleteDurabilityUncertain {
			t.Fatalf("unsupported native split = %v/%v; want complete chunks and only cleanup durability uncertainty", state, splitErr)
		}
		requireFileBytes(t, target, payload)
	}
	if retained.Live() {
		t.Fatal("completed native split retained follow-up authority")
	}
	for index := range 3 {
		chunk := fmt.Sprintf("%s.%d", target, index)
		if info, err := os.Lstat(chunk); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("complete native chunk %d is not a regular file: %v", index, err)
		}
	}
	if repeated, err := SplitRetainedWithResult(retained, fileops.SplitOptions{ChunkSize: 1, Unit: fileops.SplitUnitKiB}); repeated != fileops.SplitFailed || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("consumed native split authority accepted a follow-up: %v/%v", repeated, err)
	}
	recombined := filepath.Join(directory, "recombined.pcv")
	if err := fileops.Recombine(fileops.RecombineOptions{InputBase: target, OutputPath: recombined}); err != nil {
		t.Fatalf("recombine complete native chunks: %v", err)
	}
	requireFileBytes(t, recombined, payload)
}

func TestWindowsPrivateStageKeepsOriginalDeleteAuthorityAcrossPublication(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "output")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if !privateWindowsHandle(stage.sourceParent) || !privateWindowsHandle(stage.File()) {
		t.Fatal("protected current-owner DACL was not established on directory and file")
	}
	if _, err := stage.File().Write([]byte("original object")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stage.stagePath, filepath.Join(directory, "stolen")); !windowsSharingRefusal(err) {
		t.Fatal("ordinary pathname rename did not report the expected sharing restriction")
	}
	result := stage.Publish(context.Background())
	pcv3RequireNativeCommit(t, directory, result)
	requireFileBytes(t, target, []byte("original object"))
	requireNativeDirectoryCleanup(t, directory, stage.Cleanup())
	requireNoStageEntries(t, directory)
	requireFileBytes(t, target, []byte("original object"))
}
