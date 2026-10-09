//go:build windows

package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3result"
	"context"
	"errors"
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
	err = windowsNoReplace(stage.parent, stage.stageName, stage.targetName, PolicyNoReplace)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("native collision error: %[1]T %[1]v (%#[1]v); want os.ErrExist", err)
	}
	requireFileBytes(t, target, foreign)
	requireFileBytes(t, stage.stagePath, payload)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := windowsNoReplace(stage.parent, stage.stageName, stage.targetName, PolicyNoReplace); err != nil {
		t.Fatalf("native pinned sibling rename: %[1]T %[1]v (%#[1]v)", err)
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

func TestWindowsNativeRenameRejectsLateCollision(t *testing.T) {
	testNativeLateCollision(t)
}

func TestWindowsSafeReplaceFailsBeforeStage(t *testing.T) {
	testNativeSafeReplaceFailsBeforeStage(t)
}

func TestWindowsNativePlaintextPublicationNeverGrantsDurableRetainedAuthority(t *testing.T) {
	target := filepath.Join(t.TempDir(), "plaintext")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if _, err := stage.File().Write([]byte("authenticated plaintext")); err != nil {
		t.Fatal(err)
	}
	result, retained := stage.PublishRetained(context.Background())
	if result.State() != StatePublishedDurabilityUncertain || retained != nil {
		t.Fatalf("native Windows plaintext gained durable retained authority: %v, %v", result, retained)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireFileBytes(t, target, []byte("authenticated plaintext"))
}

func TestWindowsNativeRetainedSplitPreservesCompleteUncertainCiphertext(t *testing.T) {
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
	if result.State() != StatePublishedDurabilityUncertain || retained == nil {
		t.Fatalf("native Windows ciphertext lost retained custody: %v, %v", result, retained)
	}
	defer retained.Close()
	state, splitErr := SplitRetainedWithResult(retained, fileops.SplitOptions{ChunkSize: 1, Unit: fileops.SplitUnitKiB})
	if splitErr != nil || state != fileops.SplitCompleteDurabilityUncertain {
		t.Fatalf("native split completion = %v/%v; want complete durability uncertain", state, splitErr)
	}
	if retained.Live() {
		t.Fatal("refused native split retained follow-up authority")
	}
	requireFileBytes(t, target, payload)
	recombined := filepath.Join(directory, "recombined.pcv")
	if err := fileops.Recombine(fileops.RecombineOptions{InputBase: target, OutputPath: recombined}); err != nil {
		t.Fatalf("recombine complete uncertain native chunks: %v", err)
	}
	requireFileBytes(t, recombined, payload)
}
