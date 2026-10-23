package pcv3publication

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStageCleanupReportsOnlyDurabilityAfterClosingAndRemovingOwnedFiles(t *testing.T) {
	directory := t.TempDir()
	operations, _ := realRenameOperations(t, directory)
	stage, err := createWithOperations(filepath.Join(directory, "output"), nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	writer, pin := stage.file, stage.identityPin
	stage.operations.syncDirectory = func(*os.File) error {
		if _, err := writer.Stat(); err == nil {
			t.Error("directory barrier ran before the writable handle closed")
		}
		if _, err := pin.Stat(); err == nil {
			t.Error("directory barrier ran before the identity pin closed")
		}
		return errors.New("TEST ONLY directory barrier refused")
	}
	err = stage.Cleanup()
	if !errors.Is(err, ErrCleanupDurabilityUncertain) || errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("removed stage cleanup = %v; want durability uncertainty only", err)
	}
	if again := stage.Cleanup(); !errors.Is(again, ErrCleanupDurabilityUncertain) || errors.Is(again, ErrCleanupIncomplete) {
		t.Fatalf("repeated cleanup lost the original result: %v", again)
	}
	requireNoStageEntries(t, directory)
}

func TestRetainedStreamSeparatesRemovedSourceDurabilityFromCleanupFailure(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "retained")
	payload := []byte("exact streamed bytes despite deletion barrier failure")
	retained := publishRetainedTestFile(t, target, payload)
	retained.syncDirectory = func(*os.File) error {
		return errors.New("TEST ONLY directory barrier refused")
	}
	destination, err := os.Create(filepath.Join(t.TempDir(), "stream"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	result := retained.StreamTo(context.Background(), destination)
	if !result.Copied() || result.CleanupIncomplete() || !result.CleanupDurabilityUncertain() {
		t.Fatalf("streamed removal result = copied %v cleanup %v durability %v; want copied with deletion durability uncertainty only", result.Copied(), result.CleanupIncomplete(), result.CleanupDurabilityUncertain())
	}
	if retained.Live() {
		t.Fatal("stream left removal authority live")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stream retained its source name: %v", err)
	}
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(destination)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("streamed bytes = %q/%v", got, err)
	}
}

func TestStageCleanupKeepsCloseFailureAlongsideDeletionDurability(t *testing.T) {
	directory := t.TempDir()
	operations, _ := realRenameOperations(t, directory)
	stage, err := createWithOperations(filepath.Join(directory, "output"), nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if err := stage.file.Close(); err != nil {
		t.Fatal(err)
	}
	stage.operations.syncDirectory = func(*os.File) error {
		return errors.New("TEST ONLY directory barrier refused")
	}
	err = stage.Cleanup()
	if !errors.Is(err, ErrCleanupIncomplete) || !errors.Is(err, ErrCleanupDurabilityUncertain) {
		t.Fatalf("close failure plus deletion barrier refusal = %v; want both fixed cleanup causes", err)
	}
	requireNoStageEntries(t, directory)
}

func TestStageCleanupPreservesUnprovenNameWhenRemovalReportsNoEffect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows exact-handle removal bypasses the pathname removal seam")
	}
	directory := t.TempDir()
	operations, _ := realRenameOperations(t, directory)
	stage, err := createWithOperations(filepath.Join(directory, "output"), nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	payload := []byte("owned bytes must not be reported removed")
	if _, err := stage.file.Write(payload); err != nil {
		t.Fatal(err)
	}
	stage.operations.removeStage = func(*os.Root, string) error { return nil }
	stage.operations.syncDirectory = func(*os.File) error {
		return errors.New("TEST ONLY directory barrier refused")
	}
	err = stage.Cleanup()
	if !errors.Is(err, ErrCleanupIncomplete) || errors.Is(err, ErrCleanupDurabilityUncertain) {
		t.Fatalf("unproven removal = %v; want live cleanup failure only", err)
	}
	requireFileBytes(t, stage.stagePath, payload)
}
