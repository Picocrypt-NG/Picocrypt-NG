package pcv3publication

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCreationIdentityPinFailureCleansStageBeforeReleasingOriginal(t *testing.T) {
	directory := t.TempDir()
	operations, counts := realRenameOperations(t, directory)
	var owned *os.File
	operations.pinStage = func(file *os.File) (*os.File, error) {
		owned = file
		return nil, errors.New("descriptor duplication refused")
	}
	operations.removeStage = func(root *os.Root, name string) error {
		if _, err := owned.Stat(); err != nil {
			t.Fatalf("duplication failure released original before cleanup: %v", err)
		}
		return root.Remove(name)
	}
	target := filepath.Join(directory, "output")
	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if stage != nil {
		stage.operations.removeStage = (*os.Root).Remove
		_ = stage.Cleanup()
		t.Fatal("creation exposed an unpinned stage")
	}
	result := requireResultError(t, err)
	if result.State() != StateNotPublished || counts.atomic != 0 || errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("identity pin refusal reached publication or failed cleanup: %v, calls=%d", err, counts.atomic)
	}
	if owned == nil {
		t.Fatal("creation did not attempt to pin its real stage descriptor")
	}
	if _, err := owned.Stat(); err == nil {
		t.Fatal("duplication refusal leaked original descriptor")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("pin refusal created destination: %v", err)
	}
	requireNoStageEntries(t, directory)
}

func TestStageCleanupAfterWritableDescriptorFaultKeepsIdentityAndPreservesForeignReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned stage", true: "foreign replacement"}[replace], func(t *testing.T) {
			directory := t.TempDir()
			operations, _ := realRenameOperations(t, directory)
			target := filepath.Join(directory, "output")
			stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Cleanup()
			pin := stage.identityPin
			ownedInfo, err := stage.File().Stat()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stage.File().Write([]byte("owned output")); err != nil {
				t.Fatal(err)
			}
			if err := stage.File().Close(); err != nil {
				t.Fatal(err)
			}
			foreign := []byte("foreign bytes must survive the write fault")
			escaped := filepath.Join(directory, "failed-original")
			if replace {
				if err := os.Rename(stage.stagePath, escaped); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(stage.stagePath, foreign, 0o600); err != nil {
					t.Fatal(err)
				}
				foreignInfo, err := os.Stat(stage.stagePath)
				if err != nil || os.SameFile(ownedInfo, foreignInfo) {
					t.Fatalf("foreign replacement did not establish independent identity: %v", err)
				}
			}
			if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("already-closed writable handle lost cleanup warning: %v", err)
			}
			if replace {
				requireFileBytes(t, stage.stagePath, foreign)
				requireFileBytes(t, escaped, []byte("owned output"))
			} else {
				requireNoStageEntries(t, directory)
			}
			if pin != nil {
				if _, err := pin.Stat(); err == nil {
					t.Fatal("cleanup leaked its independent identity pin")
				}
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("failed writer published output: %v", err)
			}
		})
	}
}

func TestStageCleanupWithoutLiveIdentityPinPreservesUnprovenPath(t *testing.T) {
	directory := t.TempDir()
	operations, _ := realRenameOperations(t, directory)
	stage, err := createWithOperations(filepath.Join(directory, "output"), nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("unproven object must remain")
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := stage.File().Close(); err != nil {
		t.Fatal(err)
	}
	if stage.identityPin != nil {
		if err := stage.identityPin.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("cleanup without a live identity pin = %v", err)
	}
	requireFileBytes(t, stage.stagePath, payload)
}

// Keeping the object open through removal prevents an unlinked inode/file ID
// from being recycled for a foreign file during the ownership check.
func TestStageCleanupKeepsOwnedIdentityPinnedThroughRemoval(t *testing.T) {
	directory := t.TempDir()
	operations, _ := realRenameOperations(t, directory)
	var owned *os.File
	operations.removeStage = func(root *os.Root, name string) error {
		info, err := owned.Stat()
		if err != nil {
			t.Fatalf("last owned descriptor closed before stage removal: %v", err)
		}
		current, err := root.Lstat(name)
		if err != nil || !os.SameFile(info, current) {
			t.Fatalf("stage removal lost pinned object identity: %v", err)
		}
		return root.Remove(name)
	}
	stage, err := createWithOperations(filepath.Join(directory, "output"), nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatal(err)
	}
	owned = stage.File()
	if _, err := owned.Write([]byte("private stage")); err != nil {
		t.Fatal(err)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := owned.Stat(); err == nil {
		t.Fatal("cleanup did not close owned descriptor after removal")
	}
}

func TestRetainedRemovalKeepsOwnedIdentityPinnedThroughRemoval(t *testing.T) {
	target := filepath.Join(t.TempDir(), "retained")
	retained := publishRetainedTestFile(t, target, []byte("retained plaintext"))
	owned := retained.file
	remove := retained.remove
	retained.remove = func(root *os.Root, name string) error {
		info, err := owned.Stat()
		if err != nil {
			t.Fatalf("last owned descriptor closed before retained removal: %v", err)
		}
		current, err := root.Lstat(name)
		if err != nil || !os.SameFile(info, current) {
			t.Fatalf("retained removal lost pinned object identity: %v", err)
		}
		return remove(root, name)
	}
	if err := retained.RemoveExact(); err != nil {
		t.Fatal(err)
	}
	if _, err := owned.Stat(); err == nil {
		t.Fatal("removal did not close retained descriptor")
	}
	if retained.Live() {
		t.Fatal("removal retained authority")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("owned plaintext remains: %v", err)
	}
}

func TestPublicationPinsIdentityAcrossFinalizationClose(t *testing.T) {
	directory := t.TempDir()
	operations, _ := realRenameOperations(t, directory)
	var stage *Stage
	operations.closeStage = func(file *os.File) error {
		if err := file.Close(); err != nil {
			return err
		}
		// Publish must retain another descriptor before releasing the writable
		// original. This checks actual filesystem custody at the close boundary.
		if stage.identityPin == nil {
			t.Fatal("finalization closed the last identity pin")
		}
		pinned, err := stage.identityPin.Stat()
		if err != nil || !os.SameFile(stage.stageInfo, pinned) {
			t.Fatalf("finalization lost exact identity pin: %v", err)
		}
		return nil
	}
	var err error
	stage, err = createWithOperations(filepath.Join(directory, "output"), nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File().Write([]byte("complete output")); err != nil {
		t.Fatal(err)
	}
	if result := stage.Publish(context.Background()); result.State() != StatePublishedDurable {
		t.Fatal(result)
	}
	pin := stage.identityPin
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := pin.Stat(); err == nil {
		t.Fatal("cleanup retained publication identity descriptor")
	}
}
