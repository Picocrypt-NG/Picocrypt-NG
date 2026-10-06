package pcv3publication

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRetainedKeepsOriginalDescriptorAndUncertainPublishedOutput(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "durable", true: "uncertain"}[uncertain], func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ciphertext")
			operations, _ := realRenameOperations(t, directory)
			operations.openRetained = func(*os.Root, string) (*os.File, error) {
				t.Fatal("write custody reopened output")
				return nil, errors.New("reopen")
			}
			if uncertain {
				operations.syncDirectory = func(*os.File) error { return errors.New("sync") }
			}
			stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
			if err != nil {
				t.Fatal(err)
			}
			original := stage.File()
			if _, err := original.Write([]byte("ciphertext")); err != nil {
				t.Fatal(err)
			}
			result, held := stage.PublishWriteRetained(context.Background())
			want := StatePublishedDurable
			if uncertain {
				want = StatePublishedDurabilityUncertain
			}
			if result.State() != want || held == nil || held.file != original {
				t.Fatalf("state=%v held=%v", result, held)
			}
			if err := stage.Cleanup(); err != nil {
				t.Fatal(err)
			}
			if _, err := original.Stat(); err != nil {
				t.Fatalf("held descriptor closed: %v", err)
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "ciphertext" {
				t.Fatalf("published output lost: %q %v", data, err)
			}
		})
	}
}

func TestJournaledWriteRetiresCleanupBeforeUncertainPublication(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "ciphertext")
	stage, err := createRetainedTestStage(t, target, []byte("complete ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatal(err)
	}
	original := stage.File()
	syncDirectory := stage.operations.syncDirectory
	calls := 0
	stage.operations.syncDirectory = func(parent *os.File) error {
		calls++
		if calls == 2 {
			return errors.New("publication directory sync failed")
		}
		return syncDirectory(parent)
	}
	publication, retained := stage.PublishWriteRetained(context.Background())
	if publication.State() != StatePublishedDurabilityUncertain || retained == nil || retained.file != original {
		t.Fatalf("journaled write lost held output: %v %v", publication, retained)
	}
	if _, err := os.Stat(filepath.Join(directory, cleanupJournalName)); !os.IsNotExist(err) {
		t.Fatalf("published ciphertext still targeted by startup cleanup: %v", err)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "complete ciphertext" {
		t.Fatalf("uncertain ciphertext lost: %q %v", data, err)
	}
}

func TestJournaledWriteRetirementFailurePreventsPublication(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "ciphertext")
	stage, err := createRetainedTestStage(t, target, []byte("complete ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatal(err)
	}
	syncDirectory := stage.operations.syncDirectory
	stage.operations.syncDirectory = func(*os.File) error { return errors.New("journal retirement not durable") }
	publication, _ := stage.PublishWriteRetained(context.Background())
	if publication.State() != StateNotPublished {
		t.Fatalf("published before journal retirement barrier: %v", publication)
	}
	stage.operations.syncDirectory = syncDirectory
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("failed retirement created target: %v", err)
	}
}
