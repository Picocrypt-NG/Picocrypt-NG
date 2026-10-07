//go:build linux || android

package pcv3publication

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
