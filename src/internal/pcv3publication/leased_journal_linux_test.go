//go:build linux && !android

package pcv3publication

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func persistLeasedTestJournal(t *testing.T, stage *Stage) {
	t.Helper()
	journaler, ok := any(stage).(interface{ PersistLeasedCleanupJournal() error })
	if !ok {
		t.Fatal("stage cannot durably record the leased desktop cleanup protocol")
	}
	if err := journaler.PersistLeasedCleanupJournal(); err != nil {
		t.Fatal(err)
	}
}

func TestLeasedCiphertextJournalRemainsThroughRename(t *testing.T) {
	stage, err := createRetainedTestStage(t, filepath.Join(t.TempDir(), "output"), []byte("complete ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	persistLeasedTestJournal(t, stage)
	journalPath := filepath.Join(filepath.Dir(stage.stagePath), cleanupJournalName)
	atomic := stage.operations.atomicPublish
	reached := false
	stage.operations.atomicPublish = func(source, parent, original *os.File, old, target string, policy Policy) error {
		reached = true
		if _, err := os.Stat(journalPath); err != nil {
			t.Fatalf("ciphertext lost orphan cleanup authority before rename: %v", err)
		}
		return atomic(source, parent, original, old, target, policy)
	}
	if result := stage.PublishWrite(context.Background()); result.State() != StatePublishedDurable || !reached {
		t.Fatalf("publish ciphertext: %v, rename reached=%v", result, reached)
	}
}

func TestLeasedPublicationSyncFailurePreservesRequestedOutput(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "authenticated plaintext", true: "ciphertext"}[write], func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "requested-output")
			stage, err := createRetainedTestStage(t, target, []byte("complete requested output"))
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Cleanup()
			persistLeasedTestJournal(t, stage)
			stage.operations.syncDirectory = func(*os.File) error { return errors.New("directory synchronization refused") }
			var result Result
			if write {
				result = stage.PublishWrite(context.Background())
			} else {
				result = stage.Publish(context.Background())
			}
			if result.State() != StatePublishedDurabilityUncertain {
				t.Fatalf("committed output lost its durability truth: %v", result)
			}
			requireFileBytes(t, target, []byte("complete requested output"))
			if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("unretired journal must remain a cleanup warning: %v", err)
			}
			requireFileBytes(t, target, []byte("complete requested output"))
		})
	}
}
