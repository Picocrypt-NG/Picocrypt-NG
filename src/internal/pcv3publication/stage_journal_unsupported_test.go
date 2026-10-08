//go:build !linux && !android

package pcv3publication

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedJournalFailsBeforeCreatingCleanupAuthority(t *testing.T) {
	directory := t.TempDir()
	stage, err := createRetainedTestStage(t, filepath.Join(directory, "output"), []byte("unpublished output"))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if err := stage.PersistCleanupJournal(); !errors.Is(err, errCleanupJournalPersist) {
		t.Fatalf("unsupported journal persistence = %v", err)
	}
	if stage.journaled {
		t.Fatal("unsupported journal granted cleanup authority")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != stage.stageName {
		t.Fatalf("unsupported journal created residue: %v, %v", entries, err)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireNoStageEntries(t, directory)
}
