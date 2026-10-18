//go:build !linux || android

package pcv3publication

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedDesktopCleanupDoesNotFallBackToLegacyDeletion(t *testing.T) {
	parent := t.TempDir()
	sentinel := filepath.Join(parent, ".picocrypt-pcv3-unproven")
	if err := os.WriteFile(sentinel, []byte("preserve unsupported-platform bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := CleanupOrphanedStages(parent, nil)
	if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unsupported desktop recovery = %v, %v", state, err)
	}
	requireFileBytes(t, sentinel, []byte("preserve unsupported-platform bytes"))
	var stage Stage
	if err := stage.PersistLeasedCleanupJournal(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unsupported desktop persistence = %v", err)
	}
}
