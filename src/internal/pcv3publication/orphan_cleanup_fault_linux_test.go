//go:build linux && !android

package pcv3publication

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopRecoveryPreservesForeignReplacementsAndAliases(t *testing.T) {
	for _, replacement := range []string{"stage", "stage symlink", "stage hardlink", "journal", "journal symlink", "journal hardlink", "private directory", "destination", "extra keyfile"} {
		t.Run(replacement, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "destination")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			child, kill := startDesktopCleanupChild(t, parent, "private stage", false)
			kill()
			private := filepath.Dir(child.Stage)
			journal := filepath.Join(private, cleanupJournalName)
			foreign := filepath.Join(base, "foreign-sentinel")
			if err := os.WriteFile(foreign, []byte("foreign bytes must survive"), 0o600); err != nil {
				t.Fatal(err)
			}
			expectedOwned := child.Stage
			switch replacement {
			case "stage", "stage symlink":
				expectedOwned = filepath.Join(base, "original-stage")
				if err := os.Rename(child.Stage, expectedOwned); err != nil {
					t.Fatal(err)
				}
				if replacement == "stage symlink" {
					if err := os.Symlink(foreign, child.Stage); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(child.Stage, []byte("replacement stage"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "stage hardlink":
				if err := os.Link(child.Stage, filepath.Join(base, "stage-alias")); err != nil {
					t.Fatal(err)
				}
			case "journal", "journal symlink":
				if err := os.Rename(journal, filepath.Join(base, "original-journal")); err != nil {
					t.Fatal(err)
				}
				if replacement == "journal symlink" {
					if err := os.Symlink(foreign, journal); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(journal, []byte("replacement journal"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "journal hardlink":
				if err := os.Link(journal, filepath.Join(base, "journal-alias")); err != nil {
					t.Fatal(err)
				}
			case "private directory":
				moved := filepath.Join(base, "original-private-directory")
				if err := os.Rename(private, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(private, 0o700); err != nil {
					t.Fatal(err)
				}
				expectedOwned = filepath.Join(moved, filepath.Base(child.Stage))
				if err := os.WriteFile(filepath.Join(private, "foreign"), []byte("replacement directory contents"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "destination":
				moved := filepath.Join(base, "original-destination")
				if err := os.Rename(parent, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				// Move the original operation under a replacement selected parent;
				// its recorded destination identity must not authorize this namespace.
				if err := os.Rename(filepath.Join(moved, filepath.Base(private)), private); err != nil {
					t.Fatal(err)
				}
			case "extra keyfile":
				if err := os.WriteFile(filepath.Join(private, "selected-keyfile"), []byte("keyfile bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			state, err := CleanupOrphanedStages(parent, nil)
			if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("unproven replacement recovery = %v, %v", state, err)
			}
			requireFileBytes(t, foreign, []byte("foreign bytes must survive"))
			requireFileBytes(t, expectedOwned, []byte("complete owned output"))
			switch replacement {
			case "stage":
				requireFileBytes(t, child.Stage, []byte("replacement stage"))
			case "journal":
				requireFileBytes(t, journal, []byte("replacement journal"))
			case "private directory":
				requireFileBytes(t, filepath.Join(private, "foreign"), []byte("replacement directory contents"))
			case "extra keyfile":
				requireFileBytes(t, filepath.Join(private, "selected-keyfile"), []byte("keyfile bytes"))
			}
		})
	}
}

func TestDesktopRecoveryPreservesLegacyAndUnjournaledStages(t *testing.T) {
	for _, journal := range []bool{false, true} {
		t.Run(map[bool]string{false: "unjournaled", true: "legacy v2"}[journal], func(t *testing.T) {
			parent := t.TempDir()
			stage := createTestStage(t, parent)
			if journal {
				if err := stage.PersistCleanupJournal(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := stage.File().Write([]byte("unproven private bytes")); err != nil {
				t.Fatal(err)
			}
			path := stage.stagePath
			// A lock alone does not establish the desktop journal protocol.
			state, err := CleanupOrphanedStages(parent, nil)
			if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("live but unproven protocol recovery = %v, %v", state, err)
			}
			closeStageHandlesWithoutCleanup(t, stage)
			state, err = CleanupOrphanedStages(parent, nil)
			if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("legacy recovery = %v, %v", state, err)
			}
			requireFileBytes(t, path, []byte("unproven private bytes"))
		})
	}
}

func TestDesktopRecoveryPartialCleanupFailureRemainsIncomplete(t *testing.T) {
	parent := t.TempDir()
	child, kill := startDesktopCleanupChild(t, parent, "private stage", false)
	kill()
	foreign := filepath.Join(parent, "source-and-keyfile-sentinel")
	if err := os.WriteFile(foreign, []byte("selected source and keyfile bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	operations := nativeJournalCleanupOperations()
	operations.syncDirectory = func(*os.File) error { return errors.New("directory barrier failed after stage removal") }
	state, err := cleanupOrphanedStagesWithOperations(parent, nil, operations)
	if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("partial recovery = %v, %v", state, err)
	}
	requireAbsent(t, child.Stage)
	journal := filepath.Join(filepath.Dir(child.Stage), cleanupJournalName)
	if _, err := os.Stat(journal); err != nil {
		t.Fatal("partial cleanup discarded its uncertain identity evidence")
	}
	state, err = CleanupOrphanedStages(parent, nil)
	if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("unknown missing stage must remain incomplete: %v, %v", state, err)
	}
	requireFileBytes(t, foreign, []byte("selected source and keyfile bytes"))
	requireAbsent(t, child.Target)
}

func TestDesktopRecoveryRequiresNoAncestorDirectoryListingPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the ancestor directory permission boundary")
	}
	base := t.TempDir()
	parent := filepath.Join(base, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	child, kill := startDesktopCleanupChild(t, parent, "private stage", false)
	kill()
	selected, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	if err := os.Chmod(base, 0o111); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(base, 0o700)
	state, err := CleanupOrphanedStages(parent, []*os.File{selected})
	if err != nil || state != CleanupJournalCleaned {
		t.Fatalf("metadata-only ancestor protection required listing permission: %v, %v", state, err)
	}
	requireAbsent(t, child.Stage)
}
