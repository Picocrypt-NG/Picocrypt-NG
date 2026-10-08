//go:build linux || android

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupJournaledStageReportsAbsentWithoutClaimingCleanup(t *testing.T) {
	state, err := CleanupJournaledStage(t.TempDir())
	if err != nil || state != CleanupJournalAbsent {
		t.Fatalf("cleanup = (%v, %v); want absent without error", state, err)
	}
}

func TestCleanupJournaledStageRejectsUnjournaledPCV3Entries(t *testing.T) {
	tests := []struct {
		name   string
		entry  string
		create func(*testing.T, string)
		verify func(*testing.T, string)
	}{
		{
			name:  "regular stage",
			entry: ".picocrypt-pcv3-orphan-regular",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("unjournaled plaintext"), 0o600); err != nil {
					t.Fatalf("write orphan stage: %v", err)
				}
			},
			verify: func(t *testing.T, path string) {
				t.Helper()
				requireFileBytes(t, path, []byte("unjournaled plaintext"))
			},
		},
		{
			name:  "journal temp",
			entry: ".picocrypt-pcv3-journal-tmp-orphan",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("interrupted journal temp"), 0o600); err != nil {
					t.Fatalf("write orphan journal temp: %v", err)
				}
			},
			verify: func(t *testing.T, path string) {
				t.Helper()
				requireFileBytes(t, path, []byte("interrupted journal temp"))
			},
		},
		{
			name:  "symlink",
			entry: ".picocrypt-pcv3-orphan-symlink",
			create: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "external-sentinel")
				if err := os.WriteFile(target, []byte("external"), 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("create orphan symlink: %v", err)
				}
			},
			verify: func(t *testing.T, path string) {
				t.Helper()
				info, err := os.Lstat(path)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("orphan symlink after cleanup = (%v, %v); want preserved symlink", info, err)
				}
			},
		},
		{
			name:  "directory",
			entry: ".picocrypt-pcv3-orphan-directory",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatalf("create orphan directory: %v", err)
				}
				if err := os.WriteFile(filepath.Join(path, "sentinel"), []byte("preserve"), 0o600); err != nil {
					t.Fatalf("write directory sentinel: %v", err)
				}
			},
			verify: func(t *testing.T, path string) {
				t.Helper()
				requireFileBytes(t, filepath.Join(path, "sentinel"), []byte("preserve"))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			entryPath := filepath.Join(directory, test.entry)
			test.create(t, entryPath)

			state, err := CleanupJournaledStage(directory)
			if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("cleanup = (%v, %v); want incomplete", state, err)
			}
			test.verify(t, entryPath)
		})
	}
}

func TestCleanupJournaledStageIgnoresUnrelatedEntryWhenJournalAbsent(t *testing.T) {
	directory := t.TempDir()
	unrelatedPath := filepath.Join(directory, "unrelated-sentinel")
	unrelated := []byte("must survive absent-journal cleanup")
	if err := os.WriteFile(unrelatedPath, unrelated, 0o600); err != nil {
		t.Fatalf("write unrelated sentinel: %v", err)
	}

	state, err := CleanupJournaledStage(directory)
	if err != nil || state != CleanupJournalAbsent {
		t.Fatalf("cleanup = (%v, %v); want absent without error", state, err)
	}
	requireFileBytes(t, unrelatedPath, unrelated)
}

func TestStageCleanupJournalCreateRejectsSymlinkSelectedParentBeforeStage(t *testing.T) {
	base := t.TempDir()
	directParent := filepath.Join(base, "direct-parent")
	if err := os.Mkdir(directParent, 0o700); err != nil {
		t.Fatalf("create direct parent: %v", err)
	}
	selectedParent := filepath.Join(base, "selected-parent")
	if err := os.Symlink(directParent, selectedParent); err != nil {
		t.Fatalf("create selected-parent symlink: %v", err)
	}

	stage, err := Create(filepath.Join(selectedParent, "target.pcv"), nil, PolicyNoReplace)
	unexpectedSuccess := err == nil || stage != nil
	if unexpectedSuccess {
		t.Errorf("Create through symlink-selected parent = (%v, %v); want rejection", stage, err)
	}
	entries, readErr := os.ReadDir(directParent)
	if readErr != nil {
		t.Fatalf("inspect direct parent after rejection: %v", readErr)
	}
	if len(entries) != 0 {
		t.Errorf("symlink-selected parent rejection left entries: %v", entries)
	}
	if stage != nil {
		_ = stage.Cleanup()
	}
	if unexpectedSuccess || len(entries) != 0 {
		return
	}

	directStage, err := Create(filepath.Join(directParent, "direct-target.pcv"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatalf("Create through direct parent: %v", err)
	}
	if cleanupErr := directStage.Cleanup(); cleanupErr != nil {
		t.Fatalf("cleanup direct-parent positive control: %v", cleanupErr)
	}
}

func TestCleanupJournaledStageRemovesOnlyPersistedStageAfterRestart(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.pcv")
	source := filepath.Join(directory, "source.txt")
	sourceBytes := []byte("source must survive startup cleanup")
	if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
		t.Fatalf("write source sentinel: %v", err)
	}

	stage, err := Create(target, []string{source}, PolicyNoReplace)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	stagePath := stage.stagePath
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	stageBytes := []byte("operation-owned plaintext archive")
	if _, err := stage.File().Write(stageBytes); err != nil {
		t.Fatalf("write stage after durable ownership journal: %v", err)
	}
	closeStageHandlesWithoutCleanup(t, stage)

	state, err := CleanupJournaledStage(directory)
	if err != nil {
		t.Fatalf("startup cleanup: %v", err)
	}
	if state != CleanupJournalCleaned {
		t.Fatalf("startup cleanup state = %v; want cleaned", state)
	}
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage after startup cleanup = %v; want absent", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, cleanupJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal after startup cleanup = %v; want absent", err)
	}
	requireFileBytes(t, source, sourceBytes)
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target after startup cleanup = %v; want absent", err)
	}
}

func TestStageCleanupJournalRemovesExactStageAndJournalThenSyncs(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.pcv")
	source := filepath.Join(directory, "source.txt")
	targetBytes := []byte("pre-existing target sentinel")
	sourceBytes := []byte("source sentinel")
	if err := os.WriteFile(target, targetBytes, 0o600); err != nil {
		t.Fatalf("write target sentinel: %v", err)
	}
	if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
		t.Fatalf("write source sentinel: %v", err)
	}
	stage, err := Create(filepath.Join(directory, "other-target.pcv"), []string{source, target}, PolicyNoReplace)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	stagePath := stage.stagePath
	if _, err := stage.File().Write([]byte("plaintext after journal")); err != nil {
		t.Fatalf("write stage: %v", err)
	}

	if err := stage.Cleanup(); err != nil {
		t.Fatalf("same-process cleanup: %v", err)
	}
	requireAbsent(t, stagePath)
	requireAbsent(t, filepath.Join(directory, cleanupJournalName))
	requireFileBytes(t, source, sourceBytes)
	requireFileBytes(t, target, targetBytes)
}

func TestStageCleanupJournalCollisionNeverOverwritesFixedJournal(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, cleanupJournalName)
	foreign := []byte("foreign journal must not be overwritten")
	if err := os.WriteFile(journalPath, foreign, 0o640); err != nil {
		t.Fatalf("write fixed-name collision: %v", err)
	}
	stage := createTestStage(t, directory)
	stagePath := stage.stagePath

	err := stage.PersistCleanupJournal()
	if !errors.Is(err, errCleanupJournalExists) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("collision error = %v; want unresolved fixed journal collision", err)
	}
	requireFileBytes(t, journalPath, foreign)
	requireFileBytes(t, stagePath, nil)
	requireNoJournalTemps(t, directory)
	if cleanupErr := stage.Cleanup(); cleanupErr != nil {
		t.Fatalf("cleanup unjournaled stage after collision: %v", cleanupErr)
	}
	requireFileBytes(t, journalPath, foreign)
}

func TestStageCleanupJournalPreservesStageWhenAnExtraPlaintextLinkAppears(t *testing.T) {
	directory := t.TempDir()
	stage := createTestStage(t, directory)
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	stagePath := stage.stagePath
	aliasPath := filepath.Join(directory, "unexpected-plaintext-link")
	if err := os.Link(stagePath, aliasPath); err != nil {
		t.Fatalf("create unexpected stage hardlink: %v", err)
	}

	if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("cleanup error = %v; want incomplete", err)
	}
	if _, err := os.Lstat(stagePath); err != nil {
		t.Fatalf("recorded stage was not preserved: %v", err)
	}
	if _, err := os.Lstat(aliasPath); err != nil {
		t.Fatalf("unexpected link was not preserved: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, cleanupJournalName)); err != nil {
		t.Fatalf("journal was not preserved: %v", err)
	}
}

func TestCleanupJournaledStageRejectsMalformedOversizedAndSymlinkJournals(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string, string)
	}{
		{
			name: "malformed closed schema",
			setup: func(t *testing.T, directory, journalPath string) {
				t.Helper()
				if err := os.WriteFile(journalPath, []byte(`{"version":1,"unexpected":true}`), 0o600); err != nil {
					t.Fatalf("write malformed journal: %v", err)
				}
			},
		},
		{
			name: "oversized",
			setup: func(t *testing.T, directory, journalPath string) {
				t.Helper()
				if err := os.WriteFile(journalPath, make([]byte, cleanupJournalMaxBytes+1), 0o600); err != nil {
					t.Fatalf("write oversized journal: %v", err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, directory, journalPath string) {
				t.Helper()
				external := filepath.Join(t.TempDir(), "external-journal")
				if err := os.WriteFile(external, []byte("external"), 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Symlink(external, journalPath); err != nil {
					t.Fatalf("create journal symlink: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			stagePath := filepath.Join(directory, stageNamePrefix+"preserve")
			stageBytes := []byte("foreign plaintext-like sentinel")
			if err := os.WriteFile(stagePath, stageBytes, 0o600); err != nil {
				t.Fatalf("write stage sentinel: %v", err)
			}
			journalPath := filepath.Join(directory, cleanupJournalName)
			test.setup(t, directory, journalPath)

			state, err := CleanupJournaledStage(directory)
			if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("cleanup = (%v, %v); want incomplete", state, err)
			}
			requireFileBytes(t, stagePath, stageBytes)
			if _, err := os.Lstat(journalPath); err != nil {
				t.Fatalf("journal was not preserved: %v", err)
			}
		})
	}
}

func TestCleanupJournaledStagePreservesMovedStageAndForeignReplacement(t *testing.T) {
	directory := t.TempDir()
	stage := createTestStage(t, directory)
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	if _, err := stage.File().Write([]byte("owned plaintext")); err != nil {
		t.Fatalf("write stage: %v", err)
	}
	stagePath := stage.stagePath
	escapedPath := filepath.Join(directory, "escaped-owned-stage")
	closeStageHandlesWithoutCleanup(t, stage)
	if err := os.Rename(stagePath, escapedPath); err != nil {
		t.Fatalf("move recorded stage: %v", err)
	}
	foreign := []byte("foreign replacement")
	if err := os.WriteFile(stagePath, foreign, 0o600); err != nil {
		t.Fatalf("write foreign replacement: %v", err)
	}

	state, err := CleanupJournaledStage(directory)
	if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("cleanup = (%v, %v); want incomplete", state, err)
	}
	requireFileBytes(t, stagePath, foreign)
	requireFileBytes(t, escapedPath, []byte("owned plaintext"))
	if _, err := os.Lstat(filepath.Join(directory, cleanupJournalName)); err != nil {
		t.Fatalf("journal was not preserved: %v", err)
	}
}

func TestCleanupJournaledStageRemovesSingleRenamedIdentityAfterPublishCrash(t *testing.T) {
	directory := t.TempDir()
	stage := createTestStage(t, directory)
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	if _, err := stage.File().Write([]byte("plaintext payload")); err != nil {
		t.Fatalf("write stage: %v", err)
	}
	stagePath := stage.stagePath
	renamedPath := filepath.Join(directory, "published-but-not-retired.pcv")
	closeStageHandlesWithoutCleanup(t, stage)
	if err := os.Rename(stagePath, renamedPath); err != nil {
		t.Fatalf("simulate atomic publication: %v", err)
	}

	state, err := CleanupJournaledStage(directory)
	if err != nil || state != CleanupJournalCleaned {
		t.Fatalf("cleanup = (%v, %v); want cleaned", state, err)
	}
	requireAbsent(t, renamedPath)
	requireAbsent(t, filepath.Join(directory, cleanupJournalName))
}

func TestCleanupJournaledStageRejectsParentIdentityMismatch(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "selected")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create selected parent: %v", err)
	}
	stage := createTestStage(t, directory)
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	if _, err := stage.File().Write([]byte("owned original stage")); err != nil {
		t.Fatalf("write stage: %v", err)
	}
	originalStageName := stage.stageName
	closeStageHandlesWithoutCleanup(t, stage)
	moved := filepath.Join(base, "moved-original")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatalf("move original parent: %v", err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create replacement parent: %v", err)
	}
	journalBytes, err := os.ReadFile(filepath.Join(moved, cleanupJournalName))
	if err != nil {
		t.Fatalf("read original journal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, cleanupJournalName), journalBytes, 0o600); err != nil {
		t.Fatalf("copy journal into replacement parent: %v", err)
	}
	foreign := []byte("replacement-parent foreign stage")
	foreignPath := filepath.Join(directory, originalStageName)
	if err := os.WriteFile(foreignPath, foreign, 0o600); err != nil {
		t.Fatalf("write replacement stage: %v", err)
	}

	state, err := CleanupJournaledStage(directory)
	if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("cleanup = (%v, %v); want incomplete", state, err)
	}
	requireFileBytes(t, foreignPath, foreign)
	requireFileBytes(t, filepath.Join(moved, originalStageName), []byte("owned original stage"))
}

func TestCleanupJournaledStageReportsRemovalAndDirectorySyncFailures(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*Stage, *journalCleanupOperations)
		wantStage   bool
		wantJournal bool
	}{
		{
			name: "stage remove",
			configure: func(stage *Stage, operations *journalCleanupOperations) {
				operations.remove = func(root *os.Root, name string) error {
					if name == stage.stageName {
						return errors.New("TEST ONLY stage remove failure")
					}
					return root.Remove(name)
				}
			},
			wantStage: true, wantJournal: true,
		},
		{
			name: "journal remove",
			configure: func(stage *Stage, operations *journalCleanupOperations) {
				operations.remove = func(root *os.Root, name string) error {
					if name == cleanupJournalName {
						return errors.New("TEST ONLY journal remove failure")
					}
					return root.Remove(name)
				}
			},
			wantJournal: true,
		},
		{
			name: "first directory sync preserves journal",
			configure: func(_ *Stage, operations *journalCleanupOperations) {
				nativeSync := operations.syncDirectory
				syncCalls := 0
				operations.syncDirectory = func(parent *os.File) error {
					syncCalls++
					if syncCalls == 1 {
						return errors.New("TEST ONLY first directory sync failure")
					}
					return nativeSync(parent)
				}
			},
			wantJournal: true,
		},
		{
			name: "second directory sync remains incomplete",
			configure: func(_ *Stage, operations *journalCleanupOperations) {
				nativeSync := operations.syncDirectory
				syncCalls := 0
				operations.syncDirectory = func(parent *os.File) error {
					syncCalls++
					if syncCalls == 2 {
						return errors.New("TEST ONLY second directory sync failure")
					}
					return nativeSync(parent)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			stage := createTestStage(t, directory)
			if err := stage.PersistCleanupJournal(); err != nil {
				t.Fatalf("persist cleanup journal: %v", err)
			}
			stagePath := stage.stagePath
			closeStageHandlesWithoutCleanup(t, stage)
			operations := nativeJournalCleanupOperations()
			test.configure(stage, &operations)

			state, err := cleanupJournaledStageWithOperations(directory, operations)
			if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("cleanup = (%v, %v); want incomplete", state, err)
			}
			requireExistence(t, stagePath, test.wantStage)
			requireExistence(t, filepath.Join(directory, cleanupJournalName), test.wantJournal)
		})
	}
}

func TestStageCleanupJournalReportsRemovalAndDirectorySyncFailures(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*Stage)
		wantStage   bool
		wantJournal bool
	}{
		{
			name: "stage remove",
			configure: func(stage *Stage) {
				nativeRemove := stage.operations.removeStage
				stage.operations.removeStage = func(root *os.Root, name string) error {
					if name == stage.stageName {
						return errors.New("TEST ONLY stage remove failure")
					}
					return nativeRemove(root, name)
				}
			},
			wantStage: true, wantJournal: true,
		},
		{
			name: "journal remove",
			configure: func(stage *Stage) {
				nativeRemove := stage.operations.removeStage
				stage.operations.removeStage = func(root *os.Root, name string) error {
					if name == cleanupJournalName {
						return errors.New("TEST ONLY journal remove failure")
					}
					return nativeRemove(root, name)
				}
			},
			wantJournal: true,
		},
		{
			name: "first directory sync preserves journal",
			configure: func(stage *Stage) {
				nativeSync := stage.operations.syncDirectory
				syncCalls := 0
				stage.operations.syncDirectory = func(parent *os.File) error {
					syncCalls++
					if syncCalls == 1 {
						return errors.New("TEST ONLY first directory sync failure")
					}
					return nativeSync(parent)
				}
			},
			wantJournal: true,
		},
		{
			name: "second directory sync remains incomplete",
			configure: func(stage *Stage) {
				nativeSync := stage.operations.syncDirectory
				syncCalls := 0
				stage.operations.syncDirectory = func(parent *os.File) error {
					syncCalls++
					if syncCalls == 2 {
						return errors.New("TEST ONLY second directory sync failure")
					}
					return nativeSync(parent)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			stage := createTestStage(t, directory)
			if err := stage.PersistCleanupJournal(); err != nil {
				t.Fatalf("persist cleanup journal: %v", err)
			}
			stagePath := stage.stagePath
			test.configure(stage)
			if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("cleanup error = %v; want incomplete", err)
			}
			requireExistence(t, stagePath, test.wantStage)
			requireExistence(t, filepath.Join(directory, cleanupJournalName), test.wantJournal)
		})
	}
}

func TestStageCleanupJournalIsNotOwnedBeforeEveryDurabilityBoundary(t *testing.T) {
	directory := t.TempDir()
	stage := createTestStage(t, directory)
	nativeSyncFile := stage.operations.syncStage
	nativeSyncDirectory := stage.operations.syncDirectory
	fileSyncs := 0
	stage.operations.syncStage = func(file *os.File) error {
		fileSyncs++
		if _, err := os.Lstat(filepath.Join(directory, cleanupJournalName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fixed journal visible during file sync %d: %v", fileSyncs, err)
		}
		return nativeSyncFile(file)
	}
	directorySyncs := 0
	stage.operations.syncDirectory = func(parent *os.File) error {
		directorySyncs++
		if directorySyncs == 1 {
			if stage.journaled {
				t.Fatal("stage claimed journal ownership before directory sync")
			}
			if _, err := os.Lstat(filepath.Join(directory, cleanupJournalName)); err != nil {
				t.Fatalf("journal not installed at directory sync boundary: %v", err)
			}
			return errors.New("TEST ONLY first directory sync failure")
		}
		return nativeSyncDirectory(parent)
	}

	err := stage.PersistCleanupJournal()
	if !errors.Is(err, errCleanupJournalPersist) || errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("persist error = %v; want cleanly rolled-back persistence failure", err)
	}
	if stage.journaled {
		t.Fatal("failed persistence retained journal ownership")
	}
	if fileSyncs != 2 || directorySyncs != 2 {
		t.Fatalf("durability calls = file %d directory %d; want 2/2", fileSyncs, directorySyncs)
	}
	requireAbsent(t, filepath.Join(directory, cleanupJournalName))
	requireNoJournalTemps(t, directory)
	if cleanupErr := stage.Cleanup(); cleanupErr != nil {
		t.Fatalf("cleanup stage after rolled-back journal: %v", cleanupErr)
	}
}

func TestStageCleanupJournalPublishRetiresJournalBeforeDurableSuccess(t *testing.T) {
	directory := t.TempDir()
	stage := createTestStage(t, directory)
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	payload := []byte("published payload")
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatalf("write stage: %v", err)
	}

	result := stage.Publish(context.Background())
	requireResult(t, result, StatePublishedDurable, pcv3result.OutcomeSuccess, pcv3result.StageNone, CodePublishedDurable)
	requireAbsent(t, filepath.Join(directory, cleanupJournalName))
	requireFileBytes(t, filepath.Join(directory, "target.pcv"), payload)
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup handles after durable publication: %v", err)
	}
	requireFileBytes(t, filepath.Join(directory, "target.pcv"), payload)
}

func TestStageCleanupJournalCommittedRollbackUsesTwoDurabilityBarriers(t *testing.T) {
	tests := []struct {
		name        string
		failSync    int
		wantJournal bool
	}{
		{name: "first barrier preserves journal", failSync: 2, wantJournal: true},
		{name: "second barrier remains incomplete", failSync: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			stage := createTestStage(t, directory)
			if err := stage.PersistCleanupJournal(); err != nil {
				t.Fatalf("persist cleanup journal: %v", err)
			}
			if _, err := stage.File().Write([]byte("must not escape without capability")); err != nil {
				t.Fatalf("write stage: %v", err)
			}
			nativeRemove := stage.operations.removeStage
			journalRemoveCalls := 0
			stage.operations.removeStage = func(root *os.Root, name string) error {
				if name == cleanupJournalName {
					journalRemoveCalls++
					if journalRemoveCalls == 1 {
						return errors.New("TEST ONLY initial journal retirement failure")
					}
				}
				return nativeRemove(root, name)
			}
			nativeSync := stage.operations.syncDirectory
			syncCalls := 0
			stage.operations.syncDirectory = func(parent *os.File) error {
				syncCalls++
				if syncCalls == test.failSync {
					return errors.New("TEST ONLY committed rollback barrier failure")
				}
				return nativeSync(parent)
			}

			result, retained := stage.PublishRetained(context.Background())
			if retained != nil {
				t.Fatal("failed committed rollback returned a retained capability")
			}
			requireResult(
				t,
				result,
				StatePublicationIndeterminate,
				pcv3result.OutcomePublicationIndeterminate,
				pcv3result.StageOutputPublication,
				CodePublicationIndeterminate,
			)
			requireAbsent(t, filepath.Join(directory, "target.pcv"))
			requireExistence(t, filepath.Join(directory, cleanupJournalName), test.wantJournal)
		})
	}
}

func TestStageCleanupJournalRetirementSyncFailurePreservesTargetUntilStartupObservesJournal(t *testing.T) {
	directory := t.TempDir()
	stage := createTestStage(t, directory)
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	journalPath := filepath.Join(directory, cleanupJournalName)
	journalBytes, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read durable journal fixture: %v", err)
	}
	payload := []byte("exact published target")
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatalf("write stage: %v", err)
	}
	foreignPath := filepath.Join(directory, "foreign-sentinel")
	foreign := []byte("must never be cleanup authority")
	if err := os.WriteFile(foreignPath, foreign, 0o600); err != nil {
		t.Fatalf("write foreign sentinel: %v", err)
	}
	nativeSync := stage.operations.syncDirectory
	syncCalls := 0
	stage.operations.syncDirectory = func(parent *os.File) error {
		syncCalls++
		if syncCalls == 2 {
			return errors.New("TEST ONLY journal retirement sync failure")
		}
		return nativeSync(parent)
	}

	result, retained := stage.PublishRetained(context.Background())
	if retained != nil {
		t.Fatal("unproven journal retirement returned a retained capability")
	}
	requireResult(
		t,
		result,
		StatePublicationIndeterminate,
		pcv3result.OutcomePublicationIndeterminate,
		pcv3result.StageOutputPublication,
		CodePublicationIndeterminate,
	)
	targetPath := filepath.Join(directory, "target.pcv")
	requireFileBytes(t, targetPath, payload)
	requireFileBytes(t, foreignPath, foreign)
	requireAbsent(t, journalPath)
	if cleanupErr := stage.Cleanup(); !errors.Is(cleanupErr, ErrCleanupIncomplete) {
		t.Fatalf("same-process cleanup = %v; want incomplete without target deletion", cleanupErr)
	}
	requireFileBytes(t, targetPath, payload)
	requireFileBytes(t, foreignPath, foreign)

	state, err := CleanupJournaledStage(directory)
	if err != nil || state != CleanupJournalAbsent {
		t.Fatalf("startup with currently absent journal = (%v, %v); want absent", state, err)
	}
	requireFileBytes(t, targetPath, payload)
	if err := os.WriteFile(journalPath, journalBytes, 0o600); err != nil {
		t.Fatalf("simulate journal reappearance after failed durability barrier: %v", err)
	}
	state, err = CleanupJournaledStage(directory)
	if err != nil || state != CleanupJournalCleaned {
		t.Fatalf("startup with reappeared journal = (%v, %v); want cleaned", state, err)
	}
	requireAbsent(t, targetPath)
	requireAbsent(t, journalPath)
	requireFileBytes(t, foreignPath, foreign)
}

func TestStageCleanupJournalIndeterminatePublishRetainsExactCleanupAuthority(t *testing.T) {
	directory := t.TempDir()
	stage := createTestStage(t, directory)
	if err := stage.PersistCleanupJournal(); err != nil {
		t.Fatalf("persist cleanup journal: %v", err)
	}
	if _, err := stage.File().Write([]byte("plaintext requiring exact cleanup")); err != nil {
		t.Fatalf("write stage: %v", err)
	}
	nativeRemove := stage.operations.removeStage
	stage.operations.removeStage = func(root *os.Root, name string) error {
		if name == cleanupJournalName {
			return errors.New("TEST ONLY persistent journal remove failure")
		}
		return nativeRemove(root, name)
	}

	result, retained := stage.PublishRetained(context.Background())
	if retained != nil {
		t.Fatal("indeterminate journal retirement returned a retained capability")
	}
	requireResult(
		t,
		result,
		StatePublicationIndeterminate,
		pcv3result.OutcomePublicationIndeterminate,
		pcv3result.StageOutputPublication,
		CodePublicationIndeterminate,
	)
	requireAbsent(t, filepath.Join(directory, "target.pcv"))
	if _, err := os.Lstat(filepath.Join(directory, cleanupJournalName)); err != nil {
		t.Fatalf("failed retirement did not preserve exact journal: %v", err)
	}

	stage.operations.removeStage = nativeRemove
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("exact cleanup after transient retirement failure: %v", err)
	}
	requireAbsent(t, filepath.Join(directory, cleanupJournalName))
}

func createTestStage(t *testing.T, directory string) *Stage {
	t.Helper()
	stage, err := Create(filepath.Join(directory, "target.pcv"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	return stage
}

func requireAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s = %v; want absent", filepath.Base(path), err)
	}
}

func requireExistence(t *testing.T, path string, want bool) {
	t.Helper()
	_, err := os.Lstat(path)
	if want && err != nil {
		t.Fatalf("%s = %v; want present", filepath.Base(path), err)
	}
	if !want && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s = %v; want absent", filepath.Base(path), err)
	}
}

func requireNoJournalTemps(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read parent: %v", err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(cleanupJournalTempPrefix) && entry.Name()[:len(cleanupJournalTempPrefix)] == cleanupJournalTempPrefix {
			t.Fatalf("temporary journal residue remains: %s", entry.Name())
		}
	}
}

func closeStageHandlesWithoutCleanup(t *testing.T, stage *Stage) {
	t.Helper()
	if stage.file != nil {
		if err := stage.file.Close(); err != nil {
			t.Fatalf("close simulated prior-process stage: %v", err)
		}
		stage.file = nil
	}
	if stage.identityPin != nil {
		if err := stage.identityPin.Close(); err != nil {
			t.Fatalf("close simulated prior-process identity pin: %v", err)
		}
		stage.identityPin = nil
	}
	if stage.parent != nil {
		if err := stage.parent.Close(); err != nil {
			t.Fatalf("close simulated prior-process parent: %v", err)
		}
		stage.parent = nil
	}
	if stage.root != nil {
		if err := stage.root.Close(); err != nil {
			t.Fatalf("close simulated prior-process root: %v", err)
		}
		stage.root = nil
	}
}
