//go:build linux && !android

package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	boundedListingPayload   = "complete owned output"
	boundedListingUnrelated = "selected input and unrelated user bytes must survive"
)

// The ordinary-only phase protects large legitimate destination directories
// from a count cap. The orphan phase protects truthful completion across batches.
func TestDesktopRecoveryBoundedListingPreservesCrowdedParent(t *testing.T) {
	parent := t.TempDir()
	unrelated := writeBoundedListingUnrelated(t, parent, 1025)
	state, err := CleanupOrphanedStages(parent, nil)
	if err != nil || state != CleanupJournalAbsent {
		t.Fatalf("crowded ordinary parent = %v, %v; want absent", state, err)
	}

	var privateDirectories []string
	for index := range 257 {
		stage := createBoundedListingOrphan(t, parent, fmt.Sprintf("output-%04d", index))
		privateDirectories = append(privateDirectories, filepath.Dir(stage))
	}
	state, err = CleanupOrphanedStages(parent, nil)
	removed, residual := false, false
	for _, path := range privateDirectories {
		_, inspectErr := os.Lstat(path)
		switch {
		case errors.Is(inspectErr, os.ErrNotExist):
			removed = true
		case inspectErr == nil:
			residual = true
		default:
			t.Fatalf("inspect expected private object: %v", inspectErr)
		}
	}
	if err == nil {
		if state != CleanupJournalCleaned || residual {
			t.Fatalf("cleanup = %v, %v, residual=%v; success must retire every orphan", state, err, residual)
		}
	} else if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) || !removed || !residual {
		t.Fatalf("cleanup = %v, %v, removed=%v, residual=%v; conservative refusal requires observed progress and residue", state, err, removed, residual)
	}
	requireBoundedListingUnrelated(t, unrelated)
}

func TestDesktopRecoveryBoundedListingPreservesLiveAndIncompletePrecedence(t *testing.T) {
	for _, blocker := range []string{"none", "foreign", "protected"} {
		t.Run(blocker, func(t *testing.T) {
			parent := t.TempDir()
			unrelated := writeBoundedListingUnrelated(t, parent, 513)
			var protected []*os.File
			var preserved map[string][]byte
			var identities map[string]os.FileInfo
			if blocker != "none" {
				for index := range 129 {
					createBoundedListingOrphan(t, parent, fmt.Sprintf("output-%04d", index))
				}
				preserved = make(map[string][]byte)
				identities = make(map[string]os.FileInfo)
				if blocker == "foreign" {
					path := filepath.Join(parent, stageNamePrefix+"foreign-user-object")
					data := []byte("foreign user bytes grant no cleanup authority")
					if err := os.WriteFile(path, data, 0o600); err != nil {
						t.Fatal(err)
					}
					preserved[path] = data
				} else {
					path := createBoundedListingOrphan(t, parent, "protected-output")
					file, err := os.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = file.Close() })
					protected = append(protected, file)
					preserved[path] = []byte(boundedListingPayload)
					journal := filepath.Join(filepath.Dir(path), cleanupJournalName)
					data, err := os.ReadFile(journal)
					if err != nil {
						t.Fatal(err)
					}
					preserved[journal] = data
				}
				for path := range preserved {
					info, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					identities[path] = info
				}
			}

			// Start the live child after fixture creation, inside its existing timeout.
			live, kill := startDesktopCleanupChild(t, parent, "private stage", false)
			liveInfo, err := os.Lstat(live.Stage)
			if err != nil {
				t.Fatal(err)
			}
			state, err := CleanupOrphanedStages(parent, protected)
			if blocker == "none" {
				if err != nil || state != CleanupJournalActive {
					t.Fatalf("live lease in crowded parent = %v, %v; want active", state, err)
				}
			} else if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("unproven/protected residue with live lease = %v, %v; incomplete must take precedence", state, err)
			}
			requireFileBytes(t, live.Stage, []byte(boundedListingPayload))
			requireBoundedListingIdentity(t, live.Stage, liveInfo)
			for path, data := range preserved {
				requireFileBytes(t, path, data)
				requireBoundedListingIdentity(t, path, identities[path])
			}
			requireBoundedListingUnrelated(t, unrelated)
			kill()
			if blocker == "none" {
				state, err = CleanupOrphanedStages(parent, nil)
				if err != nil || state != CleanupJournalCleaned {
					t.Fatalf("released live lease = %v, %v; want cleaned", state, err)
				}
				requireAbsent(t, filepath.Dir(live.Stage))
				requireBoundedListingUnrelated(t, unrelated)
			}
		})
	}
}

// Removing the inspect-only gate would destroy a real orphan here. Moving it
// above the live-lease return would turn a proven active operation into failure.
func TestDesktopRecoveryInspectionNeverDeletesValidResidual(t *testing.T) {
	for _, kind := range []string{"orphan", "live", "published journal only"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			var stagePath, objectPath string
			if kind == "orphan" {
				stagePath = createBoundedListingOrphan(t, parent, "output")
				objectPath = stagePath
			} else {
				boundary := "private stage"
				if kind == "published journal only" {
					boundary = "after rename"
				}
				child, kill := startDesktopCleanupChild(t, parent, boundary, true)
				stagePath, objectPath = child.Stage, child.Stage
				if kind == "published journal only" {
					kill()
					objectPath = child.Target
				}
			}
			private := filepath.Dir(stagePath)
			journal := filepath.Join(private, cleanupJournalName)
			journalBytes, err := os.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			journalInfo, err := os.Lstat(journal)
			if err != nil {
				t.Fatal(err)
			}
			objectInfo, err := os.Lstat(objectPath)
			if err != nil {
				t.Fatal(err)
			}
			privateInfo, err := os.Lstat(private)
			if err != nil {
				t.Fatal(err)
			}
			root, err := fileops.OpenRootNoSymlink(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			handle, err := root.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
			identity, err := handle.Stat()
			if err != nil {
				t.Fatal(err)
			}
			cleanup := orphanCleanup{root: root, parent: handle, identity: identity, path: parent, operations: nativeJournalCleanupOperations()}
			state, err := cleanup.directory(filepath.Base(private), false)
			if kind == "live" {
				if err != nil || state != CleanupJournalActive {
					t.Fatalf("inspect live residue = %v, %v; want active", state, err)
				}
			} else if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("inspect released residue = %v, %v; want incomplete", state, err)
			}
			requireFileBytes(t, objectPath, []byte(boundedListingPayload))
			requireBoundedListingIdentity(t, objectPath, objectInfo)
			requireFileBytes(t, journal, journalBytes)
			requireBoundedListingIdentity(t, journal, journalInfo)
			requireBoundedListingIdentity(t, private, privateInfo)
			if kind == "published journal only" {
				state, err = CleanupOrphanedStages(parent, nil)
				if err != nil || state != CleanupJournalCleaned {
					t.Fatalf("journal-only recovery = %v, %v; want cleaned", state, err)
				}
				requireAbsent(t, private)
				requireFileBytes(t, objectPath, []byte(boundedListingPayload))
				requireBoundedListingIdentity(t, objectPath, objectInfo)
			}
		})
	}
}

func createBoundedListingOrphan(t *testing.T, parent, target string) string {
	t.Helper()
	stage, err := Create(filepath.Join(parent, target), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeStageHandlesWithoutCleanup(t, stage) })
	persistLeasedTestJournal(t, stage)
	if _, err := stage.File().Write([]byte(boundedListingPayload)); err != nil {
		t.Fatal(err)
	}
	path := stage.stagePath
	closeStageHandlesWithoutCleanup(t, stage)
	return path
}

func writeBoundedListingUnrelated(t *testing.T, parent string, count int) map[string]os.FileInfo {
	t.Helper()
	identities := make(map[string]os.FileInfo, count)
	for index := range count {
		path := filepath.Join(parent, fmt.Sprintf("unrelated-%04d-%s", index, strings.Repeat("u", 160)))
		if err := os.WriteFile(path, []byte(boundedListingUnrelated), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		identities[path] = info
	}
	return identities
}

func requireBoundedListingUnrelated(t *testing.T, identities map[string]os.FileInfo) {
	t.Helper()
	for path, info := range identities {
		requireFileBytes(t, path, []byte(boundedListingUnrelated))
		requireBoundedListingIdentity(t, path, info)
	}
}

func requireBoundedListingIdentity(t *testing.T, path string, before os.FileInfo) {
	t.Helper()
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("preserved object identity changed at %s: %v", path, err)
	}
}
