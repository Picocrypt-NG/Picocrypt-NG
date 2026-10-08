//go:build linux || darwin

package pcv3publication

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A pinned directory still accepts publication after its selected pathname is
// moved. That committed output must survive, but cannot authorize source deletion.
func TestPublicationParentRelocationIsIndeterminate(t *testing.T) {
	boundaries := []string{"atomic publication", "directory sync"}
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		boundaries = append(boundaries, "journal retirement", "journaled directory sync failure")
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			base := t.TempDir()
			selected := filepath.Join(base, "selected")
			moved := filepath.Join(base, "relocated")
			if err := os.Mkdir(selected, 0o700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(base, "source")
			if err := os.WriteFile(source, []byte("original source"), 0o600); err != nil {
				t.Fatal(err)
			}
			relocated := false
			relocate := func() {
				t.Helper()
				if err := os.Rename(selected, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(selected, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(selected, "foreign"), []byte("foreign directory sentinel"), 0o640); err != nil {
					t.Fatal(err)
				}
				relocated = true
			}
			operations := nativeOperations()
			atomic := operations.atomicPublish
			operations.atomicPublish = func(parent *os.File, old, target string, policy Policy) error {
				if boundary == "atomic publication" {
					relocate()
				}
				return atomic(parent, old, target, policy)
			}
			publishing := false
			syncs := 0
			syncDirectory := operations.syncDirectory
			operations.syncDirectory = func(parent *os.File) error {
				if err := syncDirectory(parent); err != nil {
					return err
				}
				if publishing {
					syncs++
					if boundary == "directory sync" || boundary == "journal retirement" && syncs == 2 || boundary == "journaled directory sync failure" && syncs == 1 {
						relocate()
					}
					if boundary == "journaled directory sync failure" && syncs == 1 {
						return errors.New("directory sync failed after relocation")
					}
				}
				return nil
			}
			stage, err := createWithOperations(filepath.Join(selected, "output.pcv"), []string{source}, PolicyNoReplace, operations)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stage.Cleanup() })
			if boundary == "journal retirement" || boundary == "journaled directory sync failure" {
				if err := stage.PersistCleanupJournal(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := stage.File().Write([]byte("complete owned output")); err != nil {
				t.Fatal(err)
			}
			publishing = true
			result := stage.Publish(context.Background())
			if !relocated {
				t.Fatal("publication did not reach the relocation boundary")
			}
			if result.State() != StatePublicationIndeterminate {
				t.Fatalf("relocated publication state = %s; want publication-indeterminate", result.State())
			}
			if err := stage.Cleanup(); err != nil {
				t.Fatalf("closing a preserved committed output: %v", err)
			}
			if stage.Publish(context.Background()) != result {
				t.Fatal("repeat publication changed the terminal classification")
			}
			requireFileBytes(t, filepath.Join(moved, "output.pcv"), []byte("complete owned output"))
			requireFileBytes(t, filepath.Join(selected, "foreign"), []byte("foreign directory sentinel"))
			requireFileBytes(t, source, []byte("original source"))
			entries, err := os.ReadDir(selected)
			if err != nil || len(entries) != 1 || entries[0].Name() != "foreign" {
				t.Fatalf("replacement directory changed: %v, %v", entries, err)
			}
		})
	}
}
