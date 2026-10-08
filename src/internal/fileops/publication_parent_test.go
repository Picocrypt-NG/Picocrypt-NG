package fileops

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagedFileCleanupReportsMissingOrReplacedOwnedStage(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "replaced"}[replacement], func(t *testing.T) {
			directory := t.TempDir()
			stage, err := CreateSiblingTemp(filepath.Join(directory, "output"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stage.Cleanup() })
			if _, err := stage.File().Write([]byte("owned stage")); err != nil {
				t.Fatal(err)
			}
			originalPath := stage.Path()
			moved := filepath.Join(directory, "relocated-owned")
			if err := os.Rename(originalPath, moved); err != nil {
				if windowsPreventedOpenHandleRename(err) {
					t.Skipf("platform prevented open-stage relocation: %v", err)
				}
				t.Fatal(err)
			}
			if replacement {
				if err := os.WriteFile(originalPath, []byte("foreign replacement"), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			cleanupErr := stage.Cleanup()
			if cleanupErr == nil || !strings.Contains(cleanupErr.Error(), originalPath) {
				t.Fatalf("unproven stage absence lost cleanup warning/path: %v", cleanupErr)
			}
			if stage.Path() != originalPath || stage.stageName == "" {
				t.Fatal("uncertain cleanup discarded the original stage metadata")
			}
			if stage.Cleanup() == nil {
				t.Fatal("repeated cleanup discarded the uncertainty")
			}
			requireUnpackFileBytes(t, moved, []byte("owned stage"))
			if replacement {
				requireUnpackFileBytes(t, originalPath, []byte("foreign replacement"))
			}
		})
	}
}

func TestStagedFileCommitPreservesStableSymlinkParent(t *testing.T) {
	base := t.TempDir()
	actual := filepath.Join(base, "actual")
	selected := filepath.Join(base, "selected")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, selected); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	stage, err := CreateSiblingTemp(filepath.Join(selected, "output"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stage.Cleanup() })
	if _, err := stage.File().Write([]byte("legacy output")); err != nil {
		t.Fatal(err)
	}
	if err := stage.Commit(); err != nil {
		t.Fatalf("stable symlink-selected parent refused: %v", err)
	}
	requireUnpackFileBytes(t, filepath.Join(actual, "output"), []byte("legacy output"))
}

func TestStagedFileCommitParentRelocationPreservesPublishedOutputAndReturnsError(t *testing.T) {
	base := t.TempDir()
	selected := filepath.Join(base, "selected")
	moved := filepath.Join(base, "relocated")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := CreateSiblingTemp(filepath.Join(selected, "output"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stage.Cleanup() })
	if _, err := stage.File().Write([]byte("complete legacy output")); err != nil {
		t.Fatal(err)
	}
	originalRename := stagedFileRenameFn
	stagedFileRenameFn = func(root *os.Root, old, target string) error {
		if err := os.Rename(selected, moved); err != nil {
			if windowsPreventedOpenHandleRename(err) {
				t.Skipf("platform prevented pinned-parent relocation: %v", err)
			}
			t.Fatal(err)
		}
		if err := os.Mkdir(selected, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(selected, "foreign"), []byte("foreign sentinel"), 0o640); err != nil {
			t.Fatal(err)
		}
		return originalRename(root, old, target)
	}
	t.Cleanup(func() { stagedFileRenameFn = originalRename })
	if err := stage.Commit(); err == nil {
		t.Fatal("relocated legacy publication returned ordinary success")
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("closing a preserved committed output: %v", err)
	}
	requireUnpackFileBytes(t, filepath.Join(moved, "output"), []byte("complete legacy output"))
	requireUnpackFileBytes(t, filepath.Join(selected, "foreign"), []byte("foreign sentinel"))
	if _, err := os.Stat(filepath.Join(selected, "output")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication wrote into replacement parent: %v", err)
	}
}

func TestUnpackParentRelocationAfterSyncIsIndeterminate(t *testing.T) {
	for _, boundary := range []string{"directory sync", "directory sync failure", "root close"} {
		t.Run(boundary, func(t *testing.T) {
			base := t.TempDir()
			archive := filepath.Join(base, "source.zip")
			createStoredZipForUnpackStagingTest(t, archive, "payload.txt", []byte("complete extracted plaintext"))
			selected := filepath.Join(base, "selected")
			moved := filepath.Join(base, "relocated")
			if err := os.Mkdir(selected, 0o700); err != nil {
				t.Fatal(err)
			}
			relocated := false
			relocate := func() {
				t.Helper()
				if err := os.Rename(selected, moved); err != nil {
					if windowsPreventedOpenHandleRename(err) {
						t.Skipf("platform prevented pinned-parent relocation: %v", err)
					}
					t.Fatal(err)
				}
				if err := os.Mkdir(selected, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(selected, "foreign"), []byte("foreign sentinel"), 0o640); err != nil {
					t.Fatal(err)
				}
				relocated = true
			}
			originalSync := unpackDirectorySyncFn
			originalClose := unpackCloseRootFn
			syncFailure := errors.New("TEST ONLY extraction-directory sync failure")
			unpackDirectorySyncFn = func(parent *os.File) error {
				err := originalSync(parent)
				if boundary == "directory sync failure" {
					err = errors.Join(err, syncFailure)
				}
				if boundary == "directory sync" || boundary == "directory sync failure" {
					relocate()
				}
				return err
			}
			unpackCloseRootFn = func(root *os.Root) error {
				err := originalClose(root)
				if boundary == "root close" {
					relocate()
				}
				return err
			}
			t.Cleanup(func() {
				unpackDirectorySyncFn = originalSync
				unpackCloseRootFn = originalClose
			})
			result := UnpackWithResult(UnpackOptions{ZipPath: archive, ExtractDir: selected})
			if !relocated {
				t.Fatal("extraction did not reach relocation boundary")
			}
			requireUnpackState(t, result, UnpackStatePublicationIndeterminate)
			if boundary == "directory sync failure" && !errors.Is(result, syncFailure) {
				t.Fatalf("parent relocation discarded directory-sync failure: %v", result)
			}
			requireUnpackFileBytes(t, filepath.Join(moved, "payload.txt"), []byte("complete extracted plaintext"))
			requireUnpackFileBytes(t, filepath.Join(selected, "foreign"), []byte("foreign sentinel"))
			if _, err := os.Stat(archive); err != nil {
				t.Fatalf("extraction removed source archive: %v", err)
			}
			if _, err := os.Stat(filepath.Join(selected, "payload.txt")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("extraction wrote into replacement parent: %v", err)
			}
		})
	}
}

func TestUnpackStageCleanupReportsMissingOrReplacedIdentity(t *testing.T) {
	for _, mode := range []string{"legacy", "typed"} {
		for _, replacement := range []bool{false, true} {
			t.Run(mode+"/"+map[bool]string{false: "missing", true: "replaced"}[replacement], func(t *testing.T) {
				directory := t.TempDir()
				archive := filepath.Join(directory, "source.zip")
				createStoredZipForUnpackStagingTest(t, archive, "payload.txt", []byte("owned extracted plaintext"))
				extractDir := filepath.Join(directory, "out")
				if err := os.Mkdir(extractDir, 0o700); err != nil {
					t.Fatal(err)
				}
				moved := filepath.Join(extractDir, "relocated-owned")
				var stagePath string
				originalSync := unpackStageSyncFn
				unpackStageSyncFn = func(file *os.File) error {
					if err := originalSync(file); err != nil {
						return err
					}
					stagePath = file.Name()
					if err := os.Rename(stagePath, moved); err != nil {
						if windowsPreventedOpenHandleRename(err) {
							t.Skipf("platform prevented open-stage relocation: %v", err)
						}
						t.Fatal(err)
					}
					if replacement {
						if err := os.WriteFile(stagePath, []byte("foreign replacement"), 0o640); err != nil {
							t.Fatal(err)
						}
					}
					return nil
				}
				t.Cleanup(func() { unpackStageSyncFn = originalSync })
				opts := UnpackOptions{ZipPath: archive, ExtractDir: extractDir}
				var cleanupErr error
				if mode == "typed" {
					result := UnpackWithResult(opts)
					requireUnpackState(t, result, UnpackStatePublicationIndeterminate)
					cleanupErr = result
				} else {
					cleanupErr = Unpack(opts)
				}
				if !errors.Is(cleanupErr, ErrUnpackCleanupIncomplete) {
					t.Fatalf("unproven stage cleanup = %v; want cleanup-incomplete", cleanupErr)
				}
				requireUnpackFileBytes(t, moved, []byte("owned extracted plaintext"))
				if replacement {
					requireUnpackFileBytes(t, stagePath, []byte("foreign replacement"))
				}
				if _, err := os.Stat(filepath.Join(extractDir, "payload.txt")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("lost owned-stage identity still published output: %v", err)
				}
			})
		}
	}
}
