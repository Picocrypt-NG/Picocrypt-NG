package fileops

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnpackOwnedDirectoryIdentityIsNotReplaced(t *testing.T) {
	t.Run("first evidence is retained", func(t *testing.T) {
		base := t.TempDir()
		root, err := os.OpenRoot(base)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if err := root.Mkdir("owned", 0o700); err != nil {
			t.Fatal(err)
		}
		first, err := root.Lstat("owned")
		if err != nil {
			t.Fatal(err)
		}
		dirs := &ownedUnpackDirs{}
		dir := ownedUnpackDir{targetName: "owned", outPath: filepath.Join(base, "owned"), info: first}
		if err := dirs.record(dir); err != nil {
			t.Fatal(err)
		}
		if err := dirs.record(dir); err != nil {
			t.Fatalf("same identity repeat: %v", err)
		}
		if len(dirs.entries) != 1 {
			t.Fatalf("same identity repeat is not idempotent: %d", len(dirs.entries))
		}
		if err := os.Rename(filepath.Join(base, "owned"), filepath.Join(base, "moved")); err != nil {
			t.Fatal(err)
		}
		if err := root.Mkdir("owned", 0o700); err != nil {
			t.Fatal(err)
		}
		replacement, err := root.Lstat("owned")
		if err != nil {
			t.Fatal(err)
		}
		if err := dirs.record(ownedUnpackDir{targetName: "owned", outPath: dir.outPath, info: replacement}); !errors.Is(err, ErrUnpackCleanupIncomplete) {
			t.Errorf("record accepted replacement identity: %v", err)
		}
		if !os.SameFile(first, dirs.entries[0].info) {
			t.Error("replacement overwrote first owned-directory evidence")
		}
		if err := dirs.cleanup(root); !errors.Is(err, ErrUnpackCleanupIncomplete) {
			t.Errorf("changed identity did not retain cleanup uncertainty: %v", err)
		}
		if _, err := root.Lstat("owned"); err != nil {
			t.Errorf("foreign replacement was removed: %v", err)
		}
		if _, err := root.Lstat("moved"); err != nil {
			t.Errorf("relocated owned directory was removed: %v", err)
		}
	})
	for _, mode := range []string{"legacy", "typed"} {
		for _, replacement := range []bool{false, true} {
			t.Run(mode+"/"+map[bool]string{false: "missing", true: "replacement"}[replacement], func(t *testing.T) {
				base := t.TempDir()
				archive := filepath.Join(base, "source.zip")
				createStoredZipForUnpackStagingTest(t, archive, "nested/payload.txt", []byte("payload"))
				source, err := os.ReadFile(archive)
				if err != nil {
					t.Fatal(err)
				}
				out := filepath.Join(base, "out")
				if err := os.Mkdir(out, 0o700); err != nil {
					t.Fatal(err)
				}
				owned := filepath.Join(out, "nested")
				moved := filepath.Join(out, "relocated-owned")
				opts := UnpackOptions{ZipPath: archive, ExtractDir: out, AvailableSpace: func(string) (int64, error) {
					if err := os.Rename(owned, moved); err != nil {
						t.Fatal(err)
					}
					if replacement {
						if err := os.Mkdir(owned, 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(owned, "foreign.txt"), []byte("foreign"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					return 1 << 20, nil
				}}
				var resultErr error
				if mode == "typed" {
					result := UnpackWithResult(opts)
					requireUnpackState(t, result, UnpackStateNotPublished)
					resultErr = result
				} else {
					resultErr = Unpack(opts)
				}
				if !errors.Is(resultErr, ErrUnpackCleanupIncomplete) {
					t.Errorf("two-pass extractor lost changed ownership: %v", resultErr)
				}
				if _, err := os.Lstat(filepath.Join(owned, "payload.txt")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("extractor published after directory identity changed: %v", err)
				}
				if _, err := os.Stat(moved); err != nil {
					t.Errorf("relocated ownership evidence lost: %v", err)
				}
				if replacement {
					requireUnpackFileBytes(t, filepath.Join(owned, "foreign.txt"), []byte("foreign"))
				} else if _, err := os.Lstat(owned); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("missing owned name was recreated: %v", err)
				}
				requireUnpackFileBytes(t, archive, source)
				requireNoUnpackStages(t, out)
			})
		}
	}
}

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
