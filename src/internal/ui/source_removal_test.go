package ui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func sourceRemovalFixture(t testing.TB, dir, name string) deletionSource {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("captured source"), 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	source, err := captureDeletionSource(path, false)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func requireSourceRemovalBytes(t testing.TB, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || string(body) != want {
		t.Fatalf("%s bytes=%q error=%v, want %q", path, body, err, want)
	}
}

func TestSourceRemovalPreCancelledPreservesSourceAndOutput(t *testing.T) {
	dir := t.TempDir()
	source := sourceRemovalFixture(t, dir, "source")
	output := filepath.Join(dir, "ready-output")
	if err := os.WriteFile(output, []byte("ready output"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source.path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := (&App{}).cleanupOperationSources(ctx, operationInput{mode: "decrypt", delete: true}, &operationDeletionManifest{files: []deletionSource{source}}, operationResult{completed: true})
	if !result.completed || !result.cancelled || result.deleteFailed || result.err != nil {
		t.Fatalf("cleanup=%+v", result)
	}
	requireSourceRemovalBytes(t, source.path, "captured source")
	requireSourceRemovalBytes(t, output, "ready output")
}

func TestSourceRemovalDoesNotHideJoinedNotExist(t *testing.T) {
	dir := t.TempDir()
	source := sourceRemovalFixture(t, dir, "source")
	output := filepath.Join(dir, "ready-output")
	if err := os.WriteFile(output, []byte("ready output"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{operationSourceRemover: func(context.Context, deletionSource, bool) error {
		return errors.Join(os.ErrNotExist, errors.New("close failed"))
	}}
	result := a.cleanupOperationSources(context.Background(), operationInput{mode: "decrypt", delete: true}, &operationDeletionManifest{files: []deletionSource{source}}, operationResult{completed: true})
	if !result.completed || result.cancelled || !result.deleteFailed || result.err != nil {
		t.Fatalf("cleanup=%+v", result)
	}
	requireSourceRemovalBytes(t, source.path, "captured source")
	requireSourceRemovalBytes(t, output, "ready output")
}

func sourceRemovalHooks(t *testing.T) {
	t.Helper()
	open, stat, remove, close := sourceRemovalOpenRoot, sourceRemovalLstat, sourceRemovalRemove, sourceRemovalClose
	t.Cleanup(func() {
		sourceRemovalOpenRoot, sourceRemovalLstat, sourceRemovalRemove, sourceRemovalClose = open, stat, remove, close
	})
}

func TestSourceRemovalPinsParent(t *testing.T) {
	sourceRemovalHooks(t)
	dir := t.TempDir()
	parent := filepath.Join(dir, "selected")
	moved := filepath.Join(dir, "held-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	source := sourceRemovalFixture(t, parent, "source")
	other := sourceRemovalFixture(t, parent, "unselected")
	originalOpen := sourceRemovalOpenRoot
	parentMoved := false
	sourceRemovalOpenRoot = func(path string) (*os.Root, error) {
		root, err := originalOpen(path)
		if err != nil {
			return nil, err
		}
		if err := os.Rename(parent, moved); err != nil {
			heldInfo, heldErr := root.Stat(".")
			pathInfo, pathErr := os.Stat(parent)
			if heldErr != nil || pathErr != nil || !os.SameFile(heldInfo, pathInfo) {
				root.Close()
				t.Fatalf("failed parent move did not preserve selected parent: rename=%v held=%v path=%v", err, heldErr, pathErr)
			}
			if _, movedErr := os.Lstat(moved); !errors.Is(movedErr, os.ErrNotExist) {
				root.Close()
				t.Fatalf("failed parent move created another path: %v", movedErr)
			}
			requireSourceRemovalBytes(t, source.path, "captured source")
			t.Logf("native filesystem prevented movement of opened parent: %v; verifying normal deletion through held parent", err)
			return root, nil
		}
		parentMoved = true
		if err := os.Mkdir(parent, 0o700); err != nil {
			root.Close()
			t.Fatal(err)
		}
		if err := os.WriteFile(source.path, []byte("foreign source"), 0o600); err != nil {
			root.Close()
			t.Fatal(err)
		}
		return root, nil
	}
	result := (&App{}).cleanupOperationSources(context.Background(), operationInput{mode: "decrypt", delete: true}, &operationDeletionManifest{files: []deletionSource{source}}, operationResult{completed: true})
	if result.err != nil || result.cancelled || result.deleteFailed || !result.completed {
		t.Fatalf("cleanup=%+v", result)
	}
	if parentMoved {
		requireSourceRemovalBytes(t, source.path, "foreign source")
	} else {
		moved = parent
	}
	requireSourceRemovalBytes(t, filepath.Join(moved, filepath.Base(other.path)), "captured source")
	if _, err := os.Lstat(filepath.Join(moved, "source")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("captured source still exists: %v", err)
	}
}

func TestSourceRemovalErrorsPreserveOutputAndWarning(t *testing.T) {
	for _, name := range []string{"open", "stat", "remove", "close", "missing-stat", "missing-remove", "missing-open", "missing-close", "cancel-close", "cancel-after-stat", "changed", "nonempty-directory"} {
		t.Run(name, func(t *testing.T) {
			sourceRemovalHooks(t)
			dir := t.TempDir()
			source := sourceRemovalFixture(t, dir, "source")
			output := filepath.Join(dir, "ready-output")
			if err := os.WriteFile(output, []byte("ready output"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			originalOpen, originalStat, originalClose := sourceRemovalOpenRoot, sourceRemovalLstat, sourceRemovalClose
			wantDeleted, wantCancel, wantWarning := false, false, true
			directory := false
			var held *os.Root
			sourceRemovalOpenRoot = func(path string) (*os.Root, error) { r, e := originalOpen(path); held = r; return r, e }
			switch name {
			case "open":
				sourceRemovalOpenRoot = func(string) (*os.Root, error) { return nil, os.ErrPermission }
			case "stat":
				sourceRemovalLstat = func(*os.Root, string) (os.FileInfo, error) { return nil, os.ErrPermission }
			case "remove":
				sourceRemovalRemove = func(*os.Root, string) error { return os.ErrPermission }
			case "close":
				wantDeleted = true
				sourceRemovalClose = func(r *os.Root) error { return errors.Join(originalClose(r), os.ErrPermission) }
			case "missing-stat", "missing-close":
				if err := os.Remove(source.path); err != nil {
					t.Fatal(err)
				}
				wantDeleted = true
				wantWarning = name == "missing-close"
				if wantWarning {
					sourceRemovalClose = func(r *os.Root) error { return errors.Join(originalClose(r), os.ErrPermission) }
				}
			case "missing-remove":
				wantDeleted = true
				wantWarning = false
				sourceRemovalRemove = func(r *os.Root, n string) error {
					if err := r.Remove(n); err != nil {
						return err
					}
					return r.Remove(n)
				}
			case "missing-open":
				if err := os.Remove(source.path); err != nil {
					t.Fatal(err)
				}
				source.path = filepath.Join(dir, "missing-parent", "source")
				wantDeleted = true
				wantWarning = false
			case "cancel-close":
				wantCancel = true
				sourceRemovalLstat = func(r *os.Root, n string) (os.FileInfo, error) {
					info, e := originalStat(r, n)
					cancel()
					return info, e
				}
				sourceRemovalClose = func(r *os.Root) error { return errors.Join(originalClose(r), os.ErrPermission) }
			case "cancel-after-stat":
				wantCancel = true
				wantWarning = false
				sourceRemovalLstat = func(r *os.Root, n string) (os.FileInfo, error) {
					info, e := originalStat(r, n)
					cancel()
					return info, e
				}
			case "changed":
				if err := os.WriteFile(source.path, []byte("changed source"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "nonempty-directory":
				directory = true
				var err error
				source, err = captureDeletionSource(dir, true)
				if err != nil {
					t.Fatal(err)
				}
			}
			manifest := &operationDeletionManifest{files: []deletionSource{source}}
			if directory {
				manifest = &operationDeletionManifest{directories: []deletionSource{source}}
			}
			result := (&App{}).cleanupOperationSources(ctx, operationInput{mode: "decrypt", delete: true}, manifest, operationResult{completed: true, deleteFailed: false})
			if result.err != nil || !result.completed || result.cancelled != wantCancel || result.deleteFailed != wantWarning {
				t.Fatalf("cleanup=%+v want cancelled=%v warning=%v", result, wantCancel, wantWarning)
			}
			requireSourceRemovalBytes(t, output, "ready output")
			if !directory {
				if wantDeleted {
					if _, err := os.Lstat(source.path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("source remains: %v", err)
					}
				} else {
					want := "captured source"
					if name == "changed" {
						want = "changed source"
					}
					requireSourceRemovalBytes(t, source.path, want)
				}
			} else {
				requireSourceRemovalBytes(t, filepath.Join(dir, "source"), "captured source")
			}
			if held != nil {
				if _, err := held.Stat("."); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("parent retained after cleanup: %v", err)
				}
			}
		})
	}
}

func TestSourceRemovalCancellationBetweenSourcesKeepsWarning(t *testing.T) {
	dir := t.TempDir()
	first := sourceRemovalFixture(t, dir, "first")
	second := sourceRemovalFixture(t, dir, "second")
	third := sourceRemovalFixture(t, dir, "third")
	output := filepath.Join(dir, "ready-output")
	if err := os.WriteFile(output, []byte("ready output"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &App{operationSourceRemover: func(ctx context.Context, s deletionSource, d bool) error {
		if s.path == first.path {
			return os.ErrPermission
		}
		err := removeOperationSource(ctx, s, d)
		cancel()
		return err
	}}
	result := a.cleanupOperationSources(ctx, operationInput{mode: "decrypt", delete: true}, &operationDeletionManifest{files: []deletionSource{first, second, third}}, operationResult{completed: true})
	if !result.completed || !result.cancelled || !result.deleteFailed || result.err != nil {
		t.Fatalf("cleanup=%+v", result)
	}
	requireSourceRemovalBytes(t, first.path, "captured source")
	requireSourceRemovalBytes(t, third.path, "captured source")
	requireSourceRemovalBytes(t, output, "ready output")
	if _, err := os.Lstat(second.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second source remains: %v", err)
	}
}

func TestSourceRemovalUnchangedFileAndEmptyDirectory(t *testing.T) {
	for _, symlinkParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "symlink-parent"}[symlinkParent], func(t *testing.T) {
			dir := t.TempDir()
			parent := filepath.Join(dir, "parent")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if symlinkParent {
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(parent, alias); err != nil {
					t.Skipf("parent symlink unsupported: %v", err)
				}
				parent = alias
			}
			source := sourceRemovalFixture(t, parent, "source")
			empty := filepath.Join(parent, "empty")
			if err := os.Mkdir(empty, 0o750); err != nil {
				t.Fatal(err)
			}
			directory, err := captureDeletionSource(empty, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := removeOperationSource(context.Background(), source, false); err != nil {
				t.Fatal(err)
			}
			if err := removeOperationSource(context.Background(), directory, true); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{source.path, empty} {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("source remains %s: %v", p, err)
				}
			}
		})
	}
}

func TestSourceRemovalPreservesReplacedLeafAndSymlinkTarget(t *testing.T) {
	for _, kind := range []string{"symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source := sourceRemovalFixture(t, dir, "source")
			captured := filepath.Join(dir, "captured")
			if err := os.Rename(source.path, captured); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(dir, "foreign")
			if err := os.WriteFile(foreign, []byte("foreign bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				if err := os.Symlink(foreign, source.path); err != nil {
					t.Skipf("leaf symlink unsupported: %v", err)
				}
			} else {
				if err := os.Mkdir(source.path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			result := (&App{}).cleanupOperationSources(context.Background(), operationInput{mode: "decrypt", delete: true}, &operationDeletionManifest{files: []deletionSource{source}}, operationResult{completed: true})
			if result.err != nil || !result.completed || result.cancelled || !result.deleteFailed {
				t.Fatalf("cleanup=%+v", result)
			}
			requireSourceRemovalBytes(t, captured, "captured source")
			requireSourceRemovalBytes(t, foreign, "foreign bytes")
			if _, err := os.Lstat(source.path); err != nil {
				t.Fatalf("replacement removed: %v", err)
			}
		})
	}
}
