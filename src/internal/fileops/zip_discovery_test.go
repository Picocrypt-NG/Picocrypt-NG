package fileops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A resource refusal must happen before directory children are accumulated or
// emitted; discovery is read-only and cannot damage either source or output.
func TestWalkZIPInputsRejectsDirectoryBeforeChildrenAndPreservesFiles(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original.txt")
	occupied := filepath.Join(root, "occupied.pcv")
	for _, path := range []string{original, occupied} {
		if err := os.WriteFile(path, []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	budget := NewZIPResourceBudget()
	if err := budget.Reserve(budget.LimitBytes() - 64); err != nil {
		t.Fatal(err)
	}
	var visited []string
	err := WalkZIPInputs(context.Background(), root, budget, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		visited = append(visited, path)
		return nil
	})
	if !errors.Is(err, ErrZIPMetadataLimit) {
		t.Fatalf("discovery error = %v; want resource refusal", err)
	}
	if len(visited) != 0 {
		t.Fatalf("visited before directory admission = %v", visited)
	}
	for _, path := range []string{original, occupied} {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "unchanged" {
			t.Fatalf("discovery changed %s: %q, %v", path, body, err)
		}
	}
	if got := budget.CurrentBytes(); got != budget.LimitBytes()-64 {
		t.Fatalf("failed walk retained %d temporary bytes", got-(budget.LimitBytes()-64))
	}
}

func TestWalkZIPInputsCancelledBeforeVisiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	visited := false
	err := WalkZIPInputs(ctx, t.TempDir(), NewZIPResourceBudget(), func(string, os.FileInfo, error) error { visited = true; return nil })
	if !errors.Is(err, context.Canceled) || visited {
		t.Fatalf("walk = %v, visited=%v; cancelled discovery must not visit", err, visited)
	}
}

func TestWalkZIPInputsLexicalOrderSymlinksAndCallbackCancellation(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"z", "middle"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, leaf := range []string{"z/last", "middle/inside", "a"} {
		if err := os.WriteFile(filepath.Join(root, leaf), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "b-link")
	if err := os.Symlink(filepath.Join(root, "z"), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	want := []string{root, filepath.Join(root, "a"), link, filepath.Join(root, "middle"), filepath.Join(root, "middle", "inside"), filepath.Join(root, "z"), filepath.Join(root, "z", "last")}
	budget := NewZIPResourceBudget()
	var got []string
	err := WalkZIPInputs(context.Background(), root, budget, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		got = append(got, path)
		return nil
	})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("walk = %v, paths=%v; want %v", err, got, want)
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("walk retained temporary reservation")
	}
	got = nil
	err = WalkZIPInputs(context.Background(), link, budget, func(path string, info os.FileInfo, err error) error { got = append(got, path); return err })
	if err != nil || !reflect.DeepEqual(got, []string{link}) {
		t.Fatalf("symlink root followed: %v, %v", err, got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	got = nil
	err = WalkZIPInputs(ctx, root, budget, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		got = append(got, path)
		if len(got) == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || len(got) != 2 {
		t.Fatalf("cancellation = %v, visited %v", err, got)
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("cancelled walk retained temporary reservation")
	}
}

func TestWalkZIPInputsBoundsCollectedDirectoryNames(t *testing.T) {
	root := t.TempDir()
	for i := range 600 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file-%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	budget := NewZIPResourceBudget()
	baseline := budget.LimitBytes() - (160 << 10)
	if err := budget.Reserve(baseline); err != nil {
		t.Fatal(err)
	}
	visited := false
	err := WalkZIPInputs(context.Background(), root, budget, func(string, os.FileInfo, error) error { visited = true; return nil })
	if !errors.Is(err, ErrZIPMetadataLimit) || visited {
		t.Fatalf("directory admitted beyond remaining budget: %v, visited=%v", err, visited)
	}
	if budget.CurrentBytes() != baseline {
		t.Fatal("directory-name refusal retained scratch")
	}
}

func TestGlobZIPInputsPreservesLexicalPatternsAndRejectsBudgetBeforeMatches(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"b", "a"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, leaf := range []string{"z.txt", "first.txt", "ignored.bin"} {
			if err := os.WriteFile(filepath.Join(root, dir, leaf), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	pattern := filepath.Join(root, "*", "*.txt")
	want := []string{filepath.Join(root, "a", "first.txt"), filepath.Join(root, "a", "z.txt"), filepath.Join(root, "b", "first.txt"), filepath.Join(root, "b", "z.txt")}
	var got []string
	budget := NewZIPResourceBudget()
	err := GlobZIPInputs(context.Background(), pattern, budget, func(path string) error { got = append(got, path); return nil })
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("glob=%v paths=%v; want %v", err, got, want)
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("glob retained discovery scratch")
	}
	if err := budget.Reserve(budget.LimitBytes() - 64); err != nil {
		t.Fatal(err)
	}
	got = nil
	err = GlobZIPInputs(context.Background(), pattern, budget, func(path string) error { got = append(got, path); return nil })
	if !errors.Is(err, ErrZIPMetadataLimit) || len(got) != 0 {
		t.Fatalf("glob=%v paths=%v; resource refusal must precede matches", err, got)
	}
}

func TestGlobZIPInputsCancellationAndMalformedPatterns(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var got []string
	err := GlobZIPInputs(ctx, filepath.Join(root, "*"), NewZIPResourceBudget(), func(path string) error { got = append(got, path); cancel(); return nil })
	if !errors.Is(err, context.Canceled) || len(got) != 1 {
		t.Fatalf("cancelled glob=%v paths=%v", err, got)
	}
	err = GlobZIPInputs(context.Background(), filepath.Join(root, "["), NewZIPResourceBudget(), func(string) error { t.Fatal("malformed pattern emitted a match"); return nil })
	if !errors.Is(err, filepath.ErrBadPattern) {
		t.Fatalf("malformed pattern=%v", err)
	}
}

func TestWalkZIPInputsSkipDirectoryAndSkipRemainingFileSiblings(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, leaf := range []string{"a/first", "a/second", "b/kept"} {
		if err := os.WriteFile(filepath.Join(root, leaf), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		skip string
		want []string
	}{
		{filepath.Join(root, "a"), []string{root, filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "b", "kept")}},
		{filepath.Join(root, "a", "first"), []string{root, filepath.Join(root, "a"), filepath.Join(root, "a", "first"), filepath.Join(root, "b"), filepath.Join(root, "b", "kept")}},
	}
	for _, tc := range cases {
		var got []string
		err := WalkZIPInputs(context.Background(), root, NewZIPResourceBudget(), func(path string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			got = append(got, path)
			if path == tc.skip {
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("SkipDir at %s: %v paths=%v want=%v", tc.skip, err, got, tc.want)
		}
	}
}

func TestZIPDiscoveryPanicRetiresTemporaryPathAndDirectoryCharges(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"walk", "glob"} {
		t.Run(method, func(t *testing.T) {
			budget := NewZIPResourceBudget()
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("callback panic was swallowed")
					}
				}()
				if method == "walk" {
					_ = WalkZIPInputs(context.Background(), root, budget, func(_ string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						if info.Mode().IsRegular() {
							panic("callback")
						}
						return nil
					})
				} else {
					_ = GlobZIPInputs(context.Background(), filepath.Join(root, "*"), budget, func(string) error { panic("callback") })
				}
			}()
			if budget.CurrentBytes() != 0 {
				t.Fatalf("callback panic retained %d temporary discovery bytes", budget.CurrentBytes())
			}
		})
	}
}

func TestGlobZIPInputsCancellationAfterLastMatchRemainsTerminal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "only"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{filepath.Join(root, "only"), filepath.Join(root, "*")} {
		ctx, cancel := context.WithCancel(context.Background())
		err := GlobZIPInputs(ctx, pattern, NewZIPResourceBudget(), func(string) error { cancel(); return nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("last match cancellation for %s became success: %v", pattern, err)
		}
	}
}

func TestWalkZIPInputsWrappedSkipCannotHideCallbackFailure(t *testing.T) {
	wrapped := fmt.Errorf("callback failure: %w", filepath.SkipDir)
	err := WalkZIPInputs(context.Background(), t.TempDir(), NewZIPResourceBudget(), func(string, os.FileInfo, error) error { return wrapped })
	if !errors.Is(err, wrapped) {
		t.Fatalf("wrapped callback failure became a successful skipped directory: %v", err)
	}
}

func TestGlobZIPInputsPreservesUncleanDirectoryTraversal(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"present", "other", "other/nested"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"unselected.txt", "other/selected.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	patterns := []string{"missing/../*.txt", "present/../*.txt", "*/../*.txt", "[pm]*/../*.txt", "present//../*.txt"}
	if err := os.Symlink(filepath.Join(root, "other/nested"), filepath.Join(root, "link")); err == nil {
		patterns = append(patterns, "link/../*.txt")
	}
	for _, relative := range patterns {
		t.Run(relative, func(t *testing.T) {
			pattern := root + string(filepath.Separator) + filepath.FromSlash(relative)
			want, err := filepath.Glob(pattern)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			budget := NewZIPResourceBudget()
			err = GlobZIPInputs(context.Background(), pattern, budget, func(path string) error { got = append(got, path); return nil })
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("glob=%v paths=%v; standard paths=%v", err, got, want)
			}
			if budget.CurrentBytes() != 0 {
				t.Fatal("glob retained scratch")
			}
		})
	}
}
