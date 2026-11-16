package fileops

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Schedule the same real-filesystem interleaving as a concurrent rename at the
// cancellation checkpoint immediately after classification, before enumeration.
type zipDirectorySwapContext struct {
	context.Context
	calls int
	swap  func()
}

func (ctx *zipDirectorySwapContext) Err() error {
	ctx.calls++
	if ctx.calls == 2 {
		ctx.swap()
	}
	return ctx.Context.Err()
}

func TestWalkZIPInputsRejectsDirectorySubstitutionBeforeChildSelection(t *testing.T) {
	for _, timing := range []string{"before_enumeration", "before_child_lookup"} {
		t.Run(timing, func(t *testing.T) {
			dir := t.TempDir()
			selected, outside := filepath.Join(dir, "selected"), filepath.Join(dir, "outside")
			for _, path := range []string{selected, outside} {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for path, text := range map[string]string{filepath.Join(selected, "document.txt"): "selected", filepath.Join(outside, "document.txt"): "outside secret"} {
				if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			swapped := false
			swap := func() {
				if err := os.Rename(selected, selected+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, selected); err != nil {
					t.Fatal(err)
				}
				swapped = true
			}
			ctx := context.Background()
			if timing == "before_enumeration" {
				ctx = &zipDirectorySwapContext{Context: ctx, swap: swap}
			}
			var selectedFiles []string
			err := WalkZIPInputs(ctx, selected, NewZIPResourceBudget(), func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if timing == "before_child_lookup" && path == selected {
					swap()
				}
				if info.Mode().IsRegular() {
					selectedFiles = append(selectedFiles, path)
				}
				return nil
			})
			if !swapped {
				t.Fatal("directory substitution did not run")
			}
			if err == nil || len(selectedFiles) != 0 {
				t.Fatalf("directory substitution admitted child selection: err=%v files=%v", err, selectedFiles)
			}
			body, readErr := os.ReadFile(filepath.Join(outside, "document.txt"))
			if readErr != nil || string(body) != "outside secret" {
				t.Fatalf("outside source changed: %q, %v", body, readErr)
			}
		})
	}
}

func TestZIPInputRejectsDirectorySubstitutionBeforeArchiveRead(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "zip", true: "encrypted_stage"}[encrypted], func(t *testing.T) {
			dir := t.TempDir()
			selected := filepath.Join(dir, "selected")
			if err := os.Mkdir(selected, 0o700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(selected, "document.txt")
			if err := os.WriteFile(source, []byte("selected contents"), 0o600); err != nil {
				t.Fatal(err)
			}
			identity, err := CaptureZIPInput(source, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(selected, selected+".original"); err != nil {
				t.Fatal(err)
			}
			// Even the same captured inode may not authorize a substituted directory.
			if err := os.Symlink(selected+".original", selected); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "result.zip")
			if encrypted {
				owner, archiveErr := CreateTempZip(context.Background(), TempZipOptions{Files: []string{source}, InputIdentities: []ZIPInputIdentity{identity}, RootDir: selected, NearPath: output, MaxPhysicalBytes: 1 << 20})
				if owner != nil {
					_ = owner.Close()
				}
				err = archiveErr
			} else {
				err = CreateZip(ZipOptions{Files: []string{source}, InputIdentities: []ZIPInputIdentity{identity}, RootDir: selected, OutputPath: output})
			}
			if err == nil {
				t.Fatal("substituted directory acquired archive read authority")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("rejected archive left output: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".picocrypt-") {
					t.Fatalf("rejected archive leaked stage %q", entry.Name())
				}
			}
			body, err := os.ReadFile(filepath.Join(selected+".original", "document.txt"))
			if err != nil || string(body) != "selected contents" {
				t.Fatalf("selected source changed: %q, %v", body, err)
			}
		})
	}
}

func TestGlobZIPInputCandidatesRejectsDirectorySubstitutionBetweenMatches(t *testing.T) {
	dir := t.TempDir()
	selected, outside := filepath.Join(dir, "selected"), filepath.Join(dir, "outside")
	for _, parent := range []string{selected, outside} {
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"a", "b"} {
			if err := os.WriteFile(filepath.Join(parent, name), []byte(parent), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	visited := false
	err := GlobZIPInputCandidates(context.Background(), filepath.Join(selected, "*"), NewZIPResourceBudget(), func(candidate ZIPInputCandidate) error {
		if visited {
			t.Fatal("glob selected a child after its original directory was replaced")
		}
		visited = true
		if err := os.Rename(selected, selected+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, selected); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if err == nil || !visited {
		t.Fatalf("glob substitution: visited=%v err=%v", visited, err)
	}
}

func TestGlobZIPInputCandidatesRootMetadataRefusalIsTerminal(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "selected")
	if err := os.WriteFile(file, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{file, filepath.Join(root, "*")} {
		t.Run(filepath.Base(pattern), func(t *testing.T) {
			budget := NewZIPResourceBudget()
			// Admit the pattern workspace while leaving too little for even one
			// retained directory snapshot and its memoization entry.
			baseline := budget.LimitBytes() - uint64(512+4*len(pattern)+256)
			if err := budget.Reserve(baseline); err != nil {
				t.Fatal(err)
			}
			visited := false
			err := GlobZIPInputCandidates(context.Background(), pattern, budget, func(ZIPInputCandidate) error { visited = true; return nil })
			if !errors.Is(err, ErrZIPMetadataLimit) || visited {
				t.Fatalf("metadata refusal was hidden: err=%v visited=%v", err, visited)
			}
			if budget.CurrentBytes() != baseline {
				t.Fatal("refused glob retained metadata")
			}
		})
	}
}

func TestZIPInputCandidateSymlinksEndingAtAnchorPreserveRelativeTraversal(t *testing.T) {
	for _, target := range []string{".", ".."} {
		t.Run(map[string]string{".": "current", "..": "parent"}[target], func(t *testing.T) {
			root := t.TempDir()
			via := filepath.Join(root, "via")
			if target == ".." {
				if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
					t.Fatal(err)
				}
				via = filepath.Join(root, "child", "via")
			}
			if err := os.Symlink(target, via); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "target"), []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			selected := filepath.Join(root, "chosen")
			relative, err := filepath.Rel(root, filepath.Join(via, "target"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(relative, selected); err != nil {
				t.Fatal(err)
			}
			identity, err := CaptureZIPInput(selected, true)
			if err != nil {
				t.Fatalf("stable link ending at anchor refused: %v", err)
			}
			file, err := identity.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(file)
			if closeErr := file.Close(); err != nil || closeErr != nil || string(body) != "original" {
				t.Fatalf("body=%q err=%v close=%v", body, err, closeErr)
			}
			matched := false
			if err := GlobZIPInputs(context.Background(), filepath.Join(via, "*"), NewZIPResourceBudget(), func(path string) error {
				if path == filepath.Join(via, "target") {
					matched = true
				}
				return nil
			}); err != nil || !matched {
				t.Fatalf("stable glob via anchor: matched=%v err=%v", matched, err)
			}
		})
	}
}

func TestZIPInputCandidateAnchorLinksPreserveParentTraversal(t *testing.T) {
	for _, target := range []string{".", ".."} {
		t.Run(map[string]string{".": "current", "..": "parent"}[target], func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "selected")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			via := filepath.Join(root, "via")
			if target == ".." {
				if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
					t.Fatal(err)
				}
				via = filepath.Join(root, "child", "via")
			}
			if err := os.Symlink(target, via); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "outside"), []byte("explicit outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			relative, err := filepath.Rel(root, via)
			if err != nil {
				t.Fatal(err)
			}
			selected := filepath.Join(root, "chosen")
			if err := os.Symlink(relative+string(filepath.Separator)+".."+string(filepath.Separator)+"outside", selected); err != nil {
				t.Fatal(err)
			}
			canonical, err := filepath.EvalSymlinks(selected)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := CaptureZIPInput(selected, true)
			if err != nil {
				t.Fatal(err)
			}
			if identity.ReadPath() != canonical {
				t.Fatalf("anchor changed symlink/.. semantics: read=%q standard=%q", identity.ReadPath(), canonical)
			}
			owner, err := CreateTempZip(context.Background(), TempZipOptions{Files: []string{selected}, InputIdentities: []ZIPInputIdentity{identity}, RootDir: root, NearPath: filepath.Join(dir, "result.pcv"), MaxPhysicalBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			reader, err := owner.OpenReader()
			if err != nil {
				t.Fatal(err)
			}
			logical, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			archive, err := zip.NewReader(bytes.NewReader(logical), int64(len(logical)))
			if err != nil {
				t.Fatal(err)
			}
			if len(archive.File) != 1 || archive.File[0].Name != "chosen" {
				t.Fatalf("lexical entries=%v", archive.File)
			}
			member, err := archive.File[0].Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(member)
			if closeErr := member.Close(); err != nil || closeErr != nil || string(body) != "explicit outside" {
				t.Fatalf("body=%q err=%v close=%v", body, err, closeErr)
			}
		})
	}
}

func TestZIPInputDoesNotFollowReplacedLeafLinkToSameSelectedInode(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "selected")
	if err := os.WriteFile(source, []byte("selected contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := CaptureZIPInput(source, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source, source+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("selected.original", source); err != nil {
		t.Fatal(err)
	}
	file, err := identity.Open()
	if file != nil {
		_ = file.Close()
	}
	if err == nil {
		t.Fatal("ordinary regular-file selection followed a newly introduced leaf link")
	}
}

func TestZIPInputCandidatesPreserveStableExplicitSymlinkTargetsAndEntryNames(t *testing.T) {
	for _, targetKind := range []string{"regular", "absolute_link", "relative_link", "escaping_relative_link", "directory_link_component"} {
		t.Run(targetKind, func(t *testing.T) {
			dir := t.TempDir()
			root, outside := filepath.Join(dir, "selected"), filepath.Join(dir, "explicit-external")
			for _, path := range []string{root, outside} {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			want := []byte("explicitly selected original contents")
			for _, path := range []string{filepath.Join(root, "target"), filepath.Join(outside, "target")} {
				if err := os.WriteFile(path, want, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			selected := filepath.Join(root, "chosen")
			var target string
			switch targetKind {
			case "regular":
				if err := os.WriteFile(selected, want, 0o600); err != nil {
					t.Fatal(err)
				}
			case "absolute_link":
				target = filepath.Join(outside, "target")
			case "relative_link":
				target = "target"
			case "escaping_relative_link":
				target = filepath.Join("..", "explicit-external", "target")
			case "directory_link_component":
				if err := os.Symlink(outside, filepath.Join(root, "via")); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join("via", "target")
			}
			if target != "" {
				if err := os.Symlink(target, selected); err != nil {
					t.Fatal(err)
				}
			}
			var identity ZIPInputIdentity
			err := WalkZIPInputCandidates(context.Background(), root, NewZIPResourceBudget(), func(candidate ZIPInputCandidate, err error) error {
				if err != nil {
					return err
				}
				if candidate.Path != selected {
					return nil
				}
				identity, err = candidate.Capture(targetKind != "regular")
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if target != "" {
				if err := os.WriteFile(filepath.Join(dir, "foreign"), []byte("unselected replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(selected); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(dir, "foreign"), selected); err != nil {
					t.Fatal(err)
				}
			}
			owner, err := CreateTempZip(context.Background(), TempZipOptions{Files: []string{selected}, InputIdentities: []ZIPInputIdentity{identity}, RootDir: root, NearPath: filepath.Join(dir, "result.pcv"), MaxPhysicalBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			physical, err := os.ReadFile(owner.Path())
			if err != nil || bytes.Contains(physical, want) {
				t.Fatalf("encrypted stage exposed input: %v", err)
			}
			reader, err := owner.OpenReader()
			if err != nil {
				t.Fatal(err)
			}
			logical, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			archive, err := zip.NewReader(bytes.NewReader(logical), int64(len(logical)))
			if err != nil || len(archive.File) != 1 {
				t.Fatalf("archive=%v err=%v", archive, err)
			}
			if archive.File[0].Name != "chosen" {
				t.Fatalf("lexical entry name=%q", archive.File[0].Name)
			}
			member, err := archive.File[0].Open()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(member)
			if closeErr := member.Close(); err != nil || closeErr != nil || !bytes.Equal(got, want) {
				t.Fatalf("pinned payload=%q err=%v close=%v", got, err, closeErr)
			}
			stagePath := owner.Path()
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(stagePath); !os.IsNotExist(err) {
				t.Fatalf("stage retained after close: %v", err)
			}
		})
	}
}
