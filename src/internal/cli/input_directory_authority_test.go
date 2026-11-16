package cli

import (
	"Picocrypt-NG/internal/fileops"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDiscoveryRetainsDirectoryAuthorityThroughTemporaryArchive(t *testing.T) {
	for _, selection := range []string{"folder", "glob_file", "glob_folder"} {
		for _, replace := range []string{"selected_root", "nested_directory"} {
			t.Run(selection+"/"+replace, func(t *testing.T) {
				dir := t.TempDir()
				root := filepath.Join(dir, "selected")
				nested := filepath.Join(root, "nested")
				if err := os.MkdirAll(nested, 0o700); err != nil {
					t.Fatal(err)
				}
				source := filepath.Join(nested, "document.txt")
				if err := os.WriteFile(source, []byte("original selection"), 0o600); err != nil {
					t.Fatal(err)
				}
				var literals, patterns []string
				switch selection {
				case "folder":
					literals = []string{root}
				case "glob_file":
					patterns = []string{filepath.Join(root, "*", "*.txt")}
				case "glob_folder":
					patterns = []string{filepath.Join(root, "n*")}
				}
				inputs, err := resolveEncryptInputs(literals, patterns, false)
				if err != nil {
					t.Fatal(err)
				}
				if len(inputs.inputFiles) != 1 || inputs.inputFiles[0] != source {
					t.Fatalf("selection=%v", inputs.inputFiles)
				}
				replaced := root
				if replace == "nested_directory" {
					replaced = nested
				}
				if err := os.Rename(replaced, replaced+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(replaced+".original", replaced); err != nil {
					t.Fatal(err)
				}
				owner, err := fileops.CreateTempZip(context.Background(), fileops.TempZipOptions{Files: inputs.inputFiles, InputIdentities: inputs.inputIdentities, RootDir: root, NearPath: filepath.Join(dir, "result.pcv"), MaxPhysicalBytes: 1 << 20})
				if owner != nil {
					_ = owner.Close()
				}
				if err == nil {
					t.Fatal("CLI selection lost original directory authority before archive read")
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".picocrypt-") {
						t.Fatalf("archive rejection leaked %s", entry.Name())
					}
				}
			})
		}
	}
}

// A flat ordinary selection shares its directory authority. Charging an entire
// hypothetical ancestor chain per path must not reject this actual archive.
func TestEncryptDiscoveryFollowedLinkMetadataRefusalIsTerminal(t *testing.T) {
	dir := t.TempDir()
	selected := filepath.Join(dir, "selected")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selected, "a-first"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	components := append([]string{"..", "deep"}, strings.Split(strings.TrimSuffix(strings.Repeat("d/", 400), "/"), "/")...)
	deep := filepath.Join(append([]string{selected}, components...)...)
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "target"), []byte("explicit target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(append(components, "target")...), filepath.Join(selected, "b-link")); err != nil {
		t.Fatal(err)
	}
	budget := fileops.NewZIPResourceBudget()
	baseline := budget.LimitBytes() - (160 << 10)
	if err := budget.Reserve(baseline); err != nil {
		t.Fatal(err)
	}
	inputs, err := resolveEncryptInputsWithBudget(context.Background(), []string{selected}, nil, true, budget)
	if !errors.Is(err, fileops.ErrZIPMetadataLimit) || len(inputs.inputFiles) != 0 {
		t.Fatalf("metadata refusal silently omitted explicit link: err=%v files=%v", err, inputs.inputFiles)
	}
	if budget.CurrentBytes() != baseline {
		t.Fatalf("refused selection retained metadata=%d", budget.CurrentBytes()-baseline)
	}
}

func TestArchiveLargeFlatSelectionFitsExistingWorkingBudget(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, strings.Repeat("flat", 25))
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	const count = 8000
	paths := make([]string, 0, count)
	for index := range count {
		path := filepath.Join(root, fmt.Sprintf("f%05d", index))
		if err := os.WriteFile(path, []byte{byte(index % 251)}, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	for _, source := range []string{"cli_discovery", "direct_capture"} {
		t.Run(source, func(t *testing.T) {
			budget := fileops.NewZIPResourceBudget()
			baseline := budget.LimitBytes() - (64 << 20)
			if err := budget.Reserve(baseline); err != nil {
				t.Fatal(err)
			}
			var identities []fileops.ZIPInputIdentity
			selected := paths
			if source == "cli_discovery" {
				inputs, err := resolveEncryptInputsWithBudget(context.Background(), []string{root}, nil, false, budget)
				if err != nil {
					t.Fatalf("ordinary flat discovery refused: %v", err)
				}
				selected, identities = inputs.inputFiles, inputs.inputIdentities
			}
			owner, err := fileops.CreateTempZip(context.Background(), fileops.TempZipOptions{Files: selected, InputIdentities: identities, RootDir: root, NearPath: filepath.Join(dir, "result.pcv"), MaxPhysicalBytes: 4 << 20, Budget: budget})
			if err != nil {
				t.Fatalf("ordinary flat archive refused: %v", err)
			}
			defer owner.Close()
			reader, err := owner.OpenReader()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if len(archive.File) != count {
				t.Fatalf("archive count=%d", len(archive.File))
			}
			for index, entry := range archive.File {
				if entry.Name != fmt.Sprintf("f%05d", index) {
					t.Fatalf("entry%d name=%q", index, entry.Name)
				}
				member, err := entry.Open()
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(member)
				if closeErr := member.Close(); err != nil || closeErr != nil || !bytes.Equal(body, []byte{byte(index % 251)}) {
					t.Fatalf("entry%d body=%x err=%v close=%v", index, body, err, closeErr)
				}
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if budget.CurrentBytes() != baseline {
				t.Fatalf("archive retained working charge=%d", budget.CurrentBytes()-baseline)
			}
		})
	}
}
