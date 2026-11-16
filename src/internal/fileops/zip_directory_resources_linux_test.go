//go:build linux

package fileops

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestZIPExplicitInputsUnderSearchOnlyParentPreserveReadAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary-user directory DAC enforcement")
	}
	dir := t.TempDir()
	parent := filepath.Join(dir, "search-only")
	folder := filepath.Join(parent, "folder")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{filepath.Join(parent, "known"), filepath.Join(folder, "nested")} {
		if err := os.WriteFile(source, []byte("readable original"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(parent, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(parent, 0o700); err != nil {
			t.Error(err)
		}
	})
	for _, selected := range []string{filepath.Join(parent, "known"), folder} {
		t.Run(filepath.Base(selected), func(t *testing.T) {
			budget := NewZIPResourceBudget()
			var metadata ZIPInputMetadataReservation
			defer metadata.Release()
			candidate, err := metadata.Inspect(budget, selected)
			if err != nil {
				t.Fatalf("readable explicit input refused: %v", err)
			}
			var paths []string
			var identities []ZIPInputIdentity
			if candidate.Info.IsDir() {
				err = candidate.Walk(context.Background(), budget, func(child ZIPInputCandidate, err error) error {
					if err != nil {
						return err
					}
					if !child.Info.Mode().IsRegular() {
						return nil
					}
					identity, err := metadata.Capture(budget, child, false)
					if err != nil {
						return err
					}
					paths = append(paths, child.Path)
					identities = append(identities, identity)
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				identity, err := CaptureZIPInput(selected, false)
				if err != nil {
					t.Fatal(err)
				}
				paths, identities = []string{selected}, []ZIPInputIdentity{identity}
				matched := false
				if err := GlobZIPInputCandidates(context.Background(), selected, budget, func(candidate ZIPInputCandidate) error {
					matched = true
					_, err := metadata.Capture(budget, candidate, false)
					return err
				}); err != nil || !matched {
					t.Fatalf("exact named-file glob lost read access: err=%v matched=%v", err, matched)
				}
			}
			owner, err := CreateTempZip(context.Background(), TempZipOptions{Files: paths, InputIdentities: identities, RootDir: parent, NearPath: filepath.Join(dir, "result.pcv"), MaxPhysicalBytes: 1 << 20, Budget: budget})
			if err != nil {
				t.Fatalf("readable explicit input archive refused: %v", err)
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
			if err != nil {
				t.Fatal(err)
			}
			if len(archive.File) != 1 {
				t.Fatalf("archive entries=%d", len(archive.File))
			}
			member, err := archive.File[0].Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(member)
			if closeErr := member.Close(); err != nil || closeErr != nil || string(body) != "readable original" {
				t.Fatalf("body=%q err=%v close=%v", body, err, closeErr)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if candidate.Info.IsDir() {
				if err := os.Chmod(folder, 0o111); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Chmod(folder, 0o700); err != nil {
						t.Error(err)
					}
				}()
				file, err := identities[0].Open()
				if file != nil {
					_ = file.Close()
				}
				if err == nil {
					t.Fatal("a discovered member silently fell back after its anchored directory lost read access")
				}
				// The same leaf is still available as a fresh, explicit named file.
				if _, err := CaptureZIPInput(paths[0], false); err != nil {
					t.Fatalf("explicit named-file access was lost: %v", err)
				}
			}
		})
	}
}

func TestZIPInputFIFOParentDoesNotBlockDiscovery(t *testing.T) {
	if pipe := os.Getenv("PICOCRYPT_ZIP_FIFO_PARENT_HELPER"); pipe != "" {
		if os.Getenv("PICOCRYPT_ZIP_FIFO_PARENT_OPERATION") == "enumerate" {
			if err := VisitZIPDirectoryNames(context.Background(), pipe, NewZIPResourceBudget(), func(string) error { t.Fatal("FIFO enumerated"); return nil }); err == nil {
				t.Fatal("FIFO directory accepted")
			}
		} else {
			if _, err := InspectZIPInput(pipe + string(filepath.Separator) + "child"); err == nil {
				t.Fatal("FIFO parent accepted")
			}
		}
		return
	}
	dir := t.TempDir()
	pipe := filepath.Join(dir, "parent")
	if err := unix.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"inspect", "enumerate"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestZIPInputFIFOParentDoesNotBlockDiscovery$", "-test.v")
			command.Env = append(os.Environ(), "PICOCRYPT_ZIP_FIFO_PARENT_HELPER="+pipe, "PICOCRYPT_ZIP_FIFO_PARENT_OPERATION="+operation)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("FIFO parent discovery blocked or failed: %v context=%v\n%s", err, ctx.Err(), output)
			}
		})
	}
	info, err := os.Lstat(pipe)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("FIFO input changed: %v %v", info, err)
	}
}

func TestZIPDirectoryAuthorityDoesNotRetainHandlesPerFileOrDepth(t *testing.T) {
	if os.Getenv("PICOCRYPT_ZIP_DIRECTORY_HANDLES_HELPER") != "1" {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestZIPDirectoryAuthorityDoesNotRetainHandlesPerFileOrDepth$", "-test.v")
		command.Env = append(os.Environ(), "PICOCRYPT_ZIP_DIRECTORY_HANDLES_HELPER=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("bounded-handle archive failed: %v\n%s", err, output)
		}
		return
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	originalLimit := limit
	// The standard-library TempDir cleanup descends with its own handles.
	// Restore only after production discovery/emission and leak checks finish.
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &originalLimit); err != nil {
			t.Error(err)
		}
	}()
	limit.Cur = min(limit.Cur, 32)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	deep := root
	for range 64 {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := range 96 {
		if err := os.WriteFile(filepath.Join(deep, fmt.Sprintf("%03d", index)), []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	budget := NewZIPResourceBudget()
	var paths []string
	var identities []ZIPInputIdentity
	var retained uint64
	defer func() { budget.Release(retained) }()
	err := WalkZIPInputCandidates(context.Background(), root, budget, func(candidate ZIPInputCandidate, err error) error {
		if err != nil {
			return err
		}
		if !candidate.Info.Mode().IsRegular() {
			return nil
		}
		charge, err := ReserveZIPInputPath(budget, len(candidate.Path))
		if err != nil {
			return err
		}
		retained += charge
		identity, err := candidate.Capture(false)
		if err != nil {
			return err
		}
		paths = append(paths, candidate.Path)
		identities = append(identities, identity)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := CreateTempZip(context.Background(), TempZipOptions{Files: paths, InputIdentities: identities, RootDir: root, NearPath: filepath.Join(root, "result.pcv"), MaxPhysicalBytes: 1 << 20, Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := owner.OpenReader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.CurrentBytes() != retained {
		t.Fatal("archive did not retire temporary metadata")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if target == root || strings.HasPrefix(target, root+string(filepath.Separator)) {
			t.Fatalf("archive retained descriptor for %s", target)
		}
	}
}
