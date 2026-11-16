//go:build linux

package ui

import (
	"Picocrypt-NG/internal/fileops"
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
)

func TestFolderScanCanonicalReadPathsUseSharedBudget(t *testing.T) {
	for _, count := range []int{16, 240} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			resetLocalizationForTest(t)
			a := createUIReadyDropTestApp(t, newTestFyneApp(t))
			dir := t.TempDir()
			canonical := dir
			for index := range 14 {
				canonical = filepath.Join(canonical, strings.Repeat("d", 220)+strconv.Itoa(index))
			}
			if err := os.MkdirAll(filepath.Join(canonical, "payload"), 0o700); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(dir, "alias")
			if err := os.Symlink(canonical, alias); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(alias, "payload")
			for index := range count {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%03d", index)), []byte{byte(index % 251)}, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			candidate, err := fileops.InspectZIPInput(root)
			if err != nil {
				t.Fatal(err)
			}
			budget := fileops.NewZIPResourceBudget()
			baseline := budget.LimitBytes() - (600 << 10)
			if err := budget.Reserve(baseline); err != nil {
				t.Fatal(err)
			}
			fyne.DoAndWait(func() {
				a.folderScanGeneration++
				a.State.Mode = "encrypt"
				a.State.SetScanning(true)
				a.State.OnlyFolders = []string{root}
			})
			job := folderScanJob{roots: []fileops.ZIPInputCandidate{candidate}, folderCount: 1, generation: a.folderScanGeneration, budget: budget}
			reservation, ok := a.workers.reserve()
			if !ok {
				t.Fatal("scan worker refused")
			}
			reservation.launch(func(ctx context.Context) { a.runFolderScan(ctx, job, a.scannedFileEmitter(job.generation)) })
			done := make(chan struct{})
			go func() { a.workers.wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("scan did not finish")
			}
			var paths []string
			var identities []fileops.ZIPInputIdentity
			fyne.DoAndWait(func() {
				paths = append(paths, a.State.AllFiles...)
				identities = append(identities, a.State.InputIdentities...)
			})
			if count == 240 {
				if len(paths) != 0 || len(identities) != 0 {
					t.Fatalf("canonical path expansion bypassed scan budget: files=%d identities=%d", len(paths), len(identities))
				}
				if statusLabelText(t, a) != resourceLimitCopy().Title {
					t.Fatalf("canonical refusal did not report resource limit: %q", statusLabelText(t, a))
				}
			} else {
				owner, err := fileops.CreateTempZip(context.Background(), fileops.TempZipOptions{Files: paths, InputIdentities: identities, RootDir: root, NearPath: filepath.Join(dir, "result.pcv"), MaxPhysicalBytes: 1 << 20})
				if err != nil {
					t.Fatal(err)
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
					t.Fatalf("stable archive count=%d", len(archive.File))
				}
				for index, entry := range archive.File {
					if entry.Name != fmt.Sprintf("f%03d", index) {
						t.Fatalf("lexical entry=%q", entry.Name)
					}
					member, err := entry.Open()
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(member)
					if closeErr := member.Close(); err != nil || closeErr != nil || !bytes.Equal(body, []byte{byte(index % 251)}) {
						t.Fatalf("body=%x err=%v close=%v", body, err, closeErr)
					}
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if budget.CurrentBytes() != baseline {
				t.Fatalf("scan did not retire working metadata: %d", budget.CurrentBytes()-baseline)
			}
			if body, err := os.ReadFile(filepath.Join(root, "f000")); err != nil || !bytes.Equal(body, []byte{0}) {
				t.Fatalf("source changed: %x %v", body, err)
			}
		})
	}
}
