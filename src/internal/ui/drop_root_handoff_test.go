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
	"reflect"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
)

// Pause the real scan at its context boundary, after the UI handed it the
// selected roots. Filesystem classification and enumeration stay in production.
type dropRootHandoffContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (ctx *dropRootHandoffContext) Err() error {
	ctx.once.Do(func() {
		close(ctx.entered)
		<-ctx.resume
	})
	return ctx.Context.Err()
}

func TestDroppedDirectoryIdentitySurvivesAsynchronousScanHandoff(t *testing.T) {
	for _, rootCount := range []int{1, 2} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("roots=%d/replaced=%t", rootCount, replace), func(t *testing.T) {
				resetLocalizationForTest(t)
				a := createUIReadyDropTestApp(t, newTestFyneApp(t))
				dir := t.TempDir()
				roots := make([]string, rootCount)
				want := make(map[string]string)
				for index := range roots {
					roots[index] = filepath.Join(dir, fmt.Sprintf("selected-%d", index))
					if err := os.Mkdir(roots[index], 0o700); err != nil {
						t.Fatal(err)
					}
					name := filepath.Join(roots[index], "original.txt")
					body := fmt.Sprintf("original selected file %d", index)
					if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
					want[fmt.Sprintf("selected-%d/original.txt", index)] = body
				}
				foreign := filepath.Join(dir, "foreign")
				if err := os.Mkdir(foreign, 0o700); err != nil {
					t.Fatal(err)
				}
				const foreignBody = "unselected foreign bytes"
				if err := os.WriteFile(filepath.Join(foreign, "foreign-secret.txt"), []byte(foreignBody), 0o600); err != nil {
					t.Fatal(err)
				}

				gate := &dropRootHandoffContext{Context: a.workers.ctx, entered: make(chan struct{}), resume: make(chan struct{})}
				a.workers.ctx = gate
				var resumed sync.Once
				resume := func() { resumed.Do(func() { close(gate.resume) }) }
				t.Cleanup(resume)
				accepted := false
				fyne.DoAndWait(func() { accepted = a.onDrop(roots) })
				if !accepted {
					t.Fatal("stable dropped roots were refused before scan handoff")
				}
				select {
				case <-gate.entered:
				case <-time.After(2 * time.Second):
					t.Fatal("folder worker did not reach its scan boundary")
				}
				replacedRoot := roots[len(roots)-1]
				if replace {
					if err := os.Rename(replacedRoot, replacedRoot+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(foreign, replacedRoot); err != nil {
						t.Fatal(err)
					}
				}
				resume()
				done := make(chan struct{})
				go func() { a.workers.wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("folder scan did not complete after handoff")
				}
				var paths []string
				var identities []fileops.ZIPInputIdentity
				fyne.DoAndWait(func() {
					paths = append(paths, a.State.AllFiles...)
					identities = append(identities, a.State.InputIdentities...)
				})
				if replace {
					if len(paths) != 0 || len(identities) != 0 {
						t.Fatalf("scan recaptured substituted dropped directory: selected=%v", paths)
					}
					if got := statusLabelText(t, a); got != tr("drop.failed_walk", "Failed to walk through dropped items") {
						t.Fatalf("root substitution did not report scan failure: %q", got)
					}
					for path, body := range map[string]string{
						filepath.Join(replacedRoot+".original", "original.txt"): fmt.Sprintf("original selected file %d", rootCount-1),
						filepath.Join(replacedRoot, "foreign-secret.txt"):       foreignBody,
					} {
						got, err := os.ReadFile(path)
						if err != nil || string(got) != body {
							t.Fatalf("source changed: %q bytes=%q err=%v", path, got, err)
						}
					}
					return
				}
				owner, err := fileops.CreateTempZip(context.Background(), fileops.TempZipOptions{
					Files: paths, InputIdentities: identities, RootDir: dir,
					NearPath: filepath.Join(dir, "output.pcv"), MaxPhysicalBytes: 1 << 20,
				})
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
				got := make(map[string]string)
				for _, member := range archive.File {
					reader, err := member.Open()
					if err != nil {
						t.Fatal(err)
					}
					body, readErr := io.ReadAll(reader)
					if closeErr := reader.Close(); readErr != nil || closeErr != nil {
						t.Fatalf("read archived member: %v %v", readErr, closeErr)
					}
					got[member.Name] = string(body)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("stable dropped roots changed archive contents: got=%v want=%v", got, want)
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
