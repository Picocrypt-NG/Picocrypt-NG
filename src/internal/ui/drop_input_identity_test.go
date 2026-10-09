package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/volume"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

func TestSingleFileLeafSymlinkPlaintextRefused(t *testing.T) {
	resetLocalizationForTest(t)
	dir := t.TempDir()
	source, link := filepath.Join(dir, "plaintext.txt"), filepath.Join(dir, "chosen.txt")
	if err := os.WriteFile(source, []byte("selected contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	fyne.DoAndWait(func() {
		a.onDrop([]string{link})
		snap := a.State.UISnapshot()
		if snap.Mode != "" || a.State.IsScanning() || !a.startButton.Disabled() {
			t.Fatalf("plaintext symlink became startable: %+v", snap)
		}
	})
	if got, err := os.ReadFile(source); err != nil || string(got) != "selected contents" {
		t.Fatalf("refused selection changed source: %q, %v", got, err)
	}
}

func TestEncryptionDeletionManifestRejectsSelectionReplacementBeforeWork(t *testing.T) {
	resetLocalizationForTest(t)
	dir := t.TempDir()
	source, sibling := filepath.Join(dir, "chosen.txt"), filepath.Join(dir, "sibling.txt")
	if err := os.WriteFile(source, []byte("selected-A"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sibling, []byte("sibling"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(a.State.Reset)
	var snap app.Snapshot
	fyne.DoAndWait(func() {
		a.onDrop([]string{source, sibling})
		snap = a.State.Snapshot()
	})
	input, err := a.captureOperationInput(snap)
	if err != nil {
		t.Fatal(err)
	}
	input.delete = true
	input.password = []byte("public-test-password")
	input.outputFile = filepath.Join(dir, "output.pcv")
	if err := os.Rename(source, source+".A"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("foreign-B"), 0o600); err != nil {
		t.Fatal(err)
	}
	executed := false
	executor := func(ctx context.Context, selected operationInput, reporter volume.ProgressReporter) operationResult {
		executed = true
		if err := os.Rename(source, source+".B"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(source+".A", source); err != nil {
			t.Fatal(err)
		}
		result := executeVolumeOperation(ctx, selected, reporter)
		if result.err != nil || !result.completed || result.pcv3 == nil || !result.pcv3.SourceDeletionAllowed() {
			t.Fatalf("real writer did not reach clean publication: %+v", result)
		}
		if err := os.Rename(source, source+".A"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(source+".B", source); err != nil {
			t.Fatal(err)
		}
		return result
	}
	reporter := &archiveIdentityReporter{}
	result := a.runCapturedOperation(context.Background(), executor, reporter, input)
	for _, file := range []struct{ path, want string }{{source, "foreign-B"}, {source + ".A", "selected-A"}, {sibling, "sibling"}} {
		got, err := os.ReadFile(file.path)
		if err != nil || string(got) != file.want {
			t.Fatalf("deletion authority did not match selected read: %s = %q, %v", file.path, got, err)
		}
	}
	if executed || reporter.deriving || result.err == nil || result.completed {
		t.Fatalf("replacement acquired deletion authority before work: executed=%v deriving=%v result=%+v", executed, reporter.deriving, result)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("refusal left output/stage or removed a source: %v, %v", entries, err)
	}
}

type archiveIdentityReporter struct{ deriving bool }

func (r *archiveIdentityReporter) SetStatus(status string) {
	r.deriving = r.deriving || strings.Contains(status, "Deriving key")
}
func (*archiveIdentityReporter) SetProgress(float32, string) {}
func (*archiveIdentityReporter) SetCanCancel(bool)           {}
func (*archiveIdentityReporter) Update()                     {}
func (*archiveIdentityReporter) IsCancelled() bool           { return false }

// Exercises real drop discovery, State's snapshot, worker capture, preparation,
// and deletion policy. Re-capturing identities in any later layer would admit
// the foreign file and could delete it after encrypting the wrong plaintext.
func TestDropArchiveRejectsReplacementAfterDiscoveryWithoutDeletingSources(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	for _, kind := range []string{"symlink", "regular"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source, sibling := filepath.Join(dir, "chosen.txt"), filepath.Join(dir, "sibling.txt")
			for path, body := range map[string]string{source: "selected contents", sibling: "unintended secret"} {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a := createUIReadyDropTestApp(t, fyneApp)
			t.Cleanup(a.State.Reset)
			var snap app.Snapshot
			fyne.DoAndWait(func() {
				a.onDrop([]string{source, sibling})
				snap = a.State.Snapshot()
			})
			if snap.Mode != "encrypt" {
				t.Fatalf("regular collection not admitted: %+v", snap)
			}
			input, err := a.captureOperationInput(snap)
			if err != nil {
				t.Fatal(err)
			}
			input.password = []byte("public-test-password")
			input.outputFile = filepath.Join(dir, "output.pcv")
			input.delete = true
			if err := os.Rename(source, source+".selected"); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				err = os.Symlink(sibling, source)
				if err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			} else if err := os.WriteFile(source, []byte("unintended secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			reporter := &archiveIdentityReporter{}
			result := a.runCapturedOperation(context.Background(), executeVolumeOperation, reporter, input)
			if result.err == nil || result.completed || reporter.deriving {
				t.Fatalf("replaced selection reached encryption: %+v deriving=%v", result, reporter.deriving)
			}
			for path, want := range map[string]string{source + ".selected": "selected contents", source: "unintended secret", sibling: "unintended secret"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("protected source %s changed: %q, %v", path, got, err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 3 {
				t.Fatalf("rejection left output/private stage or removed a source: %v", entries)
			}
		})
	}
}

// Direct callers without a discovery snapshot must not recapture a new read
// identity after the manifest has admitted a different file.
func TestEncryptionDeletionSnapshotBindsDirectCallerRead(t *testing.T) {
	for _, archive := range []bool{false, true} {
		t.Run(map[bool]string{false: "bare", true: "archive"}[archive], func(t *testing.T) {
			dir := t.TempDir()
			source, sibling := filepath.Join(dir, "chosen.txt"), filepath.Join(dir, "sibling.txt")
			for path, body := range map[string]string{source: "selected-A", sibling: "sibling"} {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a := createTestApp(t)
			input := operationInput{mode: "encrypt", inputFile: source, onlyFiles: []string{source}, outputFile: filepath.Join(dir, "output.pcv"), password: []byte("public-test-password"), delete: true}
			if archive {
				input.inputFiles = []string{source, sibling}
				input.onlyFiles = []string{source, sibling}
			}
			called := false
			executor := func(ctx context.Context, selected operationInput, reporter volume.ProgressReporter) operationResult {
				called = true
				if err := os.Rename(source, source+".A"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source, []byte("foreign-B"), 0o600); err != nil {
					t.Fatal(err)
				}
				return executeVolumeOperation(ctx, selected, reporter)
			}
			reporter := &archiveIdentityReporter{}
			result := a.runCapturedOperation(context.Background(), executor, reporter, input)
			if !called || result.err == nil || result.completed || reporter.deriving {
				t.Fatalf("nil discovery allowed executor to recapture foreign B: called=%v deriving=%v result=%+v", called, reporter.deriving, result)
			}
			for path, want := range map[string]string{source: "foreign-B", source + ".A": "selected-A", sibling: "sibling"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("source changed %s: %q %v", path, got, err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 3 {
				t.Fatalf("refusal left output/stage or removed a source: %v %v", entries, err)
			}
		})
	}
}
