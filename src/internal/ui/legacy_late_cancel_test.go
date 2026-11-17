package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

// These cases use the frozen reader/KDF and actual plaintext publication. A
// late cancellation must not erase a publication that already succeeded.
func TestLegacyRetainedForceOutputSurvivesLateCancellation(t *testing.T) {
	for _, mode := range []string{"single", "recursive"} {
		for _, window := range []string{"executor_return", "worker_gate"} {
			t.Run(mode+"/"+window, func(t *testing.T) {
				const child = "PICOCRYPT_TEST_LEGACY_LATE_CANCEL_CHILD"
				if os.Getenv(child) != "1" {
					command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLegacyRetainedForceOutputSurvivesLateCancellation$/^"+mode+"$/^"+window+"$", "-test.timeout=5m", "-test.v")
					command.Env = append(os.Environ(), child+"=1")
					output, err := command.CombinedOutput()
					if err != nil {
						t.Fatalf("isolated actual legacy publication/cancellation: %v\n%s", err, output)
					}
					if !bytes.Contains(output, []byte("--- PASS: "+t.Name()+" (")) {
						t.Fatalf("isolated case did not execute: %s", output)
					}
					return
				}
				resetLocalizationForTest(t)
				a := createUIReadyDropTestApp(t, newTestFyneApp(t))
				dir := t.TempDir()
				golden := filepath.Join("..", "..", "testdata", "golden")
				fixture, err := os.ReadFile(filepath.Join(golden, "pico_test_v2_keyfile_single.txt.pcv"))
				if err != nil {
					t.Fatal(err)
				}
				source, output := filepath.Join(dir, "legacy.txt.pcv"), filepath.Join(dir, "legacy.txt")
				if err := os.WriteFile(source, fixture, 0o600); err != nil {
					t.Fatal(err)
				}
				keyfiles := []string{filepath.Join(golden, "keyfile_beta.bin")}
				var saved app.RecursiveSnapshot
				var session *operationSession
				fyne.DoAndWait(func() {
					a.State.Mode = "decrypt"
					a.State.Recursively = mode == "recursive"
					a.State.Keep, a.State.Delete = true, true
					a.State.Keyfile = true
					a.State.Keyfiles = keyfiles
					a.State.Password = "test"
					a.State.SetWorking(true)
					saved = a.State.RecursiveSnapshot()
					session = a.newOperationSession()
					a.setOperationSession(session)
				})
				defer session.cancel()
				executor := func(ctx context.Context, input operationInput, reporter volume.ProgressReporter) operationResult {
					result := executeVolumeOperation(ctx, input, reporter)
					if result.err != nil || !result.completed || !result.kept {
						t.Fatalf("real Force publication failed: %+v", result)
					}
					if info, err := os.Stat(input.outputFile); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
						t.Fatalf("real recovery artifact missing before cancellation: %v %v", info, err)
					}
					if window == "executor_return" {
						session.cancel()
					}
					return result
				}
				input := operationInput{mode: "decrypt", inputFile: source, outputFile: output, password: []byte("test"), keyfiles: keyfiles, forceDecrypt: true, delete: true, rsCodecs: a.State.RSCodecs}
				var result operationResult
				if mode == "recursive" {
					input, result = a.runRecursiveOperation(session, executor, nil, []string{source}, saved)
				} else {
					result = a.runCapturedOperation(session.ctx, executor, nil, input)
				}
				if result.unverified != 1 || result.succeeded != 0 || result.failed != 0 || !result.kept {
					t.Errorf("published recovery lost its count: %+v", result)
				}
				if window == "worker_gate" {
					fyne.DoAndWait(func() { a.cancelOperation(session) })
				}
				a.finishOperationWorker(session, input, result, mode == "recursive")
				fyne.DoAndWait(func() {})
				snap := a.State.UISnapshot()
				text := renderStatus(snap.Status, snap)
				if !a.State.WasKept() || snap.Status.Color != util.YELLOW || !strings.Contains(text, "unverified") || !strings.Contains(text, "cancelled") {
					t.Errorf("late cancellation hid retained recovery: kept=%t status=%+v text=%q", a.State.WasKept(), snap.Status, text)
				}
				if mode == "recursive" && !strings.Contains(text, "1 unverified") {
					t.Errorf("recursive terminal count lost retained artifact: %q", text)
				}
				if got, err := os.ReadFile(source); err != nil || !bytes.Equal(got, fixture) {
					t.Errorf("late cancellation deleted source: %v", err)
				}
				if info, err := os.Stat(output); err != nil || info.Size() == 0 {
					t.Errorf("late cancellation removed actual artifact: %v %v", info, err)
				}
				if snap.Working {
					t.Error("worker did not finalize")
				}
			})
		}
	}
}

type refuseLegacyStageAfterBypassReporter struct {
	refuse func()
}

func (*refuseLegacyStageAfterBypassReporter) SetProgress(float32, string) {}
func (*refuseLegacyStageAfterBypassReporter) Update()                     {}
func (*refuseLegacyStageAfterBypassReporter) IsCancelled() bool           { return false }
func (r *refuseLegacyStageAfterBypassReporter) SetStatus(status string) {
	if status == "Calculating values..." {
		r.refuse()
	}
}
func (*refuseLegacyStageAfterBypassReporter) SetCanCancel(bool) {}

func TestLegacyFailedIOAfterBypassKeepsErrorAndConditionalTrustWarning(t *testing.T) {
	const child = "PICOCRYPT_TEST_LEGACY_FAILED_IO_CHILD"
	if os.Getenv(child) != "1" {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLegacyFailedIOAfterBypassKeepsErrorAndConditionalTrustWarning$", "-test.timeout=5m", "-test.v")
		command.Env = append(os.Environ(), child+"=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated failed legacy publication: %v\n%s", err, output)
		}
		return
	}
	resetLocalizationForTest(t)
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	dir := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	source, parent := filepath.Join(dir, "source.pcv"), filepath.Join(dir, "output-parent")
	if err := os.WriteFile(source, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	reporter := &refuseLegacyStageAfterBypassReporter{refuse: func() {
		if err := os.Remove(parent); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(parent, []byte("stage blocker"), 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	input := operationInput{mode: "decrypt", inputFile: source, outputFile: filepath.Join(parent, "output"), password: []byte("wrong"), forceDecrypt: true, delete: true, rsCodecs: a.State.RSCodecs}
	result := a.runCapturedOperation(t.Context(), executeVolumeOperation, reporter, input)
	if !result.kept || result.completed || result.err == nil || result.unverified != 0 {
		t.Fatalf("actual no-output I/O refusal not exercised: %+v", result)
	}
	fyne.DoAndWait(func() {
		a.State.SetWorking(true)
		session := a.newOperationSession()
		defer session.cancel()
		a.setOperationSession(session)
		a.finalizeOperation(session, input, result, false)
		snap := a.State.UISnapshot()
		text := renderStatus(snap.Status, snap)
		if snap.Status.Kind != app.StatusCustom || snap.Status.Color != util.RED || !strings.Contains(text, result.err.Error()) || !strings.Contains(text, "Authentication was bypassed; any retained output is unverified") {
			t.Fatalf("I/O failure lost error or conditional trust warning: %+v %q", snap.Status, text)
		}
		if strings.Contains(text, "kept output") || strings.Contains(text, "1 unverified") {
			t.Fatalf("failed I/O claimed retained output: %q", text)
		}
	})
	if got, err := os.ReadFile(source); err != nil || !bytes.Equal(got, fixture) {
		t.Errorf("failed I/O changed source: %v", err)
	}
	if got, err := os.ReadFile(parent); err != nil || string(got) != "stage blocker" {
		t.Errorf("failed I/O changed blocker: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(parent, "output")); err == nil {
		t.Errorf("failed I/O unexpectedly created output: %v", err)
	}
}
