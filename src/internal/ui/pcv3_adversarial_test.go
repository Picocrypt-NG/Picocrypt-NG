package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	fynetest "fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func phase9PCV3ConsentControls(
	t *testing.T,
	overlay fyne.CanvasObject,
) (roles *widget.RadioGroup, ack *widget.Check, confirm *widget.Button) {
	t.Helper()
	for _, object := range fynetest.LaidOutObjects(overlay) {
		switch object := object.(type) {
		case *widget.RadioGroup:
			roles = object
		case *widget.Check:
			ack = object
		case *widget.Button:
			if object.Text == "Recover unverified" {
				confirm = object
			}
		}
	}
	return roles, ack, confirm
}

// TestPhase9FyneResultAndPrivacyBoundary drives the real desktop App into the
// real operation executor (pcv3operation.Run, observed but not replaced) and
// proves the Fyne surface consumes the same closed operation result: identical
// axes through State and the retained result object, exact bounded rendering,
// live consent with one explicit physical role, credential clearing, no output
// on refusal, and no secret or path disclosure. On this host the production
// desktop resource admission fails closed before derivation (the cgroup v2
// root exposes no memory controller files), so the real operation terminates
// with the exact resource-unknown refusal; the fixed-profile success tuples
// are owned by the pcv3operation matrix.
func TestPhase9FyneResultAndPrivacyBoundary(t *testing.T) {
	resetLocalizationForTest(t)

	t.Run("real consented operation transfers one closed result without reconstruction or disclosure", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		base := t.TempDir()
		dir := filepath.Join(base, "p9ui-path-51b0e2")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create sentinel directory: %v", err)
		}
		secret := "p9ui-secret-7d21c94af0"
		fixturePath := filepath.Join(
			"..", "pcv3", "testdata", "normal", "volumes",
			"normal-standard-combined-ordered-one.pcv",
		)
		info, err := os.Stat(fixturePath)
		if err != nil {
			t.Fatalf("inspect frozen combined volume: %v", err)
		}
		source, err := os.Open(fixturePath)
		if err != nil {
			t.Fatalf("open frozen combined volume: %v", err)
		}
		red := filepath.Join(dir, "red.key")
		blue := filepath.Join(dir, "blue.key")
		if err := os.WriteFile(red, []byte("red"), 0o600); err != nil {
			t.Fatalf("write red keyfile: %v", err)
		}
		if err := os.WriteFile(blue, []byte("blue"), 0o600); err != nil {
			t.Fatalf("write blue keyfile: %v", err)
		}
		output := filepath.Join(dir, "recovery.pcv3-recovery")

		executorCalls := 0
		var executed *pcv3operation.Result
		a.pcv3OperationExecutor = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
			executorCalls++
			executed = pcv3operation.Run(ctx, request)
			return executed
		}
		fyne.DoAndWait(func() {
			if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, fixturePath, output, info.Size()) {
				t.Fatal("set PCV3 selection")
			}
			a.State.Password = secret
			a.State.Keyfiles = []string{red, blue}
			a.State.SetPCV3Intent(app.PCV3ActionForce, app.PCV3FactorPolicyCombined, app.PCV3KeyfileOrderSelected)
			a.refreshAdvanced()
			a.updateUIState()
			a.startPCV3Work()
		})
		waitForPCV3UI(t, func() bool {
			focused, ok := a.Window.Canvas().Focused().(*widget.Button)
			return ok && focused.Text == "Cancel recovery"
		}, "live consent did not focus its safe-default cancellation")

		// Approve exactly the primary physical role through the real consent
		// surface: role radio, acknowledgement, then the danger confirm.
		fyne.DoAndWait(func() {
			overlay := a.Window.Canvas().Overlays().Top()
			if overlay == nil {
				t.Fatal("live consent exposed no overlay")
			}
			radio, ack, confirm := phase9PCV3ConsentControls(t, overlay)
			if radio == nil {
				t.Fatalf("consent overlay %T exposed no role radio group", overlay)
			}
			if len(radio.Options) != 2 ||
				radio.Options[0] != "Primary capsule" || radio.Options[1] != "Backup capsule" {
				t.Fatalf("consent role options = %v; want exactly the two physical roles", radio.Options)
			}
			radio.SetSelected("Primary capsule")
			if ack == nil || ack.Text != "I understand that this output is unverified." {
				t.Fatal("consent acknowledgement missing or changed")
			}
			ack.SetChecked(true)
			if confirm == nil || confirm.Disabled() || confirm.OnTapped == nil {
				t.Fatal("consent confirm did not enable after exact role and acknowledgement")
			}
			confirm.OnTapped()
		})
		// The real Force analysis runs the production Reed-Solomon evaluator,
		// which is CPU-bound and much slower under the race detector; the
		// terminal wait therefore uses a 60-second bound instead of the shared
		// 3-second UI helper.
		terminal := false
		for attempt := 0; attempt < 600 && !terminal; attempt++ {
			fyne.DoAndWait(func() {
				terminal = !a.State.IsWorking() &&
					a.State.UISnapshot().PCV3Result.CompletionClass() != pcv3operation.CompletionUnknown
			})
			if !terminal {
				time.Sleep(100 * time.Millisecond)
			}
		}
		if !terminal {
			t.Fatalf(
				"PCV3 operation did not reach a terminal presentation: calls=%d executed=%v working=%v overlay=%T class=%v diagnostic=%v",
				executorCalls, executed != nil, a.State.IsWorking(),
				a.Window.Canvas().Overlays().Top(),
				a.State.UISnapshot().PCV3Result.CompletionClass(),
				a.State.UISnapshot().PCV3Result.Diagnostic(),
			)
		}

		if executorCalls != 1 || executed == nil {
			t.Fatalf("real operation executor calls = %d; want exactly one", executorCalls)
		}
		if a.pcv3Result != executed {
			t.Fatal("the desktop reconstructed rather than retained the operation's closed result")
		}
		snapshot := a.State.UISnapshot()
		presentation := snapshot.PCV3Result
		core := executed.Presentation()
		if presentation.Outcome() != core.Outcome() || presentation.Stage() != core.Stage() ||
			presentation.Code() != core.Code() || presentation.Diagnostic() != core.Diagnostic() ||
			presentation.CompletionClass() != core.CompletionClass() ||
			presentation.PublicationAttempted() != core.PublicationAttempted() ||
			presentation.PublicationState() != core.PublicationState() ||
			presentation.PublicationCode() != core.PublicationCode() ||
			presentation.ArchivePending() != core.ArchivePending() {
			t.Fatal("State presentation drifted from the operation's closed presentation")
		}
		if presentation.Outcome() != pcv3.OutcomeOperationFailed ||
			presentation.Stage() != pcv3.StageCredentialPolicy ||
			presentation.Code() != pcv3.CodeOperationFailed ||
			presentation.Diagnostic() != pcv3operation.DiagnosticResourceUnknown ||
			presentation.CompletionClass() != pcv3operation.CompletionRefused ||
			presentation.PublicationAttempted() ||
			presentation.PublicationState() != pcv3publication.State(0) ||
			len(presentation.Warnings()) != 0 ||
			presentation.ArchivePending() {
			t.Fatalf(
				"real desktop presentation = %v/%v/%v diagnostic=%v class=%v publication=%v/%v warnings=%d pending=%v; want the exact resource refusal",
				presentation.Outcome(), presentation.Stage(), presentation.Code(),
				presentation.Diagnostic(), presentation.CompletionClass(),
				presentation.PublicationState(), presentation.PublicationCode(),
				len(presentation.Warnings()), presentation.ArchivePending(),
			)
		}
		text := pcv3RenderedText(a.pcv3Container)
		for _, fragment := range []string{
			"Device resources could not be verified",
			"The operation stopped before key derivation. No output was created.",
			"Close recovery result",
		} {
			if !strings.Contains(text, fragment) {
				t.Fatalf("rendered result view %q lacks exact fragment %q", text, fragment)
			}
		}
		if strings.Contains(text, "Retry") || strings.Contains(text, "continue") {
			t.Fatalf("resource refusal offered downgrade/retry: %q", text)
		}
		if strings.Contains(text, secret) || strings.Contains(text, "p9ui-path-51b0e2") {
			t.Fatalf("result view disclosed secret or path sentinel: %q", text)
		}
		if a.State.Password != "" || a.State.Keyfiles != nil {
			t.Fatal("desktop retained credential entries after transfer")
		}
		if _, err := source.Stat(); err == nil {
			t.Fatal("transferred source descriptor remained open")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("fail-closed operation created output: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("inspect sentinel directory: %v", err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
				t.Fatalf("desktop left publication stage residue %q", entry.Name())
			}
		}
	})
}
