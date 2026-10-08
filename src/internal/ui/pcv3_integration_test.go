package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	fynetest "fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func pcv3PCV3ConsentControls(
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

// TestPCV3FyneResultAndPrivacyBoundary drives the real desktop App into the
// real operation executor (pcv3operation.Run, observed but not replaced) and
// proves the Fyne surface consumes the same closed operation result: identical
// axes through State and the retained result object, exact bounded rendering,
// live consent with one explicit physical role, credential clearing, the exact
// consented unverified-force artifact, and no secret or path disclosure. On
// this host the production desktop resource admission grants the frozen fixed
// profile (standard systemd cgroup v2, no finite limit, ample headroom); the
// wrong password then drives the consented Force operation to the bounded
// unverified emission instead of any verified output.
func TestPCV3FyneResultAndPrivacyBoundary(t *testing.T) {
	resetLocalizationForTest(t)

	t.Run("real consented operation transfers one closed result without reconstruction or disclosure", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		base := t.TempDir()
		dir := filepath.Join(base, "pcv3-ui-path")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create sentinel directory: %v", err)
		}
		secret := "wrong-password"
		fixturePath := filepath.Join(
			"..", "pcv3operation", "internal", "pcv3", "testdata", "normal", "volumes",
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
			a.State.KeyfileOrdered = true
			a.State.SetPCV3Intent(app.PCV3ActionForceUnverified, app.PCV3FactorPolicyCombined, app.PCV3KeyfileOrderSelected)
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
			radio, ack, confirm := pcv3PCV3ConsentControls(t, overlay)
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
		wantClass := pcv3operation.CompletionWarning
		wantState := pcv3publication.StatePublishedDurable
		wantStage := pcv3operation.StageNone
		wantCode := pcv3publication.CodePublishedDurable
		wantWarnings := []pcv3operation.Warning{pcv3operation.WarningForceUnverified}
		if runtime.GOOS == "windows" {
			wantClass = pcv3operation.CompletionDurabilityUncertain
			wantState = pcv3publication.StatePublishedDurabilityUncertain
			wantStage = pcv3operation.StageDirectorySync
			wantCode = pcv3publication.CodeDurabilityUncertain
			wantWarnings = append(wantWarnings, pcv3operation.WarningDurabilityUncertain)
		}
		if presentation.Outcome() != pcv3operation.OutcomeForceUnverified ||
			presentation.Stage() != pcv3operation.StageWrapAuth ||
			presentation.Code() != pcv3operation.CodeForceUnverified ||
			presentation.Diagnostic() != pcv3operation.DiagnosticNone ||
			presentation.CompletionClass() != wantClass ||
			!presentation.PublicationAttempted() ||
			presentation.PublicationState() != wantState ||
			presentation.PublicationStage() != wantStage ||
			presentation.PublicationCode() != wantCode ||
			!slices.Equal(presentation.Warnings(), wantWarnings) ||
			presentation.ArchivePending() {
			t.Fatalf(
				"real desktop presentation = %v/%v/%v diagnostic=%v class=%v publication=%v/%v warnings=%v pending=%v; want the exact consented unverified-force emission",
				presentation.Outcome(), presentation.Stage(), presentation.Code(),
				presentation.Diagnostic(), presentation.CompletionClass(),
				presentation.PublicationState(), presentation.PublicationCode(),
				presentation.Warnings(), presentation.ArchivePending(),
			)
		}
		text := pcv3RenderedText(a.pcv3Container)
		fragments := []string{
			"Unverified recovery artifact created",
			"Some recovered bytes are not authenticated and may be corrupted or unsafe. Do not open or extract this artifact as trusted content.",
		}
		if runtime.GOOS == "windows" {
			fragments = append(fragments, "Output durability not confirmed", nativePCV3UncertainBody, nativePCV3DurabilityWarningText, "Close durability warning")
			if strings.Contains(text, "File saved.") || strings.Contains(text, "Inspect recovery artifact") || executed.ArtifactInspection() != nil {
				t.Fatalf("uncertain native artifact gained durable publication authority: %q", text)
			}
		} else {
			fragments = append(fragments, "File saved.", "Inspect recovery artifact", "Close")
		}
		for _, fragment := range fragments {
			if !strings.Contains(text, fragment) {
				t.Fatalf("rendered result view %q lacks exact fragment %q", text, fragment)
			}
		}
		if strings.Contains(text, "Retry") || strings.Contains(text, "continue") {
			t.Fatalf("unverified-force result offered downgrade/retry: %q", text)
		}
		for _, sensitive := range []string{
			secret,
			dir, filepath.Base(dir),
			fixturePath, filepath.Base(fixturePath),
			red, filepath.Base(red),
			blue, filepath.Base(blue),
			output, filepath.Base(output),
		} {
			if strings.Contains(text, sensitive) {
				t.Fatalf("result view disclosed secret or path sentinel %q: %q", sensitive, text)
			}
		}
		if a.State.Password != "" || a.State.Keyfiles != nil {
			t.Fatal("desktop retained credential entries after transfer")
		}
		if _, err := source.Stat(); err == nil {
			t.Fatal("transferred source descriptor remained open")
		}
		artifact, err := os.Lstat(output)
		if err != nil {
			t.Fatalf("consented unverified operation left no artifact: %v", err)
		}
		if !artifact.Mode().IsRegular() || (runtime.GOOS != "windows" && artifact.Mode().Perm() != 0o600) || artifact.Size() != 121 {
			t.Fatalf(
				"unverified artifact = mode %v size %d; want one regular 0600 file with the exact bounded candidate",
				artifact.Mode(), artifact.Size(),
			)
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

	t.Run("real normal operation carries no consent and publishes the frozen plaintext", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		base := t.TempDir()
		dir := filepath.Join(base, "privacy-ui-normal-path-49d1ac")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create sentinel directory: %v", err)
		}
		secret := "mix"
		fixturePath := filepath.Join(
			"..", "pcv3operation", "internal", "pcv3", "testdata", "normal", "volumes",
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
		output := filepath.Join(dir, "normal.bin")

		var executorCalls atomic.Int32
		requestShape := make(chan string, 1)
		executedResults := make(chan *pcv3operation.Result, 1)
		a.pcv3OperationExecutor = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
			executorCalls.Add(1)
			shape := ""
			if request == nil || request.Mode != pcv3operation.ModeReadNormal || request.Consent != nil ||
				request.Source == nil || request.Source.Name() != fixturePath || request.Target != output ||
				request.Factors == nil || request.Factors.Mode != pcv3operation.CredentialModePasswordAndKeyfiles ||
				request.Factors.ExpectedPolicy != pcv3operation.FactorPolicyPasswordAndKeyfiles ||
				request.Factors.KeyfileMode != pcv3operation.KeyfileModeOrdered ||
				len(request.Factors.Keyfiles) != 2 || len(request.Protected) != 2 ||
				request.Protected[0] != red || request.Protected[1] != blue {
				shape = "normal request did not preserve nil consent and red/blue factor order"
			}
			requestShape <- shape
			result := pcv3operation.Run(ctx, request)
			executedResults <- result
			return result
		}
		fyne.DoAndWait(func() {
			if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, fixturePath, output, info.Size()) {
				t.Fatal("set PCV3 selection")
			}
			a.State.Password = secret
			a.State.Keyfiles = []string{red, blue}
			a.State.KeyfileOrdered = true
			a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyCombined, app.PCV3KeyfileOrderSelected)
			a.refreshAdvanced()
			a.updateUIState()
			a.startPCV3Work()
		})

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
			t.Fatalf("normal PCV3 operation did not reach a terminal presentation: calls=%d", executorCalls.Load())
		}
		if executorCalls.Load() != 1 {
			t.Fatalf("normal operation executor calls = %d; want exactly one", executorCalls.Load())
		}
		shape, ok := <-requestShape
		if !ok || shape != "" {
			t.Fatal(shape)
		}
		executed, ok := <-executedResults
		if !ok || executed == nil {
			t.Fatal("normal operation executor returned no closed result")
		}
		if a.pcv3Result != executed {
			t.Fatal("the desktop reconstructed rather than retained the normal operation result")
		}
		if executed.AuthenticatedComment() != "TEST ONLY comment" {
			t.Fatalf("authenticated comment = %q; want frozen fixture comment", executed.AuthenticatedComment())
		}
		presentation := a.State.UISnapshot().PCV3Result
		core := executed.Presentation()
		if presentation.Outcome() != core.Outcome() || presentation.Stage() != core.Stage() ||
			presentation.Code() != core.Code() || presentation.Diagnostic() != core.Diagnostic() ||
			presentation.CompletionClass() != core.CompletionClass() ||
			presentation.PublicationAttempted() != core.PublicationAttempted() ||
			presentation.PublicationState() != core.PublicationState() ||
			presentation.PublicationStage() != core.PublicationStage() ||
			presentation.PublicationCode() != core.PublicationCode() ||
			presentation.ArchivePending() != core.ArchivePending() {
			t.Fatal("State presentation drifted from the normal operation's closed presentation")
		}
		requireNativePCV3Publication(t, executed)
		text := pcv3RenderedText(a.pcv3Container)
		wantText := "Operation complete\nThe output is fully authenticated.\nComments:\nTEST ONLY comment\nFile saved.\nClose"
		if runtime.GOOS == "windows" {
			wantText = "Operation complete\nThe output is fully authenticated.\nComments:\nTEST ONLY comment\nOutput durability not confirmed\n" + nativePCV3UncertainBody + "\n" + nativePCV3DurabilityWarningText + "\nClose durability warning"
		}
		if text != wantText {
			t.Fatalf("normal result view = %q; want exact bounded success rendering", text)
		}
		for _, sentinel := range []string{
			secret,
			fixturePath,
			filepath.Base(fixturePath),
			red,
			filepath.Base(red),
			blue,
			filepath.Base(blue),
			output,
			filepath.Base(output),
		} {
			if strings.Contains(text, sentinel) {
				t.Fatalf("normal result view disclosed request-crossing sentinel %q: %q", sentinel, text)
			}
		}
		if a.State.Password != "" || a.State.Keyfiles != nil {
			t.Fatal("desktop retained normal credential entries after transfer")
		}
		if _, err := source.Stat(); err == nil {
			t.Fatal("normal transferred source descriptor remained open")
		}
		plaintext, err := os.ReadFile(output)
		if err != nil || len(plaintext) != 1 || plaintext[0] != 0x02 {
			t.Fatalf("normal durable publication = %x err=%v; want exact frozen plaintext 02", plaintext, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("inspect normal sentinel directory: %v", err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
				t.Fatalf("desktop left normal publication stage residue %q", entry.Name())
			}
		}
	})
}
