package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/pcv3recovery"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	fynetest "fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func mustPCV3Presentation(t *testing.T, spec pcv3operation.PresentationSpec) pcv3operation.Presentation {
	t.Helper()
	presentation, err := pcv3operation.NewPresentation(spec)
	if err != nil {
		t.Fatalf("NewPresentation(%#v): %v", spec, err)
	}
	return presentation
}

func pcv3RenderedText(object fyne.CanvasObject) string {
	if object == nil || !object.Visible() {
		return ""
	}
	switch value := object.(type) {
	case *widget.Label:
		return value.Text
	case *widget.Button:
		return value.Text
	case *widget.RadioGroup:
		return strings.Join(value.Options, "\n")
	case *widget.Check:
		return value.Text
	case *container.Scroll:
		return pcv3RenderedText(value.Content)
	case *fyne.Container:
		parts := make([]string, 0, len(value.Objects))
		for _, child := range value.Objects {
			if text := pcv3RenderedText(child); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func findPCV3Scroll(object fyne.CanvasObject) *container.Scroll {
	switch value := object.(type) {
	case *container.Scroll:
		return value
	case *fyne.Container:
		for _, child := range value.Objects {
			if scroll := findPCV3Scroll(child); scroll != nil {
				return scroll
			}
		}
	}
	return nil
}

func requirePCV3Text(t *testing.T, object fyne.CanvasObject, fragments ...string) {
	t.Helper()
	text := pcv3RenderedText(object)
	for _, fragment := range fragments {
		if !strings.Contains(text, fragment) {
			t.Fatalf("rendered text %q does not contain %q", text, fragment)
		}
	}
}

func checkPCV3CaseInventory(t *testing.T, executed []string, required []string) {
	t.Helper()
	counts := make(map[string]int, len(executed))
	for _, id := range executed {
		counts[id]++
	}
	for _, id := range required {
		if counts[id] != 1 {
			t.Fatalf("case %s executed %d times; want exactly once", id, counts[id])
		}
		delete(counts, id)
	}
	if len(counts) != 0 {
		t.Fatalf("unexpected executed cases: %v", counts)
	}
}

func TestPCV3FynePreservesFactorIntent(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.bin")
	keyfilePath := filepath.Join(dir, "factor.key")
	if err := os.WriteFile(sourcePath, []byte("source"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.WriteFile(keyfilePath, []byte("factor"), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}

	for _, test := range []struct {
		name   string
		format app.PCV3Format
		action app.PCV3Action
		mode   pcv3operation.Mode
	}{
		{"normal decrypt", app.PCV3FormatNormal, app.PCV3ActionDecrypt, pcv3operation.ModeReadNormal},
		{"normal recovery", app.PCV3FormatNormal, app.PCV3ActionRecovery, pcv3operation.ModeRecoverNormal},
		{"normal Force", app.PCV3FormatNormal, app.PCV3ActionForce, pcv3operation.ModeForceNormal},
		{"normal unverified Force", app.PCV3FormatNormal, app.PCV3ActionForceUnverified, pcv3operation.ModeForceUnverifiedNormal},
		{"D1 decrypt", app.PCV3FormatD1, app.PCV3ActionDecrypt, pcv3operation.ModeReadD1},
		{"D1 recovery", app.PCV3FormatD1, app.PCV3ActionRecovery, pcv3operation.ModeRecoverD1},
		{"D1 Force", app.PCV3FormatD1, app.PCV3ActionForce, pcv3operation.ModeForceD1},
		{"D1 unverified Force", app.PCV3FormatD1, app.PCV3ActionForceUnverified, pcv3operation.ModeForceUnverifiedD1},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatalf("open source: %v", err)
			}
			intent := app.PCV3OperationIntent{
				Format: test.format, Action: test.action,
				FactorPolicy: app.PCV3FactorPolicyCombined,
				KeyfileOrder: app.PCV3KeyfileOrderSelected,
				Source:       source, Target: filepath.Join(dir, test.name+".out"),
				Password: []byte("owned password"),
				Keyfiles: []string{keyfilePath, keyfilePath},
			}
			request, err := buildPCV3Request(&intent)
			if err != nil {
				t.Fatalf("buildPCV3Request: %v", err)
			}
			defer func() {
				_ = request.Source.Close()
				_ = request.Factors.Close()
			}()
			if request.Mode != test.mode {
				t.Fatalf("operation mode = %v; want %v", request.Mode, test.mode)
			}
			if request.Factors.Mode != pcv3credential.CredentialModePasswordAndKeyfiles ||
				request.Factors.ExpectedPolicy != pcv3credential.FactorPolicyPasswordAndKeyfiles ||
				request.Factors.KeyfileMode != pcv3credential.KeyfileModeOrdered ||
				string(request.Factors.Password) != "owned password" ||
				len(request.Factors.Keyfiles) != 2 ||
				!reflect.DeepEqual(request.Protected, []string{keyfilePath, keyfilePath}) {
				t.Fatalf("factor intent changed before core: factors=%#v protected=%v", request.Factors, request.Protected)
			}
			if intent.Source != nil || intent.Password != nil || intent.Keyfiles != nil || intent.Target != "" {
				t.Fatalf("caller retained transferred fields: %#v", intent)
			}
		})
	}
}

func TestPCV3ForceConsentExistsOnlyForExplicitUnverifiedAction(t *testing.T) {
	for _, test := range []struct {
		name        string
		format      app.PCV3Format
		action      app.PCV3Action
		wantMode    pcv3operation.Mode
		wantConsent bool
	}{
		{"normal authenticated", app.PCV3FormatNormal, app.PCV3ActionForce, pcv3operation.ModeForceNormal, false},
		{"D1 authenticated", app.PCV3FormatD1, app.PCV3ActionForce, pcv3operation.ModeForceD1, false},
		{"normal unverified", app.PCV3FormatNormal, app.PCV3ActionForceUnverified, pcv3operation.ModeForceUnverifiedNormal, true},
		{"D1 unverified", app.PCV3FormatD1, app.PCV3ActionForceUnverified, pcv3operation.ModeForceUnverifiedD1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)
			directory := t.TempDir()
			input := filepath.Join(directory, "input.pcv")
			if err := os.WriteFile(input, nil, 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			source, err := os.Open(input)
			if err != nil {
				t.Fatalf("open input: %v", err)
			}

			type observation struct {
				mode       pcv3operation.Mode
				hasConsent bool
			}
			observed := make(chan observation, 1)
			a.pcv3OperationExecutor = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
				observed <- observation{mode: request.Mode, hasConsent: request.Consent != nil}
				if request.Source != nil {
					_ = request.Source.Close()
					request.Source = nil
				}
				if request.Factors != nil {
					_ = request.Factors.Close()
					request.Factors = nil
				}
				return pcv3operation.Run(context.Background(), &pcv3operation.Request{})
			}
			t.Cleanup(func() {
				a.workers.wait()
				fyne.DoAndWait(func() { a.State.Reset() })
			})

			fyne.DoAndWait(func() {
				if !a.State.SetPCV3Ready(
					source,
					test.format,
					input,
					filepath.Join(directory, "output"),
					0,
				) {
					t.Fatal("set PCV3 selection")
				}
				a.State.Password = "password-only"
				a.State.SetPCV3Intent(test.action, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
				a.startPCV3Work()
			})

			select {
			case got := <-observed:
				if got.mode != test.wantMode || got.hasConsent != test.wantConsent {
					t.Fatalf(
						"request = mode %v consent %v; want mode %v consent %v",
						got.mode,
						got.hasConsent,
						test.wantMode,
						test.wantConsent,
					)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("PCV3 request did not reach the executor")
			}
		})
	}
}

// TestPCV3FynePreservesResultAxes protects the desktop projection of the
// closed result tuple: every frozen literal PresentationSpec must keep its
// outcome/stage/code/diagnostic/completion/publication axes through the real
// State snapshot and render exactly the matching bounded copy, warnings, and
// terminal action. It is the Fyne counterpart of the CLI and mobile
// PreservesResultAxes contracts.
func TestPCV3FynePreservesResultAxes(t *testing.T) {
	resetLocalizationForTest(t)
	tests := []struct {
		name           string
		spec           pcv3operation.PresentationSpec
		wantCompletion pcv3operation.CompletionClass
		wantText       []string
		forbidText     []string
		wantAction     string
		forbidActions  []string
	}{
		{
			name: "clean durable",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone, Code: pcv3.CodeSuccess,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurable,
				PublicationCode:      pcv3publication.CodePublishedDurable,
			},
			wantCompletion: pcv3operation.CompletionClean,
			wantText: []string{
				"Decryption complete", "The output is fully authenticated.",
				"Output publication is durable.",
			},
			forbidText: []string{"Cleanup could not be confirmed"},
			wantAction: "Close publication result",
		},
		{
			name: "authenticated degraded durable",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeAuthenticatedDegraded, Stage: pcv3.StageMetadata,
				Code:                 pcv3.CodeAuthenticatedDegraded,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurable,
				PublicationCode:      pcv3publication.CodePublishedDurable,
				Warnings:             []pcv3operation.Warning{pcv3operation.WarningAuthenticatedDegraded},
			},
			wantCompletion: pcv3operation.CompletionWarning,
			wantText: []string{
				"Authenticated output recovered with damage", "Output publication is durable.",
				"The output is authenticated, but recovery redundancy is damaged. Keep the original volume.",
			},
			forbidText: []string{"Decryption complete"},
			wantAction: "Close publication result",
		},
		{
			name: "force partial durable",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeForcePartial, Stage: pcv3.StageRecordAuth, Code: pcv3.CodeForcePartial,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurable,
				PublicationCode:      pcv3publication.CodePublishedDurable,
				Warnings:             []pcv3operation.Warning{pcv3operation.WarningForcePartial},
			},
			wantCompletion: pcv3operation.CompletionWarning,
			wantText: []string{
				"Partial recovery artifact created",
				"Some ranges are verified and some are missing. This .pcv3-recovery file is not a complete plaintext file.",
				"Output publication is durable.",
			},
			forbidText: []string{"Decryption complete"},
			wantAction: "Close publication result",
		},
		{
			name: "force unverified durable",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeForceUnverified, Stage: pcv3.StageRecordAuth, Code: pcv3.CodeForceUnverified,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurable,
				PublicationCode:      pcv3publication.CodePublishedDurable,
				Warnings:             []pcv3operation.Warning{pcv3operation.WarningForceUnverified},
			},
			wantCompletion: pcv3operation.CompletionWarning,
			wantText: []string{
				"Unverified recovery artifact created",
				"Some recovered bytes are not authenticated and may be corrupted or unsafe. Do not open or extract this artifact as trusted content.",
				"Output publication is durable.",
			},
			forbidText: []string{"Decryption complete"},
			wantAction: "Close publication result",
		},
		{
			name: "clean durable with cleanup warning",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone, Code: pcv3.CodeSuccess,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurable,
				PublicationCode:      pcv3publication.CodePublishedDurable,
				Warnings:             []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete},
			},
			wantCompletion: pcv3operation.CompletionWarning,
			wantText: []string{
				"Decryption complete", "Output publication is durable.",
				"Cleanup could not be confirmed",
				"The application could not prove that all operation-owned temporary plaintext was removed. Keep the encrypted source and do not delete files based on this result.",
			},
			wantAction:    "Close cleanup warning",
			forbidActions: []string{"Close publication result"},
		},
		{
			name: "durability uncertain overrides clean",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone, Code: pcv3.CodeSuccess,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublishedDurabilityUncertain,
				PublicationStage:     pcv3.StageDirectorySync,
				PublicationCode:      pcv3publication.CodeDurabilityUncertain,
				Warnings:             []pcv3operation.Warning{pcv3operation.WarningDurabilityUncertain},
			},
			wantCompletion: pcv3operation.CompletionDurabilityUncertain,
			wantText: []string{
				"Decryption complete", "Output durability not confirmed",
				"The destination may contain the output, but filesystem durability could not be confirmed. Keep every source and the destination. Do not retry, replace, delete, or clean up this operation.",
				"Output durability was not confirmed. Keep every source and the destination.",
			},
			wantAction:    "Close durability warning",
			forbidActions: []string{"Close publication result"},
		},
		{
			name: "publication indeterminate overrides force",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeForcePartial, Stage: pcv3.StageRecordAuth, Code: pcv3.CodeForcePartial,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StatePublicationIndeterminate,
				PublicationStage:     pcv3.StageOutputPublication,
				PublicationCode:      pcv3publication.CodePublicationIndeterminate,
				Warnings: []pcv3operation.Warning{
					pcv3operation.WarningForcePartial,
					pcv3operation.WarningPublicationIndeterminate,
				},
			},
			wantCompletion: pcv3operation.CompletionPublicationIndeterminate,
			wantText: []string{
				"Partial recovery artifact created", "Output state is unknown",
				"The application cannot determine whether publication committed. Keep every source and the destination exactly as they are. Do not retry or clean up this operation.",
				"Output publication state is unknown. Keep every source and the destination exactly as they are.",
			},
			forbidText: []string{"Decryption complete"},
			wantAction: "Close publication warning",
		},
		{
			name: "refused without publication",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeUnsupportedRoutingPreKDF, Stage: pcv3.StageRouting,
				Code: pcv3.CodeUnsupported,
			},
			wantCompletion: pcv3operation.CompletionRefused,
			wantText: []string{
				"Unsupported PCV3 format",
				"No output was created, and the file was not tried as a legacy volume.",
			},
			forbidText: []string{"Output publication is durable."},
			wantAction: "Close recovery result",
		},
		{
			name: "not published",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeOperationFailed, Stage: pcv3.StageOutputPublication,
				Code:                 pcv3.CodeOperationFailed,
				PublicationAttempted: true,
				PublicationState:     pcv3publication.StateNotPublished,
				PublicationStage:     pcv3.StageOutputPublication,
				PublicationCode:      pcv3publication.CodeAtomicFailed,
			},
			wantCompletion: pcv3operation.CompletionNoOutput,
			wantText: []string{
				"Operation failed",
				"The operation failed safely. No output was published. Keep the source and review the reported state.",
				"No output was published", "Source files were kept.",
			},
			wantAction: "Close publication result",
		},
		{
			name: "archive pending remains visibly nonterminal",
			spec: pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone, Code: pcv3.CodeSuccess,
				ArchivePending: true,
			},
			wantCompletion: pcv3operation.CompletionArchivePending,
			wantText: []string{
				"Authenticated archive ready to extract",
				"The archive payload is fully authenticated. Choose a new extraction folder. The encrypted source is kept.",
			},
			forbidText: []string{"Decryption complete"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := mustNewState(t)
			state.SetPCV3Result(mustPCV3Presentation(t, test.spec))
			snapshot := state.UISnapshot().PCV3Result
			if snapshot.Outcome() != test.spec.Outcome ||
				snapshot.Stage() != test.spec.Stage ||
				snapshot.Code() != test.spec.Code ||
				snapshot.Diagnostic() != test.spec.Diagnostic ||
				snapshot.ArchivePending() != test.spec.ArchivePending ||
				snapshot.PublicationAttempted() != test.spec.PublicationAttempted ||
				snapshot.PublicationState() != test.spec.PublicationState ||
				snapshot.PublicationStage() != test.spec.PublicationStage ||
				snapshot.PublicationCode() != test.spec.PublicationCode ||
				!slices.Equal(snapshot.Warnings(), test.spec.Warnings) ||
				snapshot.CompletionClass() != test.wantCompletion {
				t.Fatalf(
					"Fyne result snapshot lost axes: outcome=%v stage=%v code=%v diagnostic=%v pending=%v "+
						"publication=%v/%v/%v/%v warnings=%v completion=%v; want completion=%v from spec %#v",
					snapshot.Outcome(), snapshot.Stage(), snapshot.Code(), snapshot.Diagnostic(),
					snapshot.ArchivePending(), snapshot.PublicationAttempted(), snapshot.PublicationState(),
					snapshot.PublicationStage(), snapshot.PublicationCode(), snapshot.Warnings(),
					snapshot.CompletionClass(), test.wantCompletion, test.spec,
				)
			}

			view := (&App{}).buildPCV3ResultView(snapshot, nil)
			text := pcv3RenderedText(view)
			for _, fragment := range test.wantText {
				if !strings.Contains(text, fragment) {
					t.Fatalf("rendered result %q does not contain %q", text, fragment)
				}
			}
			for _, fragment := range test.forbidText {
				if strings.Contains(text, fragment) {
					t.Fatalf("rendered result %q must not contain %q", text, fragment)
				}
			}
			if test.wantAction == "" {
				for _, action := range []string{
					"Extract archive", "Close without extracting", "Inspect recovery artifact",
					"Close publication result", "Close durability warning", "Close publication warning",
					"Close cleanup warning", "Close recovery result",
				} {
					if findPCV3Button(view, action) != nil {
						t.Fatalf("nonterminal presentation minted action %q", action)
					}
				}
				return
			}
			button := findPCV3Button(view, test.wantAction)
			if button == nil || button.Disabled() {
				t.Fatalf("terminal action %q = %v; want a live enabled button", test.wantAction, button)
			}
			for _, action := range test.forbidActions {
				if findPCV3Button(view, action) != nil {
					t.Fatalf("result rendered superseded action %q", action)
				}
			}
		})
	}
}

func TestPCV3FyneGenerationOwnsTerminalResult(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.bin")
	secondPath := filepath.Join(dir, "second.bin")
	for _, path := range []string{firstPath, secondPath} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write source: %v", err)
		}
	}
	resultSource, err := os.Open(firstPath)
	if err != nil {
		t.Fatalf("open cancellation source: %v", err)
	}
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	firstResult := pcv3operation.Run(cancelledContext, &pcv3operation.Request{
		Mode: pcv3operation.ModeReadD1, Source: resultSource,
		Factors: &pcv3credential.FactorRequest{
			Mode:           pcv3credential.CredentialModePasswordOnly,
			ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly,
			Password:       []byte("cancelled result"),
		},
		Target: filepath.Join(dir, "cancelled.out"),
	})
	secondResult := pcv3operation.Run(context.Background(), &pcv3operation.Request{})
	if firstResult.Diagnostic() == secondResult.Diagnostic() {
		t.Fatal("generation regression oracle requires distinct real terminal results")
	}
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseFirstOnce sync.Once
	firstReturned := make(chan struct{})
	secondDone := make(chan struct{})
	thirdEntered := make(chan struct{})
	releaseThird := make(chan struct{})
	var releaseThirdOnce sync.Once
	thirdReturned := make(chan struct{})
	t.Cleanup(func() {
		releaseFirstOnce.Do(func() { close(releaseFirst) })
		releaseThirdOnce.Do(func() { close(releaseThird) })
		a.workers.wait()
	})
	var calls int
	a.pcv3OperationExecutor = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
		calls++
		call := calls
		if request.Source != nil {
			_ = request.Source.Close()
			request.Source = nil
		}
		if request.Factors != nil {
			_ = request.Factors.Close()
			request.Factors = nil
		}
		if call == 1 {
			close(firstEntered)
			<-releaseFirst
			close(firstReturned)
			return firstResult
		}
		if call == 2 {
			close(secondDone)
			return secondResult
		}
		close(thirdEntered)
		<-releaseThird
		close(thirdReturned)
		return secondResult
	}

	start := func(path, output string) {
		source, err := os.Open(path)
		if err != nil {
			t.Fatalf("open source: %v", err)
		}
		fyne.DoAndWait(func() {
			if !a.State.SetPCV3Ready(source, app.PCV3FormatD1, path, output, 0) {
				t.Fatal("set PCV3 selection")
			}
			a.State.Password = "generation password"
			a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
			a.refreshAdvanced()
			a.updateUIState()
			a.startPCV3Work()
		})
	}
	start(firstPath, filepath.Join(dir, "first.out"))
	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first operation did not start")
	}
	fyne.DoAndWait(func() {
		a.stopCurrentOperation()
		a.operationGeneration.Add(1)
		a.releasePCV3Result()
		a.State.Reset()
		a.refreshAdvanced()
		a.updateUIState()
	})
	start(secondPath, filepath.Join(dir, "second.out"))
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("second operation did not complete")
	}
	waitForPCV3UI(t, func() bool {
		return !a.State.IsWorking() && a.State.UISnapshot().PCV3Result.Diagnostic() == secondResult.Diagnostic()
	}, "second generation did not own terminal state")
	before := a.State.UISnapshot().PCV3Result
	releaseFirstOnce.Do(func() { close(releaseFirst) })
	select {
	case <-firstReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("first operation did not return")
	}
	a.workers.wait()
	fyne.DoAndWait(func() {
		after := a.State.UISnapshot().PCV3Result
		if after.Diagnostic() != before.Diagnostic() || after.Stage() != before.Stage() ||
			after.CompletionClass() != before.CompletionClass() {
			t.Fatalf("late generation clobbered terminal result: before=%v/%v/%v after=%v/%v/%v",
				before.Diagnostic(), before.Stage(), before.CompletionClass(),
				after.Diagnostic(), after.Stage(), after.CompletionClass())
		}
		if !a.clearButton.Disabled() {
			t.Fatal("transferred terminal result exposed generic Clear")
		}
	})

	// A local cancel racing with one current-generation closed Result cannot
	// replace the core's authoritative terminal tuple.
	fyne.DoAndWait(func() { a.resetUI() })
	start(firstPath, filepath.Join(dir, "third.out"))
	select {
	case <-thirdEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("third operation did not start")
	}
	a.operationMu.Lock()
	thirdSession := a.operationSession
	a.operationMu.Unlock()
	fyne.DoAndWait(func() { a.cancelOperation(thirdSession) })
	releaseThirdOnce.Do(func() { close(releaseThird) })
	select {
	case <-thirdReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled current operation did not return")
	}
	a.workers.wait()
	fyne.DoAndWait(func() {
		presentation := a.State.UISnapshot().PCV3Result
		if presentation.Diagnostic() != secondResult.Diagnostic() ||
			presentation.Stage() != secondResult.Stage() ||
			presentation.CompletionClass() != secondResult.CompletionClass() {
			t.Fatalf("local cancellation hid returned core result: got %v/%v/%v want %v/%v/%v",
				presentation.Diagnostic(), presentation.Stage(), presentation.CompletionClass(),
				secondResult.Diagnostic(), secondResult.Stage(), secondResult.CompletionClass())
		}
		if !a.clearButton.Disabled() {
			t.Fatal("current transferred terminal result exposed generic Clear")
		}
	})
}

// TestPCV3FyneArchiveExtractionCancelUsesExistingGeneration protects the
// desktop boundary around the core-owned archive effect. The blocking action
// stands in only for that slow effect; App, State, worker registration,
// generation ownership, and the existing Cancel path are all production code.
// Removing CanCancel, binding the action to the worker-lifecycle context, or
// incrementing the authenticated result generation must make this test fail.
func TestPCV3FyneArchiveExtractionCancelUsesExistingGeneration(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	ensurePCV3TestWorkersReleased(t, a, nil)
	result, generation := preparePCV3ArchiveFollowUpState(t, a)

	entered := make(chan context.Context, 1)
	returned := make(chan struct{})
	startPCV3ArchiveFollowUpForTest(t, a, result, generation, true, func(ctx context.Context) *pcv3operation.Result {
		entered <- ctx
		<-ctx.Done()
		close(returned)
		return nil
	})

	var effectContext context.Context
	select {
	case effectContext = <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("archive follow-up action did not start")
	}

	snap := a.State.UISnapshot()
	if !snap.Working || !snap.CanCancel {
		t.Fatalf("archive extraction state = working %v, can-cancel %v; want true/true", snap.Working, snap.CanCancel)
	}
	a.operationMu.Lock()
	session := a.operationSession
	a.operationMu.Unlock()
	if session == nil || session.generation != generation {
		t.Fatalf("archive extraction session = %#v; want result generation %d", session, generation)
	}
	if effectContext != session.ctx {
		t.Fatal("archive effect did not receive the exact cancelable session context")
	}
	if a.pcv3CancelButton == nil || a.pcv3CancelButton.Disabled() {
		t.Fatalf("archive extraction Cancel button = %#v; want rendered and enabled", a.pcv3CancelButton)
	}

	fyne.DoAndWait(func() { fynetest.Tap(a.pcv3CancelButton) })
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Cancel did not stop the archive follow-up action")
	}
	a.workers.wait()
	waitForPCV3UI(t, func() bool { return !a.State.IsWorking() }, "cancelled archive follow-up did not finalize")

	if a.operationGeneration.Load() != generation {
		t.Fatalf("archive follow-up changed result generation: got %d want %d", a.operationGeneration.Load(), generation)
	}
	a.operationMu.Lock()
	currentSession := a.operationSession
	a.operationMu.Unlock()
	if currentSession != nil {
		t.Fatalf("archive follow-up left operation session %#v", currentSession)
	}
	final := a.State.UISnapshot()
	if final.Working || final.CanCancel || !final.PCV3CleanupIncomplete {
		t.Fatalf(
			"archive terminal state = working %v, can-cancel %v, cleanup-warning %v; want false/false/true",
			final.Working, final.CanCancel, final.PCV3CleanupIncomplete,
		)
	}
	if final.PCV3Result.Diagnostic() != pcv3operation.DiagnosticCancellation {
		t.Fatalf("nil result after user cancellation mapped to diagnostic %v; want cancellation", final.PCV3Result.Diagnostic())
	}
}

func TestPCV3FyneArchiveCloseDoesNotAdvertiseCancellation(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	result, generation := preparePCV3ArchiveFollowUpState(t, a)

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAction := func() { releaseOnce.Do(func() { close(release) }) }
	ensurePCV3TestWorkersReleased(t, a, releaseAction)
	next := pcv3operation.Run(context.Background(), &pcv3operation.Request{})
	startPCV3ArchiveFollowUpForTest(t, a, result, generation, false, func(context.Context) *pcv3operation.Result {
		close(entered)
		<-release
		return next
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("close-without-extracting action did not start")
	}

	snap := a.State.UISnapshot()
	a.operationMu.Lock()
	session := a.operationSession
	a.operationMu.Unlock()
	if !snap.Working || snap.CanCancel || session != nil {
		t.Fatalf(
			"close-without-extracting state = working %v, can-cancel %v, session %p; want true/false/nil",
			snap.Working, snap.CanCancel, session,
		)
	}
	releaseAction()
	a.workers.wait()
	waitForPCV3UI(t, func() bool { return !a.State.IsWorking() }, "close-without-extracting did not finalize")
}

// TestPCV3FyneStaleArchiveCompletionCannotClearNewerSession protects the exact
// session clear and the process-lifetime cleanup latch independently. A late
// archive action may report cleanup uncertainty, but it must not replace or
// disable a newer operation generation.
func TestPCV3FyneStaleArchiveCompletionCannotClearNewerSession(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	result, generation := preparePCV3ArchiveFollowUpState(t, a)

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAction := func() { releaseOnce.Do(func() { close(release) }) }
	ensurePCV3TestWorkersReleased(t, a, releaseAction)
	startPCV3ArchiveFollowUpForTest(t, a, result, generation, true, func(context.Context) *pcv3operation.Result {
		close(entered)
		<-release
		return nil
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("archive follow-up action did not start")
	}

	newerResult := pcv3operation.Run(context.Background(), &pcv3operation.Request{})
	var newerSession *operationSession
	fyne.DoAndWait(func() {
		newerSession = a.newOperationSession()
		a.setOperationSession(newerSession)
		a.pcv3Result = newerResult
		a.pcv3ResultGeneration = newerSession.generation
		a.State.SetPCV3Result(newerResult.Presentation())
		a.State.SetWorking(true)
		a.State.SetCanCancel(true)
	})
	releaseAction()
	a.workers.wait()
	fyne.DoAndWait(func() {})

	a.operationMu.Lock()
	currentSession := a.operationSession
	a.operationMu.Unlock()
	snap := a.State.UISnapshot()
	if currentSession != newerSession || a.pcv3Result != newerResult ||
		a.pcv3ResultGeneration != newerSession.generation || !snap.Working || !snap.CanCancel {
		t.Fatalf(
			"stale archive completion replaced newer ownership: session=%p/%p result=%p/%p generation=%d/%d working=%v can-cancel=%v",
			currentSession, newerSession, a.pcv3Result, newerResult,
			a.pcv3ResultGeneration, newerSession.generation, snap.Working, snap.CanCancel,
		)
	}
	if !snap.PCV3CleanupIncomplete {
		t.Fatal("stale archive completion lost cleanup uncertainty")
	}
	fyne.DoAndWait(func() { a.cancelOperation(newerSession) })
}

func TestPCV3FyneArchiveShutdownDoesNotApplyTerminalResult(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	ensurePCV3TestWorkersReleased(t, a, nil)
	result, generation := preparePCV3ArchiveFollowUpState(t, a)

	entered := make(chan struct{})
	startPCV3ArchiveFollowUpForTest(t, a, result, generation, true, func(ctx context.Context) *pcv3operation.Result {
		close(entered)
		<-ctx.Done()
		return nil
	})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("archive follow-up action did not start")
	}

	a.stopSourcesAndContexts()
	a.workers.wait()
	fyne.DoAndWait(func() {})

	if a.operationGeneration.Load() == generation {
		t.Fatal("shutdown left archive result generation current")
	}
	if a.pcv3Result != nil {
		t.Fatalf("shutdown retained archive result %p", a.pcv3Result)
	}
	snap := a.State.UISnapshot()
	if !snap.PCV3Result.ArchivePending() {
		t.Fatalf("shutdown worker overwrote retained presentation with completion class %v", snap.PCV3Result.CompletionClass())
	}
	if !snap.PCV3CleanupIncomplete {
		t.Fatal("shutdown worker lost cleanup uncertainty before UI queueing")
	}
}

func preparePCV3ArchiveFollowUpState(
	t *testing.T,
	a *App,
) (*pcv3operation.Result, uint64) {
	t.Helper()
	directory := t.TempDir()
	selectedPath := filepath.Join(directory, "selected.pcv")
	if err := os.WriteFile(selectedPath, nil, 0o600); err != nil {
		t.Fatalf("write selected source: %v", err)
	}
	selected, err := os.Open(selectedPath)
	if err != nil {
		t.Fatalf("open selected source: %v", err)
	}
	if !a.State.SetPCV3Ready(
		selected,
		app.PCV3FormatNormal,
		selectedPath,
		filepath.Join(directory, "unused-output"),
		0,
	) {
		t.Fatal("set transferred PCV3 selection")
	}
	a.State.Password = "transfer only"
	a.State.SetPCV3Intent(
		app.PCV3ActionDecrypt,
		app.PCV3FactorPolicyPassword,
		app.PCV3KeyfileOrderUnset,
	)
	intent, ok := a.State.TakePCV3OperationIntent()
	if !ok {
		t.Fatal("transfer PCV3 selection")
	}
	closePCV3Intent(&intent)

	presentation := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome:        pcv3.OutcomeSuccess,
		Stage:          pcv3.StageNone,
		Code:           pcv3.CodeSuccess,
		ArchivePending: true,
	})
	result := pcv3operation.Run(context.Background(), &pcv3operation.Request{})
	generation := a.operationGeneration.Add(1)
	a.pcv3Result = result
	a.pcv3ResultGeneration = generation
	a.State.SetPCV3Result(presentation)
	return result, generation
}

func ensurePCV3TestWorkersReleased(t *testing.T, a *App, release func()) {
	t.Helper()
	t.Cleanup(func() {
		if release != nil {
			release()
		}
		a.stopCurrentOperation()
		a.workers.beginStop()
		a.workers.wait()
	})
}

func startPCV3ArchiveFollowUpForTest(
	t *testing.T,
	a *App,
	result *pcv3operation.Result,
	generation uint64,
	cancellable bool,
	run func(context.Context) *pcv3operation.Result,
) {
	t.Helper()
	started := false
	fyne.DoAndWait(func() {
		started = a.startPCV3ArchiveFollowUp(result, generation, cancellable, run)
	})
	if !started {
		t.Fatal("start PCV3 archive follow-up worker")
	}
}

// TestPCV3CleanupIncompletePersistsAfterResultRelease protects the warning
// that remains after a result's one-shot cleanup capability is gone.
func TestPCV3CleanupIncompletePersistsAfterResultRelease(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	result := pcv3operation.Run(context.Background(), &pcv3operation.Request{})
	a.pcv3ResultDisposer = func(got *pcv3operation.Result) bool {
		if got == nil {
			return false
		}
		if got != result {
			t.Fatal("release disposer received a different result")
		}
		return true
	}

	fyne.DoAndWait(func() {
		a.pcv3Result = result
		a.pcv3ResultGeneration = 41
		a.releasePCV3Result()
		a.State.ResetUI()
		a.updateUIState()
	})
	if snap := a.State.UISnapshot(); !snap.PCV3CleanupIncomplete {
		t.Fatal("release plus ResetUI lost cleanup-incomplete truth")
	}
	fyne.DoAndWait(func() {
		requirePCV3Text(
			t, a.pcv3Container,
			tr("pcv3.warning.cleanup_title", "Cleanup could not be confirmed"),
			pcv3WarningText(pcv3operation.WarningCleanupIncomplete),
		)
	})

	fyne.DoAndWait(func() {
		a.handleCloseRequest()
	})
	if snap := a.State.UISnapshot(); !snap.PCV3CleanupIncomplete {
		t.Fatal("shutdown cleared cleanup-incomplete truth")
	}
}

// TestPCV3CleanupWarningSurvivesLegacyRoute keeps process-lifetime cleanup
// truth visible when a legacy selection means the PCV3 surface would normally
// be hidden.
func TestPCV3CleanupWarningSurvivesLegacyRoute(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.State.SetPCV3RoutingChecking("legacy-selected.bin", 12)
		a.State.SetPCV3LegacyEligible()
		a.State.LatchPCV3CleanupIncomplete()
		a.updateUIState()
	})
	if a.pcv3Container.Hidden {
		t.Fatal("legacy route hid persistent cleanup warning")
	}
	requirePCV3Text(
		t, a.pcv3Container,
		tr("pcv3.warning.cleanup_title", "Cleanup could not be confirmed"),
		pcv3WarningText(pcv3operation.WarningCleanupIncomplete),
	)
}

// TestPCV3StaleWorkerLatchesCleanupBeforeUIQueueing protects cleanup truth
// from Fyne shutdown/drain dropping a queued callback. The stale worker must
// latch State before it requests the visible surface refresh.
func TestPCV3StaleWorkerLatchesCleanupBeforeUIQueueing(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	result := pcv3operation.Run(context.Background(), &pcv3operation.Request{})
	a.pcv3ResultDisposer = func(got *pcv3operation.Result) bool {
		if got != result {
			t.Fatalf("stale worker disposed %p; want %p", got, result)
		}
		return true
	}
	session := a.newOperationSession()
	a.operationGeneration.Add(1)
	a.finishPCV3Worker(session, result)

	if !a.State.UISnapshot().PCV3CleanupIncomplete {
		t.Fatal("stale worker deferred cleanup latch to Fyne callback")
	}
	waitForPCV3UI(t, func() bool {
		return strings.Contains(pcv3RenderedText(a.pcv3Container),
			tr("pcv3.warning.cleanup_title", "Cleanup could not be confirmed"))
	}, "stale worker did not refresh persistent cleanup warning")
}

func TestPCV3FyneContractAtCompactWidth(t *testing.T) {
	resetLocalizationForTest(t)
	required := []string{
		"C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "C10",
		"C11", "C12", "C13", "C14", "C15", "C16", "C17", "B01", "UI-D01", "UI-D02",
	}
	executed := make([]string, 0, len(required))
	run := func(id string, test func(*testing.T)) {
		t.Run(id, func(t *testing.T) {
			executed = append(executed, id)
			test(t)
		})
	}

	run("C01", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		requirePCV3Text(t, a.pcv3Container, "Choose a file", "Choose one file to decrypt")
		if !a.startButton.Disabled() {
			t.Fatal("empty PCV3 surface enabled Start")
		}
	})
	run("C02", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		fyne.DoAndWait(func() {
			a.State.SetPCV3RoutingChecking("selected.bin", 12)
			a.updateUIState()
		})
		requirePCV3Text(t, a.pcv3Container, "Checking selected file…")
		if !a.startButton.Disabled() || !a.passwordEntry.Disabled() {
			t.Fatal("routing pending left controls enabled")
		}
	})
	run("C03", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		fyne.DoAndWait(func() { a.State.SetPCV3RoutingFailed(); a.updateUIState() })
		text := pcv3RenderedText(a.pcv3Container)
		if !strings.Contains(text, "could not be classified safely") || strings.Contains(text, "/private/") {
			t.Fatalf("route failure copy = %q", text)
		}
	})
	run("C04", func(t *testing.T) {
		snap := app.UISnapshot{PCV3Route: app.PCV3RouteReady, PCV3Format: app.PCV3FormatNormal, OutputFile: "out"}
		view := buildPCV3IntentSummary(snap)
		requirePCV3Text(t, view, "Normal PCV3", "Not selected")
		if snap.CanStart() {
			t.Fatal("incomplete explicit operation intent became startable")
		}
	})
	run("C05", func(t *testing.T) {
		snap := app.UISnapshot{PCV3Route: app.PCV3RouteReady, PCV3Format: app.PCV3FormatNormal, PCV3Action: app.PCV3ActionDecrypt, OutputFile: "out"}
		state := &App{State: mustNewState(t)}
		if hint := state.startReadinessHint(snap); hint != "Choose the credential policy used for this operation." {
			t.Fatalf("unset policy hint = %q", hint)
		}
	})
	run("C06", func(t *testing.T) {
		presentation := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
			Outcome: pcv3.OutcomeOperationFailed, Stage: pcv3.StageCredentialPolicy,
			Code: pcv3.CodeOperationFailed, Diagnostic: pcv3operation.DiagnosticCredentialPolicy,
		})
		view := (&App{}).buildPCV3ResultView(presentation, nil)
		requirePCV3Text(t, view, "Credential policy does not match", "No key derivation or output started")
	})
	run("C07", func(t *testing.T) {
		snap := app.UISnapshot{
			PCV3Route: app.PCV3RouteReady, PCV3Format: app.PCV3FormatD1,
			PCV3Action: app.PCV3ActionRecovery, PCV3Factor: app.PCV3FactorPolicyCombined,
			PCV3Order: app.PCV3KeyfileOrderSelected, KeyfileCount: 2, OutputFile: "private/path",
		}
		view := buildPCV3IntentSummary(snap)
		text := pcv3RenderedText(view)
		for _, requiredText := range []string{"PCV3 D1", "Start recovery", "Password + keyfiles", "Use selected order", "2"} {
			if !strings.Contains(text, requiredText) {
				t.Fatalf("intent summary %q lacks %q", text, requiredText)
			}
		}
		if strings.Contains(text, "private/path") || strings.Contains(strings.ToLower(text), "identity") {
			t.Fatalf("intent summary leaked path or identity claim: %q", text)
		}
	})
	run("C08", func(t *testing.T) {
		snap := app.UISnapshot{
			PCV3Route: app.PCV3RouteReady, PCV3Format: app.PCV3FormatNormal,
			PCV3Action: app.PCV3ActionDecrypt, PCV3Factor: app.PCV3FactorPolicyCombined,
			PCV3Order: app.PCV3KeyfileOrderSelected, KeyfileCount: 2, OutputFile: "out",
		}
		view := buildPCV3IntentSummary(snap)
		requirePCV3Text(t, view, "Password + keyfiles", "2")
		if snap.CanStart() {
			t.Fatal("partial combined factors became startable")
		}
	})
	run("C09", func(t *testing.T) {
		_ = newTestFyneApp(t)
		dir := t.TempDir()
		sourcePath := filepath.Join(dir, "source.pcv")
		if err := os.WriteFile(sourcePath, nil, 0o600); err != nil {
			t.Fatalf("write source: %v", err)
		}
		source, err := os.Open(sourcePath)
		if err != nil {
			t.Fatalf("open source: %v", err)
		}
		state := mustNewState(t)
		if !state.SetPCV3Ready(source, app.PCV3FormatNormal, sourcePath, filepath.Join(dir, "out"), 0) {
			t.Fatal("set PCV3 selection")
		}
		t.Cleanup(state.Reset)
		privateRoot := filepath.Join(dir, "private-staging-tree")
		names := make([]string, 64)
		state.Keyfiles = make([]string, len(names))
		for index := range names {
			names[index] = strings.Repeat("long-keyfile-name-", 6) + strconv.Itoa(index) + ".bin"
			state.Keyfiles[index] = filepath.Join(privateRoot, names[index])
		}
		state.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyCombined, app.PCV3KeyfileOrderSelected)
		view := buildPCV3IntentSummary(state.UISnapshot())
		scroll := findPCV3Scroll(view)
		if scroll == nil {
			t.Fatal("many keyfiles did not render in a bounded scroll surface")
		}
		text := pcv3RenderedText(scroll)
		rendered := pcv3RenderedText(view)
		previous := -1
		for _, name := range names {
			position := strings.Index(text, name)
			if position <= previous {
				t.Fatalf("full keyfile display names lost selection order at %q", name)
			}
			previous = position
		}
		if strings.Contains(rendered, privateRoot) {
			t.Fatalf("keyfile list leaked private staging path: %q", rendered)
		}
	})
	run("C10", func(t *testing.T) {
		translations := []struct {
			language LanguageCode
			want     [3]string
		}{
			{language: "en", want: [3]string{"None selected", "1 keyfile", "3 keyfiles"}},
			{language: "ru", want: [3]string{"Не выбраны", "1 ключ-файл", "3 ключ-файла"}},
		}
		for _, translation := range translations {
			if err := setActiveLanguage(translation.language); err != nil {
				t.Fatalf("set language %s: %v", translation.language, err)
			}
			for index, count := range []int{0, 1, 3} {
				snap := app.UISnapshot{
					PCV3Route: app.PCV3RouteReady, PCV3Format: app.PCV3FormatNormal,
					PCV3Action: app.PCV3ActionDecrypt, PCV3Factor: app.PCV3FactorPolicyKeyfiles,
					PCV3Order: app.PCV3KeyfileOrderSelected, KeyfileCount: count, OutputFile: "out",
				}
				view := buildPCV3IntentSummary(snap)
				requirePCV3Text(t, view, translation.want[index])
				if count == 0 && snap.CanStart() {
					t.Fatal("zero keyfiles started keyfile-only policy")
				}
			}
		}
		_ = setActiveLanguage("en")
	})
	run("C11", func(t *testing.T) {
		view, ok := newPCV3ConsentView(
			pcv3operation.ModeForceUnverifiedNormal,
			[]pcv3operation.PhysicalRole{pcv3operation.RolePrimary, pcv3operation.RoleBackup},
			func(pcv3operation.PhysicalRole) {}, func() {},
		)
		if !ok || !view.confirm.Disabled() || view.roles.Selected != "" || view.ack.Checked || view.cancel.Importance != widget.HighImportance {
			t.Fatal("consent did not begin with safe default and no authority")
		}
	})
	run("C12", func(t *testing.T) {
		presentation := pcv3TerminalPresentation(pcv3operation.DiagnosticCallbackFailure)
		view := (&App{}).buildPCV3ResultView(presentation, nil)
		requirePCV3Text(t, view, "Operation failed", "No output was published")
		if strings.Contains(pcv3RenderedText(view), "Recover unverified") {
			t.Fatal("callback failure restored consent action")
		}
	})
	run("C13", func(t *testing.T) {
		view, _ := newPCV3ConsentView(
			pcv3operation.ModeForceUnverifiedD1,
			[]pcv3operation.PhysicalRole{pcv3operation.RoleD1Front, pcv3operation.RoleD1Tail},
			func(pcv3operation.PhysicalRole) {}, func() {},
		)
		fyne.DoAndWait(func() { view.roles.SetSelected(view.roles.Options[0]) })
		if !view.confirm.Disabled() {
			t.Fatal("role-only consent enabled confirmation")
		}
		fyne.DoAndWait(func() { view.roles.SetSelected(""); view.ack.SetChecked(true) })
		if !view.confirm.Disabled() {
			t.Fatal("acknowledgement-only consent enabled confirmation")
		}
	})
	run("C14", func(t *testing.T) {
		if got := pcv3ProgressText(pcv3operation.StatusCode(0xff)); got != "Working…" {
			t.Fatalf("unknown progress = %q", got)
		}
	})
	run("C15", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		dir := t.TempDir()
		sourcePath := filepath.Join(dir, "source.pcv")
		if err := os.WriteFile(sourcePath, nil, 0o600); err != nil {
			t.Fatalf("write source: %v", err)
		}
		source, err := os.Open(sourcePath)
		if err != nil {
			t.Fatalf("open source: %v", err)
		}
		entered := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		a.pcv3OperationExecutor = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
			if request.Source != nil {
				_ = request.Source.Close()
				request.Source = nil
			}
			if request.Factors != nil {
				_ = request.Factors.Close()
				request.Factors = nil
			}
			close(entered)
			<-release
			return pcv3operation.Run(context.Background(), &pcv3operation.Request{})
		}
		t.Cleanup(func() {
			releaseOnce.Do(func() { close(release) })
			a.workers.wait()
			fyne.DoAndWait(func() { a.State.Reset() })
		})
		fyne.DoAndWait(func() {
			if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, sourcePath, filepath.Join(dir, "out"), 0) {
				t.Fatal("set PCV3 selection")
			}
			a.State.Password = "in-flight password"
			a.State.SetPCV3Intent(app.PCV3ActionRecovery, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
			a.startPCV3Work()
		})
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("operation session did not start")
		}
		fyne.DoAndWait(func() {
			a.State.SetPCV3Progress(pcv3operation.StatusRecovering)
			a.updateUIState()
		})
		requirePCV3Text(t, a.pcv3Container, "Recovering available ranges…", "Cancel recovery")
		if !a.startButton.Disabled() {
			t.Fatal("in-flight operation left duplicate Start enabled")
		}
		if !a.clearButton.Disabled() {
			t.Fatal("in-flight transferred operation exposed generic Clear")
		}
	})
	run("C16", func(t *testing.T) {
		for diagnostic, title := range map[pcv3operation.Diagnostic]string{
			pcv3operation.DiagnosticResourceBusy:         "Another secure operation is running",
			pcv3operation.DiagnosticResourceInsufficient: "Required resources are unavailable",
			pcv3operation.DiagnosticResourceUnknown:      "Device resources could not be verified",
		} {
			presentation := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
				Outcome: pcv3.OutcomeOperationFailed, Stage: pcv3.StageCredentialPolicy,
				Code: pcv3.CodeOperationFailed, Diagnostic: diagnostic,
			})
			view := (&App{}).buildPCV3ResultView(presentation, nil)
			requirePCV3Text(t, view, title)
			text := pcv3RenderedText(view)
			if strings.Contains(text, "continue") || strings.Contains(text, "Retry") {
				t.Fatalf("resource refusal offered downgrade/retry: %q", text)
			}
		}
	})
	run("C17", func(t *testing.T) {
		// Status Args are intentionally not interpreted by the renderer: absent,
		// inverted, and overflowing current/total tuples all remain indeterminate.
		for _, status := range []pcv3operation.StatusCode{0, pcv3operation.StatusRecovering, 0xff} {
			text := pcv3ProgressText(status)
			if strings.Contains(text, "%") {
				t.Fatalf("progress code %d invented a percentage: %q", status, text)
			}
		}
	})
	run("B01", func(t *testing.T) {
		states := []struct {
			name string
			spec pcv3operation.PresentationSpec
		}{
			{
				name: "archive ready without detached authority",
				spec: pcv3operation.PresentationSpec{
					Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone,
					Code: pcv3.CodeSuccess, ArchivePending: true,
				},
			},
			{
				name: "closed without extraction",
				spec: pcv3operation.PresentationSpec{
					Outcome: pcv3.OutcomeOperationFailed, Stage: pcv3.StageOutputPublication,
					Code: pcv3.CodeOperationFailed, Diagnostic: pcv3operation.DiagnosticNone,
				},
			},
			{
				name: "extracted durable",
				spec: pcv3operation.PresentationSpec{
					Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone, Code: pcv3.CodeSuccess,
					PublicationAttempted: true, PublicationState: pcv3publication.StatePublishedDurable,
					PublicationCode: pcv3publication.CodePublishedDurable,
				},
			},
			{
				name: "extraction not published",
				spec: pcv3operation.PresentationSpec{
					Outcome: pcv3.OutcomeOperationFailed, Stage: pcv3.StageOutputPublication,
					Code: pcv3.CodeOperationFailed, PublicationAttempted: true,
					PublicationState: pcv3publication.StateNotPublished,
					PublicationStage: pcv3.StageOutputPublication,
					PublicationCode:  pcv3publication.CodeAtomicFailed,
				},
			},
			{
				name: "extraction durability uncertain",
				spec: pcv3operation.PresentationSpec{
					Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone, Code: pcv3.CodeSuccess,
					PublicationAttempted: true,
					PublicationState:     pcv3publication.StatePublishedDurabilityUncertain,
					PublicationStage:     pcv3.StageDirectorySync,
					PublicationCode:      pcv3publication.CodeDurabilityUncertain,
				},
			},
			{
				name: "extraction publication indeterminate",
				spec: pcv3operation.PresentationSpec{
					Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone, Code: pcv3.CodeSuccess,
					PublicationAttempted: true,
					PublicationState:     pcv3publication.StatePublicationIndeterminate,
					PublicationStage:     pcv3.StageOutputPublication,
					PublicationCode:      pcv3publication.CodePublicationIndeterminate,
				},
			},
			{
				name: "durable extraction with cleanup warning",
				spec: pcv3operation.PresentationSpec{
					Outcome: pcv3.OutcomeSuccess, Stage: pcv3.StageNone, Code: pcv3.CodeSuccess,
					PublicationAttempted: true, PublicationState: pcv3publication.StatePublishedDurable,
					PublicationCode: pcv3publication.CodePublishedDurable,
					Warnings:        []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete},
				},
			},
		}
		for _, language := range []LanguageCode{"en", "ru"} {
			if err := setActiveLanguage(language); err != nil {
				t.Fatalf("set language %s: %v", language, err)
			}
			for _, state := range states {
				presentation := mustPCV3Presentation(t, state.spec)
				content := (&App{}).buildPCV3ResultView(presentation, nil)
				content.Resize(fyne.NewSize(desktopContentWidth(), content.MinSize().Height))
				if content.MinSize().Width > desktopContentWidth() {
					t.Fatalf("%s %s width %.1f exceeds compact %.1f", language, state.name, content.MinSize().Width, desktopContentWidth())
				}
				copy := pcv3OutcomeCopy(presentation)
				requirePCV3Text(t, content, copy.Title, copy.Body)
				publication := pcv3PublicationCopy(presentation)
				if publication.Title != "" {
					requirePCV3Text(t, content, publication.Title, publication.Body)
				}
				if presentation.ArchivePending() {
					if findPCV3Button(content, tr("pcv3.archive.extract", "Extract archive")) != nil ||
						findPCV3Button(content, tr("pcv3.archive.close", "Close without extracting")) != nil {
						t.Fatal("authority-free archive presentation enabled a live action")
					}
					continue
				}
				action := publication.Action
				if slices.Contains(presentation.Warnings(), pcv3operation.WarningCleanupIncomplete) {
					action = tr("pcv3.warning.cleanup_close", "Close cleanup warning")
				}
				if action == "" {
					action = tr("pcv3.result.close", "Close recovery result")
				}
				if findPCV3Button(content, action) == nil {
					t.Fatalf("%s %s lacks terminal action %q", language, state.name, action)
				}
			}
		}
		_ = setActiveLanguage("en")
	})
	run("UI-D01", func(t *testing.T) {
		state := mustNewState(t)
		state.PCV3Factor = app.PCV3FactorPolicyCombined
		state.PCV3Order = app.PCV3KeyfileOrderAny
		state.Password = "local only"
		state.Keyfiles = []string{"one", "two"}
		snap := state.UISnapshot()
		if snap.PCV3Factor != app.PCV3FactorPolicyCombined || snap.PCV3Order != app.PCV3KeyfileOrderAny || snap.KeyfileCount != 2 {
			t.Fatalf("local credential intent lost: %#v", snap)
		}
	})
	run("UI-D02", func(t *testing.T) {
		invalid := [][]pcv3operation.PhysicalRole{
			{pcv3operation.RolePrimary},
			{pcv3operation.RolePrimary, pcv3operation.RolePrimary},
			{pcv3operation.RolePrimary, pcv3operation.RoleD1Front},
		}
		for _, roles := range invalid {
			if view, ok := newPCV3ConsentView(pcv3operation.ModeForceUnverifiedNormal, roles, func(pcv3operation.PhysicalRole) {}, func() {}); ok || view != nil {
				t.Fatalf("invalid role set rendered partial dialog: %v", roles)
			}
		}
	})

	checkPCV3CaseInventory(t, executed, required)
}

type frozenArtifactView struct {
	metadata pcv3recovery.ArtifactInspectionMetadata
	ranges   []pcv3artifact.Range
	maxPage  uint64
}

func (view *frozenArtifactView) Metadata() pcv3recovery.ArtifactInspectionMetadata {
	return view.metadata
}

func (view *frozenArtifactView) Page(offset, limit uint64) ([]pcv3artifact.Range, bool) {
	if limit == 0 || limit > 128 || offset >= uint64(len(view.ranges)) || offset+limit < offset {
		return nil, false
	}
	if limit > view.maxPage {
		view.maxPage = limit
	}
	end := offset + limit
	if end > uint64(len(view.ranges)) {
		end = uint64(len(view.ranges))
	}
	return append([]pcv3artifact.Range(nil), view.ranges[offset:end]...), true
}

func TestPCV3RecoveryArtifactLargeRangeView(t *testing.T) {
	resetLocalizationForTest(t)
	required := []string{"C18", "C19", "C20", "C21", "C22", "C23", "C24", "B03"}
	executed := make([]string, 0, len(required))
	ranges := make([]pcv3artifact.Range, 4097)
	for index := range ranges {
		status := pcv3artifact.RangeVerified
		if index%3 == 1 {
			status = pcv3artifact.RangeUnverified
		} else if index%3 == 2 {
			status = pcv3artifact.RangeMissing
		}
		ranges[index] = pcv3artifact.Range{
			RecordIndex: uint64(index), Start: uint64(index) * 4096,
			End: uint64(index)*4096 + 4095, Status: status,
		}
	}
	view := &frozenArtifactView{
		metadata: pcv3recovery.ArtifactInspectionMetadata{
			Kind: pcv3artifact.StateUnverifiedForensic, Role: pcv3artifact.RoleBackup,
			PlaintextLength: 16781312, Final: pcv3artifact.FinalUnverified,
			RangeCount: 4097, VerifiedRangeCount: 1366, UnverifiedRangeCount: 1366, MissingRangeCount: 1365,
		},
		ranges: ranges,
	}
	run := func(id string, test func(*testing.T)) {
		t.Run(id, func(t *testing.T) { executed = append(executed, id); test(t) })
	}
	run("C18", func(t *testing.T) {
		empty := &frozenArtifactView{metadata: pcv3recovery.ArtifactInspectionMetadata{Kind: pcv3artifact.StatePartial, Final: pcv3artifact.FinalMissing}}
		surface := buildPCV3ArtifactSurface(pcv3ArtifactReady, empty)
		requirePCV3Text(t, surface, "No recoverable ranges were recorded.")
		if strings.Contains(strings.ToLower(pcv3RenderedText(surface)), "complete") {
			t.Fatal("zero-range state claimed completion")
		}
	})
	run("C19", func(t *testing.T) {
		surface := buildPCV3ArtifactSurface(pcv3ArtifactLoading, nil)
		requirePCV3Text(t, surface, "Loading recovery details…")
		if strings.Contains(pcv3RenderedText(surface), "Save") {
			t.Fatal("loading inspection exposed an action")
		}
	})
	run("C20", func(t *testing.T) {
		surface := buildPCV3ArtifactSurface(pcv3ArtifactFailed, nil)
		requirePCV3Text(t, surface, "Recovery details could not be loaded")
		if strings.Contains(pcv3RenderedText(surface), "Discard") {
			t.Fatal("failed inspection inferred cleanup authority")
		}
	})
	run("C21", func(t *testing.T) {
		surface := buildPCV3ArtifactSurface(pcv3ArtifactReady, view)
		requirePCV3Text(t, surface, "Unverified forensic recovery", "Backup capsule", "16781312", "Unverified", "4097")
	})
	run("C22", func(t *testing.T) {
		for _, index := range []int{0, 1, 2} {
			rangeValue, ok := (&pcv3ArtifactRangeModel{view: view, rangeCount: view.metadata.RangeCount}).at(index)
			if !ok || rangeValue.Status != ranges[index].Status {
				t.Fatalf("range %d status = %v/%v", index, rangeValue.Status, ok)
			}
		}
	})
	run("C23", func(t *testing.T) {
		for count, fragment := range map[uint64]string{0: "No recoverable", 1: "1", 4: "4"} {
			if got := pcv3RecoveryRangeCount(count); !strings.Contains(got, fragment) {
				t.Fatalf("count %d copy = %q", count, got)
			}
		}
	})
	run("C24", func(t *testing.T) {
		last := ranges[len(ranges)-1]
		row := pcv3RecoveryRangeRow(last.RecordIndex, last.Start, last.End, last.Status)
		for _, value := range []string{"4096", "16777216", "16781311"} {
			if !strings.Contains(row, value) {
				t.Fatalf("full range row %q lacks %s", row, value)
			}
		}
		if strings.Contains(row, filepath.Join(string(filepath.Separator), "private")) {
			t.Fatal("range row exposed private path")
		}
	})
	run("B03", func(t *testing.T) {
		model := &pcv3ArtifactRangeModel{view: view, rangeCount: view.metadata.RangeCount}
		for _, index := range []int{0, len(ranges) / 2, len(ranges) - 1} {
			got, ok := model.at(index)
			if !ok || !reflect.DeepEqual(got, ranges[index]) {
				t.Fatalf("virtual row %d = %#v/%v; want %#v", index, got, ok, ranges[index])
			}
		}
		surface := buildPCV3ArtifactSurface(pcv3ArtifactReady, view)
		border, ok := surface.(*fyne.Container)
		if !ok {
			t.Fatalf("artifact surface type = %T", surface)
		}
		listCount := 0
		for _, child := range border.Objects {
			if _, ok := child.(*widget.List); ok {
				listCount++
			}
		}
		if listCount != 1 || len(border.Objects) > 3 || view.maxPage > 128 {
			t.Fatalf("large artifact renderer = lists %d children %d maxPage %d", listCount, len(border.Objects), view.maxPage)
		}
	})
	checkPCV3CaseInventory(t, executed, required)
}
