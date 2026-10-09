package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func TestStatusDetailsShowsFullScrollableMessage(t *testing.T) {
	for _, activation := range []string{"tap", "keyboard"} {
		t.Run(activation, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)
			message := "stat /" + strings.Repeat("long-directory/", 80) + "archive.zip: no such file or directory\nKeep the original files."
			fyne.DoAndWait(func() {
				a.State.SetStatus(message, util.RED)
				a.updateUIState()
				before := a.Window.Canvas().Size()
				if activation == "tap" {
					pos := fyneApp.Driver().AbsolutePositionForObject(a.statusLabel.object())
					test.TapCanvas(a.Window.Canvas(), pos.Add(fyne.NewPos(12, a.statusLabel.object().Size().Height/2)))
				} else {
					var link *widget.Hyperlink
					for _, object := range test.LaidOutObjects(a.statusLabel.object()) {
						if candidate, ok := object.(*widget.Hyperlink); ok {
							link = candidate
							break
						}
					}
					if link == nil {
						t.Error("status has no keyboard-accessible details action")
						return
					}
					a.Window.Canvas().Focus(link)
					focused := a.Window.Canvas().Focused()
					if focused != link {
						t.Error("status action did not receive keyboard focus")
						return
					}
					focused.TypedKey(&fyne.KeyEvent{Name: fyne.KeySpace})
				}
				overlay := a.Window.Canvas().Overlays().Top()
				if overlay == nil {
					t.Error("activating status did not open details")
					return
				}
				for _, object := range test.WidgetRenderer(overlay.(fyne.Widget)).Objects() {
					if popup, ok := object.(*widget.PopUp); ok {
						pos, size := popup.Position(), popup.Size()
						if pos.X < 0 || pos.Y < 0 || pos.X+size.Width > before.Width || pos.Y+size.Height > before.Height {
							t.Errorf("details exceed the window bounds: position %v, size %v, window %v", pos, size, before)
						}
					}
				}
				var scroll *container.Scroll
				var closeButton *widget.Button
				for _, object := range test.LaidOutObjects(overlay) {
					switch value := object.(type) {
					case *container.Scroll:
						scroll = value
					case *widget.Button:
						if value.Text == tr("action.close", "Close") {
							closeButton = value
						}
					}
				}
				if scroll == nil || closeButton == nil {
					t.Error("details did not expose scrollable text and Close")
					return
				}
				label, ok := scroll.Content.(*widget.Label)
				if !ok || label.Text != message || !label.Selectable {
					t.Error("details did not preserve the full selectable message")
					return
				}
				if scroll.Content.Size().Height <= scroll.Size().Height {
					t.Error("long message is not constrained to a scrollable viewport")
				}
				scroll.Scrolled(&fyne.ScrollEvent{Scrolled: fyne.Delta{DY: -300}})
				if scroll.Offset.Y <= 0 {
					t.Error("scroll did not reveal the remainder of the message")
				}
				if got := a.Window.Canvas().Size(); got != before {
					t.Errorf("details resized the main window: before %v, after %v", before, got)
				}
				test.Tap(closeButton)
				if a.Window.Canvas().Overlays().Top() != nil {
					t.Error("Close did not dismiss status details")
				}
			})
		})
	}
}

func TestStatusDetailsBlocksGlobalStartShortcut(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	input := filepath.Join(t.TempDir(), "input.txt")
	output := input + ".pcv"
	for _, path := range []string{input, output} {
		if err := os.WriteFile(path, []byte("keep this file"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.InputFile = input
		a.State.OnlyFiles = []string{input}
		a.State.AllFiles = []string{input}
		a.State.OutputFile = output
		a.State.Password, a.State.CPassword = "test-password", "test-password"
		a.State.SetStatus("Inspect this error.", util.RED)
		a.updateUIState()
		if a.startDisabled(a.State.UISnapshot()) {
			t.Error("test precondition: Start must be available")
			return
		}
		a.showStatusDetails()
		for _, key := range []fyne.KeyName{fyne.KeyReturn, fyne.KeyEnter} {
			a.onDesktopKeyDown(&fyne.KeyEvent{Name: key})
			if got := a.State.UISnapshot().Status.Text; got != "Inspect this error." {
				t.Errorf("%s dispatched Start behind the details dialog: %q", key, got)
			}
		}
		for _, object := range test.LaidOutObjects(a.Window.Canvas().Overlays().Top()) {
			if button, ok := object.(*widget.Button); ok && button.Text == tr("action.close", "Close") {
				test.Tap(button)
				break
			}
		}
		a.onDesktopKeyDown(&fyne.KeyEvent{Name: fyne.KeyReturn})
		want := tr("status.pcv3_output_exists", "PCV3 output already exists. Choose a different name.")
		if got := a.State.UISnapshot().Status.Text; got != want {
			t.Errorf("closing details did not restore Start shortcut: status %q, want %q", got, want)
		}
	})
}

// TestAboutModalShowsAppVersion pins the GUI's only version indicator: the
// window title carries no version (#133), so the About dialog must show it.
func TestAboutModalShowsAppVersion(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.showAboutModal()
	})

	if a.aboutModal == nil {
		t.Fatal("about modal was not created")
	}
	if a.aboutVersionLabel == nil {
		t.Fatal("about version label was not created")
	}
	if !strings.Contains(a.aboutVersionLabel.Text, a.Version) {
		t.Fatalf("about label %q does not contain version %q", a.aboutVersionLabel.Text, a.Version)
	}
}

// TestBuildUICreatesAboutButton ensures the About entry point is present in
// the header row without growing the fixed-size window.
func TestBuildUICreatesAboutButton(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	if a.aboutButton == nil {
		t.Fatal("buildUI did not create the about button")
	}
}

func TestNormalizeSelectedOutputPathPreservesDots(t *testing.T) {
	got := normalizeSelectedOutputPath("/tmp/report.v2.backup", "encrypt", "input.txt", false, false)
	want := filepath.Join(string(filepath.Separator), "tmp", "report.v2.txt.pcv")
	if got != want {
		t.Fatalf("normalizeSelectedOutputPath(...) = %q, want %q", got, want)
	}
}

func TestShouldShowOverwriteModalSkipsDialogConfirmedOutput(t *testing.T) {
	if showOverwriteModalForOutput(true, false, true) {
		t.Fatal("dialog-confirmed output should not trigger a second overwrite modal")
	}
	if !showOverwriteModalForOutput(true, false, false) {
		t.Fatal("plain existing output should still trigger overwrite modal")
	}
}

// TestPCV3ChangeOutputSelectionUsesFolderPickerWithoutTouchingDestination
// drives the production Change surface. It must require a folder picker, then
// preserve an existing target and leave a new target absent until the PCV3
// executor owns publication.
func TestPCV3ChangeOutputSelectionUsesFolderPickerWithoutTouchingDestination(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	t.Cleanup(a.State.Reset)
	input := filepath.Join(dir, "input.pcv3")
	if err := os.WriteFile(input, []byte("pcv3 input"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	source, err := os.Open(input)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, input, filepath.Join(dir, "suggested-output"), int64(len("pcv3 input"))) {
		t.Fatal("SetPCV3Ready rejected regular PCV3 input")
	}
	fyne.DoAndWait(a.updateUIState)

	sentinel := filepath.Join(dir, "existing-output")
	sentinelBytes := []byte("do not modify")
	if err := os.WriteFile(sentinel, sentinelBytes, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	fyne.DoAndWait(a.changeBtn.OnTapped)
	selectPCV3FolderOutputDestination(t, a, filepath.Base(sentinel))
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != string(sentinelBytes) {
		t.Fatalf("Change modified existing destination: read = %q, err = %v", got, err)
	}

	newDestination := filepath.Join(dir, "new-output")
	fyne.DoAndWait(a.changeBtn.OnTapped)
	selectPCV3FolderOutputDestination(t, a, filepath.Base(newDestination))
	if _, err := os.Stat(newDestination); !os.IsNotExist(err) {
		t.Fatalf("Change created destination before the PCV3 executor: stat(%q) = %v", newDestination, err)
	}
	snap := a.State.UISnapshot()
	if snap.OutputFile != newDestination || snap.Status.Kind != app.StatusReady {
		t.Fatalf("Change did not update ready output: %#v", snap)
	}
}

func TestPCV3CreationChangeUsesPathOnlyPickerWithoutTouchingDestination(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(input, []byte("plaintext"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	a.State.Mode = "encrypt"
	a.State.InputFile = input
	a.State.AllFiles = []string{input}
	a.State.OnlyFiles = []string{input}
	a.State.OutputFile = filepath.Join(dir, "suggested.bin.pcv")
	a.State.SetInputSelection(1, 0, int64(len("plaintext")), true)
	fyne.DoAndWait(a.updateUIState)

	sentinel := filepath.Join(dir, "existing.bin.pcv")
	sentinelBytes := []byte("do not truncate")
	if err := os.WriteFile(sentinel, sentinelBytes, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	fyne.DoAndWait(a.changeBtn.OnTapped)
	selectPCV3FolderOutputDestination(t, a, "existing")
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != string(sentinelBytes) {
		t.Fatalf("PCV3 creation Change modified existing destination: read=%q err=%v", got, err)
	}

	newDestination := filepath.Join(dir, "new.bin.pcv")
	fyne.DoAndWait(a.changeBtn.OnTapped)
	selectPCV3FolderOutputDestination(t, a, "new")
	if _, err := os.Lstat(newDestination); !os.IsNotExist(err) {
		t.Fatalf("PCV3 creation Change created destination before publication: %v", err)
	}
	snap := a.State.UISnapshot()
	if snap.OutputFile != newDestination || a.State.OutputChosenViaSaveDialog || snap.Status.Kind != app.StatusReady {
		t.Fatalf("PCV3 creation path-only selection = %#v", snap)
	}
}

func TestPCV3CreationChangeRejectsStaleSelectionWithIdenticalPaths(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(input, []byte("plaintext"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	configure := func() {
		a.State.Mode = "encrypt"
		a.State.InputFile = input
		a.State.AllFiles = []string{input}
		a.State.OnlyFiles = []string{input}
		a.State.OutputFile = filepath.Join(dir, "same.bin.pcv")
		a.State.SetInputSelection(1, 0, int64(len("plaintext")), true)
		a.updateUIState()
	}
	fyne.DoAndWait(configure)
	fyne.DoAndWait(a.changeBtn.OnTapped)
	entry, confirm := openPCV3OutputFilenameForm(t, a)

	fyne.DoAndWait(func() {
		a.resetUI()
		configure()
	})
	entry.SetText("stale")
	test.Tap(confirm)

	unchanged := filepath.Join(dir, "same.bin.pcv")
	stale := filepath.Join(dir, "stale.bin.pcv")
	if snap := a.State.UISnapshot(); snap.OutputFile != unchanged {
		t.Fatalf("stale creation picker changed replacement selection: %q", snap.OutputFile)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale creation picker created a destination: %v", err)
	}
}

// TestApplyPCV3OutputSelectionDoesNotTouchDestination isolates the path-only
// callback seam used by Change. It must update the ready destination without
// opening, truncating, renaming, or deleting either a pre-existing target or
// a new target before the PCV3 executor owns publication.
func TestApplyPCV3OutputSelectionDoesNotTouchDestination(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	t.Cleanup(a.State.Reset)
	input := filepath.Join(dir, "input.pcv3")
	if err := os.WriteFile(input, []byte("pcv3 input"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	source, err := os.Open(input)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, input, filepath.Join(dir, "suggested-output"), int64(len("pcv3 input"))) {
		t.Fatal("SetPCV3Ready rejected regular PCV3 input")
	}

	sentinel := filepath.Join(dir, "existing-output")
	sentinelBytes := []byte("do not modify")
	if err := os.WriteFile(sentinel, sentinelBytes, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	ticket := pcv3ReadyOutputTicket(t, a)
	if err := a.applyPCV3OutputSelection(ticket, dir, filepath.Base(sentinel)); err != nil {
		t.Fatalf("apply selected destination: %v", err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != string(sentinelBytes) {
		t.Fatalf("pre-existing destination changed: read = %q, err = %v", got, err)
	}

	newDestination := filepath.Join(dir, "new-output")
	if err := a.applyPCV3OutputSelection(ticket, dir, filepath.Base(newDestination)); err != nil {
		t.Fatalf("apply new destination: %v", err)
	}
	if _, err := os.Stat(newDestination); !os.IsNotExist(err) {
		t.Fatalf("new destination exists before executor: stat(%q) = %v", newDestination, err)
	}
	snap := a.State.UISnapshot()
	if snap.OutputFile != newDestination {
		t.Fatalf("OutputFile = %q, want %q", snap.OutputFile, newDestination)
	}
	if snap.Status.Kind != app.StatusReady {
		t.Fatalf("status = %v, want ready", snap.Status.Kind)
	}
}

// TestApplyPCV3OutputSelectionRejectsUnsafeFilename ensures a cancelled or
// invalid filename leaves both the operation state and the filesystem as it
// was. The folder picker callback takes the same no-op path on cancellation or
// an error before this validation is reached.
func TestApplyPCV3OutputSelectionRejectsUnsafeFilename(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	t.Cleanup(a.State.Reset)
	input := filepath.Join(dir, "input.pcv3")
	if err := os.WriteFile(input, []byte("pcv3 input"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	source, err := os.Open(input)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	originalOutput := filepath.Join(dir, "suggested-output")
	if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, input, originalOutput, int64(len("pcv3 input"))) {
		t.Fatal("SetPCV3Ready rejected regular PCV3 input")
	}
	before := a.State.UISnapshot()

	if err := a.applyPCV3OutputSelection(pcv3ReadyOutputTicket(t, a), dir, "../outside"); err == nil {
		t.Fatal("unsafe filename was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "outside")); !os.IsNotExist(err) {
		t.Fatalf("unsafe selection created a path: %v", err)
	}
	snap := a.State.UISnapshot()
	if snap.OutputFile != originalOutput || snap.Status != before.Status {
		t.Fatalf("invalid selection changed state: output=%q status=%#v", snap.OutputFile, snap.Status)
	}
}

// TestPCV3OutputFolderSelectionCancellationOrErrorIsNoOp protects the picker
// boundary itself: cancellation and a picker failure must retain the chosen
// output, ready state, and every destination byte unchanged.
func TestPCV3OutputFolderSelectionCancellationOrErrorIsNoOp(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	t.Cleanup(a.State.Reset)
	input := filepath.Join(dir, "input.pcv3")
	if err := os.WriteFile(input, []byte("pcv3 input"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	source, err := os.Open(input)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	output := filepath.Join(dir, "existing-output")
	sentinelBytes := []byte("do not modify")
	if err := os.WriteFile(output, sentinelBytes, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, input, output, int64(len("pcv3 input"))) {
		t.Fatal("SetPCV3Ready rejected regular PCV3 input")
	}
	before := a.State.UISnapshot()

	ticket := pcv3ReadyOutputTicket(t, a)
	a.handlePCV3OutputFolderSelection(ticket, nil, nil)
	a.handlePCV3OutputFolderSelection(ticket, nil, os.ErrPermission)

	if got, err := os.ReadFile(output); err != nil || string(got) != string(sentinelBytes) {
		t.Fatalf("picker cancellation or error changed destination: read = %q, err = %v", got, err)
	}
	if snap := a.State.UISnapshot(); snap.OutputFile != before.OutputFile || snap.Status != before.Status {
		t.Fatalf("picker cancellation or error changed state: output=%q status=%#v", snap.OutputFile, snap.Status)
	}
}

// TestPCV3OutputFolderSelectionRejectsNonFileURI keeps a provider URI from
// being converted to a local-looking path. The desktop PCV3 executor owns only
// local destinations selected through the folder picker.
func TestPCV3OutputFolderSelectionRejectsNonFileURI(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	t.Cleanup(a.State.Reset)
	input := filepath.Join(dir, "input.pcv3")
	if err := os.WriteFile(input, []byte("pcv3 input"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	source, err := os.Open(input)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	originalOutput := filepath.Join(dir, "existing-output")
	if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, input, originalOutput, int64(len("pcv3 input"))) {
		t.Fatal("SetPCV3Ready rejected regular PCV3 input")
	}
	nonFileURI, err := storage.ParseURI("content:///otherapp/output")
	if err != nil {
		t.Fatalf("parse non-file URI: %v", err)
	}
	a.handlePCV3OutputFolderSelection(pcv3ReadyOutputTicket(t, a), testListableURI{URI: nonFileURI}, nil)
	if a.Window.Canvas().Overlays().Top() != nil {
		t.Fatal("non-file folder URI opened a filename form")
	}
	if snap := a.State.UISnapshot(); snap.OutputFile != originalOutput {
		t.Fatalf("non-file folder URI changed output: %q", snap.OutputFile)
	}
}

// TestPCV3ChangeOutputSelectionRejectsStaleReadyTicket reproduces A's open
// folder/form, a reset and Ready selection B, then A's delayed confirmation.
// The stale confirmation must not alter B or create A's requested destination.
func TestPCV3ChangeOutputSelectionRejectsStaleReadyTicket(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	t.Cleanup(a.State.Reset)
	aInput := filepath.Join(dir, "a.pcv3")
	bInput := filepath.Join(dir, "b.pcv3")
	if err := os.WriteFile(aInput, []byte("A"), 0o600); err != nil {
		t.Fatalf("write A: %v", err)
	}
	if err := os.WriteFile(bInput, []byte("B"), 0o600); err != nil {
		t.Fatalf("write B: %v", err)
	}
	aSource, err := os.Open(aInput)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	t.Cleanup(func() { _ = aSource.Close() })
	if !a.State.SetPCV3Ready(aSource, app.PCV3FormatNormal, aInput, filepath.Join(dir, "a-output"), 1) {
		t.Fatal("SetPCV3Ready rejected A")
	}
	fyne.DoAndWait(func() {
		a.updateUIState()
		a.changeBtn.OnTapped()
	})
	entry, confirm := openPCV3OutputFilenameForm(t, a)

	a.State.Reset()
	bSource, err := os.Open(bInput)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	t.Cleanup(func() { _ = bSource.Close() })
	bOutput := filepath.Join(dir, "b-output")
	if !a.State.SetPCV3Ready(bSource, app.PCV3FormatNormal, bInput, bOutput, 1) {
		t.Fatal("SetPCV3Ready rejected B")
	}
	staleDestination := filepath.Join(dir, "a-stale-output")
	entry.SetText(filepath.Base(staleDestination))
	test.Tap(confirm)

	if _, err := os.Stat(staleDestination); !os.IsNotExist(err) {
		t.Fatalf("stale A confirmation created output: %v", err)
	}
	if snap := a.State.UISnapshot(); snap.OutputFile != bOutput {
		t.Fatalf("stale A confirmation changed B output: %q", snap.OutputFile)
	}
}

func selectPCV3FolderOutputDestination(t *testing.T, a *App, filename string) {
	t.Helper()
	entry, buttons := outputPickerControls(t, a)
	if entry != nil || buttons["Save"] != nil {
		t.Fatal("PCV3 Change used a writer-based save picker instead of folder selection")
	}
	open := buttons["Open"]
	if open == nil {
		t.Fatal("PCV3 Change did not expose a folder Open action")
	}
	test.Tap(open)
	entry, confirm := pcv3OutputFilenameFormControls(t, a)
	entry.SetText(filename)
	test.Tap(confirm)
}

func openPCV3OutputFilenameForm(t *testing.T, a *App) (*widget.Entry, *widget.Button) {
	t.Helper()
	entry, buttons := outputPickerControls(t, a)
	if entry != nil || buttons["Save"] != nil || buttons["Open"] == nil {
		t.Fatal("PCV3 Change did not show the expected folder picker")
	}
	test.Tap(buttons["Open"])
	return pcv3OutputFilenameFormControls(t, a)
}

func pcv3OutputFilenameFormControls(t *testing.T, a *App) (*widget.Entry, *widget.Button) {
	t.Helper()
	entry, buttons := outputPickerControls(t, a)
	confirm := buttons[tr("action.change", "Change")]
	if entry == nil || confirm == nil {
		t.Fatal("PCV3 filename form did not expose its entry and Change action")
	}
	return entry, confirm
}

func outputPickerControls(t *testing.T, a *App) (*widget.Entry, map[string]*widget.Button) {
	t.Helper()
	overlay := a.Window.Canvas().Overlays().Top()
	if overlay == nil {
		t.Fatal("output picker was not shown")
	}
	buttons := make(map[string]*widget.Button)
	var entry *widget.Entry
	for _, object := range test.LaidOutObjects(overlay) {
		switch object := object.(type) {
		case *widget.Entry:
			entry = object
		case *widget.Button:
			buttons[object.Text] = object
		}
	}
	return entry, buttons
}

func pcv3ReadyOutputTicket(t *testing.T, a *App) uint64 {
	t.Helper()
	ticket, _, ok := a.State.PCV3ReadyOutputSelection()
	if !ok {
		t.Fatal("PCV3 Ready selection did not expose an output ticket")
	}
	return ticket
}

type testListableURI struct{ fyne.URI }

func (testListableURI) List() ([]fyne.URI, error) { return nil, nil }

func TestShowFileDialogWithResizeSupportsFyne28Lifecycle(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	location, err := storage.ListerForURI(storage.NewFileURI(t.TempDir()))
	if err != nil {
		t.Fatalf("create save-dialog location: %v", err)
	}
	saveDialog := dialog.NewFileSave(func(fyne.URIWriteCloser, error) {}, a.Window)
	saveDialog.SetLocation(location)
	overlaysBefore := len(a.Window.Canvas().Overlays().List())

	fyne.DoAndWait(func() {
		a.Window.SetFixedSize(true)
		a.showFileDialogWithResize(saveDialog, fyne.NewSize(600, 450))
	})

	if got := len(a.Window.Canvas().Overlays().List()); got != overlaysBefore+1 {
		t.Fatalf("file dialog overlay count = %d; want %d", got, overlaysBefore+1)
	}
	if a.Window.FixedSize() {
		t.Fatal("parent window stayed fixed while the file dialog was open")
	}

	fyne.DoAndWait(saveDialog.Dismiss)

	if got := len(a.Window.Canvas().Overlays().List()); got != overlaysBefore {
		t.Fatalf("overlay count after dismiss = %d; want %d", got, overlaysBefore)
	}
	if !a.Window.FixedSize() {
		t.Fatal("parent window was not restored to fixed size after dismiss")
	}
}

func TestFileDialogPreservesUserWindowSize(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() {
		chosen := fyne.NewSize(800, 720)
		a.Window.Resize(chosen)
		saveDialog := dialog.NewFileSave(func(fyne.URIWriteCloser, error) {}, a.Window)
		a.showFileDialogWithResize(saveDialog, fyne.NewSize(600, 450))
		if a.Window.Canvas().Size() != chosen {
			t.Error("opening a file dialog shrank the user's larger window")
		}
		saveDialog.Dismiss()
		if a.Window.Canvas().Size() != chosen || a.Window.FixedSize() {
			t.Error("closing a file dialog did not preserve the user's resizable window")
		}
	})
}
