package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
)

func TestDesktopPasswordEnterStartsOnlyWithoutDialog(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	input := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(input, []byte("public keyboard fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	fyne.DoAndWait(func() { a.onDrop([]string{input}) })
	waitForDropProcessing(t, a)
	output := a.State.UISnapshot().OutputFile
	if err := os.WriteFile(output, []byte("keep existing output"), 0o600); err != nil {
		t.Fatal(err)
	}
	fyne.DoAndWait(func() {
		a.passwordEntry.SetText("public test password")
		a.cPasswordEntry.SetText("public test password")
		for _, entry := range []*PasswordEntry{a.passwordEntry, a.cPasswordEntry} {
			a.State.SetStatusMessage(app.StatusReady, util.WHITE, app.StatusArgs{})
			a.Window.Canvas().Focus(entry)
			entry.TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
			if a.State.UISnapshot().Status.Text != tr("status.pcv3_output_exists", "PCV3 output already exists. Choose a different name.") {
				t.Error("Enter in the password field did not reach the real Start preflight")
			}
			a.State.SetStatusMessage(app.StatusReady, util.WHITE, app.StatusArgs{})
			popup := dialog.NewInformation("Public test dialog", "Do not submit the form behind this dialog.", a.Window)
			popup.Show()
			entry.TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
			if a.State.UISnapshot().Status.Kind != app.StatusReady {
				t.Error("Enter submitted the form behind an open dialog")
			}
			popup.Hide()
		}
	})
	if got, err := os.ReadFile(output); err != nil || string(got) != "keep existing output" {
		t.Fatalf("Start preflight changed the occupied destination: %q, %v", got, err)
	}
}
