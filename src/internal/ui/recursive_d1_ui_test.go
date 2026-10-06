package ui

import (
	"Picocrypt-NG/internal/app"
	"testing"

	"fyne.io/fyne/v2"
	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

func recursiveD1UIControl(object fyne.CanvasObject) *ttwidget.Check {
	if check, ok := object.(*ttwidget.Check); ok && check.Text == tr("advanced.recursive_d1.label", "All selected files are PCV3 D1") {
		return check
	}
	if container, ok := object.(*fyne.Container); ok {
		for _, child := range container.Objects {
			if check := recursiveD1UIControl(child); check != nil {
				return check
			}
		}
	}
	return nil
}

func TestRecursiveD1SelectorUsesDecryptReadinessAndRestoresSelection(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.StartAction = app.StartActionZipAndEncrypt
		a.State.OnlyFolders = []string{"selected-folder"}
		a.State.AllFiles = []string{"one.bin", "two.bin"}
		a.State.Password = "existing password"
		a.State.CPassword = ""
		a.State.Comments = "saved encryption note"
		a.State.Split = true
		a.State.SplitSize = "invalid encrypt-only split value"
		a.State.Recursively = true
		a.refreshAdvanced()
		a.updateUIState()
		selector := recursiveD1UIControl(a.advancedContainer)
		if selector == nil || selector.Disabled() {
			t.Fatal("recursive batch has no enabled explicit D1 selector")
		}
		selector.SetChecked(true)
		snap := a.State.UISnapshot()
		if !snap.RecursiveD1 || a.startButton.Disabled() || a.startReadinessHint(snap) != "" {
			t.Fatalf("D1 decrypt still requires encryption confirmation/split options: selected=%v hint=%q", snap.RecursiveD1, a.startReadinessHint(snap))
		}
		if a.startButton.Text != tr("pcv3.action.decrypt", "Decrypt") || a.confirmRow.Visible() || !a.cPasswordEntry.Disabled() || !a.createBtn.Disabled() {
			t.Fatal("D1 batch presents encryption start/password controls")
		}
		if a.autoUnzipCheck == nil || a.autoUnzipCheck.Disabled() {
			t.Fatal("explicit D1 batch does not expose archive extraction options")
		}
		if !a.commentsEntry.Disabled() || a.State.Comments != "saved encryption note" {
			t.Fatal("D1 batch exposes writer comments or changes saved encryption options")
		}
		a.State.Password = ""
		a.State.Keyfiles = []string{"selected-keyfile"}
		a.updateUIState()
		if a.startButton.Disabled() || a.keyfileEditBtn.Disabled() || !a.keyfileCreateBtn.Disabled() {
			t.Fatal("D1 batch does not accept selected keyfiles without writer-only credential controls")
		}
		a.recursivelyCheck.SetChecked(false)
		if a.State.UISnapshot().RecursiveD1 || !a.confirmRow.Visible() || a.startButton.Text != tr("action.zip_and_encrypt", "Zip and Encrypt") {
			t.Fatal("unchecking recursive did not clear D1 and restore original selection UI")
		}
		if a.commentsEntry.Text != "saved encryption note" {
			t.Fatal("leaving D1 batch did not restore the original writer comment")
		}
	})
}

func TestRecursiveD1SelectorIsDisabledOutsideIdleRecursiveBatch(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.OnlyFolders = []string{"selected-folder"}
		a.State.AllFiles = []string{"one.bin", "two.bin"}
		a.refreshAdvanced()
		selector := recursiveD1UIControl(a.advancedContainer)
		if selector == nil || !selector.Disabled() {
			t.Fatal("D1 batch selector must require recursive selection")
		}
		a.recursivelyCheck.SetChecked(true)
		selector.SetChecked(true)
		for _, busy := range []string{"working", "scanning"} {
			a.State.SetWorking(busy == "working")
			a.State.SetScanning(busy == "scanning")
			a.updateUIState()
			selector = recursiveD1UIControl(a.advancedContainer)
			if selector == nil || !selector.Disabled() || !a.recursivelyCheck.Disabled() {
				t.Fatalf("batch routing controls remained editable while %s", busy)
			}
		}
		a.State.SetWorking(false)
		a.State.SetScanning(false)
		a.resetUI()
		if snap := a.State.UISnapshot(); snap.RecursiveD1 || snap.Recursively {
			t.Fatal("new selection/reset retained explicit batch D1 authority")
		}
	})
}
