// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"
	"crypto/rand"
	"path/filepath"
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const (
	keyfileDialogWidth      = windowWidth - 8
	keyfileDialogListWidth  = windowWidth - 40
	keyfileDialogListHeight = 88
	keyfileDialogHeight     = 260
)

func keyfileApplicable(mode string, required bool, deniable bool) bool {
	return mode != "decrypt" || required || deniable
}

func keyfileDisplayLabel(required bool, count int, applicable bool) string {
	switch {
	case !applicable:
		return tr("keyfiles.not_applicable", "Not applicable")
	case count == 0 && required:
		return tr("keyfiles.required", "Keyfiles required")
	case count == 0:
		return tr("keyfiles.none_selected", "None selected")
	case count == 1:
		return trn("keyfiles.count", "{{.Count}} keyfile", count, map[string]any{
			"Count": count,
		})
	default:
		return trn("keyfiles.count", "{{.Count}} keyfiles", count, map[string]any{
			"Count": count,
		})
	}
}

// buildKeyfilesSection creates the keyfiles input section.
func (a *App) buildKeyfilesSection() fyne.CanvasObject {
	a.keyfileEditBtn = newToolbarButton(tr("action.edit", "Edit"), theme.FolderOpenIcon(), func() {
		a.showKeyfileModal()
	})

	a.keyfileCreateBtn = newToolbarButton(tr("action.create", "Create"), theme.DocumentCreateIcon(), func() {
		a.createKeyfile()
	})

	a.keyfileLabel = widget.NewLabel(keyfileDisplayLabel(
		a.State.Keyfile,
		len(a.State.Keyfiles),
		keyfileApplicable(a.State.Mode, a.State.Keyfile, a.State.Deniability),
	))
	a.keyfileLabel.Wrapping = fyne.TextWrapWord

	// Create bold label for better visual hierarchy
	a.keyfilesTitleLabel = widget.NewLabel(tr("keyfiles.label", "Keyfiles:"))
	a.keyfilesTitleLabel.TextStyle = fyne.TextStyle{Bold: true}

	buttonRow := container.NewHBox(
		a.keyfileEditBtn,
		a.keyfileCreateBtn,
	)
	headerRow := container.NewBorder(nil, nil, nil, buttonRow, a.keyfilesTitleLabel)

	return container.NewVBox(
		headerRow,
		a.keyfileLabel,
	)
}

// showKeyfileModal shows the keyfile manager dialog.
func (a *App) showKeyfileModal() {
	// Create order checkbox/label based on mode
	var orderWidget fyne.CanvasObject
	if a.State.Mode != "decrypt" {
		a.keyfileOrderCheck = widget.NewCheck(tr("keyfiles.require_order", "Use order"), func(checked bool) {
			a.State.KeyfileOrdered = checked
		})
		a.keyfileOrderCheck.SetChecked(a.State.KeyfileOrdered)
		orderWidget = a.keyfileOrderCheck
	} else if a.State.KeyfileOrdered {
		orderWidget = widget.NewLabel(tr("keyfiles.order_required", "Order matters"))
	} else {
		orderWidget = widget.NewLabel("") // Empty placeholder
	}

	// Separator (only visible when keyfiles exist)
	a.keyfileSeparator = widget.NewSeparator()

	// Container for keyfile labels (dynamic)
	a.keyfileListContainer = container.NewVBox()
	a.keyfileListScroll = container.NewScroll(a.keyfileListContainer)
	a.keyfileListScroll.SetMinSize(fyne.NewSize(keyfileDialogListWidth, keyfileDialogListHeight))
	a.updateKeyfileList()

	// Buttons
	clearBtn := widget.NewButton(tr("action.clear", "Clear"), func() {
		a.State.Keyfiles = nil
		a.State.ModalID++
		a.updateKeyfileList()
		a.updateUIState()
	})

	doneBtn := widget.NewButton(tr("action.done", "Done"), func() {
		a.keyfileModal.Hide()
		a.State.ShowKeyfile = false
		a.updateUIState()
	})
	doneBtn.Importance = widget.HighImportance

	buttonRow := container.NewGridWithColumns(2, clearBtn, doneBtn)

	content := container.NewVBox(
		widget.NewLabel(tr("keyfiles.drop_hint", "Drop keyfiles here")),
		orderWidget,
		a.keyfileSeparator,
		a.keyfileListScroll,
		buttonRow,
	)

	a.keyfileModal = dialog.NewCustomWithoutButtons(tr("keyfiles.manage_title", "Keyfiles"), content, a.Window)
	a.keyfileModal.Resize(fyne.NewSize(keyfileDialogWidth, keyfileDialogHeight))
	a.State.ShowKeyfile = true
	a.State.ModalID++
	a.keyfileModal.Show()
}

// updateKeyfileList updates the keyfile list in the modal.
func (a *App) updateKeyfileList() {
	if a.keyfileListContainer == nil {
		return
	}

	// Clear existing items
	a.keyfileListContainer.RemoveAll()

	// Show/hide separator based on keyfile count
	if a.keyfileSeparator != nil {
		if len(a.State.Keyfiles) > 0 {
			a.keyfileSeparator.Show()
		} else {
			a.keyfileSeparator.Hide()
		}
	}
	if a.keyfileListScroll != nil {
		if len(a.State.Keyfiles) > 0 {
			a.keyfileListScroll.Show()
		} else {
			a.keyfileListScroll.Hide()
		}
	}

	// Add label for each keyfile
	for _, kf := range a.State.Keyfiles {
		label := newKeyfileNameLabel(filepath.Base(kf))
		a.keyfileListContainer.Add(label)
	}

	a.keyfileListContainer.Refresh()
}

func newKeyfileNameLabel(name string) *widget.Label {
	label := widget.NewLabel(name)
	label.Truncation = fyne.TextTruncateEllipsis
	return label
}

// createKeyfile creates a new random keyfile.
func (a *App) createKeyfile() {
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		defer func() { _ = writer.Close() }()

		data := make([]byte, 32)
		if n, err := rand.Read(data); err != nil || n != 32 {
			a.State.SetStatusMessage(app.StatusKeyfileGenerateFailed, util.RED, app.StatusArgs{})
			a.updateUIState()
			return
		}

		n, err := writer.Write(data)
		if err != nil || n != 32 {
			a.State.SetStatusMessage(app.StatusKeyfileWriteFailed, util.RED, app.StatusArgs{})
			a.updateUIState()
			return
		}

		a.State.SetReadyStatus()
		a.updateUIState()
	}, a.Window)

	saveDialog.SetFileName("keyfile-" + strconv.Itoa(int(time.Now().Unix())) + ".bin")

	// Set start directory if we have files selected
	startDir := ""
	if len(a.State.OnlyFiles) > 0 {
		startDir = filepath.Dir(a.State.OnlyFiles[0])
	} else if len(a.State.OnlyFolders) > 0 {
		startDir = filepath.Dir(a.State.OnlyFolders[0])
	}
	if startDir != "" {
		uri := storage.NewFileURI(startDir)
		if listable, err := storage.ListerForURI(uri); err == nil {
			saveDialog.SetLocation(listable)
		}
	}

	a.showFileDialogWithResize(saveDialog, fyne.NewSize(600, 450))
}

// updateKeyfileUIState updates the enabled/disabled state of keyfile controls.
func (a *App) updateKeyfileUIState(mainDisabled bool, snap app.UISnapshot) {
	// Keyfile section - disabled when mode == "decrypt" && !keyfile && !deniability
	keyfileDisabled := mainDisabled || (snap.Mode == "decrypt" && !snap.Keyfile && !snap.Deniability)
	if a.keyfileEditBtn != nil {
		if keyfileDisabled {
			a.keyfileEditBtn.Disable()
		} else {
			a.keyfileEditBtn.Enable()
		}
	}
	// Keyfile Create - disabled in decrypt mode
	if a.keyfileCreateBtn != nil {
		if mainDisabled || snap.Mode == "decrypt" {
			a.keyfileCreateBtn.Disable()
		} else {
			a.keyfileCreateBtn.Enable()
		}
	}
}
