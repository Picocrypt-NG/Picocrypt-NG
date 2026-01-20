// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"crypto/rand"
	"path/filepath"
	"strconv"
	"time"

	"Picocrypt-NG/internal/util"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

// buildKeyfilesSection creates the keyfiles input section.
func (a *App) buildKeyfilesSection() fyne.CanvasObject {
	a.keyfileEditBtn = widget.NewButton("Edit", func() {
		a.showKeyfileModal()
	})

	a.keyfileCreateBtn = widget.NewButton("Create", func() {
		a.createKeyfile()
	})

	a.keyfileLabel = widget.NewLabel(a.State.KeyfileLabel)

	// Create bold label for better visual hierarchy
	keyfilesLabel := widget.NewLabel("Keyfiles:")
	keyfilesLabel.TextStyle = fyne.TextStyle{Bold: true}

	// Layout: "Keyfiles:" Edit Create [label fills rest]
	return container.NewHBox(
		keyfilesLabel,
		a.keyfileEditBtn,
		a.keyfileCreateBtn,
		a.keyfileLabel,
	)
}

// showKeyfileModal shows the keyfile manager dialog.
func (a *App) showKeyfileModal() {
	// Create order checkbox/label based on mode
	var orderWidget fyne.CanvasObject
	if a.State.Mode != "decrypt" {
		a.keyfileOrderCheck = widget.NewCheck("Require correct order", func(checked bool) {
			a.State.KeyfileOrdered = checked
		})
		a.keyfileOrderCheck.SetChecked(a.State.KeyfileOrdered)
		orderWidget = a.keyfileOrderCheck
	} else if a.State.KeyfileOrdered {
		orderWidget = widget.NewLabel("Correct ordering is required")
	} else {
		orderWidget = widget.NewLabel("") // Empty placeholder
	}

	// Separator (only visible when keyfiles exist)
	a.keyfileSeparator = widget.NewSeparator()

	// Container for keyfile labels (dynamic)
	a.keyfileListContainer = container.NewVBox()
	a.updateKeyfileList()

	// Buttons
	clearBtn := widget.NewButton("Clear", func() {
		a.State.Keyfiles = nil
		if a.State.Keyfile {
			a.State.KeyfileLabel = "Keyfiles required"
		} else {
			a.State.KeyfileLabel = "None selected"
		}
		a.State.ModalID++
		a.updateKeyfileList()
		a.updateUIState()
	})

	doneBtn := widget.NewButton("Done", func() {
		a.keyfileModal.Hide()
		a.State.ShowKeyfile = false
		a.updateUIState()
	})
	doneBtn.Importance = widget.HighImportance

	buttonRow := container.NewGridWithColumns(2, clearBtn, doneBtn)

	content := container.NewVBox(
		widget.NewLabel("Drag and drop your keyfiles here"),
		orderWidget,
		a.keyfileSeparator,
		a.keyfileListContainer,
		buttonRow,
	)

	a.keyfileModal = dialog.NewCustomWithoutButtons("Manage keyfiles:", content, a.Window)
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

	// Add label for each keyfile
	for _, kf := range a.State.Keyfiles {
		label := widget.NewLabel(filepath.Base(kf))
		a.keyfileListContainer.Add(label)
	}

	a.keyfileListContainer.Refresh()
}

// createKeyfile creates a new random keyfile.
func (a *App) createKeyfile() {
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		defer writer.Close()

		data := make([]byte, 32)
		if n, err := rand.Read(data); err != nil || n != 32 {
			a.State.MainStatus = "Failed to generate keyfile"
			a.State.MainStatusColor = util.RED
			a.updateUIState()
			return
		}

		n, err := writer.Write(data)
		if err != nil || n != 32 {
			a.State.MainStatus = "Failed to write keyfile"
			a.State.MainStatusColor = util.RED
			a.updateUIState()
			return
		}

		a.State.MainStatus = "Ready"
		a.State.MainStatusColor = util.WHITE
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
func (a *App) updateKeyfileUIState(mainDisabled bool) {
	// Keyfile section - disabled when mode == "decrypt" && !keyfile && !deniability
	keyfileDisabled := mainDisabled || (a.State.Mode == "decrypt" && !a.State.Keyfile && !a.State.Deniability)
	if a.keyfileEditBtn != nil {
		if keyfileDisabled {
			a.keyfileEditBtn.Disable()
		} else {
			a.keyfileEditBtn.Enable()
		}
	}
	// Keyfile Create - disabled in decrypt mode
	if a.keyfileCreateBtn != nil {
		if mainDisabled || a.State.Mode == "decrypt" {
			a.keyfileCreateBtn.Disable()
		} else {
			a.keyfileCreateBtn.Enable()
		}
	}
}
