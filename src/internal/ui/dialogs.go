// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"Picocrypt-NG/internal/util"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

// showProgressModal shows the progress dialog.
func (a *App) showProgressModal() {
	// Reset bindings for new operation
	_ = a.boundProgress.Set(0)
	_ = a.boundStatus.Set("")

	// Create bound widgets - they auto-update when bindings change
	a.progressBar = widget.NewProgressBarWithData(a.boundProgress)
	a.progressBar.Min = 0
	a.progressBar.Max = 1

	// Status shows speed and ETA (e.g., "Encrypting at 10.33 MiB/s (ETA: 00:00:00)")
	// Progress bar already shows percentage, so no need for separate percentage label
	a.progressStatus = widget.NewLabelWithData(a.boundStatus)

	a.cancelButton = widget.NewButton("Cancel", func() {
		a.State.Working = false
		a.State.CanCancel = false
		a.cancelled.Store(true)
		a.State.MainStatus = "Operation cancelled by user"
		a.State.MainStatusColor = util.WHITE
		if a.cancelButton != nil {
			a.cancelButton.Disable()
		}
	})

	progressContent := container.NewVBox(
		container.NewBorder(nil, nil, nil, a.cancelButton, a.progressBar),
		a.progressStatus,
	)

	a.progressModal = dialog.NewCustomWithoutButtons("Progress:", progressContent, a.Window)
	a.progressModal.Show()
}

// showPassgenModal shows the password generator dialog.
func (a *App) showPassgenModal() {
	lengthLabel := widget.NewLabel(fmt.Sprintf("Length: %d", a.State.PassgenLength))

	lengthSlider := widget.NewSlider(12, 64)
	lengthSlider.Value = float64(a.State.PassgenLength)
	lengthSlider.Step = 1
	lengthSlider.OnChanged = func(value float64) {
		a.State.PassgenLength = int32(value)
		lengthLabel.SetText(fmt.Sprintf("Length: %d", int(value)))
	}

	upperCheck := widget.NewCheck("Uppercase", func(checked bool) {
		a.State.PassgenUpper = checked
	})
	upperCheck.SetChecked(a.State.PassgenUpper)

	lowerCheck := widget.NewCheck("Lowercase", func(checked bool) {
		a.State.PassgenLower = checked
	})
	lowerCheck.SetChecked(a.State.PassgenLower)

	numsCheck := widget.NewCheck("Numbers", func(checked bool) {
		a.State.PassgenNums = checked
	})
	numsCheck.SetChecked(a.State.PassgenNums)

	symbolsCheck := widget.NewCheck("Symbols", func(checked bool) {
		a.State.PassgenSymbols = checked
	})
	symbolsCheck.SetChecked(a.State.PassgenSymbols)

	copyCheck := widget.NewCheck("Copy to clipboard", func(checked bool) {
		a.State.PassgenCopy = checked
	})
	copyCheck.SetChecked(a.State.PassgenCopy)

	content := container.NewVBox(
		lengthLabel,
		lengthSlider,
		upperCheck,
		lowerCheck,
		numsCheck,
		symbolsCheck,
		copyCheck,
	)

	a.passgenModal = dialog.NewCustomConfirm("Generate password:", "Generate", "Cancel", content, func(generate bool) {
		if generate {
			// Check if at least one character type is selected
			if !a.State.PassgenUpper && !a.State.PassgenLower && !a.State.PassgenNums && !a.State.PassgenSymbols {
				return
			}
			password := a.State.GenPassword()
			a.State.Password = password
			a.State.CPassword = password
			if a.passwordEntry != nil {
				a.passwordEntry.SetText(password)
			}
			if a.cPasswordEntry != nil {
				a.cPasswordEntry.SetText(password)
			}
			a.updatePasswordStrength()
			a.updateValidation()
		}
		a.State.ShowPassgen = false
	}, a.Window)
	a.State.ShowPassgen = true
	a.State.ModalID++
	a.passgenModal.Show()
}

// showOverwriteModal shows the overwrite confirmation dialog.
func (a *App) showOverwriteModal() {
	a.overwriteModal = dialog.NewConfirm("Warning:", "Output already exists. Overwrite?", func(overwrite bool) {
		a.State.ShowOverwrite = false
		if overwrite {
			a.startWork()
		}
	}, a.Window)
	a.State.ShowOverwrite = true
	a.State.ModalID++
	a.overwriteModal.Show()
}

// changeOutputFile opens a dialog to change the output file path.
func (a *App) changeOutputFile() {
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		// Close immediately - we only need the path, not to write
		// Fyne's file save dialog creates a 0-byte file, so we must remove it
		filePath := writer.URI().Path()
		writer.Close()
		os.Remove(filePath)

		file := filePath
		// Strip any extension user might have added
		file = filepath.Join(filepath.Dir(file), strings.Split(filepath.Base(file), ".")[0])

		// Add correct extensions
		if a.State.Mode == "encrypt" {
			if len(a.State.AllFiles) > 1 || len(a.State.OnlyFolders) > 0 || a.State.Compress {
				file += ".zip.pcv"
			} else {
				file += filepath.Ext(a.State.InputFile) + ".pcv"
			}
		} else {
			if strings.HasSuffix(a.State.InputFile, ".zip.pcv") {
				file += ".zip"
			} else {
				tmp := strings.TrimSuffix(filepath.Base(a.State.InputFile), ".pcv")
				file += filepath.Ext(tmp)
			}
		}

		a.State.OutputFile = file
		a.State.MainStatus = "Ready"
		a.State.MainStatusColor = util.WHITE
		a.updateUIState()
	}, a.Window)

	// Prefill filename - preserve user's choice, only generate random name if needed
	tmp := strings.TrimSuffix(filepath.Base(a.State.OutputFile), ".pcv")
	defaultName := strings.TrimSuffix(tmp, filepath.Ext(tmp))
	// Only generate a new random name if there isn't already a meaningful filename,
	// or if the current name is auto-generated (starts with "encrypted-")
	if a.State.Mode == "encrypt" && (len(a.State.AllFiles) > 1 || len(a.State.OnlyFolders) > 0 || a.State.Compress) {
		if defaultName == "" || strings.HasPrefix(defaultName, "encrypted-") {
			defaultName = "encrypted-" + strconv.Itoa(int(time.Now().Unix()))
		}
	}
	saveDialog.SetFileName(defaultName)

	// Set start directory
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
