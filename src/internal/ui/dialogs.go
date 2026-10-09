// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/log"
	"errors"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

var errUnsafePCV3OutputFilename = errors.New("unsafe PCV3 output filename")

func (a *App) showStatusDetails() {
	if a.statusLabel == nil || a.statusLabel.text == "" || a.Window == nil {
		return
	}
	message := widget.NewLabel(a.statusLabel.text)
	message.Wrapping = fyne.TextWrapBreak
	message.Selectable = true
	details := dialog.NewCustom(
		tr("dialog.status.title", "Status details"), tr("action.close", "Close"),
		container.NewVScroll(message), a.Window,
	)
	size := a.Window.Canvas().Size()
	details.Resize(fyne.NewSize(min(size.Width*0.9, 600), min(size.Height*0.8, 400)))
	details.Show()
}

// showProgressModal shows the progress dialog.
func (a *App) showProgressModal(session *operationSession) {
	// Reset bindings for new operation
	if err := a.boundProgress.Set(0); err != nil {
		log.Error("reset operation progress binding", log.Err(err))
	}
	if err := a.boundStatus.Set(""); err != nil {
		log.Error("reset operation status binding", log.Err(err))
	}

	// Create bound widgets - they auto-update when bindings change
	a.progressBar = widget.NewProgressBarWithData(a.boundProgress)
	a.progressBar.Min = 0
	a.progressBar.Max = 1

	// Status shows speed and ETA (e.g., "Encrypting at 10.33 MiB/s (ETA: 00:00:00)")
	// Progress bar already shows percentage, so no need for separate percentage label
	a.progressStatus = widget.NewLabelWithData(a.boundStatus)

	a.cancelButton = widget.NewButton(tr("action.cancel", "Cancel"), func() {
		a.cancelOperation(session)
	})

	progressContent := container.NewVBox(
		container.NewBorder(nil, nil, nil, a.cancelButton, a.progressBar),
		a.progressStatus,
	)

	a.progressModal = dialog.NewCustomWithoutButtons(tr("dialog.progress.title", "Progress:"), progressContent, a.Window)
	a.progressModal.Show()
}

// showAboutModal shows the About dialog. It is the GUI's only version
// indicator: the window title intentionally carries none (#133).
func (a *App) showAboutModal() {
	a.aboutVersionLabel = widget.NewLabelWithStyle(
		tr("dialog.about.version_label", "Picocrypt NG {{.Version}}", map[string]any{
			"Version": a.Version,
		}), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	repo := widget.NewHyperlink(tr("dialog.about.github_link", "Picocrypt-NG on GitHub"), &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/Picocrypt-NG/Picocrypt-NG",
	})

	content := container.NewVBox(
		a.aboutVersionLabel,
		container.NewCenter(repo),
	)

	a.aboutModal = dialog.NewCustom(tr("dialog.about.title", "About:"), tr("action.close", "Close"), content, a.Window)
	a.aboutModal.Show()
}

func passgenLengthText(length int) string {
	return tr("dialog.passgen.length", "Length: {{.Length}}", map[string]any{
		"Length": length,
	})
}

// showPassgenModal shows the password generator dialog.
func (a *App) showPassgenModal() {
	lengthLabel := widget.NewLabel(passgenLengthText(int(a.State.PassgenLength)))

	lengthSlider := widget.NewSlider(12, 64)
	lengthSlider.Value = float64(a.State.PassgenLength)
	lengthSlider.Step = 1
	lengthSlider.OnChanged = func(value float64) {
		a.State.PassgenLength = int32(value)
		lengthLabel.SetText(passgenLengthText(int(value)))
	}

	upperCheck := widget.NewCheck(tr("dialog.passgen.uppercase", "Uppercase"), func(checked bool) {
		a.State.PassgenUpper = checked
	})
	upperCheck.SetChecked(a.State.PassgenUpper)

	lowerCheck := widget.NewCheck(tr("dialog.passgen.lowercase", "Lowercase"), func(checked bool) {
		a.State.PassgenLower = checked
	})
	lowerCheck.SetChecked(a.State.PassgenLower)

	numsCheck := widget.NewCheck(tr("dialog.passgen.numbers", "Numbers"), func(checked bool) {
		a.State.PassgenNums = checked
	})
	numsCheck.SetChecked(a.State.PassgenNums)

	symbolsCheck := widget.NewCheck(tr("dialog.passgen.symbols", "Symbols"), func(checked bool) {
		a.State.PassgenSymbols = checked
	})
	symbolsCheck.SetChecked(a.State.PassgenSymbols)

	copyCheck := widget.NewCheck(tr("dialog.passgen.copy", "Copy to clipboard"), func(checked bool) {
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

	a.passgenModal = dialog.NewCustomConfirm(tr("dialog.passgen.title", "Generate password:"), tr("action.generate", "Generate"), tr("action.cancel", "Cancel"), content, func(generate bool) {
		if generate {
			// Check if at least one character type is selected
			if !a.State.PassgenUpper && !a.State.PassgenLower && !a.State.PassgenNums && !a.State.PassgenSymbols {
				return
			}
			password := a.State.GenPassword()
			passwordChanged := a.passwordEntry != nil && a.passwordEntry.Text != password
			a.State.Password = password
			a.State.CPassword = password
			if a.passwordEntry != nil {
				a.passwordEntry.SetText(password)
			}
			if a.cPasswordEntry != nil {
				a.cPasswordEntry.SetText(password)
			}
			if !passwordChanged {
				a.updatePasswordStrength()
			}
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
	a.overwriteModal = dialog.NewConfirm(tr("dialog.overwrite.title", "Warning:"), tr("dialog.overwrite.message", "Output already exists. Overwrite?"), func(overwrite bool) {
		a.State.ShowOverwrite = false
		if overwrite {
			a.startWork()
		}
	}, a.Window)
	a.State.ShowOverwrite = true
	a.State.ModalID++
	a.overwriteModal.Show()
}

func normalizeSelectedOutputPath(filePath, mode, inputFile string, multiInput, compress bool) string {
	base := filepath.Base(filePath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	file := filepath.Join(filepath.Dir(filePath), base)

	if mode == "encrypt" {
		if multiInput || compress {
			return file + ".zip.pcv"
		}
		return file + filepath.Ext(inputFile) + ".pcv"
	}

	if strings.HasSuffix(inputFile, ".zip.pcv") {
		return file + ".zip"
	}
	tmp := strings.TrimSuffix(filepath.Base(inputFile), ".pcv")
	return file + filepath.Ext(tmp)
}

// changePCV3CreationOutputFile selects only a path. The PCV3 publisher must be
// the first code that opens or creates the destination.
func (a *App) changePCV3CreationOutputFile() {
	selected := a.State.UISnapshot()
	if selected.Mode != "encrypt" || selected.InputFile == "" ||
		selected.OutputFile == "" || selected.Working || selected.Scanning {
		return
	}
	selectionGeneration := a.operationGeneration.Load()
	selectionCurrent := func() bool {
		current := a.State.UISnapshot()
		return a.operationGeneration.Load() == selectionGeneration &&
			current.Mode == "encrypt" && !current.Working &&
			!current.Scanning && current.InputFile == selected.InputFile &&
			current.OutputFile == selected.OutputFile
	}
	picker := dialog.NewFolderOpen(func(folder fyne.ListableURI, err error) {
		if err != nil || folder == nil || folder.Scheme() != "file" || !selectionCurrent() {
			return
		}
		filename := widget.NewEntry()
		tmp := strings.TrimSuffix(filepath.Base(selected.OutputFile), ".pcv")
		filename.SetText(strings.TrimSuffix(tmp, filepath.Ext(tmp)))
		filename.Validator = validatePCV3OutputFilename
		form := dialog.NewForm(
			tr("output.label", "Save output as:"),
			tr("action.change", "Change"),
			tr("action.cancel", "Cancel"),
			[]*widget.FormItem{widget.NewFormItem(tr("output.label", "Save output as:"), filename)},
			func(confirm bool) {
				if !confirm || !selectionCurrent() || validatePCV3OutputFilename(filename.Text) != nil {
					return
				}
				current := a.State.Snapshot()
				a.State.OutputFile = normalizeSelectedOutputPath(
					filepath.Join(folder.Path(), filename.Text),
					"encrypt",
					current.InputFile,
					len(current.InputFiles) > 1 || len(current.OnlyFolders) > 0,
					current.Compress,
				)
				a.State.OutputChosenViaSaveDialog = false
				a.State.SetReadyStatus()
				a.updateUIState()
			},
			a.Window,
		)
		form.Show()
	}, a.Window)

	startDir := ""
	if len(a.State.OnlyFiles) > 0 {
		startDir = filepath.Dir(a.State.OnlyFiles[0])
	} else if len(a.State.OnlyFolders) > 0 {
		startDir = filepath.Dir(a.State.OnlyFolders[0])
	}
	if startDir != "" {
		if folder, err := storage.ListerForURI(storage.NewFileURI(startDir)); err == nil {
			picker.SetLocation(folder)
		}
	}
	picker.Show()
}

// changePCV3OutputFile chooses a destination without asking Fyne to open a
// writer. PCV3 publication is no-replace, so only its executor may create the
// selected path.
func (a *App) changePCV3OutputFile() {
	ticket, _, ok := a.State.PCV3ReadyOutputSelection()
	if !ok {
		return
	}
	picker := dialog.NewFolderOpen(func(folder fyne.ListableURI, err error) {
		a.handlePCV3OutputFolderSelection(ticket, folder, err)
	}, a.Window)

	startDir := ""
	if len(a.State.OnlyFiles) > 0 {
		startDir = filepath.Dir(a.State.OnlyFiles[0])
	} else if len(a.State.OnlyFolders) > 0 {
		startDir = filepath.Dir(a.State.OnlyFolders[0])
	}
	if startDir != "" {
		if folder, err := storage.ListerForURI(storage.NewFileURI(startDir)); err == nil {
			picker.SetLocation(folder)
		}
	}
	picker.Show()
}

func (a *App) handlePCV3OutputFolderSelection(ticket uint64, folder fyne.ListableURI, err error) {
	if err != nil || folder == nil || folder.Scheme() != "file" ||
		!a.State.IsPCV3ReadyOutputSelection(ticket) {
		return
	}
	a.showPCV3OutputFilenameForm(ticket, folder.Path())
}

func (a *App) showPCV3OutputFilenameForm(ticket uint64, folder string) {
	currentTicket, output, ok := a.State.PCV3ReadyOutputSelection()
	if !ok || currentTicket != ticket {
		return
	}
	filename := widget.NewEntry()
	filename.SetText(filepath.Base(output))
	filename.Validator = validatePCV3OutputFilename
	form := dialog.NewForm(
		tr("output.label", "Save output as:"),
		tr("action.change", "Change"),
		tr("action.cancel", "Cancel"),
		[]*widget.FormItem{widget.NewFormItem(tr("output.label", "Save output as:"), filename)},
		func(confirm bool) {
			if !confirm {
				return
			}
			_ = a.applyPCV3OutputSelection(ticket, folder, filename.Text)
		},
		a.Window,
	)
	form.Show()
}

func validatePCV3OutputFilename(filename string) error {
	if filename == "" || filename == "." || filename == ".." ||
		filepath.Base(filename) != filename || strings.ContainsAny(filename, "/\\\x00") {
		return errUnsafePCV3OutputFilename
	}
	return nil
}

func (a *App) applyPCV3OutputSelection(ticket uint64, folder, filename string) error {
	if folder == "" {
		return errUnsafePCV3OutputFilename
	}
	if err := validatePCV3OutputFilename(filename); err != nil {
		return err
	}
	if !a.State.SetPCV3OutputForReady(ticket, filepath.Join(folder, filename)) {
		return errors.New("PCV3 output selection is no longer available")
	}
	a.updateUIState()
	return nil
}

// changeOutputFile opens a dialog to change the output file path.
func (a *App) changeOutputFile() {
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}

		filePath := writer.URI().Path()
		_ = writer.Close()
		a.State.OutputFile = normalizeSelectedOutputPath(
			filePath,
			a.State.Mode,
			a.State.InputFile,
			len(a.State.AllFiles) > 1 || len(a.State.OnlyFolders) > 0,
			a.State.Compress,
		)
		a.State.OutputChosenViaSaveDialog = true
		a.State.SetReadyStatus()
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
