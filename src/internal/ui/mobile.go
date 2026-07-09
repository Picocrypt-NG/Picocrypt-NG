// Package ui provides mobile-specific UI components for Picocrypt NG.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/util"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

var errUnsafeMobileFilename = errors.New("unsafe file name")

// isMobile returns true if running on a mobile device
func isMobile() bool {
	return fyne.CurrentDevice().IsMobile()
}

// buildMobileUI creates the mobile-optimized UI layout
func (a *App) buildMobileUI() fyne.CanvasObject {
	snap := a.State.UISnapshot()

	// File selection section (replaces drag-drop)
	fileSection := a.buildMobileFileSection()

	// Password section with larger buttons
	passwordSection := a.buildMobilePasswordSection()

	// Keyfiles section
	keyfilesSection := a.buildMobileKeyfilesSection()

	// Comments section
	commentsSection := a.buildMobileCommentsSection()

	// Advanced section
	a.advancedContainer = container.NewVBox()
	a.advancedLabel = widget.NewLabel(tr("advanced.label", "Advanced:"))
	a.updateMobileAdvancedSection()

	// Output section
	outputSection := a.buildMobileOutputSection()

	a.languageSelector = newLanguageSelector(a)
	utilityRow := container.NewBorder(nil, nil, nil, a.languageSelector.object(), widget.NewLabel(""))

	// Start button - large and prominent
	a.startButton = widget.NewButton(renderStartAction(snap.StartAction, snap.Recursively), a.onClickStart)
	a.startButton.Importance = widget.HighImportance

	a.statusLabel = NewColoredLabel(renderStatus(snap.Status, snap), snap.Status.Color)

	// Main content in a vertical box
	a.mainContent = container.NewVBox(
		utilityRow,
		fileSection,
		widget.NewSeparator(),
		passwordSection,
		keyfilesSection,
		widget.NewSeparator(),
		commentsSection,
		a.advancedLabel,
		a.advancedContainer,
		outputSection,
		widget.NewSeparator(),
		a.startButton,
		a.statusLabel,
	)

	// Wrap in scroll container for small screens
	scroll := container.NewVScroll(container.NewPadded(a.mainContent))

	a.updateUIState()

	return scroll
}

// buildMobileFileSection creates the file selection section for mobile
func (a *App) buildMobileFileSection() fyne.CanvasObject {
	snap := a.State.UISnapshot()
	a.inputLabel = widget.NewLabel(renderInputSummary(snap.InputSummary))
	a.inputLabel.Wrapping = fyne.TextWrapWord

	// Select Files button - opens file picker
	a.mobileSelectFilesBtn = widget.NewButtonWithIcon(tr("mobile.select_files", "Select Files"), theme.FolderOpenIcon(), func() {
		a.showMobileFilePicker()
	})
	a.mobileSelectFilesBtn.Importance = widget.HighImportance

	// Select Folder button
	a.mobileSelectFolderBtn = widget.NewButtonWithIcon(tr("mobile.select_folder", "Select Folder"), theme.FolderIcon(), func() {
		a.showMobileFolderPicker()
	})

	// Clear button
	a.clearButton = widget.NewButton(tr("action.clear", "Clear"), a.resetUI)
	a.clearButton.Importance = widget.MediumImportance

	// Button row
	buttonRow := container.NewGridWithColumns(3, a.mobileSelectFilesBtn, a.mobileSelectFolderBtn, a.clearButton)

	// App Storage button for large files (no copying required)
	a.mobileAppStorageBtn = widget.NewButton(tr("mobile.app_storage.button", "App Storage (large files)"), func() {
		a.showAppStorageDialog()
	})

	// Help text
	a.mobileAppStorageHelp = widget.NewLabel(tr("mobile.app_storage.tip", "Tip: For large files, copy them to App Storage first"))
	a.mobileAppStorageHelp.Wrapping = fyne.TextWrapWord
	a.mobileAppStorageHelp.TextStyle = fyne.TextStyle{Italic: true}

	return container.NewVBox(
		a.inputLabel,
		buttonRow,
		a.mobileAppStorageBtn,
		a.mobileAppStorageHelp,
	)
}

// getAppStorageDir returns the app's local storage directory path.
// Files in this directory can be accessed directly without copying.
func (a *App) getAppStorageDir() string {
	filesDir := os.Getenv("FILESDIR")
	if filesDir != "" {
		return filepath.Join(filesDir, "Documents")
	}
	// Fallback for non-Android or testing
	return filepath.Join(os.TempDir(), "picocrypt-documents")
}

// showAppStorageDialog shows a dialog explaining how to use app storage for large files
func (a *App) showAppStorageDialog() {
	appDir := a.getAppStorageDir()

	// Ensure directory exists
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		a.State.SetStatusMessage(app.StatusMobileAppStorageCreateFailed, util.RED, app.StatusArgs{})
		a.refreshUI()
		return
	}

	// List files in app storage
	files, err := os.ReadDir(appDir)
	if err != nil {
		a.State.SetStatusMessage(app.StatusMobileAppStorageReadFailed, util.RED, app.StatusArgs{})
		a.refreshUI()
		return
	}

	if len(files) == 0 {
		// Show instructions
		content := widget.NewLabel(tr("mobile.app_storage.empty_instructions",
			"App Storage is empty.\n\n"+
				"To use large files without copying:\n"+
				"1. Open a file manager app\n"+
				"2. Copy files to:\n"+
				"   {{.Path}}\n"+
				"3. Come back and select them here", map[string]any{
				"Path": appDir,
			}))
		content.Wrapping = fyne.TextWrapWord

		copyPathBtn := widget.NewButton(tr("mobile.app_storage.copy_path", "Copy Path"), func() {
			a.fyneApp.Clipboard().SetContent(appDir)
			a.State.SetStatusMessage(app.StatusMobileAppStoragePathCopied, util.WHITE, app.StatusArgs{})
			a.refreshUI()
		})

		d := dialog.NewCustom(tr("mobile.app_storage.title", "App Storage"), tr("action.close", "Close"), container.NewVBox(content, copyPathBtn), a.Window)
		d.Show()
		return
	}

	// Show file list
	var items []string
	for _, f := range files {
		if !f.IsDir() {
			items = append(items, f.Name())
		}
	}

	if len(items) == 0 {
		a.State.SetStatusMessage(app.StatusMobileAppStorageNoFiles, util.YELLOW, app.StatusArgs{})
		a.refreshUI()
		return
	}

	list := widget.NewList(
		func() int { return len(items) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(items[i])
		},
	)
	list.OnSelected = func(id widget.ListItemID) {
		selectedPath := filepath.Join(appDir, items[id])
		a.onDrop([]string{selectedPath})
	}

	d := dialog.NewCustom(tr("mobile.app_storage.select_title", "Select from App Storage"), tr("action.cancel", "Cancel"), list, a.Window)
	d.Resize(fyne.NewSize(300, 400))
	d.Show()
}

// showMobileFilePicker opens the native file picker for mobile
func (a *App) showMobileFilePicker() {
	fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			return
		}
		defer func() { _ = reader.Close() }()

		// On Android, content:// URIs don't work with os.Stat()
		// We need to copy the file to a local temp directory
		uri := reader.URI()
		if uri.Scheme() == "content" {
			localPath, copyErr := a.copyURIToTemp(reader, uri.Name())
			if copyErr != nil {
				a.State.SetStatusMessage(mobileFileAccessStatusKind(copyErr), util.RED, mobileFileAccessStatusArgs(copyErr))
				a.refreshUI()
				return
			}
			a.onDrop([]string{localPath})
		} else {
			// For file:// URIs, use the path directly
			a.onDrop([]string{uri.Path()})
		}
	}, a.Window)

	fd.Show()
}

// showMobileFolderPicker opens the native folder picker for mobile
func (a *App) showMobileFolderPicker() {
	// On Android, folder picking via SAF has issues with recursive listing
	// Direct users to use App Storage instead
	a.showFolderNotSupportedDialog()
}

// showFolderNotSupportedDialog shows a dialog explaining folder limitations on Android
func (a *App) showFolderNotSupportedDialog() {
	appDir := a.getAppStorageDir()

	content := widget.NewLabel(tr("mobile.folder_selection.unsupported",
		"Folder selection is not fully supported on Android.\n\n"+
			"For folders, please:\n"+
			"1. Copy your folder to App Storage using a file manager\n"+
			"2. Use 'App Storage (large files)' button to select it\n\n"+
			"App Storage path:\n{{.Path}}", map[string]any{
			"Path": appDir,
		}))
	content.Wrapping = fyne.TextWrapWord

	copyPathBtn := widget.NewButton(tr("mobile.folder_selection.copy_path", "Copy Path to Clipboard"), func() {
		a.fyneApp.Clipboard().SetContent(appDir)
		a.State.SetStatusMessage(app.StatusMobileAppStoragePathCopied, util.WHITE, app.StatusArgs{})
		a.refreshUI()
	})

	openAppStorageBtn := widget.NewButton(tr("mobile.folder_selection.open_app_storage", "Open App Storage"), func() {
		a.showAppStorageDialog()
	})

	buttons := container.NewHBox(copyPathBtn, openAppStorageBtn)

	d := dialog.NewCustom(tr("mobile.folder_selection.title", "Folder Selection"), tr("action.close", "Close"), container.NewVBox(content, buttons), a.Window)
	d.Show()
}

func mobileFileAccessStatusKind(err error) app.StatusKind {
	if errors.Is(err, errUnsafeMobileFilename) {
		return app.StatusMobileFileAccessUnsafeName
	}
	return app.StatusMobileFileAccessFailed
}

func mobileFileAccessStatusArgs(err error) app.StatusArgs {
	return app.StatusArgs{Error: err.Error()}
}

// getMobileTempDir returns the temp directory for mobile file copies.
// Uses app's internal storage which is more reliable on Android.
func (a *App) getMobileTempDir() string {
	// Use FILESDIR env var if available (set by Android native code)
	filesDir := os.Getenv("FILESDIR")
	if filesDir != "" {
		return filepath.Join(filesDir, "picocrypt-temp")
	}
	// Fallback to system temp
	return filepath.Join(os.TempDir(), "picocrypt-mobile")
}

// CleanupMobileTempFiles removes all temporary files created for mobile operations.
// Call this after encryption/decryption is complete.
func (a *App) CleanupMobileTempFiles() {
	tempDir := a.getMobileTempDir()
	_ = os.RemoveAll(tempDir)
}

func validateMobileTempFilename(name string) error {
	if name == "" {
		return errUnsafeMobileFilename
	}
	if name == "." || name == ".." {
		return errUnsafeMobileFilename
	}
	if strings.ContainsAny(name, `/\`) {
		return errUnsafeMobileFilename
	}
	if filepath.IsAbs(name) {
		return errUnsafeMobileFilename
	}
	if len(name) >= 2 && name[1] == ':' {
		return errUnsafeMobileFilename
	}
	if filepath.Base(name) != name {
		return errUnsafeMobileFilename
	}

	trimmed := strings.TrimRight(name, " .")
	if trimmed == "" || trimmed != name || trimmed == "." || trimmed == ".." {
		return errUnsafeMobileFilename
	}

	return nil
}

// copyURIToTemp copies a file from a content:// URI to a local temp file
// Returns the path to the local file
func (a *App) copyURIToTemp(reader io.Reader, filename string) (string, error) {
	if err := validateMobileTempFilename(filename); err != nil {
		return "", err
	}

	// Create temp directory for mobile file copies
	tempDir := a.getMobileTempDir()
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return "", err
	}

	// Create the destination file
	destPath := filepath.Join(tempDir, filename)
	destFile, err := fileops.CreateSecureNoSymlink(destPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = destFile.Close() }()

	// Copy the content
	_, err = io.Copy(destFile, reader)
	if err != nil {
		_ = os.Remove(destPath)
		return "", err
	}

	return destPath, nil
}

// buildMobilePasswordSection creates the password section for mobile with larger buttons
func (a *App) buildMobilePasswordSection() fyne.CanvasObject {
	// Password buttons - 3 per row for better touch targets
	a.showHideBtn = newToolbarButton(passwordVisibilityLabel(a.State.PasswordMode), passwordVisibilityIcon(a.State.PasswordMode), func() {
		a.State.TogglePasswordVisibility()
		snap := a.State.UISnapshot()
		configureToolbarButton(a.showHideBtn, passwordVisibilityLabel(snap.PasswordMode), passwordVisibilityIcon(snap.PasswordMode))
		hidden := snap.PasswordMode == app.PasswordModeHidden
		a.passwordEntry.SetHidden(hidden)
		a.cPasswordEntry.SetHidden(hidden)
	})

	a.clearPwdBtn = newToolbarButton(tr("action.clear", "Clear"), theme.ContentClearIcon(), func() {
		a.State.Password = ""
		a.State.CPassword = ""
		a.passwordEntry.SetText("")
		a.cPasswordEntry.SetText("")
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState()
	})

	a.copyBtn = newToolbarButton(tr("action.copy", "Copy"), theme.ContentCopyIcon(), func() {
		a.fyneApp.Clipboard().SetContent(a.State.Password)
	})

	a.pasteBtn = newToolbarButton(tr("action.paste", "Paste"), theme.ContentPasteIcon(), func() {
		text := a.fyneApp.Clipboard().Content()
		a.State.Password = text
		a.passwordEntry.SetText(text)
		if a.State.Mode != "decrypt" {
			a.State.CPassword = text
			a.cPasswordEntry.SetText(text)
		}
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState()
	})

	a.createBtn = newToolbarButton(tr("action.create", "Create"), theme.DocumentCreateIcon(), func() {
		a.showPassgenModal()
	})

	// Two rows of buttons for better touch targets
	buttonRow1 := container.NewGridWithColumns(3, a.showHideBtn, a.clearPwdBtn, a.copyBtn)
	buttonRow2 := container.NewGridWithColumns(2, a.pasteBtn, a.createBtn)

	// Password input
	a.passwordEntry = NewPasswordEntry()
	a.passwordEntry.SetPlaceHolder(tr("password.placeholder", "Password"))
	a.passwordEntry.OnChanged = func(text string) {
		a.State.Password = text
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState()
	}

	a.strengthIndicator = NewPasswordStrengthIndicator()

	// Confirm password
	a.cPasswordEntry = NewPasswordEntry()
	a.cPasswordEntry.SetPlaceHolder(tr("password.confirm_placeholder", "Confirm password"))
	a.cPasswordEntry.OnChanged = func(text string) {
		a.State.CPassword = text
		a.updateValidation()
		a.updateUIState()
	}

	a.validIndicator = NewValidationIndicator()

	a.passwordLabel = widget.NewLabel(tr("password.label", "Password:"))
	a.confirmLabel = widget.NewLabel(tr("password.confirm_label", "Confirm password:"))
	passwordTitle := container.NewHBox(a.passwordLabel, a.strengthIndicator)
	confirmTitle := container.NewHBox(a.confirmLabel, a.validIndicator)
	a.confirmRow = container.NewVBox(confirmTitle, a.cPasswordEntry)

	return container.NewVBox(
		passwordTitle,
		buttonRow1,
		buttonRow2,
		a.passwordEntry,
		a.confirmRow,
	)
}

// buildMobileKeyfilesSection creates the keyfiles section for mobile
func (a *App) buildMobileKeyfilesSection() fyne.CanvasObject {
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

	buttonRow := container.NewGridWithColumns(2, a.keyfileEditBtn, a.keyfileCreateBtn)
	a.keyfilesTitleLabel = widget.NewLabel(tr("keyfiles.label", "Keyfiles:"))

	return container.NewVBox(
		a.keyfilesTitleLabel,
		buttonRow,
		a.keyfileLabel,
	)
}

// buildMobileCommentsSection creates the comments section for mobile
func (a *App) buildMobileCommentsSection() fyne.CanvasObject {
	a.commentsLabel = widget.NewLabel(commentsLabelText(a.State.Mode))
	a.commentsEntry = widget.NewEntry()
	a.commentsEntry.SetPlaceHolder(tr("comments.placeholder", "Public note; not encrypted."))
	a.commentsEntry.MultiLine = true
	a.commentsEntry.OnChanged = func(text string) {
		if a.State.Mode == "decrypt" {
			snap := a.State.UISnapshot()
			displayText := commentsDisplayText(snap.Mode, snap.Comments, snap.CommentsPreviewState)
			if text != displayText {
				a.commentsEntry.SetText(displayText)
			}
			return
		}
		a.State.Comments = text
	}

	return container.NewVBox(
		a.commentsLabel,
		a.commentsEntry,
	)
}

// updateMobileAdvancedSection updates advanced options for mobile
func (a *App) updateMobileAdvancedSection() {
	a.advancedContainer.RemoveAll()

	if a.State.Mode != "decrypt" {
		a.buildMobileEncryptOptions()
	} else {
		a.buildMobileDecryptOptions()
	}

	// IMPORTANT: Update disable state for newly created checkboxes
	// This ensures checkboxes are disabled until user enters credentials
	a.updateAdvancedDisableState()

	a.advancedContainer.Refresh()
}

// buildMobileEncryptOptions creates encrypt options for mobile
func (a *App) buildMobileEncryptOptions() {
	// Checkboxes with more spacing
	a.paranoidCheck = ttwidget.NewCheck(tr("advanced.paranoid.label", "Paranoid mode"), func(checked bool) {
		a.State.Paranoid = checked
	})
	a.paranoidCheck.SetChecked(a.State.Paranoid)

	a.compressCheck = ttwidget.NewCheck(tr("advanced.compress.label", "Compress files"), func(checked bool) {
		a.State.Compress = checked
		// Auto-toggle .zip suffix in output filename
		a.updateOutputFileForCompress(checked)
	})
	a.compressCheck.SetChecked(a.State.Compress)

	a.reedSolomonCheck = ttwidget.NewCheck(tr("advanced.reed_solomon.label", "Reed-Solomon"), func(checked bool) {
		a.State.ReedSolomon = checked
	})
	a.reedSolomonCheck.SetChecked(a.State.ReedSolomon)

	a.deleteCheck = ttwidget.NewCheck(tr("advanced.delete_files.label", "Delete files"), func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteCheck.SetChecked(a.State.Delete)

	a.deniabilityCheck = ttwidget.NewCheck(tr("advanced.deniability.label", "Deniability"), func(checked bool) {
		a.State.Deniability = checked
		a.updateUIState()
	})
	a.deniabilityCheck.SetChecked(a.State.Deniability)

	a.recursivelyCheck = ttwidget.NewCheck(tr("advanced.recursively.label", "Recursively"), func(checked bool) {
		a.State.Recursively = checked
		if checked {
			a.State.Compress = false
			if a.compressCheck != nil {
				a.compressCheck.SetChecked(false)
			}
		}
		a.updateUIState()
	})
	a.recursivelyCheck.SetChecked(a.State.Recursively)

	// Grid layout - 2 columns
	row1 := container.NewGridWithColumns(2, a.paranoidCheck, a.compressCheck)
	row2 := container.NewGridWithColumns(2, a.reedSolomonCheck, a.deleteCheck)
	row3 := container.NewGridWithColumns(2, a.deniabilityCheck, a.recursivelyCheck)

	// Split section
	a.splitCheck = ttwidget.NewCheck(tr("advanced.split.label", "Split:"), func(checked bool) {
		a.State.Split = checked
		a.updateUIState()
	})
	a.splitCheck.SetChecked(a.State.Split)

	a.splitSizeEntry = widget.NewEntry()
	a.splitSizeEntry.SetPlaceHolder(tr("advanced.split.size_placeholder", "Size"))
	a.splitSizeEntry.SetText(a.State.SplitSize)
	a.splitSizeEntry.OnChanged = func(text string) {
		a.State.SplitSize = text
		a.State.Split = text != ""
		if a.splitCheck != nil {
			a.splitCheck.SetChecked(a.State.Split)
		}
		a.updateUIState()
	}

	a.splitUnitSelect = widget.NewSelect(localizedSplitUnits(a.State.SplitUnits), func(selected string) {
		for i, unit := range a.State.SplitUnits {
			if localizedSplitUnit(unit) == selected {
				// #nosec G115 -- i is bounded by SplitUnits length (5 items: KiB, MiB, GiB, TiB, Total)
				a.State.SplitSelected = int32(i)
				break
			}
		}
	})
	a.splitUnitSelect.SetSelectedIndex(int(a.State.SplitSelected))

	splitRow := container.NewBorder(nil, nil, a.splitCheck, a.splitUnitSelect, a.splitSizeEntry)

	a.advancedContainer.Add(row1)
	a.advancedContainer.Add(row2)
	a.advancedContainer.Add(row3)
	a.advancedContainer.Add(splitRow)
}

// buildMobileDecryptOptions creates decrypt options for mobile
func (a *App) buildMobileDecryptOptions() {
	a.forceDecryptCheck = ttwidget.NewCheck(tr("advanced.force_decrypt.label", "Force decrypt"), func(checked bool) {
		a.State.Keep = checked
	})
	a.forceDecryptCheck.SetChecked(a.State.Keep)

	a.verifyFirstCheck = ttwidget.NewCheck(tr("advanced.verify_first.label", "Verify first"), func(checked bool) {
		a.State.VerifyFirst = checked
	})
	a.verifyFirstCheck.SetChecked(a.State.VerifyFirst)

	a.deleteCheck = ttwidget.NewCheck(tr("advanced.delete_encrypted.label", "Delete encrypted"), func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteCheck.SetChecked(a.State.Delete)

	row1 := container.NewGridWithColumns(2, a.forceDecryptCheck, a.verifyFirstCheck)
	row2 := container.NewGridWithColumns(2, a.deleteCheck, widget.NewLabel(""))

	a.advancedContainer.Add(row1)
	a.advancedContainer.Add(row2)
}

// buildMobileOutputSection creates the output section for mobile
func (a *App) buildMobileOutputSection() fyne.CanvasObject {
	outputEntry := widget.NewLabel("")
	// Truncate long filenames with ellipsis to prevent excessive wrapping
	outputEntry.Truncation = fyne.TextTruncateEllipsis
	a.outputEntry = outputEntry

	a.changeBtn = widget.NewButton(tr("action.change", "Change"), func() {
		a.changeOutputFile()
	})
	a.outputLabel = widget.NewLabel(tr("output.label", "Save output as:"))

	return container.NewVBox(
		a.outputLabel,
		outputEntry,
		a.changeBtn,
	)
}
