// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/app"
	pwnorm "Picocrypt-NG/internal/password"
	"context"
	"strings"

	"github.com/Picocrypt/zxcvbn-go"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func passwordVisibilityLabel(mode app.PasswordInputMode) string {
	if mode == app.PasswordModeVisible {
		return tr("password.hide", "Hide")
	}
	return tr("password.show", "Show")
}

func passwordVisibilityIcon(mode app.PasswordInputMode) fyne.Resource {
	if mode == app.PasswordModeVisible {
		return theme.VisibilityOffIcon()
	}
	return theme.VisibilityIcon()
}

// buildPasswordSection creates the password input section.
func (a *App) buildPasswordSection() fyne.CanvasObject {
	// Password buttons row
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
		passwordChanged := a.passwordEntry.Text != text
		a.State.Password = text
		a.passwordEntry.SetText(text)
		if operationUISnapshot(a.State.UISnapshot()).Mode != "decrypt" {
			a.State.CPassword = text
			a.cPasswordEntry.SetText(text)
		}
		if !passwordChanged {
			a.updatePasswordStrength()
		}
		a.updateValidation()
		a.updateUIState()
	})

	a.createBtn = newToolbarButton(tr("action.create", "Create"), theme.DocumentCreateIcon(), func() {
		a.showPassgenModal()
	})

	// Password input with strength indicator
	a.passwordEntry = NewPasswordEntry()
	a.passwordEntry.OnSubmitted = a.onDesktopEntrySubmitted
	a.passwordEntry.SetPlaceHolder(tr("password.placeholder", "Password"))
	a.passwordEntry.OnChanged = func(text string) {
		a.State.Password = text
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState() // Update button states based on password
	}

	a.strengthIndicator = NewPasswordStrengthIndicator()

	// Confirm password
	a.cPasswordEntry = NewPasswordEntry()
	a.cPasswordEntry.OnSubmitted = a.onDesktopEntrySubmitted
	a.cPasswordEntry.SetPlaceHolder(tr("password.confirm_placeholder", "Confirm password"))
	a.cPasswordEntry.OnChanged = func(text string) {
		a.State.CPassword = text
		a.updateValidation()
		a.updateUIState() // Update button states based on password match
	}

	a.validIndicator = NewValidationIndicator()

	// Create bold labels for better visual hierarchy
	a.passwordLabel = widget.NewLabel(tr("password.label", "Password:"))
	a.passwordLabel.TextStyle = fyne.TextStyle{Bold: true}
	a.confirmLabel = widget.NewLabel(tr("password.confirm_label", "Confirm password:"))
	a.confirmLabel.TextStyle = fyne.TextStyle{Bold: true}
	confirmTitle := container.NewHBox(a.confirmLabel, a.validIndicator)
	a.confirmRow = container.NewVBox(confirmTitle, a.scrollFormOver(a.cPasswordEntry))
	a.linkPasswordScroll()

	// Subtle advisory shown only while encrypting with a non-ASCII password (#19).
	a.nonASCIIHint = widget.NewLabel(tr("password.non_ascii_hint",
		"Non-ASCII password: it is normalized so the volume decrypts on any "+
			"platform, but make sure you can type the same characters on every "+
			"device where you'll decrypt it."))
	a.nonASCIIHint.Importance = widget.LowImportance
	a.nonASCIIHint.Wrapping = fyne.TextWrapWord
	a.nonASCIIHint.Hide()

	a.passwordContainer = container.NewVBox()
	a.rebuildPasswordHeader()
	return a.passwordContainer
}

func (a *App) adaptivePasswordHeader() fyne.CanvasObject {
	passwordTitle := container.NewHBox(a.passwordLabel, a.strengthIndicator)
	buttonRow := container.NewGridWithColumns(5,
		a.showHideBtn, a.clearPwdBtn, a.copyBtn, a.pasteBtn, a.createBtn,
	)
	passwordHeader := container.NewBorder(nil, nil, passwordTitle, buttonRow, nil)
	if passwordHeader.MinSize().Width > desktopContentWidth() {
		return container.NewVBox(passwordTitle, buttonRow)
	}
	return passwordHeader
}

func (a *App) rebuildPasswordHeader() {
	if a.passwordContainer == nil {
		return
	}
	a.passwordContainer.RemoveAll()
	a.passwordContainer.Add(a.adaptivePasswordHeader())
	a.passwordContainer.Add(a.scrollFormOver(a.passwordEntry))
	a.passwordContainer.Add(a.nonASCIIHint)
	a.passwordContainer.Add(a.confirmRow)
}

// passwordStrengthSample bounds advisory work, never the actual password.
// Clone the prefix so neither worker nor result callback retains a large paste.
func passwordStrengthSample(password string) string {
	count := 0
	for offset := range password {
		if count == 100 {
			return strings.Clone(password[:offset])
		}
		count++
	}
	return strings.Clone(password)
}

func (a *App) clearPendingPasswordStrength() {
	a.passwordStrengthMu.Lock()
	a.passwordStrengthGeneration++
	a.passwordStrengthPending = ""
	a.passwordStrengthMu.Unlock()
}

// updatePasswordStrength queues only the latest bounded sample. Even a
// 100-character input can be expensive, so the estimator never runs on Fyne.
func (a *App) updatePasswordStrength() {
	a.State.PasswordStrength = 0
	if a.strengthIndicator != nil {
		a.strengthIndicator.SetStrength(0)
		a.strengthIndicator.SetVisible(false)
		a.strengthIndicator.SetDecryptMode(operationUISnapshot(a.State.UISnapshot()).Mode == "decrypt")
	}
	a.updateNonASCIIHint()
	if operationUISnapshot(a.State.UISnapshot()).Mode == "decrypt" || a.State.Password == "" || a.workers.isStopping() {
		a.clearPendingPasswordStrength()
		return
	}
	sample := passwordStrengthSample(a.State.Password)
	a.passwordStrengthMu.Lock()
	a.passwordStrengthGeneration++
	a.passwordStrengthPending = sample
	if a.passwordStrengthRunning {
		a.passwordStrengthMu.Unlock()
		return
	}
	reservation, ok := a.workers.reserve()
	if !ok {
		a.passwordStrengthPending = ""
		a.passwordStrengthMu.Unlock()
		return
	}
	a.passwordStrengthRunning = true
	a.passwordStrengthMu.Unlock()
	reservation.launch(a.runPasswordStrengthWorker)
}

func (a *App) runPasswordStrengthWorker(ctx context.Context) {
	for {
		a.passwordStrengthMu.Lock()
		if ctx.Err() != nil || a.passwordStrengthPending == "" {
			a.passwordStrengthPending = ""
			a.passwordStrengthRunning = false
			a.passwordStrengthMu.Unlock()
			return
		}
		sample := a.passwordStrengthPending
		generation := a.passwordStrengthGeneration
		a.passwordStrengthPending = ""
		a.passwordStrengthMu.Unlock()

		score := zxcvbn.PasswordStrength(sample, nil).Score
		a.applyPasswordStrengthResult(generation, sample, score)
	}
}

func (a *App) applyPasswordStrengthResult(generation uint64, sample string, score int) {
	fyne.Do(func() {
		a.passwordStrengthMu.Lock()
		current := generation == a.passwordStrengthGeneration
		a.passwordStrengthMu.Unlock()
		if !current || a.workers.isStopping() || operationUISnapshot(a.State.UISnapshot()).Mode == "decrypt" ||
			a.State.Password == "" || passwordStrengthSample(a.State.Password) != sample {
			return
		}
		a.State.PasswordStrength = score
		if a.strengthIndicator != nil {
			a.strengthIndicator.SetStrength(score)
			a.strengthIndicator.SetDecryptMode(false)
			a.strengthIndicator.SetVisible(true)
		}
	})
}

// updateNonASCIIHint shows the non-ASCII advisory only while encrypting with a
// password that contains non-ASCII characters (#19).
func (a *App) updateNonASCIIHint() {
	if a.nonASCIIHint == nil {
		return
	}
	shouldShow := operationUISnapshot(a.State.UISnapshot()).Mode != "decrypt" && pwnorm.ContainsNonASCII([]byte(a.State.Password))
	if a.nonASCIIHint.Visible() == shouldShow {
		return
	}
	if shouldShow {
		a.nonASCIIHint.Show()
	} else {
		a.nonASCIIHint.Hide()
	}
	if a.passwordContainer != nil {
		a.passwordContainer.Refresh()
	}
}

// updateValidation updates the password validation indicator.
func (a *App) updateValidation() {
	if a.validIndicator == nil {
		return
	}
	visible := a.State.Password != "" && a.State.CPassword != "" && operationUISnapshot(a.State.UISnapshot()).Mode != "decrypt"
	valid := a.State.Password == a.State.CPassword
	a.validIndicator.SetVisible(visible)
	a.validIndicator.SetValid(valid)
}

// updatePasswordUIState updates the enabled/disabled state of password controls.
func (a *App) updatePasswordUIState(mainDisabled bool, snap app.UISnapshot) {
	snap = operationUISnapshot(snap)
	if snap.Mode == "decrypt" || snap.Password == "" {
		a.clearPendingPasswordStrength()
		a.State.PasswordStrength = 0
		if a.strengthIndicator != nil {
			a.strengthIndicator.SetStrength(0)
			a.strengthIndicator.SetVisible(false)
			a.strengthIndicator.SetDecryptMode(snap.Mode == "decrypt")
		}
	}
	// Password section - all buttons/inputs disabled when mainDisabled
	if a.passwordEntry != nil {
		if mainDisabled {
			a.passwordEntry.Disable()
		} else {
			a.passwordEntry.Enable()
		}
	}

	if a.showHideBtn != nil {
		configureToolbarButton(a.showHideBtn, passwordVisibilityLabel(snap.PasswordMode), passwordVisibilityIcon(snap.PasswordMode))
		if mainDisabled {
			a.showHideBtn.Disable()
		} else {
			a.showHideBtn.Enable()
		}
	}

	if a.clearPwdBtn != nil {
		if mainDisabled {
			a.clearPwdBtn.Disable()
		} else {
			a.clearPwdBtn.Enable()
		}
	}

	if a.copyBtn != nil {
		if mainDisabled {
			a.copyBtn.Disable()
		} else {
			a.copyBtn.Enable()
		}
	}

	if a.pasteBtn != nil {
		if mainDisabled {
			a.pasteBtn.Disable()
		} else {
			a.pasteBtn.Enable()
		}
	}

	// Create password button - disabled in decrypt mode
	if a.createBtn != nil {
		if mainDisabled || snap.Mode == "decrypt" {
			a.createBtn.Disable()
		} else {
			a.createBtn.Enable()
		}
	}

	// Confirm password - disabled when password == "" || mode == "decrypt"
	if a.cPasswordEntry != nil {
		if mainDisabled || snap.Password == "" || snap.Mode == "decrypt" {
			a.cPasswordEntry.Disable()
		} else {
			a.cPasswordEntry.Enable()
		}
	}

	// Hide confirm password section entirely in decrypt mode
	if a.confirmLabel != nil {
		if snap.Mode == "decrypt" {
			a.confirmLabel.Hide()
		} else {
			a.confirmLabel.Show()
		}
	}
	if a.confirmRow != nil {
		if snap.Mode == "decrypt" {
			a.confirmRow.Hide()
		} else {
			a.confirmRow.Show()
		}
	}

	// Re-evaluate the non-ASCII advisory when the mode changes (e.g. it must hide
	// when switching to decrypt).
	a.updateNonASCIIHint()
}
