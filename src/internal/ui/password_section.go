// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/app"
	pwnorm "Picocrypt-NG/internal/password"

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

	buttonRow := container.NewGridWithColumns(5,
		a.showHideBtn, a.clearPwdBtn, a.copyBtn, a.pasteBtn, a.createBtn,
	)

	// Password input with strength indicator
	a.passwordEntry = NewPasswordEntry()
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
	passwordTitle := container.NewHBox(a.passwordLabel, a.strengthIndicator)
	passwordHeader := container.NewBorder(nil, nil, passwordTitle, buttonRow, nil)

	a.confirmLabel = widget.NewLabel(tr("password.confirm_label", "Confirm password:"))
	a.confirmLabel.TextStyle = fyne.TextStyle{Bold: true}
	confirmTitle := container.NewHBox(a.confirmLabel, a.validIndicator)
	a.confirmRow = container.NewVBox(confirmTitle, a.cPasswordEntry)

	// Subtle advisory shown only while encrypting with a non-ASCII password (#19).
	a.nonASCIIHint = widget.NewLabel(tr("password.non_ascii_hint",
		"Non-ASCII password: it is normalized so the volume decrypts on any "+
			"platform, but make sure you can type the same characters on every "+
			"device where you'll decrypt it."))
	a.nonASCIIHint.Importance = widget.LowImportance
	a.nonASCIIHint.Wrapping = fyne.TextWrapWord
	a.nonASCIIHint.Hide()

	return container.NewVBox(
		passwordHeader,
		a.passwordEntry,
		a.nonASCIIHint,
		a.confirmRow,
	)
}

// updatePasswordStrength updates the password strength indicator.
func (a *App) updatePasswordStrength() {
	a.State.PasswordStrength = zxcvbn.PasswordStrength(a.State.Password, nil).Score
	if a.strengthIndicator != nil {
		a.strengthIndicator.SetStrength(a.State.PasswordStrength)
		a.strengthIndicator.SetVisible(a.State.Password != "")
		a.strengthIndicator.SetDecryptMode(a.State.Mode == "decrypt")
	}
	a.updateNonASCIIHint()
}

// updateNonASCIIHint shows the non-ASCII advisory only while encrypting with a
// password that contains non-ASCII characters (#19).
func (a *App) updateNonASCIIHint() {
	if a.nonASCIIHint == nil {
		return
	}
	if a.State.Mode != "decrypt" && pwnorm.ContainsNonASCII([]byte(a.State.Password)) {
		a.nonASCIIHint.Show()
	} else {
		a.nonASCIIHint.Hide()
	}
}

// updateValidation updates the password validation indicator.
func (a *App) updateValidation() {
	if a.validIndicator == nil {
		return
	}
	visible := a.State.Password != "" && a.State.CPassword != "" && a.State.Mode != "decrypt"
	valid := a.State.Password == a.State.CPassword
	a.validIndicator.SetVisible(visible)
	a.validIndicator.SetValid(valid)
}

// updatePasswordUIState updates the enabled/disabled state of password controls.
func (a *App) updatePasswordUIState(mainDisabled bool, snap app.UISnapshot) {
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
