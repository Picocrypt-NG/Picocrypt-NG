// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"github.com/Picocrypt/zxcvbn-go"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// buildPasswordSection creates the password input section.
func (a *App) buildPasswordSection() fyne.CanvasObject {
	// Password buttons row
	a.showHideBtn = widget.NewButton(a.State.PasswordStateLabel, func() {
		a.State.TogglePasswordVisibility()
		a.showHideBtn.SetText(a.State.PasswordStateLabel)
		a.passwordEntry.SetHidden(a.State.IsPasswordHidden())
		a.cPasswordEntry.SetHidden(a.State.IsPasswordHidden())
	})

	a.clearPwdBtn = widget.NewButton("Clear", func() {
		a.State.Password = ""
		a.State.CPassword = ""
		a.passwordEntry.SetText("")
		a.cPasswordEntry.SetText("")
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState()
	})

	a.copyBtn = widget.NewButton("Copy", func() {
		a.fyneApp.Clipboard().SetContent(a.State.Password)
	})

	a.pasteBtn = widget.NewButton("Paste", func() {
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

	a.createBtn = widget.NewButton("Create", func() {
		a.showPassgenModal()
	})

	// Use adaptive grid that fills available space evenly
	buttonRow := container.NewGridWithColumns(5,
		a.showHideBtn, a.clearPwdBtn, a.copyBtn, a.pasteBtn, a.createBtn,
	)

	// Password input with strength indicator
	a.passwordEntry = NewPasswordEntry()
	a.passwordEntry.SetPlaceHolder("Password")
	a.passwordEntry.OnChanged = func(text string) {
		a.State.Password = text
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState() // Update button states based on password
	}

	a.strengthIndicator = NewPasswordStrengthIndicator()

	passwordRow := container.NewBorder(nil, nil, nil, a.strengthIndicator, a.passwordEntry)

	// Confirm password
	a.cPasswordEntry = NewPasswordEntry()
	a.cPasswordEntry.SetPlaceHolder("Confirm password")
	a.cPasswordEntry.OnChanged = func(text string) {
		a.State.CPassword = text
		a.updateValidation()
		a.updateUIState() // Update button states based on password match
	}

	a.validIndicator = NewValidationIndicator()

	a.confirmRow = container.NewBorder(nil, nil, nil, a.validIndicator, a.cPasswordEntry)

	// Create bold labels for better visual hierarchy
	passwordLabel := widget.NewLabel("Password:")
	passwordLabel.TextStyle = fyne.TextStyle{Bold: true}

	a.confirmLabel = widget.NewLabel("Confirm password:")
	a.confirmLabel.TextStyle = fyne.TextStyle{Bold: true}

	return container.NewVBox(
		passwordLabel,
		buttonRow,
		passwordRow,
		a.confirmLabel,
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
func (a *App) updatePasswordUIState(mainDisabled bool) {
	// Password section - all buttons/inputs disabled when mainDisabled
	if a.passwordEntry != nil {
		if mainDisabled {
			a.passwordEntry.Disable()
		} else {
			a.passwordEntry.Enable()
		}
	}

	if a.showHideBtn != nil {
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
		if mainDisabled || a.State.Mode == "decrypt" {
			a.createBtn.Disable()
		} else {
			a.createBtn.Enable()
		}
	}

	// Confirm password - disabled when password == "" || mode == "decrypt"
	if a.cPasswordEntry != nil {
		if mainDisabled || a.State.Password == "" || a.State.Mode == "decrypt" {
			a.cPasswordEntry.Disable()
		} else {
			a.cPasswordEntry.Enable()
		}
	}

	// Hide confirm password section entirely in decrypt mode
	if a.confirmLabel != nil {
		if a.State.Mode == "decrypt" {
			a.confirmLabel.Hide()
		} else {
			a.confirmLabel.Show()
		}
	}
	if a.confirmRow != nil {
		if a.State.Mode == "decrypt" {
			a.confirmRow.Hide()
		} else {
			a.confirmRow.Show()
		}
	}
}
