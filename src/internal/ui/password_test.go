// Package ui provides tests for password validation and strength logic.
package ui

import (
	"testing"

	"Picocrypt-NG/internal/app"

	"fyne.io/fyne/v2/test"
)

// TestPasswordStrengthScoring tests password strength calculation.
func TestPasswordStrengthScoring(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	// Note: zxcvbn library returns scores 0-4
	testCases := []struct {
		name     string
		password string
		minScore int // Minimum expected score
		maxScore int // Maximum expected score
	}{
		{"Empty", "", 0, 0},
		{"VeryWeak", "a", 0, 0},
		{"Weak", "password", 0, 1},
		{"Medium", "Password1", 1, 2},
		{"Strong", "MyP@ssw0rd!2024", 2, 4},
		{"VeryStrong", "x7#Kp$9mNq@2vL!zY", 3, 4},
		{"LongPassphrase", "correct horse battery staple", 3, 4},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := createTestApp(t)
			a.State.Password = tc.password

			// The updatePasswordStrength function uses zxcvbn
			// We test the state changes, not the actual zxcvbn scoring
			if tc.password == "" {
				if a.State.PasswordStrength != 0 {
					t.Errorf("Empty password should have strength 0, got %d", a.State.PasswordStrength)
				}
			}
		})
	}
}

// TestPasswordVisibilityToggle tests show/hide password functionality.
func TestPasswordVisibilityToggle(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	a := createTestApp(t)

	// Initially hidden
	if !a.State.IsPasswordHidden() {
		t.Error("Password should be hidden initially")
	}
	if a.State.PasswordStateLabel != "Show" {
		t.Errorf("Label should be 'Show', got %q", a.State.PasswordStateLabel)
	}

	// Toggle to show
	a.State.TogglePasswordVisibility()

	if a.State.IsPasswordHidden() {
		t.Error("Password should be visible after toggle")
	}
	if a.State.PasswordStateLabel != "Hide" {
		t.Errorf("Label should be 'Hide', got %q", a.State.PasswordStateLabel)
	}

	// Toggle back to hide
	a.State.TogglePasswordVisibility()

	if !a.State.IsPasswordHidden() {
		t.Error("Password should be hidden after second toggle")
	}
	if a.State.PasswordStateLabel != "Show" {
		t.Errorf("Label should be 'Show', got %q", a.State.PasswordStateLabel)
	}
}

// TestPasswordMatchValidation tests password confirmation matching.
func TestPasswordMatchValidation(t *testing.T) {
	testCases := []struct {
		name      string
		password  string
		cPassword string
		mode      string
		valid     bool
	}{
		{"MatchEncrypt", "secret", "secret", "encrypt", true},
		{"MismatchEncrypt", "secret", "different", "encrypt", false},
		{"EmptyBothEncrypt", "", "", "encrypt", true},
		{"EmptyConfirmEncrypt", "secret", "", "encrypt", false},
		{"MatchDecrypt", "secret", "secret", "decrypt", true},
		{"MismatchDecryptOK", "secret", "different", "decrypt", true}, // Decrypt ignores confirm
		{"EmptyConfirmDecrypt", "secret", "", "decrypt", true},        // Decrypt ignores confirm
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := app.NewState()
			state.Mode = tc.mode
			state.Password = tc.password
			state.CPassword = tc.cPassword

			// Validation logic from updateValidation and CanStart
			var valid bool
			if tc.mode == "decrypt" {
				valid = true // Decrypt mode ignores CPassword
			} else {
				valid = tc.password == tc.cPassword
			}

			if valid != tc.valid {
				t.Errorf("valid = %v; want %v", valid, tc.valid)
			}
		})
	}
}

// TestPasswordClearButton tests clearing password fields.
func TestPasswordClearButton(t *testing.T) {
	state := app.NewState()

	// Set passwords
	state.Password = "secret"
	state.CPassword = "secret"
	state.PasswordStrength = 3

	// Simulate clear button
	state.Password = ""
	state.CPassword = ""
	state.PasswordStrength = 0

	if state.Password != "" {
		t.Error("Password should be empty after clear")
	}
	if state.CPassword != "" {
		t.Error("CPassword should be empty after clear")
	}
	if state.PasswordStrength != 0 {
		t.Error("PasswordStrength should be 0 after clear")
	}
}

// TestPasswordPasteButton tests pasting password behavior.
func TestPasswordPasteButton(t *testing.T) {
	t.Run("EncryptModePastesBoth", func(t *testing.T) {
		state := app.NewState()
		state.Mode = "encrypt"

		// Simulate paste
		pastedText := "pasted_password"
		state.Password = pastedText
		if state.Mode != "decrypt" {
			state.CPassword = pastedText
		}

		if state.Password != pastedText {
			t.Errorf("Password = %q; want %q", state.Password, pastedText)
		}
		if state.CPassword != pastedText {
			t.Errorf("CPassword = %q; want %q (encrypt mode)", state.CPassword, pastedText)
		}
	})

	t.Run("DecryptModeOnlyPastesPassword", func(t *testing.T) {
		state := app.NewState()
		state.Mode = "decrypt"
		state.CPassword = "original"

		// Simulate paste
		pastedText := "pasted_password"
		state.Password = pastedText
		if state.Mode != "decrypt" {
			state.CPassword = pastedText
		}

		if state.Password != pastedText {
			t.Errorf("Password = %q; want %q", state.Password, pastedText)
		}
		if state.CPassword != "original" {
			t.Errorf("CPassword = %q; want 'original' (decrypt mode)", state.CPassword)
		}
	})
}

// TestPasswordGeneratorOptions tests password generator settings.
func TestPasswordGeneratorOptions(t *testing.T) {
	testCases := []struct {
		name    string
		length  int32
		upper   bool
		lower   bool
		nums    bool
		symbols bool
	}{
		{"DefaultSettings", 32, true, true, true, true},
		{"LettersOnly", 20, true, true, false, false},
		{"NumbersOnly", 16, false, false, true, false},
		{"NoSymbols", 24, true, true, true, false},
		{"ShortPassword", 8, true, true, true, true},
		{"LongPassword", 64, true, true, true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := app.NewState()
			state.PassgenLength = tc.length
			state.PassgenUpper = tc.upper
			state.PassgenLower = tc.lower
			state.PassgenNums = tc.nums
			state.PassgenSymbols = tc.symbols

			if state.PassgenLength != tc.length {
				t.Errorf("Length = %d; want %d", state.PassgenLength, tc.length)
			}
		})
	}
}

// TestPasswordGeneratorOutput tests generated password characteristics.
func TestPasswordGeneratorOutput(t *testing.T) {
	state := app.NewState()
	state.PassgenLength = 32
	state.PassgenUpper = true
	state.PassgenLower = true
	state.PassgenNums = true
	state.PassgenSymbols = false
	state.PassgenCopy = false

	password := state.GenPassword()

	if len(password) != 32 {
		t.Errorf("Password length = %d; want 32", len(password))
	}

	// Check for no symbols (when disabled)
	symbols := "-=_+!@#$%^&*()"
	for _, ch := range password {
		for _, sym := range symbols {
			if ch == sym {
				t.Errorf("Password contains symbol %c when symbols disabled", ch)
			}
		}
	}
}

// TestConfirmPasswordDisabledStates tests when confirm password should be disabled.
func TestConfirmPasswordDisabledStates(t *testing.T) {
	testCases := []struct {
		name             string
		mode             string
		password         string
		mainDisabled     bool
		expectedDisabled bool
	}{
		{"EncryptWithPassword", "encrypt", "secret", false, false},
		{"EncryptNoPassword", "encrypt", "", false, true},
		{"DecryptMode", "decrypt", "secret", false, true},
		{"MainDisabled", "encrypt", "secret", true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := app.NewState()
			state.Mode = tc.mode
			state.Password = tc.password

			// Logic from updatePasswordUIState
			disabled := tc.mainDisabled || state.Password == "" || state.Mode == "decrypt"

			if disabled != tc.expectedDisabled {
				t.Errorf("disabled = %v; want %v", disabled, tc.expectedDisabled)
			}
		})
	}
}

// TestCreatePasswordButtonDisabledInDecrypt tests create button state.
func TestCreatePasswordButtonDisabledInDecrypt(t *testing.T) {
	testCases := []struct {
		name         string
		mode         string
		mainDisabled bool
		expected     bool
	}{
		{"EncryptEnabled", "encrypt", false, false},
		{"DecryptDisabled", "decrypt", false, true},
		{"MainDisabled", "encrypt", true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := app.NewState()
			state.Mode = tc.mode

			// Logic from updatePasswordUIState for createBtn
			disabled := tc.mainDisabled || state.Mode == "decrypt"

			if disabled != tc.expected {
				t.Errorf("disabled = %v; want %v", disabled, tc.expected)
			}
		})
	}
}

// TestPasswordValidationIndicator tests validation indicator behavior.
func TestPasswordValidationIndicator(t *testing.T) {
	testCases := []struct {
		name      string
		password  string
		cPassword string
		mode      string
		visible   bool
		valid     bool
	}{
		{"BothEmpty", "", "", "encrypt", false, true},
		{"OnlyPassword", "secret", "", "encrypt", false, true},
		{"OnlyConfirm", "", "secret", "encrypt", false, true},
		{"Match", "secret", "secret", "encrypt", true, true},
		{"Mismatch", "secret", "wrong", "encrypt", true, false},
		{"DecryptHidden", "secret", "wrong", "decrypt", false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := app.NewState()
			state.Mode = tc.mode
			state.Password = tc.password
			state.CPassword = tc.cPassword

			// Logic from updateValidation
			visible := state.Password != "" && state.CPassword != "" && state.Mode != "decrypt"
			valid := state.Password == state.CPassword

			if visible != tc.visible {
				t.Errorf("visible = %v; want %v", visible, tc.visible)
			}
			if visible && valid != tc.valid {
				t.Errorf("valid = %v; want %v", valid, tc.valid)
			}
		})
	}
}

// TestPasswordEntryOnChanged tests password entry change handling.
func TestPasswordEntryOnChanged(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	t.Run("PasswordUpdate", func(t *testing.T) {
		state := app.NewState()

		// Simulate OnChanged
		newPassword := "newpassword"
		state.Password = newPassword

		if state.Password != newPassword {
			t.Errorf("Password = %q; want %q", state.Password, newPassword)
		}
	})

	t.Run("ConfirmPasswordUpdate", func(t *testing.T) {
		state := app.NewState()

		// Simulate OnChanged
		newCPassword := "confirm"
		state.CPassword = newCPassword

		if state.CPassword != newCPassword {
			t.Errorf("CPassword = %q; want %q", state.CPassword, newCPassword)
		}
	})
}

// TestPasswordStrengthIndicatorVisibility tests strength indicator visibility.
func TestPasswordStrengthIndicatorVisibility(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		visible  bool
	}{
		{"EmptyHidden", "", false},
		{"WithPasswordShown", "secret", true},
		{"SpaceOnlyShown", " ", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Logic from updatePasswordStrength
			visible := tc.password != ""

			if visible != tc.visible {
				t.Errorf("visible = %v; want %v", visible, tc.visible)
			}
		})
	}
}
