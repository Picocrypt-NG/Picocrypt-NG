// Package ui provides tests for password validation and strength logic.
package ui

import (
	"testing"

	"fyne.io/fyne/v2"

	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

// TestPasswordStrengthScoring drives the real updatePasswordStrength and asserts
// it writes the zxcvbn score into State.PasswordStrength and the strength widget.
// It pins the contract that the score is monotonic in real password strength
// (a known-weak password must not score above a known-strong one) rather than
// recomputing zxcvbn inline, so it fails if updatePasswordStrength stops calling
// zxcvbn or stores the wrong value.
// TestNonASCIIPasswordHint verifies the #19 advisory is shown only while
// encrypting with a non-ASCII password, and hidden for ASCII passwords or in
// decrypt mode. It drives the real updateNonASCIIHint against the built widget.
func TestNonASCIIPasswordHint(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	// Built from a code point so the literal cannot be silently re-normalized.
	nonASCII := "caf" + string([]rune{0x00E9})

	fyne.DoAndWait(func() {
		if a.nonASCIIHint == nil {
			t.Fatal("nonASCIIHint widget was not built")
		}

		a.State.Mode = "encrypt"
		a.State.Password = nonASCII
		a.updateNonASCIIHint()
		if !a.nonASCIIHint.Visible() {
			t.Error("hint should be visible for a non-ASCII password in encrypt mode")
		}

		a.State.Password = "plain-ascii"
		a.updateNonASCIIHint()
		if a.nonASCIIHint.Visible() {
			t.Error("hint should be hidden for an ASCII password")
		}

		a.State.Mode = "decrypt"
		a.State.Password = nonASCII
		a.updateNonASCIIHint()
		if a.nonASCIIHint.Visible() {
			t.Error("hint should be hidden in decrypt mode")
		}
	})
}

func TestPasswordStrengthScoring(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	score := func(password string) int {
		a := createUIReadyDropTestApp(t, fyneApp)
		var s int
		fyne.DoAndWait(func() {
			a.State.Password = password
			a.updatePasswordStrength()
			s = a.State.PasswordStrength
			// The widget must mirror the stored score.
			if a.strengthIndicator.strength != s {
				t.Fatalf("strengthIndicator.strength = %d; want %d", a.strengthIndicator.strength, s)
			}
		})
		return s
	}

	if got := score(""); got != 0 {
		t.Errorf("empty password strength = %d; want 0", got)
	}

	weak := score("a")
	strong := score("x7#Kp$9mNq@2vL!zY")
	if weak >= strong {
		t.Errorf("weak score (%d) should be < strong score (%d)", weak, strong)
	}
	if weak < 0 || strong > 4 {
		t.Errorf("scores out of zxcvbn range: weak=%d strong=%d", weak, strong)
	}
}

// TestPasswordVisibilityToggle drives the real show/hide button built in
// buildPasswordSection. Desktop renders the control as an icon button with a
// localized tooltip, and tapping flips both that tooltip and the masking on
// BOTH entries. It fails if the toggle stops re-labelling the action or stops
// un/re-masking the entries.
func TestPasswordVisibilityToggle(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		wantShow := tr("password.show", "Show")
		wantHide := tr("password.hide", "Hide")

		// Initially hidden: action tooltip says "Show", both entries masked.
		if !a.State.IsPasswordHidden() {
			t.Error("Password should be hidden initially")
		}
		if a.showHideBtn.ToolTip() != wantShow {
			t.Errorf("button tooltip should be %q, got %q", wantShow, a.showHideBtn.ToolTip())
		}
		if !a.passwordEntry.IsHidden() || !a.cPasswordEntry.IsHidden() {
			t.Error("both entries should be masked initially")
		}

		// Tap to reveal: action tooltip says "Hide", entries unmasked.
		a.showHideBtn.OnTapped()
		if a.State.IsPasswordHidden() {
			t.Error("Password should be visible after toggle")
		}
		if a.showHideBtn.ToolTip() != wantHide {
			t.Errorf("button tooltip should be %q after toggle, got %q", wantHide, a.showHideBtn.ToolTip())
		}
		if a.passwordEntry.IsHidden() || a.cPasswordEntry.IsHidden() {
			t.Error("both entries should be unmasked while shown")
		}

		// Tap again to hide: action tooltip returns to "Show", entries re-masked.
		a.showHideBtn.OnTapped()
		if !a.State.IsPasswordHidden() {
			t.Error("Password should be hidden after second toggle")
		}
		if a.showHideBtn.ToolTip() != wantShow {
			t.Errorf("button tooltip should be %q after second toggle, got %q", wantShow, a.showHideBtn.ToolTip())
		}
		if !a.passwordEntry.IsHidden() || !a.cPasswordEntry.IsHidden() {
			t.Error("both entries should be re-masked after hiding")
		}
	})
}

func TestPasswordToolbarUsesLocalizedTooltips(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		if a.showHideBtn.ToolTip() != tr("password.show", "Show") {
			t.Fatalf("show/hide tooltip = %q; want localized Show label", a.showHideBtn.ToolTip())
		}
		if a.clearPwdBtn.ToolTip() != tr("action.clear", "Clear") {
			t.Fatalf("clear tooltip = %q; want localized Clear label", a.clearPwdBtn.ToolTip())
		}
		if a.copyBtn.ToolTip() != tr("action.copy", "Copy") {
			t.Fatalf("copy tooltip = %q; want localized Copy label", a.copyBtn.ToolTip())
		}
		if a.pasteBtn.ToolTip() != tr("action.paste", "Paste") {
			t.Fatalf("paste tooltip = %q; want localized Paste label", a.pasteBtn.ToolTip())
		}
		if a.createBtn.ToolTip() != tr("action.create", "Create") {
			t.Fatalf("create tooltip = %q; want localized Create label", a.createBtn.ToolTip())
		}
	})
}

func TestPasswordToolbarRelocalizesAfterSwitchLanguage(t *testing.T) {
	resetLocalizationForTest(t)

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		if err := a.SwitchLanguage("ru"); err != nil {
			t.Fatalf("SwitchLanguage(ru) returned error: %v", err)
		}
	})

	if got := a.showHideBtn.ToolTip(); got != tr("password.show", "Show") {
		t.Fatalf("show/hide tooltip after language switch = %q; want localized string", got)
	}
	if got := a.clearPwdBtn.ToolTip(); got != tr("action.clear", "Clear") {
		t.Fatalf("clear tooltip after language switch = %q; want localized string", got)
	}
	if got := a.copyBtn.ToolTip(); got != tr("action.copy", "Copy") {
		t.Fatalf("copy tooltip after language switch = %q; want localized string", got)
	}
	if got := a.pasteBtn.ToolTip(); got != tr("action.paste", "Paste") {
		t.Fatalf("paste tooltip after language switch = %q; want localized string", got)
	}
	if got := a.createBtn.ToolTip(); got != tr("action.create", "Create") {
		t.Fatalf("create tooltip after language switch = %q; want localized string", got)
	}
}

func TestPasswordToolbarDoesNotIncreaseDesktopWidth(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	fyneApp := newTestFyneApp(t)
	a := newDesktopEncryptLayoutApp(t, fyneApp)

	var min, size fyne.Size
	fyne.DoAndWait(func() {
		min = a.Window.Content().MinSize()
		size = a.Window.Canvas().Size()
	})

	if min.Width > windowWidth {
		t.Fatalf("desktop password toolbar layout MinSize width %.1f exceeds compact window width %.1f", min.Width, float32(windowWidth))
	}
	if size.Width > windowWidth {
		t.Fatalf("desktop password toolbar layout window width %.1f exceeds compact window width %.1f", size.Width, float32(windowWidth))
	}
}

func TestPasswordVisibilityToggleStillUpdatesBothFields(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.showHideBtn.OnTapped()
		if a.passwordEntry.IsHidden() || a.cPasswordEntry.IsHidden() {
			t.Fatal("both password fields should become visible together")
		}
		a.showHideBtn.OnTapped()
		if !a.passwordEntry.IsHidden() || !a.cPasswordEntry.IsHidden() {
			t.Fatal("both password fields should become hidden together")
		}
	})
}

func TestDesktopPasswordActionsSharePasswordHeaderRow(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	var section fyne.CanvasObject
	fyne.DoAndWait(func() {
		section = a.buildPasswordSection()
	})

	vbox, ok := section.(*fyne.Container)
	if !ok {
		t.Fatalf("password section type = %T; want *fyne.Container", section)
	}
	if len(vbox.Objects) < 1 {
		t.Fatal("password section has no children")
	}

	headerRow, ok := vbox.Objects[0].(*fyne.Container)
	if !ok {
		t.Fatalf("password header row type = %T; want *fyne.Container", vbox.Objects[0])
	}
	if !canvasTreeContainsObject(headerRow, a.passwordLabel) {
		t.Fatal("password header row does not contain password label")
	}
	for _, btn := range []*ttwidget.Button{a.showHideBtn, a.clearPwdBtn, a.copyBtn, a.pasteBtn, a.createBtn} {
		if !canvasTreeContainsObject(headerRow, btn) {
			t.Fatalf("password header row does not contain toolbar button %p", btn)
		}
	}
}

// TestPasswordPasteButton drives the real paste-button OnTapped handler built in
// buildPasswordSection: it reads the clipboard into State.Password, and in encrypt
// mode also mirrors it into State.CPassword, but in decrypt mode must leave
// CPassword untouched. The test sets only the clipboard and reads back State, so
// it fails if the paste handler's mode branching changes.
func TestPasswordPasteButton(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	t.Run("EncryptModePastesBoth", func(t *testing.T) {
		a := createUIReadyDropTestApp(t, fyneApp)
		var password, cpassword string
		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.fyneApp.Clipboard().SetContent("pasted_password")
			a.pasteBtn.OnTapped()
			password = a.State.Password
			cpassword = a.State.CPassword
		})
		if password != "pasted_password" {
			t.Errorf("Password = %q; want %q", password, "pasted_password")
		}
		if cpassword != "pasted_password" {
			t.Errorf("CPassword = %q; want %q (encrypt mirrors password)", cpassword, "pasted_password")
		}
	})

	t.Run("DecryptModeOnlyPastesPassword", func(t *testing.T) {
		a := createUIReadyDropTestApp(t, fyneApp)
		var password, cpassword string
		fyne.DoAndWait(func() {
			a.State.Mode = "decrypt"
			a.State.CPassword = "original"
			a.fyneApp.Clipboard().SetContent("pasted_password")
			a.pasteBtn.OnTapped()
			password = a.State.Password
			cpassword = a.State.CPassword
		})
		if password != "pasted_password" {
			t.Errorf("Password = %q; want %q", password, "pasted_password")
		}
		if cpassword != "original" {
			t.Errorf("CPassword = %q; want 'original' (decrypt must not mirror)", cpassword)
		}
	})
}

// TestPasswordGeneratorOutput tests generated password characteristics.
func TestPasswordGeneratorOutput(t *testing.T) {
	state := mustNewState(t)
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

// hasFilesForUI puts the app into a "files dropped, not scanning" state so the
// real updateUIState computes mainDisabled=false and the password controls follow
// their mode/password branches rather than being globally disabled.
func hasFilesForUI(a *App) {
	a.State.AllFiles = []string{"in.txt"}
	a.State.OnlyFiles = []string{"in.txt"}
	a.State.SetScanning(false)
}

// TestConfirmPasswordDisabledStates drives the real updateUIState ->
// updatePasswordUIState and asserts the actual cPasswordEntry widget's
// Disabled() state. Confirm-password is disabled when no files (mainDisabled),
// when the password is empty, or in decrypt mode. The test sets only inputs and
// reads the widget, so it fails if that branching changes.
func TestConfirmPasswordDisabledStates(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	testCases := []struct {
		name             string
		mode             string
		password         string
		hasFiles         bool
		expectedDisabled bool
	}{
		{"EncryptWithPassword", "encrypt", "secret", true, false},
		{"EncryptNoPassword", "encrypt", "", true, true},
		{"DecryptMode", "decrypt", "secret", true, true},
		{"MainDisabled", "encrypt", "secret", false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := createUIReadyDropTestApp(t, fyneApp)
			var disabled bool
			fyne.DoAndWait(func() {
				a.State.Mode = tc.mode
				a.State.Password = tc.password
				a.State.CPassword = tc.password
				if tc.hasFiles {
					hasFilesForUI(a)
				}
				a.updateUIState()
				disabled = a.cPasswordEntry.Disabled()
			})
			if disabled != tc.expectedDisabled {
				t.Errorf("cPasswordEntry.Disabled() = %v; want %v", disabled, tc.expectedDisabled)
			}
		})
	}
}

// TestCreatePasswordButtonDisabledInDecrypt drives the real updateUIState ->
// updatePasswordUIState and asserts the actual createBtn widget's Disabled()
// state: the Create (passgen) button is disabled in decrypt mode and whenever the
// main section is disabled (no files). Asserts the widget, not a recomputed bool.
func TestCreatePasswordButtonDisabledInDecrypt(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	testCases := []struct {
		name     string
		mode     string
		hasFiles bool
		expected bool
	}{
		{"EncryptEnabled", "encrypt", true, false},
		{"DecryptDisabled", "decrypt", true, true},
		{"MainDisabled", "encrypt", false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := createUIReadyDropTestApp(t, fyneApp)
			var disabled bool
			fyne.DoAndWait(func() {
				a.State.Mode = tc.mode
				a.State.Password = "secret"
				a.State.CPassword = "secret"
				if tc.hasFiles {
					hasFilesForUI(a)
				}
				a.updateUIState()
				disabled = a.createBtn.Disabled()
			})
			if disabled != tc.expected {
				t.Errorf("createBtn.Disabled() = %v; want %v", disabled, tc.expected)
			}
		})
	}
}

// TestPasswordValidationIndicator drives the real updateValidation and asserts
// the actual validIndicator widget's visible/valid fields: the match indicator is
// shown only when both password and confirm are non-empty and not in decrypt
// mode, and is green only when they match. Asserts the widget, not a recompute.
func TestPasswordValidationIndicator(t *testing.T) {
	fyneApp := newTestFyneApp(t)

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
			a := createUIReadyDropTestApp(t, fyneApp)
			var visible, valid bool
			fyne.DoAndWait(func() {
				a.State.Mode = tc.mode
				a.State.Password = tc.password
				a.State.CPassword = tc.cPassword
				a.updateValidation()
				visible = a.validIndicator.visible
				valid = a.validIndicator.valid
			})
			if visible != tc.visible {
				t.Errorf("validIndicator.visible = %v; want %v", visible, tc.visible)
			}
			if visible && valid != tc.valid {
				t.Errorf("validIndicator.valid = %v; want %v", valid, tc.valid)
			}
		})
	}
}

// TestPasswordEntryOnChanged drives the real OnChanged handlers wired in
// buildPasswordSection: typing into passwordEntry must update State.Password and
// recompute strength; typing into cPasswordEntry must update State.CPassword. The
// test drives the widget and reads State, so it fails if the wiring is removed.
func TestPasswordEntryOnChanged(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	t.Run("PasswordUpdate", func(t *testing.T) {
		a := createUIReadyDropTestApp(t, fyneApp)
		var password string
		var strength int
		fyne.DoAndWait(func() {
			a.passwordEntry.SetText("newpassword")
			password = a.State.Password
			strength = a.State.PasswordStrength
		})
		if password != "newpassword" {
			t.Errorf("State.Password = %q; want %q", password, "newpassword")
		}
		// OnChanged routes through updatePasswordStrength, so a non-empty
		// password must yield a non-negative score and mark the widget visible.
		if strength < 0 {
			t.Errorf("State.PasswordStrength = %d; want >= 0 after OnChanged", strength)
		}
		if !a.strengthIndicator.visible {
			t.Error("strengthIndicator should be visible for a non-empty password")
		}
	})

	t.Run("ConfirmPasswordUpdate", func(t *testing.T) {
		a := createUIReadyDropTestApp(t, fyneApp)
		var cpassword string
		fyne.DoAndWait(func() {
			a.cPasswordEntry.SetText("confirm")
			cpassword = a.State.CPassword
		})
		if cpassword != "confirm" {
			t.Errorf("State.CPassword = %q; want %q", cpassword, "confirm")
		}
	})
}

// TestPasswordStrengthIndicatorVisibility drives the real updatePasswordStrength
// and asserts the actual strengthIndicator widget's visible field: the meter is
// shown only for a non-empty password. Asserts the widget, not a recomputed bool.
func TestPasswordStrengthIndicatorVisibility(t *testing.T) {
	fyneApp := newTestFyneApp(t)

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
			a := createUIReadyDropTestApp(t, fyneApp)
			var visible bool
			fyne.DoAndWait(func() {
				a.State.Password = tc.password
				a.updatePasswordStrength()
				visible = a.strengthIndicator.visible
			})
			if visible != tc.visible {
				t.Errorf("strengthIndicator.visible = %v; want %v", visible, tc.visible)
			}
		})
	}
}
