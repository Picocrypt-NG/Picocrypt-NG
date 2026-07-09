package ui

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

// assertCheckboxWiring verifies a build...Options checkbox is present, labeled
// (non-empty), and that its OnChanged closure drives the mapped State field in
// both directions. The bidirectional OnChanged(true/false)→State assertion is the
// load-bearing part: it catches a checkbox wired to the wrong State field or with
// an inverted bool. OnChanged is invoked directly (not SetChecked, which no-ops
// when the value is unchanged) so the production callback runs unconditionally.
// The label is only checked for non-emptiness (an unlabeled control is a bug);
// wantLabel is retained solely to identify the control in failure messages.
func assertCheckboxWiring(t *testing.T, c *ttwidget.Check, wantLabel string, getField func() bool) {
	t.Helper()
	if c == nil {
		t.Fatalf("checkbox %q is nil", wantLabel)
	}
	if c.Text == "" {
		t.Fatalf("checkbox %q has an empty label", wantLabel)
	}
	if c.OnChanged == nil {
		t.Fatalf("checkbox %q has nil OnChanged", wantLabel)
	}
	c.OnChanged(true)
	if !getField() {
		t.Fatalf("checkbox %q OnChanged(true) did not flip its State field to true", wantLabel)
	}
	c.OnChanged(false)
	if getField() {
		t.Fatalf("checkbox %q OnChanged(false) did not flip its State field to false", wantLabel)
	}
}

func TestBuildEncryptOptionsWireCheckboxesToState(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	fyne.DoAndWait(func() {
		a.buildEncryptOptions()

		assertCheckboxWiring(t, a.paranoidCheck, "Paranoid mode", func() bool { return a.State.Paranoid })
		assertCheckboxWiring(t, a.compressCheck, "Compress files", func() bool { return a.State.Compress })
		assertCheckboxWiring(t, a.reedSolomonCheck, "Reed-Solomon", func() bool { return a.State.ReedSolomon })
		assertCheckboxWiring(t, a.deleteCheck, "Delete files", func() bool { return a.State.Delete })
		assertCheckboxWiring(t, a.deniabilityCheck, "Deniability", func() bool { return a.State.Deniability })
		assertCheckboxWiring(t, a.recursivelyCheck, "Recursively", func() bool { return a.State.Recursively })
		assertCheckboxWiring(t, a.splitCheck, "Split:", func() bool { return a.State.Split })
	})
}

func TestBuildDecryptOptionsWireCheckboxesToState(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()
	a.State.InputFile = "volume.zip.pcv"
	a.State.AutoUnzip = true

	fyne.DoAndWait(func() {
		a.buildDecryptOptions()

		assertCheckboxWiring(t, a.forceDecryptCheck, "Force decrypt", func() bool { return a.State.Keep })
		assertCheckboxWiring(t, a.verifyFirstCheck, "Verify first", func() bool { return a.State.VerifyFirst })
		assertCheckboxWiring(t, a.deleteVolumeCheck, "Delete volume", func() bool { return a.State.Delete })
		assertCheckboxWiring(t, a.sameLevelCheck, "Same level", func() bool { return a.State.SameLevel })

		// autoUnzip's OnChanged(false) also clears SameLevel, so assert it directly.
		wantAutoUnzip := tr("advanced.auto_unzip.label", "Auto unzip")
		if a.autoUnzipCheck == nil || a.autoUnzipCheck.Text != wantAutoUnzip {
			t.Fatalf("autoUnzipCheck missing or mislabeled: %+v", a.autoUnzipCheck)
		}
		a.autoUnzipCheck.OnChanged(true)
		if !a.State.AutoUnzip {
			t.Fatal("Auto unzip OnChanged(true) did not set State.AutoUnzip")
		}
		a.autoUnzipCheck.OnChanged(false)
		if a.State.AutoUnzip {
			t.Fatal("Auto unzip OnChanged(false) did not clear State.AutoUnzip")
		}
	})
}

func TestBuildDecryptOptionsDisableGuards(t *testing.T) {
	newTestFyneApp(t)

	testCases := []struct {
		name             string
		inputFile        string
		autoUnzip        bool
		deniability      bool
		wantAutoUnzipOff bool
		wantSameLevelOff bool
		wantForceOff     bool
	}{
		{"ZipEnablesUnzip", "volume.zip.pcv", true, false, false, false, false},
		{"NonZipDisablesUnzip", "volume.pcv", true, false, true, true, false},
		{"ZipNoAutoUnzipDisablesSameLevel", "volume.zip.pcv", false, false, false, true, false},
		{"DeniabilityDisablesForceDecrypt", "volume.zip.pcv", true, true, false, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := createTestApp(t)
			a.advancedContainer = container.NewVBox()
			a.State.InputFile = tc.inputFile
			a.State.AutoUnzip = tc.autoUnzip
			a.State.Deniability = tc.deniability

			fyne.DoAndWait(func() {
				a.buildDecryptOptions()
			})

			if got := a.autoUnzipCheck.Disabled(); got != tc.wantAutoUnzipOff {
				t.Errorf("autoUnzipCheck.Disabled() = %v, want %v", got, tc.wantAutoUnzipOff)
			}
			if got := a.sameLevelCheck.Disabled(); got != tc.wantSameLevelOff {
				t.Errorf("sameLevelCheck.Disabled() = %v, want %v", got, tc.wantSameLevelOff)
			}
			if got := a.forceDecryptCheck.Disabled(); got != tc.wantForceOff {
				t.Errorf("forceDecryptCheck.Disabled() = %v, want %v", got, tc.wantForceOff)
			}
		})
	}
}

func TestBuildMobileEncryptOptionsWireCheckboxesToState(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	fyne.DoAndWait(func() {
		a.buildMobileEncryptOptions()

		assertCheckboxWiring(t, a.paranoidCheck, "Paranoid mode", func() bool { return a.State.Paranoid })
		assertCheckboxWiring(t, a.compressCheck, "Compress files", func() bool { return a.State.Compress })
		assertCheckboxWiring(t, a.reedSolomonCheck, "Reed-Solomon", func() bool { return a.State.ReedSolomon })
		assertCheckboxWiring(t, a.deleteCheck, "Delete files", func() bool { return a.State.Delete })
		assertCheckboxWiring(t, a.deniabilityCheck, "Deniability", func() bool { return a.State.Deniability })
		assertCheckboxWiring(t, a.recursivelyCheck, "Recursively", func() bool { return a.State.Recursively })
		assertCheckboxWiring(t, a.splitCheck, "Split:", func() bool { return a.State.Split })
	})
}

func TestBuildMobileDecryptOptionsWireCheckboxesToState(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	fyne.DoAndWait(func() {
		a.buildMobileDecryptOptions()

		assertCheckboxWiring(t, a.forceDecryptCheck, "Force decrypt", func() bool { return a.State.Keep })
		assertCheckboxWiring(t, a.verifyFirstCheck, "Verify first", func() bool { return a.State.VerifyFirst })
		assertCheckboxWiring(t, a.deleteCheck, "Delete encrypted", func() bool { return a.State.Delete })
	})
}

// TestEncryptAdvancedOptionsNeverSoftLock guards against issue #56, where certain
// advanced-option combinations left the encrypt checkboxes permanently disabled,
// forcing the user to restart the app to recover. The fix makes every disabled
// state a pure function of the current UISnapshot (updateEncryptOptionsState) with
// no latched flags and no mutual exclusion, so any selection is always reversible.
// These cases assert that the two combinations reported in #56 keep every option
// interactive: the user can always toggle back out without restarting.
func TestEncryptAdvancedOptionsNeverSoftLock(t *testing.T) {
	newTestFyneApp(t)

	// newEncryptAppWithCredentials builds an encrypt-mode app whose credentials make
	// advancedDisabled==false (password set and matching) and whose >1 file count
	// keeps "Recursively" ungated, so any disabled checkbox can only come from
	// option interplay — which is exactly what #56 was about.
	newEncryptAppWithCredentials := func(t *testing.T) *App {
		t.Helper()
		a := createTestApp(t)
		a.advancedContainer = container.NewVBox()
		a.State.Mode = "encrypt"
		a.State.Password = "correct horse"
		a.State.CPassword = "correct horse"
		a.State.AllFiles = []string{"a.txt", "b.txt"}
		fyne.DoAndWait(func() { a.buildEncryptOptions() })
		return a
	}

	// recompute runs the production disable-state recomputation from the current
	// State snapshot, exactly as the app does after every UI change.
	recompute := func(a *App) {
		fyne.DoAndWait(func() { a.updateAdvancedDisableState() })
	}

	// Reported combo (b): Compress + Recursively. Enabling Recursively disables
	// Compress (intended), but disabling Recursively again must restore it.
	t.Run("CompressRecoversAfterUncheckingRecursively", func(t *testing.T) {
		a := newEncryptAppWithCredentials(t)

		recompute(a)
		if a.compressCheck.Disabled() {
			t.Fatal("precondition: Compress should be enabled before Recursively is checked")
		}

		// User checks Recursively (its OnChanged also clears Compress).
		a.State.Recursively = true
		a.State.Compress = false
		recompute(a)
		if !a.compressCheck.Disabled() {
			t.Fatal("Compress should be disabled while Recursively is checked")
		}
		if a.recursivelyCheck.Disabled() {
			t.Fatal("Recursively must stay enabled so the user can undo it")
		}

		// User unchecks Recursively: Compress MUST become usable again. A latched
		// disable (the #56 soft-lock) would leave it stuck disabled here.
		a.State.Recursively = false
		recompute(a)
		if a.compressCheck.Disabled() {
			t.Fatal("#56 regression: Compress stayed disabled after Recursively was unchecked (soft-lock)")
		}
	})

	// Reported combo (a): Paranoid + Reed-Solomon + Deniability. None of these
	// mutually exclude, so selecting all three must not disable any option.
	t.Run("ParanoidReedSolomonDeniabilityLockNothing", func(t *testing.T) {
		a := newEncryptAppWithCredentials(t)

		a.State.Paranoid = true
		a.State.ReedSolomon = true
		a.State.Deniability = true
		recompute(a)

		for _, c := range []struct {
			name string
			box  *ttwidget.Check
		}{
			{"Paranoid mode", a.paranoidCheck},
			{"Compress files", a.compressCheck},
			{"Reed-Solomon", a.reedSolomonCheck},
			{"Delete files", a.deleteCheck},
			{"Deniability", a.deniabilityCheck},
			{"Recursively", a.recursivelyCheck},
			{"Split:", a.splitCheck},
		} {
			if c.box.Disabled() {
				t.Errorf("#56 regression: %q is disabled under Paranoid+Reed-Solomon+Deniability; this combo must not lock any option", c.name)
			}
		}
	})
}

// assertTooltipsPresentAndDistinct asserts every control carries a non-empty
// tooltip (an empty tooltip is a missing-tooltip bug, issue #79) and that the
// tooltips are distinct across controls, since duplicate copy on two unrelated
// controls almost always means a copy/paste wiring mistake.
func assertTooltipsPresentAndDistinct(t *testing.T, controls []struct {
	name string
	tt   interface{ ToolTip() string }
},
) {
	t.Helper()
	seen := make(map[string]string)
	for _, c := range controls {
		got := c.tt.ToolTip()
		if got == "" {
			t.Errorf("%s has an empty tooltip", c.name)
			continue
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s share tooltip %q; tooltips must be distinct", prev, c.name, got)
		}
		seen[got] = c.name
	}
}

func TestAdvancedOptionsSetTooltips(t *testing.T) {
	newTestFyneApp(t)

	t.Run("encrypt", func(t *testing.T) {
		a := createTestApp(t)
		a.advancedContainer = container.NewVBox()
		a.buildEncryptOptions()

		assertTooltipsPresentAndDistinct(t, []struct {
			name string
			tt   interface{ ToolTip() string }
		}{
			{"Paranoid mode", a.paranoidCheck},
			{"Compress files", a.compressCheck},
			{"Reed-Solomon", a.reedSolomonCheck},
			{"Delete files", a.deleteCheck},
			{"Deniability", a.deniabilityCheck},
			{"Recursively", a.recursivelyCheck},
			{"Split:", a.splitCheck},
		})

		if got, want := a.deleteCheck.ToolTip(), tr("advanced.delete_files.tooltip", "Delete source files after encryption"); got != want {
			t.Errorf("Delete files tooltip = %q, want %q", got, want)
		}
		if got, want := a.deniabilityCheck.ToolTip(), tr("advanced.deniability.tooltip", "No readable Picocrypt header. Keep password/keyfiles."); got != want {
			t.Errorf("Deniability tooltip = %q, want %q", got, want)
		}
		if got, want := a.recursivelyCheck.ToolTip(), tr("advanced.recursively.tooltip", "Process each file separately"); got != want {
			t.Errorf("Recursively tooltip = %q, want %q", got, want)
		}
	})

	t.Run("decrypt", func(t *testing.T) {
		a := createTestApp(t)
		a.advancedContainer = container.NewVBox()
		a.buildDecryptOptions()

		assertTooltipsPresentAndDistinct(t, []struct {
			name string
			tt   interface{ ToolTip() string }
		}{
			{"Force decrypt", a.forceDecryptCheck},
			{"Verify first", a.verifyFirstCheck},
			{"Delete volume", a.deleteVolumeCheck},
			{"Auto unzip", a.autoUnzipCheck},
			{"Same level", a.sameLevelCheck},
		})

		if got := a.autoUnzipCheck.ToolTip(); got != "Extract .zip; may overwrite files" {
			t.Errorf("Auto unzip tooltip = %q; want rendered .zip overwrite warning", got)
		}
		if got := a.sameLevelCheck.ToolTip(); got != "Extract .zip beside the volume" {
			t.Errorf("Same level tooltip = %q; want rendered .zip extraction hint", got)
		}
	})
}

func TestAdvancedDisclosureCollapsedByDefault(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.AllFiles = []string{"input.txt"}
		a.State.OnlyFiles = []string{"input.txt"}
		a.State.SetInputSelection(1, 0, 0, false)
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.State.OutputFile = "input.txt.pcv"
		a.refreshAdvanced()
	})

	if a.advancedLabel != nil && a.advancedLabel.Visible() {
		t.Fatal("desktop advanced label should be replaced by disclosure, not remain as a separate visible label")
	}
	if a.advancedToggleBtn == nil {
		t.Fatal("advanced disclosure button was not built")
	}
	if a.advancedDetail == nil {
		t.Fatal("advanced disclosure detail was not built")
	}
	if a.advancedOpen {
		t.Fatal("advanced disclosure should be collapsed when all advanced options are at defaults")
	}
	if a.advancedToggleBtn.Text != tr("advanced.title", "Advanced") {
		t.Fatalf("advanced disclosure title = %q; want localized advanced title", a.advancedToggleBtn.Text)
	}
	if !canvasTreeContainsObject(a.advancedDetail, a.paranoidCheck) {
		t.Fatal("advanced disclosure detail does not contain real advanced controls")
	}
	if canvasTreeContainsLabelWithText(a.advancedDetail, tr("advanced.summary.defaults", "Optional settings. Defaults are recommended for most files.")) {
		t.Fatal("advanced disclosure should not show generic defaults summary copy")
	}
}

func TestAdvancedDisclosureOpensWhenAdvancedOptionEnabled(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.AllFiles = []string{"input.txt"}
		a.State.OnlyFiles = []string{"input.txt"}
		a.State.SetInputSelection(1, 0, 0, false)
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.State.OutputFile = "input.txt.pcv"
		a.State.Split = true
		a.refreshAdvanced()
	})

	if a.advancedDetail == nil {
		t.Fatal("advanced disclosure detail was not built")
	}
	if !a.advancedOpen {
		t.Fatal("advanced disclosure should open when a non-default advanced option is enabled")
	}
}

func TestAdvancedDisclosurePreservesSessionOpenStateOnRefresh(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.AllFiles = []string{"input.txt"}
		a.State.OnlyFiles = []string{"input.txt"}
		a.State.SetInputSelection(1, 0, 0, false)
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.State.OutputFile = "input.txt.pcv"
		a.refreshAdvanced()
		a.advancedToggleBtn.OnTapped()
		a.refreshAdvanced()
	})

	if a.advancedDetail == nil {
		t.Fatal("advanced disclosure detail was not rebuilt")
	}
	if !a.advancedOpen {
		t.Fatal("advanced disclosure manual open state was not preserved across refresh")
	}
}

func TestAdvancedDisclosureKeepsOptionTooltipsLocalized(t *testing.T) {
	resetLocalizationForTest(t)

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		if err := a.SwitchLanguage("ru"); err != nil {
			t.Fatalf("SwitchLanguage(ru) returned error: %v", err)
		}
		a.State.Mode = "encrypt"
		a.State.AllFiles = []string{"input.txt"}
		a.State.OnlyFiles = []string{"input.txt"}
		a.State.SetInputSelection(1, 0, 0, false)
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.State.OutputFile = "input.txt.pcv"
		a.refreshAdvanced()
	})

	if a.advancedToggleBtn == nil {
		t.Fatal("advanced disclosure button was not built")
	}
	if a.advancedToggleBtn.Text != tr("advanced.title", "Advanced") {
		t.Fatalf("advanced disclosure title = %q; want localized title", a.advancedToggleBtn.Text)
	}
	if got := a.paranoidCheck.ToolTip(); got != tr("advanced.paranoid.tooltip", "Adds Serpent and stronger checks") {
		t.Fatalf("paranoid tooltip = %q; want localized tooltip", got)
	}
	if canvasTreeContainsLabelWithText(a.advancedDetail, tr("advanced.summary.defaults", "Optional settings. Defaults are recommended for most files.")) {
		t.Fatal("advanced disclosure should not show generic defaults summary copy")
	}
}

func TestSplitUnitSelectLocalizesTotalWithoutChangingIndex(t *testing.T) {
	resetLocalizationForTest(t)

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		if err := a.SwitchLanguage("ru"); err != nil {
			t.Fatalf("SwitchLanguage(ru) returned error: %v", err)
		}
		a.State.Mode = "encrypt"
		a.State.AllFiles = []string{"input.txt"}
		a.State.OnlyFiles = []string{"input.txt"}
		a.State.SetInputSelection(1, 0, 0, false)
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.State.OutputFile = "input.txt.pcv"
		a.refreshAdvanced()
	})

	if a.splitUnitSelect == nil {
		t.Fatal("split unit select was not built")
	}
	if got := a.splitUnitSelect.Options[4]; got != "Всего" {
		t.Fatalf("localized split unit option = %q; want Всего", got)
	}

	fyne.DoAndWait(func() {
		a.splitUnitSelect.OnChanged("Всего")
	})
	if a.State.SplitSelected != 4 {
		t.Fatalf("SplitSelected = %d; want Total index 4", a.State.SplitSelected)
	}
}

func canvasTreeContainsLabelWithText(root fyne.CanvasObject, want string) bool {
	if root == nil {
		return false
	}
	if label, ok := root.(*widget.Label); ok && label.Text == want {
		return true
	}
	if container, ok := root.(*fyne.Container); ok {
		for _, child := range container.Objects {
			if canvasTreeContainsLabelWithText(child, want) {
				return true
			}
		}
	}
	return false
}
