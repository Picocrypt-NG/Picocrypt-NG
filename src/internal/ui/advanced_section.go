// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/app"
	"reflect"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

// updateAdvancedSection updates the advanced options based on mode.
func (a *App) updateAdvancedSection() {
	// Use mobile-specific advanced section on mobile
	if isMobile() {
		a.updateMobileAdvancedSection()
		return
	}

	a.advancedContainer.RemoveAll()
	a.advancedToggleBtn = nil
	a.advancedDetail = nil

	switch a.State.Mode {
	case "":
		// Initial state - no files selected, hide advanced section entirely
		if a.advancedLabel != nil {
			a.advancedLabel.Hide()
		}
		a.resizeDesktopWindowForCurrentContent(0)
	case "encrypt":
		if a.advancedLabel != nil {
			a.advancedLabel.Show()
		}
		a.buildDesktopAdvancedDisclosure(a.buildAdvancedDetailContent("encrypt"), a.advancedShouldAutoOpen())
		a.resizeDesktopWindowForCurrentContent(0)
	case "decrypt":
		if a.advancedLabel != nil {
			a.advancedLabel.Show()
		}
		a.buildDesktopAdvancedDisclosure(a.buildAdvancedDetailContent("decrypt"), a.advancedShouldAutoOpen())
		a.resizeDesktopWindowForCurrentContent(0)
	}

	// IMPORTANT: Newly rebuilt controls must immediately reflect the current
	// snapshot-driven disable state so a section refresh cannot leave stale
	// enabled/disabled widgets behind.
	a.updateAdvancedDisableState()

	a.advancedContainer.Refresh()
}

func (a *App) advancedShouldAutoOpen() bool {
	switch a.State.Mode {
	case "encrypt":
		return a.State.Paranoid || a.State.Compress || a.State.ReedSolomon ||
			a.State.Delete || a.State.Deniability || a.State.Recursively ||
			a.State.Split || a.State.SplitSize != ""
	case "decrypt":
		return a.State.Keep || a.State.VerifyFirst || a.State.Delete ||
			a.State.AutoUnzip || a.State.SameLevel
	default:
		return false
	}
}

func (a *App) buildAdvancedDetailContent(mode string) fyne.CanvasObject {
	options := container.NewVBox()
	switch mode {
	case "decrypt":
		a.buildDecryptOptionsInto(options)
	default:
		a.buildEncryptOptionsInto(options)
	}

	return options
}

func (a *App) buildDesktopAdvancedDisclosure(detail fyne.CanvasObject, autoOpen bool) {
	open := autoOpen
	if a.advancedOverridden {
		open = a.advancedOpen
	} else {
		a.advancedOpen = autoOpen
	}

	a.advancedDetail = detail
	a.advancedToggleBtn = widget.NewButtonWithIcon(tr("advanced.title", "Advanced"), advancedDisclosureIcon(open), func() {
		a.advancedOverridden = true
		a.setAdvancedDisclosureOpen(!a.advancedOpen)
	})
	a.advancedToggleBtn.Alignment = widget.ButtonAlignLeading
	a.advancedToggleBtn.IconPlacement = widget.ButtonIconLeadingText
	a.advancedToggleBtn.Importance = widget.LowImportance
	if !open {
		detail.Hide()
	}
	a.advancedContainer.Add(a.advancedToggleBtn)
	a.advancedContainer.Add(detail)
}

func advancedDisclosureIcon(open bool) fyne.Resource {
	if open {
		return theme.MenuDropUpIcon()
	}
	return theme.MenuDropDownIcon()
}

func (a *App) refreshAdvancedDisclosureButton() {
	if a.advancedToggleBtn == nil {
		return
	}
	a.advancedToggleBtn.SetText(tr("advanced.title", "Advanced"))
	a.advancedToggleBtn.SetIcon(advancedDisclosureIcon(a.advancedOpen))
}

func (a *App) setAdvancedDisclosureOpen(open bool) {
	a.advancedOpen = open
	if a.advancedDetail != nil {
		if open {
			a.advancedDetail.Show()
		} else {
			a.advancedDetail.Hide()
		}
	}
	a.refreshAdvancedDisclosureButton()
	if a.advancedContainer != nil {
		a.advancedContainer.Refresh()
	}
	a.resizeDesktopWindowForCurrentContent(0)
}

// buildEncryptOptions creates encrypt mode options.
func (a *App) buildEncryptOptions() {
	a.buildEncryptOptionsInto(a.advancedContainer)
}

func (a *App) buildEncryptOptionsInto(target *fyne.Container) {
	if target == nil {
		return
	}

	a.paranoidCheck = ttwidget.NewCheck(tr("advanced.paranoid.label", "Paranoid mode"), func(checked bool) {
		a.State.Paranoid = checked
	})
	a.paranoidCheck.SetToolTip(tr("advanced.paranoid.tooltip", "Adds Serpent and stronger checks"))
	a.paranoidCheck.SetChecked(a.State.Paranoid)

	a.compressCheck = ttwidget.NewCheck(tr("advanced.compress.label", "Compress files"), func(checked bool) {
		a.State.Compress = checked
		// Auto-toggle .zip suffix in output filename
		a.updateOutputFileForCompress(checked)
	})
	a.compressCheck.SetToolTip(tr("advanced.compress.tooltip", "Compress before encrypting"))
	a.compressCheck.SetChecked(a.State.Compress)

	row1 := container.NewGridWithColumns(2, a.paranoidCheck, a.compressCheck)

	a.reedSolomonCheck = ttwidget.NewCheck(tr("advanced.reed_solomon.label", "Reed-Solomon"), func(checked bool) {
		a.State.ReedSolomon = checked
	})
	a.reedSolomonCheck.SetToolTip(tr("advanced.reed_solomon.tooltip", "Add recovery data"))
	a.reedSolomonCheck.SetChecked(a.State.ReedSolomon)

	a.deleteCheck = ttwidget.NewCheck(tr("advanced.delete_files.label", "Delete files"), func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteCheck.SetToolTip(tr("advanced.delete_files.tooltip", "Delete source files after encryption"))
	a.deleteCheck.SetChecked(a.State.Delete)

	row2 := container.NewGridWithColumns(2, a.reedSolomonCheck, a.deleteCheck)

	a.deniabilityCheck = ttwidget.NewCheck(tr("advanced.deniability.label", "Deniability"), func(checked bool) {
		a.State.Deniability = checked
		a.updateUIState()
	})
	a.deniabilityCheck.SetToolTip(tr("advanced.deniability.tooltip", "No readable Picocrypt header. Keep password/keyfiles."))
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
	a.recursivelyCheck.SetToolTip(tr("advanced.recursively.tooltip", "Process each file separately"))
	a.recursivelyCheck.SetChecked(a.State.Recursively)

	row3 := container.NewGridWithColumns(2, a.deniabilityCheck, a.recursivelyCheck)

	a.splitCheck = ttwidget.NewCheck(tr("advanced.split.label", "Split:"), func(checked bool) {
		a.State.Split = checked
		a.updateUIState() // Update status to show increased disk space requirement
	})
	a.splitCheck.SetToolTip(tr("advanced.split.tooltip", "Split output into parts"))
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
		a.updateUIState() // Update status to show increased disk space requirement
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

	splitRow := container.NewBorder(nil, nil,
		a.splitCheck,
		a.splitUnitSelect,
		a.splitSizeEntry,
	)

	target.Add(row1)
	target.Add(row2)
	target.Add(row3)
	target.Add(splitRow)
}

func localizedSplitUnits(units []string) []string {
	localized := make([]string, len(units))
	for i, unit := range units {
		localized[i] = localizedSplitUnit(unit)
	}
	return localized
}

func localizedSplitUnit(unit string) string {
	if unit == "Total" {
		return tr("advanced.split.unit.total", "Total")
	}
	return unit
}

// buildDecryptOptions creates decrypt mode options.
func (a *App) buildDecryptOptions() {
	a.buildDecryptOptionsInto(a.advancedContainer)
}

func (a *App) buildDecryptOptionsInto(target *fyne.Container) {
	if target == nil {
		return
	}

	a.forceDecryptCheck = ttwidget.NewCheck(tr("advanced.force_decrypt.label", "Force decrypt"), func(checked bool) {
		a.State.Keep = checked
	})
	a.forceDecryptCheck.SetToolTip(tr("advanced.force_decrypt.tooltip", "Keep damaged or unverified output"))
	a.forceDecryptCheck.SetChecked(a.State.Keep)

	a.verifyFirstCheck = ttwidget.NewCheck(tr("advanced.verify_first.label", "Verify first"), func(checked bool) {
		a.State.VerifyFirst = checked
	})
	a.verifyFirstCheck.SetToolTip(tr("advanced.verify_first.tooltip", "Verify before decrypting"))
	a.verifyFirstCheck.SetChecked(a.State.VerifyFirst)

	row1 := container.NewGridWithColumns(2, a.forceDecryptCheck, a.verifyFirstCheck)

	a.deleteVolumeCheck = ttwidget.NewCheck(tr("advanced.delete_volume.label", "Delete volume"), func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteVolumeCheck.SetToolTip(tr("advanced.delete_volume.tooltip", "Delete volume after decryption"))
	a.deleteVolumeCheck.SetChecked(a.State.Delete)

	a.autoUnzipCheck = ttwidget.NewCheck(tr("advanced.auto_unzip.label", "Auto unzip"), func(checked bool) {
		a.State.AutoUnzip = checked
		if !checked {
			a.State.SameLevel = false
			if a.sameLevelCheck != nil {
				a.sameLevelCheck.SetChecked(false)
			}
		}
		a.updateUIState()
	})
	a.autoUnzipCheck.SetToolTip(tr("advanced.auto_unzip.tooltip", "Extract {{.Extension}}; may overwrite files", map[string]any{
		"Extension": ".zip",
	}))
	a.autoUnzipCheck.SetChecked(a.State.AutoUnzip)

	a.sameLevelCheck = ttwidget.NewCheck(tr("advanced.same_level.label", "Same level"), func(checked bool) {
		a.State.SameLevel = checked
	})
	a.sameLevelCheck.SetToolTip(tr("advanced.same_level.tooltip", "Extract {{.Extension}} beside the volume", map[string]any{
		"Extension": ".zip",
	}))
	a.sameLevelCheck.SetChecked(a.State.SameLevel)

	row2 := container.NewGridWithColumns(2, a.autoUnzipCheck, a.sameLevelCheck)

	target.Add(row1)
	target.Add(a.deleteVolumeCheck)
	target.Add(row2)

	// Disable auto unzip if not a zip file
	if !strings.HasSuffix(a.State.InputFile, ".zip.pcv") {
		a.autoUnzipCheck.Disable()
		a.sameLevelCheck.Disable()
	}

	// Disable same level if auto unzip is not checked
	if !a.State.AutoUnzip {
		a.sameLevelCheck.Disable()
	}

	// Disable force decrypt if deniability
	if a.State.Deniability {
		a.forceDecryptCheck.Disable()
	}
}

// updateAdvancedDisableState updates the disable state of advanced options.
func (a *App) updateAdvancedDisableState() {
	snap := a.State.UISnapshot()
	a.updateAdvancedDisableStateFromSnapshot(snap, snap.Scanning || !hasSelectedInput(snap))
}

func (a *App) updateAdvancedDisableStateFromSnapshot(snap app.UISnapshot, configureDisabled bool) {
	advancedDisabled := configureDisabled

	if snap.Mode != "decrypt" {
		a.updateEncryptOptionsState(advancedDisabled, snap)
	} else {
		a.updateDecryptOptionsState(advancedDisabled, snap)
	}
}

// setWidgetDisabled is a helper that enables/disables a widget and ensures refresh.
// Note: Uses reflect to handle nil interface values containing nil pointers.
func setWidgetDisabled(w fyne.Disableable, disabled bool) {
	// Check for nil interface or nil pointer inside interface
	if w == nil || reflect.ValueOf(w).IsNil() {
		return
	}
	if disabled {
		w.Disable()
	} else {
		w.Enable()
	}
}

// updateEncryptOptionsState updates encrypt mode option states.
func (a *App) updateEncryptOptionsState(advancedDisabled bool, snap app.UISnapshot) {
	// Advanced options stay configurable after input is selected; Start remains
	// disabled separately until credentials and required values are ready.

	notEnoughFiles := snap.AllFileCount <= 1 && snap.OnlyFolderCount == 0

	setWidgetDisabled(a.compressCheck, advancedDisabled || snap.Recursively)
	setWidgetDisabled(a.recursivelyCheck, advancedDisabled || notEnoughFiles)
	setWidgetDisabled(a.paranoidCheck, advancedDisabled)
	setWidgetDisabled(a.reedSolomonCheck, advancedDisabled)
	setWidgetDisabled(a.deleteCheck, advancedDisabled)
	setWidgetDisabled(a.deniabilityCheck, advancedDisabled)
	setWidgetDisabled(a.splitCheck, advancedDisabled)
	setWidgetDisabled(a.splitSizeEntry, advancedDisabled)
	setWidgetDisabled(a.splitUnitSelect, advancedDisabled)
}

// updateDecryptOptionsState updates decrypt mode option states.
func (a *App) updateDecryptOptionsState(advancedDisabled bool, snap app.UISnapshot) {
	setWidgetDisabled(a.forceDecryptCheck, advancedDisabled || snap.Deniability)
	setWidgetDisabled(a.verifyFirstCheck, advancedDisabled)
	setWidgetDisabled(a.deleteVolumeCheck, advancedDisabled)
	// On mobile, deleteCheck is used instead of deleteVolumeCheck
	setWidgetDisabled(a.deleteCheck, advancedDisabled)
	setWidgetDisabled(a.autoUnzipCheck, advancedDisabled || !strings.HasSuffix(snap.InputFile, ".zip.pcv"))
	setWidgetDisabled(a.sameLevelCheck, advancedDisabled || !snap.AutoUnzip)
}

// updateOutputFileForCompress toggles .zip suffix in output filename based on compress state.
func (a *App) updateOutputFileForCompress(compress bool) {
	if a.State.Mode != "encrypt" {
		return
	}

	originalOutput := a.State.OutputFile

	if compress {
		// Add .zip suffix before .pcv if not already present
		if strings.HasSuffix(a.State.OutputFile, ".pcv") && !strings.HasSuffix(a.State.OutputFile, ".zip.pcv") {
			a.State.OutputFile = strings.TrimSuffix(a.State.OutputFile, ".pcv") + ".zip.pcv"
		}
	} else {
		// Remove .zip suffix if present
		if before, ok := strings.CutSuffix(a.State.OutputFile, ".zip.pcv"); ok {
			a.State.OutputFile = before + ".pcv"
		}
	}

	if a.State.OutputFile != originalOutput {
		a.State.OutputChosenViaSaveDialog = false
	}

	// Refresh the output entry to show the updated filename
	a.refreshUI()
}
