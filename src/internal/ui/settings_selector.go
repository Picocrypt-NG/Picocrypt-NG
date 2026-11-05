package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const (
	rememberWindowPositionPreferenceKey = "ui.remember_window_position"
	windowPositionSavedPreferenceKey    = "ui.window_position_saved"
	windowPositionXPreferenceKey        = "ui.window_position_x"
	windowPositionYPreferenceKey        = "ui.window_position_y"
)

type settingsSelector struct {
	owner  *App
	button *widget.Button
}

func newSettingsSelector(owner *App) *settingsSelector {
	selector := &settingsSelector{owner: owner}
	selector.button = widget.NewButtonWithIcon("", theme.SettingsIcon(), func() {
		if owner == nil || owner.Window == nil {
			return
		}

		popup := widget.NewPopUpMenu(selector.menu(), owner.Window.Canvas())
		popup.ShowAtRelativePosition(fyne.NewPos(0, selector.button.Size().Height), selector.button)
	})
	selector.button.Importance = widget.LowImportance

	return selector
}

func (s *settingsSelector) object() fyne.CanvasObject {
	if s == nil || s.button == nil {
		return container.NewHBox()
	}
	return s.button
}

func (s *settingsSelector) menu() *fyne.Menu {
	positionEnabled := s.owner.rememberWindowPositionEnabled()
	positionItem := fyne.NewMenuItem(tr(
		"settings.remember_window_position",
		"Remember window position",
	), func() {
		s.owner.setRememberWindowPosition(!s.owner.rememberWindowPositionEnabled())
	})
	positionItem.Checked = positionEnabled

	sizeEnabled := s.owner.rememberWindowSizeEnabled()
	sizeItem := fyne.NewMenuItem(tr(
		"settings.remember_window_size",
		"Remember window size",
	), func() {
		s.owner.setRememberWindowSize(!s.owner.rememberWindowSizeEnabled())
	})
	sizeItem.Checked = sizeEnabled

	return fyne.NewMenu(tr("settings.menu", "Settings"), positionItem, sizeItem)
}

func (a *App) rememberWindowPositionEnabled() bool {
	if a.fyneApp == nil {
		return false
	}

	return a.fyneApp.Preferences().BoolWithFallback(
		rememberWindowPositionPreferenceKey,
		false,
	)
}

func (a *App) setRememberWindowPosition(enabled bool) {
	if a.fyneApp == nil {
		return
	}

	preferences := a.fyneApp.Preferences()
	preferences.SetBool(rememberWindowPositionPreferenceKey, enabled)

	if !enabled {
		preferences.SetBool(windowPositionSavedPreferenceKey, false)
	}
}
