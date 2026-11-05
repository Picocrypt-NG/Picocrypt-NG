package ui

import "fyne.io/fyne/v2/driver/desktop"

func (a *App) restoreDesktopWindowPosition() bool {
	if a.fyneApp == nil || a.Window == nil || !a.rememberWindowPositionEnabled() {
		return false
	}

	preferences := a.fyneApp.Preferences()
	if !preferences.BoolWithFallback(windowPositionSavedPreferenceKey, false) {
		return false
	}

	window, ok := a.Window.(desktop.Window)
	if !ok {
		return false
	}

	x := preferences.Int(windowPositionXPreferenceKey)
	y := preferences.Int(windowPositionYPreferenceKey)

	// Fyne's GLFW driver treats (0, 0) as an unset position.
	if x == 0 && y == 0 {
		x = 1
		y = 1
	}

	window.RequestPosition(x, y)
	return true
}

func (a *App) saveDesktopWindowPosition() {
	if a.fyneApp == nil || a.Window == nil || !a.rememberWindowPositionEnabled() {
		return
	}

	x, y, ok := readDesktopWindowPosition(mainWindowTitle)
	if !ok {
		return
	}

	preferences := a.fyneApp.Preferences()
	preferences.SetInt(windowPositionXPreferenceKey, x)
	preferences.SetInt(windowPositionYPreferenceKey, y)
	preferences.SetBool(windowPositionSavedPreferenceKey, true)
}
