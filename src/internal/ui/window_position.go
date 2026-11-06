package ui

import (
	"image"

	"fyne.io/fyne/v2/driver/desktop"
)

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
	workArea, minimumFrame := desktopWindowPlacementBounds(x, y)
	return requestDesktopWindowPosition(window, x, y, workArea, minimumFrame)
}

func requestDesktopWindowPosition(window desktop.Window, x, y int, workArea, minimumFrame image.Rectangle) bool {
	// Fyne's GLFW driver treats (0, 0) as an unset position.
	if x == 0 && y == 0 {
		x = 1
		y = 1
	}
	// The saved coordinates locate the client area; the caption is above it.
	frame := minimumFrame.Add(image.Pt(x, y))
	if minimumFrame.Empty() || frame.Empty() || workArea.Empty() || !frame.In(workArea) {
		return false
	}

	window.RequestPosition(x, y)
	return true
}

func (a *App) saveDesktopWindowPosition() {
	if a.fyneApp == nil || a.Window == nil || !a.rememberWindowPositionEnabled() {
		return
	}

	x, y, ok := readDesktopWindowPosition(a.Window)
	if !ok {
		return
	}

	preferences := a.fyneApp.Preferences()
	preferences.SetInt(windowPositionXPreferenceKey, x)
	preferences.SetInt(windowPositionYPreferenceKey, y)
	preferences.SetBool(windowPositionSavedPreferenceKey, true)
}
