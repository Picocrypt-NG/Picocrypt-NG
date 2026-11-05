package ui

import (
	"math"

	"fyne.io/fyne/v2"
)

const (
	rememberWindowSizePreferenceKey = "ui.remember_window_size"
	windowSizeSavedPreferenceKey    = "ui.window_size_saved"
	windowWidthPreferenceKey        = "ui.window_width"
	windowHeightPreferenceKey       = "ui.window_height"
)

func (a *App) rememberWindowSizeEnabled() bool {
	if a.fyneApp == nil {
		return false
	}

	return a.fyneApp.Preferences().BoolWithFallback(
		rememberWindowSizePreferenceKey,
		false,
	)
}

func (a *App) setRememberWindowSize(enabled bool) {
	if a.fyneApp == nil {
		return
	}

	preferences := a.fyneApp.Preferences()
	preferences.SetBool(rememberWindowSizePreferenceKey, enabled)

	if !enabled {
		preferences.SetBool(windowSizeSavedPreferenceKey, false)
	}
}

func (a *App) restoreDesktopWindowSize(minimum fyne.Size) bool {
	if a.fyneApp == nil || a.Window == nil || !supportsWindowPositionPersistence() || !a.rememberWindowSizeEnabled() {
		return false
	}

	preferences := a.fyneApp.Preferences()
	if !preferences.BoolWithFallback(windowSizeSavedPreferenceKey, false) {
		return false
	}

	width := preferences.Float(windowWidthPreferenceKey)
	height := preferences.Float(windowHeightPreferenceKey)
	if !validDesktopWindowDimension(width) || !validDesktopWindowDimension(height) {
		preferences.SetBool(windowSizeSavedPreferenceKey, false)
		return false
	}

	size := fyne.NewSize(float32(width), float32(height)).Max(minimum)
	a.Window.Resize(size)
	return true
}

func (a *App) saveDesktopWindowSize() {
	if a.fyneApp == nil || a.Window == nil || !supportsWindowPositionPersistence() || !a.rememberWindowSizeEnabled() {
		return
	}

	// The native lookup also ensures that minimized or maximized windows do not
	// replace the last normal size, matching the position-persistence behavior.
	if _, _, ok := readDesktopWindowPosition(mainWindowTitle); !ok {
		return
	}

	size := a.Window.Canvas().Size()
	if !validDesktopWindowSize(size) {
		return
	}

	preferences := a.fyneApp.Preferences()
	preferences.SetFloat(windowWidthPreferenceKey, float64(size.Width))
	preferences.SetFloat(windowHeightPreferenceKey, float64(size.Height))
	preferences.SetBool(windowSizeSavedPreferenceKey, true)
}

func validDesktopWindowDimension(value float64) bool {
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return false
	}

	converted := float32(value)
	return converted > 0 && !math.IsInf(float64(converted), 0)
}

func validDesktopWindowSize(size fyne.Size) bool {
	return validDesktopWindowDimension(float64(size.Width)) &&
		validDesktopWindowDimension(float64(size.Height))
}
