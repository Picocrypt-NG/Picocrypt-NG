//go:build !windows

package ui

import (
	"image"

	"fyne.io/fyne/v2"
)

func supportsWindowPositionPersistence() bool {
	return false
}

func readDesktopWindowPosition(fyne.Window) (int, int, bool) {
	return 0, 0, false
}

func desktopWindowPlacementBounds(int, int) (image.Rectangle, image.Rectangle) {
	return image.Rectangle{}, image.Rectangle{}
}
