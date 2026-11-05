//go:build !windows

package ui

func supportsWindowPositionPersistence() bool {
	return false
}

func readDesktopWindowPosition(string) (int, int, bool) {
	return 0, 0, false
}
