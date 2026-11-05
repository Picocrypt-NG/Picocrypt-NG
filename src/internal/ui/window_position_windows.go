//go:build windows

package ui

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	windowPositionUser32 = windows.NewLazySystemDLL("user32.dll")

	getWindowTextWProc = windowPositionUser32.NewProc("GetWindowTextW")
	clientToScreenProc = windowPositionUser32.NewProc("ClientToScreen")
	isIconicProc       = windowPositionUser32.NewProc("IsIconic")
	isZoomedProc       = windowPositionUser32.NewProc("IsZoomed")
)

type nativeWindowPoint struct {
	X int32
	Y int32
}

func supportsWindowPositionPersistence() bool {
	return true
}

func readDesktopWindowPosition(title string) (int, int, bool) {
	currentPID := windows.GetCurrentProcessId()

	var x int
	var y int
	var found bool

	callback := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		window := windows.HWND(hwnd)
		if !windows.IsWindowVisible(window) {
			return 1
		}

		var windowPID uint32
		if _, err := windows.GetWindowThreadProcessId(window, &windowPID); err != nil {
			return 1
		}
		if windowPID != currentPID {
			return 1
		}

		// Keep the last normal position when the window is maximized or minimized.
		if result, _, _ := isIconicProc.Call(hwnd); result != 0 {
			return 1
		}
		if result, _, _ := isZoomedProc.Call(hwnd); result != 0 {
			return 1
		}

		var windowTitle [256]uint16
		length, _, _ := getWindowTextWProc.Call(
			hwnd,
			uintptr(unsafe.Pointer(&windowTitle[0])),
			uintptr(len(windowTitle)),
		)
		if length == 0 || windows.UTF16ToString(windowTitle[:int(length)]) != title {
			return 1
		}

		var point nativeWindowPoint
		result, _, _ := clientToScreenProc.Call(
			hwnd,
			uintptr(unsafe.Pointer(&point)),
		)
		if result == 0 {
			return 1
		}

		x = int(point.X)
		y = int(point.Y)
		found = true
		return 0
	})

	if err := windows.EnumWindows(callback, nil); err != nil && !found {
		return 0, 0, false
	}

	return x, y, found
}
