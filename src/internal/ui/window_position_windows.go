//go:build windows

package ui

import (
	"image"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"
	"golang.org/x/sys/windows"
)

var (
	windowPositionUser32 = windows.NewLazySystemDLL("user32.dll")
	windowPositionShcore = windows.NewLazySystemDLL("shcore.dll")

	clientToScreenProc           = windowPositionUser32.NewProc("ClientToScreen")
	isIconicProc                 = windowPositionUser32.NewProc("IsIconic")
	isZoomedProc                 = windowPositionUser32.NewProc("IsZoomed")
	monitorFromRectProc          = windowPositionUser32.NewProc("MonitorFromRect")
	getMonitorInfoWProc          = windowPositionUser32.NewProc("GetMonitorInfoW")
	getSystemMetricsForDpiProc   = windowPositionUser32.NewProc("GetSystemMetricsForDpi")
	getScaleFactorForMonitorProc = windowPositionShcore.NewProc("GetScaleFactorForMonitor")
)

type nativeWindowPoint struct {
	X int32
	Y int32
}

type nativeWindowRect struct {
	Left, Top, Right, Bottom int32
}

type nativeMonitorInfo struct {
	Size    uint32
	Monitor nativeWindowRect
	Work    nativeWindowRect
	Flags   uint32
}

func supportsWindowPositionPersistence() bool {
	return true
}

func desktopWindowPlacementBounds(x, y int) (image.Rectangle, image.Rectangle) {
	// RECT uses signed 32-bit coordinates; leave room for the one-pixel rectangle.
	if x < -1<<31 || x >= 1<<31-1 || y < -1<<31 || y >= 1<<31-1 {
		return image.Rectangle{}, image.Rectangle{}
	}
	rect := nativeWindowRect{int32(x), int32(y), int32(x) + 1, int32(y) + 1}
	monitor, _, _ := monitorFromRectProc.Call(uintptr(unsafe.Pointer(&rect)), 0)
	if monitor == 0 {
		return image.Rectangle{}, image.Rectangle{}
	}
	info := nativeMonitorInfo{}
	info.Size = uint32(unsafe.Sizeof(info))
	result, _, _ := getMonitorInfoWProc.Call(monitor, uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		return image.Rectangle{}, image.Rectangle{}
	}
	if getSystemMetricsForDpiProc.Find() != nil || getScaleFactorForMonitorProc.Find() != nil {
		return image.Rectangle{}, image.Rectangle{}
	}
	var scale uint32
	result, _, _ = getScaleFactorForMonitorProc.Call(monitor, uintptr(unsafe.Pointer(&scale)))
	if result != 0 || scale == 0 {
		return image.Rectangle{}, image.Rectangle{}
	}
	dpi := (uintptr(scale)*96 + 99) / 100
	metric := func(index uintptr) int {
		value, _, _ := getSystemMetricsForDpiProc.Call(index, dpi)
		return int(int32(value))
	}
	const (
		smCYCaption      = 4
		smCXFrame        = 32
		smCYFrame        = 33
		smCXMinTrack     = 34
		smCYMinTrack     = 35
		smCXPaddedBorder = 92
	)
	caption := metric(smCYCaption)
	padding := metric(smCXPaddedBorder)
	frameX, frameY := metric(smCXFrame)+padding, metric(smCYFrame)+padding
	width, height := metric(smCXMinTrack), metric(smCYMinTrack)
	if caption <= 0 || padding < 0 || frameX <= 0 || frameY <= 0 || width <= frameX || height <= caption+frameY {
		return image.Rectangle{}, image.Rectangle{}
	}
	workArea := image.Rect(int(info.Work.Left), int(info.Work.Top), int(info.Work.Right), int(info.Work.Bottom))
	minimumFrame := image.Rect(-frameX, -caption-frameY, width-frameX, height-caption-frameY)
	return workArea, minimumFrame
}

func readDesktopWindowPosition(window fyne.Window) (int, int, bool) {
	native, ok := window.(driver.NativeWindow)
	if !ok {
		return 0, 0, false
	}

	var x int
	var y int
	var found bool

	// Fyne's Windows RunNative invokes this callback synchronously for the shown window.
	native.RunNative(func(context any) {
		win, ok := context.(driver.WindowsWindowContext)
		if !ok || win.HWND == 0 || !windows.IsWindowVisible(windows.HWND(win.HWND)) {
			return
		}
		hwnd := win.HWND

		// Keep the last normal position when the window is maximized or minimized.
		if result, _, _ := isIconicProc.Call(hwnd); result != 0 {
			return
		}
		if result, _, _ := isZoomedProc.Call(hwnd); result != 0 {
			return
		}

		var point nativeWindowPoint
		result, _, _ := clientToScreenProc.Call(
			hwnd,
			uintptr(unsafe.Pointer(&point)),
		)
		if result == 0 {
			return
		}

		x = int(point.X)
		y = int(point.Y)
		found = true
	})

	return x, y, found
}
