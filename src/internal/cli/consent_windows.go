package cli

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

var cancelSynchronousIO = windows.NewLazySystemDLL("kernel32.dll").NewProc("CancelSynchronousIo")

// Keep the console's cooked editing and echo. The thread and console handle
// belong to this read; cancellation interrupts synchronous I/O and is joined
// before either handle is closed or the OS thread can be reused.
func readConsentLine(ctx context.Context) (_ string, retErr error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := cancelSynchronousIO.Find(); err != nil {
		return "", err
	}
	console, err := os.OpenFile("CONIN$", os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer func() { retErr = errors.Join(retErr, console.Close()) }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	thread, err := windows.OpenThread(windows.THREAD_TERMINATE, false, windows.GetCurrentThreadId())
	if err != nil {
		return "", err
	}
	defer func() { retErr = errors.Join(retErr, windows.CloseHandle(thread)) }()
	finished, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-finished:
			return
		case <-ctx.Done():
		}
		// Cancellation can arrive just before ReadConsole enters the kernel.
		// ERROR_NOT_FOUND is not completion: retry until the read has returned.
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			_, _, _ = cancelSynchronousIO.Call(uintptr(thread))
			select {
			case <-finished:
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { close(finished); <-joined }()
	line := make([]uint16, 0, 32)
	var one [1]uint16
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		var n uint32
		err := windows.ReadConsole(windows.Handle(console.Fd()), &one[0], 1, &n, nil)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if err != nil {
			return "", err
		}
		if n == 0 || one[0] == '\n' {
			return strings.TrimSuffix(string(utf16.Decode(line)), "\r"), nil
		}
		if len(line) == 4096 {
			return "", errors.New("consent line is too long")
		}
		line = append(line, one[0])
	}
}
