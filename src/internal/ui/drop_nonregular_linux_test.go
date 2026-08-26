//go:build linux

package ui

import (
	"Picocrypt-NG/internal/app"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"fyne.io/fyne/v2"
	"golang.org/x/sys/unix"
)

func TestDropRejectsFIFOWithoutOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocking-input.pcv")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}

	previousOpen := openDroppedPCVInput
	var openCalls atomic.Int32
	openDroppedPCVInput = func(string, bool) (*os.File, error) {
		openCalls.Add(1)
		return nil, os.ErrInvalid
	}
	t.Cleanup(func() { openDroppedPCVInput = previousOpen })

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() { a.onDrop([]string{path}) })
	waitForDropProcessing(t, a)

	if got := openCalls.Load(); got != 0 {
		t.Fatalf("FIFO open attempts = %d; non-regular inputs must be rejected before routing or legacy parsing", got)
	}
	fyne.DoAndWait(func() {
		snap := a.State.UISnapshot()
		if snap.Status.Kind != app.StatusDropReadAccessDenied || snap.Mode != "" || snap.InputFile != "" || snap.CanStart() || snap.Scanning {
			t.Fatalf("FIFO rejection state = status %v mode %q input %q startable %v scanning %v",
				snap.Status.Kind, snap.Mode, snap.InputFile, snap.CanStart(), snap.Scanning)
		}
	})
}
