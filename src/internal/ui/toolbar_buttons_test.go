package ui

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	fynetooltip "github.com/dweymouth/fyne-tooltip"
)

func TestToolbarButtonCancelsPendingTooltipBeforeOpeningModal(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	var logs bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() {
		log.SetOutput(previousLogOutput)
	})

	var win fyne.Window
	var modal dialog.Dialog
	fyne.DoAndWait(func() {
		win = fyneApp.NewWindow("tooltip-regression")
		button := newToolbarButton("Open modal", theme.InfoIcon(), func() {
			modal = dialog.NewCustom("Modal", "Close", widget.NewLabel("content"), win)
			modal.Show()
		})
		win.SetContent(fynetooltip.AddWindowToolTipLayer(container.NewVBox(button), win.Canvas()))

		button.MouseIn(&desktop.MouseEvent{PointEvent: fyne.PointEvent{
			AbsolutePosition: fyne.NewPos(8, 8),
			Position:         fyne.NewPos(8, 8),
		}})
		button.Tapped(&fyne.PointEvent{Position: fyne.NewPos(8, 8)})
	})
	t.Cleanup(func() {
		fyne.DoAndWait(func() {
			if modal != nil {
				modal.Hide()
			}
			if win != nil {
				fynetooltip.DestroyWindowToolTipLayer(win.Canvas())
				win.Close()
			}
		})
	})

	time.Sleep(850 * time.Millisecond)
	fyne.DoAndWait(func() {})

	if got := logs.String(); strings.Contains(got, "no tool tip layer created") {
		t.Fatalf("pending toolbar tooltip was not cancelled before modal overlay opened:\n%s", got)
	}
}
