package ui

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

func TestFormWheelOverSingleLineFieldsScrollsBody(t *testing.T) {
	for _, name := range []string{"password", "confirmation", "comments"} {
		t.Run(name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			a := newDesktopEncryptLayoutApp(t, fyneApp)
			fyne.DoAndWait(func() {
				a.passwordEntry.SetText("public test password")
				a.cPasswordEntry.SetText("public test password")
				a.commentsEntry.SetText("public comment")
				a.Window.Resize(fyne.NewSize(windowWidth, 300))
				var field fyne.CanvasObject
				switch name {
				case "password":
					field = a.passwordEntry
				case "confirmation":
					field = a.cPasswordEntry
				case "comments":
					field = a.commentsEntry
				}
				viewport := fyneApp.Driver().AbsolutePositionForObject(a.mainScroll)
				position := fyneApp.Driver().AbsolutePositionForObject(field)
				a.mainScroll.ScrollToOffset(fyne.NewPos(0, a.mainScroll.Offset.Y+position.Y-viewport.Y))
				position = fyneApp.Driver().AbsolutePositionForObject(field)
				point := position.Add(fyne.NewPos(field.Size().Width/2, field.Size().Height/2))
				if point.Y < viewport.Y || point.Y >= viewport.Y+a.mainScroll.Size().Height {
					t.Fatal("test field is outside the scroll viewport")
				}
				before := a.State.UISnapshot()
				offset := a.mainScroll.Offset.Y
				delta := float32(-40)
				if offset > 0 {
					delta = 40
				}
				test.Scroll(a.Window.Canvas(), point, 0, delta)
				if a.mainScroll.Offset.Y == offset {
					t.Error("vertical wheel over the field did not move the form")
				}
				after := a.State.UISnapshot()
				if after.Password != before.Password || after.CPassword != before.CPassword || after.Comments != before.Comments {
					t.Error("scrolling changed the entered values")
				}
			})
		})
	}
}

func TestFormScrollingRetainsLongPasswordViewport(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := newDesktopEncryptLayoutApp(t, fyneApp)
	fyne.DoAndWait(func() {
		a.Window.Resize(fyne.NewSize(windowWidth, 300))
		fieldWidth := a.passwordEntry.Size().Width
		windowWidth := a.Window.Canvas().Size().Width
		longPassword := strings.Repeat("a", 128)
		a.passwordEntry.SetText(longPassword)
		a.Window.Canvas().Focus(a.passwordEntry)
		a.passwordEntry.TypedKey(&fyne.KeyEvent{Name: fyne.KeyEnd})
		a.passwordEntry.TypedRune('z')
		if a.passwordEntry.Text != longPassword+"z" || a.State.UISnapshot().Password != longPassword+"z" {
			t.Error("editing at the end of a long password changed its contents")
		}
		if a.passwordEntry.MinSize().Width > fieldWidth || a.Window.Canvas().Size().Width > windowWidth {
			t.Error("long password expanded the field or window instead of retaining its horizontal viewport")
		}
	})
}
