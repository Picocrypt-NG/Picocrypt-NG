package ui

import (
	"math"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
)

func nativePasswordScroll(t *testing.T, entry *PasswordEntry) *container.Scroll {
	t.Helper()
	for _, object := range test.WidgetRenderer(entry).Objects() {
		if scroll, ok := object.(*container.Scroll); ok {
			return scroll
		}
	}
	t.Fatal("native Entry renderer has no scroll container")
	return nil
}

func newRevealedPasswordScrollUI(t *testing.T) *App {
	t.Helper()
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		hasFilesForUI(a)
		a.updateUIState()
		value := strings.Repeat("Wim0123456789", 64)
		a.passwordEntry.SetText(value)
		a.cPasswordEntry.SetText(value)
		test.Tap(a.showHideBtn)
	})
	a.workers.wait()
	fyne.DoAndWait(func() {
		nativePasswordScroll(t, a.passwordEntry)
		nativePasswordScroll(t, a.cPasswordEntry)
		if a.passwordEntry.Password || a.cPasswordEntry.Password {
			t.Fatal("scrolling fixture was not revealed through the toolbar")
		}
	})
	return a
}

type passwordEditSnapshot struct {
	text, selected string
	row, column    int
}

func snapshotPasswordEdit(entry *PasswordEntry) passwordEditSnapshot {
	return passwordEditSnapshot{entry.Text, entry.SelectedText(), entry.CursorRow, entry.CursorColumn}
}

func requirePasswordScrollState(t *testing.T, source, peer *PasswordEntry, sourceBefore, peerBefore passwordEditSnapshot) {
	t.Helper()
	if snapshotPasswordEdit(source) != sourceBefore || snapshotPasswordEdit(peer) != peerBefore {
		t.Fatal("viewport synchronization changed text, caret, or selection")
	}
	sourceScroll, peerScroll := nativePasswordScroll(t, source), nativePasswordScroll(t, peer)
	if math.Abs(float64(sourceScroll.Offset.X-peerScroll.Offset.X)) > 0.01 {
		t.Fatalf("password viewports differ: source=%v peer=%v", sourceScroll.Offset, peerScroll.Offset)
	}
}

func TestRevealedPasswordScrollFollowsKeyboardWithoutMovingPeerCaret(t *testing.T) {
	a := newRevealedPasswordScrollUI(t)
	for _, source := range []*PasswordEntry{a.passwordEntry, a.cPasswordEntry} {
		peer := a.passwordEntry
		if source == peer {
			peer = a.cPasswordEntry
		}
		for _, key := range []fyne.KeyName{fyne.KeyEnd, fyne.KeyHome} {
			var sourceBefore, peerBefore passwordEditSnapshot
			fyne.DoAndWait(func() {
				a.Window.Canvas().Focus(peer)
				peer.TypedShortcut(&fyne.ShortcutSelectAll{})
				a.Window.Canvas().Focus(source)
				source.TypedKey(&fyne.KeyEvent{Name: key})
				sourceBefore, peerBefore = snapshotPasswordEdit(source), snapshotPasswordEdit(peer)
			})
			fyne.DoAndWait(func() {
				requirePasswordScrollState(t, source, peer, sourceBefore, peerBefore)
				scroll := nativePasswordScroll(t, source)
				if key == fyne.KeyEnd && scroll.Offset.X <= 0 || key == fyne.KeyHome && scroll.Offset.X != 0 {
					t.Fatalf("native %s did not expose the requested end of the password: %v", key, scroll.Offset)
				}
			})
		}
	}
}

func TestRevealedPasswordScrollFollowsNativeScrollEventsBothWays(t *testing.T) {
	a := newRevealedPasswordScrollUI(t)
	for _, source := range []*PasswordEntry{a.passwordEntry, a.cPasswordEntry} {
		peer := a.passwordEntry
		if source == peer {
			peer = a.cPasswordEntry
		}
		fyne.DoAndWait(func() {
			a.Window.Canvas().Focus(source)
			source.TypedKey(&fyne.KeyEvent{Name: fyne.KeyHome})
		})
		fyne.DoAndWait(func() {})
		for _, delta := range []float32{-160, 80} {
			var before float32
			var sourceBefore, peerBefore passwordEditSnapshot
			fyne.DoAndWait(func() {
				scroll := nativePasswordScroll(t, source)
				before = scroll.Offset.X
				scroll.Scrolled(&fyne.ScrollEvent{Scrolled: fyne.Delta{DX: delta}})
				sourceBefore, peerBefore = snapshotPasswordEdit(source), snapshotPasswordEdit(peer)
			})
			fyne.DoAndWait(func() {
				requirePasswordScrollState(t, source, peer, sourceBefore, peerBefore)
				if offset := nativePasswordScroll(t, source).Offset.X; delta < 0 && offset <= before || delta > 0 && offset >= before {
					t.Fatal("native horizontal scroll event did not move the source viewport")
				}
			})
		}
	}
}

func TestRevealedPasswordScrollClampsShorterPeer(t *testing.T) {
	a := newRevealedPasswordScrollUI(t)
	var sourceBefore, peerBefore passwordEditSnapshot
	fyne.DoAndWait(func() {
		a.cPasswordEntry.SetText(strings.Repeat("b", 160))
		a.Window.Canvas().Focus(a.passwordEntry)
		a.passwordEntry.TypedKey(&fyne.KeyEvent{Name: fyne.KeyEnd})
		sourceBefore, peerBefore = snapshotPasswordEdit(a.passwordEntry), snapshotPasswordEdit(a.cPasswordEntry)
	})
	fyne.DoAndWait(func() {
		peer := nativePasswordScroll(t, a.cPasswordEntry)
		limit := max(float32(0), peer.Content.MinSize().Width-peer.Size().Width)
		if sourceOffset := nativePasswordScroll(t, a.passwordEntry).Offset.X; sourceOffset <= limit || math.Abs(float64(peer.Offset.X-limit)) > 0.01 {
			t.Fatalf("shorter confirmation viewport was not clamped: source=%v peer=%v limit=%v", sourceOffset, peer.Offset.X, limit)
		}
		if snapshotPasswordEdit(a.passwordEntry) != sourceBefore || snapshotPasswordEdit(a.cPasswordEntry) != peerBefore {
			t.Fatal("clamping changed text, caret, or selection")
		}
	})
}

func TestPasswordScrollSyncRequiresTwoAvailableRevealedEncryptionFields(t *testing.T) {
	for _, state := range []string{"masked", "mixed native reveal", "decrypt", "disabled", "hidden confirmation", "shutdown", "shutdown after scroll"} {
		t.Run(state, func(t *testing.T) {
			a := newRevealedPasswordScrollUI(t)
			fyne.DoAndWait(func() {
				switch state {
				case "masked":
					test.Tap(a.showHideBtn)
				case "mixed native reveal":
					test.Tap(a.cPasswordEntry.ActionItem.(fyne.Tappable))
				case "decrypt":
					a.State.Mode = "decrypt"
					a.updateUIState()
				case "disabled":
					a.cPasswordEntry.Disable()
				case "hidden confirmation":
					a.confirmRow.Hide()
				case "shutdown":
					a.stopSourcesAndContexts()
				}
			})
			fyne.DoAndWait(func() {})
			var peerOffset float32
			fyne.DoAndWait(func() {
				source, peer := nativePasswordScroll(t, a.passwordEntry), nativePasswordScroll(t, a.cPasswordEntry)
				source.ScrollToOffset(fyne.NewPos(0, 0))
				peer.ScrollToOffset(fyne.NewPos(0, 0))
				peerOffset = peer.Offset.X
				source.Scrolled(&fyne.ScrollEvent{Scrolled: fyne.Delta{DX: -160}})
				if state == "shutdown after scroll" {
					a.stopSourcesAndContexts()
				}
			})
			fyne.DoAndWait(func() {
				if nativePasswordScroll(t, a.passwordEntry).Offset.X <= 0 {
					t.Fatal("native source viewport stopped scrolling while synchronization was disabled")
				}
				if nativePasswordScroll(t, a.cPasswordEntry).Offset.X != peerOffset {
					t.Fatalf("%s allowed password viewport synchronization", state)
				}
			})
		})
	}
}
