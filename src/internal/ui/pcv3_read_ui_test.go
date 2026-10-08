package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func newPCV3ReadUI(t *testing.T, format app.PCV3Format) *App {
	t.Helper()
	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(NewCompactTheme())
	a := createUIReadyDropTestApp(t, fyneApp)
	input := filepath.Join(t.TempDir(), "input.pcv")
	if err := os.WriteFile(input, loadPCV3DropFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fyne.DoAndWait(a.State.Reset) })
	fyne.DoAndWait(func() { a.onDrop([]string{input}) })
	waitForPCV3UI(t, func() bool { return a.State.UISnapshot().PCV3Route == app.PCV3RouteReady }, "PCV3 routing did not complete")
	if format == app.PCV3FormatD1 {
		fyne.DoAndWait(func() {
			if !a.advancedOpen {
				test.Tap(a.advancedToggleBtn)
			}
			button := a.pcv3FormatButton
			if button == nil {
				t.Fatal("format menu missing")
			}
			a.mainScroll.ScrollToBottom()
			position := a.fyneApp.Driver().AbsolutePositionForObject(button)
			viewport := a.fyneApp.Driver().AbsolutePositionForObject(a.mainScroll)
			if position.Y < viewport.Y || position.Y+button.Size().Height > viewport.Y+a.mainScroll.Size().Height {
				t.Error("explicit D1 action is outside the visible scroll viewport")
				return
			}
			menu := openPCV3FormatMenu(t, a)
			menu.TypedKey(&fyne.KeyEvent{Name: fyne.KeyDown})
			menu.TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
		})
	}
	return a
}

func openPCV3FormatMenu(t *testing.T, a *App) *widget.PopUpMenu {
	t.Helper()
	if a.pcv3FormatButton == nil {
		t.Fatal("Normal format menu is missing")
	}
	test.Tap(a.pcv3FormatButton)
	menu, ok := a.Window.Canvas().Focused().(*widget.PopUpMenu)
	if !ok {
		t.Fatal("format button did not open a keyboard-accessible menu")
	}
	return menu
}

func TestPCV3ReadUIStartsCompactAndKeepsStartReachable(t *testing.T) {
	for _, format := range []app.PCV3Format{app.PCV3FormatNormal, app.PCV3FormatD1} {
		t.Run(map[app.PCV3Format]string{app.PCV3FormatNormal: "normal", app.PCV3FormatD1: "D1"}[format], func(t *testing.T) {
			a := newPCV3ReadUI(t, format)
			fyne.DoAndWait(func() {
				snap := a.State.UISnapshot()
				if snap.PCV3Format != format || snap.PCV3Action != app.PCV3ActionDecrypt {
					t.Errorf("ready selection = format %v action %v; want ordinary decryption", snap.PCV3Format, snap.PCV3Action)
				}
				if a.passwordEntry.Disabled() || a.keyfileEditBtn.Disabled() {
					t.Error("ready PCV3 selection blocks credential entry")
				}
				passwordPosition := a.fyneApp.Driver().AbsolutePositionForObject(a.passwordEntry)
				viewport := a.fyneApp.Driver().AbsolutePositionForObject(a.mainScroll)
				if passwordPosition.Y < viewport.Y || passwordPosition.Y+a.passwordEntry.Size().Height > viewport.Y+a.mainScroll.Size().Height {
					t.Error("opening a volume leaves the password outside the visible scroll viewport")
				}
				if a.advancedOpen {
					t.Error("ordinary decryption expands recovery controls")
				}
				if a.Window.Canvas().Size().Height > windowHeight {
					t.Errorf("ready PCV3 window exceeds normal height: %v", a.Window.Canvas().Size())
				}
				a.passwordEntry.SetText("public test password")
				if a.startButton.Disabled() {
					t.Error("password entry does not enable ordinary decryption")
				}
				a.setAdvancedDisclosureOpen(true)
				a.Window.Resize(fyne.NewSize(windowWidth, 300))
				position := a.fyneApp.Driver().AbsolutePositionForObject(a.startButton)
				if position.Y < 0 || position.Y+a.startButton.Size().Height > a.Window.Canvas().Size().Height {
					t.Error("Start is outside a small window")
				}
				scroll := findPCV3Scroll(a.Window.Content())
				if scroll == nil || scroll.Content.Size().Height <= scroll.Size().Height {
					t.Error("small window does not offer scrolling for the remaining controls")
					return
				}
				scroll.Scrolled(&fyne.ScrollEvent{Scrolled: fyne.Delta{DY: -200}})
				if scroll.Offset.Y == 0 {
					t.Error("body cannot scroll")
				}
				if after := a.fyneApp.Driver().AbsolutePositionForObject(a.startButton); after != position {
					t.Error("scrolling fields moved the Start button")
				}
			})
		})
	}
}

// This checks the GUI-to-runner request, not cryptographic acceptance. The real
// runner receives an already cancelled context so no expensive KDF is needed.
func TestPCV3ReadUITransfersEveryEnteredFactor(t *testing.T) {
	for _, format := range []app.PCV3Format{app.PCV3FormatNormal, app.PCV3FormatD1} {
		for _, factors := range []struct {
			name     string
			password string
			keys     int
			ordered  bool
			mode     pcv3operation.CredentialMode
			policy   pcv3operation.FactorPolicy
			order    pcv3operation.KeyfileMode
		}{
			{"password", "  password with spaces  ", 0, false, pcv3operation.CredentialModePasswordOnly, pcv3operation.FactorPolicyPasswordOnly, pcv3operation.KeyfileModeNone},
			{"keyfile", "", 1, false, pcv3operation.CredentialModeKeyfilesOnly, pcv3operation.FactorPolicyKeyfilesOnly, pcv3operation.KeyfileModeUnordered},
			{"one-keyfile-ordered", "", 1, true, pcv3operation.CredentialModeKeyfilesOnly, pcv3operation.FactorPolicyKeyfilesOnly, pcv3operation.KeyfileModeOrdered},
			{"combined", "public password", 2, true, pcv3operation.CredentialModePasswordAndKeyfiles, pcv3operation.FactorPolicyPasswordAndKeyfiles, pcv3operation.KeyfileModeOrdered},
		} {
			t.Run(map[app.PCV3Format]string{app.PCV3FormatNormal: "normal", app.PCV3FormatD1: "D1"}[format]+"/"+factors.name, func(t *testing.T) {
				a := newPCV3ReadUI(t, format)
				keyfiles := make([]string, factors.keys)
				for index := range keyfiles {
					keyfiles[index] = filepath.Join(t.TempDir(), "factor.key")
					if err := os.WriteFile(keyfiles[index], []byte{byte(index + 1)}, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				type observedRequest struct {
					mode       pcv3operation.Mode
					factorMode pcv3operation.CredentialMode
					policy     pcv3operation.FactorPolicy
					order      pcv3operation.KeyfileMode
					password   string
					keyCount   int
					protected  []string
				}
				observed := make(chan observedRequest, 1)
				a.pcv3OperationExecutor = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
					observed <- observedRequest{request.Mode, request.Factors.Mode, request.Factors.ExpectedPolicy, request.Factors.KeyfileMode, string(request.Factors.Password), len(request.Factors.Keyfiles), append([]string(nil), request.Protected...)}
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return pcv3operation.Run(ctx, request)
				}
				fyne.DoAndWait(func() {
					a.passwordEntry.SetText(factors.password)
					if len(keyfiles) > 0 {
						a.keyfileEditBtn.OnTapped()
						a.onDrop(keyfiles)
						if a.keyfileOrderCheck == nil {
							t.Error("PCV3 keyfile manager has no order control")
							return
						}
						a.keyfileOrderCheck.SetChecked(factors.ordered)
						a.keyfileModal.Hide()
						a.State.ShowKeyfile = false
					}
					if a.startButton.Disabled() {
						t.Error("entered factors did not enable Start")
						return
					}
					a.startButton.OnTapped()
				})
				if t.Failed() {
					return
				}
				select {
				case got := <-observed:
					mode := pcv3operation.ModeReadNormal
					if format == app.PCV3FormatD1 {
						mode = pcv3operation.ModeReadD1
					}
					if got.mode != mode || got.factorMode != factors.mode || got.policy != factors.policy || got.order != factors.order || got.password != factors.password || got.keyCount != len(keyfiles) || !slices.Equal(got.protected, keyfiles) {
						t.Error("GUI request changed the entered factor combination, order, or read mode")
					}
				case <-time.After(2 * time.Second):
					t.Error("Start did not dispatch the read request")
				}
				a.workers.wait()
				fyne.DoAndWait(func() {})
			})
		}
	}
}
