package ui

import (
	"image/color"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
)

type fixedVariantTheme struct {
	fyne.Theme
	variant fyne.ThemeVariant
}

func (t fixedVariantTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	return t.Theme.Color(name, t.variant)
}

func TestOutputDisplayFollowsThemeChanges(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	fyneApp := newTestFyneApp(t)
	darkTheme := fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantDark}
	lightTheme := fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight}
	fyneApp.Settings().SetTheme(darkTheme)

	a, err := NewApp("v2.test")
	if err != nil {
		t.Fatalf("NewApp returned error: %v", err)
	}
	a.fyneApp = fyneApp

	var output fyne.CanvasObject
	fyne.DoAndWait(func() {
		output = a.buildOutputSection()
		output.Resize(output.MinSize())
	})

	fyneApp.Settings().SetTheme(lightTheme)
	fyne.DoAndWait(func() {
		output.Refresh()
	})

	wantLight := lightTheme.Color(theme.ColorNameInputBackground, theme.VariantLight)
	staleDark := darkTheme.Color(theme.ColorNameInputBackground, theme.VariantDark)
	if !hasRectangleFill(output, wantLight) {
		t.Fatalf("output display did not render the light input background after a theme change")
	}
	if hasRectangleFill(output, staleDark) {
		t.Fatalf("output display kept a stale dark input background after a light theme change")
	}
}

func TestDesktopUILayoutFitsWindowAfterBuild(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	cases := []struct {
		name      string
		configure func(*App)
	}{
		{
			name: "initial",
		},
		{
			name: "encrypt",
			configure: func(a *App) {
				a.State.Mode = "encrypt"
				a.State.OnlyFiles = []string{"input.txt"}
				a.State.SetInputSelection(1, 0, 0, false)
				a.State.OutputFile = "input.txt.pcv"
			},
		},
		{
			name: "decrypt",
			configure: func(a *App) {
				a.State.Mode = "decrypt"
				a.State.OnlyFiles = []string{"input.txt.pcv"}
				a.State.SetInputDecryptVolume()
				a.State.OutputFile = "input.txt"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

			a, err := NewApp("v2.test")
			if err != nil {
				t.Fatalf("NewApp returned error: %v", err)
			}
			a.fyneApp = fyneApp
			if tc.configure != nil {
				tc.configure(a)
			}

			var min, size fyne.Size
			fyne.DoAndWait(func() {
				a.Window = fyneApp.NewWindow("layout-test")
				a.Window.SetFixedSize(true)
				a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))
				content := a.buildUI()
				a.Window.SetContent(content)
				a.resizeDesktopWindowForContent(content, preferredDesktopWindowHeight(a.State.Mode))
				min = content.MinSize()
				size = a.Window.Canvas().Size()
			})

			if min.Width > windowWidth {
				t.Fatalf("English %s layout MinSize width %.1f exceeds compact window width %.1f", tc.name, min.Width, float32(windowWidth))
			}
			if size.Width > windowWidth {
				t.Fatalf("English %s layout grew desktop window width to %.1f; want <= %.1f", tc.name, size.Width, float32(windowWidth))
			}
			assertWindowFitsContent(t, a)
		})
	}
}

func TestDesktopRussianUILayoutKeepsCompactWidth(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	resetLocalizationForTest(t)

	cases := []struct {
		name      string
		configure func(*App)
	}{
		{
			name: "initial",
		},
		{
			name: "encrypt",
			configure: func(a *App) {
				a.State.Mode = "encrypt"
				a.State.OnlyFiles = []string{"input.txt"}
				a.State.SetInputSelection(1, 0, 0, false)
				a.State.OutputFile = "input.txt.pcv"
			},
		},
		{
			name: "decrypt",
			configure: func(a *App) {
				a.State.Mode = "decrypt"
				a.State.OnlyFiles = []string{"input.txt.pcv"}
				a.State.SetInputDecryptVolume()
				a.State.InputFile = "input.zip.pcv"
				a.State.OutputFile = "input.zip"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

			a, err := NewApp("v2.test")
			if err != nil {
				t.Fatalf("NewApp returned error: %v", err)
			}
			if err := setActiveLanguage("ru"); err != nil {
				t.Fatalf("setActiveLanguage(ru) returned error: %v", err)
			}
			a.fyneApp = fyneApp
			if tc.configure != nil {
				tc.configure(a)
			}

			var min, size fyne.Size
			fyne.DoAndWait(func() {
				a.Window = fyneApp.NewWindow("russian-layout-test")
				a.Window.SetFixedSize(true)
				a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))
				content := a.buildUI()
				a.Window.SetContent(content)
				a.resizeDesktopWindowForContent(content, preferredDesktopWindowHeight(a.State.Mode))
				min = content.MinSize()
				size = a.Window.Canvas().Size()
			})

			if min.Width > windowWidth {
				t.Fatalf("Russian %s layout MinSize width %.1f exceeds compact window width %.1f", tc.name, min.Width, float32(windowWidth))
			}
			if size.Width > windowWidth {
				t.Fatalf("Russian %s layout grew desktop window width to %.1f; want <= %.1f", tc.name, size.Width, float32(windowWidth))
			}
			assertWindowFitsContent(t, a)
		})
	}
}

func TestDesktopUILayoutKeepsCompactWidthAfterLanguageSwitch(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	resetLocalizationForTest(t)

	cases := []struct {
		name      string
		configure func(*App)
	}{
		{
			name: "encrypt",
			configure: func(a *App) {
				a.State.Mode = "encrypt"
				a.State.OnlyFiles = []string{"input.txt"}
				a.State.SetInputSelection(1, 0, 0, false)
				a.State.OutputFile = "input.txt.pcv"
			},
		},
		{
			name: "decrypt",
			configure: func(a *App) {
				a.State.Mode = "decrypt"
				a.State.OnlyFiles = []string{"input.zip.pcv"}
				a.State.SetInputDecryptVolume()
				a.State.InputFile = "input.zip.pcv"
				a.State.OutputFile = "input.zip"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

			a, err := NewApp("v2.test")
			if err != nil {
				t.Fatalf("NewApp returned error: %v", err)
			}
			a.fyneApp = fyneApp
			tc.configure(a)

			var min, size fyne.Size
			fyne.DoAndWait(func() {
				a.Window = fyneApp.NewWindow("language-switch-layout-test")
				a.Window.SetFixedSize(true)
				a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))
				content := a.buildUI()
				a.Window.SetContent(content)
				a.resizeDesktopWindowForContent(content, preferredDesktopWindowHeight(a.State.Mode))
				if err := a.SwitchLanguage("ru"); err != nil {
					t.Fatalf("SwitchLanguage(ru) returned error: %v", err)
				}
				min = content.MinSize()
				size = a.Window.Canvas().Size()
			})

			if min.Width > windowWidth {
				t.Fatalf("Russian %s layout after language switch MinSize width %.1f exceeds compact window width %.1f", tc.name, min.Width, float32(windowWidth))
			}
			if size.Width > windowWidth {
				t.Fatalf("Russian %s layout after language switch grew desktop window width to %.1f; want <= %.1f", tc.name, size.Width, float32(windowWidth))
			}
			assertWindowFitsContent(t, a)
		})
	}
}

func TestDesktopLanguageSelectorStaysInHeaderOutsideWorkflowControls(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	fyneApp := newTestFyneApp(t)
	a, err := NewApp("v2.test")
	if err != nil {
		t.Fatalf("NewApp returned error: %v", err)
	}
	a.fyneApp = fyneApp

	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("layout-test")
		content := a.buildUI()
		a.Window.SetContent(content)
	})

	if a.languageSelector == nil || a.languageSelector.button == nil {
		t.Fatal("language selector was not built")
	}
	if a.mainContent == nil {
		t.Fatal("mainContent was not built")
	}
	for _, obj := range a.mainContent.Objects {
		if obj == a.languageSelector.button {
			t.Fatal("language selector is inside main workflow content; want header utility control")
		}
	}
}

func TestMobileLanguageSelectorStaysInUtilityRowBeforeFileWorkflow(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	fyneApp := newTestFyneApp(t)
	a, err := NewApp("v2.test")
	if err != nil {
		t.Fatalf("NewApp returned error: %v", err)
	}
	a.fyneApp = fyneApp

	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("mobile-layout-test")
		content := a.buildMobileUI()
		a.Window.SetContent(content)
	})

	if a.languageSelector == nil || a.languageSelector.button == nil {
		t.Fatal("language selector was not built")
	}
	if a.mainContent == nil {
		t.Fatal("mainContent was not built")
	}
	if len(a.mainContent.Objects) < 2 {
		t.Fatalf("mainContent has %d objects; want utility row followed by file workflow", len(a.mainContent.Objects))
	}

	utilityRow := a.mainContent.Objects[0]
	fileWorkflow := a.mainContent.Objects[1]
	if !canvasTreeContainsObject(utilityRow, a.languageSelector.button) {
		t.Fatal("mobile utility row does not contain the language selector")
	}
	if canvasTreeContainsObject(fileWorkflow, a.languageSelector.button) {
		t.Fatal("language selector is inside the mobile file workflow; want utility row before it")
	}
	for i, obj := range a.mainContent.Objects[1:] {
		if canvasTreeContainsObject(obj, a.languageSelector.button) {
			t.Fatalf("language selector is inside mobile workflow control %d; want only the utility row", i+1)
		}
	}
}

func TestDesktopUILayoutFitsWindowAfterModeChange(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

	a, err := NewApp("v2.test")
	if err != nil {
		t.Fatalf("NewApp returned error: %v", err)
	}
	a.fyneApp = fyneApp

	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("layout-test")
		a.Window.SetFixedSize(true)
		a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))
		content := a.buildUI()
		a.Window.SetContent(content)
		a.resizeDesktopWindowForContent(content, preferredDesktopWindowHeight(a.State.Mode))
	})
	assertWindowFitsContent(t, a)

	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.OnlyFiles = []string{"input.txt"}
		a.State.SetInputSelection(1, 0, 0, false)
		a.State.OutputFile = "input.txt.pcv"
		a.updateAdvancedSection()
		a.updateUIState()
	})
	assertWindowFitsContent(t, a)
}

func TestDesktopOutputDisplayLongNameDoesNotGrowWindow(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}

	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

	a, err := NewApp("v2.test")
	if err != nil {
		t.Fatalf("NewApp returned error: %v", err)
	}
	a.fyneApp = fyneApp
	a.State.Mode = "encrypt"
	a.State.OnlyFiles = []string{"input.txt"}
	a.State.SetInputSelection(1, 0, 0, false)
	a.State.OutputFile = filepath.Join("/tmp", strings.Repeat("very-long-output-name-", 20)+".pcv")

	var size fyne.Size
	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("layout-test")
		a.Window.SetFixedSize(true)
		a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))
		content := a.buildUI()
		a.Window.SetContent(content)
		a.resizeDesktopWindowForContent(content, preferredDesktopWindowHeight(a.State.Mode))
		size = a.Window.Canvas().Size()
	})

	if size.Width > windowWidth {
		t.Fatalf("long output basename grew desktop window width to %.1f; want <= %.1f", size.Width, float32(windowWidth))
	}
}

func assertWindowFitsContent(t *testing.T, a *App) {
	t.Helper()

	var min, size fyne.Size
	fyne.DoAndWait(func() {
		content := a.Window.Content()
		min = content.MinSize()
		size = a.Window.Canvas().Size()
	})

	if size.Width < min.Width {
		t.Fatalf("window width %.1f is smaller than content MinSize width %.1f", size.Width, min.Width)
	}
	if size.Height < min.Height {
		t.Fatalf("window height %.1f is smaller than content MinSize height %.1f", size.Height, min.Height)
	}
}

func hasRectangleFill(root fyne.CanvasObject, fill color.Color) bool {
	for _, obj := range test.LaidOutObjects(root) {
		rect, ok := obj.(*canvas.Rectangle)
		if !ok {
			continue
		}
		if sameColor(rect.FillColor, fill) {
			return true
		}
	}
	return false
}

func sameColor(a, b color.Color) bool {
	ar, ag, ab, aa := a.RGBA()
	br, bg, bb, ba := b.RGBA()
	return ar == br && ag == bg && ab == bb && aa == ba
}
