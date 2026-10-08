package ui

import (
	"Picocrypt-NG/internal/util"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
)

const maxDesktopPolishedEncryptHeight = float32(560)

func TestDesktopWindowKeepsUserSizeAcrossEditsAndClear(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := newDesktopEncryptLayoutApp(t, fyneApp)
	fyne.DoAndWait(func() {
		chosen := fyne.NewSize(600, 400)
		a.Window.Resize(chosen)
		for _, step := range []struct {
			name string
			run  func()
		}{
			{"password", func() { a.passwordEntry.SetText("public layout fixture") }},
			{"advanced", func() {
				a.setAdvancedDisclosureOpen(true)
				a.mainScroll.ScrollToBottom()
			}},
			{"Clear", a.resetUI},
		} {
			step.run()
			if got := a.Window.Canvas().Size(); got != chosen {
				t.Errorf("%s replaced user-selected size %v with %v", step.name, chosen, got)
			}
		}
		if a.mainScroll.Offset.Y != 0 {
			t.Error("Clear did not return to the password at the top of the form")
		}
	})
}

func TestDesktopEmptySelectionKeepsFormVisible(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() { a.initializeDesktopWindow() })
	assertEmpty := func(stage string) {
		t.Helper()
		fyne.DoAndWait(func() {
			test.LaidOutObjects(a.Window.Content())
			visible := make(map[fyne.CanvasObject]bool)
			var collectVisible func(fyne.CanvasObject)
			collectVisible = func(object fyne.CanvasObject) {
				if !object.Visible() {
					return
				}
				visible[object] = true
				switch object := object.(type) {
				case *fyne.Container:
					for _, child := range object.Objects {
						collectVisible(child)
					}
				case *container.Scroll:
					collectVisible(object.Content)
				}
			}
			collectVisible(a.Window.Content())
			viewport := a.fyneApp.Driver().AbsolutePositionForObject(a.mainScroll)
			for _, field := range []fyne.CanvasObject{a.passwordEntry, a.cPasswordEntry, a.keyfileLabel, a.commentsEntry, a.outputEntry.(fyne.CanvasObject), a.changeBtn} {
				if !visible[field] {
					t.Errorf("empty window hides a familiar form field: %T", field)
					continue
				}
				position := a.fyneApp.Driver().AbsolutePositionForObject(field)
				if position.Y < viewport.Y || position.Y+field.Size().Height > viewport.Y+a.mainScroll.Size().Height {
					t.Errorf("%s: empty window clips %T at %v (%v), viewport %v (%v), window %v, mode %q", stage, field, position, field.Size(), viewport, a.mainScroll.Size(), a.Window.Canvas().Size(), a.State.UISnapshot().Mode)
				}
			}
			if a.pcv3Container.Visible() || a.startHintLabel.Visible() {
				t.Error("empty window duplicates the header's file-selection instruction")
			}
			if !a.startButton.Disabled() || !a.passwordEntry.Disabled() || a.inputLabel.Text == "" {
				t.Error("empty window must explain file selection and keep operation controls disabled")
			}
		})
	}
	assertEmpty("startup")
	if t.Failed() {
		return
	}
	path := filepath.Join(t.TempDir(), "message.txt")
	if err := os.WriteFile(path, []byte("public layout fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	fyne.DoAndWait(func() { a.onDrop([]string{path}) })
	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {
		if a.passwordEntry.Disabled() || !a.startHintLabel.Visible() {
			t.Error("selecting a file did not restore the credential form and guidance")
		}
		position := a.fyneApp.Driver().AbsolutePositionForObject(a.passwordEntry)
		viewport := a.fyneApp.Driver().AbsolutePositionForObject(a.mainScroll)
		if position.Y < viewport.Y || position.Y+a.passwordEntry.Size().Height > viewport.Y+a.mainScroll.Size().Height {
			t.Error("selected file's password field is outside the viewport")
		}
		test.Tap(a.clearButton)
	})
	assertEmpty("Clear")
	fyne.DoAndWait(func() {
		a.State.LatchPCV3CleanupIncomplete()
		a.updateUIState()
		if !a.pcv3Container.Visible() {
			t.Error("empty selection hid an unresolved cleanup warning")
		}
		requirePCV3Text(t, a.pcv3Container, "Cleanup could not be confirmed")
	})
}

func TestLongStatusDoesNotResizeDesktopWindow(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() {
		a.updateUIState()
		before := a.Window.Canvas().Size()
		for _, message := range []string{
			"stat /" + strings.Repeat("long-directory/", 80) + "archive.zip: no such file or directory",
			"first error\nsecond error\r\nthird error",
		} {
			a.State.SetStatus(message, util.RED)
			a.updateUIState()
			if after := a.Window.Canvas().Size(); after != before {
				t.Errorf("status resized desktop window from %v to %v", before, after)
			}
		}
	})
}

type fixedVariantTheme struct {
	fyne.Theme
	variant fyne.ThemeVariant
}

func (t fixedVariantTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	return t.Theme.Color(name, t.variant)
}

func TestOutputDisplayFollowsThemeChanges(t *testing.T) {
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

func TestOutputDisplayUsesBasenameOnly(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	a.State.Mode = "encrypt"
	a.State.InputFile = filepath.Join("/tmp", "nested", "input.txt")
	a.State.OnlyFiles = []string{a.State.InputFile}
	a.State.OutputFile = filepath.Join("/tmp", "nested", "deeper", "final-output.pcv")

	fyne.DoAndWait(func() {
		a.updateUIState()
	})

	entry, ok := a.outputEntry.(*OutputDisplay)
	if !ok {
		t.Fatalf("outputEntry type = %T; want *OutputDisplay", a.outputEntry)
	}
	if got, want := entry.Text, "final-output.pcv"; got != want {
		t.Fatalf("output display = %q; want basename %q", got, want)
	}

	fyne.DoAndWait(func() {
		a.State.Recursively = true
		a.updateUIState()
	})
	if got, want := entry.Text, tr("output.multiple_values", "(multiple values)"); got != want {
		t.Fatalf("recursive output display = %q; want %q", got, want)
	}
}

func TestOutputDisplaySplitSuffixIsCompact(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	a.State.Mode = "encrypt"
	a.State.InputFile = "input.txt"
	a.State.OnlyFiles = []string{"input.txt"}
	a.State.OutputFile = filepath.Join("/tmp", "split-target.pcv")
	a.State.Split = true

	fyne.DoAndWait(func() {
		a.updateUIState()
	})

	entry, ok := a.outputEntry.(*OutputDisplay)
	if !ok {
		t.Fatalf("outputEntry type = %T; want *OutputDisplay", a.outputEntry)
	}
	if got, want := entry.Text, "split-target.pcv.*"; got != want {
		t.Fatalf("split output display = %q; want %q", got, want)
	}
}

func TestDesktopUILayoutFitsWindowAfterBuild(t *testing.T) {
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
				a.Window.Resize(fyne.NewSize(windowWidth, windowHeight))
				content := a.buildUI()
				a.Window.SetContent(content)
				a.initializeDesktopWindow()
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
				a.Window.Resize(fyne.NewSize(windowWidth, windowHeight))
				content := a.buildUI()
				a.Window.SetContent(content)
				a.initializeDesktopWindow()
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
				a.Window.Resize(fyne.NewSize(windowWidth, windowHeight))
				content := a.buildUI()
				a.Window.SetContent(content)
				a.initializeDesktopWindow()
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
		a.Window.Resize(fyne.NewSize(windowWidth, windowHeight))
		content := a.buildUI()
		a.Window.SetContent(content)
		a.initializeDesktopWindow()
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

func TestOutputLongNameDoesNotWidenDesktopLayout(t *testing.T) {
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

	var min, size fyne.Size
	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("layout-test")
		a.Window.SetFixedSize(true)
		a.Window.Resize(fyne.NewSize(windowWidth, windowHeight))
		content := a.buildUI()
		a.Window.SetContent(content)
		a.initializeDesktopWindow()
		min = content.MinSize()
		size = a.Window.Canvas().Size()
	})

	if min.Width > windowWidth {
		t.Fatalf("long output basename content MinSize width %.1f exceeds compact window width %.1f", min.Width, float32(windowWidth))
	}
	if size.Width > windowWidth {
		t.Fatalf("long output basename grew desktop window width to %.1f; want <= %.1f", size.Width, float32(windowWidth))
	}
	assertWindowFitsContent(t, a)
}

func TestDesktopOutputDisplayIsPassiveText(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	if _, ok := a.outputEntry.(*OutputDisplay); !ok {
		t.Fatalf("outputEntry type = %T; want passive *OutputDisplay instead of widget.Entry", a.outputEntry)
	}
}

func TestDesktopEncryptLayoutCollapsedAdvancedHeightBudgetEnglish(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

	a := newDesktopEncryptLayoutApp(t, fyneApp)

	var min, size fyne.Size
	fyne.DoAndWait(func() {
		min = a.Window.Content().MinSize()
		size = a.Window.Canvas().Size()
	})

	if min.Width > windowWidth {
		t.Fatalf("English encrypt layout MinSize width %.1f exceeds compact window width %.1f", min.Width, float32(windowWidth))
	}
	if size.Width > windowWidth {
		t.Fatalf("English encrypt layout window width %.1f exceeds compact window width %.1f", size.Width, float32(windowWidth))
	}
	if min.Height > maxDesktopPolishedEncryptHeight {
		t.Fatalf("English collapsed encrypt layout MinSize height %.1f exceeds budget %.1f", min.Height, maxDesktopPolishedEncryptHeight)
	}
}

func TestDesktopEncryptLayoutCollapsedAdvancedHeightBudgetRussian(t *testing.T) {
	resetLocalizationForTest(t)

	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

	a := newDesktopEncryptLayoutApp(t, fyneApp)
	fyne.DoAndWait(func() {
		if err := a.SwitchLanguage("ru"); err != nil {
			t.Fatalf("SwitchLanguage(ru) returned error: %v", err)
		}
	})

	var min, size fyne.Size
	fyne.DoAndWait(func() {
		min = a.Window.Content().MinSize()
		size = a.Window.Canvas().Size()
	})

	if min.Width > windowWidth {
		t.Fatalf("Russian encrypt layout MinSize width %.1f exceeds compact window width %.1f", min.Width, float32(windowWidth))
	}
	if size.Width > windowWidth {
		t.Fatalf("Russian encrypt layout window width %.1f exceeds compact window width %.1f", size.Width, float32(windowWidth))
	}
	if min.Height > maxDesktopPolishedEncryptHeight {
		t.Fatalf("Russian collapsed encrypt layout MinSize height %.1f exceeds budget %.1f", min.Height, maxDesktopPolishedEncryptHeight)
	}
}

func TestDesktopEncryptLayoutExpandedAdvancedKeepsCompactWidthForAllBundledLanguages(t *testing.T) {
	resetLocalizationForTest(t)
	if err := loadTranslations(); err != nil {
		t.Fatalf("loadTranslations returned error: %v", err)
	}

	for _, option := range bundledLanguageOptions() {
		t.Run(string(option.Code), func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

			a := newDesktopEncryptLayoutApp(t, fyneApp)

			var min, size fyne.Size
			fyne.DoAndWait(func() {
				if err := a.SwitchLanguage(option.Code); err != nil {
					t.Fatalf("SwitchLanguage(%s) returned error: %v", option.Code, err)
				}
				if a.advancedToggleBtn == nil {
					t.Fatal("advanced disclosure button was not built")
				}
				a.advancedToggleBtn.OnTapped()
				min = a.Window.Content().MinSize()
				size = a.Window.Canvas().Size()
			})

			if min.Width > windowWidth {
				t.Fatalf("%s expanded encrypt layout MinSize width %.1f exceeds compact window width %.1f", option.Code, min.Width, float32(windowWidth))
			}
			if size.Width > windowWidth {
				t.Fatalf("%s expanded encrypt layout window width %.1f exceeds compact window width %.1f", option.Code, size.Width, float32(windowWidth))
			}
			assertWindowFitsContent(t, a)
		})
	}
}

func TestDesktopAdvancedDisclosureKeepsWindowBounds(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

	a := newDesktopEncryptLayoutApp(t, fyneApp)

	var collapsed, expanded, recollapsed fyne.Size
	var collapsedRange, expandedRange, recollapsedRange float32
	fyne.DoAndWait(func() {
		collapsed = a.Window.Canvas().Size()
		collapsedRange = a.mainScroll.Content.Size().Height - a.mainScroll.Size().Height
		if a.advancedToggleBtn == nil {
			t.Fatal("advanced disclosure button was not built")
		}
		a.advancedToggleBtn.OnTapped()
		expanded = a.Window.Canvas().Size()
		expandedRange = a.mainScroll.Content.Size().Height - a.mainScroll.Size().Height
		a.advancedToggleBtn.OnTapped()
		recollapsed = a.Window.Canvas().Size()
		recollapsedRange = a.mainScroll.Content.Size().Height - a.mainScroll.Size().Height
	})

	if expanded != collapsed || recollapsed != collapsed {
		t.Fatalf("advanced disclosure changed window bounds: %v → %v → %v", collapsed, expanded, recollapsed)
	}
	if expandedRange <= collapsedRange || recollapsedRange > collapsedRange+1 {
		t.Fatalf("scroll range did not follow advanced content: %.1f → %.1f → %.1f", collapsedRange, expandedRange, recollapsedRange)
	}
}

func TestDesktopPasswordEntriesUseFullFormWidth(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})

	a := newDesktopEncryptLayoutApp(t, fyneApp)

	var passwordWidth, confirmWidth, commentsWidth float32
	fyne.DoAndWait(func() {
		a.passwordEntry.SetText("secret")
		a.cPasswordEntry.SetText("secret")
		a.Window.Content().Refresh()

		passwordWidth = a.passwordEntry.Size().Width
		confirmWidth = a.cPasswordEntry.Size().Width
		commentsWidth = a.commentsEntry.Size().Width
	})

	if passwordWidth < commentsWidth-1 {
		t.Fatalf("password entry width %.1f is shorter than full form width %.1f", passwordWidth, commentsWidth)
	}
	if confirmWidth < commentsWidth-1 {
		t.Fatalf("confirm entry width %.1f is shorter than full form width %.1f", confirmWidth, commentsWidth)
	}
}

func TestUpdateNonASCIIHintRelayoutsPasswordSection(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})
	a := newDesktopEncryptLayoutApp(t, fyneApp)

	nonASCII := "caf" + string(rune(0x00E9))
	var baselineY, shownY, hintBottom, restoredY float32
	var hintWidth, hintHeight float32
	var shown, hidden bool

	fyne.DoAndWait(func() {
		baselineY = a.confirmRow.Position().Y

		a.State.Password = nonASCII
		a.updateNonASCIIHint()
		shown = a.nonASCIIHint.Visible()
		hintSize := a.nonASCIIHint.Size()
		hintWidth = hintSize.Width
		hintHeight = hintSize.Height
		hintBottom = a.nonASCIIHint.Position().Y + hintSize.Height
		shownY = a.confirmRow.Position().Y

		a.State.Password = "plain-ascii"
		a.updateNonASCIIHint()
		hidden = !a.nonASCIIHint.Visible()
		restoredY = a.confirmRow.Position().Y
	})

	if !shown {
		t.Fatal("non-ASCII hint was not shown")
	}
	if hintWidth <= 0 || hintHeight <= 0 {
		t.Fatalf("hint size = (%.1f, %.1f); want non-zero laid-out geometry", hintWidth, hintHeight)
	}
	if shownY < baselineY+1 {
		t.Fatalf("confirm row Y %.1f did not move below baseline %.1f", shownY, baselineY)
	}
	if shownY < hintBottom-1 {
		t.Fatalf("confirm row Y %.1f overlaps hint bottom %.1f", shownY, hintBottom)
	}
	if !hidden {
		t.Fatal("non-ASCII hint was not hidden after returning to ASCII")
	}
	restoredDelta := restoredY - baselineY
	if restoredDelta < -1 || restoredDelta > 1 {
		t.Fatalf("confirm row did not return to baseline: baseline %.1f restored %.1f", baselineY, restoredY)
	}
}

func TestDesktopNonASCIIHintLayoutDoesNotDrift(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	fyneApp.Settings().SetTheme(fixedVariantTheme{Theme: NewCompactTheme(), variant: theme.VariantLight})
	a := newDesktopEncryptLayoutApp(t, fyneApp)

	const asciiPassword = "plain-ascii"
	nonASCII := "caf" + string(rune(0x00E9))

	type layoutSnapshot struct {
		hintVisible   bool
		hintWidth     float32
		hintHeight    float32
		hintMinHeight float32
		hintBottom    float32
		confirmY      float32
		windowHeight  float32
	}

	capture := func(password string) layoutSnapshot {
		t.Helper()
		var got layoutSnapshot
		fyne.DoAndWait(func() {
			a.passwordEntry.SetText(password)
			hintSize := a.nonASCIIHint.Size()
			got = layoutSnapshot{
				hintVisible:   a.nonASCIIHint.Visible(),
				hintWidth:     hintSize.Width,
				hintHeight:    hintSize.Height,
				hintMinHeight: a.nonASCIIHint.MinSize().Height,
				hintBottom:    a.nonASCIIHint.Position().Y + hintSize.Height,
				confirmY:      a.confirmRow.Position().Y,
				windowHeight:  a.Window.Canvas().Size().Height,
			}
		})
		assertWindowFitsContent(t, a)
		return got
	}

	baseline := capture(asciiPassword)
	if baseline.hintVisible {
		t.Fatal("non-ASCII hint is visible for the ASCII baseline")
	}

	firstShown := capture(nonASCII)
	firstHidden := capture(asciiPassword)
	secondShown := capture(nonASCII)
	secondHidden := capture(asciiPassword)

	assertShown := func(cycle int, got layoutSnapshot) {
		t.Helper()
		if !got.hintVisible {
			t.Fatalf("cycle %d: non-ASCII hint is hidden", cycle)
		}
		if got.hintWidth <= 0 || got.hintHeight <= 0 {
			t.Fatalf("cycle %d: hint size = (%.1f, %.1f); want non-zero geometry", cycle, got.hintWidth, got.hintHeight)
		}
		if got.hintHeight < got.hintMinHeight-1 {
			t.Fatalf("cycle %d: hint height %.1f clips MinSize height %.1f", cycle, got.hintHeight, got.hintMinHeight)
		}
		if got.confirmY < baseline.confirmY+1 {
			t.Fatalf("cycle %d: confirm row Y %.1f did not move below baseline %.1f", cycle, got.confirmY, baseline.confirmY)
		}
		if got.confirmY < got.hintBottom-1 {
			t.Fatalf("cycle %d: confirm row Y %.1f overlaps hint bottom %.1f", cycle, got.confirmY, got.hintBottom)
		}
	}

	assertHidden := func(cycle int, got layoutSnapshot) {
		t.Helper()
		if got.hintVisible {
			t.Fatalf("cycle %d: non-ASCII hint stayed visible for ASCII password", cycle)
		}
		confirmDelta := got.confirmY - baseline.confirmY
		if confirmDelta < -1 || confirmDelta > 1 {
			t.Fatalf("cycle %d: confirm row drifted from %.1f to %.1f", cycle, baseline.confirmY, got.confirmY)
		}
		windowDelta := got.windowHeight - baseline.windowHeight
		if windowDelta < -1 || windowDelta > 1 {
			t.Fatalf("cycle %d: window height drifted from %.1f to %.1f", cycle, baseline.windowHeight, got.windowHeight)
		}
	}

	assertShown(1, firstShown)
	assertHidden(1, firstHidden)
	assertShown(2, secondShown)
	assertHidden(2, secondHidden)

	shownDelta := secondShown.windowHeight - firstShown.windowHeight
	if shownDelta < -1 || shownDelta > 1 {
		t.Fatalf("visible window height drifted from %.1f to %.1f", firstShown.windowHeight, secondShown.windowHeight)
	}
}

func newDesktopEncryptLayoutApp(t *testing.T, fyneApp fyne.App) *App {
	t.Helper()

	a, err := NewApp("v2.test")
	if err != nil {
		t.Fatalf("NewApp returned error: %v", err)
	}
	a.fyneApp = fyneApp
	a.State.Mode = "encrypt"
	a.State.OnlyFiles = []string{"input.txt"}
	a.State.AllFiles = []string{"input.txt"}
	a.State.SetInputSelection(1, 0, 0, false)
	a.State.Password = "secret"
	a.State.CPassword = "secret"
	a.State.OutputFile = "input.txt.pcv"

	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("encrypt-layout-test")
		a.Window.SetFixedSize(true)
		a.Window.Resize(fyne.NewSize(windowWidth, windowHeight))
		content := a.buildUI()
		a.Window.SetContent(content)
		a.initializeDesktopWindow()
	})

	return a
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
