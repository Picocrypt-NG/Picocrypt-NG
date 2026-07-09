package ui

import (
	"Picocrypt-NG/internal/app"
	"testing"
	"testing/fstest"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

func TestLanguageSelectorClosedTextUsesLanguageCode(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{"status.ready":"Ready"}`)},
		"translation/de.json": {Data: []byte(`{"status.ready":"Bereit"}`)},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	if err := setActiveLanguage("de"); err != nil {
		t.Fatalf("setActiveLanguage(de) returned error: %v", err)
	}

	a := &App{}
	selector := newLanguageSelector(a)
	if selector.button.Text != "de" {
		t.Fatalf("selector closed text = %q; want de", selector.button.Text)
	}
}

func TestLanguageSelectorMenuUsesNativeNamesAndNoIcons(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{"status.ready":"Ready"}`)},
		"translation/fr.json": {Data: []byte(`{"status.ready":"Pret"}`)},
		"translation/it.json": {Data: []byte(`{"status.ready":"Pronto"}`)},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	a := &App{}
	selector := newLanguageSelector(a)
	menu := selector.menu()
	got := make([]string, 0, len(menu.Items))
	for _, item := range menu.Items {
		got = append(got, item.Label)
		if item.Icon != nil {
			t.Fatalf("language menu item %q has an icon; flags/icons are not allowed", item.Label)
		}
	}
	want := []string{"English", "Français", "Italiano"}
	if len(got) != len(want) {
		t.Fatalf("menu labels = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("menu label %d = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestLanguagePreferenceRoundTrip(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	fyneApp.Preferences().SetString(languagePreferenceKey, "fr")

	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{"status.ready":"Ready"}`)},
		"translation/fr.json": {Data: []byte(`{"status.ready":"Pret"}`)},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	a := &App{fyneApp: fyneApp}
	if err := a.loadPreferredLanguage(fyneApp.Preferences()); err != nil {
		t.Fatalf("loadPreferredLanguage returned error: %v", err)
	}
	if got := activeLanguage(); got != "fr" {
		t.Fatalf("activeLanguage after preference load = %q; want fr", got)
	}
	if err := a.SwitchLanguage("en"); err != nil {
		t.Fatalf("SwitchLanguage(en) returned error: %v", err)
	}
	if got := fyneApp.Preferences().StringWithFallback(languagePreferenceKey, ""); got != "en" {
		t.Fatalf("stored language preference = %q; want en", got)
	}
}

func TestLanguageSelectionRelocalizesBuiltDesktopControls(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{
			"action.change":"Change",
			"action.clear":"Clear",
			"action.copy":"Copy",
			"action.create":"Create",
			"action.paste":"Paste",
			"action.start":"Start",
			"comments.label":"Comments:",
			"comments.placeholder":"Public note; not encrypted.",
			"drop.prompt":"Drop",
			"keyfiles.label":"Keyfiles:",
			"keyfiles.none_selected":"None selected",
			"output.label":"Save output as:",
			"password.confirm_label":"Confirm password:",
			"password.confirm_placeholder":"Confirm password",
			"password.label":"Password:",
			"password.non_ascii_hint":"Non-ASCII password hint",
			"password.placeholder":"Password",
			"password.show":"Show",
			"status.ready":"Ready"
		}`)},
		"translation/zz.json": {Data: []byte(`{
			"action.change":"ZZ Change",
			"action.clear":"ZZ Clear",
			"action.copy":"ZZ Copy",
			"action.create":"ZZ Create",
			"action.paste":"ZZ Paste",
			"action.start":"ZZ Start",
			"comments.label":"ZZ Comments:",
			"comments.placeholder":"ZZ Comments",
			"drop.prompt":"ZZ Drop",
			"keyfiles.label":"ZZ Keyfiles:",
			"keyfiles.none_selected":"ZZ None selected",
			"output.label":"ZZ Output:",
			"password.confirm_label":"ZZ Confirm password:",
			"password.confirm_placeholder":"ZZ Confirm password",
			"password.label":"ZZ Password:",
			"password.non_ascii_hint":"ZZ Non-ASCII password hint",
			"password.placeholder":"ZZ Password",
			"password.show":"ZZ Show",
			"status.ready":"ZZ Ready"
		}`)},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	fyneApp := newTestFyneApp(t)
	state, err := app.NewState()
	if err != nil {
		t.Fatalf("NewState returned error: %v", err)
	}
	a := &App{State: state, fyneApp: fyneApp, DPI: 1.0}
	var content fyne.CanvasObject
	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("language-test")
		content = a.buildUI()
		a.Window.SetContent(content)
	})

	if a.clearButton.Text != "Clear" {
		t.Fatalf("initial clearButton.Text = %q; want Clear", a.clearButton.Text)
	}
	if err := a.SwitchLanguage("zz"); err != nil {
		t.Fatalf("SwitchLanguage(zz) returned error: %v", err)
	}
	fyne.DoAndWait(func() {})
	if a.clearButton.Text != "ZZ Clear" {
		t.Fatalf("clearButton.Text after language switch = %q; want ZZ Clear", a.clearButton.Text)
	}
	if a.inputLabel.Text != "ZZ Drop" {
		t.Fatalf("inputLabel.Text after language switch = %q; want ZZ Drop", a.inputLabel.Text)
	}
	if a.startButton.Text != "ZZ Start" {
		t.Fatalf("startButton.Text after language switch = %q; want ZZ Start", a.startButton.Text)
	}
	if a.passwordEntry.PlaceHolder != "ZZ Password" {
		t.Fatalf("password placeholder after language switch = %q; want ZZ Password", a.passwordEntry.PlaceHolder)
	}
	if a.cPasswordEntry.PlaceHolder != "ZZ Confirm password" {
		t.Fatalf("confirm placeholder after language switch = %q; want ZZ Confirm password", a.cPasswordEntry.PlaceHolder)
	}
	if a.commentsEntry.PlaceHolder != "ZZ Comments" {
		t.Fatalf("comments placeholder after language switch = %q; want ZZ Comments", a.commentsEntry.PlaceHolder)
	}

	for _, text := range []string{
		"ZZ Password:",
		"ZZ Confirm password:",
		"ZZ Non-ASCII password hint",
		"ZZ Keyfiles:",
		"ZZ Comments:",
		"ZZ Output:",
	} {
		if !canvasTreeHasLabel(content, text) {
			t.Fatalf("built desktop UI is missing relocalized label %q; labels: %#v", text, collectLabelTexts(content))
		}
	}
	for _, stale := range []string{
		"Password:",
		"Confirm password:",
		"Non-ASCII password hint",
		"Keyfiles:",
		"Comments:",
		"Save output as:",
	} {
		if canvasTreeHasLabel(content, stale) {
			t.Fatalf("built desktop UI kept stale label %q after language switch; labels: %#v", stale, collectLabelTexts(content))
		}
	}
}

func TestLanguageSelectionRelocalizesBuiltMobileControls(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{
			"action.change":"Change",
			"action.clear":"Clear",
			"action.copy":"Copy",
			"action.create":"Create",
			"action.paste":"Paste",
			"action.start":"Start",
			"comments.label":"Comments:",
			"comments.placeholder":"Public note; not encrypted.",
			"drop.prompt":"Drop",
			"keyfiles.label":"Keyfiles:",
			"keyfiles.none_selected":"None selected",
			"mobile.app_storage.button":"App Storage (large files)",
			"mobile.app_storage.tip":"Tip: For large files, copy them to App Storage first",
			"mobile.select_files":"Select Files",
			"mobile.select_folder":"Select Folder",
			"output.label":"Save output as:",
			"password.confirm_label":"Confirm password:",
			"password.confirm_placeholder":"Confirm password",
			"password.label":"Password:",
			"password.placeholder":"Password",
			"password.show":"Show",
			"status.ready":"Ready"
		}`)},
		"translation/zz.json": {Data: []byte(`{
			"action.change":"ZZ Change",
			"action.clear":"ZZ Clear",
			"action.copy":"ZZ Copy",
			"action.create":"ZZ Create",
			"action.paste":"ZZ Paste",
			"action.start":"ZZ Start",
			"comments.label":"ZZ Comments:",
			"comments.placeholder":"ZZ Comments",
			"drop.prompt":"ZZ Drop",
			"keyfiles.label":"ZZ Keyfiles:",
			"keyfiles.none_selected":"ZZ None selected",
			"mobile.app_storage.button":"ZZ App Storage",
			"mobile.app_storage.tip":"ZZ App Storage Tip",
			"mobile.select_files":"ZZ Select Files",
			"mobile.select_folder":"ZZ Select Folder",
			"output.label":"ZZ Output:",
			"password.confirm_label":"ZZ Confirm password:",
			"password.confirm_placeholder":"ZZ Confirm password",
			"password.label":"ZZ Password:",
			"password.placeholder":"ZZ Password",
			"password.show":"ZZ Show",
			"status.ready":"ZZ Ready"
		}`)},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	fyneApp := newTestFyneApp(t)
	state, err := app.NewState()
	if err != nil {
		t.Fatalf("NewState returned error: %v", err)
	}
	a := &App{State: state, fyneApp: fyneApp, DPI: 1.0}
	var content fyne.CanvasObject
	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("mobile-language-test")
		content = a.buildMobileUI()
		a.Window.SetContent(content)
	})

	if err := a.SwitchLanguage("zz"); err != nil {
		t.Fatalf("SwitchLanguage(zz) returned error: %v", err)
	}
	fyne.DoAndWait(func() {})

	if a.passwordEntry.PlaceHolder != "ZZ Password" {
		t.Fatalf("mobile password placeholder after language switch = %q; want ZZ Password", a.passwordEntry.PlaceHolder)
	}
	if a.cPasswordEntry.PlaceHolder != "ZZ Confirm password" {
		t.Fatalf("mobile confirm placeholder after language switch = %q; want ZZ Confirm password", a.cPasswordEntry.PlaceHolder)
	}
	if a.commentsEntry.PlaceHolder != "ZZ Comments" {
		t.Fatalf("mobile comments placeholder after language switch = %q; want ZZ Comments", a.commentsEntry.PlaceHolder)
	}
	for _, text := range []string{
		"ZZ Select Files",
		"ZZ Select Folder",
		"ZZ App Storage",
		"ZZ App Storage Tip",
		"ZZ Password:",
		"ZZ Confirm password:",
		"ZZ Keyfiles:",
		"ZZ Comments:",
		"ZZ Output:",
	} {
		if !canvasTreeHasText(a.mainContent, text) {
			t.Fatalf("built mobile UI is missing relocalized text %q; texts: %#v", text, collectCanvasTexts(a.mainContent))
		}
	}
	for _, stale := range []string{
		"Select Files",
		"Select Folder",
		"App Storage (large files)",
		"Tip: For large files, copy them to App Storage first",
		"Password:",
		"Confirm password:",
		"Keyfiles:",
		"Comments:",
		"Save output as:",
	} {
		if canvasTreeHasText(a.mainContent, stale) {
			t.Fatalf("built mobile UI kept stale text %q after language switch; texts: %#v", stale, collectCanvasTexts(a.mainContent))
		}
	}
}

func canvasTreeHasLabel(root fyne.CanvasObject, want string) bool {
	for _, text := range collectLabelTexts(root) {
		if text == want {
			return true
		}
	}
	return false
}

func canvasTreeHasText(root fyne.CanvasObject, want string) bool {
	for _, text := range collectCanvasTexts(root) {
		if text == want {
			return true
		}
	}
	return false
}

func collectLabelTexts(root fyne.CanvasObject) []string {
	texts := make([]string, 0)
	walkCanvasTree(root, func(obj fyne.CanvasObject) {
		if label, ok := obj.(*widget.Label); ok {
			texts = append(texts, label.Text)
		}
	})
	return texts
}

func collectCanvasTexts(root fyne.CanvasObject) []string {
	texts := make([]string, 0)
	walkCanvasTree(root, func(obj fyne.CanvasObject) {
		switch typed := obj.(type) {
		case *widget.Button:
			texts = append(texts, typed.Text)
		case *widget.Label:
			texts = append(texts, typed.Text)
		}
	})
	return texts
}

func canvasTreeContainsObject(root, target fyne.CanvasObject) bool {
	found := false
	walkCanvasTree(root, func(obj fyne.CanvasObject) {
		if obj == target {
			found = true
		}
	})
	return found
}

func walkCanvasTree(root fyne.CanvasObject, visit func(fyne.CanvasObject)) {
	if root == nil {
		return
	}
	visit(root)
	if container, ok := root.(*fyne.Container); ok {
		for _, child := range container.Objects {
			walkCanvasTree(child, visit)
		}
	}
}
