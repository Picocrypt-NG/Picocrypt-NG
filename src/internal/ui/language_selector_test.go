package ui

import (
	"Picocrypt-NG/internal/app"
	"testing"
	"testing/fstest"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

func TestLanguageButtonLabelUsesCompactChineseCode(t *testing.T) {
	tests := []struct {
		code LanguageCode
		want string
	}{
		{code: "en", want: "en"},
		{code: "de", want: "de"},
		{code: "zh-Hans", want: "zh"},
		{code: "hi", want: "hi"},
		{code: "zz", want: "zz"},
	}

	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			if got := languageButtonLabel(tc.code); got != tc.want {
				t.Fatalf("languageButtonLabel(%q) = %q; want %q", tc.code, got, tc.want)
			}
		})
	}
}

func TestChineseLanguagePreferenceKeepsFullCodeWhileSelectorShowsZh(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json":      {Data: []byte(`{"status.ready":"Ready"}`)},
		"translation/zh-Hans.json": {Data: []byte(`{"status.ready":"就绪"}`)},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	a := &App{fyneApp: fyneApp}
	selector := newLanguageSelector(a)
	a.languageSelector = selector
	if got := selector.button.Text; got != "en" {
		t.Fatalf("initial selector closed text = %q; want en", got)
	}

	var chineseItem *fyne.MenuItem
	for _, item := range selector.menu().Items {
		if item.Label == "简体中文" {
			chineseItem = item
			break
		}
	}
	if chineseItem == nil {
		t.Fatal("language selector menu is missing 简体中文")
	}
	if chineseItem.Action == nil {
		t.Fatal("简体中文 language selector item has no action")
	}
	chineseItem.Action()

	if got := activeLanguage(); got != "zh-Hans" {
		t.Errorf("activeLanguage after menu action = %q; want zh-Hans", got)
	}
	if got := fyneApp.Preferences().StringWithFallback(languagePreferenceKey, ""); got != "zh-Hans" {
		t.Errorf("stored language preference after menu action = %q; want zh-Hans", got)
	}
	if got := selector.button.Text; got != "zh" {
		t.Errorf("selector closed text after menu action = %q; want zh", got)
	}
	if err := setActiveLanguage("en"); err != nil {
		t.Fatalf("setActiveLanguage(en) returned error: %v", err)
	}
	if err := a.loadPreferredLanguage(fyneApp.Preferences()); err != nil {
		t.Fatalf("loadPreferredLanguage returned error: %v", err)
	}
	if got := activeLanguage(); got != "zh-Hans" {
		t.Fatalf("activeLanguage after preference restore = %q; want zh-Hans", got)
	}
}

func TestKoreanEmbeddedCatalogDrivesLanguageSelectionAndRendering(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	resetLocalizationForTest(t)
	if err := loadTranslations(); err != nil {
		t.Fatalf("loadTranslations returned error: %v", err)
	}

	a := &App{fyneApp: fyneApp}
	selector := newLanguageSelector(a)
	a.languageSelector = selector

	var koreanItem *fyne.MenuItem
	for _, item := range selector.menu().Items {
		if item.Label == "한국어" {
			koreanItem = item
			break
		}
	}
	if koreanItem == nil {
		t.Fatal("language selector menu is missing 한국어 from the embedded Korean catalog")
	}
	if koreanItem.Action == nil {
		t.Fatal("한국어 language selector item has no action")
	}
	koreanItem.Action()

	if got := activeLanguage(); got != "ko" {
		t.Errorf("activeLanguage after Korean menu action = %q; want ko", got)
	}
	if got := fyneApp.Preferences().StringWithFallback(languagePreferenceKey, ""); got != "ko" {
		t.Errorf("stored language preference after Korean menu action = %q; want ko", got)
	}
	if got := selector.button.Text; got != "ko" {
		t.Errorf("selector closed text after Korean menu action = %q; want ko", got)
	}
	if got := renderStartAction(app.StartActionStart, false); got != "시작" {
		t.Errorf("renderStartAction(Korean) = %q; want 시작", got)
	}
	if got := tr("status.ready", "Ready"); got != "준비됨" {
		t.Errorf("tr(status.ready, Korean) = %q; want 준비됨", got)
	}
	if got := trn("selection.files", "{{.Count}} files", 2, map[string]any{"Count": 2}); got != "파일 2개" {
		t.Errorf("trn(selection.files, 2, Korean) = %q; want 파일 2개", got)
	}
	if got := tr(
		"advanced.auto_unzip.tooltip",
		"Extract {{.Extension}}; may overwrite files",
		map[string]any{"Extension": ".zip"},
	); got != ".zip 파일의 압축을 풉니다. 기존 파일을 덮어쓸 수 있습니다" {
		t.Errorf("tr(advanced.auto_unzip.tooltip, Korean) = %q; want rendered Korean template", got)
	}
}

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
		"translation/en.json":      {Data: []byte(`{"status.ready":"Ready"}`)},
		"translation/fr.json":      {Data: []byte(`{"status.ready":"Pret"}`)},
		"translation/it.json":      {Data: []byte(`{"status.ready":"Pronto"}`)},
		"translation/zh-Hans.json": {Data: []byte(`{"status.ready":"就绪"}`)},
		"translation/hi.json":      {Data: []byte(`{"status.ready":"तैयार"}`)},
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
	want := []string{"English", "Français", "Italiano", "简体中文", "हिन्दी"}
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
