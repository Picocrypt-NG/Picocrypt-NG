package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"
	"testing"
	"testing/fstest"
)

func TestProjectLocalTranslatorSwitchesActiveLanguage(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {
			Data: []byte(`{"status.ready":"Ready","selection.files":{"one":"{{.Count}} file","other":"{{.Count}} files"}}`),
		},
		"translation/zz.json": {
			Data: []byte(`{"status.ready":"ZZ Ready","selection.files":{"one":"{{.Count}} zz-file","other":"{{.Count}} zz-files"}}`),
		},
	}

	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	if got := tr("status.ready", "fallback"); got != "Ready" {
		t.Fatalf("default tr(status.ready) = %q; want Ready", got)
	}
	if err := setActiveLanguage("zz"); err != nil {
		t.Fatalf("setActiveLanguage(zz) returned error: %v", err)
	}
	if got := tr("status.ready", "fallback"); got != "ZZ Ready" {
		t.Fatalf("tr(status.ready) after language switch = %q; want ZZ Ready", got)
	}
	if got := trn("selection.files", "{{.Count}} files", 2, map[string]any{"Count": 2}); got != "2 zz-files" {
		t.Fatalf("trn(selection.files, 2) = %q; want 2 zz-files", got)
	}
}

func TestProjectLocalTranslatorRejectsUnavailableLanguage(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {
			Data: []byte(`{"status.ready":"Ready"}`),
		},
	}

	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	if err := setActiveLanguage("ru"); err == nil {
		t.Fatal("setActiveLanguage(ru) returned nil; want unavailable-language error")
	}
	if got := activeLanguage(); got != "en" {
		t.Fatalf("activeLanguage after rejected switch = %q; want en", got)
	}
}

func TestBundledLanguageOptionsOnlyIncludesLoadedCatalogs(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {
			Data: []byte(`{"status.ready":"Ready"}`),
		},
		"translation/fr.json": {
			Data: []byte(`{"status.ready":"Pret"}`),
		},
	}

	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	got := bundledLanguageOptions()
	want := []LanguageOption{
		{Code: "en", Name: "English"},
		{Code: "fr", Name: "Français"},
	}
	if len(got) != len(want) {
		t.Fatalf("bundledLanguageOptions length = %d; want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bundledLanguageOptions[%d] = %#v; want %#v", i, got[i], want[i])
		}
	}
}

func TestRequestedDesktopLocalesHaveStableMetadata(t *testing.T) {
	want := map[LanguageCode]LanguageOption{
		"de":      {Code: "de", Name: "Deutsch"},
		"fr":      {Code: "fr", Name: "Français"},
		"es":      {Code: "es", Name: "Español"},
		"zh-Hans": {Code: "zh-Hans", Name: "简体中文", ButtonLabel: "zh"},
		"hi":      {Code: "hi", Name: "हिन्दी"},
		"ko":      {Code: "ko", Name: "한국어"},
	}

	for _, option := range knownLanguageOptions {
		if expected, ok := want[option.Code]; ok {
			if option != expected {
				t.Errorf("language metadata for %q = %#v; want %#v", option.Code, option, expected)
			}
			delete(want, option.Code)
		}
	}
	if len(want) != 0 {
		t.Fatalf("requested desktop locales are not registered: %#v", want)
	}
}

func TestRuntimeLanguageSwitchRerendersInputSummary(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {
			Data: []byte(`{
				"drop.prompt":"Drop files and folders into this window",
				"selection.files":{"one":"{{.Count}} file","other":"{{.Count}} files"},
				"selection.folders":{"one":"{{.Count}} folder","other":"{{.Count}} folders"},
				"selection.mixed":"{{.Files}} and {{.Folders}}",
				"selection.with_size":"{{.Label}} ({{.Size}})",
				"selection.scanning_files":"Scanning files... ({{.Size}})",
				"selection.volume_for_decryption":"Volume for decryption"
			}`),
		},
		"translation/zz.json": {
			Data: []byte(`{
				"drop.prompt":"ZZ drop",
				"selection.files":{"one":"{{.Count}} zz-file","other":"{{.Count}} zz-files"},
				"selection.folders":{"one":"{{.Count}} zz-folder","other":"{{.Count}} zz-folders"},
				"selection.mixed":"{{.Files}} + {{.Folders}}",
				"selection.with_size":"{{.Label}} [{{.Size}}]",
				"selection.scanning_files":"ZZ scan {{.Size}}",
				"selection.volume_for_decryption":"ZZ volume"
			}`),
		},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	summary := app.InputSummary{Kind: app.InputSummarySelection, Files: 1, Folders: 2, SizeBytes: 4096, ShowSize: true}
	if got := renderInputSummary(summary); got != "1 file and 2 folders (4.00 KiB)" {
		t.Fatalf("renderInputSummary(en) = %q; want English mixed label", got)
	}
	if err := setActiveLanguage("zz"); err != nil {
		t.Fatalf("setActiveLanguage(zz) returned error: %v", err)
	}
	if got := renderInputSummary(summary); got != "1 zz-file + 2 zz-folders [4.00 KiB]" {
		t.Fatalf("renderInputSummary(zz) = %q; want relocalized mixed label", got)
	}
}

func TestRuntimeLanguageSwitchRerendersStartAction(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {
			Data: []byte(`{"action.start":"Start","action.encrypt":"Encrypt","action.decrypt":"Decrypt","action.zip_and_encrypt":"Zip and Encrypt","action.process":"Process"}`),
		},
		"translation/zz.json": {
			Data: []byte(`{"action.start":"ZZ Start","action.encrypt":"ZZ Encrypt","action.decrypt":"ZZ Decrypt","action.zip_and_encrypt":"ZZ Zip","action.process":"ZZ Process"}`),
		},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	if got := renderStartAction(app.StartActionZipAndEncrypt, false); got != "Zip and Encrypt" {
		t.Fatalf("renderStartAction(en) = %q; want Zip and Encrypt", got)
	}
	if err := setActiveLanguage("zz"); err != nil {
		t.Fatalf("setActiveLanguage(zz) returned error: %v", err)
	}
	if got := renderStartAction(app.StartActionZipAndEncrypt, false); got != "ZZ Zip" {
		t.Fatalf("renderStartAction(zz) = %q; want ZZ Zip", got)
	}
	if got := renderStartAction(app.StartActionEncrypt, true); got != "ZZ Process" {
		t.Fatalf("renderStartAction(recursive zz) = %q; want ZZ Process", got)
	}
}

func TestCustomReporterStatusSurvivesLanguageSwitch(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{"status.completed":"Completed"}`)},
		"translation/zz.json": {Data: []byte(`{"status.completed":"ZZ Completed"}`)},
	}
	if err := loadTranslationsFromFS(testFS); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	status := app.StatusMessage{Kind: app.StatusCustom, Text: "Encrypting...", Color: util.WHITE}

	if err := setActiveLanguage("zz"); err != nil {
		t.Fatalf("setActiveLanguage(zz) returned error: %v", err)
	}
	if got := renderStatus(status, app.UISnapshot{}); got != "Encrypting..." {
		t.Fatalf("renderStatus(custom) = %q; want raw reporter text", got)
	}
}

func resetLocalizationForTest(t *testing.T) {
	t.Helper()
	original := localizationState
	localizationState = newLocalizationState()
	t.Cleanup(func() {
		localizationState = original
	})
}
