package ui

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLoadTranslations(t *testing.T) {
	resetLocalizationForTest(t)

	for i := range 2 {
		if err := loadTranslations(); err != nil {
			t.Fatalf("loadTranslations call %d returned error: %v", i+1, err)
		}
	}

	if got := tr("status.ready", "fallback"); got != "Ready" {
		t.Fatalf("tr(status.ready) = %q; want Ready", got)
	}

	got := trn("keyfiles.count", "{{.Count}} fallback", 2, map[string]any{"Count": 2})
	if got != "2 keyfiles" {
		t.Fatalf("trn(keyfiles.count, 2) = %q; want 2 keyfiles", got)
	}
}

func TestLocalizationCatalogJSON(t *testing.T) {
	catalog := loadEmbeddedCatalog(t, "translation/en.json")
	if len(catalog) == 0 {
		t.Fatal("translation/en.json is empty")
	}

	for key, value := range catalog {
		if strings.TrimSpace(key) == "" {
			t.Fatal("translation/en.json contains an empty key")
		}
		validateCatalogValue(t, key, value)
	}
}

func TestLocalizationCatalogEmbeddedByLoader(t *testing.T) {
	resetLocalizationForTest(t)

	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("change to temp working directory: %v", err)
	}

	if err := loadTranslations(); err != nil {
		t.Fatalf("loadTranslations from embedded catalog returned error: %v", err)
	}
	if got := tr("status.ready", "fallback"); got != "Ready" {
		t.Fatalf("tr(status.ready) after embedded load = %q; want Ready", got)
	}
	got := trn("keyfiles.count", "{{.Count}} fallback", 2, map[string]any{"Count": 2})
	if got != "2 keyfiles" {
		t.Fatalf("trn(keyfiles.count, 2) after embedded load = %q; want 2 keyfiles", got)
	}
}

func TestRussianFyneCatalogMatchesEnglishKeysAndPlaceholders(t *testing.T) {
	english := loadEmbeddedCatalog(t, "translation/en.json")
	russian := loadEmbeddedCatalog(t, "translation/ru.json")

	assertCatalogMatchesEnglish(t, "translation/ru.json", english, russian)
}

func TestRussianFyneCatalogUsesRussianPluralForms(t *testing.T) {
	english := loadEmbeddedCatalog(t, "translation/en.json")
	russian := loadEmbeddedCatalog(t, "translation/ru.json")

	var failures []string
	for key, englishValue := range english {
		if !isPluralCatalogValue(englishValue) {
			continue
		}
		translated, ok := russian[key].(map[string]any)
		if !ok {
			failures = append(failures, key+": missing Russian plural object")
			continue
		}
		if got, want := sortedMapKeys(translated), []string{"few", "many", "one", "other"}; !sameStringSet(got, want) {
			failures = append(failures, fmt.Sprintf("%s: plural forms = %v; want %v", key, got, want))
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("Russian plural catalog must use one/few/many/other forms:\n%s", strings.Join(failures, "\n"))
	}
}

func TestRussianFyneCatalogPluralizesAtRuntime(t *testing.T) {
	resetLocalizationForTest(t)
	if err := loadTranslations(); err != nil {
		t.Fatalf("loadTranslations returned error: %v", err)
	}
	if err := setActiveLanguage("ru"); err != nil {
		t.Fatalf("setActiveLanguage(ru) returned error: %v", err)
	}

	if got := tr("status.ready", "fallback"); got != "Готов к работе" {
		t.Fatalf("Russian status.ready = %q; want Готов к работе", got)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "one file",
			got:  trn("selection.files", "{{.Count}} files", 1, map[string]any{"Count": 1}),
			want: "1 файл",
		},
		{
			name: "few files",
			got:  trn("selection.files", "{{.Count}} files", 2, map[string]any{"Count": 2}),
			want: "2 файла",
		},
		{
			name: "many files",
			got:  trn("selection.files", "{{.Count}} files", 5, map[string]any{"Count": 5}),
			want: "5 файлов",
		},
		{
			name: "one after many files",
			got:  trn("selection.files", "{{.Count}} files", 21, map[string]any{"Count": 21}),
			want: "21 файл",
		},
		{
			name: "few keyfiles",
			got:  trn("keyfiles.count", "{{.Count}} keyfiles", 3, map[string]any{"Count": 3}),
			want: "3 ключ-файла",
		},
		{
			name: "many completed",
			got:  trn("status.recursive_completed", "Completed ({{.Count}} files)", 11, map[string]any{"Count": 11}),
			want: "Готово (11 файлов)",
		},
	}

	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %q; want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestRussianFyneHighRiskWordingKeepsSecurityMeaning(t *testing.T) {
	catalog := loadEmbeddedCatalog(t, "translation/ru.json")

	assertCatalogStringContains(t, catalog, "advanced.force_decrypt.tooltip", "непровер", "повреж")
	assertCatalogStringContains(t, catalog, "status.kept_output_unverified", "не провер", "повреж")
	assertCatalogStringContains(t, catalog, "comments.placeholder", "открыт", "не шифру")
	assertCatalogStringEquals(t, catalog, "comments.placeholder", "Открытая заметка; не шифруется")
	assertCatalogStringEquals(t, catalog, "keyfiles.label", "Ключ-файлы:")
	assertCatalogStringEquals(t, catalog, "advanced.split.unit.total", "Всего")
	assertCatalogStringEquals(t, catalog, "advanced.delete_files.tooltip", "Удаляет исходные файлы после шифрования")
	assertCatalogStringContains(t, catalog, "advanced.auto_unzip.tooltip", "извлеч", "перезапис")
	assertCatalogStringContains(t, catalog, "advanced.deniability.tooltip", "заголов", "парол", "ключ-файлы")
	assertCatalogStringContains(t, catalog, "advanced.recursively.tooltip", "кажд", "отдель")
	assertCatalogStringContains(t, catalog, "drop.header_may_be_deniable", "может", "правдоподоб")
	assertCatalogStringEquals(t, catalog, "advanced.delete_volume.label", "Удалить зашифрованный том")

	deniabilityCopy := strings.ToLower(catalogString(t, catalog, "advanced.deniability.label") + "\n" +
		catalogString(t, catalog, "advanced.deniability.tooltip") + "\n" +
		catalogString(t, catalog, "drop.header_may_be_deniable"))
	for _, forbidden := range []string{"аноним", "невидим", "скрытый режим"} {
		if strings.Contains(deniabilityCopy, forbidden) {
			t.Fatalf("Russian deniability copy must not contain %q:\n%s", forbidden, deniabilityCopy)
		}
	}

	keyfileCopy := strings.ToLower(catalogString(t, catalog, "keyfiles.label") + "\n" +
		catalogString(t, catalog, "keyfiles.required") + "\n" +
		catalogString(t, catalog, "keyfiles.drop_hint") + "\n" +
		catalogString(t, catalog, "keyfiles.generate_failed") + "\n" +
		catalogString(t, catalog, "keyfiles.write_failed") + "\n" +
		catalogString(t, catalog, "keyfiles.read_access_denied"))
	for _, forbidden := range []string{"ключевой файл", "ключевые файлы", "ключевых"} {
		if strings.Contains(keyfileCopy, forbidden) {
			t.Fatalf("Russian keyfile copy must use ключ-файл/ключ-файлы, not %q:\n%s", forbidden, keyfileCopy)
		}
	}
}

func TestFyneProductionLocaleFilesRequireReviewProof(t *testing.T) {
	entries, err := os.ReadDir("translation")
	if err != nil {
		t.Fatalf("read translation dir: %v", err)
	}

	var productionLocales []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Name() != "en.json" {
			productionLocales = append(productionLocales, entry.Name())
		}
	}
	if len(productionLocales) == 0 {
		return
	}

	var missing []string
	for _, locale := range productionLocales {
		proofPath := productionLocaleProofPath(t, locale)
		if _, err := os.Stat(proofPath); err != nil {
			missing = append(missing, fmt.Sprintf("%s -> %s (%v)", locale, proofPath, err))
		}
	}
	if len(missing) > 0 {
		t.Fatalf("production Fyne locale files require review or round-trip proof:\n%s", strings.Join(missing, "\n"))
	}
}

func TestFyneRoundTripProofPathUsesRepositoryRoot(t *testing.T) {
	proofPath := fyneRoundTripProofPath(t)
	wantDir := filepath.Join(repoRoot(t), "docs", "localization")
	if filepath.Dir(proofPath) != wantDir {
		t.Fatalf("Fyne round-trip proof dir = %q; want repo-root docs/localization dir %q", filepath.Dir(proofPath), wantDir)
	}
	if _, err := os.Stat(wantDir); err != nil {
		t.Fatalf("Fyne round-trip proof dir %q must exist at repo root: %v", wantDir, err)
	}
}

func fyneRoundTripProofPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "docs", "localization", "fyne-weblate-roundtrip.md")
}

func productionLocaleProofPath(t *testing.T, filename string) string {
	t.Helper()
	switch filename {
	case "ru.json":
		return filepath.Join(repoRoot(t), "docs", "localization", "RUSSIAN_TRANSLATION_REVIEW.md")
	default:
		return fyneRoundTripProofPath(t)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	current := wd
	for {
		if _, err := os.Stat(filepath.Join(current, ".github", "workflows")); err == nil {
			return current
		}

		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("could not find repository root from test working directory")
		}
		current = parent
	}
}

func TestAdvancedZipExtensionCatalogUsesTemplateData(t *testing.T) {
	data, err := translationFS.ReadFile("translation/en.json")
	if err != nil {
		t.Fatalf("read embedded en catalog: %v", err)
	}
	var catalog map[string]any
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("parse translation/en.json: %v", err)
	}

	for _, key := range []string{
		"advanced.auto_unzip.tooltip",
		"advanced.same_level.tooltip",
	} {
		value, ok := catalog[key].(string)
		if !ok {
			t.Fatalf("%s is %T; want string", key, catalog[key])
		}
		if strings.Contains(value, ".zip") {
			t.Fatalf("%s exposes .zip as translator-facing prose: %q", key, value)
		}
		if !strings.Contains(value, "{{.Extension}}") {
			t.Fatalf("%s = %q; want {{.Extension}} placeholder", key, value)
		}
	}
}

func TestSelectionMixedCatalogComposesPluralizedPhrases(t *testing.T) {
	data, err := translationFS.ReadFile("translation/en.json")
	if err != nil {
		t.Fatalf("read embedded en catalog: %v", err)
	}
	var catalog map[string]any
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("parse translation/en.json: %v", err)
	}

	for _, key := range []string{
		"selection.file_and_folder",
		"selection.file_and_folders",
		"selection.files_and_folder",
		"selection.files_and_folders",
	} {
		if _, ok := catalog[key]; ok {
			t.Fatalf("%s should be composed from pluralized file/folder phrases, not cataloged as an English-shaped mixed plural", key)
		}
	}

	value, ok := catalog["selection.mixed"].(string)
	if !ok {
		t.Fatalf("selection.mixed is %T; want string", catalog["selection.mixed"])
	}
	if value != "{{.Files}} and {{.Folders}}" {
		t.Fatalf("selection.mixed = %q; want composed phrase template", value)
	}
}

func TestCatalogValueValidationRequiresEnglishPluralForms(t *testing.T) {
	tests := []struct {
		name  string
		value map[string]any
	}{
		{
			name: "missing one",
			value: map[string]any{
				"other": "{{.Count}} files",
			},
		},
		{
			name: "missing other",
			value: map[string]any{
				"one": "{{.Count}} file",
			},
		},
		{
			name: "missing count",
			value: map[string]any{
				"one":   "One file",
				"other": "{{.Count}} files",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := catalogValueValidationError("selection.files", tc.value); err == nil {
				t.Fatal("catalogValueValidationError returned nil; want validation error")
			}
		})
	}

	valid := map[string]any{
		"one":   "{{.Count}} file",
		"other": "{{.Count}} files",
	}
	if err := catalogValueValidationError("selection.files", valid); err != nil {
		t.Fatalf("catalogValueValidationError(valid) = %v; want nil", err)
	}
}

func TestDisplayStringGuardDetectsDirectDisplayLiteral(t *testing.T) {
	source := `package ui

import "fyne.io/fyne/v2/widget"

func rawLabel() {
	_ = widget.NewLabel("Raw visible text")
}
`
	failures := collectRawDisplayStringFailuresFromSource(t, "raw.go", source)
	if len(failures) != 1 {
		t.Fatalf("failures = %#v; want one raw display literal failure", failures)
	}
	if !strings.Contains(failures[0], "Raw visible text") {
		t.Fatalf("failure = %q; want literal text in failure", failures[0])
	}
}

func TestDisplayStringGuardDetectsSetTextLiteral(t *testing.T) {
	source := `package ui

func rawSetText(label interface{ SetText(string) }) {
	label.SetText("Raw visible text")
}
`
	failures := collectRawDisplayStringFailuresFromSource(t, "raw.go", source)
	if len(failures) != 1 {
		t.Fatalf("failures = %#v; want one raw SetText literal failure", failures)
	}
	if !strings.Contains(failures[0], "Raw visible text") {
		t.Fatalf("failure = %q; want literal text in failure", failures[0])
	}
}

func TestDisplayStringGuardUnquotesInterpretedLiterals(t *testing.T) {
	source := `package ui

import "fyne.io/fyne/v2/dialog"

func rawDialog() {
	_ = dialog.NewCustom("Line 1\n\nLine 2", "Close", nil, nil)
}
`
	failures := collectRawDisplayStringFailuresFromSource(t, "raw.go", source)
	if len(failures) != 2 {
		t.Fatalf("failures = %#v; want title and dismiss literal failures", failures)
	}
	if !strings.Contains(failures[0], "\n\n") && !strings.Contains(failures[1], "\n\n") {
		t.Fatalf("failures = %#v; want interpreted newlines, not quoted escape text", failures)
	}
}

func TestCountedHelperFallbacksWithoutLoadedTranslations(t *testing.T) {
	if os.Getenv("PICOCRYPT_LOCALIZATION_FALLBACK_SUBPROCESS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCountedHelperFallbacksWithoutLoadedTranslations$")
		cmd.Env = append(os.Environ(),
			"PICOCRYPT_LOCALIZATION_FALLBACK_SUBPROCESS=1",
			"LANGUAGE=ru_RU",
			"LANG=ru_RU.UTF-8",
			"LC_ALL=",
			"LC_MESSAGES=",
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fallback subprocess failed: %v\n%s", err, output)
		}
		return
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"keyfile singular", keyfileDisplayLabel(false, 1, true), "1 keyfile"},
		{"keyfile plural", keyfileDisplayLabel(false, 2, true), "2 keyfiles"},
		{"selection file singular", selectedFilesLabel(1), "1 file"},
		{"selection file plural", selectedFilesLabel(2), "2 files"},
		{"selection folder singular", selectedFoldersLabel(1), "1 folder"},
		{"selection folder plural", selectedFoldersLabel(2), "2 folders"},
		{"selection mixed", selectionSummary(1, 3), "1 file and 3 folders"},
		{"recursive completed singular", recursiveStatusCompleted(1), "Completed (1 file)"},
		{"recursive completed plural", recursiveStatusCompleted(2), "Completed (2 files)"},
		{"recursive failed singular", recursiveStatusFailedAll(1), "Failed (all 1 file)"},
		{"recursive failed plural", recursiveStatusFailedAll(2), "Failed (all 2 files)"},
	}

	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %q; want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestFyneUIDisplayStringsUseLocalizationCalls(t *testing.T) {
	files := uiProductionGoFiles(t)

	var failures []string
	for _, file := range files {
		failures = append(failures, collectRawDisplayStringFailuresFromFile(t, file)...)
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("display strings must be passed through tr/trn:\n%s", strings.Join(failures, "\n"))
	}
}

func TestFyneUITranslationCallKeysExistInCatalog(t *testing.T) {
	data, err := translationFS.ReadFile("translation/en.json")
	if err != nil {
		t.Fatalf("read embedded en catalog: %v", err)
	}
	var catalog map[string]any
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("parse translation/en.json: %v", err)
	}

	files := uiProductionGoFiles(t)

	var missing []string
	for _, file := range files {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isTranslationCall(call) || len(call.Args) == 0 {
				return true
			}
			callName := translationCallName(call)
			keyLit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || keyLit.Kind != token.STRING {
				missing = append(missing, fset.Position(call.Pos()).String()+": "+callName+" key must be a string literal")
				return true
			}
			key, err := unquoteStringLiteral(keyLit)
			if err != nil {
				missing = append(missing, fset.Position(keyLit.Pos()).String()+": invalid translation key literal: "+err.Error())
				return true
			}
			value, ok := catalog[key]
			if !ok {
				missing = append(missing, fset.Position(keyLit.Pos()).String()+": "+key)
				return true
			}
			if callName == "trn" {
				plural, ok := value.(map[string]any)
				if !ok {
					missing = append(missing, fset.Position(keyLit.Pos()).String()+": "+key+" is not plural")
					return true
				}
				if err := catalogValueValidationError(key, plural); err != nil {
					missing = append(missing, fset.Position(keyLit.Pos()).String()+": "+err.Error())
				}
			}
			return true
		})
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("translation calls without matching catalog entries:\n%s", strings.Join(missing, "\n"))
	}
}

func TestUIStateDoesNotStoreLocalizedDisplayStrings(t *testing.T) {
	files := uiProductionGoFiles(t)
	var failures []string
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		source := string(data)
		for _, bad := range []string{
			".InputLabel = ",
			".StartLabel = ",
			".MainStatus = tr(",
			".PopupStatus = tr(",
			".SetStatus(tr(",
			".SetPopupStatus(tr(",
		} {
			if strings.Contains(source, bad) {
				failures = append(failures, path+": stores localized UI text via "+bad)
			}
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("UI state must store semantic display state, not localized strings:\n%s", strings.Join(failures, "\n"))
	}
}

func TestNewAppLoadsEmbeddedTranslationsBeforeReturning(t *testing.T) {
	resetLocalizationForTest(t)

	if got := tr("status.ready", "fallback"); got != "fallback" {
		t.Fatalf("tr(status.ready) before NewApp = %q; want fallback before embedded translations are loaded", got)
	}

	if _, err := NewApp("v2.test"); err != nil {
		t.Fatalf("NewApp returned error: %v", err)
	}

	if got := tr("status.ready", "fallback"); got != "Ready" {
		t.Fatalf("tr(status.ready) after NewApp = %q; want embedded translation Ready", got)
	}
}

func validateCatalogValue(t *testing.T, key string, value any) {
	t.Helper()

	if err := catalogValueValidationError(key, value); err != nil {
		t.Fatal(err)
	}
}

func loadEmbeddedCatalog(t *testing.T, path string) map[string]any {
	t.Helper()

	data, err := translationFS.ReadFile(path)
	if err != nil {
		t.Fatalf("read embedded catalog %s: %v", path, err)
	}
	if !utf8.Valid(data) {
		t.Fatalf("%s is not valid UTF-8", path)
	}

	var catalog map[string]any
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return catalog
}

func assertCatalogMatchesEnglish(t *testing.T, path string, english, translated map[string]any) {
	t.Helper()

	var failures []string
	for key, englishValue := range english {
		translatedValue, ok := translated[key]
		if !ok {
			failures = append(failures, key+": missing")
			continue
		}
		if isPluralCatalogValue(englishValue) != isPluralCatalogValue(translatedValue) {
			failures = append(failures, key+": plural/string shape differs")
			continue
		}
		if err := catalogValueValidationError(key, translatedValue); err != nil {
			failures = append(failures, key+": "+err.Error())
		}
		if got, want := templatePlaceholders(translatedValue), templatePlaceholders(englishValue); !sameStringSet(got, want) {
			failures = append(failures, fmt.Sprintf("%s: placeholders = %v; want %v", key, got, want))
		}
	}
	for key := range translated {
		if _, ok := english[key]; !ok {
			failures = append(failures, key+": extra")
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("%s must match translation/en.json keys, shapes, and placeholders:\n%s", path, strings.Join(failures, "\n"))
	}
}

func assertCatalogStringContains(t *testing.T, catalog map[string]any, key string, fragments ...string) {
	t.Helper()

	value := strings.ToLower(catalogString(t, catalog, key))
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			t.Fatalf("%s must contain %q: %q", key, fragment, value)
		}
	}
}

func assertCatalogStringEquals(t *testing.T, catalog map[string]any, key, want string) {
	t.Helper()

	if got := catalogString(t, catalog, key); got != want {
		t.Fatalf("%s = %q; want %q", key, got, want)
	}
}

func catalogString(t *testing.T, catalog map[string]any, key string) string {
	t.Helper()

	value, ok := catalog[key]
	if !ok {
		t.Fatalf("missing catalog key %s", key)
	}
	text, ok := value.(string)
	if !ok {
		t.Fatalf("catalog key %s is %T; want string", key, value)
	}
	return text
}

func isPluralCatalogValue(value any) bool {
	_, ok := value.(map[string]any)
	return ok
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var templatePlaceholderPattern = regexp.MustCompile(`{{\s*\.([A-Za-z0-9_]+)\s*}}`)

func templatePlaceholders(value any) []string {
	seen := map[string]bool{}
	collect := func(text string) {
		for _, match := range templatePlaceholderPattern.FindAllStringSubmatch(text, -1) {
			seen[match[1]] = true
		}
	}

	switch v := value.(type) {
	case string:
		collect(v)
	case map[string]any:
		for _, raw := range v {
			if text, ok := raw.(string); ok {
				collect(text)
			}
		}
	}

	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func catalogValueValidationError(key string, value any) error {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("translation %q has an empty value", key)
		}
	case map[string]any:
		for _, form := range []string{"one", "other"} {
			if _, ok := v[form]; !ok {
				return fmt.Errorf("plural translation %q is missing %s", key, form)
			}
		}
		for form, raw := range v {
			if strings.TrimSpace(form) == "" {
				return fmt.Errorf("plural translation %q contains an empty plural form", key)
			}
			text, ok := raw.(string)
			if !ok {
				return fmt.Errorf("plural translation %q form %q has non-string value %T", key, form, raw)
			}
			if strings.TrimSpace(text) == "" {
				return fmt.Errorf("plural translation %q form %q has an empty value", key, form)
			}
			if !strings.Contains(text, "{{.Count}}") {
				return fmt.Errorf("plural translation %q form %q omits {{.Count}}", key, form)
			}
		}
	default:
		return fmt.Errorf("translation %q has unsupported value type %T", key, value)
	}
	return nil
}

func collectRawDisplayStringFailuresFromFile(t *testing.T, file string) []string {
	t.Helper()

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return collectRawDisplayStringFailuresFromSource(t, file, string(data))
}

func collectRawDisplayStringFailuresFromSource(t *testing.T, filename, source string) []string {
	t.Helper()

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filename, source, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	var failures []string
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, argIndex := range displayArgumentIndexes(call) {
			if argIndex >= len(call.Args) {
				continue
			}
			collectRawDisplayStringFailuresInArg(fset, call.Args[argIndex], &failures)
		}
		return true
	})
	return failures
}

func collectRawDisplayStringFailuresInArg(fset *token.FileSet, arg ast.Expr, failures *[]string) {
	if call, ok := arg.(*ast.CallExpr); ok && isTranslationCall(call) {
		return
	}

	ast.Inspect(arg, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isTranslationCall(call) {
			return false
		}
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := unquoteStringLiteral(lit)
		if err != nil {
			*failures = append(*failures, fset.Position(lit.Pos()).String()+": invalid string literal: "+err.Error())
			return true
		}
		if isAllowedDisplayStringLiteral(value) {
			return true
		}
		*failures = append(*failures, fset.Position(lit.Pos()).String()+": "+value)
		return true
	})
}

func isAllowedDisplayStringLiteral(value string) bool {
	// Empty labels are layout placeholders or icon-only buttons. Non-empty
	// technical data such as extensions, schemes, filenames, and mode tokens are
	// intentionally not allowed in display argument positions; pass those through
	// variables or translation template data instead.
	return value == ""
}

func displayArgumentIndexes(call *ast.CallExpr) []int {
	name := callName(call)
	switch name {
	case "configureToolbarButton":
		return []int{1}
	case "NewColoredLabel",
		"newToolbarButton",
		"fyne.NewMenu",
		"widget.NewButton",
		"widget.NewButtonWithIcon",
		"widget.NewCheck",
		"widget.NewHyperlink",
		"widget.NewLabel",
		"widget.NewLabelWithStyle",
		"ttwidget.NewCheck":
		return []int{0}
	case "dialog.NewCustom":
		return []int{0, 1}
	case "dialog.NewCustomWithoutButtons":
		return []int{0}
	case "dialog.NewCustomConfirm":
		return []int{0, 1, 2}
	case "dialog.NewConfirm":
		return []int{0, 1}
	default:
		switch callSelectorName(call) {
		case "SetPlaceHolder", "SetStatus", "SetText", "SetToolTip":
			return []int{0}
		default:
			return nil
		}
	}
}

func callName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			return ident.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	default:
		return ""
	}
}

func callSelectorName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	default:
		return ""
	}
}

func unquoteStringLiteral(lit *ast.BasicLit) (string, error) {
	if lit.Kind != token.STRING {
		return "", fmt.Errorf("literal kind %s is not string", lit.Kind)
	}
	return strconv.Unquote(lit.Value)
}

func isTranslationCall(call *ast.CallExpr) bool {
	return translationCallName(call) != ""
}

func translationCallName(call *ast.CallExpr) string {
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if ident.Name == "tr" || ident.Name == "trn" {
			return ident.Name
		}
	}
	return ""
}
