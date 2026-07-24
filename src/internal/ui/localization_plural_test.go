package ui

import (
	"encoding/json"
	"fmt"
	"testing"
	"testing/fstest"
)

func TestTargetLocalePluralRulesAtRuntime(t *testing.T) {
	tests := []struct {
		code   LanguageCode
		forms  []string
		probes map[int]string
	}{
		{
			code:  "de",
			forms: []string{"one", "other"},
			probes: map[int]string{
				0: "other",
				1: "one",
				2: "other",
			},
		},
		{
			code:  "fr",
			forms: []string{"one", "many", "other"},
			probes: map[int]string{
				0:       "one",
				1:       "one",
				2:       "other",
				1000000: "many",
			},
		},
		{
			code:  "es",
			forms: []string{"one", "many", "other"},
			probes: map[int]string{
				0:       "other",
				1:       "one",
				2:       "other",
				1000000: "many",
			},
		},
		{
			code:  "zh-Hans",
			forms: []string{"other"},
			probes: map[int]string{
				0: "other",
				1: "other",
				2: "other",
			},
		},
		{
			code:  "hi",
			forms: []string{"one", "other"},
			probes: map[int]string{
				0: "one",
				1: "one",
				2: "other",
			},
		},
		{
			code:  "ko",
			forms: []string{"other"},
			probes: map[int]string{
				0: "other",
				1: "other",
				2: "other",
			},
		},
	}

	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			resetLocalizationForTest(t)
			pluralMessage := make(map[string]string, len(tc.forms))
			for _, form := range tc.forms {
				pluralMessage[form] = form + " {{.Count}}"
			}
			catalogData, err := json.Marshal(map[string]any{
				"selection.files": pluralMessage,
			})
			if err != nil {
				t.Fatalf("marshal %s catalog fixture: %v", tc.code, err)
			}

			testFS := fstest.MapFS{
				"translation/en.json": {
					Data: []byte(`{"selection.files":{"one":"one {{.Count}}","other":"other {{.Count}}"}}`),
				},
				"translation/" + string(tc.code) + ".json": {
					Data: catalogData,
				},
			}
			if err := loadTranslationsFromFS(testFS); err != nil {
				t.Fatalf("loadTranslationsFromFS(%s) returned error: %v", tc.code, err)
			}
			if err := setActiveLanguage(tc.code); err != nil {
				t.Fatalf("setActiveLanguage(%s) returned error: %v", tc.code, err)
			}
			if got := activeLanguage(); got != tc.code {
				t.Fatalf("activeLanguage = %q; want %q", got, tc.code)
			}

			for count, wantForm := range tc.probes {
				got := trn("selection.files", "fallback {{.Count}}", count, map[string]any{"Count": count})
				want := fmt.Sprintf("%s %d", wantForm, count)
				if got != want {
					t.Errorf("%s plural for %d = %q; want %q", tc.code, count, got, want)
				}
			}
		})
	}
}
