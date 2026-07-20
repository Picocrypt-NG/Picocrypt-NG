package mobile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestClassifyStatusStatic(t *testing.T) {
	tests := []struct {
		text string
		code string
	}{
		{text: "Starting...", code: "STARTING"},
		{text: "Completed", code: "COMPLETED"},
		{text: "Cancelled", code: "CANCELLED"},
		{text: "Error", code: "ERROR"},
		{text: "Compressing files...", code: "COMPRESSING_FILES"},
		{text: "Generating values...", code: "GENERATING_VALUES"},
		{text: "Deriving key...", code: "DERIVING_KEY"},
		{text: "Reading keyfiles...", code: "READING_KEYFILES"},
		{text: "Calculating values...", code: "CALCULATING_VALUES"},
		{text: "Writing values...", code: "WRITING_VALUES"},
		{text: "Splitting...", code: "SPLITTING"},
		{text: "Recombining chunks...", code: "RECOMBINING_CHUNKS"},
		{text: "Reading values...", code: "READING_VALUES"},
		{text: "Warning: duplicate keyfiles detected (keys cancel out)...", code: "DUPLICATE_KEYFILES_WARNING"},
		{text: "Verifying integrity (pass 1 of 2)...", code: "VERIFYING_INTEGRITY"},
		{text: "MAC verification failed, continuing anyway...", code: "MAC_VERIFICATION_FAILED_CONTINUING"},
		{text: "Repairing (verifying)...", code: "REPAIRING_VERIFYING"},
		{text: "Integrity verified, decrypting...", code: "INTEGRITY_VERIFIED_DECRYPTING"},
		{text: "Comparing values...", code: "COMPARING_VALUES"},
		{text: "Unzipping...", code: "UNZIPPING"},
		{text: "Adding plausible deniability...", code: "ADDING_PLAUSIBLE_DENIABILITY"},
		{text: "Removing deniability protection...", code: "REMOVING_DENIABILITY_PROTECTION"},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			want := classifiedStatus{Code: tc.code}
			if got := classifyStatus(tc.text); got != want {
				t.Fatalf("classifyStatus(%q) = %#v, want %#v", tc.text, got, want)
			}
		})
	}
}

func TestClassifyStatusRates(t *testing.T) {
	tests := []struct {
		prefix string
		code   string
	}{
		{prefix: "Compressing at", code: "COMPRESSING_RATE"},
		{prefix: "Encrypting at", code: "ENCRYPTING_RATE"},
		{prefix: "Splitting at", code: "SPLITTING_RATE"},
		{prefix: "Recombining at", code: "RECOMBINING_RATE"},
		{prefix: "Verifying at", code: "VERIFYING_RATE"},
		{prefix: "Decrypting at", code: "DECRYPTING_RATE"},
		{prefix: "Repairing at", code: "REPAIRING_RATE"},
		{prefix: "Unpacking at", code: "UNPACKING_RATE"},
		{prefix: "Adding deniability at", code: "ADDING_DENIABILITY_RATE"},
		{prefix: "Removing deniability at", code: "REMOVING_DENIABILITY_RATE"},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			text := fmt.Sprintf("%s 12.34 MiB/s (ETA: 01:02:03)", tc.prefix)
			want := classifiedStatus{
				Code:              tc.code,
				SpeedMiBPerSecond: 12.34,
				ETA:               "01:02:03",
			}
			if got := classifyStatus(text); got != want {
				t.Fatalf("classifyStatus(%q) = %#v, want %#v", text, got, want)
			}
		})
	}
}

func TestClassifyStatusRejectsUnknownOrMalformedText(t *testing.T) {
	tests := []struct {
		name string
		text string
		code string
	}{
		{name: "blank", text: "", code: "NONE"},
		{name: "unknown prose", text: "Working...", code: "UNKNOWN"},
		{name: "whitespace is not normalized", text: " ", code: "UNKNOWN"},
		{name: "unanchored prefix", text: "prefix Encrypting at 1.00 MiB/s (ETA: 00:00:01)", code: "UNKNOWN"},
		{name: "unanchored suffix", text: "Encrypting at 1.00 MiB/s (ETA: 00:00:01) suffix", code: "UNKNOWN"},
		{name: "one speed decimal", text: "Encrypting at 1.0 MiB/s (ETA: 00:00:01)", code: "UNKNOWN"},
		{name: "three speed decimals", text: "Encrypting at 1.000 MiB/s (ETA: 00:00:01)", code: "UNKNOWN"},
		{name: "negative speed", text: "Encrypting at -1.00 MiB/s (ETA: 00:00:01)", code: "UNKNOWN"},
		{name: "NaN speed", text: "Encrypting at NaN MiB/s (ETA: 00:00:01)", code: "UNKNOWN"},
		{name: "positive infinity speed", text: "Encrypting at +Inf MiB/s (ETA: 00:00:01)", code: "UNKNOWN"},
		{name: "negative infinity speed", text: "Encrypting at -Inf MiB/s (ETA: 00:00:01)", code: "UNKNOWN"},
		{name: "short ETA hour", text: "Encrypting at 1.00 MiB/s (ETA: 0:00:01)", code: "UNKNOWN"},
		{name: "ETA minute out of range", text: "Encrypting at 1.00 MiB/s (ETA: 00:60:01)", code: "UNKNOWN"},
		{name: "ETA second out of range", text: "Encrypting at 1.00 MiB/s (ETA: 00:00:60)", code: "UNKNOWN"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyStatus(tc.text)
			if got != (classifiedStatus{Code: tc.code}) {
				t.Fatalf("classifyStatus(%q) = %#v, want code %q with empty arguments", tc.text, got, tc.code)
			}
		})
	}
}

func TestClassifyInfo(t *testing.T) {
	tests := []struct {
		name string
		text string
		want classifiedInfo
	}{
		{name: "blank", text: "", want: classifiedInfo{Code: "NONE"}},
		{name: "percent", text: "50.00%", want: classifiedInfo{Code: "PERCENT"}},
		{name: "verifying percent", text: "50.00% (verifying)", want: classifiedInfo{Code: "PERCENT"}},
		{name: "item count", text: "3/10", want: classifiedInfo{Code: "ITEM_COUNT", Current: 3, Total: 10}},
		{name: "unknown prose", text: "three of ten", want: classifiedInfo{Code: "UNKNOWN"}},
		{name: "whitespace is not normalized", text: " ", want: classifiedInfo{Code: "UNKNOWN"}},
		{name: "percent needs two decimals", text: "50%", want: classifiedInfo{Code: "UNKNOWN"}},
		{name: "verifying suffix is exact", text: "50.00% verifying", want: classifiedInfo{Code: "UNKNOWN"}},
		{name: "item count is anchored", text: "prefix 3/10", want: classifiedInfo{Code: "UNKNOWN"}},
		{name: "item count has no spaces", text: "3 / 10", want: classifiedInfo{Code: "UNKNOWN"}},
		{name: "item count rejects overflow", text: "9223372036854775808/10", want: classifiedInfo{Code: "UNKNOWN"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyInfo(tc.text); got != tc.want {
				t.Fatalf("classifyInfo(%q) = %#v, want %#v", tc.text, got, tc.want)
			}
		})
	}
}

func TestProductionStatusTemplatesAreClassified(t *testing.T) {
	want := map[string]string{
		"Compressing files...":  "COMPRESSING_FILES",
		"Generating values...":  "GENERATING_VALUES",
		"Deriving key...":       "DERIVING_KEY",
		"Reading keyfiles...":   "READING_KEYFILES",
		"Calculating values...": "CALCULATING_VALUES",
		"Writing values...":     "WRITING_VALUES",
		"Splitting...":          "SPLITTING",
		"Recombining chunks...": "RECOMBINING_CHUNKS",
		"Reading values...":     "READING_VALUES",
		"Warning: duplicate keyfiles detected (keys cancel out)...": "DUPLICATE_KEYFILES_WARNING",
		"Verifying integrity (pass 1 of 2)...":                      "VERIFYING_INTEGRITY",
		"MAC verification failed, continuing anyway...":             "MAC_VERIFICATION_FAILED_CONTINUING",
		"Repairing (verifying)...":                                  "REPAIRING_VERIFYING",
		"Integrity verified, decrypting...":                         "INTEGRITY_VERIFIED_DECRYPTING",
		"Comparing values...":                                       "COMPARING_VALUES",
		"Unzipping...":                                              "UNZIPPING",
		"Adding plausible deniability...":                           "ADDING_PLAUSIBLE_DENIABILITY",
		"Removing deniability protection...":                        "REMOVING_DENIABILITY_PROTECTION",
		"Compressing at %.2f MiB/s (ETA: %s)":                       "COMPRESSING_RATE",
		"Encrypting at %.2f MiB/s (ETA: %s)":                        "ENCRYPTING_RATE",
		"Splitting at %.2f MiB/s (ETA: %s)":                         "SPLITTING_RATE",
		"Recombining at %.2f MiB/s (ETA: %s)":                       "RECOMBINING_RATE",
		"Verifying at %.2f MiB/s (ETA: %s)":                         "VERIFYING_RATE",
		"Decrypting at %.2f MiB/s (ETA: %s)":                        "DECRYPTING_RATE",
		"Repairing at %.2f MiB/s (ETA: %s)":                         "REPAIRING_RATE",
		"Unpacking at %.2f MiB/s (ETA: %s)":                         "UNPACKING_RATE",
		"Adding deniability at %.2f MiB/s (ETA: %s)":                "ADDING_DENIABILITY_RATE",
		"Removing deniability at %.2f MiB/s (ETA: %s)":              "REMOVING_DENIABILITY_RATE",
	}

	got := productionStatusTemplates(t)
	if !reflect.DeepEqual(got, sortedKeys(want)) {
		t.Fatalf("production status templates changed\n got: %q\nwant: %q", got, sortedKeys(want))
	}

	for template, wantCode := range want {
		text := template
		if strings.Contains(template, "%.2f") {
			text = fmt.Sprintf(template, 12.34, "01:02:03")
		}
		if gotCode := classifyStatus(text).Code; gotCode != wantCode {
			t.Errorf("production template %q classified as %q, want %q", template, gotCode, wantCode)
		}
	}
}

func productionStatusTemplates(t *testing.T) []string {
	t.Helper()

	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate status_test.go")
	}
	srcRoot := filepath.Dir(filepath.Dir(testFile))
	dirs := []string{
		filepath.Join(srcRoot, "internal", "volume"),
		filepath.Join(srcRoot, "internal", "fileops"),
	}

	templates := make(map[string]struct{})
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}

			path := filepath.Join(dir, entry.Name())
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (selector.Sel.Name != "SetStatus" && selector.Sel.Name != "Status") {
					return true
				}

				if template, ok := statusTemplate(call.Args[0]); ok {
					templates[template] = struct{}{}
				}
				return true
			})
		}
	}

	got := make([]string, 0, len(templates))
	for template := range templates {
		got = append(got, template)
	}
	sort.Strings(got)
	return got
}

func statusTemplate(expr ast.Expr) (string, bool) {
	switch expr := expr.(type) {
	case *ast.BasicLit:
		if expr.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(expr.Value)
		return text, err == nil
	case *ast.CallExpr:
		selector, ok := expr.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Sprintf" || len(expr.Args) == 0 {
			return "", false
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" {
			return "", false
		}
		return statusTemplate(expr.Args[0])
	default:
		return "", false
	}
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
