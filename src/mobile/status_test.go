package mobile

import (
	"errors"
	"fmt"
	"go/ast"
	"go/format"
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
			text := tc.prefix + " 12.34 MiB/s (ETA: 01:02:03)"
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

func TestClassifyStatusAcceptsLongETA(t *testing.T) {
	text := "Encrypting at 12.34 MiB/s (ETA: 100:59:59)"
	want := classifiedStatus{
		Code:              "ENCRYPTING_RATE",
		SpeedMiBPerSecond: 12.34,
		ETA:               "100:59:59",
	}

	if got := classifyStatus(text); got != want {
		t.Fatalf("classifyStatus(%q) = %#v, want %#v", text, got, want)
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

func TestStatusCallTemplateRejectsUnsupportedArgumentForms(t *testing.T) {
	tests := []struct {
		name       string
		expression string
	}{
		{name: "constant", expression: "statusConstant"},
		{name: "concatenation", expression: `"Encrypting at " + suffix`},
		{name: "helper", expression: "buildStatus()"},
		{name: "nonliteral Sprintf format", expression: "fmt.Sprintf(format, speed, eta)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			call := parseFixtureStatusCall(t, tc.expression)
			if _, _, err := statusCallTemplate("fixture.go", "fixture", call, nil); err == nil {
				t.Fatalf("status argument %q was accepted without an explicit template or forwarding allowlist", tc.expression)
			}
		})
	}
}

func TestStatusCallTemplateAllowsExplicitForwarding(t *testing.T) {
	call := parseFixtureStatusCall(t, "status")
	forwarding := statusForwarding{
		File:     "fixture.go",
		Function: "fixture",
		Receiver: "ctx",
		Method:   "SetStatus",
		Argument: "status",
	}

	template, forwarded, err := statusCallTemplate(
		"fixture.go",
		"fixture",
		call,
		map[statusForwarding]struct{}{forwarding: {}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if template != "" || !forwarded {
		t.Fatalf("explicit forwarding classified as template=%q forwarded=%v", template, forwarded)
	}
}

func parseFixtureStatusCall(t *testing.T, expression string) *ast.CallExpr {
	t.Helper()

	source := fmt.Sprintf("package fixture\nfunc fixture(ctx *context) { ctx.SetStatus(%s) }\n", expression)
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var statusCall *ast.CallExpr
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "SetStatus" {
			statusCall = call
			return false
		}
		return true
	})
	if statusCall == nil {
		t.Fatal("fixture SetStatus call not found")
	}
	return statusCall
}

type statusForwarding struct {
	File     string
	Function string
	Receiver string
	Method   string
	Argument string
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
	allowedForwardings := productionStatusForwardings()
	seenForwardings := make(map[statusForwarding]int)
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
			relativePath, err := filepath.Rel(srcRoot, path)
			if err != nil {
				t.Fatalf("resolve %s: %v", path, err)
			}
			relativePath = filepath.ToSlash(relativePath)
			fileSet := token.NewFileSet()
			file, err := parser.ParseFile(fileSet, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}

				var inspectErr error
				ast.Inspect(function.Body, func(node ast.Node) bool {
					if inspectErr != nil {
						return false
					}
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || (selector.Sel.Name != "SetStatus" && selector.Sel.Name != "Status") {
						return true
					}

					template, forwarded, err := statusCallTemplate(
						relativePath,
						function.Name.Name,
						call,
						allowedForwardings,
					)
					if err != nil {
						inspectErr = fmt.Errorf("%s: %w", fileSet.Position(call.Pos()), err)
						return false
					}
					if forwarded {
						forwarding, ok := statusForwardingFor(relativePath, function.Name.Name, call)
						if !ok {
							inspectErr = fmt.Errorf("%s: allowed forwarding could not be identified", fileSet.Position(call.Pos()))
							return false
						}
						seenForwardings[forwarding]++
						return true
					}
					templates[template] = struct{}{}
					return true
				})
				if inspectErr != nil {
					t.Fatal(inspectErr)
				}
			}
		}
	}
	if len(seenForwardings) != len(allowedForwardings) {
		t.Fatalf("production status forwardings changed\n got: %#v\nwant: %#v", seenForwardings, allowedForwardings)
	}
	for forwarding := range allowedForwardings {
		if seenForwardings[forwarding] != 1 {
			t.Fatalf("production status forwarding %#v occurred %d times, want exactly once", forwarding, seenForwardings[forwarding])
		}
	}

	got := make([]string, 0, len(templates))
	for template := range templates {
		got = append(got, template)
	}
	sort.Strings(got)
	return got
}

func productionStatusForwardings() map[statusForwarding]struct{} {
	return map[statusForwarding]struct{}{
		{
			File:     "internal/volume/context.go",
			Function: "SetStatus",
			Receiver: "ctx.Reporter",
			Method:   "SetStatus",
			Argument: "status",
		}: {},
		{
			File:     "internal/volume/encrypt.go",
			Function: "encryptPreprocess",
			Receiver: "ctx",
			Method:   "SetStatus",
			Argument: "s",
		}: {},
		{
			File:     "internal/volume/encrypt.go",
			Function: "encryptFinalize",
			Receiver: "ctx",
			Method:   "SetStatus",
			Argument: "s",
		}: {},
		{
			File:     "internal/volume/decrypt.go",
			Function: "decryptPreprocess",
			Receiver: "ctx",
			Method:   "SetStatus",
			Argument: "s",
		}: {},
		{
			File:     "internal/volume/decrypt.go",
			Function: "decryptFinalize",
			Receiver: "ctx",
			Method:   "SetStatus",
			Argument: "s",
		}: {},
	}
}

func statusCallTemplate(
	fileName string,
	functionName string,
	call *ast.CallExpr,
	allowedForwardings map[statusForwarding]struct{},
) (string, bool, error) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (selector.Sel.Name != "SetStatus" && selector.Sel.Name != "Status") {
		return "", false, errors.New("not a status call")
	}
	if len(call.Args) != 1 {
		return "", false, fmt.Errorf("status call has %d arguments, want 1", len(call.Args))
	}
	if template, ok := statusTemplate(call.Args[0]); ok {
		return template, false, nil
	}
	if forwarding, ok := statusForwardingFor(fileName, functionName, call); ok {
		if _, allowed := allowedForwardings[forwarding]; allowed {
			return "", true, nil
		}
	}

	var expression strings.Builder
	if err := format.Node(&expression, token.NewFileSet(), call.Args[0]); err != nil {
		return "", false, fmt.Errorf("unsupported status argument of type %T", call.Args[0])
	}
	return "", false, fmt.Errorf("unsupported status argument %q", expression.String())
}

func statusForwardingFor(fileName string, functionName string, call *ast.CallExpr) (statusForwarding, bool) {
	if len(call.Args) != 1 {
		return statusForwarding{}, false
	}
	argument, ok := call.Args[0].(*ast.Ident)
	if !ok {
		return statusForwarding{}, false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return statusForwarding{}, false
	}
	receiver, ok := selectorName(selector.X)
	if !ok {
		return statusForwarding{}, false
	}
	return statusForwarding{
		File:     fileName,
		Function: functionName,
		Receiver: receiver,
		Method:   selector.Sel.Name,
		Argument: argument.Name,
	}, true
}

func selectorName(expression ast.Expr) (string, bool) {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name, true
	case *ast.SelectorExpr:
		prefix, ok := selectorName(expression.X)
		if !ok {
			return "", false
		}
		return prefix + "." + expression.Sel.Name, true
	default:
		return "", false
	}
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
