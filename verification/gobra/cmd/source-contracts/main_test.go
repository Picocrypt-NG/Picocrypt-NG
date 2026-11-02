package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repository(t *testing.T) string {
	t.Helper()
	repo, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestAnnotationsUseDeclarationPositionsAndPreserveExecutableAST(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repository(t), sourceRelative))
	if err != nil {
		t.Fatal(err)
	}
	source = []byte(strings.Replace(string(source), "// SafeUint64ToInt64 returns", "// decoy: func SafeUint64ToInt64(v uint64) (int64, bool)\n// SafeUint64ToInt64 returns", 1))
	positive, identity, err := annotate(source, false)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.ASTIdentical || !identity.BodyIdentical {
		t.Fatal("Gobra comments changed the actual Go signature or body")
	}
	if strings.Count(string(positive), "//@ requires 0 <= v && v <= 18446744073709551615") != 1 ||
		!strings.Contains(string(positive), "func SafeUint64ToInt64(v uint64) (/*@ value @*/ int64, /*@ ok @*/ bool)") {
		t.Fatal("contract or result names were not attached to the real declaration")
	}
	if !strings.Contains(string(positive), "//@ ensures -9223372036854775808 <= value && value <= 9223372036854775807") {
		t.Fatal("EasyCrypt int64-result premise has no checked Gobra counterpart")
	}
	negative, changed, err := annotate(source, true)
	if err != nil {
		t.Fatal(err)
	}
	if changed.ASTIdentical || changed.BodyIdentical || !strings.Contains(string(negative), "if false && (v > math.MaxInt64)") {
		t.Fatal("negative control did not disable only the real guard")
	}
}

func TestCurrentSourceAndBothGeneratedCasesTypecheck(t *testing.T) {
	repo := repository(t)
	t.Setenv("GOPACKAGESDRIVER", "/nonexistent/safecast-driver")
	t.Setenv("GOFLAGS", "-overlay=/nonexistent/safecast-overlay.json")
	t.Setenv("GOWORK", "/nonexistent/safecast.work")
	t.Setenv("GOENV", "/nonexistent/safecast-goenv")
	target, err := loadTarget(repo, filepath.Join(repo, "verification/gobra/_build/go-cache"))
	if err != nil {
		t.Fatal(err)
	}
	if target.ConstantValue != "9223372036854775807" {
		t.Fatalf("actual math.MaxInt64 = %s", target.ConstantValue)
	}
	for _, negative := range []bool{false, true} {
		generated, _, err := annotate(target.Source, negative)
		if err != nil {
			t.Fatal(err)
		}
		if err := typecheckCopy(generated, target.Math); err != nil {
			t.Fatalf("generated Go does not typecheck (negative=%v): %v", negative, err)
		}
	}
}

func TestChangedParameterTypeCannotReceiveUint64Contract(t *testing.T) {
	source := []byte("package util\nimport \"math\"\nfunc SafeUint64ToInt64(v int64) (int64, bool) { if v > math.MaxInt64 { return 0, false }; return int64(v), true }\n")
	if _, _, err := annotate(source, false); err == nil {
		t.Fatal("int64 input was given a uint64 representation contract")
	}
}

func TestSourceCannotReplaceMathConstantWithLookalikeField(t *testing.T) {
	build := filepath.Join(repository(t), "verification/gobra/_build")
	if err := os.MkdirAll(filepath.Join(build, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(build, "tests"))
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "src/internal/util"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "src/go.mod"), []byte("module Picocrypt-NG\n\ngo 1.27.3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	source := "package util\nvar math = struct{MaxInt64 uint64}{9223372036854775807}\nfunc SafeUint64ToInt64(v uint64) (int64, bool) { if v > math.MaxInt64 { return 0, false }; return int64(v), true }\n"
	if err := os.WriteFile(filepath.Join(repo, sourceRelative), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTarget(repo, filepath.Join(build, "go-cache")); err == nil || !strings.Contains(err.Error(), "actual math.MaxInt64") {
		t.Fatalf("lookalike constant binding was not rejected: %v", err)
	}
}

func TestOverflowControlRejectsUnrelatedFailureOrWrongLocation(t *testing.T) {
	log := "Error at: </workspace/guard-disabled/safecast.go:14:9> Expression may cause integer overflow.\nExpression int64(v) might cause integer overflow.\nGobra found 1 error.\n"
	if !overflowRejected(1, log, 14, 9) {
		t.Fatal("expected overflow proof diagnostic was rejected")
	}
	for _, altered := range []string{
		strings.Replace(log, ":14:9>", ":10:9>", 1),
		strings.Replace(log, "Expression int64(v) might cause integer overflow.", "unknown identifier math", 1),
		log + "timeout",
		strings.Replace(log, "Gobra found 1 error.", "Gobra found 2 errors.", 1),
	} {
		if overflowRejected(1, altered, 14, 9) {
			t.Fatal("unrelated, incomplete, timed-out or misplaced error counted as a valid proof control")
		}
	}
}

func TestRecordCountUsesCurrentDeclarationAndExactConstant(t *testing.T) {
	repo := repository(t)
	actual, err := loadRecordCount(repo, filepath.Join(repo, "verification/gobra/_build/go-cache"))
	if err != nil {
		t.Fatal(err)
	}
	for _, negative := range []bool{false, true} {
		generated, identity, err := annotateRecordCount(actual.Source, actual.ConstantValue, negative)
		if err != nil {
			t.Fatal(err)
		}
		if identity.ASTIdentical == negative || identity.BodyIdentical == negative {
			t.Fatalf("record-count source identity (negative=%v) = %+v", negative, identity)
		}
		if err := typecheckCopy(generated, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(generated), "const recordPlaintextMax = 1048576") || !strings.Contains(string(generated), "plaintextLength <= 18446744073709551615") {
			t.Fatal("actual chunk constant or full uint64 domain was lost")
		}
	}
}

func TestRecordCountControlRejectsUnrelatedPostconditionFailure(t *testing.T) {
	log := "Error at: </workspace/record-count-extra-record/records.go:7:9> Postcondition might not hold.\nAssertion plaintextLength % recordPlaintextMax == 0 ==> count == plaintextLength / recordPlaintextMax might not hold.\nGobra found 1 error.\n"
	if !recordCountRejected(1, log, 7) {
		t.Fatal("expected exact-multiple postcondition failure was rejected")
	}
	for _, altered := range []string{
		strings.Replace(log, ":7:9>", ":6:9>", 1),
		strings.Replace(log, "Assertion plaintextLength % recordPlaintextMax == 0 ==> count == plaintextLength / recordPlaintextMax might not hold.", "Assertion count <= 1 might not hold.", 1),
		log + "timeout",
		log + "Expression may cause integer overflow.",
		strings.Replace(log, "Gobra found 1 error.", "Gobra found 2 errors.", 1),
	} {
		if recordCountRejected(1, altered, 7) {
			t.Fatal("an unrelated, misplaced, timed-out or overflow failure counted as the exact-multiple control")
		}
	}
}

func recordCountFixture(t *testing.T, source string) (string, string) {
	t.Helper()
	build := filepath.Join(repository(t), "verification/gobra/_build")
	if err := os.MkdirAll(filepath.Join(build, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(build, "tests"))
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, filepath.Dir(recordCountRelative)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "src/go.mod"), []byte("module Picocrypt-NG\n\ngo 1.27.3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, recordCountRelative), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	return repo, filepath.Join(build, "go-cache")
}

func TestRecordCountCannotShadowTheResolvedChunkConstant(t *testing.T) {
	repo, cache := recordCountFixture(t, "package pcv3\nconst recordPlaintextMax = 1048576\nfunc canonicalRecordCount(plaintextLength uint64) uint64 { const recordPlaintextMax = 2; if plaintextLength == 0 { return 0 }; return (plaintextLength-1)/recordPlaintextMax+1 }\n")
	if _, err := loadRecordCount(repo, cache); err == nil || !strings.Contains(err.Error(), "constant binding") {
		t.Fatalf("shadowed chunk constant was not rejected: %v", err)
	}
}

func TestRecordCountProjectionCannotRebindPackageFunctionAsGoBuiltin(t *testing.T) {
	repo, cache := recordCountFixture(t, "package pcv3\nconst recordPlaintextMax = 1048576\nfunc min(a, b uint64) uint64 { return 0 }\nfunc canonicalRecordCount(plaintextLength uint64) uint64 { if plaintextLength == 0 { return 0 }; return min((plaintextLength-1)/recordPlaintextMax+1, 18446744073709551615) }\n")
	if _, err := loadRecordCount(repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed") {
		t.Fatalf("package min could become builtin min after projection: %v", err)
	}
}

func TestRecordCountChunkInitializerCannotDependOnOmittedDeclarations(t *testing.T) {
	repo, cache := recordCountFixture(t, "package pcv3\nconst recordChunk = 1048576\nconst recordPlaintextMax = recordChunk\nfunc canonicalRecordCount(plaintextLength uint64) uint64 { if plaintextLength == 0 { return 0 }; return (plaintextLength-1)/recordPlaintextMax+1 }\n")
	if _, err := loadRecordCount(repo, cache); err == nil || !strings.Contains(err.Error(), "literal initializer") {
		t.Fatalf("indirect chunk initializer was accepted: %v", err)
	}
}

func TestSafeCastProjectionCannotRebindPackageFunctionAsGoBuiltin(t *testing.T) {
	build := filepath.Join(repository(t), "verification/gobra/_build")
	if err := os.MkdirAll(filepath.Join(build, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(build, "tests"))
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, filepath.Dir(sourceRelative)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "src/go.mod"), []byte("module Picocrypt-NG\n\ngo 1.27.3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	source := "package util\nimport \"math\"\nfunc SafeUint64ToInt64(v uint64) (int64, bool) { if v > math.MaxInt64 { return 0, false }; return min(int64(v), math.MaxInt64), true }\n"
	if err := os.WriteFile(filepath.Join(repo, sourceRelative), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "src/internal/util/other.go"), []byte("package util\nfunc min(a,b int64) int64 { return 0 }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTarget(repo, filepath.Join(build, "go-cache")); err == nil || !strings.Contains(err.Error(), "unreviewed") {
		t.Fatalf("package min could become builtin min after projection: %v", err)
	}
}

func TestOriginalSourcesCannotSupplySpacedGobraAnnotations(t *testing.T) {
	repo := repository(t)
	safe, err := os.ReadFile(filepath.Join(repo, sourceRelative))
	if err != nil {
		t.Fatal(err)
	}
	count, err := os.ReadFile(filepath.Join(repo, recordCountRelative))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"// @ assume true", "//\t@ assume true", "//\v@ assume true", "/* @ assume true @*/", "/*\t@ assume true @*/", "/*\n@ assume true @*/", "/*\v@ assume true @*/"} {
		t.Run(marker, func(t *testing.T) {
			source := []byte(strings.Replace(string(safe), "if v >", marker+"\nif v >", 1))
			if _, _, err := annotate(source, false); err == nil {
				t.Error("SafeCast source was allowed to supply its own verifier assumption")
			}
			source = []byte(strings.Replace(string(count), "if plaintextLength ==", marker+"\nif plaintextLength ==", 1))
			if _, _, err := annotateRecordCount(source, "1048576", false); err == nil {
				t.Error("record-count source was allowed to supply its own verifier assumption")
			}
		})
	}
}

func TestBareGobraClosersCannotHideExecutableReturns(t *testing.T) {
	repo := repository(t)
	actual, err := loadTarget(repo, filepath.Join(repo, "verification/gobra/_build/go-cache"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"@*/", "@ */", "@\t*/", "@\v*/", "@\f*/", "@\r*/", "@\n*/"} {
		t.Run(marker, func(t *testing.T) {
			safe := []byte(strings.Replace(string(actual.Source), "return int64(v), true", "/* hide "+marker+" return int64(v)+1, true /* end */\n\treturn int64(v), true", 1))
			if err := typecheckCopy(safe, actual.Math); err != nil {
				t.Fatalf("bare-closer fixture is not valid Go: %v", err)
			}
			if _, _, err := annotate(safe, false); err == nil {
				t.Error("bare Gobra closer could hide the actual incorrect cast return")
			}
			count := []byte("package pcv3\nconst recordPlaintextMax = 1048576\nfunc canonicalRecordCount(plaintextLength uint64) uint64 { if plaintextLength == 0 { return 0 }; /* hide " + marker + " return (plaintextLength-1)/recordPlaintextMax+2 /* end */; return (plaintextLength-1)/recordPlaintextMax+1 }\n")
			if err := typecheckCopy(count, nil); err != nil {
				t.Fatalf("bare-closer fixture is not valid Go: %v", err)
			}
			if _, _, err := annotateRecordCount(count, "1048576", false); err == nil {
				t.Error("bare Gobra closer could hide the actual incorrect record-count return")
			}
		})
	}
}

func TestGoLineDirectivesCannotHideRecordCountIdentifierBindings(t *testing.T) {
	for _, directive := range []string{"//line spoof.go:1", "/*line spoof.go:1*/"} {
		t.Run(directive, func(t *testing.T) {
			source := "package pcv3\nconst recordPlaintextMax = 1048576\nconst true = false\nfunc canonicalRecordCount(plaintextLength uint64) uint64 {\nif plaintextLength == 0 { return 0 }\nif plaintextLength == recordPlaintextMax { return 1 }\n" + directive + "\nif true { return (plaintextLength-1)/recordPlaintextMax+1 }\nreturn 0\n}\n"
			repo, cache := recordCountFixture(t, source)
			if _, err := loadRecordCount(repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed source identifier binding") {
				t.Fatalf("line directive hid the actual non-builtin true binding: %v", err)
			}
		})
	}
}

func TestCastDiagnosticCoordinatesIgnoreGoLineDirectives(t *testing.T) {
	repo := repository(t)
	original, err := os.ReadFile(filepath.Join(repo, sourceRelative))
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{"//line spoof.go:1", "/*line spoof.go:1*/"} {
		t.Run(directive, func(t *testing.T) {
			source := []byte(strings.Replace(string(original), "\treturn int64(v), true", directive+"\n\treturn int64(v), true", 1))
			generated, identity, err := annotate(source, false)
			if err != nil {
				t.Fatal(err)
			}
			offset := strings.Index(string(generated), "int64(v)")
			before := string(generated[:offset])
			line := strings.Count(before, "\n") + 1
			column := offset - strings.LastIndex(before, "\n")
			if identity.ConversionLine != line || identity.ConversionColumn != column {
				t.Fatalf("diagnostic coordinates = %d:%d, want physical %d:%d", identity.ConversionLine, identity.ConversionColumn, line, column)
			}
		})
	}
}
