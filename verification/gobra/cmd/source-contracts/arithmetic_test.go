package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArithmeticActualBodiesFullContractsAndFiniteAlphaMap(t *testing.T) {
	repo := repository(t)
	target, err := loadArithmetic(repo, filepath.Join(repo, "verification/gobra/_build/go-cache"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"arithmetic-positive", "arithmetic-add-ignores-carry", "arithmetic-mul-returns-high", "arithmetic-ceil-floors"} {
		generated, evidence, err := annotateArithmetic(target, name)
		if err != nil {
			t.Fatal(err)
		}
		if len(evidence.Functions) != 3 || len(evidence.Alpha) != 2 {
			t.Fatal("all three real bodies and exactly two alpha tokens are required")
		}
		for _, function := range evidence.Functions {
			if !function.ASTRecovered || !function.BodyRecovered {
				t.Fatalf("original body not recovered: %+v", function)
			}
			if name == "arithmetic-positive" && function.RawBodyIdentical != (function.Function != "checkedMul64") {
				t.Fatal("raw body identity hid the reviewed Mul local rename")
			}
		}
		for _, replacement := range evidence.Alpha {
			if string(target.Source[replacement.SourceOffset:replacement.SourceOffset+3]) != "low" || replacement.Replacement != arithmeticFreshName {
				t.Fatal("alpha map was not bound to original physical tokens")
			}
		}
		for _, contract := range arithmeticContracts {
			if !bytes.Contains(generated, []byte(contract)) {
				t.Fatal("full positive contract changed in a control")
			}
		}
		if strings.Contains(string(generated), "//@ requires left ==") || strings.Contains(string(generated), "//@ requires value ==") {
			t.Fatal("arithmetic domain was narrowed")
		}
		if _, err = arithmeticFreshBindings(generated, target.Imports); err != nil {
			t.Fatal(err)
		}
	}
}

func arithmeticFixture(t *testing.T, source, extra string) (string, string) {
	t.Helper()
	repo, cache := recordCountFixture(t, "package pcv3\n")
	for relative, content := range map[string]string{arithmeticRelative: source, "src/internal/pcv3operation/internal/pcv3/extra.go": "package pcv3\n" + extra, bitsHeaderRelative: "package bits\n"} {
		path := filepath.Join(repo, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return repo, cache
}

func TestArithmeticInputAdmissionRejectsChangedTupleCarryAndBody(t *testing.T) {
	for name, source := range map[string]string{
		"carry literal":     strings.Replace(arithmeticReviewed, "Add64(left, right, 0)", "Add64(left, right, 1)", 1),
		"tuple order":       strings.Replace(arithmeticReviewed, "high, low :=", "low, high :=", 1),
		"new low use":       strings.Replace(arithmeticReviewed, "return low, high == 0", "return low+low-low, high == 0", 1),
		"input assignment":  strings.Replace(arithmeticReviewed, "sum, carry :=", "left=0; sum, carry :=", 1),
		"bodyless helper":   strings.Replace(arithmeticReviewed, " sum, carry := bits.Add64(left, right, 0)\n return sum, carry == 0\n}", "}", 1),
		"extra declaration": arithmeticReviewed + "\nfunc unreviewed() {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := reviewArithmetic([]byte(source)); err == nil {
				t.Fatal("unreviewed arithmetic body entered source proof")
			}
		})
	}
	for _, marker := range []string{"// @ requires false", "/*\t@ requires false @*/", "@ \t*/"} {
		if err := reviewArithmetic([]byte(arithmeticReviewed + "\n// " + marker)); err == nil {
			t.Fatal("verifier input marker admitted")
		}
	}
}

func TestArithmeticActualFreeNameCannotBecomeBuiltinAfterProjection(t *testing.T) {
	source := strings.Replace(arithmeticReviewed, " quotient :=", "//line hidden.go:1\n quotient :=", 1)
	repo, cache := arithmeticFixture(t, source, "var true = false\n")
	if _, err := loadArithmetic(repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed actual binding") {
		t.Fatalf("free true binding disappeared under line-directive projection: %v", err)
	}
}

func TestArithmeticAlphaUsesObjectPositionsRatherThanText(t *testing.T) {
	source := strings.Replace(arithmeticReviewed, " high, low :=", " // low low low: comment text is not a variable occurrence\n high, low :=", 1)
	repo, cache := arithmeticFixture(t, source, "")
	target, err := loadArithmetic(repo, cache)
	if err != nil {
		t.Fatal(err)
	}
	generated, evidence, err := annotateArithmetic(target, "arithmetic-positive")
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Alpha) != 2 || !bytes.Contains(generated, []byte("// low low low: comment text")) {
		t.Fatal("alpha conversion rewrote text instead of exactly bound local tokens")
	}
}

func TestArithmeticAlphaFreshNameCannotCaptureContractIdentifier(t *testing.T) {
	original := arithmeticContracts["checkedMul64"]
	t.Cleanup(func() { arithmeticContracts["checkedMul64"] = original })
	arithmeticContracts["checkedMul64"] += "//@ ensures pcv3LowWord == 0\n"
	repo, cache := arithmeticFixture(t, arithmeticReviewed, "")
	if _, err := loadArithmetic(repo, cache); err == nil || !strings.Contains(err.Error(), "fresh-name collision") {
		t.Fatalf("alpha name collided with a contract identifier: %v", err)
	}
}

func TestArithmeticControlRequiresExactPostconditionLocationAndOrdinaryFailure(t *testing.T) {
	for name, control := range arithmeticControls {
		log := "Error at: </workspace/" + name + "/arithmetic.go:18:9> Postcondition might not hold.\nAssertion " + control.Post + " might not hold.\nGobra found 1 error.\n"
		if !arithmeticRejected(1, log, name, 18) {
			t.Fatal("required control diagnostic rejected")
		}
		for _, changed := range []string{strings.Replace(log, ":18:9>", ":17:9>", 1), strings.Replace(log, "Assertion "+control.Post, "Assertion false", 1), log + "timeout", log + "OutOfMemory", log + "integer overflow", strings.Replace(log, "found 1 error", "found 2 errors", 1)} {
			if arithmeticRejected(1, changed, name, 18) {
				t.Fatal("unrelated failure was counted as arithmetic control")
			}
		}
	}
}
