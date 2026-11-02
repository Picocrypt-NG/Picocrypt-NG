package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func currentMetadata(t *testing.T) metadataTarget {
	t.Helper()
	repo := repository(t)
	cache := filepath.Join(repo, "verification/gobra/_build/go-cache")
	arithmetic, err := loadArithmetic(repo, cache)
	if err != nil {
		t.Fatal(err)
	}
	target, err := loadMetadata(repo, cache, arithmetic)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestMetadataFourActualBodiesPreserveOriginalNamedReturns(t *testing.T) {
	target := currentMetadata(t)
	for _, result := range []string{"result:0:blocks:uint64", "result:1:frontHeaderLength:uint64", "result:2:ok:bool"} {
		found := false
		for _, reference := range target.Graphs[metadataFunctionName] {
			found = found || strings.Contains(reference, result)
		}
		if !found {
			t.Fatalf("actual named-return object is absent from binding graph: %s", result)
		}
	}
	for _, local := range target.Locals {
		if local.Function == metadataFunctionName && local.Name == "ok" {
			t.Fatal("named result ok was replaced by a body-local object")
		}
	}
	for _, name := range []string{"metadata-positive", "metadata-ceil-floor"} {
		generated, evidence, err := annotateMetadata(target, name)
		if err != nil {
			t.Fatal(err)
		}
		if !evidence.BindingGraphs || len(evidence.Functions) != 4 || len(evidence.NamedOutputs) != 3 {
			t.Fatal("four source bodies and original named outputs required")
		}
		for _, function := range evidence.Functions {
			if !function.ASTRecovered || !function.BodyRecovered {
				t.Fatal("metadata original source not recovered")
			}
			if name == "metadata-positive" && function.RawBodyIdentical != (function.Function != "checkedMul64") {
				t.Fatal("metadata body changed beyond the sole reviewed Mul alpha")
			}
		}
		if !bytes.Contains(generated, []byte(metadataContract)) || bytes.Contains(generated, []byte("func canonicalMetadataGeometry(commentLength uint32) (/*@")) {
			t.Fatal("original named outputs were given synthetic names or a changed contract")
		}
	}
	if strings.Contains(metadataContract, "requires commentLength <= 99999") {
		t.Fatal("full uint32 proof was narrowed to UI comment admission")
	}
}

func metadataFixture(t *testing.T, target metadataTarget, extra string) (string, string) {
	t.Helper()
	repo, cache := recordCountFixture(t, "package pcv3\n")
	var source bytes.Buffer
	source.WriteString("package pcv3\n")
	source.Write(target.OriginalConstants)
	source.Write(target.Function)
	source.WriteByte('\n')
	for relative, content := range map[string][]byte{arithmeticRelative: target.Arithmetic.Source, preambleRelative: source.Bytes(), bitsHeaderRelative: target.Arithmetic.Header, "src/internal/pcv3operation/internal/pcv3/extra.go": []byte("package pcv3\n" + extra)} {
		path := filepath.Join(repo, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return repo, cache
}

func loadMetadataFixture(t *testing.T, repo, cache string) (metadataTarget, error) {
	t.Helper()
	arithmetic, err := loadArithmetic(repo, cache)
	if err != nil {
		return metadataTarget{}, err
	}
	return loadMetadata(repo, cache, arithmetic)
}

func TestMetadataGoValidSignatureChangesRequireReview(t *testing.T) {
	target := currentMetadata(t)
	for _, kind := range []string{"input width", "named outputs removed"} {
		t.Run(kind, func(t *testing.T) {
			repo, cache := metadataFixture(t, target, "")
			path := filepath.Join(repo, preambleRelative)
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "input width" {
				source = bytes.Replace(source, []byte("commentLength uint32"), []byte("commentLength uint64"), 1)
			} else {
				source = bytes.Replace(source, []byte("(blocks, frontHeaderLength uint64, ok bool) {"), []byte("(uint64, uint64, bool) {\nvar blocks, frontHeaderLength uint64\nvar ok bool"), 1)
			}
			if err = os.WriteFile(path, source, 0644); err != nil {
				t.Fatal(err)
			}
			if _, _, err = loadSource(repo, cache, preambleRelative, "./internal/pcv3operation/internal/pcv3"); err != nil {
				t.Fatalf("metadata signature fixture must remain valid Go: %v", err)
			}
			if _, err = loadMetadataFixture(t, repo, cache); err == nil {
				t.Fatal("unreviewed metadata input/output representation entered the proof")
			}
		})
	}
}

func TestMetadataConstantSameValueDependencyOutsideClosureRejected(t *testing.T) {
	repo, cache := metadataFixture(t, currentMetadata(t), "const outsideBase = 976\n")
	path := filepath.Join(repo, preambleRelative)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source = bytes.Replace(source, []byte("frontHeaderBase         uint64 = 976"), []byte("frontHeaderBase uint64 = outsideBase"), 1)
	if !bytes.Contains(source, []byte("uint64 = outsideBase")) {
		t.Fatal("metadata dependency fixture did not change")
	}
	if err = os.WriteFile(path, source, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadSource(repo, cache, preambleRelative, "./internal/pcv3operation/internal/pcv3"); err != nil {
		t.Fatal(err)
	}
	if _, err = loadMetadataFixture(t, repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed dependency") {
		t.Fatalf("metadata dependency escaped the actual constant closure: %v", err)
	}
}

func TestMetadataNamedOutputGraphStillRejectsOmittedGlobalFalse(t *testing.T) {
	repo, cache := metadataFixture(t, currentMetadata(t), "var false = true\n")
	path := filepath.Join(repo, preambleRelative)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source = bytes.Replace(source, []byte("decodedLength, ok :="), []byte("//line hidden.go:1\ndecodedLength, ok :="), 1)
	if err = os.WriteFile(path, source, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadMetadataFixture(t, repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed payload binding") {
		t.Fatalf("metadata projection silently replaced actual global false: %v", err)
	}
}

func TestMetadataControlRequiresExactTargetPostconditionAndOrdinaryFailure(t *testing.T) {
	log := "Error at: </workspace/metadata-ceil-floor/metadata.go:42:9> Postcondition might not hold.\nAssertion 1 <= blocks might not hold.\nGobra found 1 error.\n"
	if !metadataRejected(1, log, 42) {
		t.Fatal("required metadata diagnostic rejected")
	}
	for _, changed := range []string{strings.Replace(log, ":42:9>", ":41:9>", 1), strings.Replace(log, "Assertion 1 <= blocks", "Assertion ok", 1), log + "timeout", log + "OutOfMemory", log + "integer overflow", strings.Replace(log, "found 1 error", "found 2 errors", 1)} {
		if metadataRejected(1, changed, 42) {
			t.Fatal("unrelated failure counted as metadata control")
		}
	}
}
