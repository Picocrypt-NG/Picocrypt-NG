package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func currentOffset(t *testing.T) offsetTarget {
	t.Helper()
	payload := currentPayload(t)
	repo := repository(t)
	target, err := loadOffset(repo, filepath.Join(repo, "verification/gobra/_build/go-cache"), payload)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestOffsetSevenBodiesCompleteTypesAndIndependentFullInputDomain(t *testing.T) {
	target := currentOffset(t)
	if len(target.Types) != 3 {
		t.Fatal("complete core and both defined enum declarations required")
	}
	okObjects := map[int]bool{}
	for _, local := range target.Locals {
		if local.Name == "ok" {
			if okObjects[local.Definition] || local.Type != "bool" {
				t.Fatal("distinct offset ok objects merged")
			}
			okObjects[local.Definition] = true
		}
	}
	if len(okObjects) != 3 {
		t.Fatal("offset needs three distinct lexical ok objects")
	}
	for _, name := range []string{"offset-positive", "offset-boundary-inclusive", "offset-rs-wrong-width", "offset-partial-omitted"} {
		generated, evidence, err := annotateOffset(target, name)
		if err != nil {
			t.Fatal(err)
		}
		if !evidence.CompleteTypes || !evidence.BindingGraphs || len(evidence.Functions) != 7 {
			t.Fatal("seven actual bodies and full type bindings required")
		}
		for _, function := range evidence.Functions {
			if !function.ASTRecovered || !function.BodyRecovered {
				t.Fatal("source body was not recovered")
			}
			if name == "offset-positive" && function.RawBodyIdentical != (function.Function != "checkedMul64") {
				t.Fatal("raw identity hid more than the reviewed local alpha")
			}
		}
		if !bytes.Contains(generated, []byte(offsetContract)) {
			t.Fatal("negative control changed the full positive contract")
		}
		if strings.Contains(offsetContract, "canonicalRecordCount") || strings.Contains(offsetContract, "requires index <= core.recordCount") || strings.Contains(offsetContract, "core.magic") || strings.Contains(offsetContract, "core.featureFlags") {
			t.Fatal("raw offset helper was given an unestablished caller validity premise")
		}
		for _, declaration := range target.Types {
			if !bytes.Contains(generated, []byte(declaration.Declaration)) {
				t.Fatal("full actual type declaration was narrowed")
			}
		}
	}
}

func offsetFixture(t *testing.T, target offsetTarget, extra string) (string, string) {
	t.Helper()
	repo, cache := payloadFixture(t, target.Payload, extra)
	for _, declaration := range target.Types {
		path := filepath.Join(repo, declaration.Path)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(declaration.Declaration + "\n")
		closeErr := file.Close()
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	path := filepath.Join(repo, recordsRelative)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(append(bytes.Clone(target.Function), '\n'))
	closeErr := file.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return repo, cache
}

func loadOffsetFixture(t *testing.T, repo, cache string) (offsetTarget, error) {
	t.Helper()
	payload, err := loadPayloadFixture(t, repo, cache)
	if err != nil {
		return offsetTarget{}, err
	}
	return loadOffset(repo, cache, payload)
}

func TestOffsetGoValidUnusedFieldSubsetAndAliasesRequireReview(t *testing.T) {
	target := currentOffset(t)
	for _, kind := range []string{"unused field removed", "core alias", "suite alias", "enum width", "pointer argument"} {
		t.Run(kind, func(t *testing.T) {
			repo, cache := offsetFixture(t, target, "")
			relative := recordCountRelative
			if kind == "suite alias" || kind == "enum width" {
				relative = preambleRelative
			}
			if kind == "pointer argument" {
				relative = recordsRelative
			}
			path := filepath.Join(repo, relative)
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unused field removed":
				source = bytes.Replace(source, []byte("\tmagic              [4]byte\n"), nil, 1)
			case "core alias":
				source = bytes.Replace(source, []byte("type logicalCore struct"), []byte("type logicalCore = struct"), 1)
			case "suite alias":
				source = bytes.Replace(source, []byte("type Suite uint16"), []byte("type Suite = uint16"), 1)
			case "enum width":
				source = bytes.Replace(source, []byte("type Suite uint16"), []byte("type Suite uint32"), 1)
			case "pointer argument":
				source = bytes.Replace(source, []byte("core logicalCore,"), []byte("core *logicalCore,"), 1)
			}
			if err = os.WriteFile(path, source, 0644); err != nil {
				t.Fatal(err)
			}
			if _, _, err = loadSource(repo, cache, recordsRelative, "./internal/pcv3operation/internal/pcv3"); err != nil {
				t.Fatalf("type-closure fixture must be valid actual Go: %v", err)
			}
			if _, err = loadOffsetFixture(t, repo, cache); err == nil {
				t.Fatal("unreviewed by-value/full-type source change was admitted")
			}
		})
	}
}

func TestOffsetFullStructBuiltinFieldTypesCannotBeProjectedFromOmittedAliases(t *testing.T) {
	repo, cache := offsetFixture(t, currentOffset(t), "type byte = uint16\n")
	if _, _, err := loadSource(repo, cache, recordsRelative, "./internal/pcv3operation/internal/pcv3"); err != nil {
		t.Fatalf("unused array-field alias fixture must be valid Go: %v", err)
	}
	if _, err := loadOffsetFixture(t, repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed field/type binding") {
		t.Fatalf("omitted byte alias changed the full struct representation: %v", err)
	}
}

func TestOffsetFreshResultNamesCannotCaptureExistingOk(t *testing.T) {
	target := currentOffset(t)
	repo, cache := offsetFixture(t, target, "")
	payload, err := loadPayloadFixture(t, repo, cache)
	if err != nil {
		t.Fatal(err)
	}
	previous := payloadResultNames
	t.Cleanup(func() { payloadResultNames = previous })
	payloadResultNames = []string{"resultValue", "ok"}
	if _, err = loadOffset(repo, cache, payload); err == nil || !strings.Contains(err.Error(), "collides with a source identifier") {
		t.Fatalf("offset named result could capture a real local ok: %v", err)
	}
}

func TestOffsetControlRequiresExactPostconditionAndOrdinaryFailure(t *testing.T) {
	for name := range offsetControls {
		log := "Error at: </workspace/" + name + "/offset.go:196:9> Postcondition might not hold.\nAssertion " + offsetPost + " might not hold.\nGobra found 1 error.\n"
		if !offsetRejected(1, log, name, 196) {
			t.Fatal("required offset diagnostic rejected")
		}
		for _, changed := range []string{strings.Replace(log, ":196:9>", ":195:9>", 1), strings.Replace(log, "Assertion "+offsetPost, "Assertion false", 1), log + "timeout", log + "OutOfMemory", log + "integer overflow", strings.Replace(log, "found 1 error", "found 2 errors", 1)} {
			if offsetRejected(1, changed, name, 196) {
				t.Fatal("unrelated failure counted as offset proof control")
			}
		}
	}
}
