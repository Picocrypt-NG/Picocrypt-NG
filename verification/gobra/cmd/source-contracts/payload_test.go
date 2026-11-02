package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func currentPayload(t *testing.T) payloadTarget {
	t.Helper()
	repo := repository(t)
	cache := filepath.Join(repo, "verification/gobra/_build/go-cache")
	arithmetic, err := loadArithmetic(repo, cache)
	if err != nil {
		t.Fatal(err)
	}
	target, err := loadPayload(repo, cache, arithmetic)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestPayloadSixActualBodiesConstantsLocalScopesAndFullContracts(t *testing.T) {
	target := currentPayload(t)
	if _, ok := target.Snapshots[preambleRelative]; !ok {
		t.Fatal("RS constant dependency file is outside the parsed source closure")
	}
	scopes := map[int]bool{}
	for _, local := range target.Locals {
		if local.Function == "canonicalPayloadLength" && local.Name == "ok" {
			if scopes[local.Definition] || local.Type != "bool" {
				t.Fatal("distinct ok objects were merged")
			}
			scopes[local.Definition] = true
		}
	}
	if len(scopes) != 3 {
		t.Fatal("canonical payload needs all three distinct lexical ok objects")
	}
	for _, name := range []string{"payload-positive", "payload-final-omitted", "payload-rs-floored", "payload-bad-count-accepted"} {
		generated, evidence, err := annotatePayload(target, name)
		if err != nil {
			t.Fatal(err)
		}
		if !evidence.BindingGraphs || len(evidence.Functions) != 6 {
			t.Fatal("all six original binding graphs are required")
		}
		for _, function := range evidence.Functions {
			if !function.ASTRecovered || !function.BodyRecovered {
				t.Fatal("source body was not recovered")
			}
			if name == "payload-positive" && function.RawBodyIdentical != (function.Function != "checkedMul64") {
				t.Fatal("raw body identity hides the sole reviewed alpha adapter")
			}
		}
		for _, contract := range []string{payloadLengthContract, encodedBodyContract, payloadCountContract} {
			if !bytes.Contains(generated, []byte(contract)) {
				t.Fatal("control weakened a full positive contract")
			}
		}
		if strings.Contains(string(generated), "//@ requires ciphertextLength <= 1048576") || strings.Contains(string(generated), "//@ requires recordCount ==") {
			t.Fatal("caller bounds replaced the full helper domain")
		}
	}
}

func payloadFixture(t *testing.T, target payloadTarget, extra string) (string, string) {
	t.Helper()
	repo, cache := recordCountFixture(t, "package pcv3\n")
	sources := map[string]string{}
	for path := range target.Snapshots {
		sources[path] = "package pcv3\n"
	}
	sources[arithmeticRelative] = string(target.Arithmetic.Source)
	for _, constant := range target.Constants {
		sources[constant.Path] += "const " + constant.Initializer + "\n"
	}
	for _, name := range []string{"canonicalRecordCount", "canonicalPayloadLength", "encodedRecordBodyLength"} {
		sources[payloadPaths[name]] += string(target.Functions[name]) + "\n"
	}
	sources[bitsHeaderRelative] = string(target.Arithmetic.Header)
	sources["src/internal/pcv3operation/internal/pcv3/extra.go"] = "package pcv3\n" + extra
	for path, source := range sources {
		full := filepath.Join(repo, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return repo, cache
}

func loadPayloadFixture(t *testing.T, repo, cache string) (payloadTarget, error) {
	t.Helper()
	arithmetic, err := loadArithmetic(repo, cache)
	if err != nil {
		return payloadTarget{}, err
	}
	return loadPayload(repo, cache, arithmetic)
}

func TestPayloadConstantClosureRejectsSameValueUnwatchedDependency(t *testing.T) {
	target := currentPayload(t)
	repo, cache := payloadFixture(t, target, "const outsideData = 128\n")
	path := filepath.Join(repo, preambleRelative)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`rs128DataLength\s+uint64\s*=\s*128`)
	changed := pattern.ReplaceAll(source, []byte("rs128DataLength uint64 = outsideData"))
	if bytes.Equal(source, changed) {
		t.Fatal("constant dependency fixture did not change")
	}
	if err = os.WriteFile(path, changed, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadSourceSnapshots(repo, cache, []string{arithmeticRelative, recordCountRelative, geometryRelative, recordsRelative, preambleRelative}, "./internal/pcv3operation/internal/pcv3"); err != nil {
		t.Fatalf("constant dependency fixture must be Go-valid: %v", err)
	}
	if _, err = loadPayloadFixture(t, repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed dependency") {
		t.Fatalf("same-valued constant dependency escaped the watched closure: %v", err)
	}
}

func TestPayloadConstantMaterializationPreservesGoTypeAsWellAsValue(t *testing.T) {
	repo, cache := payloadFixture(t, currentPayload(t), "")
	path := filepath.Join(repo, recordCountRelative)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := regexp.MustCompile(`recordPlaintextMax\s*=`).ReplaceAll(source, []byte("recordPlaintextMax uint64 ="))
	if bytes.Equal(source, changed) {
		t.Fatal("typed constant fixture did not change")
	}
	if err = os.WriteFile(path, changed, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadSource(repo, cache, recordCountRelative, "./internal/pcv3operation/internal/pcv3"); err != nil {
		t.Fatalf("same-value typed constant fixture must remain Go-valid: %v", err)
	}
	if _, err = loadPayloadFixture(t, repo, cache); err == nil || !strings.Contains(err.Error(), "type/value/origin changed") {
		t.Fatalf("untyped-to-typed constant change was ignored: %v", err)
	}
}

func TestPayloadFreshResultsRejectRealLocalOkBeforeGobrafier(t *testing.T) {
	repo, cache := payloadFixture(t, currentPayload(t), "")
	if _, _, err := loadSource(repo, cache, geometryRelative, "./internal/pcv3operation/internal/pcv3"); err != nil {
		t.Fatal(err)
	}
	previous := payloadResultNames
	t.Cleanup(func() { payloadResultNames = previous })
	payloadResultNames = []string{"resultValue", "ok"}
	if _, err := loadPayloadFixture(t, repo, cache); err == nil || !strings.Contains(err.Error(), "collides with a source identifier") {
		t.Fatalf("named-result ok could rebind a real local ShortDecl: %v", err)
	}
}

func TestPayloadPhysicalBindingsRejectOmittedFalseGlobal(t *testing.T) {
	repo, cache := payloadFixture(t, currentPayload(t), "var false = true\n")
	path := filepath.Join(repo, geometryRelative)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source = bytes.Replace(source, []byte("if recordCount !="), []byte("//line hidden.go:1\nif recordCount !="), 1)
	if err = os.WriteFile(path, source, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadPayloadFixture(t, repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed payload binding") {
		t.Fatalf("omitted global false became the builtin under line directives: %v", err)
	}
}

func TestPayloadControlRequiresExactValuePostconditionAndOrdinaryFailure(t *testing.T) {
	for name, control := range payloadControls {
		log := "Error at: </workspace/" + name + "/payload.go:92:9> Postcondition might not hold.\nAssertion " + control.Post + " might not hold.\nGobra found 1 error.\n"
		if !payloadRejected(1, log, name, 92) {
			t.Fatal("intended payload postcondition was rejected")
		}
		for _, changed := range []string{strings.Replace(log, ":92:9>", ":91:9>", 1), strings.Replace(log, "Assertion "+control.Post, "Assertion false", 1), log + "timeout", log + "OutOfMemory", log + "integer overflow", strings.Replace(log, "found 1 error", "found 2 errors", 1)} {
			if payloadRejected(1, changed, name, 92) {
				t.Fatal("unrelated failure counted as a payload control")
			}
		}
	}
}

func TestPayloadClosureCannotReplaceEarlierRecordCountSnapshot(t *testing.T) {
	before, err := os.ReadFile(filepath.Join(repository(t), recordCountRelative))
	if err != nil {
		t.Fatal(err)
	}
	after := append(bytes.Clone(before), []byte("\n// changed after the earlier source check\n")...)
	snapshots := map[string][]byte{recordCountRelative: before}
	if err = mergeSourceSnapshots(snapshots, map[string][]byte{recordCountRelative: after}); err == nil {
		t.Fatal("later payload closure replaced the earlier record-count source snapshot")
	}
	if !bytes.Equal(snapshots[recordCountRelative], before) {
		t.Fatal("conflict erased the earlier proof's source evidence")
	}
}

func TestPayloadSnapshotUnionAcceptsMatchingEarlierAndNewDependencies(t *testing.T) {
	snapshots := map[string][]byte{recordCountRelative: []byte("earlier capsule")}
	incoming := map[string][]byte{recordCountRelative: []byte("earlier capsule"), preambleRelative: []byte("RS dependency")}
	if err := mergeSourceSnapshots(snapshots, incoming); err != nil {
		t.Fatal(err)
	}
	if string(snapshots[recordCountRelative]) != "earlier capsule" || string(snapshots[preambleRelative]) != "RS dependency" {
		t.Fatal("compatible proof source views were not retained")
	}
}
