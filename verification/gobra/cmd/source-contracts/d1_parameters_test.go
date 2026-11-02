package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestD1CurrentFullStructsAndOwnedCommentsPreserveExecutableSource(t *testing.T) {
	repo := repository(t)
	target, err := loadD1(repo, filepath.Join(repo, "verification/gobra/_build/go-cache"))
	if err != nil {
		t.Fatal(err)
	}
	for _, negative := range []bool{false, true} {
		generated, identity, err := annotateD1(target.Projection, negative)
		if err != nil {
			t.Fatal(err)
		}
		if identity.BodyRecovered == negative || identity.ControlBodyRecovered != negative || identity.BodyBytesIdentical || identity.DeclarationsIdentical == negative || identity.OwnedResultComments != 2 || len(identity.OwnedBodyComments) != 4 {
			t.Fatalf("incorrect D1 source identity: %+v", identity)
		}
		if err = typecheckD1(generated, target.Imports); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(generated, []byte("index <= 18446744073709551615")) || bytes.Contains(generated, []byte("index < 281474976710656")) {
			t.Fatal("constructor proof lost full uint64 domain")
		}
		if negative && (!bytes.Contains(generated, []byte("//@ requires index == 0")) || !bytes.Contains(generated, []byte(d1BytePost)) || bytes.Contains(generated, []byte(d1NoncePost))) {
			t.Fatal("concrete negative consequence is not isolated to the control")
		}
		if !negative && (!bytes.Contains(generated, []byte(d1NoncePost)) || bytes.Contains(generated, []byte("//@ requires index == 0"))) {
			t.Fatal("positive contract was narrowed for the negative control")
		}
	}
}

func TestD1GoValidWrappingExpressionFailsAdmissionBeforeProof(t *testing.T) {
	source := strings.Replace(d1Reviewed, "nonce[16:], index)", "nonce[16:], (index*2)/2)", 1)
	repo, cache := d1Fixture(t, source, "", "type D1Profile uint16\n")
	if _, _, err := loadSource(repo, cache, d1Relative, "./internal/pcv3operation/internal/pcv3"); err != nil {
		t.Fatalf("wrapping constructor fixture must remain valid actual Go: %v", err)
	}
	if _, err := loadD1(repo, cache); err == nil || !strings.Contains(err.Error(), "outside the reviewed constructor") {
		t.Fatalf("Go finite-word arithmetic was admitted to a nooverflow proof: %v", err)
	}
}

func TestD1NoOverflowAdmissionRejectsArithmeticInputMutationAndAliases(t *testing.T) {
	// These Go-valid changes need a new finite-word semantics review before nooverflow.
	for name, mutant := range map[string]string{
		"wrapping multiplication division": strings.Replace(d1Reviewed, "nonce[16:], index)", "nonce[16:], (index*2)/2)", 1),
		"shift changed":                    strings.Replace(d1Reviewed, "index<<16", "index<<15", 1),
		"parameter write":                  strings.Replace(d1Reviewed, "var nonce [24]byte", "index = 0; var nonce [24]byte", 1),
		"receiver write":                   strings.Replace(d1Reviewed, "var nonce [24]byte", "codec.closed = true; var nonce [24]byte", 1),
		"alias":                            strings.Replace(d1Reviewed, "var nonce [24]byte", "alias := index; _ = alias; var nonce [24]byte", 1),
		"wrong prefix":                     strings.Replace(d1Reviewed, "codec.keys.xNoncePrefix[:]", "codec.keys.serpentPrefix[:]", 1),
		"partial struct":                   strings.Replace(d1Reviewed, " mac [32]byte\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := reviewD1Shape([]byte(mutant)); err == nil {
				t.Fatal("unreviewed nooverflow source behavior was admitted")
			}
		})
	}
}

func d1Fixture(t *testing.T, source, extra, profile string) (string, string) {
	t.Helper()
	repo, cache := recordCountFixture(t, "package pcv3\n")
	for relative, content := range map[string]string{d1Relative: source, "src/internal/pcv3operation/internal/pcv3/extra.go": "package pcv3\n" + extra, d1ProfileRelative: "package pcv3credential\n" + profile, binaryHeaderRelative: "package binary\n"} {
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

func TestD1ActualBindingsCannotBecomeBuiltinsWhenOtherFilesAreOmitted(t *testing.T) {
	for name, extra := range map[string]string{"copy": "func copy(dst, src []byte) int { return 0 }", "byte": "type byte = uint8"} {
		t.Run(name, func(t *testing.T) {
			// Physical positions keep this check effective even after a source line directive.
			source := strings.Replace(d1Reviewed, " var nonce [24]byte", "//line omitted.go:1\n var nonce [24]byte", 1)
			repo, cache := d1Fixture(t, source, extra, "type D1Profile uint16\n")
			if _, err := loadD1(repo, cache); err == nil || !strings.Contains(err.Error(), "unreviewed actual binding") {
				t.Fatalf("omitted package binding became builtin: %v", err)
			}
		})
	}
}

func TestD1ProfileProjectionRejectsAliases(t *testing.T) {
	repo, cache := d1Fixture(t, d1Reviewed, "", "type D1Profile = uint16\n")
	if _, err := loadD1(repo, cache); err == nil {
		t.Fatal("changed app type header was silently substituted")
	}
}

func TestD1GoValidStructAliasNeedsSourceSubsetReview(t *testing.T) {
	source := strings.Replace(d1Reviewed, "type d1OuterKeys struct", "type d1OuterKeys = struct", 1)
	repo, cache := d1Fixture(t, source, "", "type D1Profile uint16\n")
	if _, _, err := loadSource(repo, cache, d1Relative, "./internal/pcv3operation/internal/pcv3"); err != nil {
		t.Fatalf("struct-alias fixture must remain valid actual Go: %v", err)
	}
	if _, err := loadD1(repo, cache); err == nil {
		t.Fatal("unreviewed struct alias was admitted to the defined-struct source subset")
	}
}

func TestD1InputMarkersRejectedBeforeOwnedAnnotations(t *testing.T) {
	for _, marker := range []string{"// @ requires false", "/*\t@ requires false @*/", "@ \t*/", "//\v@ requires false"} {
		if err := reviewD1Shape([]byte(d1Reviewed + "\n// " + marker + "\n")); err == nil {
			t.Fatalf("input marker %q was admitted", marker)
		}
	}
}

func TestD1ControlRequiresExactBytePostconditionAndOrdinaryFailure(t *testing.T) {
	log := "Error at: </workspace/d1-parameters-wrong-index/parameters.go:29:9> Postcondition might not hold.\nAssertion nonceOut[23] == 0 might not hold.\nGobra found 1 error.\n"
	if !d1Rejected(1, log, 29) {
		t.Fatal("exact control diagnostic rejected")
	}
	for _, changed := range []string{strings.Replace(log, ":29:9>", ":28:9>", 1), strings.Replace(log, "nonceOut[23] == 0", "ivOut[0] == 0", 1), log + "timeout", log + "OutOfMemory", log + "integer overflow", strings.Replace(log, "found 1 error", "found 2 errors", 1)} {
		if d1Rejected(1, changed, 29) {
			t.Fatal("unrelated or incomplete prover failure counted as control evidence")
		}
	}
}
