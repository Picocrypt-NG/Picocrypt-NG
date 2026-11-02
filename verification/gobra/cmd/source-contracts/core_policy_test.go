package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func currentCorePolicy(t *testing.T) corePolicyTarget {
	t.Helper()
	repo := repository(t)
	cache := filepath.Join(repo, "verification/gobra/_build/go-cache")
	arithmetic, err := loadArithmetic(repo, cache)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := loadMetadata(repo, cache, arithmetic)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := loadPayload(repo, cache, arithmetic)
	if err != nil {
		t.Fatal(err)
	}
	target, err := loadCorePolicy(repo, cache, metadata, payload)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestCorePolicyNineActualBodiesKeepOneBooleanCallerInterface(t *testing.T) {
	target := currentCorePolicy(t)
	for _, name := range []string{"core-policy-positive", "core-policy-count-mismatch"} {
		generated, evidence, err := annotateCorePolicy(target, name)
		if err != nil {
			t.Fatal(err)
		}
		if !evidence.BindingGraphs || !evidence.CompleteTypes || len(evidence.Functions) != 9 || evidence.MaskUnion != "uint16(3)" {
			t.Fatal("core policy source/types/mask binding was not established")
		}
		for _, identity := range evidence.Functions {
			if !identity.ASTRecovered || !identity.BodyRecovered {
				t.Fatalf("actual source not recovered for %s", identity.Function)
			}
		}
		if !bytes.Contains(generated, []byte("func validLogicalCore(core logicalCore /*@ , ghost magicOut gpointer[bool] @*/) (/*@ accepted @*/ bool)")) || !bytes.Contains(generated, []byte("!validLogicalCore(core) /*@ with: magicOut @*/")) {
			t.Fatal("callable one-Boolean ghost OUT interface was replaced")
		}
		if name == "core-policy-positive" && digest(generated) != corePolicyTemplateSHA256 {
			t.Fatal("frozen source proof input changed")
		}
		if name == "core-policy-count-mismatch" && evidence.PostconditionLine == 0 {
			t.Fatal("count control has no exact full-IFF diagnostic location")
		}
	}
}

func TestCorePolicyRejectsChangedActualValidatorAndGeometryDeclarations(t *testing.T) {
	target := currentCorePolicy(t)
	for _, kind := range []string{"major guard", "full geometry"} {
		t.Run(kind, func(t *testing.T) {
			changed := target
			if kind == "major guard" {
				changed.Functions = map[string][]byte{}
				for name, source := range target.Functions {
					changed.Functions[name] = source
				}
				changed.Functions["validLogicalCore"] = bytes.Replace(target.Functions["validLogicalCore"], []byte("core.major != formatMajor"), []byte("core.major == formatMajor"), 1)
			} else {
				changed.Types = map[string][]byte{}
				for name, source := range target.Types {
					changed.Types[name] = source
				}
				changed.Types["Geometry"] = bytes.Replace(target.Types["Geometry"], []byte("fileSize            int64"), []byte("fileSize            uint64"), 1)
				if bytes.Equal(changed.Types["Geometry"], target.Types["Geometry"]) {
					t.Fatal("geometry change fixture did not alter its native width")
				}
			}
			if _, _, err := annotateCorePolicy(changed, "core-policy-positive"); err == nil {
				t.Fatal("changed native source declaration received the old proof")
			}
		})
	}
}

func TestCorePolicyNativeBindingGraphRejectsAnOmittedFalseGlobal(t *testing.T) {
	target := currentCorePolicy(t)
	source := append(bytes.Clone(target.Original), []byte("\nvar false = true\n")...)
	pkg, info, _, functions, err := sourceCopyInfo(source, target.Metadata.Arithmetic.Imports, corePolicyNames)
	if err != nil {
		t.Fatalf("capture fixture must remain valid Go: %v", err)
	}
	if _, err = corePolicyGraph(pkg, info, functions["validLogicalCore"]); err == nil || !strings.Contains(err.Error(), "unreviewed core policy binding") {
		t.Fatalf("omitted false global was silently replaced by builtin false: %v", err)
	}
}

func TestCorePolicyOwnedOUTObservationCannotDrift(t *testing.T) {
	target := currentCorePolicy(t)
	source := bytes.Replace([]byte(corePolicyTemplate), []byte(corePolicyOwnedComments[1]), []byte("//@ *magicOut = true\n"), 1)
	if _, _, err := corePolicyInverse(source, target.Metadata.Arithmetic.Imports); err == nil {
		t.Fatal("changed ghost observation received the source-erasure evidence")
	}
}

func TestCorePolicyControlRequiresExactFullIFFRejection(t *testing.T) {
	log := "Error at: </workspace/core-policy-count-mismatch/core_policy.go:255:9> Postcondition might not hold.\nAssertion matches == " + corePolicyPost + " might not hold.\nGobra found 1 error.\n"
	if !corePolicyRejected(1, log, 255) {
		t.Fatal("expected full-IFF rejection was refused")
	}
	for _, altered := range []string{strings.Replace(log, ":255:9>", ":254:9>", 1), strings.Replace(log, "Assertion matches == "+corePolicyPost, "Assertion true", 1), strings.Replace(log, "Gobra found 1 error.", "Gobra found 2 errors.", 1), log + "timeout", log + "OutOfMemory", log + "integer overflow"} {
		if corePolicyRejected(1, altered, 255) {
			t.Fatal("unrelated, incomplete or resource failure counted as the count control")
		}
	}
	if corePolicyRejected(0, log, 255) {
		t.Fatal("successful process counted as a negative proof control")
	}
}
