package pcv3corpus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testD1CorpusFormat         = "pcv3-corpus-v4"
	testD1SchemaRevision       = "4"
	testD1SpecRevision         = "0.4"
	testD1SchemaResourceURL    = "https://pcv3.invalid/cumulative-v4/manifest.schema.json"
	testD1MutationPlanID       = "d1-mutation-plan-v1"
	testD1PrivateFixtureNotice = "TEST ONLY PRIVATE PCV3 D1 CONFORMANCE DATA; NOT SECRET OR OPERATIONAL"
	testD1GrammarNotice        = "TEST ONLY SYNTHETIC GRAMMAR; NOT A D1 MUTATION CAMPAIGN"
)

var testD1ArtifactRoles = [...]string{
	"credentials",
	"schedule",
	"front-bootstrap",
	"tail-bootstrap",
	"body",
	"volume",
	"inner-volume",
	"outer-plaintext",
	"plaintext",
}

type testD1VectorContract struct {
	id, credentialMode, keyfileMode string
	frontBootstrap, tailBootstrap   bool
}

// These are only identities, credential grammar, and physical membership for
// synthetic loader-policy artifacts. Product expectations are built once by
// testD1ScheduleDocument and never enter production loader tables.
var testD1VectorContracts = [...]testD1VectorContract{
	{id: "d1-paranoid-password-only-healthy", credentialMode: "password-only", keyfileMode: "none", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-paranoid-keyfiles-only-healthy", credentialMode: "keyfiles-only", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-paranoid-combined-ordered-healthy", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-paranoid-combined-unordered-healthy", credentialMode: "combined", keyfileMode: "unordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-degraded-front-bootstrap-only", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true},
	{id: "d1-degraded-tail-bootstrap-only", credentialMode: "combined", keyfileMode: "ordered", tailBootstrap: true},
	{id: "d1-negative-wrong-credential", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-record-tamper", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-record-reorder", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-body-truncation", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-final-loss", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-bootstrap-splice", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-anchored-ambiguity", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-inner-volume", credentialMode: "combined", keyfileMode: "ordered", frontBootstrap: true, tailBootstrap: true},
}

// TestD1PrivateCorpusContract is custody/loader policy evidence. Product D1
// behavior is asserted only by the tagged TestD1ProductionKDF lane.
func TestD1PrivateCorpusContract(t *testing.T) {
	t.Run("complete cumulative corpus is current", func(t *testing.T) {
		corpus, err := Load(writeTestD1Corpus(t), testCustodyID)
		if err != nil {
			t.Fatalf("Load(D1 corpus) error = %v", err)
		}
		if !corpus.isCurrentPhase4() {
			t.Fatal("D1 corpus lost the cumulative normal-volume contract")
		}
		if !corpus.isCurrentD1() {
			t.Fatal("complete D1 corpus did not satisfy the closed D1 inventory")
		}
	})

	t.Run("previous cumulative corpus remains normal-only", func(t *testing.T) {
		corpus, err := Load(writeTestCumulativeV3Corpus(t), testCustodyID)
		if err != nil {
			t.Fatalf("Load(v3 corpus) error = %v", err)
		}
		if !corpus.isCurrentPhase4() || corpus.isCurrentD1() {
			t.Fatal("v3 corpus was not preserved as normal-only compatibility evidence")
		}
	})

	t.Run("structured factors and operation schedule are callback scoped", func(t *testing.T) {
		const id = "d1-paranoid-combined-ordered-healthy"
		var aliases [][]byte
		err := WithD1VolumeFixtures(writeTestD1Corpus(t), testCustodyID, []string{id}, func(fixtures []*D1VolumeFixture) error {
			if len(fixtures) != 1 || fixtures[0] == nil {
				t.Fatal("structured D1 fixture was not borrowed")
			}
			fixture := fixtures[0]
			aliases = append(aliases, fixture.Password(), fixture.WrongPassword())
			aliases = append(aliases, fixture.Keyfiles()...)
			aliases = append(aliases, fixture.WrongKeyfiles()...)
			for _, alias := range aliases {
				if len(alias) == 0 || allZero(alias) {
					t.Fatal("decoded D1 credential was empty or already zero inside callback")
				}
			}
			normal, found := fixture.Operation("normal-correct")
			if !found || normal.Mode() != "normal" || normal.Factors() != "correct" ||
				normal.KeyfileOrder() != "manifest" || normal.ExpectedOutcome() != "success" ||
				normal.ExpectedKDFCalls() != 2 || !normal.ExpectedCompletion() {
				t.Fatal("decoded D1 normal operation did not preserve the closed schedule")
			}
			force, found := fixture.Operation("force-correct")
			if !found || force.Mode() != "force" || force.ExpectedD1Provenance() != "matching" ||
				force.ExpectedForceProvenance() != "verified" || force.ExpectedKDFCalls() != 3 {
				t.Fatal("decoded D1 Force operation did not preserve independent expectations")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WithD1VolumeFixtures(structured) error = %v", err)
		}
		assertAliasesZero(t, aliases)
	})

	t.Run("unknown credential grammar fails before callback", func(t *testing.T) {
		root := writeTestD1Corpus(t)
		mutateTestD1ArtifactDocument(t, root, testD1ArtifactID(testD1VectorContracts[0].id, "credentials"), func(document map[string]any) {
			document["unexpected_secret_field"] = "must-not-be-accepted"
		})
		called := false
		err := WithD1VolumeFixtures(root, testCustodyID, []string{testD1VectorContracts[0].id}, func([]*D1VolumeFixture) error {
			called = true
			return nil
		})
		assertRefusal(t, err, RefusalUnknown)
		if called {
			t.Fatal("malformed D1 credentials reached the callback")
		}
	})

	t.Run("credential mode is owned by the credentials document", func(t *testing.T) {
		id := testD1VectorContracts[0].id
		root := writeTestD1Corpus(t)
		mutateTestD1ArtifactDocument(t, root, testD1ArtifactID(id, "credentials"), func(document map[string]any) {
			document["credential_mode"] = "combined"
			document["keyfile_mode"] = "unordered"
			document["correct"].(map[string]any)["keyfiles_hex"] = []any{"0102"}
			document["wrong"].(map[string]any)["keyfiles_hex"] = []any{"0304"}
		})
		err := WithD1VolumeFixtures(root, testCustodyID, []string{id}, func(fixtures []*D1VolumeFixture) error {
			if len(fixtures) != 1 || fixtures[0].CredentialMode() != "combined" ||
				fixtures[0].KeyfileMode() != "unordered" {
				t.Fatal("D1 fixture did not take credential modes from its credentials document")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WithD1VolumeFixtures(credentials-owned mode) error = %v", err)
		}
	})

	t.Run("unknown schedule code fails before callback", func(t *testing.T) {
		id := testD1VectorContracts[0].id
		root := writeTestD1Corpus(t)
		mutateTestD1ArtifactDocument(t, root, testD1ArtifactID(id, "schedule"), func(document map[string]any) {
			operation := document["operations"].([]any)[0].(map[string]any)
			operation["expected_code"] = "PCV3_NOT_A_CODE"
		})
		called := false
		err := WithD1VolumeFixtures(root, testCustodyID, []string{id}, func([]*D1VolumeFixture) error {
			called = true
			return nil
		})
		assertRefusal(t, err, RefusalMalformed)
		if called {
			t.Fatal("internally inconsistent D1 schedule reached the callback")
		}
	})

	t.Run("manifest semantics must agree across all physical roles", func(t *testing.T) {
		root := writeTestD1Corpus(t)
		id := testD1ArtifactID(testD1VectorContracts[0].id, "body")
		mutateTestD1Manifest(t, root, func(manifest map[string]any) {
			for _, raw := range manifest["fixtures"].([]any) {
				fixture := raw.(map[string]any)
				if fixture["id"] == id {
					fixture["kdf_calls"] = 1
					return
				}
			}
			t.Fatal("synthetic D1 body manifest entry is missing")
		})
		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalMalformed)
	})

	t.Run("volume must be the exact physical artifact composition", func(t *testing.T) {
		id := testD1VectorContracts[0].id
		root := writeTestD1Corpus(t)
		mutateTestD1ArtifactBytes(t, root, testD1ArtifactID(id, "volume"), func(data []byte) []byte {
			return append(data, 0x7f)
		})
		called := false
		err := WithD1VolumeFixtures(root, testCustodyID, []string{id}, func([]*D1VolumeFixture) error {
			called = true
			return nil
		})
		assertRefusal(t, err, RefusalMalformed)
		if called {
			t.Fatal("D1 volume with non-member bytes reached the callback")
		}
	})

	tests := []struct {
		name   string
		want   RefusalKind
		mutate func(*testing.T, string)
	}{
		{
			name: "missing pinned artifact",
			want: RefusalMissing,
			mutate: func(t *testing.T, root string) {
				removeTestD1ArtifactFile(t, root, testD1ArtifactID(testD1VectorContracts[0].id, testD1ArtifactRoles[0]))
			},
		},
		{
			name: "extra artifact",
			want: RefusalExtra,
			mutate: func(t *testing.T, root string) {
				writeTestFile(t, root, "positive/d1-unpinned-extra.bin", "TEST ONLY")
			},
		},
		{
			name: "duplicate fixture identity",
			want: RefusalDuplicate,
			mutate: func(t *testing.T, root string) {
				mutateTestD1Manifest(t, root, func(manifest map[string]any) {
					fixtures := manifest["fixtures"].([]any)
					for _, raw := range fixtures {
						fixture := raw.(map[string]any)
						if fixture["category"] == "d1-volume" {
							clone := make(map[string]any, len(fixture))
							for key, value := range fixture {
								clone[key] = value
							}
							manifest["fixtures"] = append(fixtures, clone)
							return
						}
					}
					t.Fatal("D1 fixture missing from synthetic manifest")
				})
			},
		},
		{
			name: "unknown fixture identity",
			want: RefusalUnknown,
			mutate: func(t *testing.T, root string) {
				mutateTestD1Manifest(t, root, func(manifest map[string]any) {
					for _, raw := range manifest["fixtures"].([]any) {
						fixture := raw.(map[string]any)
						if fixture["category"] == "d1-volume" {
							fixture["id"] = "d1-unknown--credentials"
							return
						}
					}
				})
			},
		},
		{
			name: "stale specification revision",
			want: RefusalSchema,
			mutate: func(t *testing.T, root string) {
				mutateTestD1Manifest(t, root, func(manifest map[string]any) {
					manifest["spec_revision"] = "0.3"
				})
			},
		},
		{
			name: "unprovenanced artifact",
			want: RefusalProvenance,
			mutate: func(t *testing.T, root string) {
				corruptTestD1Provenance(t, root)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestD1Corpus(t)
			tt.mutate(t, root)
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, tt.want)
		})
	}

	t.Run("wrong custody", func(t *testing.T) {
		_, err := Load(writeTestD1Corpus(t), "wrong-synthetic-custody")
		assertRefusal(t, err, RefusalCustody)
	})
}

func TestWithD1VolumeFixturesZeroesBorrowedBytes(t *testing.T) {
	root := writeTestD1Corpus(t)
	ids := []string{
		"d1-paranoid-combined-ordered-healthy",
		"d1-negative-record-tamper",
	}
	var aliases [][]byte
	err := WithD1VolumeFixtures(root, testCustodyID, ids, func(fixtures []*D1VolumeFixture) error {
		if len(fixtures) != len(ids) {
			t.Fatalf("borrowed D1 fixture count = %d, want %d", len(fixtures), len(ids))
		}
		for index, fixture := range fixtures {
			if fixture.ID() != ids[index] {
				t.Fatalf("borrowed D1 fixture %d ID = %q, want %q", index, fixture.ID(), ids[index])
			}
			contract := testD1VectorContractForID(t, fixture.ID())
			if fixture.CredentialMode() != contract.credentialMode || fixture.KeyfileMode() != contract.keyfileMode ||
				(len(fixture.FrontBootstrap()) == d1BootstrapBytes) != contract.frontBootstrap ||
				(len(fixture.TailBootstrap()) == d1BootstrapBytes) != contract.tailBootstrap {
				t.Fatal("borrowed D1 fixture did not preserve credential grammar or physical membership")
			}
			borrowed := d1FixtureAliases(fixture)
			for _, alias := range borrowed {
				if len(alias) == 0 || allZero(alias) {
					t.Fatal("borrowed D1 artifact was empty or already zero inside callback")
				}
			}
			aliases = append(aliases, borrowed...)
			formatted := fmt.Sprintf("%s|%q|%v|%+v|%#v", fixture, fixture, fixture, fixture, fixture)
			if strings.Contains(formatted, root) || strings.Contains(formatted, "TEST ONLY") {
				t.Fatal("D1 fixture formatting disclosed borrowed material or the private root")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithD1VolumeFixtures() error = %v", err)
	}
	assertAliasesZero(t, aliases)
}

func TestWithD1VolumeFixturesZeroesOnCallbackErrorAndPanic(t *testing.T) {
	const id = "d1-paranoid-combined-ordered-healthy"
	sentinel := errors.New("TEST ONLY callback sentinel")
	panicSentinel := &struct{ label string }{label: "TEST ONLY callback panic sentinel"}

	t.Run("error", func(t *testing.T) {
		var aliases [][]byte
		err := WithD1VolumeFixtures(writeTestD1Corpus(t), testCustodyID, []string{id}, func(fixtures []*D1VolumeFixture) error {
			aliases = append(aliases, d1FixtureAliases(fixtures[0])...)
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("WithD1VolumeFixtures() error = %v, want callback sentinel", err)
		}
		assertAliasesZero(t, aliases)
	})

	t.Run("panic", func(t *testing.T) {
		var aliases [][]byte
		func() {
			defer func() {
				if recovered := recover(); recovered != panicSentinel {
					t.Fatalf("WithD1VolumeFixtures() panic = %v, want callback panic sentinel", recovered)
				}
			}()
			_ = WithD1VolumeFixtures(writeTestD1Corpus(t), testCustodyID, []string{id}, func(fixtures []*D1VolumeFixture) error {
				aliases = append(aliases, d1FixtureAliases(fixtures[0])...)
				panic(panicSentinel)
			})
		}()
		assertAliasesZero(t, aliases)
	})
}

func TestWithD1VolumeFixturesRejectsDuplicateUnknownAndLegacySelections(t *testing.T) {
	d1Root := writeTestD1Corpus(t)
	for _, tt := range []struct {
		name string
		root string
		ids  []string
		want RefusalKind
	}{
		{name: "duplicate", root: d1Root, ids: []string{testD1VectorContracts[0].id, testD1VectorContracts[0].id}, want: RefusalDuplicate},
		{name: "unknown", root: d1Root, ids: []string{"d1-future-unknown"}, want: RefusalUnknown},
		{name: "normal-only corpus", root: writeTestCumulativeV3Corpus(t), ids: []string{testD1VectorContracts[0].id}, want: RefusalUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			err := WithD1VolumeFixtures(tt.root, testCustodyID, tt.ids, func([]*D1VolumeFixture) error {
				called = true
				return nil
			})
			assertRefusal(t, err, tt.want)
			if called {
				t.Fatal("rejected D1 selection invoked the callback")
			}
		})
	}
}

func TestWithD1MutationPlanZeroesBorrowedBytes(t *testing.T) {
	var aliases [][]byte
	err := WithD1MutationPlan(writeTestD1Corpus(t), testCustodyID, func(plan *D1MutationPlan) error {
		if plan.ID() != testD1MutationPlanID {
			t.Fatalf("D1 mutation plan ID = %q, want %q", plan.ID(), testD1MutationPlanID)
		}
		mutations := plan.Mutations()
		if len(mutations) != len(d1MutationRegistry) {
			t.Fatal("D1 mutation plan did not preserve the closed registry")
		}
		for index, mutation := range mutations {
			if mutation.Contract().ID() != d1MutationRegistry[index].ID() || !validSHA256(mutation.SourceSHA256()) {
				t.Fatal("D1 mutation plan did not bind private material to tracked authority")
			}
			for _, alias := range [][]byte{mutation.Before(), mutation.After()} {
				if len(alias) == 0 || allZero(alias) {
					t.Fatal("D1 mutation transform was empty or already zero inside callback")
				}
				aliases = append(aliases, alias)
			}
			formattedMutation := fmt.Sprintf("%s|%q|%v|%+v|%#v", mutation, mutation, mutation, mutation, mutation)
			beforeDefaultFormat := fmt.Sprint(mutation.Before()) //nolint:staticcheck // QF1010 would change the default []byte-format leak oracle.
			afterDefaultFormat := fmt.Sprint(mutation.After())   //nolint:staticcheck // QF1010 would change the default []byte-format leak oracle.
			if strings.Contains(formattedMutation, beforeDefaultFormat) ||
				strings.Contains(formattedMutation, afterDefaultFormat) {
				t.Fatal("D1 mutation formatting disclosed private transform bytes")
			}
		}
		formatted := fmt.Sprintf("%s|%q|%v|%+v|%#v", plan, plan, plan, plan, plan)
		if strings.Contains(formatted, "grammar-only-a") || strings.Contains(formatted, "internal/pcv3") {
			t.Fatal("D1 mutation plan formatting disclosed private plan material")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithD1MutationPlan() error = %v", err)
	}
	assertAliasesZero(t, aliases)
}

func TestWithD1MutationPlanZeroesOnCallbackErrorAndPanic(t *testing.T) {
	sentinel := errors.New("TEST ONLY mutation callback sentinel")
	panicSentinel := &struct{ label string }{label: "TEST ONLY mutation callback panic sentinel"}

	t.Run("error", func(t *testing.T) {
		var aliases [][]byte
		err := WithD1MutationPlan(writeTestD1Corpus(t), testCustodyID, func(plan *D1MutationPlan) error {
			aliases = append(aliases, d1MutationAliases(plan)...)
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("WithD1MutationPlan() error = %v, want callback sentinel", err)
		}
		assertAliasesZero(t, aliases)
	})

	t.Run("panic", func(t *testing.T) {
		var aliases [][]byte
		func() {
			defer func() {
				if recovered := recover(); recovered != panicSentinel {
					t.Fatalf("WithD1MutationPlan() panic = %v, want callback panic sentinel", recovered)
				}
			}()
			_ = WithD1MutationPlan(writeTestD1Corpus(t), testCustodyID, func(plan *D1MutationPlan) error {
				aliases = append(aliases, d1MutationAliases(plan)...)
				panic(panicSentinel)
			})
		}()
		assertAliasesZero(t, aliases)
	})
}

func TestWithD1MutationPlanRejectsPrivateExecutionAuthority(t *testing.T) {
	for _, tt := range []struct {
		name  string
		field string
		value any
		want  RefusalKind
	}{
		{name: "self-authored marker", field: "expected_assertion_marker", value: "private marker is not authority", want: RefusalMalformed},
		{name: "per-entry timeout", field: "timeout_seconds", value: d1MutationTimeoutSeconds - 1, want: RefusalMalformed},
		{name: "unknown semantic ID", field: "id", value: "private-extra-mutation", want: RefusalUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestD1Corpus(t)
			mutateTestD1ArtifactDocument(t, root, testD1MutationPlanID, func(document map[string]any) {
				document["mutations"].([]any)[0].(map[string]any)[tt.field] = tt.value
			})
			called := false
			err := WithD1MutationPlan(root, testCustodyID, func(*D1MutationPlan) error {
				called = true
				return nil
			})
			assertRefusal(t, err, tt.want)
			if called {
				t.Fatal("private mutation execution authority reached the callback")
			}
		})
	}
}

func d1MutationAliases(plan *D1MutationPlan) [][]byte {
	var aliases [][]byte
	for _, mutation := range plan.Mutations() {
		aliases = append(aliases, mutation.Before(), mutation.After())
	}
	return aliases
}

func d1FixtureAliases(fixture *D1VolumeFixture) [][]byte {
	aliases := [][]byte{
		fixture.credentials, fixture.schedule, fixture.FrontBootstrap(), fixture.TailBootstrap(),
		fixture.Body(), fixture.Volume(), fixture.InnerVolume(), fixture.OuterPlaintext(), fixture.Plaintext(),
	}
	aliases = append(aliases, fixture.Password(), fixture.WrongPassword())
	aliases = append(aliases, fixture.Keyfiles()...)
	aliases = append(aliases, fixture.WrongKeyfiles()...)
	return aliases
}

func assertAliasesZero(t *testing.T, aliases [][]byte) {
	t.Helper()
	if len(aliases) == 0 {
		t.Fatal("zeroing oracle captured no aliases")
	}
	for _, alias := range aliases {
		if !allZero(alias) {
			t.Fatal("borrowed D1 alias retained bytes after callback unwind")
		}
	}
}

func writeTestD1Corpus(t *testing.T) string {
	t.Helper()
	root := writeTestCumulativeV3Corpus(t)
	writeTestFile(t, root, "manifest.schema.json", testD1ManifestSchema(t))

	manifestPath := filepath.Join(root, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read cumulative v3 manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode cumulative v3 manifest: %v", err)
	}
	manifest["format"] = testD1CorpusFormat
	manifest["schema_revision"] = testD1SchemaRevision
	manifest["spec_revision"] = testD1SpecRevision
	manifest["deferred_vector_classes"] = []any{"pcv3-writer"}

	generatorSource := "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"TEST ONLY D1 GRAMMAR\") }\n"
	generatorPath := "generator/d1-v4.go"
	generatorSHA := testSHA256(generatorSource)
	writeTestFile(t, root, generatorPath, generatorSource)
	provenance := testD1Provenance(generatorSHA)

	fixtures := manifest["fixtures"].([]any)
	for index, contract := range testD1VectorContracts {
		bundle := testD1ArtifactBundle(contract, byte(index+1))
		for _, role := range testD1ArtifactRoles {
			artifactID := testD1ArtifactID(contract.id, role)
			artifactPath := "positive/" + artifactID + ".bin"
			provenancePath := "provenance/" + artifactID + ".json"
			data := bundle[role]
			writeTestFile(t, root, artifactPath, string(data))
			writeTestFile(t, root, provenancePath, provenance)
			fixtures = append(fixtures, testD1ManifestEntry(
				artifactID, artifactPath, data, provenancePath, provenance, generatorPath, generatorSHA,
				"d1-volume", "success", "none", 0, "not-applicable",
			))
		}
	}

	mutationDocument := testD1MutationPlanDocument(t)
	mutationPath := "positive/" + testD1MutationPlanID + ".json"
	mutationProvenancePath := "provenance/" + testD1MutationPlanID + ".json"
	writeTestFile(t, root, mutationPath, string(mutationDocument))
	writeTestFile(t, root, mutationProvenancePath, provenance)
	fixtures = append(fixtures, testD1ManifestEntry(
		testD1MutationPlanID, mutationPath, mutationDocument, mutationProvenancePath, provenance,
		generatorPath, generatorSHA, "d1-mutation-plan", "accept", "none", 0, "not-applicable",
	))
	manifest["fixtures"] = fixtures

	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode synthetic D1 manifest: %v", err)
	}
	writeTestFile(t, root, "manifest.json", string(encoded))
	return root
}

func testD1ManifestSchema(t *testing.T) string {
	t.Helper()
	var schema map[string]any
	if err := json.Unmarshal([]byte(testSchemaV3), &schema); err != nil {
		t.Fatalf("decode cumulative v3 schema: %v", err)
	}
	schema["$id"] = testD1SchemaResourceURL
	properties := schema["properties"].(map[string]any)
	properties["format"] = map[string]any{"const": testD1CorpusFormat}
	properties["schema_revision"] = map[string]any{"const": testD1SchemaRevision}
	properties["spec_revision"] = map[string]any{"const": testD1SpecRevision}
	properties["fixtures"].(map[string]any)["minItems"] = len(testV3NormalFixtures) + len(testV2Phase4Fixtures) + 2 + len(testD1VectorContracts)*len(testD1ArtifactRoles) + 1
	properties["deferred_vector_classes"] = map[string]any{
		"type": "array", "minItems": 1, "maxItems": 1, "uniqueItems": true,
		"items": map[string]any{"const": "pcv3-writer"},
	}
	fixtureProperties := schema["$defs"].(map[string]any)["fixture"].(map[string]any)["properties"].(map[string]any)
	fixtureProperties["category"] = map[string]any{"enum": []any{"unicode17", "governance", "stream", "capsule", "normal-volume", "d1-volume", "d1-mutation-plan"}}
	fixtureProperties["failure_stage"] = map[string]any{"enum": []any{"none", "canonicalization", "governance", "wrap-auth", "replica-auth", "capsule-rs", "capsule-structure", "metadata", "descriptor", "record-auth", "final-record", "tail-geometry", "d1-bootstrap", "d1-body", "inner-volume"}}
	fixtureProperties["kdf_calls"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 4}
	fixtureProperties["force_state"] = map[string]any{"enum": []any{"not-applicable", "verified", "partial", "unverified"}}
	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("encode synthetic D1 schema: %v", err)
	}
	return string(encoded)
}

func testD1ArtifactBundle(contract testD1VectorContract, fill byte) map[string][]byte {
	password := []byte("TEST ONLY D1 password: " + contract.id)
	wrongPassword := []byte("TEST ONLY D1 wrong password: " + contract.id)
	keyfiles := [][]byte{{fill, fill ^ 0x31, fill ^ 0x72}, {fill ^ 0x5a, fill ^ 0xa5}}
	wrongKeyfiles := [][]byte{{fill ^ 0xff, fill ^ 0x17}}
	if contract.credentialMode == "password-only" {
		keyfiles = nil
		wrongKeyfiles = nil
	}
	if contract.credentialMode == "keyfiles-only" {
		password = nil
		wrongPassword = nil
	}
	credentials := testD1CredentialsDocument(contract, password, keyfiles, wrongPassword, wrongKeyfiles)
	front := []byte(nil)
	if contract.frontBootstrap {
		front = bytes.Repeat([]byte{fill}, 224)
	}
	tail := []byte(nil)
	if contract.tailBootstrap {
		tail = bytes.Repeat([]byte{fill ^ 0x5a}, 224)
	}
	body := bytes.Repeat([]byte{fill ^ 0xa5}, 96)
	plaintext := []byte("TEST ONLY SYNTHETIC PLAINTEXT GRAMMAR: " + contract.id)
	outerPlaintext := []byte("TEST ONLY SYNTHETIC OUTER PLAINTEXT GRAMMAR: " + contract.id)
	schedule := testD1ScheduleDocument(contract.id, uint64(len(plaintext)))
	volume := make([]byte, 0, len(front)+len(body)+len(tail))
	volume = append(volume, front...)
	volume = append(volume, body...)
	volume = append(volume, tail...)
	return map[string][]byte{
		"credentials":     credentials,
		"schedule":        schedule,
		"front-bootstrap": front,
		"tail-bootstrap":  tail,
		"body":            body,
		"volume":          volume,
		"inner-volume":    []byte("PCV\x00TEST ONLY INVALID INNER GRAMMAR: " + contract.id),
		"outer-plaintext": outerPlaintext,
		"plaintext":       plaintext,
	}
}

func testD1CredentialsDocument(
	contract testD1VectorContract,
	password []byte,
	keyfiles [][]byte,
	wrongPassword []byte,
	wrongKeyfiles [][]byte,
) []byte {
	encodeFactors := func(password []byte, keyfiles [][]byte) map[string]any {
		encodedKeyfiles := make([]any, 0, len(keyfiles))
		for _, keyfile := range keyfiles {
			encodedKeyfiles = append(encodedKeyfiles, hex.EncodeToString(keyfile))
		}
		return map[string]any{
			"password_utf8_hex": hex.EncodeToString(password),
			"keyfiles_hex":      encodedKeyfiles,
		}
	}
	document := map[string]any{
		"test_only": true, "public_test_data_notice": testD1GrammarNotice,
		"id": contract.id, "category": "d1-credentials",
		"credential_mode": contract.credentialMode, "keyfile_mode": contract.keyfileMode,
		"correct": encodeFactors(password, keyfiles), "wrong": encodeFactors(wrongPassword, wrongKeyfiles),
		"status": "required", "generated_at_test_time": false,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return encoded
}

func testD1ScheduleDocument(id string, plaintextLength uint64) []byte {
	normal := map[string]any{
		"name": "normal-correct", "mode": "normal", "factors": "correct", "keyfile_order": "manifest",
		"unverified_role": "none", "expected_outcome": "success", "expected_stage": "none",
		"expected_detail_stage": "none", "expected_code": "PCV3_SUCCESS", "expected_d1_provenance": "front",
		"expected_force_provenance": "none", "expected_kdf_calls": 2, "expected_completion": true,
		"expected_output": "plaintext", "expected_plaintext_length_hex": "0000000000000000",
		"expected_final_state": "none", "expected_ranges": []any{},
	}
	force := map[string]any{
		"name": "force-correct", "mode": "force", "factors": "correct", "keyfile_order": "manifest",
		"unverified_role": "none", "expected_outcome": "authenticated-degraded", "expected_stage": "d1-body",
		"expected_detail_stage": "none", "expected_code": "PCV3_AUTHENTICATED_DEGRADED",
		"expected_d1_provenance": "matching", "expected_force_provenance": "verified",
		"expected_kdf_calls": 3, "expected_completion": true, "expected_output": "plaintext",
		"expected_plaintext_length_hex": fmt.Sprintf("%016x", plaintextLength),
		"expected_final_state":          "verified",
		"expected_ranges": []any{map[string]any{
			"record_index_hex": "0000000000000000", "start_hex": "0000000000000000",
			"end_hex": fmt.Sprintf("%016x", plaintextLength), "state": "verified",
		}},
	}
	document := map[string]any{
		"test_only": true, "public_test_data_notice": testD1GrammarNotice,
		"id": id, "category": "d1-schedule", "operations": []any{normal, force},
		"status": "required", "generated_at_test_time": false,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return encoded
}

func testD1ManifestEntry(id, logicalPath string, data []byte, provenancePath, provenance, generatorPath, generatorSHA, category, outcome, stage string, kdfCalls int, forceState string) map[string]any {
	return map[string]any{
		"id": id, "path": logicalPath, "sha256": testBytesSHA256(data),
		"provenance_path": provenancePath, "provenance_sha256": testSHA256(provenance),
		"generator_source_path": generatorPath, "generator_source_sha256": generatorSHA,
		"category": category, "outcome": outcome, "failure_stage": stage,
		"kdf_calls": kdfCalls, "publication_state": "not-applicable", "force_state": forceState,
		"status": "required", "generated_at_test_time": false,
	}
}

func testD1MutationPlanDocument(t *testing.T) []byte {
	t.Helper()
	mutations := make([]any, 0, len(d1MutationRegistry))
	for index, contract := range d1MutationRegistry {
		before := []byte{byte(index + 1), 0x5a}
		after := []byte{byte(index + 1), 0xa5}
		mutations = append(mutations, map[string]any{
			"id": contract.ID(), "source_path": contract.SourcePath(),
			"source_sha256": strings.Repeat(fmt.Sprintf("%x", (index%15)+1), 64),
			"before_hex":    hex.EncodeToString(before), "after_hex": hex.EncodeToString(after),
			"package": contract.Package(), "test_name": contract.TestName(),
			"expected_assertion_marker": contract.AssertionMarker(),
			"timeout_seconds":           contract.TimeoutSeconds(),
		})
	}
	document := map[string]any{
		"test_only": true, "public_test_data_notice": testD1GrammarNotice,
		"id": testD1MutationPlanID, "category": "d1-mutation-plan",
		"mutations": mutations,
		"status":    "required", "generated_at_test_time": false,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode synthetic D1 mutation grammar: %v", err)
	}
	return encoded
}

func testD1Provenance(generatorSHA string) string {
	lock := "go=1.26.5;pcv3-d1-private-generator=synthetic-grammar-only"
	return fmt.Sprintf(`{"test_only":true,"author":"independent-d1-fixture-generator","generator":"pcv3-d1-independent","generator_version":"1","source_revision":"PCV3 revision 0.4 sections 20 and 25","source_sha256":%q,"dependency_lock":%q,"dependency_lock_sha256":%q,"reproduction_command":"private generator command omitted from tracked grammar test","independent_of_production":true,"production_code":false}`, generatorSHA, lock, testSHA256(lock))
}

func testD1ArtifactID(vectorID, role string) string {
	return vectorID + "--" + role
}

func testD1VectorContractForID(t *testing.T, id string) testD1VectorContract {
	t.Helper()
	for _, contract := range testD1VectorContracts {
		if contract.id == id {
			return contract
		}
	}
	t.Fatalf("synthetic D1 contract %q is missing", id)
	return testD1VectorContract{}
}

func mutateTestD1Manifest(t *testing.T, root string, mutate func(map[string]any)) {
	t.Helper()
	manifestPath := filepath.Join(root, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read synthetic D1 manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode synthetic D1 manifest: %v", err)
	}
	mutate(manifest)
	updated, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode mutated D1 manifest: %v", err)
	}
	writeTestFile(t, root, "manifest.json", string(updated))
}

func mutateTestD1ArtifactDocument(t *testing.T, root, id string, mutate func(map[string]any)) {
	t.Helper()
	manifestPath := filepath.Join(root, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read synthetic D1 manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode synthetic D1 manifest: %v", err)
	}
	for _, raw := range manifest["fixtures"].([]any) {
		fixture := raw.(map[string]any)
		if fixture["id"] != id {
			continue
		}
		logicalPath := fixture["path"].(string)
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(logicalPath)))
		if err != nil {
			t.Fatalf("read synthetic D1 artifact: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("decode synthetic D1 artifact: %v", err)
		}
		mutate(document)
		updated, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("encode mutated D1 artifact: %v", err)
		}
		writeTestFile(t, root, logicalPath, string(updated))
		fixture["sha256"] = testBytesSHA256(updated)
		encodedManifest, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("encode synthetic D1 manifest: %v", err)
		}
		writeTestFile(t, root, "manifest.json", string(encodedManifest))
		return
	}
	t.Fatalf("synthetic D1 artifact %q missing", id)
}

func mutateTestD1ArtifactBytes(t *testing.T, root, id string, mutate func([]byte) []byte) {
	t.Helper()
	manifestPath := filepath.Join(root, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read synthetic D1 manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode synthetic D1 manifest: %v", err)
	}
	for _, raw := range manifest["fixtures"].([]any) {
		fixture := raw.(map[string]any)
		if fixture["id"] != id {
			continue
		}
		logicalPath := fixture["path"].(string)
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(logicalPath)))
		if err != nil {
			t.Fatalf("read synthetic D1 artifact: %v", err)
		}
		updated := mutate(data)
		writeTestFile(t, root, logicalPath, string(updated))
		fixture["sha256"] = testBytesSHA256(updated)
		encodedManifest, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("encode synthetic D1 manifest: %v", err)
		}
		writeTestFile(t, root, "manifest.json", string(encodedManifest))
		return
	}
	t.Fatalf("synthetic D1 artifact %q missing", id)
}

func removeTestD1ArtifactFile(t *testing.T, root, id string) {
	t.Helper()
	mutateTestD1Manifest(t, root, func(manifest map[string]any) {
		for _, raw := range manifest["fixtures"].([]any) {
			fixture := raw.(map[string]any)
			if fixture["id"] != id {
				continue
			}
			logicalPath := fixture["path"].(string)
			if err := os.Remove(filepath.Join(root, filepath.FromSlash(logicalPath))); err != nil {
				t.Fatalf("remove synthetic D1 artifact: %v", err)
			}
			return
		}
		t.Fatalf("synthetic D1 artifact %q missing", id)
	})
}

func corruptTestD1Provenance(t *testing.T, root string) {
	t.Helper()
	mutateTestD1Manifest(t, root, func(manifest map[string]any) {
		for _, raw := range manifest["fixtures"].([]any) {
			fixture := raw.(map[string]any)
			if fixture["category"] != "d1-volume" {
				continue
			}
			logicalPath := fixture["provenance_path"].(string)
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(logicalPath)))
			if err != nil {
				t.Fatalf("read synthetic D1 provenance: %v", err)
			}
			var provenance map[string]any
			if err := json.Unmarshal(data, &provenance); err != nil {
				t.Fatalf("decode synthetic D1 provenance: %v", err)
			}
			provenance["independent_of_production"] = false
			updated, err := json.Marshal(provenance)
			if err != nil {
				t.Fatalf("encode corrupted D1 provenance: %v", err)
			}
			writeTestFile(t, root, logicalPath, string(updated))
			fixture["provenance_sha256"] = testBytesSHA256(updated)
			return
		}
		t.Fatal("D1 provenance fixture missing")
	})
}
