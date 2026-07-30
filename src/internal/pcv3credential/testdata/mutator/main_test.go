package main

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	fixtureBaseline = "1111111111111111111111111111111111111111"
	fixtureSpecHash = "2222222222222222222222222222222222222222222222222222222222222222"
)

func TestMutatorAppliesExactlyOnce(t *testing.T) {
	fixture := newMutatorFixture(t)
	if err := run(fixture.args()); err != nil {
		t.Fatalf("apply one deterministic mutation: %v", err)
	}
	got, err := os.ReadFile(fixture.sourcePath)
	if err != nil {
		t.Fatalf("read mutated source: %v", err)
	}
	if string(got) != "package fixture\nconst value = \"after\"\n" {
		t.Fatalf("mutated source = %q", got)
	}
	resultData, err := os.ReadFile(fixture.resultPath)
	if err != nil {
		t.Fatalf("read mutation result: %v", err)
	}
	var result mutationResult
	if err := json.Unmarshal(resultData, &result); err != nil {
		t.Fatalf("decode mutation result: %v", err)
	}
	if result.ApplicationCount != 1 ||
		result.AnchorMatches != 1 ||
		result.SourceBeforeSHA256 == result.SourceAfterSHA256 ||
		result.ExpectedPristine.Status != "PASS" ||
		result.ExpectedMutant.Status != "FAIL" {
		t.Fatalf("mutation result does not prove exactly one change: %+v", result)
	}
	beforeRetry := append([]byte(nil), got...)
	if err := run(fixture.args()); err == nil {
		t.Fatal("second mutation application unexpectedly succeeded")
	}
	afterRetry, err := os.ReadFile(fixture.sourcePath)
	if err != nil {
		t.Fatalf("read source after rejected retry: %v", err)
	}
	if !bytes.Equal(afterRetry, beforeRetry) {
		t.Fatal("rejected retry changed source bytes")
	}
}

func TestMutationCampaignRuntimeBaseline(t *testing.T) {
	fixture := newMutatorFixture(t)
	runtimeBaseline := strings.Repeat("3", 40)
	args := fixture.args()
	replaceArgValue(t, args, "--baseline", runtimeBaseline)
	if err := run(args); err != nil {
		t.Fatalf("apply mutation with runtime baseline: %v", err)
	}
	resultData, err := os.ReadFile(fixture.resultPath)
	if err != nil {
		t.Fatalf("read mutation result: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(resultData, &result); err != nil {
		t.Fatalf("decode mutation result: %v", err)
	}
	if result["baseline_commit"] != runtimeBaseline {
		t.Fatalf(
			"mutation result baseline = %v; want runtime baseline %s",
			result["baseline_commit"],
			runtimeBaseline,
		)
	}
}

func TestMutationSourceSetCommitment(t *testing.T) {
	fixture := newMutatorFixture(t)
	args := fixture.args()
	if err := run(args); err != nil {
		t.Fatalf("apply mutation with source-set commitment: %v", err)
	}
	resultData, err := os.ReadFile(fixture.resultPath)
	if err != nil {
		t.Fatalf("read mutation result: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(resultData, &result); err != nil {
		t.Fatalf("decode mutation result: %v", err)
	}
	if _, exists := result["source_manifest_sha256"]; exists {
		t.Fatal("mutation result retained the misleading source-manifest field")
	}
	if result["source_set_sha256"] == "" {
		t.Fatal("mutation result omitted the source-set commitment")
	}
}

func TestMutatorRejectsBaselineOrSpecDrift(t *testing.T) {
	tests := []struct {
		name string
		edit func([]string)
	}{
		{
			name: "invalid baseline",
			edit: func(args []string) {
				replaceArgValue(t, args, "--baseline", strings.Repeat("A", 40))
			},
		},
		{
			name: "spec",
			edit: func(args []string) {
				replaceArgValue(t, args, "--spec-sha256", strings.Repeat("4", 64))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMutatorFixture(t)
			args := fixture.args()
			test.edit(args)
			fixture.requireRejectedUnchanged(t, args)
		})
	}
	t.Run("argv order", func(t *testing.T) {
		fixture := newMutatorFixture(t)
		args := fixture.args()
		args[0], args[2] = args[2], args[0]
		args[1], args[3] = args[3], args[1]
		fixture.requireRejectedUnchanged(t, args)
	})
}

func TestMutatorRejectsHashDrift(t *testing.T) {
	t.Run("source set identity", func(t *testing.T) {
		fixture := newMutatorFixture(t)
		args := fixture.args()
		replaceArgValue(
			t,
			args,
			"--source-set-sha256",
			strings.Repeat("5", 64),
		)
		fixture.requireRejectedUnchanged(t, args)
	})
	t.Run("source bytes", func(t *testing.T) {
		fixture := newMutatorFixture(t)
		if err := os.WriteFile(
			fixture.sourcePath,
			[]byte("package fixture\nconst value = \"drift\"\n"),
			0o600,
		); err != nil {
			t.Fatalf("write drifted source: %v", err)
		}
		fixture.requireRejectedUnchanged(t, fixture.args())
	})
}

func TestMutatorRejectsAnchorCardinality(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "zero", data: "package fixture\nconst other = \"different\"\n"},
		{
			name: "multiple",
			data: "package fixture\nconst a = \"before\"\nconst b = \"before\"\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMutatorFixture(t)
			fixture.rewriteSourceAndManifest(t, []byte(test.data))
			fixture.requireRejectedUnchanged(t, fixture.args())
		})
	}
}

func TestMutatorRejectsNoOp(t *testing.T) {
	fixture := newMutatorFixture(t)
	fixture.manifest.Mutations[0].Replacement = fixture.manifest.Mutations[0].Anchor
	fixture.writeManifest(t)
	fixture.requireRejectedUnchanged(t, fixture.args())
}

func TestMutatorConfinesWrites(t *testing.T) {
	t.Run("parent traversal", func(t *testing.T) {
		fixture := newMutatorFixture(t)
		outside := filepath.Join(filepath.Dir(fixture.sourceCopy), "outside.go")
		outsideData := []byte("const value = \"before\"\n")
		if err := os.WriteFile(outside, outsideData, 0o600); err != nil {
			t.Fatalf("write outside sentinel: %v", err)
		}
		fixture.manifest.Mutations[0].SourcePath = "../outside.go"
		fixture.rebindSourceManifest()
		fixture.writeManifest(t)
		if err := run(fixture.args()); err == nil {
			t.Fatal("parent-traversal mutation unexpectedly succeeded")
		}
		got, err := os.ReadFile(outside)
		if err != nil {
			t.Fatalf("read outside sentinel: %v", err)
		}
		if !bytes.Equal(got, outsideData) {
			t.Fatal("parent-traversal attempt changed outside file")
		}
	})
	t.Run("symlink target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation is not reliably available on Windows")
		}
		fixture := newMutatorFixture(t)
		outside := filepath.Join(t.TempDir(), "outside.go")
		outsideData := []byte("const value = \"before\"\n")
		if err := os.WriteFile(outside, outsideData, 0o600); err != nil {
			t.Fatalf("write outside sentinel: %v", err)
		}
		if err := os.Remove(fixture.sourcePath); err != nil {
			t.Fatalf("remove source before symlink: %v", err)
		}
		if err := os.Symlink(outside, fixture.sourcePath); err != nil {
			t.Fatalf("create source symlink: %v", err)
		}
		if err := run(fixture.args()); err == nil {
			t.Fatal("symlink-target mutation unexpectedly succeeded")
		}
		got, err := os.ReadFile(outside)
		if err != nil {
			t.Fatalf("read outside sentinel: %v", err)
		}
		if !bytes.Equal(got, outsideData) {
			t.Fatal("symlink-target attempt changed outside file")
		}
	})
	t.Run("symlink parent", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation is not reliably available on Windows")
		}
		fixture := newMutatorFixture(t)
		outside := t.TempDir()
		outsideSource := filepath.Join(outside, "source.go")
		outsideData := []byte("package fixture\nconst value = \"before\"\n")
		if err := os.WriteFile(outsideSource, outsideData, 0o600); err != nil {
			t.Fatalf("write outside sentinel: %v", err)
		}
		link := filepath.Join(fixture.sourceCopy, "linked")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatalf("create parent symlink: %v", err)
		}
		fixture.manifest.Mutations[0].SourcePath = "linked/source.go"
		fixture.rebindSourceManifest()
		fixture.writeManifest(t)
		if err := run(fixture.args()); err == nil {
			t.Fatal("symlink-parent mutation unexpectedly succeeded")
		}
		got, err := os.ReadFile(outsideSource)
		if err != nil {
			t.Fatalf("read outside sentinel: %v", err)
		}
		if !bytes.Equal(got, outsideData) {
			t.Fatal("symlink-parent attempt changed outside file")
		}
	})
	t.Run("live checkout marker", func(t *testing.T) {
		fixture := newMutatorFixture(t)
		if err := os.Mkdir(filepath.Join(fixture.sourceCopy, ".git"), 0o700); err != nil {
			t.Fatalf("create live-checkout marker: %v", err)
		}
		fixture.requireRejectedUnchanged(t, fixture.args())
	})
	t.Run("nested below live checkout marker", func(t *testing.T) {
		fixture := newMutatorFixture(t)
		if err := os.Mkdir(
			filepath.Join(filepath.Dir(fixture.sourceCopy), ".git"),
			0o700,
		); err != nil {
			t.Fatalf("create ancestor live-checkout marker: %v", err)
		}
		fixture.requireRejectedUnchanged(t, fixture.args())
	})
}

func TestMutationManifestSchema(t *testing.T) {
	manifest := loadRepositoryManifest(t)
	if err := validateManifest(manifest); err != nil {
		t.Fatalf("repository mutation manifest is invalid: %v", err)
	}
	expectedIDs := []string{
		"M-CRD06-ADMISSION-ONE-SHOT-REMOVAL",
		"M-CRD06-FIXED-PROFILE-WEAKENING",
		"M-CRD07-KEYFILE-DOMAIN-REMOVAL",
		"M-CRD07-KEYFILE-MODE-OFFSET-2",
		"M-CRD07-LEGACY-PROCESSOR-REENTRY",
		"M-CRD07-NONADJACENT-DUPLICATE-ACCEPT",
		"M-CRD07-POLICY-FALLBACK",
		"M-CRD07-RAW-NFD-FALLBACK",
		"M-CRD07-SELECTED-FACTOR-REMOVAL",
		"M-CRD07-UNORDERED-SORT-REMOVAL",
		"M-CRD07-XOR-FALLBACK",
		"M-CRD08-BORROW-EXPIRY-REMOVAL",
		"M-CRD08-DERIVED-KEY-CLEANUP-REMOVAL",
		"M-CRD08-KDF-RETURN-CLEANUP-REMOVAL",
		"M-CRD08-POSTKDF-CANCEL-CHECK-REMOVAL",
		"M-CRD09-INDEPENDENT-INFO-REMOVAL",
		"M-CRD09-PREEXPAND-VALIDATION-REMOVAL",
		"M-CRD09-SEPARATE-ROOTS-REMOVAL",
		"M-CRD10-OWNER-PUBLICATION-REMOVAL",
		"M-CRD10-VOLUME-ID-ENTROPY-REMOVAL",
	}
	if len(manifest.Mutations) != len(expectedIDs) {
		t.Fatalf(
			"mutation count = %d; want exact invariant set %d",
			len(manifest.Mutations),
			len(expectedIDs),
		)
	}
	for _, id := range expectedIDs {
		_ = mutationByID(t, manifest, id)
	}
	requirements := map[string]bool{}
	for _, mutation := range manifest.Mutations {
		requirements[mutation.Requirement] = true
		source := filepath.Join(repositorySourceRoot(t), mutation.SourcePath)
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", mutation.SourcePath, err)
		}
		if sha256Hex(data) != mutation.SourceSHA256 {
			t.Fatalf("%s source hash drift", mutation.ID)
		}
		if matches := bytes.Count(data, []byte(mutation.Anchor)); matches != 1 {
			t.Fatalf("%s anchor matches = %d; want 1", mutation.ID, matches)
		}
		mutated := bytes.Replace(
			data,
			[]byte(mutation.Anchor),
			[]byte(mutation.Replacement),
			1,
		)
		if _, err := parser.ParseFile(
			token.NewFileSet(),
			mutation.SourcePath,
			mutated,
			parser.AllErrors,
		); err != nil {
			t.Fatalf("%s produces invalid Go syntax: %v", mutation.ID, err)
		}
	}
	for _, requirement := range []string{
		"CRD-06", "CRD-07", "CRD-08", "CRD-09", "CRD-10",
	} {
		if !requirements[requirement] {
			t.Fatalf("manifest has no mutation for %s", requirement)
		}
	}
	t.Run("duplicate ID rejected", func(t *testing.T) {
		duplicate := *manifest
		duplicate.Mutations = append(
			append([]mutationSpec(nil), manifest.Mutations...),
			manifest.Mutations[0],
		)
		if err := validateManifest(&duplicate); err == nil {
			t.Fatal("duplicate mutation ID unexpectedly validated")
		}
	})
	t.Run("missing required field rejected", func(t *testing.T) {
		missing := *manifest
		missing.Mutations = append([]mutationSpec(nil), manifest.Mutations...)
		missing.Mutations[0].SourceSHA256 = ""
		if err := validateManifest(&missing); err == nil {
			t.Fatal("mutation missing source hash unexpectedly validated")
		}
	})
}

func TestMutationRequiredCanonicalTriplet(t *testing.T) {
	manifest := loadRepositoryManifest(t)
	required := map[string]struct {
		testID string
		marker string
	}{
		"M-CRD07-SELECTED-FACTOR-REMOVAL": {
			"TestCanonicalTranscriptSelectedFactorRemoval",
			"selected_factor_missing",
		},
		"M-CRD07-KEYFILE-MODE-OFFSET-2": {
			"TestCanonicalTranscriptKeyfileModeOffset2Mutation",
			"keyfile_mode_offset_2_mismatch",
		},
		"M-CRD07-UNORDERED-SORT-REMOVAL": {
			"TestCanonicalTranscriptUnorderedSortMutation",
			"unordered_digest_order_noncanonical",
		},
	}
	for id, want := range required {
		mutation := mutationByID(t, manifest, id)
		if mutation.KillingTestID != want.testID ||
			mutation.ViolationMarker != want.marker ||
			mutation.Requirement != "CRD-07" {
			t.Fatalf("%s binding = %q/%q/%q", id, mutation.KillingTestID, mutation.ViolationMarker, mutation.Requirement)
		}
	}
}

func TestMutationExactCommandAndKillingTest(t *testing.T) {
	manifest := loadRepositoryManifest(t)
	testSources := repositorySemanticTestSources(t)
	if !equalStrings(manifest.ArgvTemplate, exactArgvTemplate) {
		t.Fatal("manifest argv template is not exact")
	}
	for _, mutation := range manifest.Mutations {
		for _, outcome := range []mutationOutcome{mutation.Pristine, mutation.Mutant} {
			if !semanticCommandKills(outcome.SemanticCommand, mutation.KillingTestID) {
				t.Fatalf("%s outcome does not execute its exact killing test", mutation.ID)
			}
		}
		if !bytes.Contains(
			testSources,
			[]byte("func "+mutation.KillingTestID+"("),
		) {
			t.Fatalf("%s killing test is not present in package tests", mutation.ID)
		}
		if !bytes.Contains(testSources, []byte(mutation.ViolationMarker)) {
			t.Fatalf(
				"%s violation marker is not emitted by package tests",
				mutation.ID,
			)
		}
	}
	t.Run("substring is not exact", func(t *testing.T) {
		fixture := newMutatorFixture(t)
		fixture.manifest.Mutations[0].Mutant.SemanticCommand = []string{
			"go", "test", "./internal/pcv3credential",
			"-run", "^OtherTestFixtureSemanticSuffix$", "-count=1",
		}
		if err := validateManifest(fixture.manifest); err == nil {
			t.Fatal("substring-only killing command unexpectedly validated")
		}
	})
}

func repositorySemanticTestSources(t *testing.T) []byte {
	t.Helper()
	paths, err := filepath.Glob(
		filepath.Join(repositorySourceRoot(t), "internal/pcv3credential/*_test.go"),
	)
	if err != nil {
		t.Fatalf("find semantic test sources: %v", err)
	}
	var combined []byte
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read semantic test source %s: %v", path, err)
		}
		combined = append(combined, data...)
	}
	return combined
}

func TestMutationOutcomeRequiresPristineAndMutant(t *testing.T) {
	fixture := newMutatorFixture(t)
	fixture.manifest.Mutations[0].Pristine.Status = ""
	if err := validateManifest(fixture.manifest); err == nil {
		t.Fatal("manifest without pristine PASS unexpectedly validated")
	}
	fixture = newMutatorFixture(t)
	fixture.manifest.Mutations[0].Mutant.ViolationMarker = ""
	if err := validateManifest(fixture.manifest); err == nil {
		t.Fatal("manifest without mutant marker unexpectedly validated")
	}
}

func TestMutationRejectsCompileOnlyKill(t *testing.T) {
	fixture := newMutatorFixture(t)
	fixture.manifest.Mutations[0].Mutant.CompileOnly = true
	if err := validateManifest(fixture.manifest); err == nil {
		t.Fatal("compile-only mutant outcome unexpectedly validated")
	}
	fixture = newMutatorFixture(t)
	fixture.manifest.Mutations[0].Mutant.SemanticCommand = []string{
		"go", "test", "./internal/pcv3credential", "-run", "^$",
	}
	if err := validateManifest(fixture.manifest); err == nil {
		t.Fatal("compile-only command unexpectedly validated")
	}
}

type mutatorFixture struct {
	sourceCopy   string
	sourcePath   string
	manifestPath string
	resultPath   string
	manifest     *mutationManifest
}

func newMutatorFixture(t *testing.T) *mutatorFixture {
	t.Helper()
	root := t.TempDir()
	sourceCopy := filepath.Join(root, "copy")
	sourcePath := filepath.Join(sourceCopy, "source.go")
	if err := os.Mkdir(sourceCopy, 0o700); err != nil {
		t.Fatalf("create source copy: %v", err)
	}
	sourceData := []byte("package fixture\nconst value = \"before\"\n")
	if err := os.WriteFile(sourcePath, sourceData, 0o600); err != nil {
		t.Fatalf("write source fixture: %v", err)
	}
	command := []string{
		"go", "test", "./internal/pcv3credential",
		"-run", "^TestFixtureSemantic$", "-count=1",
	}
	manifest := &mutationManifest{
		SchemaVersion: manifestSchemaVersion,
		SpecSHA256:    fixtureSpecHash,
		ArgvTemplate:  append([]string(nil), exactArgvTemplate...),
		Mutations: []mutationSpec{{
			ID:              "M-CRD07-FIXTURE",
			Requirement:     "CRD-07",
			Invariant:       "fixture deterministic replacement",
			SourcePath:      "source.go",
			SourceSHA256:    sha256Hex(sourceData),
			Anchor:          "\"before\"",
			Replacement:     "\"after\"",
			KillingTestID:   "TestFixtureSemantic",
			ViolationMarker: "fixture_violation",
			Pristine: mutationOutcome{
				Status: "PASS", Execution: "semantic",
				SemanticCommand: command, TestID: "TestFixtureSemantic",
				Stage: "none", Reason: "success",
			},
			Mutant: mutationOutcome{
				Status: "FAIL", Execution: "semantic",
				SemanticCommand: command, TestID: "TestFixtureSemantic",
				ViolationMarker: "fixture_violation",
				Stage:           "transcript", Reason: "fixture_violation",
			},
		}},
	}
	fixture := &mutatorFixture{
		sourceCopy:   sourceCopy,
		sourcePath:   sourcePath,
		manifestPath: filepath.Join(root, "mutations.json"),
		resultPath:   filepath.Join(root, "result.json"),
		manifest:     manifest,
	}
	fixture.rebindSourceManifest()
	fixture.writeManifest(t)
	return fixture
}

func (fixture *mutatorFixture) rebindSourceManifest() {
	sources := map[string]string{}
	for _, mutation := range fixture.manifest.Mutations {
		sources[mutation.SourcePath] = mutation.SourceSHA256
	}
	fixture.manifest.SourceSetSHA256 = sourceSetHash(sources)
}

func (fixture *mutatorFixture) rewriteSourceAndManifest(t *testing.T, data []byte) {
	t.Helper()
	if err := os.WriteFile(fixture.sourcePath, data, 0o600); err != nil {
		t.Fatalf("rewrite source fixture: %v", err)
	}
	fixture.manifest.Mutations[0].SourceSHA256 = sha256Hex(data)
	fixture.rebindSourceManifest()
	fixture.writeManifest(t)
}

func (fixture *mutatorFixture) writeManifest(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(fixture.manifest)
	if err != nil {
		t.Fatalf("encode fixture manifest: %v", err)
	}
	if err := os.WriteFile(fixture.manifestPath, data, 0o600); err != nil {
		t.Fatalf("write fixture manifest: %v", err)
	}
}

func (fixture *mutatorFixture) args() []string {
	return []string{
		"--source-copy", fixture.sourceCopy,
		"--manifest", fixture.manifestPath,
		"--mutation-id", fixture.manifest.Mutations[0].ID,
		"--source-set-sha256", fixture.manifest.SourceSetSHA256,
		"--baseline", fixtureBaseline,
		"--spec-sha256", fixture.manifest.SpecSHA256,
		"--result", fixture.resultPath,
	}
}

func (fixture *mutatorFixture) requireRejectedUnchanged(t *testing.T, args []string) {
	t.Helper()
	before, err := os.ReadFile(fixture.sourcePath)
	if err != nil {
		t.Fatalf("read fixture before rejection: %v", err)
	}
	if err := run(args); err == nil {
		t.Fatal("invalid mutation unexpectedly succeeded")
	}
	after, err := os.ReadFile(fixture.sourcePath)
	if err != nil {
		t.Fatalf("read fixture after rejection: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("rejected mutation changed source bytes")
	}
}

func loadRepositoryManifest(t *testing.T) *mutationManifest {
	t.Helper()
	path := filepath.Join(
		repositorySourceRoot(t),
		"internal/pcv3credential/testdata/mutations.json",
	)
	manifest, err := loadManifest(path)
	if err != nil {
		t.Fatalf("load repository mutation manifest: %v", err)
	}
	return manifest
}

func repositorySourceRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve mutator test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
}

func mutationByID(
	t *testing.T,
	manifest *mutationManifest,
	id string,
) *mutationSpec {
	t.Helper()
	mutation, err := selectMutation(manifest, id)
	if err != nil {
		t.Fatal(err)
	}
	return mutation
}

func replaceArgValue(t *testing.T, args []string, name, value string) {
	t.Helper()
	for i := 0; i < len(args); i += 2 {
		if args[i] == name {
			args[i+1] = value
			return
		}
	}
	t.Fatalf("argument %s not found", name)
}
