package pcv3validation

// All tests in this file are tooling/policy evidence for the campaign
// machinery itself (manifest parsing, event acceptance, source-copy
// confinement). They are never product behavior coverage: product behavior is
// established only by the owning product oracles the manifest points at
// (AGENTS.md Rule 9; Phase 9 validation strategy evidence classes).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	syntheticModulePath = "example.test/campaign"
	syntheticTimeout    = 90 * time.Second
)

// --- synthetic fixtures -------------------------------------------------

func syntheticManifestEntries() []Mutation {
	entries := make([]Mutation, 0, len(CanonicalFamilies))
	for index, family := range CanonicalFamilies {
		id := "e-" + family
		replacement := fmt.Sprintf("// replacement-%s\n", id)
		subtest := ""
		if index == 0 {
			subtest = "exact subtest"
		}
		entries = append(entries, Mutation{
			ID:           id,
			Family:       family,
			SourcePath:   fmt.Sprintf("internal/pcv3/f%d.go", index/2),
			SourceSHA256: strings.Repeat("ab", 32),
			Anchor:       fmt.Sprintf("// anchor-%s\n", id),
			Replacement:  &replacement,
			Package:      "./internal/pcv3",
			Test:         fmt.Sprintf("TestOracle%d", index),
			Subtest:      &subtest,
			Marker:       "marker-" + id,
			Observations: Observations{
				Stage: "obs", KDF: "obs", Output: "obs", Publication: "obs",
				Completion: "obs", Owner: "obs", Cleanup: "obs",
			},
		})
	}
	return entries
}

func syntheticManifestData(t *testing.T, mutate func(entries []Mutation)) []byte {
	t.Helper()
	entries := syntheticManifestEntries()
	if mutate != nil {
		mutate(entries)
	}
	data, err := json.Marshal(Manifest{SchemaVersion: ManifestSchemaVersion, Mutations: entries})
	if err != nil {
		t.Fatalf("marshal synthetic manifest: %v", err)
	}
	return data
}

type syntheticFixture struct {
	sourceRoot string
	workParent string
	manifest   *Manifest
	digest     string
	files      map[string]string
}

// buildSyntheticFixture writes a synthetic module tree whose source files
// carry exactly the manifest anchors, then freezes each file hash into the
// manifest. Adjacent entries share one file so a failed restore between
// mutations is observed by the next entry as source drift.
func buildSyntheticFixture(t *testing.T, mutate func(entries []Mutation, files map[string]string)) syntheticFixture {
	t.Helper()
	entries := syntheticManifestEntries()
	files := map[string]string{}
	for _, entry := range entries {
		content := files[entry.SourcePath]
		if content == "" {
			content = "package fake\n\n"
		}
		files[entry.SourcePath] = content + entry.Anchor
	}
	if mutate != nil {
		mutate(entries, files)
	}
	fixture := syntheticFixture{
		sourceRoot: t.TempDir(),
		workParent: t.TempDir(),
		files:      files,
	}
	goMod := "module " + syntheticModulePath + "\n\ngo 1.26\n"
	if err := os.WriteFile(filepath.Join(fixture.sourceRoot, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatalf("write synthetic go.mod: %v", err)
	}
	for name, content := range files {
		full := filepath.Join(fixture.sourceRoot, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("create synthetic source parent: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write synthetic source: %v", err)
		}
	}
	for index := range entries {
		entries[index].SourceSHA256 = sha256Hex([]byte(files[entries[index].SourcePath]))
	}
	fixture.manifest = &Manifest{SchemaVersion: ManifestSchemaVersion, Mutations: entries}
	data, err := json.Marshal(fixture.manifest)
	if err != nil {
		t.Fatalf("marshal synthetic manifest: %v", err)
	}
	fixture.digest = sha256Hex(data)
	return fixture
}

func (fixture syntheticFixture) config(runner CommandRunner) CampaignConfig {
	return CampaignConfig{
		SourceRoot:     fixture.sourceRoot,
		WorkParent:     fixture.workParent,
		Manifest:       fixture.manifest,
		ManifestSHA256: fixture.digest,
		Runner:         runner,
		Timeout:        syntheticTimeout,
	}
}

// --- event stream builders ----------------------------------------------

func rawStream(t *testing.T, events ...TestEvent) []byte {
	t.Helper()
	var buffer bytes.Buffer
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal synthetic event: %v", err)
		}
		buffer.Write(data)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

func passStream(t *testing.T, eventPkg, test, subtest string) []byte {
	t.Helper()
	events := []TestEvent{{Action: "run", Package: eventPkg, Test: test}}
	if subtest != "" {
		events = append(events,
			TestEvent{Action: "run", Package: eventPkg, Test: test + "/" + subtest},
			TestEvent{Action: "pass", Package: eventPkg, Test: test + "/" + subtest},
		)
	}
	events = append(events,
		TestEvent{Action: "pass", Package: eventPkg, Test: test},
		TestEvent{Action: "pass", Package: eventPkg},
	)
	return rawStream(t, events...)
}

func failStream(t *testing.T, eventPkg, test, subtest, marker string) []byte {
	t.Helper()
	events := []TestEvent{{Action: "run", Package: eventPkg, Test: test}}
	if subtest != "" {
		events = append(events,
			TestEvent{Action: "run", Package: eventPkg, Test: test + "/" + subtest},
			TestEvent{Action: "output", Package: eventPkg, Test: test + "/" + subtest, Output: marker + "\n"},
			TestEvent{Action: "fail", Package: eventPkg, Test: test + "/" + subtest},
		)
	} else {
		events = append(events,
			TestEvent{Action: "output", Package: eventPkg, Test: test, Output: marker + "\n"},
		)
	}
	events = append(events,
		TestEvent{Action: "fail", Package: eventPkg, Test: test},
		TestEvent{Action: "fail", Package: eventPkg},
	)
	return rawStream(t, events...)
}

// --- scripted runner ------------------------------------------------------

type scriptedRunner struct {
	t            *testing.T
	manifest     *Manifest
	workParent   string
	calls        [][]string
	dirs         []string
	overrides    map[int]CommandResult
	perTestCalls map[string]int
}

func newScriptedRunner(t *testing.T, fixture syntheticFixture) *scriptedRunner {
	t.Helper()
	return &scriptedRunner{
		t:            t,
		manifest:     fixture.manifest,
		workParent:   fixture.workParent,
		overrides:    map[int]CommandResult{},
		perTestCalls: map[string]int{},
	}
}

func (runner *scriptedRunner) run(dir string, argv []string, timeout time.Duration) CommandResult {
	if timeout != syntheticTimeout {
		runner.t.Fatalf("command timeout = %s; want %s", timeout, syntheticTimeout)
	}
	if filepath.Dir(dir) != runner.workParent ||
		!strings.HasPrefix(filepath.Base(dir), copyDirPrefix) {
		runner.t.Fatalf("command ran outside the private copy: %q", dir)
	}
	runner.calls = append(runner.calls, append([]string(nil), argv...))
	runner.dirs = append(runner.dirs, dir)
	index := len(runner.calls) - 1
	if result, ok := runner.overrides[index]; ok {
		return result
	}
	var selector, pkg string
	for i, arg := range argv {
		if arg == "-run" && i+1 < len(argv) {
			selector = argv[i+1]
		}
		pkg = arg
	}
	if selector == "^$" {
		return CommandResult{}
	}
	test := strings.TrimSuffix(strings.TrimPrefix(selector, "^"), "$")
	var mutation *Mutation
	for i := range runner.manifest.Mutations {
		if runner.manifest.Mutations[i].Test == test {
			mutation = &runner.manifest.Mutations[i]
		}
	}
	if mutation == nil {
		runner.t.Fatalf("scripted runner saw unexpected test %q", test)
	}
	eventPkg := syntheticModulePath + "/" + strings.TrimPrefix(pkg, "./")
	runner.perTestCalls[test]++
	if runner.perTestCalls[test] == 1 {
		return CommandResult{Output: passStream(runner.t, eventPkg, test, mutation.RequiredSubtest())}
	}
	return CommandResult{
		Output: failStream(runner.t, eventPkg, test, mutation.RequiredSubtest(), mutation.Marker),
		Err:    errors.New("exit status 1"),
	}
}

func requireNoResidue(t *testing.T, workParent string, allowed ...string) {
	t.Helper()
	entries, err := os.ReadDir(workParent)
	if err != nil {
		t.Fatalf("read work parent: %v", err)
	}
	keep := map[string]bool{}
	for _, name := range allowed {
		keep[name] = true
	}
	for _, entry := range entries {
		if !keep[entry.Name()] {
			t.Fatalf("work parent has residue entry %q", entry.Name())
		}
	}
}

// --- manifest tests -------------------------------------------------------

func TestManifestCanonicalFrozen(t *testing.T) {
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	manifest, _, err := LoadManifest(filepath.Join(moduleRoot, "internal", "pcv3validation", "testdata", "mutations.json"))
	if err != nil {
		t.Fatalf("load canonical manifest: %v", err)
	}
	if len(manifest.Mutations) != 39 {
		t.Fatalf("canonical manifest entries = %d; want exactly 39", len(manifest.Mutations))
	}
	root, err := os.OpenRoot(moduleRoot)
	if err != nil {
		t.Fatalf("open module root: %v", err)
	}
	defer func() { _ = root.Close() }()
	testSources := map[string]string{}
	for _, mutation := range manifest.Mutations {
		data, err := root.ReadFile(filepath.FromSlash(mutation.SourcePath))
		if err != nil {
			t.Fatalf("mutation %s: read source: %v", mutation.ID, err)
		}
		if got := sha256Hex(data); got != mutation.SourceSHA256 {
			t.Fatalf("mutation %s: source preimage drift (%s)", mutation.ID, got)
		}
		if count := bytes.Count(data, []byte(mutation.Anchor)); count != 1 {
			t.Fatalf("mutation %s: anchor occurs %d times; want exactly once", mutation.ID, count)
		}
		postimage := bytes.Replace(data, []byte(mutation.Anchor), []byte(mutation.ReplacementText()), 1)
		if bytes.Equal(postimage, data) {
			t.Fatalf("mutation %s: transform is a no-op", mutation.ID)
		}
		pkgDir := strings.TrimPrefix(mutation.Package, "./")
		sources, ok := testSources[pkgDir]
		if !ok {
			entries, err := os.ReadDir(filepath.Join(moduleRoot, filepath.FromSlash(pkgDir)))
			if err != nil {
				t.Fatalf("read oracle package dir %s: %v", pkgDir, err)
			}
			var builder strings.Builder
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				content, err := root.ReadFile(filepath.FromSlash(pkgDir + "/" + entry.Name()))
				if err != nil {
					t.Fatalf("read oracle test source %s/%s: %v", pkgDir, entry.Name(), err)
				}
				builder.Write(content)
			}
			sources = builder.String()
			testSources[pkgDir] = sources
		}
		if !strings.Contains(sources, "func "+mutation.Test+"(t *testing.T)") {
			t.Fatalf("mutation %s: oracle %s not found in %s test sources", mutation.ID, mutation.Test, pkgDir)
		}
		if subtest := mutation.RequiredSubtest(); subtest != "" && !strings.Contains(sources, subtest) {
			t.Fatalf("mutation %s: required subtest %q not found in %s test sources", mutation.ID, subtest, pkgDir)
		}
	}
}

func TestManifestFamilyInventory(t *testing.T) {
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	manifest, _, err := LoadManifest(filepath.Join(moduleRoot, "internal", "pcv3validation", "testdata", "mutations.json"))
	if err != nil {
		t.Fatalf("load canonical manifest: %v", err)
	}
	wantCounts := map[string]int{
		"routing": 5, "credential": 14, "key-label": 4, "capsule": 2,
		"record": 1, "reed-solomon": 1, "metadata": 2, "tail-completion": 1,
		"force": 1, "d1": 3, "publication-extraction": 2, "lifecycle-diagnostics": 3,
	}
	counts := map[string]int{}
	ids := map[string]bool{}
	for _, mutation := range manifest.Mutations {
		counts[mutation.Family]++
		ids[mutation.ID] = true
	}
	for family, want := range wantCounts {
		if counts[family] != want {
			t.Fatalf("family %s entries = %d; want %d", family, counts[family], want)
		}
		delete(counts, family)
	}
	for family := range counts {
		t.Fatalf("unexpected family %q in canonical manifest", family)
	}
	wantIDs := []string{
		// Tasks 1+2 demonstrated RED transforms.
		"capsule-adopt-zero", "capsule-wrap-drops-prefix",
		"record-tag-failopen", "rs-retry-no-reauth",
		"metadata-damaged-fallthrough", "metadata-tag-drops-commitment",
		"tail-trust-cached-suffix", "force-ignore-live-role",
		"routing-weakened-prefix-guard", "routing-accept-unknown-tuple",
		"key-label-role-binding-weakened", "key-label-aliased-roots",
		"d1-decrypt-early", "d1-retain-plaintext-on-failure", "d1-close-only-one-owner",
		"publication-blind-delete", "extraction-create-missing-root",
		"lifecycle-remove-owner-close", "lifecycle-replay-admission", "lifecycle-diagnostic-downgrade",
		// Migrated routing knowledge (Phase 3 manifest).
		"P3-LENGTH-GUARD-001", "P3-NO-FALLBACK-001", "P3-ROUTE-ORDER-001",
		// Migrated credential/key-label knowledge (Phase 2 manifest).
		"M-CRD06-FIXED-PROFILE-WEAKENING",
		"M-CRD07-SELECTED-FACTOR-REMOVAL", "M-CRD07-KEYFILE-MODE-OFFSET-2",
		"M-CRD07-UNORDERED-SORT-REMOVAL", "M-CRD07-POLICY-FALLBACK",
		"M-CRD07-RAW-NFD-FALLBACK", "M-CRD07-XOR-FALLBACK",
		"M-CRD07-KEYFILE-DOMAIN-REMOVAL", "M-CRD07-LEGACY-PROCESSOR-REENTRY",
		"M-CRD07-NONADJACENT-DUPLICATE-ACCEPT",
		"M-CRD08-BORROW-EXPIRY-REMOVAL", "M-CRD08-DERIVED-KEY-CLEANUP-REMOVAL",
		"M-CRD09-INDEPENDENT-INFO-REMOVAL", "M-CRD09-PREEXPAND-VALIDATION-REMOVAL",
		"M-CRD10-VOLUME-ID-ENTROPY-REMOVAL", "M-CRD10-OWNER-PUBLICATION-REMOVAL",
	}
	if len(wantIDs) != len(manifest.Mutations) {
		t.Fatalf("frozen ID inventory = %d; want %d", len(wantIDs), len(manifest.Mutations))
	}
	for _, id := range wantIDs {
		if !ids[id] {
			t.Fatalf("canonical manifest lacks frozen mutation ID %q", id)
		}
		delete(ids, id)
	}
	for id := range ids {
		t.Fatalf("canonical manifest has unfrozen mutation ID %q", id)
	}
}

func TestManifestClosedSchemaValidation(t *testing.T) {
	t.Run("valid synthetic manifest is accepted", func(t *testing.T) {
		if _, err := ParseManifest(syntheticManifestData(t, nil)); err != nil {
			t.Fatalf("valid synthetic manifest rejected: %v", err)
		}
	})

	t.Run("empty replacement is accepted only when explicitly present", func(t *testing.T) {
		data := syntheticManifestData(t, func(entries []Mutation) {
			empty := ""
			entries[0].Replacement = &empty
		})
		if _, err := ParseManifest(data); err != nil {
			t.Fatalf("explicit empty replacement (deletion transform) rejected: %v", err)
		}
	})

	cases := []struct {
		name   string
		mutate func(entries []Mutation)
	}{
		{"wrong schema version", nil},
		{"no mutations", nil},
		{"duplicate mutation ID", func(e []Mutation) { e[1].ID = e[0].ID }},
		{"empty mutation ID", func(e []Mutation) { e[0].ID = "" }},
		{"mutation ID with space", func(e []Mutation) { e[0].ID = "has space" }},
		{"unknown family", func(e []Mutation) { e[0].Family = "unknown" }},
		{"missing family", func(e []Mutation) { e[4].Family = e[3].Family }},
		{"absolute source path", func(e []Mutation) { e[0].SourcePath = "/abs/f.go" }},
		{"escaping source path", func(e []Mutation) { e[0].SourcePath = "../f.go" }},
		{"backslash source path", func(e []Mutation) { e[0].SourcePath = `internal\pcv3\f.go` }},
		{"test source path", func(e []Mutation) { e[0].SourcePath = "internal/pcv3/f_test.go" }},
		{"testdata source path", func(e []Mutation) { e[0].SourcePath = "internal/pcv3/testdata/f.go" }},
		{"non-go source path", func(e []Mutation) { e[0].SourcePath = "internal/pcv3/f.txt" }},
		{"disallowed source dir", func(e []Mutation) { e[0].SourcePath = "internal/crypto/f.go" }},
		{"deep source path", func(e []Mutation) { e[0].SourcePath = "internal/pcv3/sub/f.go" }},
		{"invalid preimage hash", func(e []Mutation) { e[0].SourceSHA256 = "zz" }},
		{"uppercase preimage hash", func(e []Mutation) { e[0].SourceSHA256 = strings.Repeat("AB", 32) }},
		{"empty anchor", func(e []Mutation) { e[0].Anchor = "" }},
		{"absent replacement", func(e []Mutation) { e[0].Replacement = nil }},
		{"no-op replacement", func(e []Mutation) { *e[0].Replacement = e[0].Anchor }},
		{"disallowed package", func(e []Mutation) { e[0].Package = "./internal/crypto" }},
		{"test name without Test prefix", func(e []Mutation) { e[0].Test = "testOracle0" }},
		{"test name with space", func(e []Mutation) { e[0].Test = "Test Oracle0" }},
		{"absent subtest", func(e []Mutation) { e[0].Subtest = nil }},
		{"subtest with newline", func(e []Mutation) { *e[0].Subtest = "exact\nsubtest" }},
		{"empty marker", func(e []Mutation) { e[0].Marker = "" }},
		{"marker with newline", func(e []Mutation) { e[0].Marker = "marker\nsplit" }},
		{"empty observation", func(e []Mutation) { e[0].Observations.Stage = "" }},
		{"observation with newline", func(e []Mutation) { e[0].Observations.Cleanup = "a\nb" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var data []byte
			switch test.name {
			case "wrong schema version":
				data = syntheticManifestData(t, nil)
				var manifest Manifest
				if err := json.Unmarshal(data, &manifest); err != nil {
					t.Fatalf("decode synthetic manifest: %v", err)
				}
				manifest.SchemaVersion = 2
				data, _ = json.Marshal(manifest)
			case "no mutations":
				data, _ = json.Marshal(Manifest{SchemaVersion: ManifestSchemaVersion})
			default:
				data = syntheticManifestData(t, test.mutate)
			}
			if _, err := ParseManifest(data); err == nil {
				t.Fatalf("invalid manifest accepted (%s)", test.name)
			}
		})
	}

	t.Run("unknown field is rejected", func(t *testing.T) {
		var decoded map[string]any
		if err := json.Unmarshal(syntheticManifestData(t, nil), &decoded); err != nil {
			t.Fatalf("decode synthetic manifest: %v", err)
		}
		decoded["unexpected"] = true
		data, _ := json.Marshal(decoded)
		if _, err := ParseManifest(data); err == nil {
			t.Fatal("manifest with unknown field accepted")
		}
	})

	t.Run("trailing JSON is rejected", func(t *testing.T) {
		data := append(syntheticManifestData(t, nil), []byte("\n{}")...)
		if _, err := ParseManifest(data); err == nil {
			t.Fatal("manifest with trailing JSON accepted")
		}
	})

	t.Run("absent replacement JSON field is rejected", func(t *testing.T) {
		var decoded map[string]any
		if err := json.Unmarshal(syntheticManifestData(t, nil), &decoded); err != nil {
			t.Fatalf("decode synthetic manifest: %v", err)
		}
		delete(decoded["mutations"].([]any)[0].(map[string]any), "replacement")
		data, _ := json.Marshal(decoded)
		if _, err := ParseManifest(data); err == nil {
			t.Fatal("manifest with absent replacement accepted")
		}
	})

	t.Run("absent subtest JSON field is rejected", func(t *testing.T) {
		var decoded map[string]any
		if err := json.Unmarshal(syntheticManifestData(t, nil), &decoded); err != nil {
			t.Fatalf("decode synthetic manifest: %v", err)
		}
		delete(decoded["mutations"].([]any)[0].(map[string]any), "subtest")
		data, _ := json.Marshal(decoded)
		if _, err := ParseManifest(data); err == nil {
			t.Fatal("manifest with absent subtest accepted")
		}
	})
}

// --- event inventory tests ------------------------------------------------

const (
	eventPkg  = syntheticModulePath + "/internal/pcv3"
	eventTest = "TestOracle0"
)

func eventSelector(subtest string) OracleSelector {
	return OracleSelector{EventPackage: eventPkg, Test: eventTest, Subtest: subtest}
}

func TestEventInventoryParseRejects(t *testing.T) {
	if _, err := ParseTestEvents([]byte("\n\n")); err != nil {
		t.Fatalf("empty stream rejected: %v", err)
	}
	valid := rawStream(t, TestEvent{Action: "run", Package: eventPkg, Test: eventTest})
	if _, err := ParseTestEvents(valid); err != nil {
		t.Fatalf("valid stream rejected: %v", err)
	}
	if _, err := ParseTestEvents([]byte("not json\n")); err == nil {
		t.Fatal("malformed event line accepted")
	}
	bench := rawStream(t, TestEvent{Action: "bench", Package: eventPkg, Test: eventTest})
	if _, err := ParseTestEvents(bench); err == nil {
		t.Fatal("non-allowlisted event action accepted")
	}
}

func TestEventInventoryPristineAcceptance(t *testing.T) {
	cases := []struct {
		name    string
		subtest string
		stream  []byte
		want    Classification
	}{
		{"pass without subtest", "", passStream(t, eventPkg, eventTest, ""), ""},
		{"pass with required subtest", "exact subtest", passStream(t, eventPkg, eventTest, "exact subtest"), ""},
		{"zero run events", "", rawStream(t, TestEvent{Action: "pass", Package: eventPkg}), ClassPristineMissing},
		{"duplicate run events", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg},
		), ClassEventInvalid},
		{"duplicate pass events", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg},
		), ClassEventInvalid},
		{"failing oracle", "", failStream(t, eventPkg, eventTest, "", "boom"), ClassPristineFailed},
		{"skipped oracle", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "skip", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg},
		), ClassRequiredSkip},
		{"skipped subtest", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest + "/other"},
			TestEvent{Action: "skip", Package: eventPkg, Test: eventTest + "/other"},
			TestEvent{Action: "pass", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg},
		), ClassRequiredSkip},
		{"foreign test", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "run", Package: eventPkg, Test: "TestOther"},
			TestEvent{Action: "pass", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg},
		), ClassUnexpectedTest},
		{"foreign package", "", rawStream(t,
			TestEvent{Action: "run", Package: "example.test/other/internal/pcv3", Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg, Test: eventTest},
		), ClassUnexpectedTest},
		{"missing pass", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "pass", Package: eventPkg},
		), ClassPristineFailed},
		{"missing required subtest", "exact subtest", passStream(t, eventPkg, eventTest, ""), ClassPristineMissing},
		{"failing required subtest", "exact subtest", failStream(t, eventPkg, eventTest, "exact subtest", "boom"), ClassPristineFailed},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			events, err := ParseTestEvents(test.stream)
			if err != nil {
				t.Fatalf("parse stream: %v", err)
			}
			_, rejection := AcceptPristine(events, eventSelector(test.subtest))
			if test.want == "" {
				if rejection != nil {
					t.Fatalf("pristine rejected: %v", rejection)
				}
				return
			}
			if rejection == nil || rejection.Kind != test.want {
				t.Fatalf("pristine rejection = %v; want %s", rejection, test.want)
			}
		})
	}
}

func TestEventInventoryMutantAcceptance(t *testing.T) {
	marker := "frozen behavioral marker"
	cases := []struct {
		name          string
		subtest       string
		stream        []byte
		processFailed bool
		want          Classification
	}{
		{"kill without subtest", "", failStream(t, eventPkg, eventTest, "", marker), true, ""},
		{"kill in tree subtest output", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest + "/case"},
			TestEvent{Action: "output", Package: eventPkg, Test: eventTest + "/case", Output: marker + "\n"},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest + "/case"},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg},
		), true, ""},
		{"kill with required subtest", "exact subtest", failStream(t, eventPkg, eventTest, "exact subtest", marker), true, ""},
		{"survived", "", passStream(t, eventPkg, eventTest, ""), false, ClassSurvived},
		{"missing selector", "", rawStream(t, TestEvent{Action: "pass", Package: eventPkg}), false, ClassSelectorMissing},
		{"required skip", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "skip", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg},
		), true, ClassRequiredSkip},
		{"error-only failure", "", failStream(t, eventPkg, eventTest, "", "some other assertion"), true, ClassMarkerMissing},
		{"marker in wrong subtest", "exact subtest", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest + "/exact subtest"},
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest + "/other"},
			TestEvent{Action: "output", Package: eventPkg, Test: eventTest + "/other", Output: marker + "\n"},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest + "/other"},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest + "/exact subtest"},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg},
		), true, ClassMarkerMissing},
		{"unrelated process failure", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg},
		), true, ClassUnrelatedFailure},
		{"failure outside required subtest", "exact subtest", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest + "/exact subtest"},
			TestEvent{Action: "pass", Package: eventPkg, Test: eventTest + "/exact subtest"},
			TestEvent{Action: "output", Package: eventPkg, Test: eventTest + "/other", Output: marker + "\n"},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg},
		), true, ClassUnrelatedFailure},
		{"foreign test", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg, Test: "TestOther"},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg},
		), true, ClassUnexpectedTest},
		{"no terminal event", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
		), false, ClassEventInvalid},
		{"duplicate fail events", "", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg},
		), true, ClassEventInvalid},
		{"required subtest never ran", "exact subtest", rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "output", Package: eventPkg, Test: eventTest, Output: marker + "\n"},
			TestEvent{Action: "fail", Package: eventPkg, Test: eventTest},
			TestEvent{Action: "fail", Package: eventPkg},
		), true, ClassSelectorMissing},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			events, err := ParseTestEvents(test.stream)
			if err != nil {
				t.Fatalf("parse stream: %v", err)
			}
			_, rejection := AcceptMutant(events, eventSelector(test.subtest), marker, test.processFailed)
			if test.want == "" {
				if rejection != nil {
					t.Fatalf("mutant rejected: %v", rejection)
				}
				return
			}
			if rejection == nil || rejection.Kind != test.want {
				t.Fatalf("mutant rejection = %v; want %s", rejection, test.want)
			}
		})
	}
}

// --- campaign tests -------------------------------------------------------

func TestCampaignSyntheticKill(t *testing.T) {
	fixture := buildSyntheticFixture(t, nil)
	runner := newScriptedRunner(t, fixture)
	report, err := RunCampaign(fixture.config(runner.run))
	if err != nil {
		t.Fatalf("synthetic campaign error = %v", err)
	}
	if report.Killed != len(fixture.manifest.Mutations) || report.Total != len(fixture.manifest.Mutations) ||
		len(report.Mutations) != len(fixture.manifest.Mutations) {
		t.Fatalf("campaign counts = %d/%d of %d; want all killed", report.Killed, len(report.Mutations), report.Total)
	}
	if report.ManifestSHA256 != fixture.digest {
		t.Fatalf("campaign manifest digest = %s; want %s", report.ManifestSHA256, fixture.digest)
	}
	for i, mutationReport := range report.Mutations {
		mutation := fixture.manifest.Mutations[i]
		if mutationReport.Classification != ClassKilled ||
			mutationReport.Diagnostic != classificationDiagnostics[ClassKilled] {
			t.Fatalf("mutation %s classification = %s; want killed", mutation.ID, mutationReport.Classification)
		}
		if mutationReport.PristineRuns != 1 || mutationReport.PristinePasses != 1 ||
			mutationReport.MutantRuns != 1 || mutationReport.MutantFails != 1 {
			t.Fatalf("mutation %s event counts = %d/%d/%d/%d; want 1/1/1/1",
				mutation.ID, mutationReport.PristineRuns, mutationReport.PristinePasses,
				mutationReport.MutantRuns, mutationReport.MutantFails)
		}
		if !validSHA256Hex(mutationReport.PostimageSHA256) ||
			mutationReport.PostimageSHA256 == mutationReport.SourceSHA256 {
			t.Fatalf("mutation %s postimage hash invalid or unchanged", mutation.ID)
		}
	}
	wantCalls := 3 * len(fixture.manifest.Mutations)
	if len(runner.calls) != wantCalls {
		t.Fatalf("runner calls = %d; want %d", len(runner.calls), wantCalls)
	}
	for i, mutation := range fixture.manifest.Mutations {
		oracle := oracleCommand(&mutation)
		compile := compileCommand(&mutation)
		for j, want := range [][]string{oracle, compile, oracle} {
			got := runner.calls[3*i+j]
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Fatalf("mutation %s call %d = %q; want %q", mutation.ID, j, got, want)
			}
		}
	}
	requireNoResidue(t, fixture.workParent)
	for name, content := range fixture.files {
		data, err := os.ReadFile(filepath.Join(fixture.sourceRoot, filepath.FromSlash(name)))
		if err != nil || string(data) != content {
			t.Fatalf("live source %s changed during campaign: err=%v", name, err)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal campaign report: %v", err)
	}
	for _, forbidden := range []string{fixture.sourceRoot, fixture.workParent, "// anchor-", "// replacement-"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("campaign report leaks %q", forbidden)
		}
	}
}

func TestCampaignRejectsInvalidOutcomes(t *testing.T) {
	exitErr := errors.New("exit status 1")
	entry := func(fixture syntheticFixture, index int) *Mutation {
		return &fixture.manifest.Mutations[index]
	}
	oracleTest := func(fixture syntheticFixture, index int) string {
		return fixture.manifest.Mutations[index].Test
	}

	t.Run("preimage drift", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		target := filepath.Join(fixture.sourceRoot, filepath.FromSlash(entry(fixture, 0).SourcePath))
		if err := os.WriteFile(target, []byte("package fake\n\ndrift\n"), 0o600); err != nil {
			t.Fatalf("drift live source: %v", err)
		}
		runner := newScriptedRunner(t, fixture)
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassSourceDrift)
		if len(runner.calls) != 0 {
			t.Fatalf("runner called %d times on preimage drift; want 0", len(runner.calls))
		}
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("zero anchors", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, func(entries []Mutation, files map[string]string) {
			first := entries[0]
			files[first.SourcePath] = strings.Replace(files[first.SourcePath], first.Anchor, "", 1)
		})
		runner := newScriptedRunner(t, fixture)
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassTransformInvalid)
		if len(runner.calls) != 1 {
			t.Fatalf("runner calls = %d; want 1 (pristine only)", len(runner.calls))
		}
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("multiple anchors", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, func(entries []Mutation, files map[string]string) {
			first := entries[0]
			files[first.SourcePath] += first.Anchor
		})
		runner := newScriptedRunner(t, fixture)
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassTransformInvalid)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("missing pristine event", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		runner.overrides[0] = CommandResult{Output: rawStream(t, TestEvent{Action: "pass", Package: eventPkg})}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassPristineMissing)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("pristine oracle failed", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		test := oracleTest(fixture, 0)
		runner.overrides[0] = CommandResult{
			Output: failStream(t, eventPkg, test, entry(fixture, 0).RequiredSubtest(), "boom"),
			Err:    exitErr,
		}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassPristineFailed)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("required pristine skip", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		runner.overrides[0] = CommandResult{Output: rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: oracleTest(fixture, 0)},
			TestEvent{Action: "skip", Package: eventPkg, Test: oracleTest(fixture, 0)},
			TestEvent{Action: "pass", Package: eventPkg},
		)}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassRequiredSkip)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("compile failure is not a kill", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		runner.overrides[1] = CommandResult{Err: exitErr}
		report, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassCompileFailed)
		if len(runner.calls) != 2 {
			t.Fatalf("runner calls = %d; want 2 (pristine, compile)", len(runner.calls))
		}
		if report.Killed != 0 {
			t.Fatalf("compile failure counted %d kills; want 0", report.Killed)
		}
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("missing selector", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		runner.overrides[2] = CommandResult{Output: rawStream(t, TestEvent{Action: "pass", Package: eventPkg})}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassSelectorMissing)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("unexpected test", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		runner.overrides[2] = CommandResult{Output: rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: oracleTest(fixture, 0)},
			TestEvent{Action: "run", Package: eventPkg, Test: "TestUnrelated"},
			TestEvent{Action: "fail", Package: eventPkg, Test: "TestUnrelated"},
			TestEvent{Action: "fail", Package: eventPkg},
		), Err: exitErr}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassUnexpectedTest)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("unrelated failure", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		runner.overrides[2] = CommandResult{Output: rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: oracleTest(fixture, 0)},
			TestEvent{Action: "fail", Package: eventPkg},
		), Err: exitErr}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassUnrelatedFailure)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("error-only failure is not a kill", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		test := oracleTest(fixture, 0)
		runner.overrides[2] = CommandResult{
			Output: failStream(t, eventPkg, test, entry(fixture, 0).RequiredSubtest(), "some other assertion"),
			Err:    exitErr,
		}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassMarkerMissing)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("survived mutant is not a kill", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		test := oracleTest(fixture, 0)
		runner.overrides[2] = CommandResult{
			Output: passStream(t, eventPkg, test, entry(fixture, 0).RequiredSubtest()),
		}
		report, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassSurvived)
		if report.Killed != 0 {
			t.Fatalf("survived mutant counted %d kills; want 0", report.Killed)
		}
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("required mutant skip", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		runner.overrides[2] = CommandResult{Output: rawStream(t,
			TestEvent{Action: "run", Package: eventPkg, Test: oracleTest(fixture, 0)},
			TestEvent{Action: "skip", Package: eventPkg, Test: oracleTest(fixture, 0)},
			TestEvent{Action: "fail", Package: eventPkg},
		), Err: exitErr}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassRequiredSkip)
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("timeout is not a kill", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		runner := newScriptedRunner(t, fixture)
		runner.overrides[2] = CommandResult{Err: errors.New("context deadline exceeded"), TimedOut: true}
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, entry(fixture, 0).ID, ClassTimeout)
		requireNoResidue(t, fixture.workParent)
	})
}

func TestCampaignRejectsUnconfinedTargets(t *testing.T) {
	t.Run("symlink escape in source tree", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		link := filepath.Join(fixture.sourceRoot, "internal", "pcv3", "escape.go")
		if err := os.Symlink(filepath.Join(fixture.workParent, "outside.go"), link); err != nil {
			t.Fatalf("plant symlink: %v", err)
		}
		runner := newScriptedRunner(t, fixture)
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, "", ClassConfinementFailed)
		if len(runner.calls) != 0 {
			t.Fatalf("runner called %d times on symlink escape; want 0", len(runner.calls))
		}
		requireNoResidue(t, fixture.workParent)
	})

	t.Run("work parent inside a live checkout", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		if err := os.Mkdir(filepath.Join(fixture.workParent, ".git"), 0o700); err != nil {
			t.Fatalf("plant checkout marker: %v", err)
		}
		runner := newScriptedRunner(t, fixture)
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, "", ClassConfinementFailed)
		if len(runner.calls) != 0 {
			t.Fatalf("runner called %d times on live-tree target; want 0", len(runner.calls))
		}
		requireNoResidue(t, fixture.workParent, ".git")
	})

	t.Run("work parent inside source root", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		nested := filepath.Join(fixture.sourceRoot, "work")
		if err := os.Mkdir(nested, 0o700); err != nil {
			t.Fatalf("create nested work parent: %v", err)
		}
		fixture.workParent = nested
		runner := newScriptedRunner(t, fixture)
		runner.workParent = nested
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, "", ClassConfinementFailed)
		if len(runner.calls) != 0 {
			t.Fatalf("runner called %d times on ancestor target; want 0", len(runner.calls))
		}
		requireNoResidue(t, nested)
	})

	t.Run("source root resolves through a symlink", func(t *testing.T) {
		fixture := buildSyntheticFixture(t, nil)
		link := filepath.Join(t.TempDir(), "linked-source")
		if err := os.Symlink(fixture.sourceRoot, link); err != nil {
			t.Fatalf("plant source symlink: %v", err)
		}
		fixture.sourceRoot = link
		runner := newScriptedRunner(t, fixture)
		_, err := RunCampaign(fixture.config(runner.run))
		requireCampaignError(t, err, "", ClassConfinementFailed)
		if len(runner.calls) != 0 {
			t.Fatalf("runner called %d times on symlink source root; want 0", len(runner.calls))
		}
	})
}

func requireCampaignError(t *testing.T, err error, wantID string, want Classification) {
	t.Helper()
	if err == nil {
		t.Fatalf("campaign succeeded; want %s refusal", want)
	}
	var campaignErr *CampaignError
	if !errors.As(err, &campaignErr) || campaignErr.Classification != want {
		t.Fatalf("campaign error = %v; want classification %s", err, want)
	}
	if campaignErr.MutationID != wantID {
		t.Fatalf("campaign error mutation = %q; want %q", campaignErr.MutationID, wantID)
	}
	if classificationDiagnostics[want] == "" {
		t.Fatalf("classification %s has no closed diagnostic", want)
	}
}
