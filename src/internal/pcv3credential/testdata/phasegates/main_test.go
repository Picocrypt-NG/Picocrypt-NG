package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testBaseline = "1111111111111111111111111111111111111111"
	testBase     = "2222222222222222222222222222222222222222"
)

func TestFreezeIdentityCanonicalAndReadOnly(t *testing.T) {
	output := filepath.Join(t.TempDir(), "execution-identity.json")
	hash, err := writeExclusiveCanonical(output, struct {
		SchemaVersion int `json:"schema_version"`
	}{SchemaVersion: 1})
	if err != nil {
		t.Fatalf("freeze canonical identity: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("identity SHA-256 length = %d; want 64", len(hash))
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read canonical identity: %v", err)
	}
	if string(data) != "{\"schema_version\":1}\n" ||
		hash != sha256Hex(data) {
		t.Fatalf("identity bytes/hash are not canonical: %q / %s", data, hash)
	}
	info, err := os.Lstat(output)
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("identity mode = %04o; want 0444", info.Mode().Perm())
	}
	if _, err := writeExclusiveCanonical(output, map[string]int{"replacement": 1}); err == nil {
		t.Fatal("second identity publication unexpectedly replaced the first")
	}
}

func TestFreezeIdentityBindsRunnerAndInspector(t *testing.T) {
	fixture := newGateFixture(t)
	identity, hash := fixture.freeze(t)
	if identity.Runner.File.Path == identity.Inspector.File.Path ||
		identity.Runner.File.SHA256 == "" ||
		identity.Inspector.File.SHA256 == "" ||
		identity.Runner.File.SHA256 == identity.Inspector.File.SHA256 ||
		identity.Runner.GoBuildVersion != "go1.26.5" ||
		identity.Inspector.GoBuildVersion != "go1.26.5" {
		t.Fatalf("runner/inspector identities are not independently bound: %+v / %+v",
			identity.Runner, identity.Inspector)
	}
	data, err := os.ReadFile(fixture.identityPath)
	if err != nil {
		t.Fatalf("read frozen identity: %v", err)
	}
	if hash != sha256Hex(data) {
		t.Fatal("returned identity hash does not bind the snapshot bytes")
	}
}

func TestFreezeIdentityRejectsMissingOrAliasedInspector(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.freezeOptions.Inspector = filepath.Join(fixture.root, "missing-inspector")
		fixture.requireFreezeRejectedWithoutOutput(t)
	})
	t.Run("symlink alias", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires host privileges on Windows")
		}
		fixture := newGateFixture(t)
		alias := filepath.Join(fixture.root, "inspector-link")
		if err := os.Symlink(fixture.runnerPath, alias); err != nil {
			t.Fatalf("create inspector alias: %v", err)
		}
		fixture.freezeOptions.Inspector = alias
		fixture.requireFreezeRejectedWithoutOutput(t)
	})
	t.Run("same path", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.freezeOptions.Inspector = fixture.runnerPath
		fixture.requireFreezeRejectedWithoutOutput(t)
	})
}

func TestFreezeIdentityRejectsSecrets(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.config.ChildEnvironment.Allowlist = append(
		fixture.config.ChildEnvironment.Allowlist,
		"DEPLOY_TOKEN",
	)
	fixture.config.ChildEnvironment.Required["DEPLOY_TOKEN"] = "not-a-real-secret"
	fixture.writeConfig(t)
	fixture.requireFreezeRejectedWithoutOutput(t)
}

func TestStageRejectsIdentityBeforeReservation(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.addHostThreatClosure()
	_, hash := fixture.freeze(t)
	if err := os.WriteFile(
		fixture.specPath,
		[]byte("identity drift"),
		0o600,
	); err != nil {
		t.Fatalf("drift bound specification: %v", err)
	}
	options := fixture.stageOptions("host", hash)
	if err := runStage(context.Background(), options, fixture.deps()); err == nil {
		t.Fatal("stage accepted pre-reservation identity drift")
	}
	if _, err := os.Lstat(options.Evidence); !os.IsNotExist(err) {
		t.Fatalf("identity mismatch created evidence: %v", err)
	}
}

func TestStageZeroSubprocessOnMismatch(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.setCommand(
		"normal1",
		fixture.helperCommand(t, "record", filepath.Join(fixture.root, "record.json")),
	)
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("normal1", hash)
	options.ExecutionIdentitySHA256 = strings.Repeat("f", 64)
	var starts atomic.Int32
	deps := fixture.deps()
	deps.commandContext = func(
		ctx context.Context,
		name string,
		args ...string,
	) *exec.Cmd {
		starts.Add(1)
		return exec.CommandContext(ctx, name, args...)
	}
	if err := runStage(context.Background(), options, deps); err == nil {
		t.Fatal("stage accepted mismatched identity hash")
	}
	if starts.Load() != 0 {
		t.Fatalf("identity mismatch constructed %d subprocesses; want 0", starts.Load())
	}
	if _, err := os.Lstat(options.Evidence); !os.IsNotExist(err) {
		t.Fatalf("identity mismatch created evidence: %v", err)
	}
}

func TestStageCreateExclusive(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.addHostThreatClosure()
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("host", hash)
	if err := runStage(context.Background(), options, fixture.deps()); err != nil {
		t.Fatalf("run one create-exclusive host stage: %v", err)
	}
	evidence := readEvidence(t, options.Evidence)
	if evidence.Status != "PASS" {
		t.Fatalf("first stage evidence status = %q; want PASS", evidence.Status)
	}
	info, err := os.Lstat(options.Evidence)
	if err != nil {
		t.Fatalf("stat stage evidence: %v", err)
	}
	if info.Mode().Perm() != evidenceMode {
		t.Fatalf("evidence mode = %04o; want %04o", info.Mode().Perm(), evidenceMode)
	}
	before, err := os.ReadFile(options.Evidence)
	if err != nil {
		t.Fatalf("read first evidence: %v", err)
	}
	if err := runStage(context.Background(), options, fixture.deps()); err == nil {
		t.Fatal("stage retry unexpectedly replaced existing evidence")
	}
	after, err := os.ReadFile(options.Evidence)
	if err != nil {
		t.Fatalf("read evidence after retry: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected stage retry changed terminal evidence")
	}

	for _, contents := range []string{"", "{\"status\":\"PARTIAL\"}\n"} {
		t.Run("existing-"+strings.ReplaceAll(contents, "\n", ""), func(t *testing.T) {
			other := fixture.stageOptions("host", hash)
			other.Evidence = filepath.Join(t.TempDir(), "existing-evidence.json")
			if err := os.WriteFile(other.Evidence, []byte(contents), 0o600); err != nil {
				t.Fatalf("write existing evidence: %v", err)
			}
			if err := runStage(context.Background(), other, fixture.deps()); err == nil {
				t.Fatal("stage accepted malformed or partial existing evidence")
			}
		})
	}
}

func TestStageRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires host privileges on Windows")
	}
	fixture := newGateFixture(t)
	fixture.addHostThreatClosure()
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("host", hash)
	target := filepath.Join(fixture.root, "symlink-target")
	if err := os.Symlink(target, options.Evidence); err != nil {
		t.Fatalf("create evidence symlink: %v", err)
	}
	if err := runStage(context.Background(), options, fixture.deps()); err == nil {
		t.Fatal("stage accepted symlink evidence path")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("stage followed evidence symlink: %v", err)
	}
}

func TestStageRevalidatesAfterRun(t *testing.T) {
	fixture := newGateFixture(t)
	recordPath := filepath.Join(fixture.root, "record.json")
	fixture.setCommand("normal1", fixture.helperCommand(t, "record", recordPath, "post-check"))
	_, hash := fixture.freeze(t)
	deps := fixture.deps()
	deps.beforePostCheck = func() {
		_ = os.WriteFile(fixture.specPath, []byte("post-run drift"), 0o600)
	}
	options := fixture.stageOptions("normal1", hash)
	if err := runStage(context.Background(), options, deps); err == nil {
		t.Fatal("stage accepted post-run identity drift")
	}
	evidence := readEvidence(t, options.Evidence)
	if evidence.Status != "FAIL" ||
		!strings.Contains(evidence.Failure, "post-execution identity validation") {
		t.Fatalf("post-run mismatch did not produce terminal failure: %+v", evidence)
	}
}

func TestStageUsesExactArgvAndEnv(t *testing.T) {
	fixture := newGateFixture(t)
	recordPath := filepath.Join(fixture.root, "exact-argv-env.json")
	literal := "$(touch " + filepath.Join(fixture.root, "shell-escape") + ")"
	fixture.setCommand(
		"normal1",
		fixture.helperCommand(t, "record", recordPath, "argument with spaces", literal),
	)
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("normal1", hash)
	if err := runStage(context.Background(), options, fixture.deps()); err != nil {
		t.Fatalf("run exact argv/env stage: %v", err)
	}
	var record helperRecord
	readJSON(t, recordPath, &record)
	wantArgs := []string{"record", recordPath, "argument with spaces", literal}
	if !reflect.DeepEqual(record.Args, wantArgs) {
		t.Fatalf("helper argv = %#v; want %#v", record.Args, wantArgs)
	}
	if !reflect.DeepEqual(record.Env, []string{"GOMAXPROCS=10"}) {
		t.Fatalf("helper env = %#v; want exact frozen environment", record.Env)
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, "shell-escape")); !os.IsNotExist(err) {
		t.Fatalf("literal shell syntax was interpreted: %v", err)
	}
}

func TestStageEnforcesHalfCoreEveryGoChild(t *testing.T) {
	fixture := newGateFixture(t)
	recordPath := filepath.Join(fixture.root, "go-child-env.json")
	command := fixture.helperCommand(t, "record", recordPath, "go-based")
	command.GoBased = true
	command.PackageParallelism = float64(1)
	fixture.setCommand("normal1", command)
	identity, hash := fixture.freeze(t)
	if identity.Online != 20 || identity.PhaseJobs != 10 {
		t.Fatalf("frozen CPU contract = online %d / jobs %d; want 20 / 10",
			identity.Online, identity.PhaseJobs)
	}
	if err := runStage(
		context.Background(),
		fixture.stageOptions("normal1", hash),
		fixture.deps(),
	); err != nil {
		t.Fatalf("run Go-based helper stage: %v", err)
	}
	var record helperRecord
	readJSON(t, recordPath, &record)
	if !reflect.DeepEqual(record.Env, []string{"GOMAXPROCS=10"}) {
		t.Fatalf("Go-based child env = %#v; want frozen half-core GOMAXPROCS", record.Env)
	}
}

func TestReviewedGateAndMutationContracts(t *testing.T) {
	config, configIdentity, err := loadGateConfig(
		filepath.Join("..", "gates.json"),
		reviewedGateConfigSHA,
	)
	if err != nil {
		t.Fatalf("load exact reviewed gate config: %v", err)
	}
	if err := validateGateConfig(config); err != nil {
		t.Fatalf("validate exact reviewed gate config: %v", err)
	}
	mutationStage := config.Stages["mutation"]
	if len(mutationStage.Commands) != 1 ||
		mutationStage.Commands[0].Kind != "mutation-campaign" ||
		len(mutationStage.Commands[0].Argv) != 0 {
		t.Fatalf("mutation stage can bypass the internal campaign: %+v", mutationStage)
	}
	if configIdentity.SHA256 != reviewedGateConfigSHA {
		t.Fatal("compiled gate hash does not bind the reviewed manifest")
	}
	if len(config.ThreatClosure) != 21 {
		t.Fatalf("reviewed threat closure count = %d; want 21", len(config.ThreatClosure))
	}
	if !contains(
		config.Stages["host"].Commands[0].RequiredTestIDs,
		"TestUnpackAllowsSystemTempDirSymlinkPrefix",
	) {
		t.Fatal("host runtime inventory does not require the reviewed skip test")
	}
	for _, stage := range config.Stages {
		for _, command := range stage.Commands {
			if !command.GoBased {
				continue
			}
			value, err := parallelismValue(command.PackageParallelism)
			if err != nil || value != 1 {
				t.Fatalf("Go command %s aggregate package parallelism is not one", command.ID)
			}
		}
	}
	if contains(config.Stages["host"].Commands[0].Argv, "./...") {
		t.Fatal("reviewed host test surface contains a package wildcard")
	}
	overlapLeft := executionSurface{
		PackagePaths: []string{"./internal/pcv3credential"},
		BuildTags:    []string{"migrated_fynedo"},
		TestSelector: "all",
		EvidenceKind: "go-test-json",
	}
	overlapRight := overlapLeft
	overlapRight.TestSelector = "^TestFactorModeMatrix$"
	if !executionSurfacesOverlap(overlapLeft, overlapRight) {
		t.Fatal("all-tests surface did not overlap an exact selector")
	}
	overlapRight.EvidenceKind = "go-test-race-json"
	if executionSurfacesOverlap(overlapLeft, overlapRight) {
		t.Fatal("distinct evidence kinds were treated as duplicate execution surfaces")
	}
	reorderedLeft := executionSurface{
		PackagePaths: []string{"./internal/pcv3credential"},
		BuildTags:    []string{"migrated_fynedo", "pcv3_production_kdf"},
		TestSelector: "^TestProductionKDFExactProfiles$/^normal-1$",
		EvidenceKind: "go-test-json",
	}
	reorderedRight := reorderedLeft
	reorderedRight.BuildTags = []string{"pcv3_production_kdf", "migrated_fynedo"}
	if !executionSurfacesOverlap(reorderedLeft, reorderedRight) {
		t.Fatal("reordered build tags evaded execution-surface overlap")
	}
	regexCommand := commandConfig{
		ID:   "regex-overlap",
		Kind: "go-test",
		ExecutionSurface: executionSurface{
			PackagePaths: []string{"./internal/pcv3credential"},
			BuildTags:    []string{"migrated_fynedo"},
			TestSelector: "^Test(Foo|Bar)$",
			EvidenceKind: "go-test-json",
		},
		Argv: []string{
			"${GO}", "test", "-tags", "migrated_fynedo",
			"./internal/pcv3credential", "-run", "^Test(Foo|Bar)$", "-json",
		},
	}
	if err := validateExecutionSurface(regexCommand); err == nil {
		t.Fatal("intersecting regular-expression selector was accepted as exact")
	}

	var manifest campaignManifest
	if err := decodeStrictFile(filepath.Join("..", "mutations.json"), &manifest); err != nil {
		t.Fatalf("strict-decode tracked mutation manifest: %v", err)
	}
	identity := executionIdentity{
		Baseline: manifest.BaselineCommit,
		Spec: fileIdentity{
			SHA256: manifest.SpecSHA256,
		},
		SourceManifest: fileIdentity{
			SHA256: manifest.SourceManifestSHA256,
		},
	}
	if err := validateCampaignManifest(&manifest, config, identity); err != nil {
		t.Fatalf("validate tracked mutation campaign: %v", err)
	}
}

func TestLintJSONRequiresCurrentReportSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lint.json")
	for name, contents := range map[string]string{
		"valid":          `{"Issues":[],"Report":{"Linters":[{"Name":"gosec","Enabled":true}]}}`,
		"missing report": `{"Issues":[]}`,
		"unknown field":  `{"Issues":[],"Report":{"Linters":[{"Name":"gosec","Enabled":true}]},"Extra":true}`,
		"empty report":   `{"Issues":[],"Report":{"Linters":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("write lint JSON: %v", err)
			}
			err := validateLintJSON(path, 0)
			if name == "valid" && err != nil {
				t.Fatalf("valid current lint JSON rejected: %v", err)
			}
			if name != "valid" && err == nil {
				t.Fatal("malformed lint JSON accepted")
			}
		})
	}
}

func TestMutationCampaignOverallTimeout(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	result, err := runConfiguredCommand(
		expired,
		commandConfig{
			ID:             "mutation-campaign",
			Kind:           "mutation-campaign",
			TimeoutSeconds: 3600,
		},
		&gateConfig{},
		executionIdentity{},
		nil,
		defaultDeps(),
	)
	if !errors.Is(err, context.DeadlineExceeded) || !result.TimedOut {
		t.Fatalf("overall mutation timeout = (%+v, %v); want terminal deadline", result, err)
	}
}

func TestStageLeaseSerializesAllStages(t *testing.T) {
	root := t.TempDir()
	rootHandle, err := openEvidenceRootHandle(root)
	if err != nil {
		t.Fatalf("open stage lease root: %v", err)
	}
	defer rootHandle.Close()
	release, err := acquireStageLease(rootHandle)
	if err != nil {
		t.Fatalf("acquire first stage lease: %v", err)
	}
	if _, err := acquireStageLease(rootHandle); err == nil {
		t.Fatal("second stage acquired the shared execution lease")
	}
	if err := release(); err != nil {
		t.Fatalf("release first stage lease: %v", err)
	}
	secondRelease, err := acquireStageLease(rootHandle)
	if err != nil {
		t.Fatalf("acquire stage lease after release: %v", err)
	}
	if err := secondRelease(); err != nil {
		t.Fatalf("release second stage lease: %v", err)
	}
}

func TestSourceManifestBindsBaselineAndDiff(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.writeConfig(t)
	fixture.writeSourceManifest(t)
	var manifest sourceManifest
	readJSON(t, fixture.sourceManifest, &manifest)
	manifest.Baseline = strings.Repeat("a", 40)
	data, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatalf("encode drifted source manifest: %v", err)
	}
	if err := os.WriteFile(fixture.sourceManifest, data, 0o600); err != nil {
		t.Fatalf("write drifted source manifest: %v", err)
	}
	if _, err := freezeIdentity(fixture.freezeOptions, fixture.deps()); err == nil {
		t.Fatal("freeze accepted source manifest with a false baseline")
	}
}

func TestFreezeIdentityRequiresManifestedVendorTree(t *testing.T) {
	t.Run("missing vendor modules", func(t *testing.T) {
		fixture := newGateFixture(t)
		if err := os.Remove(filepath.Join(
			fixture.source,
			"src",
			"vendor",
			"modules.txt",
		)); err != nil {
			t.Fatalf("remove vendor/modules.txt: %v", err)
		}
		fixture.requireFreezeRejectedWithoutOutput(t)
	})

	t.Run("vendor omitted from source manifest", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.writeConfig(t)
		fixture.writeSourceManifest(t)
		var manifest sourceManifest
		readJSON(t, fixture.sourceManifest, &manifest)
		var filtered []treeEntry
		for _, entry := range manifest.Entries {
			if entry.Path != "src/vendor/modules.txt" {
				filtered = append(filtered, entry)
			}
		}
		manifest.Entries = filtered
		data, err := canonicalJSON(manifest)
		if err != nil {
			t.Fatalf("encode incomplete source manifest: %v", err)
		}
		if err := os.WriteFile(fixture.sourceManifest, data, 0o600); err != nil {
			t.Fatalf("write incomplete source manifest: %v", err)
		}
		if _, err := freezeIdentity(fixture.freezeOptions, fixture.deps()); err == nil {
			t.Fatal("freeze accepted vendor omitted from source manifest")
		}
		if _, err := os.Lstat(fixture.identityPath); !os.IsNotExist(err) {
			t.Fatalf("rejected unmanifested vendor created identity: %v", err)
		}
	})

	t.Run("valid vendored fixture", func(t *testing.T) {
		fixture := newGateFixture(t)
		identity, _ := fixture.freeze(t)
		if identity.SourceTree.EntryCount == 0 {
			t.Fatal("valid vendored fixture produced an empty source identity")
		}
	})
}

func TestVendoredChildEnvironmentHasNoModuleFallback(t *testing.T) {
	config, _, err := loadGateConfig(
		filepath.Join("..", "gates.json"),
		reviewedGateConfigSHA,
	)
	if err != nil {
		t.Fatalf("load reviewed vendored gate config: %v", err)
	}
	root := t.TempDir()
	finalize, err := preparePrivateEnvironmentRoots(root, config)
	if err != nil {
		t.Fatalf("prepare reviewed private workspaces: %v", err)
	}
	defer func() {
		if err := finalize(false); err != nil {
			t.Errorf("roll back reviewed private workspaces: %v", err)
		}
	}()
	environments := map[string][]string{}
	for stage := range config.Stages {
		environments[stage], err = frozenEnvironment(
			config,
			10,
			stage,
			stageTempDirectory(root, stage),
			filepath.Dir(os.Args[0]),
		)
		if err != nil {
			t.Fatalf("freeze %s child environment: %v", stage, err)
		}
		flags, ok := environmentValue(environments[stage], "GOFLAGS")
		if !ok || flags != "-mod=vendor -trimpath" {
			t.Fatalf("%s GOFLAGS = %q; want vendored trimpath policy", stage, flags)
		}
		moduleCache, ok := environmentValue(environments[stage], "GOMODCACHE")
		if !ok {
			t.Fatalf("%s lacks module-cache sentinel", stage)
		}
		empty, err := directoryEmpty(moduleCache)
		if err != nil || !empty {
			t.Fatalf("%s module-cache fallback sentinel is not empty: %v", stage, err)
		}
	}
	if err := validateDistinctStageCaches(environments); err != nil {
		t.Fatalf("stage build caches are not distinct: %v", err)
	}
	identity := executionIdentity{
		EvidenceRoot: directoryIdentity{Path: root},
		Environment:  environments,
	}
	if err := validateStagePrivateWorkspace(identity, "host", true); err != nil {
		t.Fatalf("valid vendored host workspace failed preflight: %v", err)
	}
	moduleCache, _ := environmentValue(environments["host"], "GOMODCACHE")
	if err := os.WriteFile(filepath.Join(moduleCache, "fallback"), []byte("used"), 0o600); err != nil {
		t.Fatalf("mark module-cache fallback: %v", err)
	}
	if err := validateStagePrivateWorkspace(identity, "host", true); err == nil {
		t.Fatal("module-cache fallback did not fail before evidence reservation")
	}
	if err := os.Remove(filepath.Join(moduleCache, "fallback")); err != nil {
		t.Fatalf("remove module-cache fallback fixture: %v", err)
	}
}

func TestFreezeIdentityRejectsWrongInspectorMainPackage(t *testing.T) {
	fixture := newGateFixture(t)
	wrongInspector := filepath.Join(fixture.root, "wrong-inspector")
	copyExecutable(t, fixture.runnerPath, wrongInspector)
	file, err := os.OpenFile(wrongInspector, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open wrong inspector fixture: %v", err)
	}
	if _, err := file.Write([]byte{0}); err != nil {
		_ = file.Close()
		t.Fatalf("distinguish wrong inspector bytes: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close wrong inspector fixture: %v", err)
	}
	fixture.freezeOptions.Inspector = wrongInspector
	fixture.requireFreezeRejectedWithoutOutput(t)
}

func TestStageRejectsNestedSourceTreeDrift(t *testing.T) {
	t.Run("before reservation", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.addHostThreatClosure()
		_, hash := fixture.freeze(t)
		if err := os.WriteFile(
			filepath.Join(fixture.source, "src", "nested-drift"),
			[]byte("drift"),
			0o600,
		); err != nil {
			t.Fatalf("write nested source drift: %v", err)
		}
		options := fixture.stageOptions("host", hash)
		if err := runStage(context.Background(), options, fixture.deps()); err == nil {
			t.Fatal("stage accepted nested source drift before reservation")
		}
		if _, err := os.Lstat(options.Evidence); !os.IsNotExist(err) {
			t.Fatalf("nested source drift created evidence: %v", err)
		}
	})

	t.Run("after execution", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.setCommand(
			"normal1",
			fixture.helperCommand(t, "record", filepath.Join(fixture.root, "record.json")),
		)
		_, hash := fixture.freeze(t)
		deps := fixture.deps()
		deps.beforePostCheck = func() {
			_ = os.WriteFile(
				filepath.Join(fixture.source, "src", "post-run-drift"),
				[]byte("drift"),
				0o600,
			)
		}
		options := fixture.stageOptions("normal1", hash)
		if err := runStage(context.Background(), options, deps); err == nil {
			t.Fatal("stage accepted nested source drift after execution")
		}
		if evidence := readEvidence(t, options.Evidence); evidence.Status != "FAIL" {
			t.Fatalf("post-run source drift evidence status = %q; want FAIL", evidence.Status)
		}
	})
}

func TestExpectedNonzeroExitIsStructuredSuccess(t *testing.T) {
	fixture := newGateFixture(t)
	command := fixture.helperCommand(t, "fail", "expected-marker")
	command.RequiredExitCode = 1
	command.RequiredOutputMarker = "expected-marker"
	fixture.setCommand("normal1", command)
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("normal1", hash)
	if err := runStage(context.Background(), options, fixture.deps()); err != nil {
		t.Fatalf("expected nonzero exit was rejected: %v", err)
	}
	if evidence := readEvidence(t, options.Evidence); evidence.Status != "PASS" {
		t.Fatalf("expected nonzero evidence status = %q; want PASS", evidence.Status)
	}
}

func TestStagePassRequiresPublicationProof(t *testing.T) {
	t.Run("published proof binds evidence", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.setCommand("normal1", fixture.helperCommand(t, "record",
			filepath.Join(fixture.root, "record.json")))
		_, hash := fixture.freeze(t)
		options := fixture.stageOptions("normal1", hash)
		if err := runStage(context.Background(), options, fixture.deps()); err != nil {
			t.Fatalf("run successful stage: %v", err)
		}
		root, err := openEvidenceRootHandle(fixture.root)
		if err != nil {
			t.Fatalf("open evidence root: %v", err)
		}
		defer root.Close()
		if err := verifyEvidencePublicationProofAt(
			root,
			filepath.Base(options.Evidence),
			fixture.config.EvidenceContract.PublicationProofSuffix,
		); err != nil {
			t.Fatalf("verify successful evidence publication proof: %v", err)
		}
	})

	t.Run("late proof failure cannot authenticate PASS bytes", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.setCommand("normal1", fixture.helperCommand(t, "record",
			filepath.Join(fixture.root, "record.json")))
		_, hash := fixture.freeze(t)
		deps := fixture.deps()
		deps.beforePublish = func(root, evidenceName string) {
			_ = os.WriteFile(
				filepath.Join(
					root,
					evidenceName+fixture.config.EvidenceContract.PublicationProofSuffix,
				),
				[]byte("invalid proof"),
				evidenceMode,
			)
		}
		options := fixture.stageOptions("normal1", hash)
		if err := runStage(context.Background(), options, deps); err == nil {
			t.Fatal("stage accepted a failed publication commit")
		}
		if evidence := readEvidence(t, options.Evidence); evidence.Status != "PASS" {
			t.Fatalf("pre-publication evidence status = %q; want PASS bytes", evidence.Status)
		}
		root, err := openEvidenceRootHandle(fixture.root)
		if err != nil {
			t.Fatalf("open evidence root: %v", err)
		}
		defer root.Close()
		if err := verifyEvidencePublicationProofAt(
			root,
			filepath.Base(options.Evidence),
			fixture.config.EvidenceContract.PublicationProofSuffix,
		); err == nil {
			t.Fatal("invalid late publication proof authenticated PASS bytes")
		}
	})
}

func TestEvidenceReplacementIsDetected(t *testing.T) {
	root := t.TempDir()
	rootHandle, err := openEvidenceRootHandle(root)
	if err != nil {
		t.Fatalf("open evidence root: %v", err)
	}
	defer rootHandle.Close()
	path := filepath.Join(root, "evidence.json")
	file, err := createEvidenceFileAt(rootHandle, filepath.Base(path))
	if err != nil {
		t.Fatalf("reserve evidence: %v", err)
	}
	displaced := filepath.Join(root, "displaced.json")
	if err := os.Rename(path, displaced); err != nil {
		t.Fatalf("displace reserved evidence: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("write evidence replacement: %v", err)
	}
	if _, err := finishEvidence(
		file,
		rootHandle,
		filepath.Base(path),
		stageEvidence{Status: "FAIL"},
	); err == nil {
		t.Fatal("evidence replacement was not detected")
	}
}

func TestStageExactSkipAllowlist(t *testing.T) {
	fixture := newGateFixture(t)
	if err := validateRuntimeSkips(&fixture.config, nil); err != nil {
		t.Fatalf("zero runtime skips must be valid: %v", err)
	}
	exact := []skipEvent{{
		Test:   "TestUnpackAllowsSystemTempDirSymlinkPrefix",
		Reason: "temp dir path has no symlinked prefix on this platform",
	}}
	if err := validateRuntimeSkips(&fixture.config, exact); err != nil {
		t.Fatalf("exact reviewed skip must be valid: %v", err)
	}
	if err := validateRuntimeSkips(
		&fixture.config,
		append(append([]skipEvent(nil), exact...), exact...),
	); err == nil {
		t.Fatal("duplicate runtime skip unexpectedly validated")
	}
	if err := validateRuntimeSkips(
		&fixture.config,
		[]skipEvent{{Test: exact[0].Test, Reason: exact[0].Reason + " extra"}},
	); err == nil {
		t.Fatal("prefix-matching skip unexpectedly validated")
	}
	source := filepath.Join(t.TempDir(), "unpack_test.go")
	if err := os.WriteFile(source, []byte(
		"package fileops\n"+
			"import \"testing\"\n"+
			"func TestUnpackAllowsSystemTempDirSymlinkPrefix(t *testing.T) {}\n",
	), 0o600); err != nil {
		t.Fatalf("write skip source fixture: %v", err)
	}
	count, err := exactGoTestDeclarationCount(
		source,
		"TestUnpackAllowsSystemTempDirSymlinkPrefix",
	)
	if err != nil || count != 1 {
		t.Fatalf("exact Go test declaration count = %d, %v; want 1", count, err)
	}
}

func TestGoTestJSONRequiresExactPackageTestAndSkipReason(t *testing.T) {
	const (
		testID      = "TestUnpackAllowsSystemTempDirSymlinkPrefix"
		packagePath = "Picocrypt-NG/internal/fileops"
		reason      = "temp dir path has no symlinked prefix on this platform"
	)
	requiredPackages := map[string]string{testID: packagePath}
	valid := strings.Join([]string{
		`{"Action":"run","Package":"` + packagePath + `","Test":"` + testID + `"}`,
		`{"Action":"output","Package":"` + packagePath + `","Test":"` + testID +
			`","Output":"    unpack_test.go:123: ` + reason + `\n"}`,
		`{"Action":"skip","Package":"` + packagePath + `","Test":"` + testID + `"}`,
	}, "\n")
	observed, skips, err := parseGoTestJSON(
		[]byte(valid),
		[]string{testID},
		requiredPackages,
	)
	if err != nil || !equalStrings(observed, []string{testID}) ||
		len(skips) != 1 || skips[0].Reason != reason {
		t.Fatalf("exact skip JSON rejected: observed=%v skips=%v err=%v", observed, skips, err)
	}

	for name, changed := range map[string]string{
		"wrong package":     strings.Replace(valid, packagePath, "other/package", 3),
		"substring reason":  strings.Replace(valid, reason, "prefix "+reason, 1),
		"package pass only": `{"Action":"pass","Package":"` + packagePath + `"}`,
		"competing diagnostic": strings.Replace(
			valid,
			`{"Action":"skip"`,
			`{"Action":"output","Package":"`+packagePath+`","Test":"`+testID+
				`","Output":"    unpack_test.go:122: other reason\n"}`+"\n"+
				`{"Action":"skip"`,
			1,
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseGoTestJSON(
				[]byte(changed),
				[]string{testID},
				requiredPackages,
			); err == nil {
				t.Fatal("spoofed Go test JSON satisfied the exact inventory")
			}
		})
	}
}

func TestPrivateEnvironmentRootsRollback(t *testing.T) {
	root := t.TempDir()
	config := &gateConfig{Stages: map[string]stageConfig{
		"host": {}, "mutation": {}, "normal1": {}, "paranoid1": {},
	}}
	blocker := filepath.Join(root, ".phasegates-xdg-cache")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatalf("create private-root collision: %v", err)
	}
	if _, err := preparePrivateEnvironmentRoots(root, config); err == nil {
		t.Fatal("private-root collision unexpectedly succeeded")
	}
	for _, name := range []string{".phasegates-home", ".phasegates-host-go-cache"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("failed setup left poisoned private root %s: %v", name, err)
		}
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatalf("remove private-root collision: %v", err)
	}
	finalize, err := preparePrivateEnvironmentRoots(root, config)
	if err != nil {
		t.Fatalf("prepare private roots: %v", err)
	}
	if err := finalize(false); err != nil {
		t.Fatalf("roll back private roots: %v", err)
	}
	for _, name := range []string{
		".phasegates-home",
		".phasegates-go-mod-cache",
		".phasegates-go-path",
		".phasegates-xdg-cache",
		".phasegates-xdg-config",
		".phasegates-host-go-cache",
		".phasegates-mutation-go-cache",
		".phasegates-normal1-go-cache",
		".phasegates-paranoid1-go-cache",
	} {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("rollback left private root %s: %v", name, err)
		}
	}
}

func TestStageRejectsEvalSymlinksSkip(t *testing.T) {
	fixture := newGateFixture(t)
	event := skipEvent{
		Test: "TestUnpackAllowsSystemTempDirSymlinkPrefix",
		Reason: "Cannot resolve temp dir symlinks on this platform: " +
			"simulated filesystem failure",
	}
	if err := validateRuntimeSkips(&fixture.config, []skipEvent{event}); err == nil {
		t.Fatal("EvalSymlinks error-path skip unexpectedly validated")
	}
}

func TestStageTimeoutTerminal(t *testing.T) {
	fixture := newGateFixture(t)
	command := fixture.helperCommand(t, "block")
	command.TimeoutSeconds = 1
	fixture.setCommand("normal1", command)
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("normal1", hash)
	if err := runStage(context.Background(), options, fixture.deps()); err == nil {
		t.Fatal("timed-out stage unexpectedly passed")
	}
	evidence := readEvidence(t, options.Evidence)
	if evidence.Status != "FAIL" || len(evidence.Commands) != 1 ||
		!evidence.Commands[0].TimedOut ||
		evidence.Commands[0].WaitErr == "" {
		t.Fatalf("timeout did not preserve terminal process evidence: %+v", evidence)
	}
}

func TestStageHasNoResetRetryOverwrite(t *testing.T) {
	var rootHelp bytes.Buffer
	if err := run([]string{"--help"}, &rootHelp); err != nil {
		t.Fatalf("render root help: %v", err)
	}
	if rootHelp.String() != "phasegates freeze-identity\nphasegates stage\n" {
		t.Fatalf("unexpected public commands:\n%s", rootHelp.String())
	}
	var stageHelp bytes.Buffer
	if err := run([]string{"stage", "--help"}, &stageHelp); err != nil {
		t.Fatalf("render stage help: %v", err)
	}
	for _, forbidden := range []string{
		"reset", "retry", "resume", "overwrite", "truncate", "delete", "inspector",
	} {
		if strings.Contains(strings.ToLower(stageHelp.String()), forbidden) {
			t.Fatalf("stage help exposes forbidden capability %q: %s",
				forbidden, stageHelp.String())
		}
	}
	var freezeHelp bytes.Buffer
	if err := run([]string{"freeze-identity", "--help"}, &freezeHelp); err != nil {
		t.Fatalf("render freeze help: %v", err)
	}
	if !strings.Contains(freezeHelp.String(), "--inspector") {
		t.Fatal("freeze-identity help does not bind the inspector")
	}
	for _, command := range []string{"reset", "retry", "resume", "overwrite", "truncate", "delete"} {
		if err := run([]string{command}, io.Discard); err == nil {
			t.Fatalf("forbidden command %q unexpectedly exists", command)
		}
	}
}

func TestPhasegatesHelperProcess(t *testing.T) {
	args := flag.Args()
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "record":
		if len(args) < 2 {
			t.Fatal("record helper requires output path")
		}
		record := helperRecord{
			Args: append([]string(nil), args...),
			Env:  append([]string(nil), os.Environ()...),
		}
		data, err := canonicalJSON(record)
		if err != nil {
			t.Fatalf("encode helper record: %v", err)
		}
		if err := os.WriteFile(args[1], data, 0o600); err != nil {
			t.Fatalf("write helper record: %v", err)
		}
	case "block":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt)
		<-signals
		signal.Stop(signals)
	case "fail":
		if len(args) != 2 {
			t.Fatal("fail helper requires one marker")
		}
		_, _ = fmt.Fprintln(os.Stderr, args[1])
		os.Exit(1)
	default:
		t.Fatalf("unknown helper mode %q", args[0])
	}
}

type helperRecord struct {
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

type gateFixture struct {
	root            string
	source          string
	config          gateConfig
	configPath      string
	sourceManifest  string
	diffPath        string
	specPath        string
	vectorsPath     string
	vectorInputPath string
	mutationsPath   string
	runnerPath      string
	inspectorPath   string
	identityPath    string
	freezeOptions   freezeOptions
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	t.Setenv("GOMAXPROCS", "10")
	root := t.TempDir()
	source := filepath.Join(root, "archive")
	sourceDir := filepath.Join(source, "src")
	if err := os.MkdirAll(
		filepath.Join(sourceDir, "vendor", "example.com", "fixturedep"),
		0o700,
	); err != nil {
		t.Fatalf("create source fixture: %v", err)
	}
	fixture := &gateFixture{
		root:            root,
		source:          source,
		configPath:      filepath.Join(sourceDir, "gates.json"),
		sourceManifest:  filepath.Join(root, "source.manifest.json"),
		diffPath:        filepath.Join(sourceDir, "source.diff"),
		specPath:        filepath.Join(sourceDir, "spec.md"),
		vectorsPath:     filepath.Join(sourceDir, "vectors.json"),
		vectorInputPath: filepath.Join(sourceDir, "vector-input.json"),
		mutationsPath:   filepath.Join(sourceDir, "mutations.json"),
		runnerPath:      filepath.Join(root, "phasegates"),
		inspectorPath:   filepath.Join(root, "phaseinspect"),
		identityPath:    filepath.Join(root, "execution-identity.json"),
	}
	for path, contents := range map[string]string{
		filepath.Join(sourceDir, "go.mod"): "module Picocrypt-NG\n\ngo 1.26.0\n\n" +
			"require example.com/fixturedep v1.0.0\n",
		filepath.Join(sourceDir, "vendor", "modules.txt"): "# example.com/fixturedep v1.0.0\n" +
			"## explicit; go 1.20\nexample.com/fixturedep\n",
		filepath.Join(
			sourceDir,
			"vendor",
			"example.com",
			"fixturedep",
			"dep.go",
		): "package fixturedep\n",
		fixture.diffPath:        "source diff\n",
		fixture.specPath:        "specification\n",
		fixture.vectorsPath:     "{\"vectors\":[]}\n",
		fixture.vectorInputPath: "{\"inputs\":[]}\n",
		fixture.mutationsPath:   "{\"mutations\":[]}\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write identity fixture %s: %v", path, err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	copyExecutable(t, executable, fixture.runnerPath)
	copyExecutable(t, executable, fixture.inspectorPath)
	inspector, err := os.OpenFile(fixture.inspectorPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open distinct inspector fixture: %v", err)
	}
	if _, err := inspector.Write([]byte{0}); err != nil {
		_ = inspector.Close()
		t.Fatalf("distinguish inspector fixture bytes: %v", err)
	}
	if err := inspector.Sync(); err != nil {
		_ = inspector.Close()
		t.Fatalf("sync distinct inspector fixture: %v", err)
	}
	if err := inspector.Close(); err != nil {
		t.Fatalf("close distinct inspector fixture: %v", err)
	}
	runnerIdentity, err := executableFileIdentity(fixture.runnerPath)
	if err != nil {
		t.Fatalf("read runner fixture identity: %v", err)
	}
	threatIDs := make([]string, 21)
	for index := range threatIDs {
		threatIDs[index] = "T-02-" + formatTwoDigits(index+1)
	}
	fixture.config = gateConfig{
		SchemaVersion: gateSchemaVersion,
		GoVersion:     runnerIdentity.GoBuildVersion,
		Module:        runnerIdentity.ModulePath,
		CPUContract: cpuContract{
			MinimumOnline:                     2,
			ExactProfileMinimumOnline:         8,
			MemoryHardPackageParallelism:      1,
			RequireForAllGoAndGoBasedChildren: true,
		},
		ChildEnvironment: childEnvironment{
			Allowlist: []string{"GOMAXPROCS"},
			Required: map[string]string{
				"GOMAXPROCS": "${PHASE_JOBS}",
			},
			RejectNameFragments: []string{
				"AUTH", "CREDENTIAL", "KEY", "PASSWORD", "SECRET", "TOKEN",
			},
		},
		RequiredThreatIDs: threatIDs,
		RequiredExecutionUnits: []string{
			"mutation-unit", "normal-unit", "paranoid-unit", "host-unit",
		},
		SkipAllowlist: []skipRule{{
			Test:                       "TestUnpackAllowsSystemTempDirSymlinkPrefix",
			Reason:                     "temp dir path has no symlinked prefix on this platform",
			Match:                      "exact",
			SourcePath:                 "internal/fileops/unpack_test.go",
			RequiredGoTestDeclarations: 1,
		}},
		SkipRuntimeCardinality: skipCardinality{Minimum: 0, Maximum: 1},
		SkipRejectedReasons: []string{
			"Cannot resolve temp dir symlinks on this platform:",
		},
		LintRuns: []lintRun{
			{ID: "lint-normal"},
			{ID: "lint-reproduction"},
			{ID: "lint-production"},
		},
		Stages: map[string]stageConfig{
			"mutation":  {MinimumOnline: 2, OwnedExecutionUnits: []string{"mutation-unit"}},
			"normal1":   {MinimumOnline: 8, OwnedExecutionUnits: []string{"normal-unit"}},
			"paranoid1": {MinimumOnline: 8, OwnedExecutionUnits: []string{"paranoid-unit"}},
			"host":      {MinimumOnline: 2, OwnedExecutionUnits: []string{"host-unit"}},
		},
		EvidenceContract: evidenceContract{
			SchemaVersion:          1,
			TerminalStatuses:       []string{"PASS", "FAIL"},
			RequiredStageNames:     []string{"mutation", "normal1", "paranoid1", "host"},
			CreateExclusive:        true,
			ReplaceForbidden:       true,
			PublicationProofSuffix: ".verified",
		},
	}
	fixture.writeConfig(t)
	fixture.freezeOptions = freezeOptions{
		Config:         fixture.configPath,
		Baseline:       testBaseline,
		Base:           testBase,
		SourceManifest: fixture.sourceManifest,
		Diff:           fixture.diffPath,
		Spec:           fixture.specPath,
		Vectors:        fixture.vectorsPath,
		VectorInput:    fixture.vectorInputPath,
		Mutations:      fixture.mutationsPath,
		Runner:         fixture.runnerPath,
		Inspector:      fixture.inspectorPath,
		Output:         fixture.identityPath,
	}
	return fixture
}

func (fixture *gateFixture) deps() runtimeDeps {
	deps := defaultDeps()
	configIdentity, err := regularFileIdentity(fixture.configPath)
	if err != nil {
		panic("read gate fixture config identity: " + err.Error())
	}
	deps.gateConfigSHA = configIdentity.SHA256
	deps.hostFacts = func() (hostFacts, error) {
		return hostFacts{
			GOOS:           runtime.GOOS,
			GOARCH:         runtime.GOARCH,
			CPUModel:       "test-cpu-model",
			CPUModelSource: "test fixture",
			OnlineSource:   "runtime.NumCPU",
			Online:         20,
		}, nil
	}
	deps.executable = func() (string, error) {
		return fixture.runnerPath, nil
	}
	deps.executableID = func(path string) (executableIdentity, error) {
		identity, err := executableFileIdentity(path)
		if err == nil {
			manifest, manifestErr := regularFileIdentity(fixture.sourceManifest)
			if manifestErr != nil {
				return executableIdentity{}, manifestErr
			}
			identity.Attestation = buildAttestation{
				Baseline:             testBaseline,
				Base:                 testBase,
				SourceManifestSHA256: manifest.SHA256,
			}
			if filepath.Clean(path) == filepath.Clean(fixture.inspectorPath) {
				identity.MainPackagePath = "Picocrypt-NG/internal/pcv3credential/testdata/phaseinspect"
			}
		}
		return identity, err
	}
	deps.compiledAttestation = func() buildAttestation {
		manifest, err := regularFileIdentity(fixture.sourceManifest)
		if err != nil {
			panic("read fixture source manifest attestation: " + err.Error())
		}
		return buildAttestation{
			Baseline:             testBaseline,
			Base:                 testBase,
			SourceManifestSHA256: manifest.SHA256,
		}
	}
	return deps
}

func (fixture *gateFixture) freeze(t *testing.T) (executionIdentity, string) {
	t.Helper()
	fixture.writeConfig(t)
	fixture.writeSourceManifest(t)
	hash, err := freezeIdentity(fixture.freezeOptions, fixture.deps())
	if err != nil {
		t.Fatalf("freeze fixture identity: %v", err)
	}
	var identity executionIdentity
	readJSON(t, fixture.identityPath, &identity)
	return identity, hash
}

func (fixture *gateFixture) requireFreezeRejectedWithoutOutput(t *testing.T) {
	t.Helper()
	fixture.writeSourceManifest(t)
	if _, err := freezeIdentity(fixture.freezeOptions, fixture.deps()); err == nil {
		t.Fatal("invalid freeze identity unexpectedly succeeded")
	}
	if _, err := os.Lstat(fixture.identityPath); !os.IsNotExist(err) {
		t.Fatalf("rejected freeze created identity output: %v", err)
	}
}

func (fixture *gateFixture) writeConfig(t *testing.T) {
	t.Helper()
	data, err := canonicalJSON(fixture.config)
	if err != nil {
		t.Fatalf("encode gate config fixture: %v", err)
	}
	if err := os.WriteFile(fixture.configPath, data, 0o600); err != nil {
		t.Fatalf("write gate config fixture: %v", err)
	}
}

func (fixture *gateFixture) writeSourceManifest(t *testing.T) {
	t.Helper()
	sourceTree, entries, err := stableDirectoryTreeSnapshot(fixture.source)
	if err != nil {
		t.Fatalf("snapshot gate fixture source: %v", err)
	}
	diff, err := regularFileIdentity(fixture.diffPath)
	if err != nil {
		t.Fatalf("read gate fixture diff identity: %v", err)
	}
	data, err := canonicalJSON(sourceManifest{
		SchemaVersion: gateSchemaVersion,
		Baseline:      testBaseline,
		Base:          testBase,
		DiffSHA256:    diff.SHA256,
		SourceTree:    sourceTree,
		Entries:       entries,
	})
	if err != nil {
		t.Fatalf("encode gate fixture source manifest: %v", err)
	}
	if err := os.WriteFile(fixture.sourceManifest, data, 0o600); err != nil {
		t.Fatalf("write gate fixture source manifest: %v", err)
	}
}

func (fixture *gateFixture) addHostThreatClosure() {
	stage := fixture.config.Stages["host"]
	stage.Commands = []commandConfig{{
		ID:                "host-threat-closure",
		Kind:              "internal",
		RequiredIDsSource: "required_threat_ids",
		RequiredCount:     21,
	}}
	fixture.config.Stages["host"] = stage
}

func (fixture *gateFixture) setCommand(stageName string, command commandConfig) {
	stage := fixture.config.Stages[stageName]
	stage.Commands = []commandConfig{command}
	fixture.config.Stages[stageName] = stage
}

func (fixture *gateFixture) helperCommand(
	t *testing.T,
	args ...string,
) commandConfig {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve helper executable: %v", err)
	}
	argv := []string{
		executable,
		"-test.run=^TestPhasegatesHelperProcess$",
		"--",
	}
	argv = append(argv, args...)
	return commandConfig{
		ID:               "helper-command",
		Kind:             "structured",
		Argv:             argv,
		CWD:              filepath.Join(fixture.source, "src"),
		TimeoutSeconds:   10,
		RequiredExitCode: 0,
	}
}

func (fixture *gateFixture) stageOptions(stage, identityHash string) stageOptions {
	return stageOptions{
		Stage:                   stage,
		Config:                  fixture.configPath,
		Baseline:                testBaseline,
		Base:                    testBase,
		Source:                  fixture.source,
		SourceManifest:          fixture.sourceManifest,
		Diff:                    fixture.diffPath,
		ExecutionIdentity:       fixture.identityPath,
		ExecutionIdentitySHA256: identityHash,
		Evidence:                filepath.Join(fixture.root, stage+"-evidence.json"),
	}
}

func copyExecutable(t *testing.T, source, target string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatalf("open executable fixture source: %v", err)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatalf("create executable fixture: %v", err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatalf("copy executable fixture: %v", err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		t.Fatalf("sync executable fixture: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close executable fixture: %v", err)
	}
}

func readEvidence(t *testing.T, path string) stageEvidence {
	t.Helper()
	var evidence stageEvidence
	readJSON(t, path, &evidence)
	return evidence
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read JSON %s: %v", path, err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatalf("decode JSON %s: %v", path, err)
	}
}

func formatTwoDigits(value int) string {
	if value < 10 {
		return "0" + string(rune('0'+value))
	}
	return string([]byte{byte('0' + value/10), byte('0' + value%10)})
}

func init() {
	// Keep the test binary's flag parser aware that helper arguments follow "--".
	flag.CommandLine.SetOutput(io.Discard)
	time.Local = time.UTC
}
