package main

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testBaseline              = "1111111111111111111111111111111111111111"
	testBase                  = "2222222222222222222222222222222222222222"
	expectedGoTestFailureIDs  = 32
	goTestFailureOutputSecret = "failure-output-secret-must-not-enter-evidence"
)

func oversizedGoTestFailureID() string {
	return "TestOversizedFailureID" + strings.Repeat("Z", 512)
}

type testFileSnapshot struct {
	SHA256          string
	Mode            os.FileMode
	Size            int64
	ModTimeUnixNano int64
}

func snapshotTestFile(t *testing.T, path string) testFileSnapshot {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshotted file: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat snapshotted file: %v", err)
	}
	return testFileSnapshot{
		SHA256:          sha256Hex(data),
		Mode:            info.Mode(),
		Size:            info.Size(),
		ModTimeUnixNano: info.ModTime().UnixNano(),
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func requireCanonicalJSONFile(t *testing.T, path string, value any) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canonical JSON fixture %s: %v", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Fatalf("decode canonical JSON fixture %s: %v", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("canonical JSON fixture %s has trailing values", path)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("re-encode canonical JSON fixture %s: %v", path, err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		t.Fatalf("JSON fixture %s is not canonical", path)
	}
	return data
}

// Kills production mutation: accepting uppercase or non-40-byte object IDs.
func TestValidOIDAcceptsExactly40LowercaseHex(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "lowercase hex", value: strings.Repeat("a", 40), want: true},
		{name: "uppercase hex", value: strings.Repeat("A", 40), want: false},
		{name: "64 lowercase hex", value: strings.Repeat("a", 64), want: false},
		{name: "non-hex", value: strings.Repeat("g", 40), want: false},
		{name: "short", value: strings.Repeat("a", 39), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validOID(test.value); got != test.want {
				t.Fatalf("validOID(%q) = %t; want %t", test.value, got, test.want)
			}
		})
	}
}

func TestFreezeIdentityCanonicalAndReadOnly(t *testing.T) {
	output := filepath.Join(t.TempDir(), "execution-identity.json")
	hash, err := writeExclusiveCanonical(output, struct {
		SchemaVersion int `json:"schema_version"`
	}{SchemaVersion: 1}, defaultDeps().syncDirectory)
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
	if _, err := writeExclusiveCanonical(
		output,
		map[string]int{"replacement": 1},
		defaultDeps().syncDirectory,
	); err == nil {
		t.Fatal("second identity publication unexpectedly replaced the first")
	}
}

// Kills omitting the authenticated parent-directory sync after exclusive
// identity creation.
func TestFreezeIdentityDirectorySyncFailureIsTerminal(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.writeConfig(t)
	fixture.writeSourceManifest(t)
	parentInfo, err := os.Lstat(fixture.root)
	if err != nil {
		t.Fatalf("stat identity parent fixture: %v", err)
	}
	sentinel := errors.New("sentinel identity directory sync failure")
	syncCalls := 0
	deps := fixture.deps()
	deps.syncDirectory = func(directory *os.File) error {
		syncCalls++
		directoryInfo, err := directory.Stat()
		if err != nil {
			t.Fatalf("stat authenticated identity directory handle: %v", err)
		}
		if !directoryInfo.IsDir() || !os.SameFile(directoryInfo, parentInfo) {
			t.Fatal("identity sync callback did not receive the authenticated parent")
		}
		var identity executionIdentity
		requireCanonicalJSONFile(t, fixture.identityPath, &identity)
		identityInfo, err := os.Lstat(fixture.identityPath)
		if err != nil {
			t.Fatalf("stat identity at directory-sync boundary: %v", err)
		}
		if identityInfo.Mode().Perm() != executionIdentityMode {
			t.Fatalf(
				"identity mode at directory-sync boundary = %04o; want %04o",
				identityInfo.Mode().Perm(),
				executionIdentityMode,
			)
		}
		return sentinel
	}

	hash, freezeErr := freezeIdentity(fixture.freezeOptions, deps)
	if hash != "" {
		t.Fatalf("directory-sync failure returned identity hash %q; want empty", hash)
	}
	if !errors.Is(freezeErr, sentinel) {
		t.Fatalf("identity directory-sync error = %v; want sentinel in chain", freezeErr)
	}
	if syncCalls != 1 {
		t.Fatalf("identity directory sync calls = %d; want exactly 1", syncCalls)
	}
	if _, err := os.Lstat(fixture.identityPath); err != nil {
		t.Fatalf("terminal identity directory-sync failure removed identity: %v", err)
	}
}

func TestFreezeIdentityRequiresPrivateEvidenceRoot(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.writeConfig(t)
	fixture.writeSourceManifest(t)
	if err := os.Chmod(fixture.root, 0o755); err != nil {
		t.Fatalf("make evidence root public: %v", err)
	}
	if _, err := freezeIdentity(
		fixture.freezeOptions,
		fixture.deps(),
	); err == nil || err.Error() != "evidence root must have mode 0700" {
		t.Fatalf("public evidence root error = %v; want exact rejection", err)
	}
	if _, err := os.Lstat(fixture.identityPath); !os.IsNotExist(err) {
		t.Fatalf("public evidence root created identity output: %v", err)
	}
}

// Kills production mutation: allowing non-canonical OIDs past freeze validation.
func TestFreezeIdentityRejectsNonCanonicalOIDBeforePublication(t *testing.T) {
	for _, test := range []struct {
		name     string
		baseline string
	}{
		{name: "uppercase", baseline: strings.Repeat("A", 40)},
		{name: "64 characters", baseline: strings.Repeat("a", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGateFixture(t)
			fixture.freezeOptions.Baseline = test.baseline
			fixture.writeConfig(t)
			fixture.writeSourceManifest(t)

			var manifest sourceManifest
			readJSON(t, fixture.sourceManifest, &manifest)
			manifest.Baseline = strings.ToLower(test.baseline)
			data, err := canonicalJSON(manifest)
			if err != nil {
				t.Fatalf("encode matching source manifest: %v", err)
			}
			if err := os.WriteFile(fixture.sourceManifest, data, 0o600); err != nil {
				t.Fatalf("write matching source manifest: %v", err)
			}
			manifestIdentity, err := regularFileIdentity(fixture.sourceManifest)
			if err != nil {
				t.Fatalf("bind matching source manifest: %v", err)
			}

			deps := fixture.deps()
			deps.compiledAttestation = func() buildAttestation {
				return buildAttestation{
					Baseline:             strings.ToLower(test.baseline),
					Base:                 testBase,
					SourceManifestSHA256: manifestIdentity.SHA256,
				}
			}
			_, freezeErr := freezeIdentity(fixture.freezeOptions, deps)
			if freezeErr == nil ||
				freezeErr.Error() !=
					"baseline and base must be full hexadecimal object IDs" {
				t.Errorf("non-canonical OID freeze error = %v; want early rejection",
					freezeErr)
			}
			if _, err := os.Lstat(fixture.identityPath); !os.IsNotExist(err) {
				t.Errorf("non-canonical OID created identity: %v", err)
			}
		})
	}
}

func TestFreezeIdentityBindsRunnerAndInspector(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.writeConfig(t)
	fixture.writeSourceManifest(t)
	manifest, err := regularFileIdentity(fixture.sourceManifest)
	if err != nil {
		t.Fatalf("bind source manifest: %v", err)
	}
	savedBaseline := phase2Baseline
	savedBase := phase2Base
	savedSourceManifest := phase2SourceManifestSHA256
	phase2Baseline = testBaseline
	phase2Base = testBase
	phase2SourceManifestSHA256 = manifest.SHA256
	t.Cleanup(func() {
		phase2Baseline = savedBaseline
		phase2Base = savedBase
		phase2SourceManifestSHA256 = savedSourceManifest
	})
	deps := fixture.deps()
	deps.compiledAttestation = defaultDeps().compiledAttestation
	hash, err := freezeIdentity(fixture.freezeOptions, deps)
	if err != nil {
		t.Fatalf("freeze with matching runtime globals: %v", err)
	}
	var identity executionIdentity
	readJSON(t, fixture.identityPath, &identity)
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
	if bytes.Contains(data, []byte(`"build_attestation"`)) {
		t.Fatal("executable identity duplicates the top-level runtime binding")
	}

	t.Run("Go executable role binding", func(t *testing.T) {
		config := fixture.config
		config.Stages = map[string]stageConfig{
			"host": {
				Commands: []commandConfig{{Argv: []string{"${GO}"}}},
			},
		}
		config.LintRuns = nil
		_, err := frozenExecutables(
			&config,
			identity.Runner,
			func(string) (string, error) {
				return fixture.runnerPath, nil
			},
		)
		if err == nil ||
			err.Error() != "go executable main package is not cmd/go" {
			t.Fatalf("wrong-role Go executable error = %v", err)
		}
	})

	t.Run("real trimpath binary checks all runtime globals", func(t *testing.T) {
		if runtime.NumCPU() < 2 {
			t.Fatalf(
				"real phasegates self-binding test requires at least two online CPUs; got %d",
				runtime.NumCPU(),
			)
		}
		moduleRoot := phasegatesTestModuleRoot(t)
		goExecutable := testGoExecutable(t)
		inputRoot := t.TempDir()
		if err := os.Chmod(inputRoot, 0o700); err != nil {
			t.Fatalf("make real-binary evidence root private: %v", err)
		}
		buildEnvironmentRoot := t.TempDir()
		sourceDirectory := filepath.Join(inputRoot, "src")
		if err := os.MkdirAll(sourceDirectory, 0o700); err != nil {
			t.Fatalf("create real-binary source fixture: %v", err)
		}
		configData, err := os.ReadFile(filepath.Join(
			moduleRoot,
			"internal",
			"pcv3credential",
			"testdata",
			"gates.json",
		))
		if err != nil {
			t.Fatalf("read reviewed gate config: %v", err)
		}
		inputs := map[string][]byte{
			"gates.json":     configData,
			"manifest.json":  []byte("{}\n"),
			"diff.patch":     []byte("diff\n"),
			"spec.md":        []byte("spec\n"),
			"vectors.json":   []byte("{}\n"),
			"vector.in":      []byte("vector\n"),
			"mutations.json": []byte("{}\n"),
		}
		for name, data := range inputs {
			if err := os.WriteFile(
				filepath.Join(sourceDirectory, name),
				data,
				0o400,
			); err != nil {
				t.Fatalf("write real-binary input %s: %v", name, err)
			}
		}
		manifestSHA256 := sha256Hex(inputs["manifest.json"])
		for index, test := range []struct {
			name                 string
			baseline             string
			base                 string
			sourceManifestSHA256 string
			wantError            string
		}{
			{
				name:                 "matching",
				baseline:             testBaseline,
				base:                 testBase,
				sourceManifestSHA256: manifestSHA256,
				wantError:            "vendored source is absent from the complete source manifest",
			},
			{
				name:                 "wrong baseline",
				baseline:             strings.Repeat("3", 40),
				base:                 testBase,
				sourceManifestSHA256: manifestSHA256,
				wantError:            "running phasegates build attestation mismatch",
			},
			{
				name:                 "wrong base",
				baseline:             testBaseline,
				base:                 strings.Repeat("3", 40),
				sourceManifestSHA256: manifestSHA256,
				wantError:            "running phasegates build attestation mismatch",
			},
			{
				name:                 "wrong source manifest",
				baseline:             testBaseline,
				base:                 testBase,
				sourceManifestSHA256: strings.Repeat("3", 64),
				wantError:            "running phasegates build attestation mismatch",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				binary := buildRealPhasegatesBinary(
					t,
					moduleRoot,
					buildEnvironmentRoot,
					goExecutable,
					filepath.Join(inputRoot, fmt.Sprintf("phasegates-%d", index)),
					test.baseline,
					test.base,
					test.sourceManifestSHA256,
				)
				output := filepath.Join(inputRoot, fmt.Sprintf("identity-%d.json", index))
				command := exec.Command(
					binary,
					"freeze-identity",
					"--config", filepath.Join(sourceDirectory, "gates.json"),
					"--baseline", testBaseline,
					"--base", testBase,
					"--source-manifest", filepath.Join(sourceDirectory, "manifest.json"),
					"--diff", filepath.Join(sourceDirectory, "diff.patch"),
					"--spec", filepath.Join(sourceDirectory, "spec.md"),
					"--vectors", filepath.Join(sourceDirectory, "vectors.json"),
					"--vector-input", filepath.Join(sourceDirectory, "vector.in"),
					"--mutations", filepath.Join(sourceDirectory, "mutations.json"),
					"--runner", binary,
					"--inspector", binary,
					"--output", output,
				)
				phaseJobs := derivedPhaseJobs(runtime.NumCPU())
				command.Env = []string{
					"GOMAXPROCS=" + strconv.Itoa(phaseJobs),
					"HOME=" + inputRoot,
					"PATH=" + filepath.Dir(goExecutable),
					"TMPDIR=" + inputRoot,
				}
				var stdout bytes.Buffer
				var stderr bytes.Buffer
				command.Stdout = &stdout
				command.Stderr = &stderr
				runErr := command.Run()
				var exitError *exec.ExitError
				if !errors.As(runErr, &exitError) || exitError.ExitCode() != 1 {
					t.Fatalf("real phasegates exit = %v; want 1", runErr)
				}
				if stdout.Len() != 0 {
					t.Fatalf("rejected real phasegates stdout = %q", stdout.String())
				}
				if stderr.String() != test.wantError+"\n" {
					t.Fatalf(
						"real phasegates stderr = %q; want %q",
						stderr.String(),
						test.wantError+"\n",
					)
				}
				if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
					t.Fatalf("rejected real phasegates created identity: %v", statErr)
				}
			})
		}
	})
}

func phasegatesTestModuleRoot(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Fatalf("resolve phasegates test directory: %v", err)
	}
	for {
		if info, statErr := os.Lstat(filepath.Join(current, "go.mod")); statErr == nil && info.Mode().IsRegular() {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("cannot locate phasegates test module root")
		}
		current = parent
	}
}

func testGoExecutable(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("resolve go executable: %v", err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatalf("make go executable path absolute: %v", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve go executable symlinks: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat go executable: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("go executable is not a regular file: %s", path)
	}
	return path
}

func buildRealPhasegatesBinary(
	t *testing.T,
	moduleRoot string,
	buildEnvironmentRoot string,
	goExecutable string,
	output string,
	baseline string,
	base string,
	sourceManifestSHA256 string,
) string {
	t.Helper()
	if runtime.Version() != "go1.26.5" {
		t.Fatalf("real phasegates test uses %s; want go1.26.5", runtime.Version())
	}
	moduleMode := "vendor"
	moduleCache := filepath.Join(buildEnvironmentRoot, "go-mod-cache")
	vendorModules := filepath.Join(moduleRoot, "vendor", "modules.txt")
	if info, err := os.Lstat(vendorModules); err != nil {
		if !os.IsNotExist(err) {
			t.Fatalf("stat vendored module inventory: %v", err)
		}
		moduleMode = "readonly"
		userHome, homeErr := os.UserHomeDir()
		if homeErr != nil {
			t.Fatalf("resolve Go module cache: %v", homeErr)
		}
		moduleCache = filepath.Join(userHome, "go", "pkg", "mod")
	} else if !info.Mode().IsRegular() {
		t.Fatalf("vendored module inventory is not a regular file: %s", vendorModules)
	}
	ldflags := strings.Join([]string{
		"-X=main.phase2Baseline=" + baseline,
		"-X=main.phase2Base=" + base,
		"-X=main.phase2SourceManifestSHA256=" + sourceManifestSHA256,
	}, " ")
	command := exec.Command(
		goExecutable,
		"build",
		"-mod="+moduleMode,
		"-trimpath",
		"-p", "1",
		"-ldflags", ldflags,
		"-o", output,
		"./internal/pcv3credential/testdata/phasegates",
	)
	command.Dir = moduleRoot
	command.Env = []string{
		"CGO_ENABLED=0",
		"GOCACHE=" + filepath.Join(buildEnvironmentRoot, "go-build"),
		"GOENV=off",
		"GOFLAGS=",
		"GOMAXPROCS=1",
		"GOMODCACHE=" + moduleCache,
		"GOPATH=" + filepath.Join(buildEnvironmentRoot, "gopath"),
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"HOME=" + buildEnvironmentRoot,
		"PATH=" + filepath.Dir(goExecutable),
		"TMPDIR=" + buildEnvironmentRoot,
	}
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build real phasegates binary: %v\n%s", err, combined)
	}
	return output
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

	t.Run("runtime build attestation drift", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.addHostThreatClosure()
		_, hash := fixture.freeze(t)
		options := fixture.stageOptions("host", hash)
		deps := fixture.deps()
		deps.compiledAttestation = func() buildAttestation {
			return buildAttestation{
				Baseline:             strings.Repeat("3", 40),
				Base:                 testBase,
				SourceManifestSHA256: strings.Repeat("3", 64),
			}
		}
		if err := os.WriteFile(
			fixture.specPath,
			[]byte("later input drift"),
			0o600,
		); err != nil {
			t.Fatalf("create later input mismatch: %v", err)
		}
		err := runStage(context.Background(), options, deps)
		if err == nil || err.Error() != "running phasegates build attestation mismatch" {
			t.Fatalf(
				"stage build-attestation error = %v; want exact mismatch",
				err,
			)
		}
		if _, statErr := os.Lstat(options.Evidence); !os.IsNotExist(statErr) {
			t.Fatalf("build-attestation mismatch created evidence: %v", statErr)
		}
	})
}

func TestExactStageEvidenceFilename(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.addHostThreatClosure()
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("host", hash)
	options.Evidence = filepath.Join(fixture.root, "wrong-name.json")
	if err := runStage(context.Background(), options, fixture.deps()); err == nil {
		t.Fatal("stage accepted an evidence basename outside the reviewed contract")
	}
	if _, err := os.Lstat(options.Evidence); !os.IsNotExist(err) {
		t.Fatalf("wrong evidence basename was reserved: %v", err)
	}
	if _, err := os.Lstat(options.Evidence + ".verified"); !os.IsNotExist(err) {
		t.Fatalf("wrong evidence proof basename was reserved: %v", err)
	}
}

func TestCPUFacts(t *testing.T) {
	if _, err := cpuFactsForOnline(1); err == nil {
		t.Fatal("CPU facts accepted fewer than two online CPUs")
	}
	root := t.TempDir()
	t.Chdir(root)
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o400); err != nil {
		t.Fatalf("write CPU-facts sentinel: %v", err)
	}
	before := snapshotTestFile(t, sentinel)
	var stdout bytes.Buffer
	if err := run([]string{"cpu-facts"}, &stdout); err != nil {
		t.Fatalf("report CPU facts: %v", err)
	}
	after := snapshotTestFile(t, sentinel)
	if before != after {
		t.Fatalf("cpu-facts changed controlled filesystem state: before=%+v after=%+v",
			before, after)
	}
	var rejectedStdout bytes.Buffer
	if err := run([]string{"cpu-facts", "unexpected"}, &rejectedStdout); err == nil {
		t.Fatal("cpu-facts accepted an extra argument")
	}
	if rejectedStdout.Len() != 0 {
		t.Fatalf("rejected cpu-facts invocation wrote stdout: %q", rejectedStdout.String())
	}
	var facts struct {
		Online       int    `json:"online"`
		PhaseJobs    int    `json:"phase_jobs"`
		OnlineSource string `json:"online_source"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &facts); err != nil {
		t.Fatalf("decode CPU facts: %v", err)
	}
	wantJobs := runtime.NumCPU() / 2
	if wantJobs > 10 {
		wantJobs = 10
	}
	wantJSON := fmt.Sprintf(
		"{\"online\":%d,\"phase_jobs\":%d,\"online_source\":\"runtime.NumCPU\"}\n",
		runtime.NumCPU(),
		wantJobs,
	)
	if stdout.String() != wantJSON {
		t.Fatalf("CPU facts bytes = %q; want canonical %q", stdout.String(), wantJSON)
	}
	if facts.Online != runtime.NumCPU() ||
		facts.PhaseJobs != wantJobs ||
		facts.OnlineSource != "runtime.NumCPU" {
		t.Fatalf("CPU facts = %+v; want online=%d phase_jobs=%d runtime.NumCPU",
			facts, runtime.NumCPU(), wantJobs)
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

// Kills omitting the evidence-directory sync or omitting/misordering the
// proof-directory sync before publication success.
func TestStagePublicationDirectorySyncOrderingAndFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		failCall int
	}{
		{name: "evidence directory", failCall: 1},
		{name: "proof directory", failCall: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGateFixture(t)
			stageTemp := stageTempDirectory(fixture.root, "normal1")
			fixture.setCommand(
				"normal1",
				fixture.helperCommand(
					t,
					"record",
					filepath.Join(stageTemp, "command-output.json"),
				),
			)
			_, hash := fixture.freeze(t)
			options := fixture.stageOptions("normal1", hash)
			finalProof := options.Evidence +
				fixture.config.EvidenceContract.PublicationProofSuffix
			pendingProof := filepath.Join(
				fixture.root,
				"."+filepath.Base(finalProof)+".pending",
			)
			lease := filepath.Join(fixture.root, ".phasegates-execution-lease")
			rootInfo, err := os.Lstat(fixture.root)
			if err != nil {
				t.Fatalf("stat stage evidence root fixture: %v", err)
			}
			sentinel := errors.New("sentinel stage directory sync failure")
			syncCalls := 0
			deps := fixture.deps()
			deps.syncDirectory = func(directory *os.File) error {
				syncCalls++
				directoryInfo, err := directory.Stat()
				if err != nil {
					t.Fatalf("stat authenticated evidence directory handle: %v", err)
				}
				if !directoryInfo.IsDir() || !os.SameFile(directoryInfo, rootInfo) {
					t.Fatal("stage sync callback did not receive the authenticated evidence root")
				}
				var evidence stageEvidence
				evidenceBytes := requireCanonicalJSONFile(
					t,
					options.Evidence,
					&evidence,
				)
				if evidence.Status != "PASS" {
					t.Fatalf(
						"evidence status at directory-sync boundary = %q; want PASS",
						evidence.Status,
					)
				}
				evidenceInfo, err := os.Lstat(options.Evidence)
				if err != nil {
					t.Fatalf("stat evidence at directory-sync boundary: %v", err)
				}
				if evidenceInfo.Mode().Perm() != evidenceMode {
					t.Fatalf(
						"evidence mode at directory-sync boundary = %04o; want %04o",
						evidenceInfo.Mode().Perm(),
						evidenceMode,
					)
				}
				if _, err := os.Lstat(stageTemp); !os.IsNotExist(err) {
					t.Fatalf("stage temp exists at directory-sync call %d: %v", syncCalls, err)
				}

				switch syncCalls {
				case 1:
					for _, path := range []string{finalProof, pendingProof} {
						if _, err := os.Lstat(path); !os.IsNotExist(err) {
							t.Fatalf(
								"proof path %s exists at evidence sync boundary: %v",
								path,
								err,
							)
						}
					}
				case 2:
					var proof evidencePublicationProof
					requireCanonicalJSONFile(t, finalProof, &proof)
					if proof.EvidenceSHA256 !=
						fmt.Sprintf("%x", sha256.Sum256(evidenceBytes)) {
						t.Fatal("published proof does not bind canonical evidence bytes")
					}
					proofInfo, err := os.Lstat(finalProof)
					if err != nil {
						t.Fatalf("stat final proof at directory-sync boundary: %v", err)
					}
					if proofInfo.Mode().Perm() != evidenceMode {
						t.Fatalf(
							"proof mode at directory-sync boundary = %04o; want %04o",
							proofInfo.Mode().Perm(),
							evidenceMode,
						)
					}
					for _, path := range []string{pendingProof, stageTemp, lease} {
						if _, err := os.Lstat(path); !os.IsNotExist(err) {
							t.Fatalf(
								"transient path %s exists at proof sync boundary: %v",
								path,
								err,
							)
						}
					}
				default:
					t.Fatalf("unexpected directory sync call %d", syncCalls)
				}
				if syncCalls == test.failCall {
					return sentinel
				}
				return nil
			}

			stageErr := runStage(context.Background(), options, deps)
			if !errors.Is(stageErr, sentinel) {
				t.Fatalf("stage directory-sync error = %v; want sentinel in chain", stageErr)
			}
			if syncCalls != test.failCall {
				t.Fatalf(
					"stage directory sync calls = %d; want exactly %d",
					syncCalls,
					test.failCall,
				)
			}
			if test.failCall == 1 {
				if _, err := os.Lstat(finalProof); !os.IsNotExist(err) {
					t.Fatalf("evidence sync failure published proof: %v", err)
				}
			} else {
				if _, err := os.Lstat(finalProof); err != nil {
					t.Fatalf("proof sync failure removed final proof: %v", err)
				}
			}
		})
	}
}

// Kills publishing successful PASS evidence before its terminal timestamp is
// assigned.
func TestStagePassEvidenceHasFinalTimestamp(t *testing.T) {
	const wantTimestamp = "2026-07-30T12:34:56.123456789Z"
	instant, err := time.Parse(time.RFC3339Nano, wantTimestamp)
	if err != nil {
		t.Fatalf("parse independently specified test instant: %v", err)
	}
	fixture := newGateFixture(t)
	fixture.setCommand(
		"normal1",
		fixture.helperCommand(
			t,
			"record",
			filepath.Join(fixture.root, "timestamp-command.json"),
		),
	)
	_, hash := fixture.freeze(t)
	deps := fixture.deps()
	deps.now = func() time.Time {
		return instant
	}
	options := fixture.stageOptions("normal1", hash)
	if err := runStage(context.Background(), options, deps); err != nil {
		t.Fatalf("run successful timestamp stage: %v", err)
	}
	evidence := readEvidence(t, options.Evidence)
	if evidence.StartedAt != wantTimestamp {
		t.Fatalf(
			"published PASS started_at = %q; want %q",
			evidence.StartedAt,
			wantTimestamp,
		)
	}
	started, err := time.Parse(time.RFC3339Nano, evidence.StartedAt)
	if err != nil {
		t.Fatalf("parse published PASS started_at: %v", err)
	}
	if evidence.FinishedAt != wantTimestamp {
		t.Fatalf(
			"published PASS finished_at = %q; want %q",
			evidence.FinishedAt,
			wantTimestamp,
		)
	}
	finished, err := time.Parse(time.RFC3339Nano, evidence.FinishedAt)
	if err != nil {
		t.Fatalf("parse published PASS finished_at: %v", err)
	}
	if finished.Before(started) {
		t.Fatalf(
			"published PASS finished_at %q precedes started_at %q",
			evidence.FinishedAt,
			evidence.StartedAt,
		)
	}
}

func TestStageRemovesTemporaryWorkspace(t *testing.T) {
	t.Run("after pass", func(t *testing.T) {
		fixture := newGateFixture(t)
		stageTemp := stageTempDirectory(fixture.root, "normal1")
		fixture.setCommand(
			"normal1",
			fixture.helperCommand(
				t,
				"record",
				filepath.Join(stageTemp, "command-output.json"),
			),
		)
		_, hash := fixture.freeze(t)
		options := fixture.stageOptions("normal1", hash)
		deps := fixture.deps()
		deps.beforePublish = func(string, string) {
			if _, err := os.Lstat(stageTemp); !os.IsNotExist(err) {
				t.Fatalf("stage temp still existed before publication: %v", err)
			}
		}
		if err := runStage(
			context.Background(),
			options,
			deps,
		); err != nil {
			t.Fatalf("run successful stage: %v", err)
		}
		if _, err := os.Lstat(stageTemp); !os.IsNotExist(err) {
			t.Fatalf("successful stage left temporary workspace: %v", err)
		}
		if evidence := readEvidence(t, options.Evidence); evidence.Status != "PASS" {
			t.Fatalf("successful stage evidence status = %q; want PASS", evidence.Status)
		}
	})

	t.Run("after terminal failure", func(t *testing.T) {
		fixture := newGateFixture(t)
		stageTemp := stageTempDirectory(fixture.root, "normal1")
		fixture.setCommand(
			"normal1",
			fixture.helperCommand(
				t,
				"record",
				filepath.Join(stageTemp, "command-output.json"),
			),
		)
		_, hash := fixture.freeze(t)
		deps := fixture.deps()
		deps.beforePostCheck = func() {
			_ = os.WriteFile(fixture.specPath, []byte("post-run drift"), 0o600)
		}
		options := fixture.stageOptions("normal1", hash)
		if err := runStage(context.Background(), options, deps); err == nil {
			t.Fatal("stage accepted post-run identity drift")
		}
		if _, err := os.Lstat(stageTemp); !os.IsNotExist(err) {
			t.Fatalf("failed stage left temporary workspace: %v", err)
		}
		if evidence := readEvidence(t, options.Evidence); evidence.Status != "FAIL" {
			t.Fatalf("failed stage evidence status = %q; want FAIL", evidence.Status)
		}
	})

	t.Run("cleanup failure cannot authenticate pass", func(t *testing.T) {
		fixture := newGateFixture(t)
		stageTemp := stageTempDirectory(fixture.root, "normal1")
		fixture.setCommand(
			"normal1",
			fixture.helperCommand(
				t,
				"record",
				filepath.Join(stageTemp, "command-output.json"),
			),
		)
		_, hash := fixture.freeze(t)
		deps := fixture.deps()
		deps.removeStageTemp = func(*os.Root, string) error {
			return errors.New("simulated rooted cleanup failure")
		}
		options := fixture.stageOptions("normal1", hash)
		err := runStage(context.Background(), options, deps)
		if err == nil || !strings.Contains(err.Error(), "remove stage temp directory") {
			t.Fatalf("cleanup failure error = %v; want exact operation context", err)
		}
		if evidence := readEvidence(t, options.Evidence); evidence.Status != "FAIL" {
			t.Fatalf("cleanup failure evidence status = %q; want FAIL", evidence.Status)
		}
		proof := options.Evidence +
			fixture.config.EvidenceContract.PublicationProofSuffix
		if _, err := os.Lstat(proof); !os.IsNotExist(err) {
			t.Fatalf("cleanup failure published an authentication proof: %v", err)
		}
		if _, err := os.Lstat(stageTemp); err != nil {
			t.Fatalf("simulated cleanup failure did not preserve its fixture: %v", err)
		}
	})
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

// Kills production mutations: accepting race aliases or an unmarked go-test command.
func TestGateConfigStructureRejectsRaceWhenCGODisabled(t *testing.T) {
	fixture := newGateFixture(t)
	config := fixture.config
	config.ChildEnvironment = fixture.config.ChildEnvironment
	config.ChildEnvironment.Required = cloneStringMap(
		fixture.config.ChildEnvironment.Required,
	)
	config.ChildEnvironment.Allowlist = append(
		append([]string(nil), fixture.config.ChildEnvironment.Allowlist...),
		"CGO_ENABLED",
	)
	config.ChildEnvironment.Required["CGO_ENABLED"] = "0"
	stage := config.Stages["normal1"]
	stage.Commands = []commandConfig{{
		ID:                 "controlled-go-command",
		Kind:               "structured",
		Argv:               []string{"${GO}", "test"},
		GoBased:            true,
		PackageParallelism: float64(1),
	}}
	config.Stages["normal1"] = stage
	if err := validateGateConfigStructure(&config); err != nil {
		t.Fatalf("valid non-race Go command rejected: %v", err)
	}

	stage.Commands[0].Argv = append(stage.Commands[0].Argv, "-race")
	config.Stages["normal1"] = stage
	err := validateGateConfigStructure(&config)
	if err == nil || err.Error() != "go -race command requires CGO_ENABLED=1" {
		t.Fatalf("CGO-disabled race command error = %v; want impossibility rejection", err)
	}

	config.ChildEnvironment.Required["CGO_ENABLED"] = "1"
	if err := validateGateConfigStructure(&config); err != nil {
		t.Fatalf("CGO-enabled exact -race command rejected: %v", err)
	}

	for _, alias := range []string{"--race", "-race=true", "--race=true"} {
		t.Run("noncanonical "+alias, func(t *testing.T) {
			stage.Commands[0].Argv = []string{"${GO}", "test", alias}
			config.Stages["normal1"] = stage
			err := validateGateConfigStructure(&config)
			if err == nil || err.Error() != "go race flag must use exact -race form" {
				t.Fatalf("race alias %q error = %v; want exact-form rejection",
					alias, err)
			}
		})
	}

	stage.Commands[0].Kind = "go-test"
	stage.Commands[0].GoBased = false
	stage.Commands[0].Argv = []string{"${GO}", "test", "--race"}
	config.Stages["normal1"] = stage
	config.ChildEnvironment.Required["CGO_ENABLED"] = "0"
	err = validateGateConfigStructure(&config)
	if err == nil || err.Error() != "go-test command must be Go-based" {
		t.Fatalf("unmarked go-test error = %v; want metadata rejection before race parsing",
			err)
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
	if err := validateExecutionSurface(regexCommand, "0"); err == nil {
		t.Fatal("intersecting regular-expression selector was accepted as exact")
	}

	var manifest campaignManifest
	if err := decodeStrictFile(filepath.Join("..", "mutations.json"), &manifest); err != nil {
		t.Fatalf("strict-decode tracked mutation manifest: %v", err)
	}
	identity := executionIdentity{
		Baseline: strings.Repeat("3", 40),
		Source: directoryIdentity{
			Path: "/frozen/source",
		},
		Spec: fileIdentity{
			SHA256: manifest.SpecSHA256,
		},
		SourceManifest: fileIdentity{
			SHA256: strings.Repeat("4", 64),
		},
		Mutations: fileIdentity{
			Path: "/frozen/source/src/internal/pcv3credential/testdata/mutations.json",
		},
	}
	if err := validateCampaignManifest(&manifest, config, identity); err != nil {
		t.Fatalf("validate tracked mutation campaign: %v", err)
	}

	t.Run("runner rejects application receipt drift", func(t *testing.T) {
		mutation := &manifest.Mutations[0]
		application := mutationApplicationCommand(
			"/tool/go",
			identity,
			&manifest,
			mutation,
			"/private/M-CRD/source",
			"/private/M-CRD/application.json",
		)
		wantArgv := []string{
			"/tool/go",
			"run",
			"-tags",
			"migrated_fynedo",
			"./internal/pcv3credential/testdata/mutator",
			"--source-copy", "/private/M-CRD/source/src",
			"--manifest", identity.Mutations.Path,
			"--mutation-id", mutation.ID,
			"--source-set-sha256", manifest.SourceSetSHA256,
			"--baseline", identity.Baseline,
			"--spec-sha256", manifest.SpecSHA256,
			"--result", "/private/M-CRD/application.json",
		}
		if !equalStrings(application.Argv, wantArgv) ||
			application.CWD != "/frozen/source/src" {
			t.Fatalf("runner application command = %#v in %q; want %#v in %q",
				application.Argv, application.CWD, wantArgv, "/frozen/source/src")
		}
		record := campaignApplicationRecord{
			SchemaVersion:      gateSchemaVersion,
			MutationID:         mutation.ID,
			BaselineCommit:     identity.Baseline,
			SpecSHA256:         manifest.SpecSHA256,
			SourceSetSHA256:    manifest.SourceSetSHA256,
			SourcePath:         mutation.SourcePath,
			SourceBeforeSHA256: mutation.SourceSHA256,
			SourceAfterSHA256:  strings.Repeat("5", 64),
			AnchorMatches:      1,
			ApplicationCount:   1,
			KillingTestID:      mutation.KillingTestID,
			ViolationMarker:    mutation.ViolationMarker,
			ExpectedPristine:   mutation.Pristine,
			ExpectedMutant:     mutation.Mutant,
		}
		if !validCampaignApplication(
			&record,
			&manifest,
			mutation,
			identity.Baseline,
		) {
			t.Fatal("runner rejected the exact identity-bound application receipt")
		}
		for name, corrupt := range map[string]func(*campaignApplicationRecord){
			"baseline": func(value *campaignApplicationRecord) {
				value.BaselineCommit = strings.Repeat("6", 40)
			},
			"spec": func(value *campaignApplicationRecord) {
				value.SpecSHA256 = strings.Repeat("7", 64)
			},
			"source set": func(value *campaignApplicationRecord) {
				value.SourceSetSHA256 = strings.Repeat("8", 64)
			},
		} {
			t.Run(name, func(t *testing.T) {
				invalid := record
				corrupt(&invalid)
				if validCampaignApplication(
					&invalid,
					&manifest,
					mutation,
					identity.Baseline,
				) {
					t.Fatal("runner accepted a drifted application receipt")
				}
			})
		}
		path := filepath.Join(t.TempDir(), "application.json")
		data, err := canonicalJSON(record)
		if err != nil {
			t.Fatalf("encode application receipt: %v", err)
		}
		data = append(
			append([]byte(nil), data[:len(data)-2]...),
			[]byte(",\"unknown\":true}\n")...,
		)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write unknown-field application receipt: %v", err)
		}
		var decoded campaignApplicationRecord
		if err := decodeStrictFile(path, &decoded); err == nil {
			t.Fatal("runner accepted an unknown application receipt field")
		}
	})

	t.Run("configured artifact namespace is the only authority", func(t *testing.T) {
		candidate := *config
		candidate.EvidenceContract = config.EvidenceContract
		candidate.EvidenceContract.StageFilenames = map[string]string{
			"mutation":  "campaign.result",
			"normal1":   "normal.result",
			"paranoid1": "paranoid.result",
			"host":      "host.result",
		}
		candidate.EvidenceContract.PublicationProofSuffix = ".proof"
		if err := validateGateConfig(&candidate); err != nil {
			t.Fatalf("safe configured artifact namespace rejected: %v", err)
		}
		for name, mutate := range map[string]func(*gateConfig){
			"missing stage": func(value *gateConfig) {
				delete(value.EvidenceContract.StageFilenames, "host")
			},
			"extra stage": func(value *gateConfig) {
				value.EvidenceContract.StageFilenames["extra"] = "extra.result"
			},
			"duplicate filename": func(value *gateConfig) {
				value.EvidenceContract.StageFilenames["host"] = value.EvidenceContract.StageFilenames["normal1"]
			},
			"unsafe filename": func(value *gateConfig) {
				value.EvidenceContract.StageFilenames["host"] = "../host.result"
			},
			"unsafe suffix": func(value *gateConfig) {
				value.EvidenceContract.PublicationProofSuffix = "/proof"
			},
		} {
			t.Run(name, func(t *testing.T) {
				invalid := candidate
				invalid.EvidenceContract = candidate.EvidenceContract
				invalid.EvidenceContract.StageFilenames = cloneStringMap(
					candidate.EvidenceContract.StageFilenames,
				)
				mutate(&invalid)
				if err := validateGateConfig(&invalid); err == nil {
					t.Fatal("invalid configured artifact namespace accepted")
				}
			})
		}
	})

	t.Run("producer evidence records complete authenticated observations", func(t *testing.T) {
		for name, fixtureJSON := range map[string]string{
			"command": `{"id":"normal-1-exact-profile","argv":["go","test"],"cwd":"/source/src","exit_code":0,"timed_out":false,"contract":{"kind":"go-test","execution_surface":{"package_paths":["./internal/pcv3credential"],"build_tags":["migrated_fynedo","pcv3_production_kdf"],"test_selector":"^TestProductionKDFExactProfiles$/^normal-1$","evidence_kind":"go-test-json"},"timeout_seconds":3900,"go_based":true,"memory_hard":true,"package_parallelism":1,"required_exit_code":0,"required_test_ids":["TestProductionKDFExactProfiles/normal-1"],"required_test_packages":{"TestProductionKDFExactProfiles/normal-1":"Picocrypt-NG/internal/pcv3credential"}}}`,
			"lint":    `{"id":"host-lint-normal","argv":["golangci-lint","run"],"cwd":"/source/src","exit_code":0,"timed_out":false,"contract":{"kind":"golangci-lint","execution_surface":{"package_paths":["./internal/pcv3credential"],"build_tags":["migrated_fynedo"],"test_selector":"all","evidence_kind":"lint-json"},"timeout_seconds":600,"go_based":true,"memory_hard":false,"package_parallelism":1,"required_exit_code":0,"required_test_ids":[],"required_test_packages":{}},"lint_result":{"run_id":"lint-normal","json_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issues":[],"enabled_linters":["gosec"]}}`,
			"scan":    `{"id":"host-gitleaks","argv":["gitleaks","detect"],"cwd":"/source/src","exit_code":0,"timed_out":false,"contract":{"kind":"gitleaks","execution_surface":{"package_paths":["./internal/pcv3credential"],"build_tags":[],"test_selector":"all","evidence_kind":"gitleaks"},"timeout_seconds":300,"go_based":true,"memory_hard":false,"package_parallelism":1,"required_exit_code":0,"required_test_ids":[],"required_test_packages":{}},"scan_result":{"scanner":"gitleaks","target":"/source/src/internal/pcv3credential","findings":0}}`,
		} {
			t.Run(name, func(t *testing.T) {
				var result commandResult
				if err := json.Unmarshal([]byte(fixtureJSON), &result); err != nil {
					t.Fatalf("decode producer evidence fixture: %v", err)
				}
				data, err := canonicalJSON(result)
				if err != nil {
					t.Fatalf("encode producer evidence fixture: %v", err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(data, &fields); err != nil {
					t.Fatalf("decode encoded producer evidence: %v", err)
				}
				if len(fields["contract"]) == 0 {
					t.Fatal("producer evidence omitted the command contract")
				}
				if len(fields["go_test_event"]) != 0 {
					t.Fatal("top-level producer evidence contains a nested Go test event")
				}
				if name == "lint" && len(fields["lint_result"]) == 0 {
					t.Fatal("producer evidence omitted the lint JSON result")
				}
				if name == "scan" && len(fields["scan_result"]) == 0 {
					t.Fatal("producer evidence omitted the scan result")
				}
			})
		}
		var mutation mutationExecution
		if err := json.Unmarshal([]byte(
			`{"id":"M-CRD06-01","killing_test_id":"TestFactorModeMatrix","violation_marker":"marker","pristine":{"id":"M-CRD06-01/pristine","exit_code":0,"go_test_event":{"package":"Picocrypt-NG/internal/pcv3credential","test_id":"TestFactorModeMatrix","terminal_action":"pass"},"timed_out":false},"application":{"id":"M-CRD06-01/application","exit_code":0,"timed_out":false},"mutant":{"id":"M-CRD06-01/mutant","exit_code":1,"go_test_event":{"package":"Picocrypt-NG/internal/pcv3credential","test_id":"TestFactorModeMatrix","terminal_action":"fail"},"timed_out":false},"application_receipt":{"schema_version":1,"mutation_id":"M-CRD06-01","baseline_commit":"1111111111111111111111111111111111111111","spec_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_set_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","source_path":"internal/pcv3credential/example.go","source_before_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","source_after_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","anchor_matches":1,"application_count":1,"killing_test_id":"TestFactorModeMatrix","expected_violation_marker":"marker","expected_pristine":{},"expected_mutant":{}}}`,
		), &mutation); err != nil {
			t.Fatalf("decode mutation producer fixture: %v", err)
		}
		data, err := canonicalJSON(mutation)
		if err != nil {
			t.Fatalf("encode mutation producer fixture: %v", err)
		}
		var mutationFields map[string]json.RawMessage
		if err := json.Unmarshal(data, &mutationFields); err != nil {
			t.Fatalf("decode encoded mutation producer evidence: %v", err)
		}
		if len(mutationFields["application_receipt"]) == 0 {
			t.Fatal("producer evidence omitted the validated mutation application receipt")
		}
		if mutation.Pristine.GoTestEvent == nil ||
			mutation.Pristine.GoTestEvent.TerminalAction != "pass" ||
			mutation.Mutant.GoTestEvent == nil ||
			mutation.Mutant.GoTestEvent.TerminalAction != "fail" ||
			mutation.Application.GoTestEvent != nil {
			t.Fatal("producer evidence misplaced a nested Go test event")
		}

		command := commandConfig{
			ID:   "normal-1-exact-profile",
			Kind: "go-test",
			ExecutionSurface: executionSurface{
				PackagePaths: []string{"./internal/pcv3credential"},
				BuildTags: []string{
					"migrated_fynedo",
					"pcv3_production_kdf",
				},
				TestSelector: "^TestProductionKDFExactProfiles$/^normal-1$",
				EvidenceKind: "go-test-json",
			},
			Argv: []string{
				"${GO}", "test",
				"-tags", "migrated_fynedo,pcv3_production_kdf",
				"-p", "1",
				"./internal/pcv3credential",
				"-run", "^TestProductionKDFExactProfiles$/^normal-1$",
				"-json",
			},
			CWD:                "${SOURCE}/src",
			TimeoutSeconds:     3900,
			GoBased:            true,
			MemoryHard:         true,
			PackageParallelism: float64(1),
			RequiredExitCode:   0,
			RequiredTestIDs: []string{
				"TestProductionKDFExactProfiles/normal-1",
			},
			RequiredTestPackages: map[string]string{
				"TestProductionKDFExactProfiles/normal-1": "Picocrypt-NG/internal/pcv3credential",
			},
		}
		replacements := map[string]string{
			"${GO}":     "/tool/go",
			"${SOURCE}": "/frozen/source",
		}
		validResult := func() commandResult {
			return commandResult{
				ID:       command.ID,
				Argv:     replaceSlice(command.Argv, replacements),
				CWD:      "/frozen/source/src",
				Contract: commandEvidenceFor(command),
				ExitCode: 0,
				TimedOut: false,
			}
		}
		if err := validateProducedCommandResult(
			command,
			validResult(),
			replacements,
		); err != nil {
			t.Fatalf("exact producer command record rejected: %v", err)
		}
		for name, corrupt := range map[string]func(*commandResult){
			"argv": func(value *commandResult) {
				value.Argv[0] = "/wrong/go"
			},
			"cwd": func(value *commandResult) {
				value.CWD = "/wrong/source"
			},
			"timeout": func(value *commandResult) {
				value.Contract.TimeoutSeconds++
			},
			"package": func(value *commandResult) {
				value.Contract.ExecutionSurface.PackagePaths[0] = "./wrong"
			},
			"tag": func(value *commandResult) {
				value.Contract.ExecutionSurface.BuildTags[0] = "wrong"
			},
			"selector": func(value *commandResult) {
				value.Contract.ExecutionSurface.TestSelector = "^wrong$"
			},
			"required package binding": func(value *commandResult) {
				value.Contract.RequiredTestPackages["TestProductionKDFExactProfiles/normal-1"] = "Picocrypt-NG/wrong"
			},
		} {
			t.Run("corrupt "+name, func(t *testing.T) {
				invalid := validResult()
				invalid.Argv = append([]string(nil), invalid.Argv...)
				invalid.Contract.ExecutionSurface.PackagePaths = append(
					[]string(nil),
					invalid.Contract.ExecutionSurface.PackagePaths...,
				)
				invalid.Contract.ExecutionSurface.BuildTags = append(
					[]string(nil),
					invalid.Contract.ExecutionSurface.BuildTags...,
				)
				invalid.Contract.RequiredTestPackages = cloneStringMap(
					invalid.Contract.RequiredTestPackages,
				)
				corrupt(&invalid)
				if err := validateProducedCommandResult(
					command,
					invalid,
					replacements,
				); err == nil {
					t.Fatal("corrupt producer command record accepted")
				}
			})
		}

		lintCommand := command
		lintCommand.ID = "host-lint-normal"
		lintCommand.Kind = "golangci-lint"
		lintCommand.LintRun = "lint-normal"
		lintResult := commandResult{
			ID:       lintCommand.ID,
			Argv:     replaceSlice(lintCommand.Argv, replacements),
			CWD:      "/frozen/source/src",
			Contract: commandEvidenceFor(lintCommand),
			ExitCode: 0,
			LintResult: &lintEvidenceResult{
				RunID:          "lint-normal",
				JSONSHA256:     strings.Repeat("a", 64),
				Issues:         []struct{}{},
				EnabledLinters: []string{"gosec"},
			},
		}
		if err := validateProducedCommandResult(
			lintCommand,
			lintResult,
			replacements,
		); err != nil {
			t.Fatalf("exact lint producer record rejected: %v", err)
		}
		lintResult.LintResult.Issues = []struct{}{{}}
		if err := validateProducedCommandResult(
			lintCommand,
			lintResult,
			replacements,
		); err == nil {
			t.Fatal("lint producer accepted a nonempty Issues array")
		}

		scanCommand := command
		scanCommand.ID = "host-gitleaks"
		scanCommand.Kind = "gitleaks"
		scanCommand.Argv = []string{
			"/tool/gitleaks",
			"detect",
			"--no-git",
			"--source",
			"${SOURCE}/src/internal/pcv3credential",
		}
		scanResult := commandResult{
			ID:       scanCommand.ID,
			Argv:     replaceSlice(scanCommand.Argv, replacements),
			CWD:      "/frozen/source/src",
			Contract: commandEvidenceFor(scanCommand),
			ExitCode: 0,
			ScanResult: &scanEvidenceResult{
				Scanner: "gitleaks",
				Target:  "/frozen/source/src/internal/pcv3credential",
			},
		}
		if err := validateProducedCommandResult(
			scanCommand,
			scanResult,
			replacements,
		); err != nil {
			t.Fatalf("exact scan producer record rejected: %v", err)
		}
		scanResult.ScanResult.Findings = 1
		if err := validateProducedCommandResult(
			scanCommand,
			scanResult,
			replacements,
		); err == nil {
			t.Fatal("scan producer accepted a nonzero finding count")
		}
	})
}

func TestExecutionSurfacesOverlapHierarchicalSelectors(t *testing.T) {
	parent := executionSurface{
		PackagePaths: []string{"./internal/pcv3credential"},
		BuildTags:    []string{"migrated_fynedo"},
		TestSelector: "^TestFoo$",
		EvidenceKind: "go-test-json",
	}
	child := parent
	child.TestSelector = "^TestFoo$/^bar$"
	if !executionSurfacesOverlap(parent, child) {
		t.Fatal("exact parent selector did not overlap its child selector")
	}

	sibling := parent
	sibling.TestSelector = "^TestFoo$/^baz$"
	if executionSurfacesOverlap(child, sibling) {
		t.Fatal("equal-depth sibling selectors were treated as overlapping")
	}
}

func TestFiniteGoTestSelectorBindsRequiredInventory(t *testing.T) {
	const selector = "^(TestFreezeIdentityBindsRunnerAndInspector|TestEvidenceReplacementIsDetected)$"
	command := commandConfig{
		ID:   "host-controller-tests",
		Kind: "go-test",
		ExecutionSurface: executionSurface{
			PackagePaths: []string{
				"./internal/pcv3credential/testdata/phasegates",
			},
			BuildTags:    []string{"migrated_fynedo"},
			TestSelector: selector,
			EvidenceKind: "go-test-json",
		},
		Argv: []string{
			"${GO}", "test",
			"-tags", "migrated_fynedo",
			"-p", "1",
			"./internal/pcv3credential/testdata/phasegates",
			"-run", selector,
			"-count=1",
			"-timeout=5m",
			"-json",
		},
		TimeoutSeconds: 360,
		GoBased:        true,
		RequiredTestIDs: []string{
			"TestFreezeIdentityBindsRunnerAndInspector",
			"TestEvidenceReplacementIsDetected",
		},
		RequiredTestPackages: map[string]string{
			"TestFreezeIdentityBindsRunnerAndInspector": pcv3PackagePath +
				"/testdata/phasegates",
			"TestEvidenceReplacementIsDetected": pcv3PackagePath +
				"/testdata/phasegates",
		},
	}
	if err := validateExecutionSurface(command, "0"); err != nil {
		t.Fatalf("exact finite controller selector rejected: %v", err)
	}

	command.RequiredTestIDs = command.RequiredTestIDs[:1]
	if err := validateExecutionSurface(command, "0"); err == nil {
		t.Fatal("finite selector selected a test outside the required evidence inventory")
	}
}

func TestReviewedGateRejectsExecutableGoTestArguments(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*commandConfig)
	}{
		{
			name: "wrong executable",
			mutate: func(command *commandConfig) {
				command.Argv[0] = "/bin/sh"
			},
		},
		{
			name: "go test exec hook",
			mutate: func(command *commandConfig) {
				command.Argv = append(
					append([]string(nil), command.Argv[:2]...),
					append(
						[]string{"-exec=/tmp/phase2-escape"},
						command.Argv[2:]...,
					)...,
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, _, err := loadGateConfig(
				filepath.Join("..", "gates.json"),
				reviewedGateConfigSHA,
			)
			if err != nil {
				t.Fatalf("load reviewed gate config: %v", err)
			}
			host := config.Stages["host"]
			commandFound := false
			for index := range host.Commands {
				if host.Commands[index].ID != "host-phase2-tests" {
					continue
				}
				test.mutate(&host.Commands[index])
				commandFound = true
				break
			}
			if !commandFound {
				t.Fatal("reviewed Phase-2 command is missing")
			}
			config.Stages["host"] = host

			if err := validateGateConfig(config); err == nil {
				t.Fatal("executable go-test argument passed producer validation")
			}
		})
	}
}

func TestRuntimeRejectsEmptyThreatClosureBeforeSideEffects(t *testing.T) {
	const wantError = "reviewed gate config requires a complete threat closure"

	t.Run("freeze identity", func(t *testing.T) {
		fixture := newGateFixture(t)
		fixture.writeSourceManifest(t)
		deps := fixture.deps()
		deps.validateConfig = defaultDeps().validateConfig

		_, err := freezeIdentity(fixture.freezeOptions, deps)
		if err == nil || err.Error() != wantError {
			t.Fatalf("empty-closure freeze error = %v; want %q", err, wantError)
		}
		if _, err := os.Lstat(fixture.identityPath); !os.IsNotExist(err) {
			t.Fatalf("rejected empty-closure freeze created identity: %v", err)
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
			if _, err := os.Lstat(filepath.Join(fixture.root, name)); !os.IsNotExist(err) {
				t.Fatalf("rejected empty-closure freeze created private root %s: %v", name, err)
			}
		}
	})

	t.Run("run stage", func(t *testing.T) {
		fixture := newGateFixture(t)
		_, hash := fixture.freeze(t)
		options := fixture.stageOptions("normal1", hash)
		deps := fixture.deps()
		deps.validateConfig = defaultDeps().validateConfig
		var subprocesses atomic.Int32
		deps.commandContext = func(
			ctx context.Context,
			name string,
			args ...string,
		) *exec.Cmd {
			subprocesses.Add(1)
			return exec.CommandContext(ctx, name, args...)
		}

		err := runStage(context.Background(), options, deps)
		if err == nil || err.Error() != wantError {
			t.Fatalf("empty-closure stage error = %v; want %q", err, wantError)
		}
		if subprocesses.Load() != 0 {
			t.Fatalf(
				"rejected empty-closure stage constructed %d subprocesses; want 0",
				subprocesses.Load(),
			)
		}
		for _, path := range []string{
			options.Evidence,
			options.Evidence + fixture.config.EvidenceContract.PublicationProofSuffix,
			stageTempDirectory(fixture.root, "normal1"),
		} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("rejected empty-closure stage created %s: %v", path, err)
			}
		}
	})
}

func TestReviewedGateRejectsBroadenedHostEvidence(t *testing.T) {
	const unexpectedTest = "TestUnexpectedControllerWork"
	extendControllerSelector := func(t *testing.T, command *commandConfig) {
		t.Helper()
		selector := command.ExecutionSurface.TestSelector
		if !strings.HasSuffix(selector, ")$") {
			t.Fatalf("reviewed controller selector is not a finite union: %q", selector)
		}
		selector = strings.TrimSuffix(selector, ")$") +
			"|" + unexpectedTest + ")$"
		command.ExecutionSurface.TestSelector = selector
		for index := range command.Argv {
			if command.Argv[index] == "-run" && index+1 < len(command.Argv) {
				command.Argv[index+1] = selector
				return
			}
		}
		t.Fatal("reviewed controller command has no selector argument")
	}
	for _, test := range []struct {
		name      string
		commandID string
		wantError string
		mutate    func(*testing.T, *commandConfig)
	}{
		{
			name:      "additional Phase-2 package",
			commandID: "host-phase2-tests",
			wantError: "host Phase-2 or controller test scope is not exact",
			mutate: func(t *testing.T, command *commandConfig) {
				t.Helper()
				command.ExecutionSurface.PackagePaths = append(
					command.ExecutionSurface.PackagePaths,
					"./internal/fileops",
				)
				for index, argument := range command.Argv {
					if argument != "./internal/pcv3credential" {
						continue
					}
					command.Argv = append(
						append([]string(nil), command.Argv[:index+1]...),
						append(
							[]string{"./internal/fileops"},
							command.Argv[index+1:]...,
						)...,
					)
					return
				}
				t.Fatal("reviewed Phase-2 command has no credential package argument")
			},
		},
		{
			name:      "additional auxiliary package",
			commandID: "host-fixture-schema",
			wantError: "host Phase-2 or controller test scope is not exact",
			mutate: func(t *testing.T, command *commandConfig) {
				t.Helper()
				command.ExecutionSurface.PackagePaths = append(
					command.ExecutionSurface.PackagePaths,
					"./internal/fileops",
				)
				for index, argument := range command.Argv {
					if argument !=
						"./internal/pcv3credential/testdata/mutator" {
						continue
					}
					command.Argv = append(
						append([]string(nil), command.Argv[:index+1]...),
						append(
							[]string{"./internal/fileops"},
							command.Argv[index+1:]...,
						)...,
					)
					return
				}
				t.Fatal("reviewed fixture command has no mutator package argument")
			},
		},
		{
			name:      "selector outside required inventory",
			commandID: "host-controller-tests",
			wantError: "command host-controller-tests execution surface: " +
				"go-test selector does not match the required evidence inventory",
			mutate: extendControllerSelector,
		},
		{
			name:      "controller test outside threat closure",
			commandID: "host-controller-tests",
			wantError: "test command evidence inventory exceeds its threat closure",
			mutate: func(t *testing.T, command *commandConfig) {
				t.Helper()
				extendControllerSelector(t, command)
				command.RequiredTestIDs = append(
					command.RequiredTestIDs,
					unexpectedTest,
				)
				command.RequiredTestPackages[unexpectedTest] = picocryptModulePath +
					"/internal/pcv3credential/testdata/phasegates"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, _, err := loadGateConfig(
				filepath.Join("..", "gates.json"),
				reviewedGateConfigSHA,
			)
			if err != nil {
				t.Fatalf("load reviewed gate config: %v", err)
			}
			host := config.Stages["host"]
			commandFound := false
			for index := range host.Commands {
				if host.Commands[index].ID != test.commandID {
					continue
				}
				test.mutate(t, &host.Commands[index])
				commandFound = true
				break
			}
			if !commandFound {
				t.Fatalf("reviewed host command %q is missing", test.commandID)
			}
			config.Stages["host"] = host

			err = validateGateConfig(config)
			if err == nil || err.Error() != test.wantError {
				t.Fatalf(
					"broadened host evidence error = %v; want %q",
					err,
					test.wantError,
				)
			}
		})
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

// Kills production mutation: iterating manifest rows instead of RequiredMutationIDs.
func TestMutationCampaignAttemptsConfiguredOrderBeforeManifestOrder(t *testing.T) {
	const (
		configuredFirst = "M-CRD07-KEYFILE-MODE-OFFSET-2"
		manifestFirst   = "M-CRD07-SELECTED-FACTOR-REMOVAL"
	)
	var tracked campaignManifest
	if err := decodeStrictFile(filepath.Join("..", "mutations.json"), &tracked); err != nil {
		t.Fatalf("decode tracked mutation manifest: %v", err)
	}
	byID := make(map[string]campaignMutation, len(tracked.Mutations))
	for _, mutation := range tracked.Mutations {
		byID[mutation.ID] = mutation
	}
	firstManifestMutation, ok := byID[manifestFirst]
	if !ok {
		t.Fatalf("tracked manifest lacks controlled mutation %s", manifestFirst)
	}
	firstConfiguredMutation, ok := byID[configuredFirst]
	if !ok {
		t.Fatalf("tracked manifest lacks controlled mutation %s", configuredFirst)
	}
	manifest := tracked
	manifest.Mutations = []campaignMutation{
		firstManifestMutation,
		firstConfiguredMutation,
	}
	manifest.SourceSetSHA256 = campaignSourceSetHash(manifest.Mutations)

	root := t.TempDir()
	source := filepath.Join(root, "archive")
	moduleRoot := phasegatesTestModuleRoot(t)
	writtenSources := map[string]bool{}
	for _, mutation := range manifest.Mutations {
		if writtenSources[mutation.SourcePath] {
			continue
		}
		sourceBytes, err := os.ReadFile(filepath.Join(moduleRoot, mutation.SourcePath))
		if err != nil {
			t.Fatalf("read controlled mutation source %s: %v", mutation.SourcePath, err)
		}
		if sha256Hex(sourceBytes) != mutation.SourceSHA256 {
			t.Fatalf("tracked source identity drifted for %s", mutation.SourcePath)
		}
		target := filepath.Join(source, "src", mutation.SourcePath)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatalf("create controlled mutation source parent: %v", err)
		}
		if err := os.WriteFile(target, sourceBytes, 0o600); err != nil {
			t.Fatalf("write controlled mutation source: %v", err)
		}
		writtenSources[mutation.SourcePath] = true
	}

	manifestPath := filepath.Join(root, "mutations.json")
	manifestData, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatalf("encode controlled mutation manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatalf("write controlled mutation manifest: %v", err)
	}
	stageTemp := filepath.Join(root, "stage")
	if err := os.Mkdir(stageTemp, 0o700); err != nil {
		t.Fatalf("create controlled stage temp: %v", err)
	}
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve controlled child executable: %v", err)
	}
	var starts atomic.Int32
	deps := defaultDeps()
	deps.commandContext = func(
		ctx context.Context,
		_ string,
		_ ...string,
	) *exec.Cmd {
		starts.Add(1)
		return exec.CommandContext(
			ctx,
			testExecutable,
			"-test.run=^TestPhasegatesHelperProcess$",
			"--",
			"fail",
			"controlled pristine failure",
		)
	}
	result, err := runMutationCampaign(
		context.Background(),
		commandConfig{ID: "mutation-campaign"},
		&gateConfig{
			RequiredMutationIDs: []string{configuredFirst, manifestFirst},
		},
		executionIdentity{
			Baseline: testBaseline,
			Source: directoryIdentity{
				Path: source,
			},
			Spec: fileIdentity{
				SHA256: manifest.SpecSHA256,
			},
			Mutations: fileIdentity{
				Path: manifestPath,
			},
			Executables: map[string]executableIdentity{
				"${GO}": {
					File: fileIdentity{Path: "/frozen/go"},
				},
			},
			Environment: map[string][]string{
				"mutation": {"GOMAXPROCS=1"},
			},
		},
		map[string]string{
			"${STAGE}":        "mutation",
			"${STAGE_TMPDIR}": stageTemp,
		},
		deps,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"mutation "+configuredFirst+" pristine test",
		) {
		t.Errorf("first controlled mutation error = %v; want configured-first failure", err)
	}
	if starts.Load() != 1 {
		t.Errorf("controlled mutation child starts = %d; want exactly 1", starts.Load())
	}
	if len(result.Mutations) != 1 ||
		result.Mutations[0].ID != configuredFirst {
		t.Errorf("first mutation result = %+v; want only %s",
			result.Mutations, configuredFirst)
	}
}

// Kills binding a tracked mutation to a parent test instead of the exact
// marker-owning top-level test event.
func TestTrackedMutationKillingTestsProduceExactEvents(t *testing.T) {
	type trackedMutation struct {
		id     string
		testID string
		marker string
	}
	required := []trackedMutation{
		{
			id:     "M-CRD08-KDF-RETURN-CLEANUP-REMOVAL",
			testID: "TestKDFReturnedSliceCleanupMutation",
			marker: "KDF runner did not clear the exact returned slice",
		},
		{
			id:     "M-CRD09-INDEPENDENT-INFO-REMOVAL",
			testID: "TestScheduleIndependentExpandMutation",
			marker: "reused Info",
		},
		{
			id:     "M-CRD07-RAW-NFD-FALLBACK",
			testID: "TestCanonicalTranscriptRawNFDFallbackMutation",
			marker: "raw/decomposed legacy transcript became reachable",
		},
		{
			id:     "M-CRD07-XOR-FALLBACK",
			testID: "TestCanonicalTranscriptXORFallbackMutation",
			marker: "legacy XOR transcript became reachable",
		},
		{
			id:     "M-CRD09-PREEXPAND-VALIDATION-REMOVAL",
			testID: "TestPipelinePreExpandScheduleValidationMutation",
			marker: "schedule rejection published an owner",
		},
		{
			id:     "M-CRD06-FIXED-PROFILE-WEAKENING",
			testID: "TestKDFFixedProfileWeakeningMutation",
			marker: "admission/KDF calls/profiles",
		},
		{
			id:     "M-CRD08-POSTKDF-CANCEL-CHECK-REMOVAL",
			testID: "TestKDFPostCallCancellationMutation",
			marker: "post-call cancellation published a credential root",
		},
	}

	var tracked campaignManifest
	if err := decodeStrictFile(filepath.Join("..", "mutations.json"), &tracked); err != nil {
		t.Fatalf("strict-decode tracked mutation manifest: %v", err)
	}
	byID := make(map[string]campaignMutation, len(tracked.Mutations))
	for _, mutation := range tracked.Mutations {
		byID[mutation.ID] = mutation
	}
	manifest := tracked
	manifest.Mutations = make([]campaignMutation, 0, len(required))
	requiredIDs := make([]string, 0, len(required))
	for _, want := range required {
		mutation, ok := byID[want.id]
		if !ok {
			t.Fatalf("tracked manifest lacks required mutation %s", want.id)
		}
		manifest.Mutations = append(manifest.Mutations, mutation)
		requiredIDs = append(requiredIDs, want.id)
	}
	manifest.SourceSetSHA256 = campaignSourceSetHash(manifest.Mutations)

	root := t.TempDir()
	source := filepath.Join(root, "archive")
	moduleRoot := phasegatesTestModuleRoot(t)
	if err := os.CopyFS(filepath.Join(source, "src"), os.DirFS(moduleRoot)); err != nil {
		t.Fatalf("copy actual src module into frozen-source fixture: %v", err)
	}
	manifestPath := filepath.Join(root, "mutations.json")
	manifestData, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatalf("encode controlled mutation manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatalf("write controlled mutation manifest: %v", err)
	}
	stageTemp := filepath.Join(root, "stage")
	tmpDirectory := filepath.Join(root, "tmp")
	for _, directory := range []string{stageTemp, tmpDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create controlled mutation workspace: %v", err)
		}
	}

	if runtime.Version() != "go1.26.5" {
		t.Fatalf("tracked mutation campaign uses %s; want go1.26.5", runtime.Version())
	}
	goExecutable := testGoExecutable(t)
	moduleCache := os.Getenv("GOMODCACHE")
	if moduleCache == "" {
		userHome, homeErr := os.UserHomeDir()
		if homeErr != nil {
			t.Fatalf("resolve populated Go module cache: %v", homeErr)
		}
		moduleCache = filepath.Join(userHome, "go", "pkg", "mod")
	}
	if info, statErr := os.Lstat(moduleCache); statErr != nil || !info.IsDir() {
		t.Fatalf("populated Go module cache is unavailable: %v", statErr)
	}
	environment := []string{
		"CGO_ENABLED=0",
		"GOCACHE=" + filepath.Join(root, "go-cache"),
		"GOENV=off",
		"GOFLAGS=-mod=readonly",
		"GOMAXPROCS=1",
		"GOMODCACHE=" + moduleCache,
		"GOPATH=" + filepath.Join(root, "go-path"),
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"HOME=" + root,
		"PATH=" + filepath.Dir(goExecutable),
		"TMPDIR=" + tmpDirectory,
	}
	campaignContext, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	result, err := runMutationCampaign(
		campaignContext,
		commandConfig{ID: "mutation-campaign"},
		&gateConfig{RequiredMutationIDs: requiredIDs},
		executionIdentity{
			Baseline: testBaseline,
			Source:   directoryIdentity{Path: source},
			Spec:     fileIdentity{SHA256: manifest.SpecSHA256},
			Mutations: fileIdentity{
				Path: manifestPath,
			},
			Executables: map[string]executableIdentity{
				"${GO}": {File: fileIdentity{Path: goExecutable}},
			},
			Environment: map[string][]string{"mutation": environment},
		},
		map[string]string{
			"${STAGE}":        "mutation",
			"${STAGE_TMPDIR}": stageTemp,
		},
		defaultDeps(),
	)
	if err != nil {
		t.Fatalf("run tracked mutation campaign: %v", err)
	}
	if result.ExitCode != 0 || !equalStrings(result.ObservedIDs, requiredIDs) {
		t.Fatalf(
			"tracked campaign result = exit %d, observed %v; want exit 0, observed %v",
			result.ExitCode,
			result.ObservedIDs,
			requiredIDs,
		)
	}
	if len(result.Mutations) != len(required) {
		t.Fatalf("tracked campaign mutation count = %d; want %d",
			len(result.Mutations), len(required))
	}
	for index, want := range required {
		got := result.Mutations[index]
		pristineEvent := goTestEventAttestation{
			Package:        pcv3PackagePath,
			TestID:         want.testID,
			TerminalAction: "pass",
		}
		mutantEvent := pristineEvent
		mutantEvent.TerminalAction = "fail"
		if got.ID != want.id ||
			got.KillingTestID != want.testID ||
			got.ViolationMarker != want.marker ||
			got.Pristine.ExitCode != 0 ||
			got.Pristine.TimedOut ||
			got.Pristine.GoTestEvent == nil ||
			*got.Pristine.GoTestEvent != pristineEvent ||
			got.Application.ExitCode != 0 ||
			got.Application.TimedOut ||
			got.Mutant.ExitCode != 1 ||
			got.Mutant.TimedOut ||
			got.Mutant.GoTestEvent == nil ||
			*got.Mutant.GoTestEvent != mutantEvent ||
			got.ApplicationReceipt.MutationID != want.id ||
			got.ApplicationReceipt.KillingTestID != want.testID ||
			got.ApplicationReceipt.ViolationMarker != want.marker {
			t.Fatalf("tracked mutation %s lacks exact event attestations: %+v", want.id, got)
		}
	}
}

// Kills production mutation: accepting an exit-zero pristine skip as execution.
func TestMutationCampaignRejectsSkippedPristineBeforeApplication(t *testing.T) {
	const (
		mutationID = "M-CRD01-PRISTINE-SKIP"
		testID     = "TestPristineSkip"
		sourcePath = "internal/pcv3credential/value.go"
		marker     = "controlled mutation violation"
	)
	root := t.TempDir()
	source := filepath.Join(root, "archive")
	moduleRoot := filepath.Join(source, "src")
	packageRoot := filepath.Join(moduleRoot, "internal", "pcv3credential")
	for _, directory := range []string{
		packageRoot,
		filepath.Join(root, "stage"),
		filepath.Join(root, "tmp"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("create pristine-skip fixture directory: %v", err)
		}
	}
	sourceData := []byte("package pcv3credential\n\nconst mutationValue = 1\n")
	for path, data := range map[string][]byte{
		filepath.Join(moduleRoot, "go.mod"): []byte(
			"module Picocrypt-NG\n\ngo 1.26.5\n",
		),
		filepath.Join(packageRoot, "value.go"): sourceData,
		filepath.Join(packageRoot, "value_test.go"): []byte(
			"package pcv3credential\n\n" +
				"import \"testing\"\n\n" +
				"func TestPristineSkip(t *testing.T) {\n" +
				"\tt.Skip(\"controlled pristine skip\")\n" +
				"}\n",
		),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write pristine-skip fixture: %v", err)
		}
	}
	outcome := func(status, violationMarker string) campaignOutcome {
		return campaignOutcome{
			Status:          status,
			Execution:       "semantic",
			SemanticCommand: []string{"go", "test", "./internal/pcv3credential", "-run", "^" + testID + "$", "-count=1"},
			TestID:          testID,
			ViolationMarker: violationMarker,
			Stage:           "fixture",
			Reason:          "controlled fixture",
		}
	}
	manifest := campaignManifest{
		SchemaVersion: gateSchemaVersion,
		SpecSHA256:    strings.Repeat("a", 64),
		ArgvTemplate:  append([]string(nil), campaignArgvTemplate...),
		Mutations: []campaignMutation{{
			ID:              mutationID,
			Requirement:     "CRD-01",
			Invariant:       "the pristine killing test executes",
			SourcePath:      sourcePath,
			SourceSHA256:    sha256Hex(sourceData),
			Anchor:          "const mutationValue = 1",
			Replacement:     "const mutationValue = 2",
			KillingTestID:   testID,
			ViolationMarker: marker,
			Pristine:        outcome("PASS", ""),
			Mutant:          outcome("FAIL", marker),
		}},
	}
	manifest.SourceSetSHA256 = campaignSourceSetHash(manifest.Mutations)
	manifestPath := filepath.Join(root, "mutations.json")
	manifestData, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatalf("encode pristine-skip mutation manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatalf("write pristine-skip mutation manifest: %v", err)
	}
	goExecutable := testGoExecutable(t)
	environment := []string{
		"CGO_ENABLED=0",
		"GOCACHE=" + filepath.Join(root, "go-cache"),
		"GOENV=off",
		"GOMAXPROCS=1",
		"GOMODCACHE=" + filepath.Join(root, "go-mod-cache"),
		"GOPATH=" + filepath.Join(root, "go-path"),
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"HOME=" + root,
		"PATH=" + filepath.Dir(goExecutable),
		"TMPDIR=" + filepath.Join(root, "tmp"),
	}
	result, err := runMutationCampaign(
		context.Background(),
		commandConfig{ID: "mutation-campaign"},
		&gateConfig{RequiredMutationIDs: []string{mutationID}},
		executionIdentity{
			Baseline: testBaseline,
			Source:   directoryIdentity{Path: source},
			Spec:     fileIdentity{SHA256: manifest.SpecSHA256},
			Mutations: fileIdentity{
				Path: manifestPath,
			},
			Executables: map[string]executableIdentity{
				"${GO}": {File: fileIdentity{Path: goExecutable}},
			},
			Environment: map[string][]string{"mutation": environment},
		},
		map[string]string{
			"${STAGE}":        "mutation",
			"${STAGE_TMPDIR}": filepath.Join(root, "stage"),
		},
		defaultDeps(),
	)
	if err == nil {
		t.Fatal("pristine skip advanced through the mutation campaign")
	}
	if strings.Contains(err.Error(), "apply mutation "+mutationID) {
		t.Fatalf(
			"pristine skip advanced to mutation application: %v; want mutation %s pristine test rejection",
			err,
			mutationID,
		)
	}
	if !strings.Contains(err.Error(), "mutation "+mutationID+" pristine test") {
		t.Fatalf("pristine skip error = %v; want pristine-owned rejection", err)
	}
	if len(result.Mutations) != 1 ||
		result.Mutations[0].Application.ID != "" {
		t.Fatalf("pristine skip recorded mutation application: %+v", result.Mutations)
	}
}

// Kills production mutations: collapsing or accepting invalid exact events.
func TestNestedGoTestJSONRejectsInvalidExactEvents(t *testing.T) {
	const (
		packagePath = "Picocrypt-NG/internal/pcv3credential"
		testID      = "TestKilling"
		marker      = "controlled violation"
	)
	event := func(action, output string) string {
		data, err := json.Marshal(map[string]string{
			"Action":  action,
			"Package": packagePath,
			"Test":    testID,
			"Output":  output,
		})
		if err != nil {
			t.Fatalf("encode duplicate-event fixture: %v", err)
		}
		return string(data)
	}
	for _, test := range []struct {
		name           string
		terminalAction string
		requiredMarker string
		events         []string
	}{
		{
			name:           "duplicate run",
			terminalAction: "fail",
			requiredMarker: marker,
			events: []string{
				event("run", ""),
				event("run", ""),
				event("output", marker),
				event("fail", ""),
			},
		},
		{
			name:           "duplicate fail",
			terminalAction: "fail",
			requiredMarker: marker,
			events: []string{
				event("run", ""),
				event("output", marker),
				event("fail", ""),
				event("fail", ""),
			},
		},
		{
			name:           "duplicate pass",
			terminalAction: "pass",
			events: []string{
				event("run", ""),
				event("pass", ""),
				event("pass", ""),
			},
		},
		{
			name:           "pristine fail",
			terminalAction: "pass",
			events: []string{
				event("run", ""),
				event("fail", ""),
			},
		},
		{
			name:           "pristine skip",
			terminalAction: "pass",
			events: []string{
				event("run", ""),
				event("skip", ""),
			},
		},
		{
			name:           "mutant pass",
			terminalAction: "fail",
			requiredMarker: marker,
			events: []string{
				event("run", ""),
				event("output", marker),
				event("pass", ""),
			},
		},
		{
			name:           "mutant skip",
			terminalAction: "fail",
			requiredMarker: marker,
			events: []string{
				event("run", ""),
				event("output", marker),
				event("skip", ""),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseNestedGoTestJSON(
				[]byte(strings.Join(test.events, "\n")+"\n"),
				goTestEventAttestation{
					Package:        packagePath,
					TestID:         testID,
					TerminalAction: test.terminalAction,
				},
				test.requiredMarker,
			)
			if err == nil {
				t.Fatalf("%s events were accepted", test.name)
			}
		})
	}
}

// Kills allowing an exact parent event to borrow a violation marker emitted by
// a child or unrelated sibling test event.
func TestNestedGoTestJSONDoesNotBorrowChildOrSiblingMarker(t *testing.T) {
	const (
		packagePath = "Picocrypt-NG/internal/pcv3credential"
		parentID    = "TestKilling"
		childID     = "TestKilling/child"
		siblingID   = "TestSibling"
		marker      = "controlled violation"
	)
	event := func(action, testID, output string) string {
		data, err := json.Marshal(map[string]string{
			"Action":  action,
			"Package": packagePath,
			"Test":    testID,
			"Output":  output,
		})
		if err != nil {
			t.Fatalf("encode nested-event fixture: %v", err)
		}
		return string(data)
	}
	events := []string{
		event("run", parentID, ""),
		event("run", childID, ""),
		event("output", childID, marker),
		event("run", siblingID, ""),
		event("output", siblingID, marker),
		event("fail", siblingID, ""),
		event("fail", childID, ""),
		event("fail", parentID, ""),
	}
	_, err := parseNestedGoTestJSON(
		[]byte(strings.Join(events, "\n")+"\n"),
		goTestEventAttestation{
			Package:        packagePath,
			TestID:         parentID,
			TerminalAction: "fail",
		},
		marker,
	)
	if err == nil ||
		err.Error() != "mutant output lacks the exact failing test and violation marker" {
		t.Fatalf("parent marker borrowing error = %v; want exact rejection", err)
	}
}

func TestNestedGoTestJSONAttestsExactTerminalEvent(t *testing.T) {
	const (
		packagePath = "Picocrypt-NG/internal/pcv3credential"
		testID      = "TestKilling"
		marker      = "controlled violation"
	)
	for _, terminalAction := range []string{"pass", "fail"} {
		t.Run(terminalAction, func(t *testing.T) {
			expected := goTestEventAttestation{
				Package:        packagePath,
				TestID:         testID,
				TerminalAction: terminalAction,
			}
			events := fmt.Sprintf(
				"{\"Action\":\"run\",\"Package\":%q,\"Test\":%q}\n"+
					"{\"Action\":\"output\",\"Package\":%q,\"Test\":%q,\"Output\":%q}\n"+
					"{\"Action\":%q,\"Package\":%q,\"Test\":%q}\n",
				packagePath,
				testID,
				packagePath,
				testID,
				marker,
				terminalAction,
				packagePath,
				testID,
			)
			requiredMarker := ""
			if terminalAction == "fail" {
				requiredMarker = marker
			}
			got, err := parseNestedGoTestJSON(
				[]byte(events),
				expected,
				requiredMarker,
			)
			if err != nil {
				t.Fatalf("parse exact %s events: %v", terminalAction, err)
			}
			if got != expected {
				t.Fatalf("exact %s attestation = %+v; want %+v",
					terminalAction, got, expected)
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
		defaultDeps().syncDirectory,
	); err == nil {
		t.Fatal("evidence replacement was not detected")
	}
}

func TestStageRejectsEveryRuntimeSkip(t *testing.T) {
	const (
		testID      = "TestFactorModeMatrix"
		packagePath = "Picocrypt-NG/internal/pcv3credential"
	)
	fixture := newGateFixture(t)
	command := fixture.helperCommand(
		t,
		"go-json-skip",
		packagePath,
		testID,
		"-p",
		"1",
	)
	command.Kind = "go-test"
	command.GoBased = true
	command.PackageParallelism = 1
	command.ExecutionSurface = executionSurface{
		PackagePaths: []string{"./internal/pcv3credential"},
		TestSelector: "^" + testID + "$",
		EvidenceKind: "go-test-json",
	}
	command.RequiredTestIDs = []string{testID}
	command.RequiredTestPackages = map[string]string{testID: packagePath}
	fixture.setCommand("normal1", command)
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("normal1", hash)
	deps := fixture.deps()
	var subprocesses atomic.Int32
	deps.commandContext = func(
		ctx context.Context,
		name string,
		args ...string,
	) *exec.Cmd {
		subprocesses.Add(1)
		return exec.CommandContext(ctx, name, args...)
	}

	err := runStage(context.Background(), options, deps)
	const wantError = "go test reported forbidden skip events"
	if err == nil || err.Error() != wantError {
		t.Fatalf("runtime skip error = %v; want %q", err, wantError)
	}
	if subprocesses.Load() != 1 {
		t.Fatalf(
			"runtime skip stage constructed %d subprocesses; want exactly 1",
			subprocesses.Load(),
		)
	}
	evidence := readEvidence(t, options.Evidence)
	if evidence.Status != "FAIL" ||
		evidence.Failure != wantError ||
		len(evidence.Commands) != 1 ||
		len(evidence.Commands[0].SkipEvents) != 1 ||
		len(evidence.SkipEvents) != 1 ||
		evidence.SkipEvents[0].Test != "TestUnexpectedRuntimeSkip" {
		t.Fatalf("runtime skip did not produce bound terminal failure: %+v", evidence)
	}
	proof := options.Evidence +
		fixture.config.EvidenceContract.PublicationProofSuffix
	if _, err := os.Lstat(proof); !os.IsNotExist(err) {
		t.Fatalf("runtime skip failure published a PASS proof: %v", err)
	}
}

func TestStageRecordsBoundedGoTestFailureSummary(t *testing.T) {
	const (
		testID      = "TestManifestRootResolution"
		packagePath = "Picocrypt-NG/internal/pcv3credential/testdata/mutator"
	)
	testCases := []struct {
		name               string
		helperMode         string
		classification     string
		truncated          bool
		failureIDCount     int
		requireExpectedID  bool
		forbiddenFailureID string
	}{
		{
			name:              "bounded sorted top-level IDs",
			helperMode:        "go-json-fail",
			classification:    "test",
			truncated:         true,
			failureIDCount:    expectedGoTestFailureIDs,
			requireExpectedID: true,
		},
		{
			name:               "oversized ID is redacted",
			helperMode:         "go-json-fail-oversized",
			classification:     "unclassified",
			failureIDCount:     0,
			forbiddenFailureID: oversizedGoTestFailureID(),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newGateFixture(t)
			command := fixture.helperCommand(
				t,
				testCase.helperMode,
				packagePath,
				testID,
				"-p",
				"1",
			)
			command.Kind = "go-test"
			command.GoBased = true
			command.PackageParallelism = 1
			command.ExecutionSurface = executionSurface{
				PackagePaths: []string{"./internal/pcv3credential/testdata/mutator"},
				TestSelector: "^" + testID + "$",
				EvidenceKind: "go-test-json",
			}
			command.RequiredTestIDs = []string{testID}
			command.RequiredTestPackages = map[string]string{testID: packagePath}
			fixture.setCommand("normal1", command)
			_, hash := fixture.freeze(t)
			options := fixture.stageOptions("normal1", hash)

			if err := runStage(context.Background(), options, fixture.deps()); err == nil {
				t.Fatal("failing Go test stage unexpectedly passed")
			}
			evidenceBytes, err := os.ReadFile(options.Evidence)
			if err != nil {
				t.Fatalf("read terminal Go test failure evidence: %v", err)
			}
			if bytes.Contains(evidenceBytes, []byte(goTestFailureOutputSecret)) {
				t.Fatal("raw Go test failure output leaked into terminal evidence")
			}
			if testCase.forbiddenFailureID != "" &&
				bytes.Contains(evidenceBytes, []byte(testCase.forbiddenFailureID)) {
				t.Fatal("oversized Go test failure ID leaked into terminal evidence")
			}
			var evidence stageEvidence
			if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
				t.Fatalf("decode terminal Go test failure evidence: %v", err)
			}
			if evidence.Status != "FAIL" || len(evidence.Commands) != 1 ||
				evidence.Commands[0].GoTestFailure == nil {
				t.Fatalf("Go test failure summary is absent from terminal evidence: %+v", evidence)
			}
			summary := evidence.Commands[0].GoTestFailure
			if summary.Classification != testCase.classification ||
				summary.Truncated != testCase.truncated ||
				len(summary.TopLevelTestIDs) != testCase.failureIDCount ||
				len(evidence.Commands[0].ObservedIDs) != 0 ||
				len(evidence.Commands[0].ClosedThreatIDs) != 0 {
				t.Fatalf("Go test failure summary is not safe terminal evidence: %+v", evidence)
			}
			if testCase.requireExpectedID &&
				!contains(summary.TopLevelTestIDs, testID) {
				t.Fatalf("expected failing test ID is absent from summary: %+v", summary)
			}
			if !sort.StringsAreSorted(summary.TopLevelTestIDs) {
				t.Fatalf("Go test failure IDs are not sorted: %v", summary.TopLevelTestIDs)
			}
			for _, id := range summary.TopLevelTestIDs {
				if strings.Contains(id, "/") {
					t.Fatalf("subtest ID entered bounded failure summary: %q", id)
				}
			}
			proof := options.Evidence +
				fixture.config.EvidenceContract.PublicationProofSuffix
			if _, err := os.Lstat(proof); !os.IsNotExist(err) {
				t.Fatalf("failed Go test stage published a PASS proof: %v", err)
			}
		})
	}
}

func TestStageBoundsChildOutput(t *testing.T) {
	fixture := newGateFixture(t)
	fixture.setCommand("normal1", fixture.helperCommand(t, "flood"))
	_, hash := fixture.freeze(t)
	options := fixture.stageOptions("normal1", hash)

	err := runStage(context.Background(), options, fixture.deps())
	if !errors.Is(err, errOutputLimit) {
		t.Fatalf("oversize child output error = %v; want output-limit failure", err)
	}
	evidenceBytes, readErr := os.ReadFile(options.Evidence)
	if readErr != nil {
		t.Fatalf("read terminal overflow evidence: %v", readErr)
	}
	var evidence stageEvidence
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("decode terminal overflow evidence: %v", err)
	}
	if evidence.Status != "FAIL" ||
		evidence.Failure != errOutputLimit.Error() ||
		len(evidence.Commands) != 1 {
		t.Fatalf("overflow did not produce bounded terminal failure: %+v", evidence)
	}
	if bytes.Contains(evidenceBytes, []byte("forbidden-child-payload")) {
		t.Fatal("raw child output leaked into terminal evidence")
	}
	proof := options.Evidence +
		fixture.config.EvidenceContract.PublicationProofSuffix
	if _, err := os.Lstat(proof); !os.IsNotExist(err) {
		t.Fatalf("overflow failure published a PASS proof: %v", err)
	}
}

func TestGoTestJSONRejectsEverySkipAndRequiresPass(t *testing.T) {
	const (
		testID      = "TestFactorModeMatrix"
		packagePath = "Picocrypt-NG/internal/pcv3credential"
	)
	requiredPackages := map[string]string{testID: packagePath}
	passing := strings.Join([]string{
		`{"Action":"run","Package":"` + packagePath + `","Test":"` + testID + `"}`,
		`{"Action":"pass","Package":"` + packagePath + `","Test":"` + testID + `"}`,
	}, "\n")
	observed, skips, err := parseGoTestJSON(
		[]byte(passing),
		[]string{testID},
		requiredPackages,
	)
	if err != nil || !equalStrings(observed, []string{testID}) ||
		len(skips) != 0 {
		t.Fatalf("required PASS rejected: observed=%v skips=%v err=%v", observed, skips, err)
	}

	for name, changed := range map[string]string{
		"required test skipped": strings.Replace(
			passing,
			`"Action":"pass"`,
			`"Action":"skip"`,
			1,
		),
		"unrelated test skipped": passing + "\n" +
			`{"Action":"skip","Package":"` + packagePath +
			`","Test":"TestUnrelated"}`,
		"package skipped": passing + "\n" +
			`{"Action":"skip","Package":"` + packagePath + `"}`,
		"wrong package": strings.ReplaceAll(
			passing,
			packagePath,
			"other/package",
		),
		"selected test also passes in wrong package": passing + "\n" +
			`{"Action":"pass","Package":"other/package","Test":"` + testID + `"}`,
		"duplicate selected test pass": passing + "\n" +
			`{"Action":"pass","Package":"` + packagePath +
			`","Test":"` + testID + `"}`,
		"package pass only": `{"Action":"pass","Package":"` + packagePath + `"}`,
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
	if rootHelp.String() !=
		"phasegates cpu-facts\nphasegates freeze-identity\nphasegates stage\n" {
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
	case "flood":
		if len(args) != 1 {
			t.Fatal("flood helper does not accept arguments")
		}
		payload := append(
			[]byte("forbidden-child-payload:"),
			bytes.Repeat([]byte{'x'}, maxCommandOutputBytes+1)...,
		)
		if _, err := os.Stdout.Write(payload); err != nil {
			t.Fatalf("write oversize child output: %v", err)
		}
	case "go-json-skip":
		if len(args) != 5 || args[3] != "-p" || args[4] != "1" {
			t.Fatal("go-json-skip helper requires package, test ID, and serial marker")
		}
		encoder := json.NewEncoder(os.Stdout)
		for _, event := range []struct {
			Action  string `json:"Action"`
			Package string `json:"Package"`
			Test    string `json:"Test"`
			Output  string `json:"Output,omitempty"`
		}{
			{Action: "run", Package: args[1], Test: args[2]},
			{Action: "pass", Package: args[1], Test: args[2]},
			{
				Action:  "skip",
				Package: args[1],
				Test:    "TestUnexpectedRuntimeSkip",
				Output:  "simulated forbidden runtime skip\n",
			},
		} {
			if err := encoder.Encode(event); err != nil {
				t.Fatalf("encode go-json-skip event: %v", err)
			}
		}
		os.Exit(0)
	case "go-json-fail", "go-json-fail-oversized":
		if len(args) != 5 || args[3] != "-p" || args[4] != "1" {
			t.Fatal("Go JSON failure helper requires package, test ID, and serial marker")
		}
		encoder := json.NewEncoder(os.Stdout)
		type goTestEvent struct {
			Action  string `json:"Action"`
			Package string `json:"Package"`
			Test    string `json:"Test,omitempty"`
			Output  string `json:"Output,omitempty"`
		}
		events := []goTestEvent{
			{Action: "run", Package: args[1], Test: args[2]},
			{Action: "fail", Package: args[1], Test: args[2] + "/case", Output: goTestFailureOutputSecret},
			{Action: "fail", Package: args[1], Test: args[2], Output: goTestFailureOutputSecret},
			{Action: "fail", Package: args[1], Output: goTestFailureOutputSecret},
		}
		if args[0] == "go-json-fail" {
			for index := range expectedGoTestFailureIDs {
				events = append(events, goTestEvent{
					Action:  "fail",
					Package: args[1],
					Test:    fmt.Sprintf("TestZDiagnosticFailure%02d", index),
					Output:  goTestFailureOutputSecret,
				})
			}
		} else {
			events = append(events, goTestEvent{
				Action:  "fail",
				Package: args[1],
				Test:    oversizedGoTestFailureID(),
				Output:  goTestFailureOutputSecret,
			})
		}
		for _, event := range events {
			if err := encoder.Encode(event); err != nil {
				t.Fatalf("encode go-json-fail event: %v", err)
			}
		}
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
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("make gate fixture root private: %v", err)
	}
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
		SkipAllowlist:          []skipRule{},
		SkipRuntimeCardinality: skipCardinality{},
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
			SchemaVersion:      1,
			TerminalStatuses:   []string{"PASS", "FAIL"},
			RequiredStageNames: []string{"mutation", "normal1", "paranoid1", "host"},
			StageFilenames: map[string]string{
				"mutation":  "mutation.evidence.json",
				"normal1":   "normal1.evidence.json",
				"paranoid1": "paranoid1.evidence.json",
				"host":      "host.evidence.json",
			},
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
	deps.validateConfig = validateGateConfigStructure
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
		Evidence: filepath.Join(
			fixture.root,
			fixture.config.EvidenceContract.StageFilenames[stage],
		),
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
