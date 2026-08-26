package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"Picocrypt-NG/internal/pcv3corpus"
)

func TestD1MutationPlanIsPrivateAndBounded(t *testing.T) {
	environment, job := newD1RunnerFixture(t)
	var commands [][]string
	runner := func(_ string, command []string, timeout time.Duration) d1CommandResult {
		if timeout != 90*time.Second {
			t.Fatalf("D1 command timeout = %s; want tracked 90s deadline", timeout)
		}
		commands = append(commands, append([]string(nil), command...))
		testName := job.contract.TestName()
		switch len(commands) {
		case 1:
			return d1CommandResult{output: d1TestEvents(testName, "pass", "")}
		case 2:
			return d1CommandResult{}
		default:
			return d1CommandResult{
				output: d1TestEvents(testName, "fail", job.contract.AssertionMarker()),
				err:    errors.New("exit status 1"),
			}
		}
	}
	err := runD1PrivateCampaignWith(environment, d1TestLoader(job), runner)
	if err != nil {
		t.Fatalf("runD1PrivateCampaignWith() error = %v", err)
	}
	wantCommands := [][]string{
		d1NamedTestCommand(job.contract),
		d1CompileCommand(job.contract),
		d1NamedTestCommand(job.contract),
	}
	if !reflect.DeepEqual(commands, wantCommands) {
		t.Fatalf("D1 command identities = %q; want %q", commands, wantCommands)
	}
	data, err := os.ReadFile(environment.result)
	if err != nil {
		t.Fatalf("read D1 result: %v", err)
	}
	info, err := os.Stat(environment.result)
	if err != nil {
		t.Fatalf("stat D1 result: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("D1 result mode = %v; want private 0600", info.Mode().Perm())
	}
	var report d1CampaignReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode D1 result: %v", err)
	}
	if report.TerminalClassification != d1Killed || len(report.Mutations) != 1 ||
		report.Mutations[0].TerminalClassification != d1Killed {
		t.Fatalf("D1 terminal report = %+v; want one killed mutant", report)
	}
	source, err := os.ReadFile(filepath.Join(environment.sourceCopy, filepath.FromSlash(job.contract.SourcePath())))
	if err != nil || sha256Hex(source) != job.sourceSHA256 {
		t.Fatalf("D1 source copy was not restored: err=%v", err)
	}
	originalReport := append([]byte(nil), data...)
	err = runD1PrivateCampaignWith(environment, d1TestLoader(job), runner)
	var collision *d1CampaignError
	if !errors.As(err, &collision) || collision.terminal != d1ReportCollision {
		t.Fatalf("retained report error = %v; want report collision", err)
	}
	data, err = os.ReadFile(environment.result)
	if err != nil || !bytes.Equal(data, originalReport) {
		t.Fatalf("retained D1 report was replaced: err=%v", err)
	}
	checkout := t.TempDir()
	if err := os.Mkdir(filepath.Join(checkout, ".git"), 0o700); err != nil {
		t.Fatalf("create synthetic checkout marker: %v", err)
	}
	sourceCopy := filepath.Join(checkout, "candidate", "source")
	if err := os.MkdirAll(sourceCopy, 0o700); err != nil {
		t.Fatalf("create nested synthetic source copy: %v", err)
	}
	if root, terminal := openD1SourceRoot(sourceCopy); root != nil || terminal != d1SetupFailed {
		t.Fatalf("live checkout source terminal = %q; want setup refusal", terminal)
	}

	driftEnvironment, driftJob := newD1RunnerFixture(t)
	driftJob.sourceSHA256 = strings.Repeat("0", 64)
	driftRunnerCalled := false
	driftRunner := func(string, []string, time.Duration) d1CommandResult {
		driftRunnerCalled = true
		return d1CommandResult{}
	}
	err = runD1PrivateCampaignWith(driftEnvironment, d1TestLoader(driftJob), driftRunner)
	var drift *d1CampaignError
	if !errors.As(err, &drift) || drift.terminal != d1SourceDrift || driftRunnerCalled {
		t.Fatalf("source drift error = %v, runnerCalled=%t; want pre-command source-drift", err, driftRunnerCalled)
	}
}

func TestD1MutationNamedAssertionRequired(t *testing.T) {
	contract := pcv3corpus.D1MutationContracts()[0]
	testName := contract.TestName()
	marker := contract.AssertionMarker()
	cases := []struct {
		name   string
		result d1CommandResult
		want   d1Terminal
	}{
		{"exact named assertion", d1CommandResult{output: d1TestEvents(testName, "fail", marker), err: errors.New("exit status 1")}, d1Killed},
		{"missing marker", d1CommandResult{output: d1TestEvents(testName, "fail", "different assertion"), err: errors.New("exit status 1")}, d1MissingMarker},
		{"setup failure", d1CommandResult{output: []byte("{\"Action\":\"fail\",\"Package\":\"example\"}\n"), err: errors.New("exit status 1")}, d1SetupFailed},
		{"survived", d1CommandResult{output: d1TestEvents(testName, "pass", "")}, d1Survived},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyD1Mutant(test.result, contract); got != test.want {
				t.Fatalf("classifyD1Mutant() = %q; want %q", got, test.want)
			}
		})
	}
	if got := classifyD1Compile(d1CommandResult{err: errors.New("compile failed")}); got != d1CompileFailed {
		t.Fatalf("compile failure classification = %q; want %q", got, d1CompileFailed)
	}
	if got := classifyD1Baseline(
		d1CommandResult{output: d1TestEvents(testName, "fail", "baseline assertion"), err: errors.New("exit status 1")},
		contract,
	); got != d1BaselineFailed {
		t.Fatalf("baseline failure classification = %q; want %q", got, d1BaselineFailed)
	}
}

func TestD1MutationTimeoutCannotKill(t *testing.T) {
	environment, job := newD1RunnerFixture(t)
	calls := 0
	runner := func(_ string, _ []string, _ time.Duration) d1CommandResult {
		calls++
		if calls == 1 {
			return d1CommandResult{output: d1TestEvents(job.contract.TestName(), "pass", "")}
		}
		if calls == 2 {
			return d1CommandResult{}
		}
		return d1CommandResult{
			output:   d1TestEvents(job.contract.TestName(), "fail", job.contract.AssertionMarker()),
			err:      context.DeadlineExceeded,
			timedOut: true,
		}
	}
	err := runD1PrivateCampaignWith(environment, d1TestLoader(job), runner)
	var campaignErr *d1CampaignError
	if !errors.As(err, &campaignErr) || campaignErr.terminal != d1Timeout {
		t.Fatalf("timeout error = %v; want distinct timeout terminal", err)
	}
	data, readErr := os.ReadFile(environment.result)
	if readErr != nil {
		t.Fatalf("read timeout result: %v", readErr)
	}
	if bytes.Contains(data, []byte(`"terminal_classification":"killed"`)) ||
		!bytes.Contains(data, []byte(`"terminal_classification":"timeout"`)) {
		t.Fatalf("timeout report counted as kill: %s", data)
	}
}

func TestD1MutationRedactsPrivateInputs(t *testing.T) {
	environment, job := newD1RunnerFixture(t)
	environment.corpusRoot = "private-root-sentinel"
	environment.custodyID = "private-custody-sentinel"
	loader := func(root, custody string, _ func([]d1MutationJob) error) error {
		return errors.New(root + custody)
	}
	err := runD1PrivateCampaignWith(environment, loader, func(string, []string, time.Duration) d1CommandResult {
		return d1CommandResult{}
	})
	var setup *d1CampaignError
	if !errors.As(err, &setup) || setup.terminal != d1SetupFailed {
		t.Fatalf("private loader error = %v; want redacted setup failure", err)
	}
	for _, privateValue := range []string{environment.corpusRoot, environment.custodyID, environment.sourceCopy, environment.result} {
		if strings.Contains(err.Error(), privateValue) {
			t.Fatalf("D1 error disclosed private environment value")
		}
	}

	environment, job = newD1RunnerFixture(t)
	calls := 0
	runner := func(_ string, _ []string, _ time.Duration) d1CommandResult {
		calls++
		if calls == 1 {
			return d1CommandResult{output: d1TestEvents(job.contract.TestName(), "pass", "")}
		}
		if calls == 2 {
			return d1CommandResult{}
		}
		return d1CommandResult{output: d1TestEvents(job.contract.TestName(), "fail", job.contract.AssertionMarker()), err: errors.New("exit status 1")}
	}
	if err := runD1PrivateCampaignWith(environment, d1TestLoader(job), runner); err != nil {
		t.Fatalf("redacted D1 campaign error = %v", err)
	}
	data, err := os.ReadFile(environment.result)
	if err != nil {
		t.Fatalf("read redacted D1 report: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte(environment.corpusRoot), []byte(environment.custodyID),
		[]byte(environment.sourceCopy), []byte(environment.result), job.before, job.after,
	} {
		if len(forbidden) != 0 && bytes.Contains(data, forbidden) {
			t.Fatal("D1 report disclosed a private input")
		}
	}
}

func newD1RunnerFixture(t *testing.T) (d1PrivateEnvironment, d1MutationJob) {
	t.Helper()
	contract := pcv3corpus.D1MutationContracts()[0]
	source := []byte("runner before sentinel\n")
	job := d1MutationJob{
		contract: contract, sourceSHA256: sha256Hex(source),
		before: []byte("before"), after: []byte("after"),
	}
	sourceRoot := t.TempDir()
	target := filepath.Join(sourceRoot, filepath.FromSlash(contract.SourcePath()))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("create D1 source parent: %v", err)
	}
	if err := os.WriteFile(target, source, 0o600); err != nil {
		t.Fatalf("write D1 source: %v", err)
	}
	return d1PrivateEnvironment{
		corpusRoot: "corpus-root-sentinel", custodyID: "custody-sentinel",
		sourceCopy: sourceRoot, result: filepath.Join(t.TempDir(), "result.json"),
	}, job
}

func d1TestLoader(job d1MutationJob) d1PlanLoader {
	return func(_, _ string, use func([]d1MutationJob) error) error {
		return use([]d1MutationJob{job})
	}
}

func d1TestEvents(testName, terminal, marker string) []byte {
	var buffer bytes.Buffer
	for _, event := range []testEvent{
		{Action: "run", Test: testName},
		{Action: "output", Test: testName, Output: marker},
		{Action: terminal, Test: testName},
	} {
		data, _ := json.Marshal(event)
		buffer.Write(data)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

func TestRunnerMechanics(t *testing.T) {
	source := []byte("before\nanchor\nafter\n")
	mutation := mutationSpec{
		ID:           "P3-ROUTE-ORDER-001",
		SourceSHA256: sha256Hex(source),
		Anchor:       "anchor\n",
		AnchorSHA256: sha256Hex([]byte("anchor\n")),
		Replacement:  "replacement\n",
	}
	mutated, err := applyMutation(source, mutation)
	if err != nil {
		t.Fatalf("applyMutation() error = %v", err)
	}
	if string(mutated) != "before\nreplacement\nafter\n" {
		t.Fatalf("applyMutation() = %q", mutated)
	}
	mutation.Anchor = "missing\n"
	mutation.AnchorSHA256 = sha256Hex([]byte(mutation.Anchor))
	if _, err := applyMutation(source, mutation); err == nil || !strings.Contains(err.Error(), "exactly once") {
		t.Fatalf("missing anchor error = %v; want exactly-once rejection", err)
	}

	passing := []byte("{\"Action\":\"run\",\"Test\":\"TestBinding\"}\n" +
		"{\"Action\":\"pass\",\"Test\":\"TestBinding\"}\n")
	if err := requireBaselinePass(passing, nil, "TestBinding"); err != nil {
		t.Fatalf("requireBaselinePass() error = %v", err)
	}
	failing := []byte("{\"Action\":\"run\",\"Test\":\"TestBinding\"}\n" +
		"{\"Action\":\"output\",\"Test\":\"TestBinding\",\"Output\":\"binding removed\\n\"}\n" +
		"{\"Action\":\"fail\",\"Test\":\"TestBinding\"}\n")
	if err := requireNamedAssertionFailure(failing, errors.New("exit status 1"), "TestBinding", "binding removed"); err != nil {
		t.Fatalf("requireNamedAssertionFailure() error = %v", err)
	}
	setupFailure := []byte("{\"Action\":\"fail\",\"Package\":\"example\"}\n")
	if err := requireNamedAssertionFailure(setupFailure, errors.New("exit status 1"), "TestBinding", "binding removed"); err == nil {
		t.Fatal("setup failure counted as a named assertion failure")
	}

	report := campaignReport{
		SchemaVersion:  1,
		BaselineCommit: strings.Repeat("a", 40),
		BaselineTree:   strings.Repeat("b", 40),
		SpecRevision:   "0.3",
		SpecSHA256:     strings.Repeat("c", 64),
		ManifestSHA256: strings.Repeat("d", 64),
		Command:        canonicalCampaignCommand,
		Mutations: []mutationResult{{
			ID:                   "P3-ROUTE-ORDER-001",
			BaselineGreen:        true,
			Applied:              true,
			Compiled:             true,
			NamedAssertionFailed: true,
			Restored:             true,
			Killed:               true,
		}},
	}
	first, err := marshalReport(report)
	if err != nil {
		t.Fatalf("marshalReport() error = %v", err)
	}
	second, err := marshalReport(report)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("marshalReport() is nondeterministic: err=%v", err)
	}
	for _, forbidden := range []string{"/home/", "/tmp/", "timestamp", "hostname"} {
		if bytes.Contains(first, []byte(forbidden)) {
			t.Fatalf("report contains volatile/private field %q", forbidden)
		}
	}

	resultPath := filepath.Join(t.TempDir(), "report.json")
	if err := writeAtomicReport(resultPath, first); err != nil {
		t.Fatalf("writeAtomicReport() error = %v", err)
	}
	written, err := os.ReadFile(resultPath)
	if err != nil || !bytes.Equal(written, first) {
		t.Fatalf("written report mismatch: err=%v", err)
	}
	if err := writeAtomicReport(resultPath, first); err == nil {
		t.Fatal("writeAtomicReport() overwrote retained evidence")
	}

	repoRoot, err := gitValue(".", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatalf("resolve test repository: %v", err)
	}
	commit, err := gitValue(repoRoot, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("resolve test commit: %v", err)
	}
	committedTree := t.TempDir()
	if err := materializeCommittedTree(repoRoot, commit, committedTree); err != nil {
		t.Fatalf("materializeCommittedTree() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(committedTree, "src", "go.mod")); err != nil {
		t.Fatalf("materialized committed tree lacks src/go.mod: %v", err)
	}
}
