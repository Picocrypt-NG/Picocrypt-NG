package workflowpolicy

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestProductionKDFLocalCommandsUseCompleteSharedRunner(t *testing.T) {
	var config struct {
		Tasks map[string]struct {
			Dir string
			Run any
		}
	}
	if _, err := toml.Decode(mustReadRepoFile(t, "mise.toml"), &config); err != nil {
		t.Fatal(err)
	}
	if task := config.Tasks["test:production-kdf"]; task.Dir != "" || task.Run != "bash .github/scripts/test-production-kdf.sh" {
		t.Fatalf("production-KDF task = %#v, want the complete shared runner without selectors", task)
	}
	var jouet struct {
		Checks struct{ Focused map[string]string }
	}
	if _, err := toml.Decode(mustReadRepoFile(t, ".jouet/project.toml"), &jouet); err != nil {
		t.Fatal(err)
	}
	if got := jouet.Checks.Focused["pcv3_production_kdf"]; got != "jouet test --cmd -- mise run test:production-kdf" {
		t.Fatalf("jouet production-KDF command = %q, want the same operation and CLI runner as CI", got)
	}
	if command := config.Tasks["tooling:test"].Run; command != "bash .github/scripts/test-go-tooling.sh" {
		t.Fatalf("tooling command = %#v, want the shared real-HK and platform-aware helper route", command)
	}
	for _, name := range []string{"tooling:fmt", "tooling:lint"} {
		command, ok := config.Tasks[name].Run.(string)
		if !ok {
			t.Fatalf("missing shared %s command", name)
		}
		if name == "tooling:fmt" {
			mustContain(t, command, ".github/scripts/production-kdf.go")
			mustContain(t, command, ".github/scripts/production-kdf_test.go")
		} else if command != "bash .github/scripts/lint-go.sh sarif tooling" {
			t.Fatalf("tooling lint command = %q, want the shared transparent SARIF wrapper", command)
		}
	}
}

func TestLinuxProductionKDFJobRunsCompleteSharedLaneAndRetainsReports(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-linux.yml")
	job := mustJob(t, workflow, "production-kdf")
	if job.RunsOn != "ubuntu-24.04" || job.TimeoutMinutes != 75 || job.If != "" || job.Needs != nil || (job.ContinueOnError != nil && job.ContinueOnError != false) {
		t.Fatalf("production-KDF must run independently on every PR with provisional 75m job budget: %+v", job)
	}
	for name, want := range map[string]string{
		"CGO_ENABLED": "1", "PICOCRYPT_RUN_CLI_INTEGRATION": "1",
		"GOMEMLIMIT": "2GiB", "GOMAXPROCS": "2",
	} {
		if got := job.Env[name]; got != want {
			t.Errorf("production-KDF %s = %q, want %q", name, got, want)
		}
	}
	setup := mustStepNamed(t, job, "Setup Go")
	if setup.With["go-version"] != "1.27.3" {
		t.Fatalf("production-KDF Go version = %#v", setup.With["go-version"])
	}
	prepare := mustStepNamed(t, job, "Prepare compiler temporary directory")
	if prepare.Env["GOTMPDIR"] != "${{ runner.temp }}/production-kdf-go-tmp" {
		t.Fatalf("compiler preparation path = %q", prepare.Env["GOTMPDIR"])
	}
	mustContain(t, prepare.Run, `mkdir -p "$GOTMPDIR"`)
	mustNotContain(t, prepare.Run, `mkdir -p "$PICOCRYPT_PRODUCTION_KDF_REPORT_DIR"`)
	run := mustStepNamed(t, job, "Run complete native production-KDF lane")
	for name, want := range map[string]string{
		"GOTMPDIR":                            "${{ runner.temp }}/production-kdf-go-tmp",
		"PICOCRYPT_PRODUCTION_KDF_REPORT_DIR": "${{ runner.temp }}/production-kdf-reports",
	} {
		if got := run.Env[name]; got != want {
			t.Errorf("production-KDF run %s = %q, want %q", name, got, want)
		}
	}
	if run.Run != "mise run test:production-kdf" || run.If != "" || (run.ContinueOnError != nil && run.ContinueOnError != false) {
		t.Fatalf("production-KDF must propagate the unchanged shared command result: %+v", run)
	}
	upload := mustStepNamed(t, job, "Upload production-KDF reports")
	if !strings.HasPrefix(upload.Uses, "actions/upload-artifact@") || upload.If != "${{ always() }}" || upload.With["path"] != "${{ runner.temp }}/production-kdf-reports" || upload.With["if-no-files-found"] != "error" {
		t.Fatalf("production-KDF must retain reports after success, failure or cancellation: %+v", upload)
	}
	pullRequest, ok := workflow.On.OtherEvents["pull_request"].(map[string]any)
	if !ok {
		t.Fatal("missing pull_request trigger")
	}
	for _, filter := range []string{"paths", "paths-ignore"} {
		if _, exists := pullRequest[filter]; exists {
			t.Fatalf("required Linux workflow must not use workflow-level %s", filter)
		}
	}
}

func TestLinuxAggregateBashRejectsEveryNonSuccessDependency(t *testing.T) {
	gate := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-linux.yml"), "pr-test-build-linux")
	needs, ok := gate.Needs.([]any)
	if !ok || !slices.Equal(needs, []any{"build", "production-kdf"}) || gate.If != "${{ always() }}" || gate.TimeoutMinutes != 10 || (gate.ContinueOnError != nil && gate.ContinueOnError != false) {
		t.Fatalf("cheap Linux aggregate must directly inspect both dependencies even after cancellation: %+v", gate)
	}
	step := mustStepNamed(t, gate, "Require all Linux matrix jobs to pass")
	if len(gate.Steps) != 1 || step.If != "${{ always() }}" || step.Shell != "bash" || (step.ContinueOnError != nil && step.ContinueOnError != false) {
		t.Fatalf("aggregate must run one unconditional Bash result check: %+v", step)
	}
	if step.Env["BUILD_RESULT"] != "${{ needs.build.result }}" || step.Env["PRODUCTION_KDF_RESULT"] != "${{ needs.production-kdf.result }}" {
		t.Fatalf("aggregate dependency bindings = %#v", step.Env)
	}
	mustNotContain(t, step.Run, "${{")
	// Execute the actual workflow body. An unknown or absent conclusion must
	// fail closed just like failure, skipped, neutral, cancelled or timeout.
	statuses := []string{"success", "failure", "skipped", "neutral", "cancelled", "timed_out", "", "unknown"}
	for _, build := range statuses {
		for _, kdf := range statuses {
			t.Run(build+"/"+kdf, func(t *testing.T) {
				command := exec.Command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", step.Run)
				command.Env = []string{"PATH=" + os.Getenv("PATH")}
				if build != "" {
					command.Env = append(command.Env, "BUILD_RESULT="+build)
				}
				if kdf != "" {
					command.Env = append(command.Env, "PRODUCTION_KDF_RESULT="+kdf)
				}
				output, err := command.CombinedOutput()
				if passed, want := err == nil, build == "success" && kdf == "success"; passed != want {
					t.Fatalf("build=%q production-kdf=%q accepted=%v, want %v: %v\n%s", build, kdf, passed, want, err, output)
				}
			})
		}
	}
}

func TestStaticChecksEnforceProductionKDFHelperQuality(t *testing.T) {
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-static-checks.yml"), "static-checks")
	for _, name := range []string{"fmt", "lint"} {
		step := mustStepNamed(t, job, "Check Go tooling "+name)
		if step.Run != "mise run tooling:"+name || step.If != "" || (step.ContinueOnError != nil && step.ContinueOnError != false) {
			t.Fatalf("Go tooling %s must use the same required shared check as local tooling: %+v", name, step)
		}
	}
}
