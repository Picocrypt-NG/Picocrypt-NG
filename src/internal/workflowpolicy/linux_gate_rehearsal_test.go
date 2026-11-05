package workflowpolicy

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// These checks protect a hosted gate experiment, not product behavior. Only
// actual GitHub job conclusions can establish its cancellation/timeout result.
func TestLinuxGateRehearsalUsesProductionGateForRealDependencyResults(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/rehearse-linux-gate.yml")
	production := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-linux.yml"), "pr-test-build-linux"), "Require all Linux matrix jobs to pass")
	for _, scenario := range []string{"success", "failure", "skip", "timeout", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			gate := mustJob(t, workflow, "gate-"+scenario)
			if gate.Needs != "parent-"+scenario || gate.TimeoutMinutes != 2 || gate.Environment != nil || (gate.ContinueOnError != nil && gate.ContinueOnError != false) {
				t.Fatalf("rehearsal gate must inspect its actual parent without suppression: %+v", gate)
			}
			branch := "ci/rehearse-linux-gate"
			if scenario == "cancel" {
				branch += "-cancel"
			}
			if want := "${{ always() && github.ref == 'refs/heads/" + branch + "' }}"; gate.If != want {
				t.Fatalf("gate condition = %q, want %q", gate.If, want)
			}
			if len(gate.Steps) != 1 {
				t.Fatal("rehearsal gate must have only the blocking production result check")
			}
			step := mustStepNamed(t, gate, "Require all Linux matrix jobs to pass")
			if step.Run != production.Run || step.Shell != production.Shell || step.If != production.If || (step.ContinueOnError != nil && step.ContinueOnError != false) {
				t.Fatal("rehearsal gate drifted from the production Bash contract")
			}
			if step.Env["BUILD_RESULT"] != "${{ needs.parent-"+scenario+".result }}" || step.Env["PRODUCTION_KDF_RESULT"] != "success" {
				t.Fatalf("gate does not bind its real parent result: %#v", step.Env)
			}
		})
	}
	success := mustJob(t, workflow, "parent-success")
	failure := mustJob(t, workflow, "parent-failure")
	skipped := mustJob(t, workflow, "parent-skip")
	timeout := mustJob(t, workflow, "parent-timeout")
	if success.Steps[0].Run != "exit 0\n" || failure.Steps[0].Run != "exit 23\n" || skipped.If != "${{ github.ref == 'refs/heads/ci/rehearse-linux-gate-disabled' }}" || timeout.TimeoutMinutes != 1 || timeout.Steps[0].Run != "exec tail -f /dev/null\n" {
		t.Fatal("parents must produce real success, failure, skip and job timeout")
	}
}

func TestLinuxGateRehearsalCannotRunOnProductionBranchesOrCancelOtherRuns(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/rehearse-linux-gate.yml")
	push, ok := workflow.On.OtherEvents["push"].(map[string]any)
	if !ok || len(workflow.On.OtherEvents) != 1 || !reflect.DeepEqual(push["branches"], []any{"ci/rehearse-linux-gate", "ci/rehearse-linux-gate-cancel"}) || len(push) != 1 || len(workflow.On.WorkflowDispatch.Inputs) != 0 {
		t.Fatalf("rehearsal must emit only on its two exact test branches: %#v", workflow.On)
	}
	if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read"}) {
		t.Fatalf("rehearsal workflow permissions = %#v", workflow.Permissions)
	}
	for name, job := range workflow.Jobs {
		if name != "parent-cancel" && job.Permissions != nil {
			t.Fatalf("job %s unexpectedly overrides read-only permissions", name)
		}
		if job.Environment != nil || job.Uses != "" {
			t.Fatalf("job %s must not enter a release environment or reusable workflow", name)
		}
		for _, step := range job.Steps {
			for _, value := range append([]string{step.Run, step.Uses}, linuxGateEnvValues(step.Env)...) {
				if strings.Contains(value, "secrets.") || strings.Contains(value, "sign-and-attest") || strings.Contains(value, "stage-release") {
					t.Fatalf("job %s unexpectedly uses signing or release authority", name)
				}
			}
		}
	}
	cancel := mustJob(t, workflow, "parent-cancel")
	if cancel.If != "${{ !cancelled() && github.repository == 'Picocrypt-NG/Picocrypt-NG' && github.ref == 'refs/heads/ci/rehearse-linux-gate-cancel' }}" || !reflect.DeepEqual(cancel.Permissions, map[string]string{"actions": "write", "contents": "read"}) {
		t.Fatalf("self-cancellation authority is not isolated to its exact test branch: %+v", cancel)
	}
	step := mustStepNamed(t, cancel, "Cancel this rehearsal run")
	if step.Env["GH_HOST"] != "github.com" || step.Env["GH_TOKEN"] != "${{ github.token }}" || step.Env["GH_REPO"] != "${{ github.repository }}" || step.Env["RUN_ID"] != "${{ github.run_id }}" {
		t.Fatalf("self-cancel identity is not bound to the current event: %#v", step.Env)
	}
	const selfCancel = `[[ "$GH_REPO" == Picocrypt-NG/Picocrypt-NG && "$RUN_ID" =~ ^[0-9]+$ ]]
gh api --method POST "repos/$GH_REPO/actions/runs/$RUN_ID/cancel"
exec tail -f /dev/null
`
	if step.Run != selfCancel {
		t.Fatal("self-cancel must issue only the reviewed current-run request")
	}
}

func TestLinuxGateRehearsalObserverRejectsUnexpectedOrMissingConclusions(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/rehearse-linux-gate.yml")
	job := mustJob(t, workflow, "observe")
	if job.If != "${{ always() && github.ref == 'refs/heads/ci/rehearse-linux-gate' }}" {
		t.Fatalf("observer condition = %q", job.If)
	}
	dependencies := []any{"parent-success", "parent-failure", "parent-skip", "parent-timeout", "gate-success", "gate-failure", "gate-skip", "gate-timeout"}
	if !reflect.DeepEqual(job.Needs, dependencies) {
		t.Fatalf("observer dependencies = %#v", job.Needs)
	}
	step := mustStepNamed(t, job, "Check expected rehearsal conclusions")
	bindings := map[string]string{
		"PARENT_SUCCESS": "${{ needs.parent-success.result }}", "PARENT_FAILURE": "${{ needs.parent-failure.result }}",
		"PARENT_SKIP": "${{ needs.parent-skip.result }}", "PARENT_TIMEOUT": "${{ needs.parent-timeout.result }}",
		"GATE_SUCCESS": "${{ needs.gate-success.result }}", "GATE_FAILURE": "${{ needs.gate-failure.result }}",
		"GATE_SKIP": "${{ needs.gate-skip.result }}", "GATE_TIMEOUT": "${{ needs.gate-timeout.result }}",
	}
	if !reflect.DeepEqual(step.Env, bindings) || step.If != "${{ always() }}" || (step.ContinueOnError != nil && step.ContinueOnError != false) {
		t.Fatalf("observer must inspect real dependency conclusions without suppression: %+v", step)
	}
	want := map[string]string{
		"PARENT_SUCCESS": "success", "PARENT_FAILURE": "failure", "PARENT_SKIP": "skipped", "PARENT_TIMEOUT": "cancelled",
		"GATE_SUCCESS": "success", "GATE_FAILURE": "failure", "GATE_SKIP": "failure", "GATE_TIMEOUT": "failure",
	}
	run := func(values map[string]string) bool {
		command := exec.Command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", step.Run)
		command.Env = []string{"PATH=" + os.Getenv("PATH")}
		for name, value := range values {
			command.Env = append(command.Env, name+"="+value)
		}
		_, err := command.CombinedOutput()
		return err == nil
	}
	if !run(want) {
		t.Fatal("observer rejected the complete expected result set")
	}
	for name := range want {
		for _, invalid := range []string{"", "unknown", "cancelled", "neutral", "success", "failure", "skipped"} {
			if invalid == want[name] {
				continue
			}
			values := make(map[string]string, len(want))
			for key, value := range want {
				values[key] = value
			}
			if invalid == "" {
				delete(values, name)
			} else {
				values[name] = invalid
			}
			if run(values) {
				t.Fatalf("observer accepted %s=%q", name, invalid)
			}
		}
	}
}

func linuxGateEnvValues(env map[string]string) []string {
	values := make([]string, 0, len(env))
	for _, value := range env {
		values = append(values, value)
	}
	return values
}
