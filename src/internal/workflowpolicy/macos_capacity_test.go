package workflowpolicy

import (
	"reflect"
	"testing"
)

// Release packaging must use the same complete, memory-bounded native lane as PRs.
func TestMacOSReleaseUsesCompleteNativeLaneBeforePackaging(t *testing.T) {
	pr := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-macos.yml"), "pr-test-build-macos")
	action := mustReadCompositeActionDoc(t, ".github/actions/build-macos/action.yml")
	for _, name := range []string{"Run native test suite", "Run tests"} {
		want := mustStepNamed(t, pr, name)
		want.Shell = "bash"
		want.Env = map[string]string{"CGO_ENABLED": "1"}
		if name == "Run native test suite" {
			want.Env["SHARD_INDEX"] = "0"
			want.Env["SHARD_COUNT"] = "1"
		}
		got := mustCompositeStepNamed(t, action, name)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s must preserve the complete PR native/race/CLI lane and blocking outcome: got %+v, want %+v", name, got, want)
		}
	}
	mustContainInOrder(t, mustReadRepoFile(t, ".github/actions/build-macos/action.yml"),
		"- name: Run native test suite",
		"- name: Run tests",
		"- name: Build GUI",
		"- name: Build CLI-only (no graphics dependencies)",
		"- name: Package as .app in a .dmg",
		"- name: Upload artifacts",
	)
}

func TestMacOSPRUsesOneRunnerForFullNativeSuiteAndPackaging(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-macos.yml")
	if len(workflow.Jobs) != 1 {
		t.Fatalf("macOS PR must require one runner acquisition, got %d jobs", len(workflow.Jobs))
	}
	job := mustJob(t, workflow, "pr-test-build-macos")
	if job.RunsOn != "macos-15" || job.Env["CGO_ENABLED"] != "1" {
		t.Fatal("capacity changes must preserve native macOS ARM64 CGO execution")
	}
	if job.Needs != nil || job.If != "" || job.ContinueOnError != nil || !reflect.ValueOf(job.Strategy).IsZero() {
		t.Fatal("the required macOS job must run directly without a matrix or softened result")
	}

	run := mustStepNamed(t, job, "Run native test suite")
	if run.Env["SHARD_INDEX"] != "0" || run.Env["SHARD_COUNT"] != "1" {
		t.Fatal("one native runner must select every dynamically discovered test parent")
	}
	if run.Run != "bash .github/scripts/test-macos-pcv3.sh \"$SHARD_INDEX\" \"$SHARD_COUNT\"" {
		t.Fatal("capacity changes must retain the existing full native discovery runner")
	}
	if run.If != "" || run.ContinueOnError != nil {
		t.Fatal("the full native suite must run by default and fail the required macOS job")
	}
}
