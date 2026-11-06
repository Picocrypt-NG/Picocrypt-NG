package workflowpolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseRequestRejectsUnfulfilledOrConflictingModes(t *testing.T) {
	for _, tc := range []struct {
		name, publish, signTest, dryRun, event, ref string
		wantOK                                      bool
	}{
		{"unsigned main", "false", "false", "false", "workflow_dispatch", "refs/heads/main", true},
		{"unsigned review ref", "false", "false", "false", "workflow_dispatch", "refs/heads/review", true},
		{"unsigned other event", "false", "false", "false", "push", "refs/heads/review", true},
		{"publish main", "true", "false", "false", "workflow_dispatch", "refs/heads/main", true},
		{"test signing main", "false", "true", "false", "workflow_dispatch", "refs/heads/main", true},
		{"production dry run main", "false", "false", "true", "workflow_dispatch", "refs/heads/main", true},
		{"publish review ref", "true", "false", "false", "workflow_dispatch", "refs/heads/review", false},
		{"test signing review ref", "false", "true", "false", "workflow_dispatch", "refs/heads/review", false},
		{"production dry run review ref", "false", "false", "true", "workflow_dispatch", "refs/heads/review", false},
		{"publish other event", "true", "false", "false", "push", "refs/heads/main", false},
		{"test signing other event", "false", "true", "false", "push", "refs/heads/main", false},
		{"production dry run other event", "false", "false", "true", "push", "refs/heads/main", false},
		{"publish and test signing", "true", "true", "false", "workflow_dispatch", "refs/heads/main", false},
		{"publish and production dry run", "true", "false", "true", "workflow_dispatch", "refs/heads/main", false},
		{"test signing and production dry run", "false", "true", "true", "workflow_dispatch", "refs/heads/main", false},
		{"all modes", "true", "true", "true", "workflow_dispatch", "refs/heads/main", false},
		{"invalid publish boolean", "yes", "false", "false", "workflow_dispatch", "refs/heads/main", false},
		{"invalid test signing boolean", "false", "yes", "false", "workflow_dispatch", "refs/heads/main", false},
		{"invalid dry run boolean", "false", "false", "yes", "workflow_dispatch", "refs/heads/main", false},
		{"empty publish boolean", "", "false", "false", "workflow_dispatch", "refs/heads/main", false},
		{"empty test signing boolean", "false", "", "false", "workflow_dispatch", "refs/heads/main", false},
		{"empty dry run boolean", "false", "false", "", "workflow_dispatch", "refs/heads/main", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command("bash", filepath.Join(repoRoot(t), ".github/scripts/validate-release-request.sh"))
			command.Env = append(os.Environ(),
				"PUBLISH_RELEASE="+tc.publish, "SIGNPATH_TEST="+tc.signTest,
				"SIGNPATH_RELEASE_DRY_RUN="+tc.dryRun, "SOURCE_EVENT="+tc.event, "SOURCE_REF="+tc.ref)
			output, err := command.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("release request returned %v, want success %v: %s", err, tc.wantOK, output)
			}
			if !tc.wantOK && !strings.Contains(string(output), "::error::") {
				t.Fatalf("rejected request must explain the input error: %s", output)
			}
		})
	}
}

func TestReleaseBuildsValidateRequestsBeforeDependencies(t *testing.T) {
	for _, tc := range []struct {
		name, job string
		signpath  bool
	}{
		{"build-linux", "prepare", false},
		{"build-macos", "build", false},
		{"build-android", "build", false},
		{"build-snapcraft", "build-snapcraft", false},
		{"build-windows", "build", true},
		{"build-windows-legacy", "build", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, ".github/workflows/"+tc.name+".yml")
			build := mustJob(t, workflow, tc.job)
			check := mustStepNamed(t, build, "Validate release request")
			if len(build.Steps) < 2 || !strings.HasPrefix(build.Steps[0].Uses, "actions/checkout@") || build.Steps[1].Name != check.Name {
				t.Fatal("release requests must be checked immediately after checkout, before dependencies or builds")
			}
			wantIf := ""
			if tc.name == "build-linux" {
				wantIf = "${{ " + linuxDirectInvocation + " }}"
			}
			if build.If != wantIf || (build.ContinueOnError != nil && build.ContinueOnError != false) ||
				check.If != "" || (check.ContinueOnError != nil && check.ContinueOnError != false) {
				t.Fatal("invalid release requests must fail the build unconditionally")
			}
			if check.Shell != "bash" || check.Run != "bash .github/scripts/validate-release-request.sh" || check.WorkingDirectory != "" {
				t.Fatalf("release request validation must execute the shared Bash guard from the repository root: %#v", check)
			}
			expected := map[string]string{
				"PUBLISH_RELEASE":          "${{ inputs.publish_release }}",
				"SIGNPATH_TEST":            "false",
				"SIGNPATH_RELEASE_DRY_RUN": "false",
				"SOURCE_EVENT":             "${{ github.event_name }}",
				"SOURCE_REF":               "${{ github.ref }}",
			}
			if tc.signpath {
				expected["SIGNPATH_TEST"] = "${{ inputs.signpath_test }}"
				expected["SIGNPATH_RELEASE_DRY_RUN"] = "${{ inputs.signpath_release_dry_run }}"
			}
			for name, expression := range expected {
				if check.Env[name] != expression {
					t.Fatalf("release input %s = %q, want %q", name, check.Env[name], expression)
				}
			}
		})
	}
}
