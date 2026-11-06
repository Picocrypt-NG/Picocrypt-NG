package workflowpolicy

import (
	"os"
	"os/exec"
	"testing"
)

func TestAppImageDispatchRejectsUnfulfilledProductionRequests(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	build := mustJob(t, workflow, "build")
	check := mustStepNamed(t, build, "Validate AppImage dispatch inputs")
	if len(build.Steps) == 0 || build.Steps[0].Name != check.Name || check.If != "" {
		t.Fatal("dispatch inputs must be checked unconditionally before building")
	}
	if check.ContinueOnError != nil && check.ContinueOnError != false {
		t.Fatal("invalid production requests must block the workflow")
	}
	for name, expression := range map[string]string{
		"PUBLISH_RELEASE": "${{ inputs.publish_release }}",
		"SOURCE_EVENT":    "${{ github.event_name }}",
		"SOURCE_REF":      "${{ github.ref }}",
	} {
		if check.Env[name] != expression {
			t.Fatalf("dispatch input %s is not bound to %s", name, expression)
		}
	}
	for _, tc := range []struct {
		name, publish, event, ref string
		wantOK                    bool
	}{
		{"unsigned main", "false", "workflow_dispatch", "refs/heads/main", true},
		{"unsigned review ref", "false", "workflow_dispatch", "refs/heads/review", true},
		{"production main", "true", "workflow_dispatch", "refs/heads/main", true},
		{"production review ref", "true", "workflow_dispatch", "refs/heads/review", false},
		{"production wrong event", "true", "push", "refs/heads/main", false},
		{"invalid boolean", "yes", "workflow_dispatch", "refs/heads/main", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", check.Run)
			command.Env = append(os.Environ(), "PUBLISH_RELEASE="+tc.publish, "SOURCE_EVENT="+tc.event, "SOURCE_REF="+tc.ref)
			output, err := command.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("dispatch validation returned %v, want success %v: %s", err, tc.wantOK, output)
			}
		})
	}
}
