package workflowpolicy

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type fullValidationProducer struct {
	job, owner, ownerJob, action, arch string
}

func fullValidationProducers() []fullValidationProducer {
	return []fullValidationProducer{
		{"build-amd64", "build-linux", "build-amd64", "build-linux", "amd64"},
		{"build-arm64", "build-linux", "build-arm64", "build-linux", "arm64"},
		{"build-appimage", "build-appimage", "build", "build-appimage", "amd64"},
		{"build-snapcraft", "build-snapcraft", "build-snapcraft", "build-snapcraft", "amd64"},
		{"build-macos", "build-macos", "build", "build-macos", "arm64"},
		{"build-android", "build-android", "build", "build-android", "all"},
		{"build-windows", "build-windows", "build", "build-windows", "amd64"},
		{"build-windows-legacy", "build-windows-legacy", "build", "build-windows-legacy", "amd64"},
	}
}

func TestFullValidationCoordinatorHasOnlyValidationAuthority(t *testing.T) {
	const path = ".github/workflows/release.yml"
	workflow := mustReadWorkflowDoc(t, path)
	var choices struct {
		On struct {
			Dispatch struct {
				Inputs map[string]struct {
					Options []string `yaml:"options"`
				} `yaml:"inputs"`
			} `yaml:"workflow_dispatch"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, path)), &choices); err != nil {
		t.Fatal(err)
	}
	mode := workflow.On.WorkflowDispatch.Inputs["mode"]
	if len(workflow.On.WorkflowDispatch.Inputs) != 1 || mode.Type != "choice" || mode.Default != "validation" ||
		!reflect.DeepEqual(choices.On.Dispatch.Inputs["mode"].Options, []string{"validation"}) || len(workflow.On.OtherEvents) != 0 {
		t.Fatal("the full coordinator must remain manual and validation-only by default")
	}
	wantJobs := map[string]bool{"prepare": true, "verify-linux": true, "verify-platforms": true, "validation": true}
	for _, producer := range fullValidationProducers() {
		wantJobs[producer.job] = true
	}
	if len(workflow.Jobs) != len(wantJobs) {
		t.Fatal("full validation requires prepare, eight real producers, two verifiers and the final gate")
	}
	for name, job := range workflow.Jobs {
		if !wantJobs[name] || job.Environment != nil {
			t.Fatalf("unreviewed or privileged coordinator job %q", name)
		}
		mustEffectivePermission(t, workflow, job, "contents", "read")
		permissions := workflow.Permissions
		if job.Permissions != nil {
			permissions = job.Permissions
		}
		for _, permission := range []string{"id-token", "attestations", "packages"} {
			if permissions[permission] != "" && permissions[permission] != "none" {
				t.Fatalf("coordinator job %s has %s authority", name, permission)
			}
		}
		for _, value := range job.Permissions {
			if value != "read" && value != "none" {
				t.Fatalf("coordinator job %s has write authority", name)
			}
		}
		for _, step := range job.Steps {
			if step.ContinueOnError != nil && step.ContinueOnError != false {
				t.Fatalf("coordinator step %s must fail closed", step.Name)
			}
			for _, forbidden := range []string{"sign-and-attest", "stage-release", "signpath"} {
				mustNotContain(t, strings.ToLower(step.Uses), forbidden)
			}
			mustNotContain(t, step.Run, "--sign")
		}
	}
	raw := mustReadWorkflow(t, path)
	if regexp.MustCompile(`\bsecrets\s*(?:\.|\[)`).MatchString(raw) {
		t.Fatal("validation must not reference production credentials")
	}
	for _, dump := range []string{"toJSON(needs)", "toJSON(github)", "toJson(needs)", "toJson(github)"} {
		mustNotContain(t, raw, dump)
	}
	mustContain(t, raw, "name: release-validation\n")
	prepare := mustStepNamed(t, mustJob(t, workflow, "prepare"), "Bind source and canonical manifest")
	mustContain(t, prepare.Run, `test "$MODE" = validation`)
}

func TestFullValidationProducersMatchNativeOwnersAndCanonicalOutputs(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/release.yml")
	for _, tc := range fullValidationProducers() {
		t.Run(tc.job, func(t *testing.T) {
			job := mustJob(t, workflow, tc.job)
			owner := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/"+tc.owner+".yml"), tc.ownerJob)
			if job.Needs != "prepare" || job.If != "" || job.RunsOn != owner.RunsOn || job.TimeoutMinutes != owner.TimeoutMinutes || !reflect.DeepEqual(job.Env, owner.Env) {
				t.Fatal("producer must retain its owner's native runner, timeout and public environment")
			}
			if !reflect.DeepEqual(job.Outputs, map[string]string{
				"artifact-id": "${{ steps.build.outputs.artifact-id }}", "artifact-digest": "${{ steps.build.outputs.artifact-digest }}", "run-attempt": "${{ steps.build.outputs.run-attempt }}",
			}) {
				t.Fatal("coordinator producer outputs must be the canonical official ID/digest/attempt, never a signing-input alias")
			}
			call := mustHaveStepUsingPrefix(t, job, "./.github/actions/"+tc.action)
			if call.Uses != "./.github/actions/"+tc.action || call.ID != "build" || call.If != "" {
				t.Fatal("coordinator must invoke the actual blocking producer component")
			}
			if mustReadCompositeActionDoc(t, ".github/actions/"+tc.action+"/action.yml").Runs.Using != "composite" {
				t.Fatal("registered producer is not an executable composite")
			}
			for _, name := range []string{"source-sha", "version", "manifest-digest"} {
				if call.With[name] != "${{ needs.prepare.outputs."+name+" }}" {
					t.Fatalf("producer loses prepared %s", name)
				}
			}
			if tc.action != "build-linux" && len(call.With) != 3 {
				t.Fatal("validation producers must not receive signing flags or unused inputs")
			}
			if len(job.Steps) != 2 || !strings.HasPrefix(job.Steps[0].Uses, "actions/checkout@") ||
				job.Steps[0].With["ref"] != "${{ github.sha }}" || job.Steps[0].With["persist-credentials"] != false {
				t.Fatal("each native producer must execute the immutable event checkout")
			}
		})
	}
}

func TestFullValidationUsesExactIDsBeforeTheCompleteNineteenFileGate(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/release.yml")
	platforms := mustJob(t, workflow, "verify-platforms")
	if platforms.If != "${{ always() }}" || fmt.Sprint(platforms.Needs) != "[prepare build-appimage build-snapcraft build-macos build-android build-windows build-windows-legacy]" ||
		len(platforms.Steps) == 0 || platforms.Steps[0].Name != "Require all platform producers" {
		t.Fatal("platform verification must fail on every failed/skipped producer before checkout or APIs")
	}
	mustHaveStepUsingPrefix(t, platforms, "./.github/actions/setup-gh")
	metadata := mustStepNamed(t, platforms, "Verify immutable platform artifact metadata")
	payload := mustStepNamed(t, platforms, "Verify platform payload manifests")
	if metadata.Run != "bash .github/actions/verify-platform-artifacts/verify-artifacts.sh metadata" || metadata.Env["GH_TOKEN"] != "${{ github.token }}" {
		t.Fatal("platform metadata must use the read-only exact-ID consumer")
	}
	mustContain(t, payload.Run, "bash .github/actions/verify-platform-artifacts/verify-artifacts.sh payload")
	seen := make(map[string]bool)
	metadataSeen, payloadSeen := false, false
	for _, step := range platforms.Steps {
		if step.Name == metadata.Name {
			metadataSeen = true
		}
		if step.Name == payload.Name {
			payloadSeen = true
		}
		if !strings.HasPrefix(step.Uses, "actions/download-artifact@") {
			continue
		}
		if !metadataSeen || payloadSeen || step.Uses != "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" {
			t.Fatal("six official downloads must occur between metadata and payload validation")
		}
		matched := false
		for _, producer := range fullValidationProducers()[2:] {
			if step.With["artifact-ids"] != "${{ needs."+producer.job+".outputs.artifact-id }}" {
				continue
			}
			if seen[producer.job] || step.With["path"] != "artifacts/"+producer.owner || step.With["merge-multiple"] != true || step.With["digest-mismatch"] != "error" {
				t.Fatal("platform download must use its unique canonical ID and stable directory with blocking digest checks")
			}
			seen[producer.job], matched = true, true
		}
		if !matched || step.With["name"] != nil || step.With["pattern"] != nil || step.With["run-id"] != nil || step.With["repository"] != nil || step.With["github-token"] != nil {
			t.Fatal("platform artifacts must not be selected by name, pattern or another run")
		}
	}
	if len(seen) != 6 {
		t.Fatal("all six non-Linux owners must be downloaded")
	}
	for _, name := range []string{"verify-linux", "verify-platforms"} {
		job := mustJob(t, workflow, name)
		for _, output := range []string{"artifact-id", "artifact-digest"} {
			if job.Outputs[output] != "${{ steps.upload.outputs."+output+" }}" {
				t.Fatalf("%s report %s must come from its official uploader", name, output)
			}
		}
		if job.Outputs["run-attempt"] == "" {
			t.Fatal("final report metadata needs the actual verifier's producing attempt")
		}
	}
	final := mustJob(t, workflow, "validation")
	if final.If != "${{ always() }}" || fmt.Sprint(final.Needs) != "[prepare verify-linux verify-platforms]" ||
		len(final.Steps) == 0 || final.Steps[0].Name != "Require both artifact verifiers" {
		t.Fatal("the final gate must require both verifiers before downloading reports")
	}
	mustHaveStepUsingPrefix(t, final, "./.github/actions/setup-gh")
	mustStepNamed(t, final, "Verify immutable verifier report metadata")
	join := mustStepNamed(t, final, "Join complete validation manifest")
	for _, field := range []string{"publish_release:false", `production_signing:"not-requested"`, "Developer ID", "notarization"} {
		mustContain(t, join.Run, field)
	}
	for _, name := range []string{"linux", "platforms"} {
		step := mustStepNamed(t, final, "Download "+name+" verification report")
		if step.Uses != "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" ||
			step.With["artifact-ids"] != "${{ needs.verify-"+name+".outputs.artifact-id }}" || step.With["merge-multiple"] != true || step.With["digest-mismatch"] != "error" {
			t.Fatal("final report downloads must use only the exact verifier artifact IDs")
		}
	}
}
