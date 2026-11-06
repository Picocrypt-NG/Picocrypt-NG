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

func TestFullValidationCoordinatorKeepsValidationReadOnlyAndProductionExplicit(t *testing.T) {
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
		Jobs map[string]yaml.Node `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, path)), &choices); err != nil {
		t.Fatal(err)
	}
	mode := workflow.On.WorkflowDispatch.Inputs["mode"]
	if len(workflow.On.WorkflowDispatch.Inputs) != 1 || mode.Type != "choice" || mode.Default != "validation" ||
		!reflect.DeepEqual(choices.On.Dispatch.Inputs["mode"].Options, []string{"validation", "stage", "publish"}) || len(workflow.On.OtherEvents) != 0 {
		t.Fatal("the full coordinator must remain manual and validation-only by default, with explicit stage/publish choices")
	}
	wantJobs := map[string]bool{"prepare": true, "verify-linux": true, "verify-platforms": true, "validation": true}
	for _, producer := range fullValidationProducers() {
		wantJobs[producer.job] = true
	}
	owners := []string{"linux", "macos", "snapcraft", "android", "windows", "windows-legacy", "appimage"}
	if len(workflow.Jobs) != len(wantJobs)+len(owners)+2 {
		t.Fatal("the coordinator requires the complete validation graph, seven real owners, final publication and readonly outcome reporting")
	}
	for name, job := range workflow.Jobs {
		if !wantJobs[name] && name != "result" {
			if name == "publish" {
				if job.If != "${{ always() && !cancelled() && inputs.mode == 'publish' }}" || job.Environment != "release" ||
					!reflect.DeepEqual(job.Permissions, map[string]string{"contents": "write", "actions": "read"}) {
					t.Fatal("final publication must be explicit, cancel-aware, release-protected and have no OIDC authority")
				}
				guard := mustStepNamed(t, job, "Require every staged owner")
				if len(job.Steps) == 0 || job.Steps[0].Name != guard.Name {
					t.Fatal("all staged results must be checked before checkout or API writes")
				}
				mustContain(t, guard.Run, `test "$MODE" = publish`)
				mustContain(t, guard.Run, `.result == "success" and .staged == "true"`)
				for _, owner := range owners {
					if !strings.Contains(fmt.Sprint(job.Needs), "owner-"+owner) {
						t.Fatalf("publication lacks owner %s dependency", owner)
					}
					mustContain(t, job.Env["OWNER_RESULTS_JSON"], "${{ needs.owner-"+owner+".result }}")
					mustContain(t, job.Env["OWNER_RESULTS_JSON"], "${{ needs.owner-"+owner+".outputs.staged }}")
				}
				mustContain(t, mustStepNamed(t, job, "Strictly finalize complete release").Run, "release-gate.sh strict-finalize")
				mustContain(t, mustStepNamed(t, job, "Require confirmed publication").Run, `test "$PUBLISHED" = true`)
				continue
			}
			matched := false
			for _, owner := range owners {
				if name != "owner-"+owner {
					continue
				}
				matched = true
				if job.Uses != "./.github/workflows/build-"+owner+".yml" || job.If != "${{ !cancelled() && inputs.mode != 'validation' && needs.validation.result == 'success' }}" ||
					job.Environment != nil || job.Steps != nil || !strings.Contains(fmt.Sprint(job.Needs), "prepare") || !strings.Contains(fmt.Sprint(job.Needs), "validation") ||
					!reflect.DeepEqual(job.Permissions, map[string]string{"contents": "write", "actions": "read", "id-token": "write", "attestations": "write"}) {
					t.Fatalf("%s must call the same-commit real owner only after protected preparation and the full19 validation barrier", name)
				}
			}
			if !matched {
				t.Fatalf("unreviewed coordinator job %q", name)
			}
			continue
		}
		if job.Environment != nil || job.Uses != "" {
			t.Fatalf("validation/reporting job %q must not have publication authority", name)
		}
		if name == "result" && job.If != "${{ always() && !cancelled() }}" {
			t.Fatal("readonly outcome reporting must run after failed dependencies without ignoring cancellation")
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
		encoded, err := yaml.Marshal(choices.Jobs[name])
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`\bsecrets\s*(?:\.|\[)`).Match(encoded) {
			t.Fatalf("validation/reporting job %s references production credentials", name)
		}
	}
	raw := mustReadWorkflow(t, path)
	for _, dump := range []string{"toJSON(needs)", "toJSON(github)", "toJson(needs)", "toJson(github)"} {
		mustNotContain(t, raw, dump)
	}
	mustContain(t, raw, "name: release-coordinator\n")
	prepare := mustStepNamed(t, mustJob(t, workflow, "prepare"), "Bind source and canonical manifest")
	for _, guard := range []string{
		`case "$MODE" in`, `validation) ;;`, `stage|publish)`,
		`test "$GITHUB_REPOSITORY" = Picocrypt-NG/Picocrypt-NG`, `test "$GITHUB_REF" = refs/heads/main`,
		`test "$GITHUB_EVENT_NAME" = workflow_dispatch`, `test "$GITHUB_WORKFLOW_REF" = Picocrypt-NG/Picocrypt-NG/.github/workflows/release.yml@refs/heads/main`,
		`test "$GITHUB_WORKFLOW_SHA" = "$SOURCE_SHA"`, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`, `version=$(cat VERSION)`, `release-manifest.sh "$version"`,
	} {
		mustContain(t, prepare.Run, guard)
	}
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
			wantOutputs := map[string]string{
				"artifact-id": "${{ steps.build.outputs.artifact-id }}", "artifact-digest": "${{ steps.build.outputs.artifact-digest }}", "run-attempt": "${{ steps.build.outputs.run-attempt }}",
			}
			if tc.action == "build-android" || tc.action == "build-windows" || tc.action == "build-windows-legacy" || tc.action == "build-appimage" {
				for _, output := range []string{"signing-input-id", "signing-input-digest", "signing-input-attempt"} {
					wantOutputs[output] = "${{ steps.build.outputs." + output + " }}"
				}
			}
			if tc.action == "build-appimage" {
				wantOutputs["signing-input-sha256"] = "${{ steps.build.outputs.signing-input-sha256 }}"
			}
			if !reflect.DeepEqual(job.Outputs, wantOutputs) {
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
			if tc.action != "build-linux" {
				wantInputs := map[string]any{"source-sha": "${{ needs.prepare.outputs.source-sha }}", "version": "${{ needs.prepare.outputs.version }}", "manifest-digest": "${{ needs.prepare.outputs.manifest-digest }}"}
				if tc.action == "build-appimage" {
					wantInputs["retain-signing-input"] = "${{ inputs.mode != 'validation' }}"
				}
				if !reflect.DeepEqual(call.With, wantInputs) {
					t.Fatal("native producers may receive only prepared source and the explicit AppImage carrier retention switch")
				}
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
