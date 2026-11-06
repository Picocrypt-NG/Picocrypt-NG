package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestMacosSnapReusableOwnersSeparateRawAttestAndRetainedStage(t *testing.T) {
	for _, tc := range []struct{ owner, label, arch, build string }{
		{"build-macos", "macOS", "arm64", "build"},
		{"build-snapcraft", "Snap", "amd64", "build-snapcraft"},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			path := ".github/workflows/" + tc.owner + ".yml"
			var document struct {
				On struct {
					Call struct {
						Inputs  map[string]workflowDispatchInput
						Outputs map[string]struct{ Value string }
					} `yaml:"workflow_call"`
				} `yaml:"on"`
				Concurrency workflowConcurrency `yaml:"concurrency"`
			}
			if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, path)), &document); err != nil {
				t.Fatal(err)
			}
			if document.Concurrency.Group != tc.owner+"-${{ github.ref }}" || document.Concurrency.CancelInProgress != false {
				t.Fatal("owner concurrency must be static and preserve retained outputs")
			}
			inputs := []string{"source_sha", "version", "canonical_manifest_sha256", "raw_artifact_id", "raw_artifact_digest", "raw_producing_attempt"}
			if len(document.On.Call.Inputs) != len(inputs) || len(document.On.Call.Outputs) != 5 {
				t.Fatal("single-carrier owner must expose only the agreed reusable interface")
			}
			for _, name := range inputs {
				input := document.On.Call.Inputs[name]
				if !input.Required || input.Type != "string" {
					t.Fatalf("%s must be a required string", name)
				}
			}
			workflow := mustReadWorkflowDoc(t, path)
			direct := fmt.Sprintf("github.workflow_ref == format('{0}/.github/workflows/%s.yml@{1}', github.repository, github.ref)", tc.owner)
			if mustJob(t, workflow, tc.build).If != "${{ "+direct+" }}" {
				t.Fatal("reusable invocation must not run a native producer")
			}
			if mustJob(t, workflow, "release").If != "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release && "+direct+" }}" {
				t.Fatal("direct publication must retain its original main/dispatch/publish guard")
			}
			inspect, attest, stage := mustJob(t, workflow, "inspect"), mustJob(t, workflow, "attest"), mustJob(t, workflow, "stage")
			if inspect.If != "${{ "+strings.Replace(direct, " == ", " != ", 1)+" }}" {
				t.Fatal("non-direct callers must reach the readonly source rejection")
			}
			if !reflect.DeepEqual(inspect.Permissions, map[string]string{"contents": "read"}) || !reflect.DeepEqual(attest.Permissions, map[string]string{"contents": "read", "actions": "read", "id-token": "write", "attestations": "write"}) || !reflect.DeepEqual(stage.Permissions, map[string]string{"contents": "write", "actions": "read"}) {
				t.Fatal("inspection, attestation and staging authority must remain separated")
			}
			if attest.Needs != "inspect" || stage.Needs != "attest" || attest.Environment != "release" || stage.Environment != "release" {
				t.Fatal("successful attest outputs must be retained before stage-only retry")
			}
			for _, job := range []workflowJob{inspect, attest, stage} {
				if job.Concurrency.Group != "${{ github.repository }}-release-publication" || job.Concurrency.Queue != "max" {
					t.Fatal("all owner decisions must hold the common publication job lock")
				}
				if job.Steps[0].With["ref"] != "${{ github.sha }}" || job.Steps[0].With["persist-credentials"] != false {
					t.Fatal("reusable jobs require exact source checkout")
				}
				mustStepNamed(t, job, "Validate reusable "+tc.label+" source")
				for _, step := range job.Steps {
					if step.Uses == "./.github/actions/"+tc.owner || strings.Contains(step.Run, "go build") || strings.Contains(step.Run, "snapcraft ") || strings.Contains(step.Run, "codesign") {
						t.Fatal("reusable path cannot rebuild or add native Apple signing")
					}
				}
			}
			fresh := mustStepNamed(t, attest, "Inspect full "+tc.label+" owner")
			if fresh.Run != mustStepNamed(t, inspect, fresh.Name).Run || fresh.ID != "inventory" {
				t.Fatal("every attest attempt must freshly inspect the complete owner under lock")
			}
			for _, name := range []string{"Verify immutable " + tc.label + " artifact metadata", "Download " + tc.label + " raw artifact", "Verify " + tc.label + " payload manifest", "Sign and attest artifacts", "Record signed " + tc.label + " generation", "Upload signed " + tc.label + " generation"} {
				if mustStepNamed(t, attest, name).If != "${{ steps.inventory.outputs.state == 'missing' }}" {
					t.Fatalf("%s must skip complete/partial owners", name)
				}
			}
			if attest.Env["PLATFORM_OWNER"] != tc.owner+".yml" {
				t.Fatal("single-carrier verification must select its actual owner")
			}
			text := attest.Env["PLATFORM_ARTIFACTS_JSON"]
			for key, value := range map[string]string{"raw_artifact_id": "101", "raw_artifact_digest": strings.Repeat("1", 64), "raw_producing_attempt": "1"} {
				text = strings.ReplaceAll(text, "${{ inputs."+key+" }}", value)
			}
			var descriptors []map[string]any
			if err := json.Unmarshal([]byte(text), &descriptors); err != nil {
				t.Fatal(err)
			}
			want := []map[string]any{{"owner": tc.owner + ".yml", "arch": tc.arch, "id": float64(101), "digest": strings.Repeat("1", 64), "attempt": float64(1)}}
			if !reflect.DeepEqual(descriptors, want) {
				t.Fatal("raw descriptor must bind the one real carrier without aliases")
			}
			if mustStepNamed(t, attest, "Verify immutable "+tc.label+" artifact metadata").Run != "bash .github/actions/verify-platform-artifacts/verify-artifacts.sh metadata" || mustStepNamed(t, attest, "Verify "+tc.label+" payload manifest").Run != "bash .github/actions/verify-platform-artifacts/verify-artifacts.sh payload" {
				t.Fatal("raw trust must use the existing platform verifier")
			}
			download := mustStepNamed(t, attest, "Download "+tc.label+" raw artifact")
			if download.With["artifact-ids"] != "${{ inputs.raw_artifact_id }}" || download.With["path"] != "artifacts/"+tc.owner || download.With["digest-mismatch"] != "error" || download.With["merge-multiple"] != true {
				t.Fatal("raw bytes require one official exact-ID download")
			}
			upload := mustStepNamed(t, attest, "Upload signed "+tc.label+" generation")
			if mustStepNamed(t, attest, "Record signed "+tc.label+" generation").Env["GH_TOKEN"] != "${{ github.token }}" {
				t.Fatal("online generation verification must receive the scoped GitHub token")
			}
			if upload.ID != "upload-generation" || upload.With["name"] != "${{ steps.generation.outputs.artifact-name }}" || upload.With["retention-days"] != 7 || upload.With["overwrite"] != false {
				t.Fatal("signed generation must be immutable and retained before staging")
			}
			for output, value := range map[string]string{"generation-id": "${{ steps.upload-generation.outputs.artifact-id }}", "generation-digest": "${{ steps.upload-generation.outputs.artifact-digest }}", "generation-attempt": "${{ steps.generation.outputs.run-attempt }}"} {
				if attest.Outputs[output] != value {
					t.Fatal("generation outputs must come from actual record/uploader steps")
				}
			}
			var order []string
			for _, step := range stage.Steps {
				switch step.Name {
				case "Verify signed generation metadata", "Download signed " + tc.label + " generation", "Restore signed " + tc.label + " generation", "Generate release notes", "Stage release assets":
					order = append(order, step.Name)
				}
			}
			if !reflect.DeepEqual(order, []string{"Verify signed generation metadata", "Download signed " + tc.label + " generation", "Restore signed " + tc.label + " generation", "Generate release notes", "Stage release assets"}) {
				t.Fatal("stage must restore the full verified generation before any upload")
			}
			if mustStepNamed(t, stage, "Stage release assets").With["finalize"] != "false" {
				t.Fatal("reusable owner must not publish")
			}
		})
	}
}

func TestMacosSnapReusableOwnersPreserveDirectRecipes(t *testing.T) {
	for _, tc := range []struct {
		owner  string
		hashes map[string]string
	}{
		{"build-macos", map[string]string{"build": "e36f8f228015cdc984784298eb767d9e1c8d8f2bb3feb500ecb2b5321acb3095", "release": "5f371d3e529ccc9073bde3d5e499d94fa48c72464f4e4f7b80ea994c959f6393"}},
		{"build-snapcraft", map[string]string{"build-snapcraft": "89225ca8aa281b6df6215be7b822950158d7c44e54bd03393c4f268e31269867", "release": "602ac93216c1fd0d95d4213fcb0d3fe0985ebd8682a71ba5d3d62516d4852143"}},
	} {
		var document struct {
			Jobs map[string]map[string]any `yaml:"jobs"`
		}
		if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, ".github/workflows/"+tc.owner+".yml")), &document); err != nil {
			t.Fatal(err)
		}
		for name, want := range tc.hashes {
			job := document.Jobs[name]
			delete(job, "if")
			data, err := json.Marshal(job)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
				t.Fatalf("direct %s/%s changed beyond invocation gating: %s", tc.owner, name, got)
			}
		}
	}
}
