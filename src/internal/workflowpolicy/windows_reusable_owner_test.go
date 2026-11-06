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

func windowsReusableOwners() []string { return []string{"build-windows", "build-windows-legacy"} }

func TestWindowsReusableOwnerSeparatesDirectSigningAttestationAndStaging(t *testing.T) {
	for _, owner := range windowsReusableOwners() {
		t.Run(owner, func(t *testing.T) {
			path := ".github/workflows/" + owner + ".yml"
			var doc struct {
				On struct {
					Call struct {
						Inputs  map[string]workflowDispatchInput   `yaml:"inputs"`
						Secrets map[string]struct{ Required bool } `yaml:"secrets"`
						Outputs map[string]struct{ Value string }  `yaml:"outputs"`
					} `yaml:"workflow_call"`
				} `yaml:"on"`
				Concurrency workflowConcurrency `yaml:"concurrency"`
			}
			if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, path)), &doc); err != nil {
				t.Fatal(err)
			}
			wantInputs := []string{"source_sha", "version", "canonical_manifest_sha256", "raw_artifact_id", "raw_artifact_digest", "raw_producing_attempt", "signing_input_id", "signing_input_digest", "signing_input_attempt"}
			if len(doc.On.Call.Inputs) != len(wantInputs) {
				t.Fatal("owner needs source and two immutable input tuples")
			}
			for _, key := range wantInputs {
				if v := doc.On.Call.Inputs[key]; !v.Required || v.Type != "string" {
					t.Fatalf("required string %s", key)
				}
			}
			if len(doc.On.Call.Secrets) != 1 || !doc.On.Call.Secrets["SIGNPATH_API_TOKEN"].Required {
				t.Fatal("callee must declare only the existing SignPath token")
			}
			if len(doc.On.Call.Outputs) != 5 {
				t.Fatal("only real stage/reuse and generation outputs")
			}
			if doc.Concurrency.Group != owner+"-${{ github.ref }}" || doc.Concurrency.CancelInProgress != false {
				t.Fatal("callee must not inherit/cancel the coordinator concurrency group")
			}
			workflow := mustReadWorkflowDoc(t, path)
			direct := "github.workflow_ref == format('{0}/.github/workflows/" + owner + ".yml@{1}', github.repository, github.ref)"
			if mustJob(t, workflow, "build").If != "${{ "+direct+" }}" {
				t.Fatal("reusable owner may not rebuild")
			}
			inspect, sign, attest, stage := mustJob(t, workflow, "inspect"), mustJob(t, workflow, "sign"), mustJob(t, workflow, "attest"), mustJob(t, workflow, "stage")
			if !reflect.DeepEqual(inspect.Permissions, map[string]string{"contents": "read"}) {
				t.Fatal("inspection must be readonly")
			}
			if !reflect.DeepEqual(sign.Permissions, map[string]string{"contents": "read", "actions": "read"}) || sign.Environment != "release" {
				t.Fatal("SignPath must stay protected without OIDC or repository write")
			}
			if !reflect.DeepEqual(attest.Permissions, map[string]string{"contents": "read", "actions": "read", "id-token": "write", "attestations": "write"}) || attest.Environment != "release" {
				t.Fatal("only attest may obtain OIDC")
			}
			if !reflect.DeepEqual(stage.Permissions, map[string]string{"contents": "write", "actions": "read"}) || stage.Environment != "release" {
				t.Fatal("stage must have no signing authority")
			}
			if fmt.Sprint(sign.Needs) != "[build inspect]" || !strings.Contains(sign.If, "always()") || !strings.Contains(sign.If, "needs.build.result == 'success'") || !strings.Contains(sign.If, "needs.inspect.result == 'success'") {
				t.Fatal("both direct and reusable prerequisites must fail closed across skipped branches")
			}
			if fmt.Sprint(attest.Needs) != "sign" || fmt.Sprint(stage.Needs) != "attest" {
				t.Fatal("failed-only stage retry must retain successful signing and attestation outputs")
			}
			for _, job := range []workflowJob{inspect, sign, attest, stage} {
				if job.Concurrency.Group != "${{ github.repository }}-release-publication" || job.Concurrency.Queue != "max" {
					t.Fatal("fresh inspections and writes must share the publication lock")
				}
				mustStepNamed(t, job, "Validate reusable Windows source")
				if job.Env["OWNER_WORKFLOW"] != owner+".yml" || job.Env["SOURCE_SHA"] != "${{ inputs.source_sha }}" {
					t.Fatal("source and owner env must bind the agreed helpers")
				}
			}
			for _, job := range []workflowJob{inspect, sign, attest} {
				mustStepNamed(t, job, "Inspect full Windows owner")
			}
			if sign.Env["PLATFORM_OWNER"] != owner+".yml" || attest.Env["GENERATION_OWNER"] != owner+".yml" || stage.Env["GENERATION_OWNER"] != owner+".yml" {
				t.Fatal("shared verifier/generation owner selectors must be exact")
			}
			for _, job := range []workflowJob{attest, stage, mustJob(t, workflow, "release")} {
				if !strings.Contains(job.If, "always()") || !strings.Contains(job.If, "result == 'success'") {
					t.Fatal("skipped branch ancestors must not suppress required successor jobs")
				}
			}
			for _, name := range []string{"Verify immutable Windows input metadata", "Download Windows validation artifact", "Verify Windows validation payload", "Validate Windows signing carrier", "Require SignPath token"} {
				mustStepNamed(t, sign, name)
			}
			for _, step := range sign.Steps {
				if strings.HasPrefix(step.Uses, "signpath/") && !strings.Contains(step.If, "steps.inventory.outputs.state == 'missing'") {
					t.Fatal("fresh complete reuse must skip every SignPath request")
				}
			}
			for _, step := range attest.Steps {
				if strings.Contains(step.Run, "SignPath") || strings.HasPrefix(step.Uses, "signpath/") {
					t.Fatal("Ubuntu must consume the verified OS-signed carrier, never native-sign again")
				}
			}
			if mustStepNamed(t, attest, "Sign and attest artifacts").Uses != "./.github/actions/sign-and-attest" {
				t.Fatal("owner SAN must remain in existing signing action")
			}
			if !strings.Contains(mustStepNamed(t, attest, "Record signed Windows generation").Run, "generation.sh record") {
				t.Fatal("full signed generation must use existing P5 primitive")
			}
			for _, job := range []workflowJob{attest, stage} {
				for _, step := range job.Steps {
					if strings.Contains(step.Uses, "download-artifact@") && (step.With["digest-mismatch"] != "error" || step.With["merge-multiple"] != true || step.With["artifact-ids"] == nil) {
						t.Fatal("exact immutable downloads must fail on digest mismatch")
					}
				}
			}
			if strings.Contains(stage.If, "generation-id") {
				t.Fatal("missing successful generation outputs must fail metadata validation, not silently skip")
			}
			if mustStepNamed(t, stage, "Stage release assets").With["finalize"] != "false" {
				t.Fatal("owner stages but never finalizes")
			}
			for _, step := range stage.Steps {
				if step.Uses == "./.github/actions/sign-and-attest" || strings.HasPrefix(step.Uses, "signpath/") {
					t.Fatal("stage retry must never re-sign")
				}
			}
			carrier := mustStepNamed(t, sign, "Upload OS-signed Windows carrier")
			if carrier.With["name"] != "os-signed-"+owner+"-attempt-${{ github.run_attempt }}" || carrier.With["overwrite"] != false || carrier.With["retention-days"] != 7 {
				t.Fatal("OS-signed carrier must be immutable and retained")
			}
			for _, name := range []string{"artifact-id", "artifact-digest"} {
				if sign.Outputs["os-signed-"+strings.TrimPrefix(name, "artifact-")] != "${{ steps.upload-os-signed.outputs."+name+" }}" {
					t.Fatal("OS-signed outputs must identify the official carrier")
				}
			}
			metadata := mustReadRepoFile(t, ".github/actions/"+owner+"/action.yml")
			mustContain(t, metadata, "signing-input-digest:")
			mustContain(t, metadata, "${{ steps.signing-input.outputs.artifact-digest }}")
			mustContain(t, metadata, "signing-input-attempt:")
		})
	}
}

// This freeze protects SignPath policy, all Authenticode checks, and the current
// export/sign/import installer chain while invocation conditions change around it.
func TestWindowsReusablePreservesExistingSignPathPrograms(t *testing.T) {
	want := map[string]string{"build-windows": "83e4c07ee6e1c624458cf1f0b9d7e7b4872d0bd66e9ed846a6476a4ef48bcb69", "build-windows-legacy": "d8b2cdccb2bb0d528c857cab20107cab18c3d0883a3d236ed481c9c7772b4a3b"}
	for _, owner := range windowsReusableOwners() {
		job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/"+owner+".yml"), "sign")
		var steps []workflowStep
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "signpath/") || (step.Shell == "pwsh" && step.Name != "Reject conflicting SignPath modes" && step.Name != "Require SignPath token") || strings.HasPrefix(step.ID, "upload-signpath-") {
				step.If = ""
				if strings.HasPrefix(step.ID, "upload-signpath-") {
					original := map[string]string{"upload-signpath-binaries": "signpath-windows-binaries", "upload-signpath-uninstaller": "signpath-windows-uninstaller", "upload-signpath-installer": "signpath-windows-installer", "upload-signpath-legacy": "signpath-windows-legacy"}[step.ID]
					if !strings.Contains(fmt.Sprint(step.With["name"]), "'"+original+"'") || !strings.Contains(fmt.Sprint(step.With["name"]), "-attempt-{0}") {
						t.Fatal("reusable SignPath transport must be per-attempt while DIRECT names stay frozen")
					}
					step.With["name"] = original
				}
				steps = append(steps, step)
			}
		}
		data, err := json.Marshal(steps)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want[owner] {
			t.Errorf("%s native signing recipe hash=%s want%s", owner, got, want[owner])
		}
	}
}

func TestWindowsReusablePinsNativeGHWithoutChangingLinuxDefault(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/setup-gh/action.yml")
	windows := mustCompositeStepNamed(t, action, "Install checksum-locked Windows GitHub CLI")
	if windows.Shell != "pwsh" || windows.If != "${{ runner.os == 'Windows' }}" {
		t.Fatal("Windows CLI install must be explicit")
	}
	for _, value := range []string{"Get-FileHash", "SHA256", "windows_amd64.zip", "Expand-Archive", "GITHUB_PATH"} {
		mustContain(t, windows.Run, value)
	}
	linux := mustCompositeStepNamed(t, action, "Install checksum-locked GitHub CLI")
	if linux.If != "${{ runner.os != 'Windows' }}" {
		t.Fatal("Linux installer must remain the default")
	}
	var pin struct {
		Version, URL, SHA256 string
		Windows              struct{ URL, SHA256 string }
	}
	if err := json.Unmarshal([]byte(mustReadRepoFile(t, ".github/toolchains/github-cli.json")), &pin); err != nil {
		t.Fatal(err)
	}
	if pin.SHA256 != "77b9e297e94c50336823d0f84de7ef1be60cba704601fa0d98f129f47a94987b" || pin.Windows.SHA256 != "843c0dc119f014d9458aeaff96c44c16fc4b8e556c1c4c5df9bab5ba002356e9" {
		t.Fatal("CLI downloads must match independently checked official archives")
	}
}
