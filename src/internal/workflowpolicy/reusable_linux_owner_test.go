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

const linuxDirectInvocation = "github.workflow_ref == format('{0}/.github/workflows/build-linux.yml@{1}', github.repository, github.ref)"

func TestLinuxReusableOwnerKeepsDirectAndSeparatesAuthority(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/build-linux.yml")
	var document struct {
		On struct {
			WorkflowCall struct {
				Inputs  map[string]workflowDispatchInput
				Outputs map[string]struct{ Value string }
			} `yaml:"workflow_call"`
		} `yaml:"on"`
		Concurrency workflowConcurrency `yaml:"concurrency"`
	}
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		t.Fatal(err)
	}
	if document.Concurrency.CancelInProgress != false {
		t.Fatal("a newer call must not cancel an active signing or staging generation")
	}
	if document.Concurrency.Group != "build-linux-${{ github.ref }}" {
		t.Fatal("callee concurrency must not inherit the caller workflow name")
	}
	inputs := []string{"source_sha", "version", "canonical_manifest_sha256", "amd64_artifact_id", "amd64_artifact_digest", "amd64_producing_attempt", "arm64_artifact_id", "arm64_artifact_digest", "arm64_producing_attempt"}
	if len(document.On.WorkflowCall.Inputs) != len(inputs) {
		t.Fatal("reusable owner requires the agreed source and two immutable raw artifact tuples")
	}
	for _, name := range inputs {
		input := document.On.WorkflowCall.Inputs[name]
		if !input.Required || input.Type != "string" {
			t.Fatalf("%s must be a required exact string", name)
		}
	}
	if len(document.On.WorkflowCall.Outputs) != 5 {
		t.Fatal("owner must export only consumed stage/reuse and real generation outputs")
	}
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-linux.yml")
	for _, name := range []string{"prepare", "build-amd64", "build-arm64"} {
		if mustJob(t, workflow, name).If != "${{ "+linuxDirectInvocation+" }}" {
			t.Fatalf("%s could rebuild during a reusable call", name)
		}
	}
	if mustJob(t, workflow, "verify-linux").If != "${{ always() && "+linuxDirectInvocation+" }}" {
		t.Fatal("direct verifier must still fail closed after failed native producers")
	}
	mustContain(t, mustJob(t, workflow, "release").If, linuxDirectInvocation)
	inspect := mustJob(t, workflow, "inspect")
	attest := mustJob(t, workflow, "attest")
	stage := mustJob(t, workflow, "stage")
	if inspect.If != "${{ github.workflow_ref != format('{0}/.github/workflows/build-linux.yml@{1}', github.repository, github.ref) }}" {
		t.Fatal("untrusted non-direct calls must reach readonly rejection rather than silently skip all jobs")
	}
	if !reflect.DeepEqual(inspect.Permissions, map[string]string{"contents": "read"}) {
		t.Fatal("inspection must be readonly")
	}
	if !reflect.DeepEqual(attest.Permissions, map[string]string{"contents": "read", "actions": "read", "id-token": "write", "attestations": "write"}) || attest.Environment != "release" {
		t.Fatal("only attest may receive signing authority under the release environment")
	}
	if !reflect.DeepEqual(stage.Permissions, map[string]string{"contents": "write", "actions": "read"}) || stage.Environment != "release" {
		t.Fatal("stage must have no OIDC or attestation authority")
	}
	if fmt.Sprint(attest.Needs) != "inspect" || fmt.Sprint(stage.Needs) != "attest" {
		t.Fatal("successful inspect/attest outputs must survive a failed-only stage retry")
	}
	for _, job := range []workflowJob{inspect, attest, stage} {
		if job.Concurrency.Group != "${{ github.repository }}-release-publication" || job.Concurrency.Queue != "max" || job.Concurrency.CancelInProgress != nil {
			t.Fatal("remote owner checks, signing and writes must share only the publication job lock")
		}
		if job.Steps[0].With["ref"] != "${{ github.sha }}" || job.Steps[0].With["persist-credentials"] != false {
			t.Fatal("reusable work must use the exact caller checkout")
		}
		mustStepNamed(t, job, "Validate reusable Linux source")
		for _, step := range job.Steps {
			if step.Uses == "./.github/actions/build-linux" || strings.Contains(step.Run, "go build") || strings.Contains(step.Run, "go test") {
				t.Fatal("reusable owner must never run native producers")
			}
		}
	}
	fresh := mustStepNamed(t, attest, "Inspect full Linux owner")
	if fresh.ID != "inventory" || fresh.Run != mustStepNamed(t, inspect, "Inspect full Linux owner").Run {
		t.Fatal("every attest attempt needs fresh full-owner inspection under the same lock")
	}
	for _, name := range []string{"Verify immutable Linux artifact metadata", "Download Linux AMD64 artifact", "Download Linux ARM64 artifact", "Verify Linux payload manifests", "Sign and attest artifacts", "Record signed Linux generation", "Upload signed Linux generation"} {
		step := mustStepNamed(t, attest, name)
		if step.If != "${{ steps.inventory.outputs.state == 'missing' }}" {
			t.Fatalf("%s must skip for fresh complete/partial owner state", name)
		}
	}
	if mustStepNamed(t, attest, "Sign and attest artifacts").Uses != "./.github/actions/sign-and-attest" {
		t.Fatal("owner signing identity must stay in the existing action")
	}
	record := mustStepNamed(t, attest, "Record signed Linux generation")
	if record.ID != "generation" || record.Run != "bash .github/actions/signed-generation/generation.sh record" {
		t.Fatal("full signed generation must use the agreed primitive")
	}
	upload := mustStepNamed(t, attest, "Upload signed Linux generation")
	if upload.ID != "upload-generation" || upload.With["name"] != "${{ steps.generation.outputs.artifact-name }}" || upload.With["path"] != "signed-generation/*" || upload.With["overwrite"] != false || upload.With["retention-days"] != 7 {
		t.Fatal("successful attest must durably retain immutable full signed bytes before staging")
	}
	for name, value := range map[string]string{"generation-id": "${{ steps.upload-generation.outputs.artifact-id }}", "generation-digest": "${{ steps.upload-generation.outputs.artifact-digest }}", "generation-attempt": "${{ steps.generation.outputs.run-attempt }}"} {
		if attest.Outputs[name] != value {
			t.Fatalf("%s must be a real retained output", name)
		}
	}
	var order []string
	for _, step := range stage.Steps {
		switch step.Name {
		case "Verify signed generation metadata", "Download signed Linux generation", "Restore signed Linux generation", "Generate release notes", "Stage release assets":
			order = append(order, step.Name)
		}
	}
	if !reflect.DeepEqual(order, []string{"Verify signed generation metadata", "Download signed Linux generation", "Restore signed Linux generation", "Generate release notes", "Stage release assets"}) {
		t.Fatalf("stage order=%v", order)
	}
	download := mustStepNamed(t, stage, "Download signed Linux generation")
	if download.With["artifact-ids"] != "${{ needs.attest.outputs.generation-id }}" || download.With["digest-mismatch"] != "error" || download.With["merge-multiple"] != true || download.With["path"] != "signed-generation" {
		t.Fatal("stage must restore one exact prior signed generation")
	}
	if mustStepNamed(t, stage, "Verify signed generation metadata").Run != "bash .github/actions/signed-generation/generation.sh metadata" || mustStepNamed(t, stage, "Restore signed Linux generation").Run != "bash .github/actions/signed-generation/generation.sh restore" {
		t.Fatal("stage must verify metadata and bytes without signing")
	}
	staging := mustStepNamed(t, stage, "Stage release assets")
	if staging.Uses != "./.github/actions/stage-release" || staging.With["finalize"] != "false" {
		t.Fatal("reusable owner stages only; it must not finalize")
	}
}

func TestLinuxReusableOwnerPreservesDirectRecipes(t *testing.T) {
	var workflow struct {
		Jobs map[string]map[string]any `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, ".github/workflows/build-linux.yml")), &workflow); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"prepare": "60ce177cd27c86877c79f8f46eed1d37ee28b371fa406484639159de6bcbad71", "build-amd64": "c551fbb0c23441062c73a6feeee6761183d498bc26f9e05f55d79a015694f481", "build-arm64": "231e24538a18849320368e565c2ecb8f08a0676aa84881a36f9237027ff58060", "verify-linux": "c217b34845692279d4d9abf6591ab376330da292c7aa055536896352871bf153", "release": "2791cb407021d7c0bcbbbfae06f224cc51ff1dfc26457db6b30093945c836298"} {
		job := workflow.Jobs[name]
		switch name {
		case "verify-linux":
			job["if"] = "${{ always() }}"
		case "release":
			job["if"] = "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release }}"
		default:
			delete(job, "if")
		}
		data, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			t.Fatalf("direct %s recipe changed beyond invocation gating: %s want%s", name, got, want)
		}
	}
}
