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

const appimageDirectInvocation = "github.workflow_ref == format('{0}/.github/workflows/build-appimage.yml@{1}', github.repository, github.ref)"

func TestAppImageReusableOwnerSeparatesNativeSigningAttestationAndStage(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/build-appimage.yml")
	var document struct {
		On struct {
			Call struct {
				Inputs  map[string]workflowDispatchInput
				Secrets map[string]struct{ Required bool }
				Outputs map[string]struct{ Value string }
			} `yaml:"workflow_call"`
		} `yaml:"on"`
		Concurrency workflowConcurrency
	}
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		t.Fatal(err)
	}
	if document.Concurrency.Group != "build-appimage-${{ github.ref }}" || document.Concurrency.CancelInProgress != false {
		t.Fatal("callee must neither share caller concurrency nor cancel an active signing generation")
	}
	inputs := []string{"source_sha", "version", "canonical_manifest_sha256", "raw_artifact_id", "raw_artifact_digest", "raw_producing_attempt", "signing_input_id", "signing_input_digest", "signing_input_attempt", "signing_input_sha256"}
	if len(document.On.Call.Inputs) != len(inputs) {
		t.Fatal("require source, raw, signing-carrier tuples and independent tar hash")
	}
	for _, name := range inputs {
		if input := document.On.Call.Inputs[name]; !input.Required || input.Type != "string" {
			t.Fatalf("unbound %s", name)
		}
	}
	if len(document.On.Call.Secrets) != 2 || !document.On.Call.Secrets["APPIMAGE_GPG_PRIVATE_KEY"].Required || !document.On.Call.Secrets["APPIMAGE_GPG_PASSPHRASE"].Required {
		t.Fatal("caller must explicitly map exactly the two existing release environment secret names")
	}
	if len(document.On.Call.Outputs) != 5 {
		t.Fatal("export only real staged/reused/generation values")
	}
	w := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	build := mustJob(t, w, "build")
	if build.If != "${{ "+appimageDirectInvocation+" }}" || build.RunsOn != "ubuntu-22.04" {
		t.Fatal("only direct invocation may run the native producer at the portability floor")
	}
	if mustHaveStepUsingPrefix(t, build, "./.github/actions/build-appimage").With["retain-signing-input"] != "${{ inputs.publish_release }}" {
		t.Fatal("unsigned validation must not retain AppDir signing input by default")
	}
	mustContain(t, mustJob(t, w, "release").If, appimageDirectInvocation)
	inspect, sign, attest, stage := mustJob(t, w, "inspect"), mustJob(t, w, "sign"), mustJob(t, w, "attest"), mustJob(t, w, "stage")
	if inspect.If != "${{ ! ("+appimageDirectInvocation+") }}" {
		t.Fatal("all non-direct callers must reach readonly source rejection")
	}
	if fmt.Sprint(sign.Needs) != "[build inspect]" || fmt.Sprint(attest.Needs) != "sign" || fmt.Sprint(stage.Needs) != "attest" {
		t.Fatal("successful signing/attest dependencies must be retained for failed-only stage retry")
	}
	for name, want := range map[string]map[string]string{
		"inspect": {"contents": "read"}, "sign": {"contents": "read", "actions": "read"},
		"attest": {"contents": "read", "actions": "read", "id-token": "write", "attestations": "write"},
		"stage":  {"contents": "write", "actions": "read"},
	} {
		job := mustJob(t, w, name)
		if !reflect.DeepEqual(job.Permissions, want) {
			t.Fatalf("%s authority=%v", name, job.Permissions)
		}
		if job.Concurrency.Group != "${{ github.repository }}-release-publication" || job.Concurrency.Queue != "max" {
			t.Fatalf("%s must serialize actual full-owner checks/signing/writes", name)
		}
		if job.Steps[0].With["ref"] != "${{ github.sha }}" || job.Steps[0].With["persist-credentials"] != false {
			t.Fatalf("%s must check out exact source without stored credentials", name)
		}
		if mustStepNamed(t, job, "Validate reusable AppImage source").Run != mustStepNamed(t, inspect, "Validate reusable AppImage source").Run {
			t.Fatal("every reusable authority boundary must enforce the same caller/source contract")
		}
		for _, step := range job.Steps {
			if step.Uses == "./.github/actions/build-appimage" || strings.Contains(step.Run, "go build") || strings.Contains(step.Run, "go test") || strings.Contains(step.Run, "linuxdeploy ") {
				t.Fatalf("%s must not rerun native producer", name)
			}
		}
	}
	for _, job := range []workflowJob{sign, attest, stage, mustJob(t, w, "release")} {
		mustContain(t, job.If, "!cancelled()")
		mustContain(t, job.If, ".result == 'success'")
	}
	for _, guard := range []string{"always()", "github.ref == 'refs/heads/main'", "github.event_name == 'workflow_dispatch'", "inputs.publish_release", "needs.build.result == 'success'", "needs.inspect.result == 'success'"} {
		mustContain(t, sign.If, guard)
	}
	for _, job := range []workflowJob{sign, attest} {
		if mustStepNamed(t, job, "Inspect full AppImage owner").Run != mustStepNamed(t, inspect, "Inspect full AppImage owner").Run {
			t.Fatal("GPG and OIDC each require fresh full-owner inspection under publication lock")
		}
	}
	for _, name := range []string{"Verify immutable AppImage raw metadata", "Download AppImage raw artifact", "Verify AppImage raw payload", "Verify AppImage signing-input metadata", "Download same-run signing input", "Check and extract signing input", "Import GPG signing key", "Build signed AppImage", "Verify AppImage signature", "Smoke test AppImage", "Upload signed artifacts"} {
		mustContain(t, mustStepNamed(t, sign, name).If, "steps.inventory.outputs.state == 'missing'")
	}
	if sign.Env["PLATFORM_OWNER"] != "build-appimage.yml" || mustStepNamed(t, sign, "Verify immutable AppImage raw metadata").Run != "bash .github/actions/verify-platform-artifacts/verify-artifacts.sh metadata" {
		t.Fatal("reuse shared single-owner raw validation")
	}
	for _, pair := range []struct {
		job            workflowJob
		name, id, path string
	}{
		{sign, "Download AppImage raw artifact", "${{ inputs.raw_artifact_id }}", "artifacts/build-appimage"},
		{sign, "Download same-run signing input", "${{ inputs.signing_input_id || needs.build.outputs.signing-input-id }}", "signing-input"},
		{attest, "Download verified signed AppImage", "${{ needs.sign.outputs.artifact-id }}", "artifacts"},
		{stage, "Download signed AppImage generation", "${{ needs.attest.outputs.generation-id }}", "signed-generation"},
	} {
		step := mustStepNamed(t, pair.job, pair.name)
		if step.With["artifact-ids"] != pair.id || step.With["path"] != pair.path || step.With["merge-multiple"] != true || step.With["digest-mismatch"] != "error" {
			t.Fatalf("%s must restore only exact immutable transport", pair.name)
		}
	}
	if mustStepNamed(t, sign, "Check and extract signing input").Env["EXPECTED_SHA256"] != "${{ inputs.signing_input_sha256 || needs.build.outputs.signing-input-sha256 }}" {
		t.Fatal("the tar hash must remain separate from its carrier ZIP digest")
	}
	for _, name := range []string{"Verify signed AppImage carrier metadata", "Download verified signed AppImage", "Sign and attest artifacts", "Record signed AppImage generation", "Upload signed AppImage generation"} {
		if mustStepNamed(t, attest, name).If != "${{ steps.inventory.outputs.state == 'missing' }}" {
			t.Fatalf("%s must skip complete owners", name)
		}
	}
	record := mustStepNamed(t, attest, "Record signed AppImage generation")
	if record.Run != "bash .github/actions/signed-generation/generation.sh record" || record.Env["GH_TOKEN"] != "${{ github.token }}" {
		t.Fatal("full generation must use authenticated provenance verification outside the signing action")
	}
	upload := mustStepNamed(t, attest, "Upload signed AppImage generation")
	if upload.With["path"] != "signed-generation/*" || upload.With["overwrite"] != false || upload.With["retention-days"] != 7 {
		t.Fatal("retain immutable full signed bytes before staging")
	}
	if mustStepNamed(t, stage, "Verify signed generation metadata").Run != "bash .github/actions/signed-generation/generation.sh metadata" || mustStepNamed(t, stage, "Restore signed AppImage generation").Run != "bash .github/actions/signed-generation/generation.sh restore" || mustStepNamed(t, stage, "Stage release assets").With["finalize"] != "false" {
		t.Fatal("stage restores the retained generation without signing or publication")
	}
	for _, set := range []struct {
		job         workflowJob
		step, field string
		want        []string
	}{
		{attest, "Sign and attest artifacts", "paths", []string{"artifacts/Picocrypt-NG-${{ inputs.version }}-x86_64.AppImage", "artifacts/Picocrypt-NG-${{ inputs.version }}-x86_64.AppImage.zsync"}},
		{stage, "Stage release assets", "files", []string{"artifacts/Picocrypt-NG-${{ inputs.version }}-x86_64.AppImage", "artifacts/Picocrypt-NG-${{ inputs.version }}-x86_64.AppImage.sigstore.json", "artifacts/Picocrypt-NG-${{ inputs.version }}-x86_64.AppImage.zsync", "artifacts/Picocrypt-NG-${{ inputs.version }}-x86_64.AppImage.zsync.sigstore.json"}},
	} {
		got := strings.Split(strings.TrimSpace(fmt.Sprint(mustStepNamed(t, set.job, set.step).With[set.field])), "\n")
		for i := range got {
			got[i] = strings.TrimSpace(got[i])
		}
		if !reflect.DeepEqual(got, set.want) {
			t.Fatal("retain exactly AppImage and zsync with both Sigstore bundles")
		}
	}
	for _, job := range []workflowJob{sign, attest, stage} {
		if releaseEnvironmentName(job.Environment) != "release" {
			t.Fatal("retain the protected release environment")
		}
	}
}

func TestAppImageReusableOwnerPreservesGPGRecipeAndNativePrefix(t *testing.T) {
	w := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	sign := mustJob(t, w, "sign")
	for name, want := range map[string]string{
		"Check and extract signing input":   "2eb09cd3ab0531cc2d9897b2256e61c9e9546ff98b41e4cead2facdf5073df69",
		"Install packaging dependencies":    "0ea15b78d656f6c2237f68de1164f4f0d99de58ee6d4ab8ab503de5fadd24029",
		"Fetch and verify AppImage tooling": "e9f3f08f562876eed6dd6ffbc48749756d1238580ffe9094b816b80c7ff5442b",
		"Import GPG signing key":            "215918067c4bdae3afc8e1c62bff7d79c090e68afc7e02f5c378375496ffb282",
		"Build signed AppImage":             "7d2a4294b69bd65449a6318702f5bb79f9c201142c6a4095ec7027285504ee03",
		"Remove production signing key":     "5b10af71fdc8fbe2128757427b27537bd718ccbcc2dc7c967fbf2fc9456d4993",
		"Verify AppImage signature":         "3c600f1c869e9ed7e5ebf166284778a629857b8a5963fc56c79892dede39cabe",
		"Smoke test AppImage":               "a46d2d682d44b4005dba51eb2465ba1c5c0544dc32b7042bb08145a4691a3f3c",
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(mustStepNamed(t, sign, name).Run))); got != want {
			t.Fatalf("GPG signing recipe %s changed: %s", name, got)
		}
	}
	if mustStepNamed(t, sign, "Remove production signing key").If != "${{ always() }}" {
		t.Fatal("owned GPG key cleanup must survive failures and cancellation")
	}
	if mustStepNamed(t, sign, "Import GPG signing key").Env["GPG_PRIVATE_KEY"] != "${{ secrets.APPIMAGE_GPG_PRIVATE_KEY }}" || mustStepNamed(t, sign, "Build signed AppImage").Env["APPIMAGETOOL_SIGN_PASSPHRASE"] != "${{ secrets.APPIMAGE_GPG_PASSPHRASE }}" {
		t.Fatal("retain exact step-only existing key/passphrase bindings")
	}
	for _, job := range w.Jobs {
		for _, value := range job.Env {
			if strings.Contains(value, "secrets.") {
				t.Fatal("GPG credentials cannot enter job environment")
			}
		}
		for _, step := range job.Steps {
			if step.Name == "Import GPG signing key" || step.Name == "Build signed AppImage" {
				continue
			}
			for _, value := range step.Env {
				if strings.Contains(value, "secrets.") {
					t.Fatal("GPG secret exposed outside the original two steps")
				}
			}
		}
	}
	var action struct {
		Runs struct{ Steps []map[string]any }
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-appimage/action.yml")), &action); err != nil {
		t.Fatal(err)
	}
	var prefix []map[string]any
	active := false
	for _, step := range action.Runs.Steps {
		if step["name"] == "Setup Go" {
			active = true
		}
		if active {
			delete(step, "shell")
			prefix = append(prefix, step)
		}
		if step["name"] == "Prepare to upload artifacts" {
			break
		}
	}
	data, err := json.Marshal(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "895aa99fb5834fc1a6394aec894319ed287541000341041259ebee4d0ef8f97c" {
		t.Fatalf("unsigned native/tool-pin/smoke prefix changed: %s", got)
	}
}

func TestAppImageReusableSigningCarrierIsOptionalImmutableAndReal(t *testing.T) {
	var action struct {
		Inputs map[string]struct {
			Required bool
			Default  any
		}
		Outputs map[string]struct{ Value string }
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-appimage/action.yml")), &action); err != nil {
		t.Fatal(err)
	}
	option, ok := action.Inputs["retain-signing-input"]
	if !ok || option.Required || option.Default != "false" {
		t.Fatal("AppDir signing retention must be an explicit optional false input")
	}
	for name, want := range map[string]string{"artifact-id": "${{ steps.upload.outputs.artifact-id }}", "artifact-digest": "${{ steps.upload.outputs.artifact-digest }}", "run-attempt": "${{ steps.source.outputs.run-attempt }}", "signing-input-id": "${{ steps.signing-input.outputs.artifact-id }}", "signing-input-digest": "${{ steps.signing-input.outputs.artifact-digest }}", "signing-input-sha256": "${{ steps.prepare-signing-input.outputs.sha256 }}", "signing-input-attempt": "${{ steps.signing-input.outputs.artifact-id && steps.source.outputs.run-attempt || '' }}"} {
		if action.Outputs[name].Value != want {
			t.Fatalf("%s must name the actual producer output", name)
		}
	}
	a := mustReadCompositeActionDoc(t, ".github/actions/build-appimage/action.yml")
	for _, name := range []string{"Prepare signing input", "Upload signing input"} {
		if mustCompositeStepNamed(t, a, name).If != "${{ inputs.retain-signing-input == 'true' }}" {
			t.Fatalf("%s must not run for unsigned validation", name)
		}
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(mustCompositeStepNamed(t, a, "Prepare signing input").Run))); got != "a9ebdcb2572d44bf3a3b1b6a8ed1387ebc09cc8fb8c7c4789751e17b7fd226d8" {
		t.Fatal("move the existing tar/hash producer unchanged")
	}
	upload := mustCompositeStepNamed(t, a, "Upload signing input")
	if upload.With["name"] != "appimage-signing-input-attempt-${{ github.run_attempt }}" || upload.With["path"] != "AppDir.tar" || upload.With["retention-days"] != 7 || upload.With["overwrite"] != false || upload.With["compression-level"] != 0 {
		t.Fatal("signing carrier must survive the generation window without name collisions or recompression")
	}
	for _, step := range mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml"), "build").Steps {
		if step.Name == "Prepare signing input" || step.Name == "Upload signing input" {
			t.Fatal("the real producer must live in the reusable secret-free composite")
		}
	}
}
