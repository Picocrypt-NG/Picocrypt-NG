package workflowpolicy

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
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
	if fmt.Sprint(sign.Needs) != "[build inspect prepare-signing-tools]" || fmt.Sprint(attest.Needs) != "sign" || fmt.Sprint(stage.Needs) != "attest" {
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
	for _, name := range []string{"Verify immutable AppImage raw metadata", "Download AppImage raw artifact", "Verify AppImage raw payload", "Verify AppImage signing-input metadata", "Download same-run signing input", "Check and extract signing input", "Download locked AppImage signing tools", "Build AppImage signing image before loading secrets", "Build signed AppImage", "Verify AppImage signature", "Smoke test AppImage", "Upload signed artifacts"} {
		if mustStepNamed(t, sign, name).If != "${{ ("+appimageDirectInvocation+") || steps.inventory.outputs.state == 'missing' }}" {
			t.Fatalf("%s must cover both direct signing and a missing reusable owner", name)
		}
	}
	if sign.Env["PLATFORM_OWNER"] != "build-appimage.yml" || mustStepNamed(t, sign, "Verify immutable AppImage raw metadata").Run != "bash .github/actions/verify-platform-artifacts/verify-artifacts.sh metadata" {
		t.Fatal("reuse shared single-owner raw validation")
	}
	for _, pair := range []struct {
		job            workflowJob
		name, id, path string
	}{
		{sign, "Download AppImage raw artifact", "${{ inputs.raw_artifact_id || needs.build.outputs.artifact-id }}", "artifacts/build-appimage"},
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
	if mustStepNamed(t, stage, "Verify signed generation metadata").Run != "bash .github/actions/signed-generation/generation.sh metadata" || mustStepNamed(t, stage, "Restore signed AppImage generation").Run != "bash .github/actions/signed-generation/generation.sh restore" {
		t.Fatal("stage must verify and restore the retained signed generation")
	}
	if mustStepNamed(t, stage, "Stage release assets").Uses != "./.github/actions/stage-release" {
		t.Fatal("owner must upload through the shared draft staging action")
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

func TestAppImageReusableOwnerPreservesGPGRecipe(t *testing.T) {
	w := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	sign := mustJob(t, w, "sign")
	for name, want := range map[string]string{
		"Build signed AppImage":     "ecb8e81484bc55fd3cdb70229b6272be2591c6b86ac682ea5f9daee8f78a8d78",
		"Verify AppImage signature": "d7e37d010ac32bf811404fc8071c268d61aed94129ccff894592337f15a090a0",
		"Smoke test AppImage":       "a46d2d682d44b4005dba51eb2465ba1c5c0544dc32b7042bb08145a4691a3f3c",
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(mustStepNamed(t, sign, name).Run))); got != want {
			t.Fatalf("GPG signing recipe %s changed: %s", name, got)
		}
	}
	container := mustReadRepoFile(t, ".github/scripts/sign-appimage.sh")
	mustContainInOrder(t, container, "set +x", "umask 077", "mktemp -d", "run-release-signing-container.sh", "mv -T --no-clobber")
	sandbox := mustReadRepoFile(t, ".github/scripts/run-release-signing-container.sh")
	mustContainInOrder(t, sandbox, "docker create", "--pull never", "--network none", "--read-only", "--log-driver none", "docker start --attach --interactive")
	mustContain(t, sandbox, "docker rm --force")
	signStep := mustStepNamed(t, sign, "Build signed AppImage")
	if len(signStep.Env) != 2 || signStep.Env["GPG_PRIVATE_KEY"] != "${{ secrets.APPIMAGE_GPG_PRIVATE_KEY }}" || signStep.Env["APPIMAGETOOL_SIGN_PASSPHRASE"] != "${{ secrets.APPIMAGE_GPG_PASSPHRASE }}" {
		t.Fatal("retain the exact key and passphrase bindings only in the signing step")
	}
	for _, job := range w.Jobs {
		for _, value := range job.Env {
			if strings.Contains(value, "secrets.") {
				t.Fatal("GPG credentials cannot enter job environment")
			}
		}
		for _, step := range job.Steps {
			if step.Name == signStep.Name {
				continue
			}
			for _, value := range step.Env {
				if strings.Contains(value, "secrets.") {
					t.Fatal("GPG secret exposed outside the isolated signing step")
				}
			}
		}
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
