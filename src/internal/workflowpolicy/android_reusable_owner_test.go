package workflowpolicy

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const androidDirectInvocation = "github.workflow_ref == format('{0}/.github/workflows/build-android.yml@{1}', github.repository, github.ref)"

func TestAndroidReusableOwnerSeparatesBuildSigningAttestationAndStage(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/build-android.yml")
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
	if document.Concurrency.Group != "build-android-${{ github.ref }}" || document.Concurrency.CancelInProgress != false {
		t.Fatal("owner scheduling must neither inherit caller concurrency nor cancel active signing")
	}
	inputs := []string{"source_sha", "version", "canonical_manifest_sha256", "raw_artifact_id", "raw_artifact_digest", "raw_producing_attempt", "signing_input_id", "signing_input_digest", "signing_input_attempt"}
	if len(document.On.Call.Inputs) != len(inputs) {
		t.Fatal("require exact source, raw and signing carrier tuples")
	}
	for _, name := range inputs {
		if input := document.On.Call.Inputs[name]; !input.Required || input.Type != "string" {
			t.Fatalf("unbound input %s", name)
		}
	}
	if len(document.On.Call.Secrets) != 4 {
		t.Fatal("only four existing Android key secrets may cross the reusable boundary")
	}
	for _, name := range []string{"ANDROID_KEYSTORE_BASE64", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_PASSWORD", "ANDROID_KEY_ALIAS"} {
		if !document.On.Call.Secrets[name].Required {
			t.Fatalf("caller must explicitly map %s", name)
		}
	}
	if len(document.On.Call.Outputs) != 5 {
		t.Fatal("export only actual staged/reused/generation results")
	}
	w := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	if mustJob(t, w, "build").If != "${{ "+androidDirectInvocation+" }}" {
		t.Fatal("a reusable call must not rebuild Android")
	}
	mustContain(t, mustJob(t, w, "release").If, androidDirectInvocation)
	inspect, sign, attest, stage := mustJob(t, w, "inspect"), mustJob(t, w, "sign"), mustJob(t, w, "attest"), mustJob(t, w, "stage")
	if inspect.If != "${{ ! ("+androidDirectInvocation+") }}" {
		t.Fatal("non-direct calls must reach readonly rejection")
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
			t.Fatalf("%s must share the publication job lock", name)
		}
		if job.Steps[0].With["ref"] != "${{ github.sha }}" || job.Steps[0].With["persist-credentials"] != false {
			t.Fatalf("%s checkout must be exact and credential-free", name)
		}
		mustStepNamed(t, job, "Validate reusable Android source")
		for _, step := range job.Steps {
			if step.Uses == "./.github/actions/build-android" || strings.Contains(step.Run, "gradlew") || strings.Contains(step.Run, "build-gomobile") {
				t.Fatalf("%s must not rebuild native payload", name)
			}
		}
	}
	if fmt.Sprint(sign.Needs) != "[build inspect]" || fmt.Sprint(attest.Needs) != "sign" || fmt.Sprint(stage.Needs) != "attest" {
		t.Fatal("failed-only stage retry must consume the successful signing/attest DAG")
	}
	mustContain(t, sign.If, "always()")
	mustContain(t, sign.If, "!cancelled()")
	mustContain(t, sign.If, "github.ref == 'refs/heads/main'")
	mustContain(t, sign.If, "github.event_name == 'workflow_dispatch'")
	mustContain(t, sign.If, "inputs.publish_release")
	mustContain(t, sign.If, "needs.build.result == 'success'")
	mustContain(t, sign.If, "needs.inspect.result == 'success'")
	for _, job := range []workflowJob{attest, stage, mustJob(t, w, "release")} {
		mustContain(t, job.If, "!cancelled()")
		mustContain(t, job.If, ".result == 'success'")
	}
	for _, job := range []workflowJob{sign, attest} {
		if mustStepNamed(t, job, "Inspect full Android owner").Run != mustStepNamed(t, inspect, "Inspect full Android owner").Run {
			t.Fatal("key and OIDC jobs require the same fresh full-owner check on every attempt")
		}
	}
	for _, name := range []string{"Verify immutable Android raw metadata", "Download Android raw artifact", "Verify Android raw payload", "Verify Android signing-input metadata", "Download source-bound unsigned APKs", "Bind reusable Android signing metadata", "Match raw APKs to signing inputs", "Sign verified APKs with the offline SDK", "Upload signed release APKs"} {
		mustContain(t, mustStepNamed(t, sign, name).If, "steps.inventory.outputs.state == 'missing'")
	}
	if mustStepNamed(t, sign, "Verify immutable Android raw metadata").Run != "bash .github/actions/verify-platform-artifacts/verify-artifacts.sh metadata" || sign.Env["PLATFORM_OWNER"] != "build-android.yml" {
		t.Fatal("raw carrier must use the shared exact-owner verifier")
	}
	for _, pair := range []struct {
		job            workflowJob
		name, id, path string
	}{
		{sign, "Download Android raw artifact", "${{ inputs.raw_artifact_id }}", "artifacts/build-android"},
		{sign, "Download source-bound unsigned APKs", "${{ inputs.signing_input_id || needs.build.outputs.artifact-id }}", "unsigned-release"},
		{attest, "Download verified signed APKs", "${{ needs.sign.outputs.artifact-id }}", "out"},
		{stage, "Download signed Android generation", "${{ needs.attest.outputs.generation-id }}", "signed-generation"},
	} {
		step := mustStepNamed(t, pair.job, pair.name)
		if step.With["artifact-ids"] != pair.id || step.With["path"] != pair.path || step.With["digest-mismatch"] != "error" || step.With["merge-multiple"] != true {
			t.Fatalf("%s must fail closed on exact-ID transport", pair.name)
		}
	}
	for _, name := range []string{"Verify signed APK carrier metadata", "Download verified signed APKs", "Sign and attest artifacts", "Record signed Android generation", "Upload signed Android generation"} {
		if mustStepNamed(t, attest, name).If != "${{ steps.inventory.outputs.state == 'missing' }}" {
			t.Fatalf("%s must skip already staged owners", name)
		}
	}
	if mustStepNamed(t, attest, "Sign and attest artifacts").Uses != "./.github/actions/sign-and-attest" {
		t.Fatal("keep the actual owner signing action")
	}
	if mustStepNamed(t, attest, "Record signed Android generation").Run != "bash .github/actions/signed-generation/generation.sh record" {
		t.Fatal("retain the full signed owner through the existing primitive")
	}
	if mustStepNamed(t, attest, "Record signed Android generation").Env["GH_TOKEN"] != "${{ github.token }}" {
		t.Fatal("generation recording must authenticate its mandatory provenance verification outside the signing action")
	}
	upload := mustStepNamed(t, attest, "Upload signed Android generation")
	if upload.With["path"] != "signed-generation/*" || upload.With["overwrite"] != false || upload.With["retention-days"] != 7 {
		t.Fatal("generation must be immutable and durable before stage")
	}
	if mustStepNamed(t, stage, "Verify signed generation metadata").Run != "bash .github/actions/signed-generation/generation.sh metadata" || mustStepNamed(t, stage, "Restore signed Android generation").Run != "bash .github/actions/signed-generation/generation.sh restore" {
		t.Fatal("stage restores exact signed bytes, never signs")
	}
	if mustStepNamed(t, stage, "Stage release assets").With["finalize"] != "false" {
		t.Fatal("owner stage cannot publish")
	}
	for _, job := range []workflowJob{attest, stage} {
		if job.Env["GENERATION_OWNER"] != "build-android.yml" || job.Env["GENERATION_DIR"] != "signed-generation" {
			t.Fatal("bind the full Android generation")
		}
	}
	for _, job := range []workflowJob{sign, attest, stage} {
		if releaseEnvironmentName(job.Environment) != "release" {
			t.Fatal("retain the protected release environment")
		}
	}
}

func TestAndroidReusableOwnerPreservesNativeSigningAndFiveFinalPairs(t *testing.T) {
	w := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	sign := mustJob(t, w, "sign")
	for _, recipe := range []struct {
		name, sha256 string
	}{
		{
			name:   "Validate unsigned signing inputs before loading secrets",
			sha256: "0dd6339d6be93e9723865593fd00aac7eebaf502102114cbb1305fd1d989ad58",
		},
		{
			name:   "Compile the SDK signing launcher before loading secrets",
			sha256: "0a6097567ab25ad0b01ca9c8910845b88d4e61f21650f04bf73a055a021d1936",
		},
		{
			name:   "Sign verified APKs with the offline SDK",
			sha256: "7cd191598cc942d0125a6bf5d27a1c8630a5f154f9d29a7456772f88b54611d6",
		},
		{
			name:   "Verify exact signed release APK contract",
			sha256: "6b24b2fa4595b06a082d7a3fd20c90f2709129f0781da7f549a0c12edc69cf64",
		},
	} {
		name, want := recipe.name, recipe.sha256
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(mustStepNamed(t, sign, name).Run))); got != want {
			t.Fatalf("native signing recipe %s changed: %s", name, got)
		}
	}
	secret := mustStepNamed(t, sign, "Sign verified APKs with the offline SDK")
	if len(secret.Env) != 4 {
		t.Fatal("credentials must remain scoped to the original signing step")
	}
	for _, name := range []string{"ANDROID_KEYSTORE_BASE64", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_PASSWORD", "ANDROID_KEY_ALIAS"} {
		if secret.Env[name] != "${{ secrets."+name+" }}" {
			t.Fatalf("credential %s lost its exact original binding", name)
		}
	}
	for _, job := range w.Jobs {
		for _, value := range job.Env {
			if strings.Contains(value, "secrets.") {
				t.Fatal("keys must not enter job environment")
			}
		}
		for _, step := range job.Steps {
			if step.Name == secret.Name {
				continue
			}
			for _, value := range step.Env {
				if strings.Contains(value, "secrets.") {
					t.Fatal("keys exposed outside the original native signing step")
				}
			}
		}
	}
	if len(strings.Fields(fmt.Sprint(mustStepNamed(t, mustJob(t, w, "attest"), "Sign and attest artifacts").With["paths"]))) != 5 || len(strings.Fields(fmt.Sprint(mustStepNamed(t, mustJob(t, w, "stage"), "Stage release assets").With["files"]))) != 10 {
		t.Fatal("generation must retain exactly five primary/bundle pairs")
	}
	for _, abi := range []string{"armeabi-v7a", "arm64-v8a", "x86", "x86_64", "universal"} {
		path := "out/Picocrypt-NG-android-" + abi + ".apk"
		mustContain(t, fmt.Sprint(mustStepNamed(t, mustJob(t, w, "attest"), "Sign and attest artifacts").With["paths"]), path)
		mustContain(t, fmt.Sprint(mustStepNamed(t, mustJob(t, w, "stage"), "Stage release assets").With["files"]), path+".sigstore.json")
	}
	var action struct {
		Outputs map[string]struct{ Value string }
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-android/action.yml")), &action); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"signing-input-digest": "${{ steps.upload-unsigned.outputs.artifact-digest }}", "signing-input-attempt": "${{ steps.source.outputs.run-attempt }}"} {
		if action.Outputs[name].Value != value {
			t.Fatalf("signing carrier %s must come from the actual producer", name)
		}
	}
}
