package workflowpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

// These are release-policy checks; cryptographic behavior is exercised by appimage-verifier-test.py.
func TestAppImageValidationHasNoSigningOrPublicationAuthority(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	build := mustJob(t, workflow, "build")
	if build.If != "" {
		t.Fatal("unsigned validation must execute on the selected dispatch ref before merge")
	}
	if build.Environment != nil {
		t.Fatalf("unsigned validation can access environment %#v", build.Environment)
	}
	mustEffectivePermission(t, workflow, build, "contents", "read")
	for _, step := range build.Steps {
		for _, text := range append([]string{step.Run, step.Uses}, appImageEnvValues(step.Env)...) {
			for _, forbidden := range []string{"secrets.", "--sign", "sign-and-attest", "stage-release", "signpath"} {
				if strings.Contains(strings.ToLower(text), forbidden) {
					t.Fatalf("unsigned validation step %q contains %q", step.Name, forbidden)
				}
			}
		}
	}
	sign := mustJob(t, workflow, "sign")
	if sign.If != "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release }}" {
		t.Fatalf("production signing guard = %q", sign.If)
	}
	if releaseEnvironmentName(sign.Environment) != "release" {
		t.Fatal("production AppImage signing requires the release environment")
	}
	download := mustStepNamed(t, sign, "Download same-run signing input")
	if download.With["artifact-ids"] != "${{ needs.build.outputs.signing-input-id }}" {
		t.Fatal("signing must consume the exact immutable build artifact ID")
	}
	for _, crossRun := range []string{"github-token", "run-id", "repository", "name", "pattern"} {
		if _, exists := download.With[crossRun]; exists {
			t.Fatalf("same-run signing input must not override %s", crossRun)
		}
	}
	input := mustStepNamed(t, sign, "Check and extract signing input")
	if input.Env["EXPECTED_SHA256"] != "${{ needs.build.outputs.signing-input-sha256 }}" {
		t.Fatal("signing must check the source build's AppDir archive digest")
	}
	mustContain(t, input.Run, `sha256sum --check --strict --status`)
	mustContain(t, input.Run, `.github/scripts/extract-appimage-appdir.py`)
	for _, job := range []workflowJob{build, sign} {
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/checkout@") && step.With["ref"] != nil {
				t.Fatal("AppImage jobs must check out the current workflow source SHA")
			}
		}
	}
	if mustJob(t, workflow, "release").Needs != "sign" {
		t.Fatal("release publication must depend on verified production signing")
	}
}

func TestAppImageProductionTrustPrecedesArtifactPublication(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	sign := mustJob(t, workflow, "sign")
	importKey := mustStepNamed(t, sign, "Import GPG signing key")
	mustContain(t, importKey.Run, `.expected_fingerprint`)
	mustNotContain(t, importKey.Run, `awk -F: '/^fpr:/ {print $10; exit}'`)
	mustContain(t, importKey.Env["GPG_PRIVATE_KEY"], "secrets.APPIMAGE_GPG_PRIVATE_KEY")
	pack := mustStepNamed(t, sign, "Build signed AppImage")
	mustContain(t, pack.Run, `--sign --sign-key "$SIGN_KEY"`)
	mustContain(t, pack.Run, `--runtime-file .appimage-tools/runtime`)
	verify := mustStepNamed(t, sign, "Verify AppImage signature")
	if verify.If != "" || (verify.ContinueOnError != nil && verify.ContinueOnError != false) {
		t.Fatal("cryptographic AppImage verification must be unconditional and blocking")
	}
	mustContain(t, verify.Run, `bash .github/scripts/verify-appimage.sh "$APP"`)
	verified := false
	for _, step := range sign.Steps {
		if step.Name == verify.Name {
			verified = true
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && !verified {
			t.Fatal("production artifact upload precedes cryptographic verification")
		}
	}
	var manifest struct {
		ExpectedFingerprint string `json:"expected_fingerprint"`
	}
	if err := json.Unmarshal([]byte(mustReadRepoFile(t, ".github/toolchains/appimage-verifier/manifest.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	documentation := strings.ReplaceAll(mustReadRepoFile(t, "SIGNING.md"), " ", "")
	mustContain(t, documentation, manifest.ExpectedFingerprint)
}

func appImageEnvValues(env map[string]string) []string {
	values := make([]string, 0, len(env))
	for _, value := range env {
		values = append(values, value)
	}
	return values
}
