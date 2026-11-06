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
	if build.If != "${{ "+appimageDirectInvocation+" }}" {
		t.Fatal("direct unsigned validation must execute on the dispatch ref without reusable rebuilding")
	}
	if build.Environment != nil {
		t.Fatalf("unsigned validation can access environment %#v", build.Environment)
	}
	mustEffectivePermission(t, workflow, build, "contents", "read")
	build.Steps = append(build.Steps, mustReadCompositeActionDoc(t, ".github/actions/build-appimage/action.yml").Runs.Steps...)
	for _, step := range build.Steps {
		for index, text := range append([]string{step.Run, step.Uses}, appImageEnvValues(step.Env)...) {
			for _, forbidden := range []string{"secrets.", "--sign", "sign-and-attest", "stage-release", "signpath"} {
				if strings.Contains(strings.ToLower(text), forbidden) {
					if forbidden == "stage-release" && index == 0 && appImageReadsOnlyOwnershipManifest(text) {
						continue
					}
					t.Fatalf("unsigned validation step %q contains %q", step.Name, forbidden)
				}
			}
		}
	}
	sign := mustJob(t, workflow, "sign")
	if sign.If != "${{ always() && !cancelled() && (("+appimageDirectInvocation+" && github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release && needs.build.result == 'success') || (! ("+appimageDirectInvocation+") && needs.inspect.result == 'success' && needs.inspect.outputs.state != 'complete')) }}" {
		t.Fatalf("production signing guard = %q", sign.If)
	}
	if releaseEnvironmentName(sign.Environment) != "release" {
		t.Fatal("production AppImage signing requires the release environment")
	}
	download := mustStepNamed(t, sign, "Download same-run signing input")
	if download.With["artifact-ids"] != "${{ inputs.signing_input_id || needs.build.outputs.signing-input-id }}" || download.With["digest-mismatch"] != "error" || download.With["merge-multiple"] != true {
		t.Fatal("signing must consume the exact source-bound immutable carrier ID for either invocation")
	}
	for _, crossRun := range []string{"github-token", "run-id", "repository", "name", "pattern"} {
		if _, exists := download.With[crossRun]; exists {
			t.Fatalf("same-run signing input must not override %s", crossRun)
		}
	}
	input := mustStepNamed(t, sign, "Check and extract signing input")
	if input.Env["EXPECTED_SHA256"] != "${{ inputs.signing_input_sha256 || needs.build.outputs.signing-input-sha256 }}" {
		t.Fatal("signing must check the source-bound AppDir tar digest separately from the carrier ZIP digest")
	}
	mustContain(t, input.Run, `sha256sum --check --strict --status`)
	mustContain(t, input.Run, `.github/scripts/extract-appimage-appdir.py`)
	for _, job := range []workflowJob{build, sign} {
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/checkout@") && (step.With["ref"] != "${{ github.sha }}" || step.With["persist-credentials"] != false) {
				t.Fatal("AppImage jobs must check out the exact workflow source SHA without stored credentials")
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
	whenSigning := "${{ (" + appimageDirectInvocation + ") || steps.inventory.outputs.state == 'missing' }}"
	if verify.If != whenSigning || importKey.If != whenSigning || pack.If != whenSigning || mustStepNamed(t, sign, "Upload signed artifacts").If != whenSigning ||
		(verify.ContinueOnError != nil && verify.ContinueOnError != false) {
		t.Fatal("cryptographic AppImage verification must block every fresh signing and upload; complete-owner reuse skips them together")
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

func TestAppImageManifestReadDoesNotPermitPublicationCommands(t *testing.T) {
	read := `canonical=$(bash .github/actions/stage-release/release-manifest.sh "$SOURCE_VERSION")`
	gate := `bash .github/actions/stage-release/release-gate.sh upload 3.0`
	for _, tc := range []struct {
		name, run string
		wantRead  bool
	}{
		{"canonical read", read, true},
		{"source digest read", `actual=$(bash .github/actions/stage-release/release-manifest.sh "$SOURCE_VERSION" | sha256sum)`, true},
		{"owner digest read", `digest=$(bash .github/actions/stage-release/release-manifest.sh "$version" | sha256sum)`, true},
		{"gate", gate, false},
		{"gate appended to read", read + "; " + gate, false},
		{"gate after read", read + "\n" + gate, false},
		{"publication action", "./.github/actions/stage-release", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := appImageReadsOnlyOwnershipManifest(tc.run); got != tc.wantRead {
				t.Fatalf("read-only ownership command = %v, want %v", got, tc.wantRead)
			}
		})
	}
}

func appImageReadsOnlyOwnershipManifest(run string) bool {
	read := false
	for _, line := range strings.Split(run, "\n") {
		if !strings.Contains(strings.ToLower(line), "stage-release") {
			continue
		}
		switch strings.TrimSpace(line) {
		case `canonical=$(bash .github/actions/stage-release/release-manifest.sh "$SOURCE_VERSION")`,
			`actual=$(bash .github/actions/stage-release/release-manifest.sh "$SOURCE_VERSION" | sha256sum)`,
			`digest=$(bash .github/actions/stage-release/release-manifest.sh "$version" | sha256sum)`:
			read = true
		default:
			return false
		}
	}
	return read
}

func appImageEnvValues(env map[string]string) []string {
	values := make([]string, 0, len(env))
	for _, value := range env {
		values = append(values, value)
	}
	return values
}
