package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func androidBuildPolicyJob(t *testing.T, job workflowJob) workflowJob {
	t.Helper()
	call := mustHaveStepUsingPrefix(t, job, "./.github/actions/build-android")
	if call.Uses != "./.github/actions/build-android" || call.If != "" ||
		(call.ContinueOnError != nil && call.ContinueOnError != false) {
		t.Fatal("Android unsigned checks must execute through the registered, blocking composite")
	}
	job.Steps = append(job.Steps, mustReadCompositeActionDoc(t, ".github/actions/build-android/action.yml").Runs.Steps...)
	return job
}

// These freeze the extracted release contract, not Android execution or cryptography.
func TestAndroidSharedBuildPreservesUnsignedPrefixAndSigningBoundary(t *testing.T) {
	var action struct {
		Runs struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-android/action.yml")), &action); err != nil {
		t.Fatal(err)
	}
	var frozen []map[string]any
	active := false
	for _, step := range action.Runs.Steps {
		if step["name"] == "Validate Gradle Wrapper" {
			active = true
		}
		if active {
			delete(step, "shell")
			if step["name"] == "Upload artifacts" {
				step["with"].(map[string]any)["name"] = "build-android-gomobile"
			}
			if step["name"] == "Upload unsigned release APKs" {
				transport := step["with"].(map[string]any)
				transport["name"] = "unsigned-android"
				delete(transport, "overwrite")
			}
			frozen = append(frozen, step)
		}
		if step["name"] == "Upload unsigned release APKs" {
			break
		}
	}
	data, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "a52f7b8e731450f5df1c8375c0075e36b01ec66d759baad2eceb6708704da74d" {
		t.Fatalf("existing unsigned Android commands or signing-input bundle changed: %s", got)
	}
	owner := mustReadRepoFile(t, ".github/workflows/build-android.yml")
	start := strings.Index(owner, "  sign:\n")
	if start < 0 || fmt.Sprintf("%x", sha256.Sum256([]byte(owner[start:]))) != "4a07251f879da3f996919058fee1fc827dda505e8ab9e7acfc61956e75d8ec5e" {
		t.Fatal("Android signing validation, credentials, APK names or publication changed during extraction")
	}
}

func TestAndroidSharedBuildKeepsSigningInputsSeparateFromCanonicalValidation(t *testing.T) {
	build := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-android.yml"), "build")
	if build.If != "" || build.Environment != nil {
		t.Fatal("Android unsigned validation must run without the release environment")
	}
	call := mustHaveStepUsingPrefix(t, build, "./.github/actions/build-android")
	bind := mustStepNamed(t, build, "Bind Android source and canonical manifest")
	if bind.ID != "source" || bind.If != "" || bind.Shell != "bash" || call.ID != "build" || bind.Env["SOURCE_SHA"] != "${{ github.sha }}" {
		t.Fatal("Android source binding and shared build must execute unconditionally")
	}
	bound := false
	for _, step := range build.Steps {
		if step.ID == bind.ID {
			bound = true
		}
		if step.Uses == call.Uses && !bound {
			t.Fatal("Android build precedes its source binding")
		}
	}
	mustContainInOrder(t, bind.Run, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`, `version=$(cat VERSION)`, `release-manifest.sh "$version"`)
	if len(call.With) != 3 {
		t.Fatal("Android build must receive only source, version and canonical manifest bindings")
	}
	for _, name := range []string{"source-sha", "version", "manifest-digest"} {
		if call.With[name] != "${{ steps.source.outputs."+name+" }}" {
			t.Fatalf("Android shared build loses %s binding", name)
		}
	}
	if !reflect.DeepEqual(build.Outputs, map[string]string{
		"artifact-id":     "${{ steps.build.outputs.signing-input-id }}",
		"manifest-sha256": "${{ steps.build.outputs.manifest-sha256 }}",
		"aar-sha256":      "${{ steps.build.outputs.aar-sha256 }}",
		"version":         "${{ steps.build.outputs.version }}",
		"version-code":    "${{ steps.build.outputs.version-code }}",
	}) {
		t.Fatal("Android owner must preserve only its five legacy signing-input output bindings")
	}
	action := mustReadCompositeActionDoc(t, ".github/actions/build-android/action.yml")
	source := mustCompositeStepNamed(t, action, "Assert prepared Android source")
	if action.Runs.Using != "composite" || len(action.Runs.Steps) == 0 || action.Runs.Steps[0].Name != source.Name || source.If != "" ||
		(source.ContinueOnError != nil && source.ContinueOnError != false) {
		t.Fatal("Android composite must reject a wrong source before dependencies")
	}
	for name, input := range map[string]string{"SOURCE_SHA": "source-sha", "SOURCE_VERSION": "version", "CANONICAL_MANIFEST_SHA256": "manifest-digest"} {
		if source.Env[name] != "${{ inputs."+input+" }}" {
			t.Fatalf("Android source assertion loses %s input", input)
		}
	}
	mustContainInOrder(t, source.Run, `test "$SOURCE_SHA" = "$GITHUB_SHA"`, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`,
		`test "$(cat VERSION)" = "$SOURCE_VERSION"`, `release-manifest.sh "$SOURCE_VERSION"`, `test "${actual%% *}" = "$CANONICAL_MANIFEST_SHA256"`)
	var document struct {
		Outputs map[string]struct {
			Value string `yaml:"value"`
		} `yaml:"outputs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-android/action.yml")), &document); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"artifact-id": "${{ steps.upload.outputs.artifact-id }}", "artifact-digest": "${{ steps.upload.outputs.artifact-digest }}",
		"run-attempt": "${{ steps.source.outputs.run-attempt }}", "signing-input-id": "${{ steps.upload-unsigned.outputs.artifact-id }}",
		"manifest-sha256": "${{ steps.prepare-unsigned.outputs.manifest-sha256 }}", "aar-sha256": "${{ steps.prepare-unsigned.outputs.aar-sha256 }}",
		"version": "${{ steps.version.outputs.version }}", "version-code": "${{ steps.version.outputs.version-code }}",
	}
	if len(document.Outputs) != len(want) {
		t.Fatal("Android composite must expose the five existing signing fields and three canonical artifact fields")
	}
	for name, value := range want {
		if document.Outputs[name].Value != value {
			t.Fatalf("Android composite output %s is not bound to its actual producer", name)
		}
	}
	aarUpload := mustCompositeStepNamed(t, action, "Upload artifacts")
	if aarUpload.With["name"] != "build-android-gomobile-attempt-${{ github.run_attempt }}" ||
		aarUpload.With["path"] != "android/app/libs/picocrypt-mobile.aar" || aarUpload.With["overwrite"] == true {
		t.Fatal("the auxiliary AAR upload must not collide with a failed producing attempt")
	}
	signingInput := mustCompositeStepNamed(t, action, "Upload unsigned release APKs")
	if signingInput.ID != "upload-unsigned" || signingInput.Uses != "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" ||
		signingInput.With["name"] != "unsigned-android-attempt-${{ github.run_attempt }}" || signingInput.With["path"] != "unsigned-release/" ||
		signingInput.With["overwrite"] != false || signingInput.With["retention-days"] != 1 {
		t.Fatal("Android signing inputs must keep their payload and retention while using an immutable producing attempt")
	}
	upload := mustCompositeStepNamed(t, action, "Upload Android validation artifacts")
	if upload.ID != "upload" || upload.With["name"] != "validate-android-all-attempt-${{ github.run_attempt }}" ||
		upload.Uses != "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" || upload.With["compression-level"] != 9 ||
		upload.With["path"] != "validation-out/*" || upload.With["overwrite"] != false || upload.With["retention-days"] != 7 {
		t.Fatal("canonical Android validation must retain a separate immutable attempt")
	}
}

func TestAndroidSharedBuildHasNoSigningOrPublicationAuthority(t *testing.T) {
	raw := mustReadRepoFile(t, ".github/actions/build-android/action.yml")
	if regexp.MustCompile(`\bsecrets\s*(?:\.|\[)`).MatchString(raw) {
		t.Fatal("Android unsigned component must not reference secrets")
	}
	for _, forbidden := range []string{"PICOCRYPT_KEYSTORE_", "PICOCRYPT_KEY_PASSWORD", "PICOCRYPT_KEY_ALIAS", "PICOCRYPT_REQUIRE_RELEASE_SIGNING"} {
		mustNotContain(t, raw, forbidden)
	}
	action := mustReadCompositeActionDoc(t, ".github/actions/build-android/action.yml")
	for _, step := range action.Runs.Steps {
		texts := []string{step.Uses}
		for _, value := range step.Env {
			texts = append(texts, value)
		}
		for _, text := range texts {
			for _, forbidden := range []string{"--sign", "sign-and-attest", "stage-release", "signpath"} {
				mustNotContain(t, strings.ToLower(text), forbidden)
			}
		}
		for _, forbidden := range []string{"--sign", "sign-and-attest", "signpath"} {
			mustNotContain(t, strings.ToLower(step.Run), forbidden)
		}
		for _, line := range strings.Split(step.Run, "\n") {
			if !strings.Contains(strings.ToLower(line), "stage-release") {
				continue
			}
			switch strings.TrimSpace(line) {
			case `canonical=$(bash .github/actions/stage-release/release-manifest.sh "$SOURCE_VERSION")`,
				`actual=$(bash .github/actions/stage-release/release-manifest.sh "$SOURCE_VERSION" | sha256sum)`:
			default:
				t.Fatalf("Android unsigned component contains a publication command: %s", line)
			}
		}
	}
}
