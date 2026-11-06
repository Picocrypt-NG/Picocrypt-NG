package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

// These freeze the manual release build contract, not native macOS behavior.
func TestMacOSSharedBuildPreservesProductionStepsAndRelease(t *testing.T) {
	var action struct {
		Runs struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-macos/action.yml")), &action); err != nil {
		t.Fatal(err)
	}
	var frozen []map[string]any
	active := false
	for _, step := range action.Runs.Steps {
		if step["name"] == "Setup Go" {
			active = true
		}
		if active {
			delete(step, "shell")
			frozen = append(frozen, step)
		}
		if step["name"] == "Stage release artifacts" {
			break
		}
	}
	data, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	const wantBuild = "b25188d1ff891b0d0eb0706f8f96aa80b5a281d5b6d728d9613ab297b567e060"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != wantBuild {
		t.Fatalf("macOS native tests, build, compatibility, ad-hoc seal or packaging changed: %s, want %s", got, wantBuild)
	}
	var owner struct {
		Jobs map[string]struct{ Steps []map[string]any }
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/workflows/build-macos.yml")), &owner); err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(owner.Jobs["release"].Steps)
	if err != nil {
		t.Fatal(err)
	}
	// Frozen from the direct owner before reusable jobs were appended.
	const wantRelease = "cfd1ffe51bfa785879f693790bba7c5ba4ca87a5fd1a1a6919fdfdbf49bb13cf"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != wantRelease {
		t.Fatal("direct macOS download, signing identity, release notes or staging program changed")
	}
	release := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml"), "release")
	if release.If != "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release && github.workflow_ref == format('{0}/.github/workflows/build-macos.yml@{1}', github.repository, github.ref) }}" ||
		release.Needs != "build" || release.RunsOn != "ubuntu-24.04" || release.TimeoutMinutes != 20 || release.Environment != "release" ||
		!reflect.DeepEqual(release.Permissions, map[string]string{"contents": "write", "id-token": "write", "attestations": "write"}) ||
		release.Concurrency.Group != "${{ github.repository }}-release-publication" || release.Concurrency.Queue != "max" || release.Env != nil || release.Outputs != nil {
		t.Fatal("direct macOS release must retain its exact invocation guard, authority and publication queue")
	}
}

func TestMacOSSharedBuildHasSourceBoundImmutableInterface(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml")
	build := mustJob(t, workflow, "build")
	if build.If != "${{ github.workflow_ref == format('{0}/.github/workflows/build-macos.yml@{1}', github.repository, github.ref) }}" {
		t.Fatal("direct native macOS build must not run inside a reusable call")
	}
	if build.RunsOn != "macos-26" || build.TimeoutMinutes != 180 || build.Environment != nil ||
		!reflect.DeepEqual(build.Permissions, map[string]string{"contents": "read"}) {
		t.Fatal("manual macOS build must retain its native runner, 180-minute limit and read-only authority")
	}
	if !reflect.DeepEqual(build.Env, map[string]string{
		"MACOSX_DEPLOYMENT_TARGET": "15.0", "CGO_CFLAGS": "-mmacosx-version-min=15.0", "CGO_LDFLAGS": "-mmacosx-version-min=15.0",
	}) {
		t.Fatal("shared macOS build must retain the existing deployment and CGO target")
	}
	call := mustHaveStepUsingPrefix(t, build, "./.github/actions/build-macos")
	if call.ID != "build" || !reflect.DeepEqual(build.Outputs, map[string]string{"artifact-id": "${{ steps.build.outputs.artifact-id }}"}) {
		t.Fatal("manual macOS owner must export only the artifact ID consumed by release")
	}
	if !reflect.DeepEqual(call.With, map[string]any{
		"source-sha": "${{ steps.source.outputs.source-sha }}", "version": "${{ steps.source.outputs.version }}",
		"manifest-digest": "${{ steps.source.outputs.manifest-digest }}",
	}) {
		t.Fatal("shared macOS build must use the prepared source, VERSION and canonical manifest digest")
	}
	bind := mustStepNamed(t, build, "Bind macOS source and canonical manifest")
	if bind.ID != "source" || bind.If != "" || bind.Shell != "bash" || bind.Env["SOURCE_SHA"] != "${{ github.sha }}" {
		t.Fatal("manual macOS source binding must use the immutable event SHA")
	}
	bound := false
	for _, step := range build.Steps {
		if step.ID == bind.ID {
			bound = true
		}
		if step.ID == call.ID && !bound {
			t.Fatal("shared macOS build precedes source binding")
		}
	}
	mustContainInOrder(t, bind.Run, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`, `version=$(cat VERSION)`, `shasum -a 256`)
	action := mustReadCompositeActionDoc(t, ".github/actions/build-macos/action.yml")
	source := mustCompositeStepNamed(t, action, "Assert prepared macOS source")
	if len(action.Runs.Steps) == 0 || action.Runs.Steps[0].Name != source.Name {
		t.Fatal("shared macOS build must verify source and deployment preconditions before dependencies")
	}
	mustContainInOrder(t, source.Run, `test "$SOURCE_SHA" = "$GITHUB_SHA"`, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`,
		`test "$(cat VERSION)" = "$SOURCE_VERSION"`, `release-manifest.sh "$SOURCE_VERSION"`, `test "${actual%% *}" = "$CANONICAL_MANIFEST_SHA256"`)
	for _, precondition := range []string{
		`test "$MACOSX_DEPLOYMENT_TARGET" = 15.0`, `test "$CGO_CFLAGS" = -mmacosx-version-min=15.0`, `test "$CGO_LDFLAGS" = -mmacosx-version-min=15.0`,
	} {
		mustContain(t, source.Run, precondition)
	}
	content := mustReadRepoFile(t, ".github/actions/build-macos/action.yml")
	for _, forbidden := range []string{"secrets.", "sign-and-attest", "release-gate.sh", "notarytool", "security import", "sha256sum", "find -printf"} {
		mustNotContain(t, content, forbidden)
	}
	record := mustCompositeStepNamed(t, action, "Record macOS payload manifest")
	mustContainInOrder(t, record.Run, `arch=$(go env GOARCH)`, `--arg arch "$arch"`)
	var outputs struct {
		Outputs map[string]struct {
			Value string `yaml:"value"`
		} `yaml:"outputs"`
	}
	if err := yaml.Unmarshal([]byte(content), &outputs); err != nil {
		t.Fatal(err)
	}
	if len(outputs.Outputs) != 3 {
		t.Fatal("shared macOS outputs must be limited to the real artifact ID, ZIP digest and producing attempt")
	}
	for _, name := range []string{"artifact-id", "artifact-digest"} {
		if outputs.Outputs[name].Value != "${{ steps.upload.outputs."+name+" }}" {
			t.Fatalf("macOS %s must come directly from the official uploader", name)
		}
	}
	if outputs.Outputs["run-attempt"].Value != "${{ steps.source.outputs.run-attempt }}" {
		t.Fatal("macOS artifact attempt must identify the actual producer")
	}
	upload := mustCompositeStepNamed(t, action, "Upload artifacts")
	if upload.ID != "upload" || upload.With["name"] != "build-macos-attempt-${{ github.run_attempt }}" ||
		upload.With["path"] != "release-staging/" || upload.With["overwrite"] != false ||
		upload.With["retention-days"] != 7 || upload.With["compression-level"] != 9 {
		t.Fatal("macOS upload must retain each immutable attempt with the existing flat staging directory")
	}
	download := mustStepNamed(t, mustJob(t, workflow, "release"), "Download artifact")
	if !reflect.DeepEqual(download.With, map[string]any{
		"artifact-ids": "${{ needs.build.outputs.artifact-id }}", "path": "artifacts/build-macos",
		"merge-multiple": true, "digest-mismatch": "error",
	}) {
		t.Fatal("macOS release must consume the exact same-run ID with a blocking ZIP digest in the existing directory")
	}
}
