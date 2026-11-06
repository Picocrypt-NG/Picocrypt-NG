package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

// These are packaging-transfer and release-policy checks, not product coverage.
func TestSnapcraftSharedBuildPreservesProductionStepsAndRelease(t *testing.T) {
	var action struct {
		Runs struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-snapcraft/action.yml")), &action); err != nil {
		t.Fatal(err)
	}
	var frozen []map[string]any
	active := false
	for _, step := range action.Runs.Steps {
		if step["name"] == "Copy Snapcraft files to source" {
			active = true
		}
		if active {
			delete(step, "shell")
			frozen = append(frozen, step)
		}
		if step["name"] == "Smoke-test snap command" {
			break
		}
	}
	data, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	const wantBuild = "61cd070d88e74e7d9a37370232699c20b61883d45dde7234c2aeff9c1cef0949"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != wantBuild {
		t.Fatalf("Snapcraft production build or installed-snap smoke changed: %s, want %s", got, wantBuild)
	}
	var owner struct {
		Jobs map[string]struct{ Steps []map[string]any }
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/workflows/build-snapcraft.yml")), &owner); err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(owner.Jobs["release"].Steps)
	if err != nil {
		t.Fatal(err)
	}
	// Frozen from the direct owner before reusable jobs were appended.
	const wantRelease = "b508f2dcc810ebea7d64fd233230461900dcdc3f852fedc42e5410e581169ab7"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != wantRelease {
		t.Fatal("direct Snapcraft download, signing identity, release notes or staging program changed")
	}
	release := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml"), "release")
	if release.If != "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release && github.workflow_ref == format('{0}/.github/workflows/build-snapcraft.yml@{1}', github.repository, github.ref) }}" ||
		release.Needs != "build-snapcraft" || release.RunsOn != "ubuntu-24.04" || release.TimeoutMinutes != 20 || release.Environment != "release" ||
		!reflect.DeepEqual(release.Permissions, map[string]string{"contents": "write", "id-token": "write", "attestations": "write"}) ||
		release.Concurrency.Group != "${{ github.repository }}-release-publication" || release.Concurrency.Queue != "max" || release.Env != nil || release.Outputs != nil {
		t.Fatal("direct Snapcraft release must retain its exact invocation guard, authority and publication queue")
	}
}

func TestSnapcraftSharedBuildHasSourceBoundImmutableInterface(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	build := mustJob(t, workflow, "build-snapcraft")
	if build.If != "${{ github.workflow_ref == format('{0}/.github/workflows/build-snapcraft.yml@{1}', github.repository, github.ref) }}" {
		t.Fatal("direct native Snapcraft build must not run inside a reusable call")
	}
	if build.RunsOn != "ubuntu-latest" || build.TimeoutMinutes != 90 || build.Environment != nil ||
		!reflect.DeepEqual(build.Permissions, map[string]string{"contents": "read"}) {
		t.Fatal("Snapcraft unsigned owner must preserve its runner, 90-minute limit and read-only authority")
	}
	call := mustHaveStepUsingPrefix(t, build, "./.github/actions/build-snapcraft")
	if call.ID != "build" || !reflect.DeepEqual(build.Outputs, map[string]string{"artifact-id": "${{ steps.build.outputs.artifact-id }}"}) {
		t.Fatal("Snapcraft owner must export only the artifact ID used by release")
	}
	if !reflect.DeepEqual(call.With, map[string]any{
		"source-sha": "${{ steps.source.outputs.source-sha }}", "version": "${{ steps.source.outputs.version }}",
		"manifest-digest": "${{ steps.source.outputs.manifest-digest }}",
	}) {
		t.Fatal("Snapcraft shared build must use the prepared source, VERSION and canonical manifest digest")
	}
	bind := mustStepNamed(t, build, "Bind Snap source and canonical manifest")
	if bind.ID != "source" || bind.If != "" || bind.Shell != "bash" || bind.Env["SOURCE_SHA"] != "${{ github.sha }}" {
		t.Fatal("Snapcraft source binding must use the immutable event SHA")
	}
	bound := false
	for _, step := range build.Steps {
		if step.ID == bind.ID {
			bound = true
		}
		if step.ID == call.ID && !bound {
			t.Fatal("Snapcraft shared build precedes prepared source binding")
		}
	}
	mustContainInOrder(t, bind.Run, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`, `version=$(cat VERSION)`, `release-manifest.sh "$version"`)
	action := mustReadCompositeActionDoc(t, ".github/actions/build-snapcraft/action.yml")
	source := mustCompositeStepNamed(t, action, "Assert prepared Snap source")
	if len(action.Runs.Steps) == 0 || action.Runs.Steps[0].Name != source.Name {
		t.Fatal("Snapcraft must verify the source before copying or building")
	}
	mustContainInOrder(t, source.Run, `test "$SOURCE_SHA" = "$GITHUB_SHA"`, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`,
		`test "$(cat VERSION)" = "$SOURCE_VERSION"`, `release-manifest.sh "$SOURCE_VERSION"`, `test "${actual%% *}" = "$CANONICAL_MANIFEST_SHA256"`)
	content := mustReadRepoFile(t, ".github/actions/build-snapcraft/action.yml")
	for _, forbidden := range []string{"secrets.", "sign-and-attest", "release-gate.sh", "id-token:", "attestations:"} {
		mustNotContain(t, content, forbidden)
	}
	var outputs struct {
		Outputs map[string]struct {
			Value string `yaml:"value"`
		} `yaml:"outputs"`
	}
	if err := yaml.Unmarshal([]byte(content), &outputs); err != nil {
		t.Fatal(err)
	}
	if len(outputs.Outputs) != 3 {
		t.Fatal("Snapcraft composite must expose only the real artifact ID, ZIP digest and producing attempt")
	}
	for _, name := range []string{"artifact-id", "artifact-digest"} {
		if outputs.Outputs[name].Value != "${{ steps.upload.outputs."+name+" }}" {
			t.Fatalf("Snapcraft %s must come directly from the official uploader", name)
		}
	}
	if outputs.Outputs["run-attempt"].Value != "${{ steps.source.outputs.run-attempt }}" {
		t.Fatal("Snapcraft artifact attempt must identify the actual producer")
	}
	upload := mustCompositeStepNamed(t, action, "Upload .snap artifacts")
	if upload.ID != "upload" || upload.With["name"] != "build-snapcraft-attempt-${{ github.run_attempt }}" ||
		upload.With["overwrite"] != false || upload.With["retention-days"] != 7 || upload.With["compression-level"] != 9 {
		t.Fatal("Snapcraft upload must retain each immutable attempt with the existing compression setting")
	}
	download := mustStepNamed(t, mustJob(t, workflow, "release"), "Download .snap artifacts")
	if !reflect.DeepEqual(download.With, map[string]any{
		"artifact-ids": "${{ needs.build-snapcraft.outputs.artifact-id }}", "path": "out",
		"merge-multiple": true, "digest-mismatch": "error",
	}) {
		t.Fatal("Snapcraft release must consume the exact same-run ID with a blocking ZIP digest in the existing directory")
	}
}
