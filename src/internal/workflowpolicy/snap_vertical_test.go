package workflowpolicy

import (
	"reflect"
	"testing"

	"go.yaml.in/yaml/v4"
)

// These are packaging-transfer and release-policy checks, not product coverage.
func TestSnapcraftSharedBuildSignsOnlyAfterLockedVMBuild(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/build-snapcraft/action.yml")
	build := mustCompositeStepNamed(t, action, "Build and smoke-test Snap in the locked VM")
	if build.If != "" || build.ContinueOnError != nil || build.Env["SOURCE_VERSION"] != "${{ inputs.version }}" ||
		build.Run != `bash .github/scripts/build-snap-release.sh "$RUNNER_TEMP/picocrypt-snap-release" "$SOURCE_VERSION"` {
		t.Fatal("the unsigned Snap producer must use the locked VM and its installed-snap check")
	}
	mustContainInOrder(t, mustReadRepoFile(t, ".github/actions/build-snapcraft/action.yml"),
		"Assert prepared Snap source", build.Name, "Record Snap payload manifest", "Upload .snap artifacts")
	mustContain(t, mustReadRepoFile(t, ".github/scripts/build-snap-release.sh"), "restrict=on")
	mustContainInOrder(t, mustReadRepoFile(t, ".github/scripts/build-snap-release-guest.sh"),
		"snap install", "--dangerous", "snap run picocrypt-ng --version")

	release := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml"), "release")
	if release.If != "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release && github.workflow_ref == format('{0}/.github/workflows/build-snapcraft.yml@{1}', github.repository, github.ref) }}" ||
		release.Needs != "build-snapcraft" || release.RunsOn != "ubuntu-24.04" || release.TimeoutMinutes != 20 || release.Environment != "release" ||
		!reflect.DeepEqual(release.Permissions, map[string]string{"contents": "write", "actions": "read", "id-token": "write", "attestations": "write"}) ||
		release.Concurrency.Group != "${{ github.repository }}-release-publication" || release.Concurrency.Queue != "max" || release.Outputs != nil {
		t.Fatal("direct Snap release must retain the invocation guard, publication queue and only the authority it needs")
	}
}

func TestDirectSnapReleaseVerifiesSourceBoundPayloadBeforeSigning(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	release, attest := mustJob(t, workflow, "release"), mustJob(t, workflow, "attest")
	order := []string{"Verify immutable Snap artifact metadata", "Download Snap raw artifact", "Verify Snap payload manifest", "Prepare canonical Snap signing path", "Sign and attest artifacts"}
	var actual []string
	for _, step := range release.Steps {
		for _, name := range order {
			if step.Name == name {
				if step.If != "" || (step.ContinueOnError != nil && step.ContinueOnError != false) {
					t.Fatalf("%s must block direct release on failure", name)
				}
				actual = append(actual, name)
			}
		}
	}
	if !reflect.DeepEqual(actual, order) {
		t.Fatalf("direct Snap release must verify its raw carrier before signing, got %v", actual)
	}
	for _, name := range []string{order[0], order[2], order[3]} {
		if direct, reusable := mustStepNamed(t, release, name), mustStepNamed(t, attest, name); direct.Run != reusable.Run {
			t.Fatalf("%s must use the same program in direct and reusable Snap release", name)
		}
	}
}

func TestSnapcraftSharedBuildHasSourceBoundImmutableInterface(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	build := mustJob(t, workflow, "build-snapcraft")
	if build.If != "${{ github.workflow_ref == format('{0}/.github/workflows/build-snapcraft.yml@{1}', github.repository, github.ref) }}" {
		t.Fatal("direct native Snapcraft build must not run inside a reusable call")
	}
	if build.RunsOn != "ubuntu-24.04" || build.TimeoutMinutes != 90 || build.Environment != nil ||
		!reflect.DeepEqual(build.Permissions, map[string]string{"contents": "read"}) {
		t.Fatal("Snapcraft unsigned owner must preserve its runner, 90-minute limit and read-only authority")
	}
	coordinated := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "build-snapcraft")
	if coordinated.RunsOn != build.RunsOn || coordinated.TimeoutMinutes != build.TimeoutMinutes ||
		!reflect.DeepEqual(coordinated.Permissions, build.Permissions) {
		t.Fatal("direct and coordinated Snap producers must use the same pinned host runner, timeout and read-only authority")
	}
	call := mustHaveStepUsingPrefix(t, build, "./.github/actions/build-snapcraft")
	if call.ID != "build" || !reflect.DeepEqual(build.Outputs, map[string]string{
		"artifact-id":     "${{ steps.build.outputs.artifact-id }}",
		"artifact-digest": "${{ steps.build.outputs.artifact-digest }}",
		"run-attempt":     "${{ steps.build.outputs.run-attempt }}",
		"source-sha":      "${{ steps.source.outputs.source-sha }}",
		"version":         "${{ steps.source.outputs.version }}",
		"manifest-digest": "${{ steps.source.outputs.manifest-digest }}",
	}) {
		t.Fatal("Snap owner must carry the source and immutable artifact tuple to release")
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
	download := mustStepNamed(t, mustJob(t, workflow, "release"), "Download Snap raw artifact")
	if !reflect.DeepEqual(download.With, map[string]any{
		"artifact-ids": "${{ needs.build-snapcraft.outputs.artifact-id }}", "path": "artifacts/build-snapcraft",
		"merge-multiple": true, "digest-mismatch": "error",
	}) {
		t.Fatal("Snapcraft release must consume the exact same-run ID with a blocking ZIP digest in the existing directory")
	}
}
