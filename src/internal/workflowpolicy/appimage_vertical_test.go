package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

// These checks freeze the extracted release contract, not product cryptography.
func TestAppImageSharedBuildPreservesProductionStepsAndSigningBoundary(t *testing.T) {
	var action struct {
		Runs struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-appimage/action.yml")), &action); err != nil {
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
		if step["name"] == "Prepare to upload artifacts" {
			break
		}
	}
	data, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	const wantBuild = "895aa99fb5834fc1a6394aec894319ed287541000341041259ebee4d0ef8f97c"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != wantBuild {
		t.Fatalf("unsigned AppImage production steps changed: %s, want %s", got, wantBuild)
	}
	prepare := mustCompositeStepNamed(t, mustReadCompositeActionDoc(t, ".github/actions/build-appimage/action.yml"), "Prepare signing input")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(prepare.Run))); got != "a9ebdcb2572d44bf3a3b1b6a8ed1387ebc09cc8fb8c7c4789751e17b7fd226d8" {
		t.Fatal("the moved AppDir tar/hash producer changed")
	}
	var owner struct {
		Jobs map[string]struct{ Steps []map[string]any }
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/workflows/build-appimage.yml")), &owner); err != nil {
		t.Fatal(err)
	}
	// Original 3b0851a native recipes stay frozen independently of the reusable routing.
	for _, recipe := range []struct {
		job   string
		names []string
		want  string
	}{
		{"sign", []string{"Check and extract signing input", "Install packaging dependencies", "Fetch and verify AppImage tooling", "Import GPG signing key", "Build signed AppImage", "Remove production signing key", "Verify AppImage signature", "Smoke test AppImage"}, "79c3ecd0d0e84480aa69dd5b591a16af16eb7049184385f1e9094bbefac3786c"},
		{"release", []string{"Get version tag", "Sign and attest artifacts", "Generate release notes", "Stage release assets"}, "9ef0b33106724f81330a6791c46dfbc2b2b6b8db2eaf3fa1cbb8e6dea86cc813"},
	} {
		var selected []map[string]any
		for _, step := range owner.Jobs[recipe.job].Steps {
			name, _ := step["name"].(string)
			if !slices.Contains(recipe.names, name) {
				continue
			}
			if recipe.job == "sign" && name != "Remove production signing key" {
				if step["if"] != "${{ ("+appimageDirectInvocation+") || steps.inventory.outputs.state == 'missing' }}" {
					t.Fatalf("native AppImage %s lost direct/fresh-signing gating", name)
				}
				delete(step, "if")
				if name == "Check and extract signing input" {
					env := step["env"].(map[string]any)
					if env["EXPECTED_SHA256"] != "${{ inputs.signing_input_sha256 || needs.build.outputs.signing-input-sha256 }}" {
						t.Fatal("AppDir tar hash must remain source-bound for both invocations")
					}
					env["EXPECTED_SHA256"] = "${{ needs.build.outputs.signing-input-sha256 }}"
				}
			}
			selected = append(selected, step)
		}
		if len(selected) != len(recipe.names) {
			t.Fatalf("missing or duplicate native AppImage %s steps", recipe.job)
		}
		data, err := json.Marshal(selected)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != recipe.want {
			t.Fatalf("native AppImage %s recipe changed: %s", recipe.job, got)
		}
	}
}

func TestAppImageSharedBuildExportsSourceBoundImmutableArtifact(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	build := mustJob(t, workflow, "build")
	call := mustHaveStepUsingPrefix(t, build, "./.github/actions/build-appimage")
	bind := mustStepNamed(t, build, "Bind AppImage source and canonical manifest")
	if bind.ID != "source" || bind.If != "" || bind.Shell != "bash" {
		t.Fatal("AppImage source binding must execute before the shared build")
	}
	bound := false
	for _, step := range build.Steps {
		if step.ID == bind.ID {
			bound = true
		}
		if step.Uses == call.Uses && !bound {
			t.Fatal("shared AppImage build precedes prepared source binding")
		}
	}
	mustContainInOrder(t, bind.Run, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`, `version=$(cat VERSION)`, `release-manifest.sh "$version"`)
	for _, name := range []string{"source-sha", "version", "manifest-digest"} {
		if call.With[name] != "${{ steps.source.outputs."+name+" }}" {
			t.Fatalf("AppImage owner loses prepared %s binding", name)
		}
	}
	if !reflect.DeepEqual(build.Outputs, map[string]string{
		"signing-input-id":      "${{ steps.build.outputs.signing-input-id }}",
		"signing-input-sha256":  "${{ steps.build.outputs.signing-input-sha256 }}",
		"signing-input-digest":  "${{ steps.build.outputs.signing-input-digest }}",
		"signing-input-attempt": "${{ steps.build.outputs.signing-input-attempt }}",
	}) {
		t.Fatal("direct owner must export the real composite signing tuple and tar hash")
	}
	action := mustReadCompositeActionDoc(t, ".github/actions/build-appimage/action.yml")
	source := mustCompositeStepNamed(t, action, "Assert prepared AppImage source")
	if len(action.Runs.Steps) == 0 || action.Runs.Steps[0].Name != source.Name {
		t.Fatal("shared AppImage build must reject a wrong source before dependencies")
	}
	mustContainInOrder(t, source.Run, `test "$SOURCE_SHA" = "$GITHUB_SHA"`, `test "$(git rev-parse HEAD)" = "$SOURCE_SHA"`,
		`test "$(cat VERSION)" = "$SOURCE_VERSION"`, `release-manifest.sh "$SOURCE_VERSION"`, `test "${actual%% *}" = "$CANONICAL_MANIFEST_SHA256"`)
	var outputs struct {
		Outputs map[string]struct {
			Value string `yaml:"value"`
		} `yaml:"outputs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-appimage/action.yml")), &outputs); err != nil {
		t.Fatal(err)
	}
	if len(outputs.Outputs) != 7 {
		t.Fatal("shared AppImage outputs must contain the canonical tuple plus separate signing tuple and tar hash")
	}
	for _, name := range []string{"artifact-id", "artifact-digest"} {
		if outputs.Outputs[name].Value != "${{ steps.upload.outputs."+name+" }}" {
			t.Fatalf("AppImage %s must come directly from the official uploader", name)
		}
	}
	if outputs.Outputs["run-attempt"].Value != "${{ steps.source.outputs.run-attempt }}" {
		t.Fatal("AppImage artifact attempt must identify the actual producer")
	}
	for name, value := range map[string]string{"signing-input-id": "${{ steps.signing-input.outputs.artifact-id }}", "signing-input-digest": "${{ steps.signing-input.outputs.artifact-digest }}", "signing-input-sha256": "${{ steps.prepare-signing-input.outputs.sha256 }}", "signing-input-attempt": "${{ steps.signing-input.outputs.artifact-id && steps.source.outputs.run-attempt || '' }}"} {
		if outputs.Outputs[name].Value != value {
			t.Fatalf("signing output %s must identify its actual producer", name)
		}
	}
	upload := mustCompositeStepNamed(t, action, "Upload artifacts")
	if upload.ID != "upload" || upload.With["name"] != "validate-appimage-amd64-attempt-${{ github.run_attempt }}" ||
		upload.With["overwrite"] != false || upload.With["retention-days"] != 7 || upload.With["compression-level"] != 0 {
		t.Fatal("AppImage validation must retain each immutable attempt without recompressing SquashFS")
	}
}
