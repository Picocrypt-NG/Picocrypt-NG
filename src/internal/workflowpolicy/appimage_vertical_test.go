package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"go.yaml.in/yaml/v4"
)

// These checks cover the shared production path and signing authority boundaries.
func TestAppImageSharedBuildPreservesProductionStepsAndSigningBoundary(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/build-appimage/action.yml")
	prepare := mustCompositeStepNamed(t, action, "Prepare verified AppImage build materials")
	mustContainInOrder(t, prepare.Run,
		`bash .github/scripts/prepare-release-go.sh linux-amd64 "$work"`,
		`bash .github/scripts/prepare-appimage-release.sh "$work"`,
	)
	for _, name := range []string{"Build GUI", "Build AppImage"} {
		step := mustCompositeStepNamed(t, action, name)
		if step.Shell != "bash .github/scripts/run-appimage-release-build.sh {0}" || step.If != "" ||
			step.ContinueOnError == true {
			t.Fatalf("%s must run unconditionally in the locked offline image", name)
		}
	}
	pack := mustCompositeStepNamed(t, action, "Build AppImage")
	if pack.Env["APPIMAGE_EXTRACT_AND_RUN"] != "1" {
		t.Fatal("AppImage packaging must run without FUSE")
	}
	mustContainInOrder(t, pack.Run, `"$APPIMAGE_TOOLS/linuxdeploy"`, `"$APPIMAGE_TOOLS/appimagetool"`, `--runtime-file "$APPIMAGE_TOOLS/runtime"`)
	var owner struct {
		Jobs map[string]struct{ Steps []map[string]any }
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/workflows/build-appimage.yml")), &owner); err != nil {
		t.Fatal(err)
	}
	// Keep the authenticated signing and staging recipes fixed outside the input boundary.
	for _, recipe := range []struct {
		job   string
		names []string
		want  string
	}{
		{"sign", []string{"Check and extract signing input", "Download locked AppImage signing tools", "Build AppImage signing image before loading secrets", "Build signed AppImage", "Verify AppImage signature", "Smoke test AppImage"}, "3e3f41a2cddd2ca6f125debc17b5d73e80557fe0b468626533d2721d55bb934c"},
		{"release", []string{"Get version tag", "Sign and attest artifacts", "Generate release notes", "Stage release assets"}, "9ef0b33106724f81330a6791c46dfbc2b2b6b8db2eaf3fa1cbb8e6dea86cc813"},
	} {
		var selected []map[string]any
		for _, step := range owner.Jobs[recipe.job].Steps {
			name, _ := step["name"].(string)
			if !slices.Contains(recipe.names, name) {
				continue
			}
			if recipe.job == "sign" {
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
		"source-sha":            "${{ steps.source.outputs.source-sha }}",
		"version":               "${{ steps.source.outputs.version }}",
		"manifest-digest":       "${{ steps.source.outputs.manifest-digest }}",
		"artifact-id":           "${{ steps.build.outputs.artifact-id }}",
		"artifact-digest":       "${{ steps.build.outputs.artifact-digest }}",
		"run-attempt":           "${{ steps.build.outputs.run-attempt }}",
		"signing-input-id":      "${{ steps.build.outputs.signing-input-id }}",
		"signing-input-sha256":  "${{ steps.build.outputs.signing-input-sha256 }}",
		"signing-input-digest":  "${{ steps.build.outputs.signing-input-digest }}",
		"signing-input-attempt": "${{ steps.build.outputs.signing-input-attempt }}",
	}) {
		t.Fatal("direct owner must export the prepared source and both exact producer artifact tuples")
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
