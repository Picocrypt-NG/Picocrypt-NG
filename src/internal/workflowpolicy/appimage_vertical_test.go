package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
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
	owner := mustReadRepoFile(t, ".github/workflows/build-appimage.yml")
	start := strings.Index(owner, "    - name: Prepare signing input\n")
	const wantSigning = "029b56c5f3df455b5018e6f51e5d537fbc3e1f480d7ddb460a0a405e45b732e0"
	if start < 0 || fmt.Sprintf("%x", sha256.Sum256([]byte(owner[start:]))) != wantSigning {
		t.Fatal("AppDir handoff, signing or release publication changed during unsigned extraction")
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
		"signing-input-id":     "${{ steps.signing-input.outputs.artifact-id }}",
		"signing-input-sha256": "${{ steps.prepare-signing-input.outputs.sha256 }}",
	}) {
		t.Fatal("unsigned extraction must preserve the existing signing input outputs")
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
	if len(outputs.Outputs) != 3 {
		t.Fatal("shared AppImage outputs must be limited to the real artifact ID, ZIP digest and attempt")
	}
	for _, name := range []string{"artifact-id", "artifact-digest"} {
		if outputs.Outputs[name].Value != "${{ steps.upload.outputs."+name+" }}" {
			t.Fatalf("AppImage %s must come directly from the official uploader", name)
		}
	}
	if outputs.Outputs["run-attempt"].Value != "${{ steps.source.outputs.run-attempt }}" {
		t.Fatal("AppImage artifact attempt must identify the actual producer")
	}
	upload := mustCompositeStepNamed(t, action, "Upload artifacts")
	if upload.ID != "upload" || upload.With["name"] != "validate-appimage-amd64-attempt-${{ github.run_attempt }}" ||
		upload.With["overwrite"] != false || upload.With["retention-days"] != 7 || upload.With["compression-level"] != 0 {
		t.Fatal("AppImage validation must retain each immutable attempt without recompressing SquashFS")
	}
}
