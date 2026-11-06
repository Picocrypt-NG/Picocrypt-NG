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

type windowsBuildCase struct {
	owner, first, prefix, tail, bundle, directory string
	files                                         []string
}

func windowsBuildCases() []windowsBuildCase {
	return []windowsBuildCase{
		{"build-windows", "Setup Go", "d0c09d24bbdcec224f7fc42a0f6a5f6544684ae8d3fa5d71d3cb218ce1abb795", "eab8ad617ed324ddfd0acf30399cf0ea776fe74b0cea0a211349a18bad0130ae", "unsigned-windows", "validation-windows-current", []string{"Picocrypt-NG-portable.exe", "Picocrypt-NG-cli.exe", "Picocrypt-NG-Setup.exe"}},
		{"build-windows-legacy", "Build patched Go 1.27.3 for Windows 7/8", "bf6c359c6e8d0d31e461554f9cb3bbc176e2179f86c240af531deb288a874336", "ee7207156c7599fe450a6500325af133af5aaa0c1b72fe407246fb6dc9742b09", "unsigned-windows-legacy", "validation-windows-legacy", []string{"Picocrypt-NG-cli-Legacy.exe"}},
	}
}

func windowsBuildPolicyJob(t *testing.T, path, name string) workflowJob {
	t.Helper()
	job := mustJob(t, mustReadWorkflowDoc(t, path), name)
	if name != "build" || (path != ".github/workflows/build-windows.yml" && path != ".github/workflows/build-windows-legacy.yml") {
		return job
	}
	owner := strings.TrimSuffix(strings.TrimPrefix(path, ".github/workflows/"), ".yml")
	producer := mustStepNamed(t, job, "Build unsigned Windows artifacts")
	if producer.Uses != "./.github/actions/"+owner || producer.If != "" || producer.ContinueOnError != nil {
		t.Fatal("Windows policy must follow the registered, blocking unsigned producer")
	}
	job.Steps = mustReadCompositeActionDoc(t, ".github/actions/"+owner+"/action.yml").Runs.Steps
	return job
}

func windowsBuildPolicyContent(t *testing.T, path string) string {
	t.Helper()
	if path != ".github/workflows/build-windows.yml" && path != ".github/workflows/build-windows-legacy.yml" {
		return mustReadWorkflow(t, path)
	}
	windowsBuildPolicyJob(t, path, "build")
	owner := strings.TrimSuffix(strings.TrimPrefix(path, ".github/workflows/"), ".yml")
	return mustReadRepoFile(t, ".github/actions/"+owner+"/action.yml")
}

func TestWindowsBuildExtractionPreservesUnsignedSteps(t *testing.T) {
	for _, tc := range windowsBuildCases() {
		t.Run(tc.owner, func(t *testing.T) {
			var action struct {
				Runs struct {
					Steps []map[string]any `yaml:"steps"`
				} `yaml:"runs"`
			}
			if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/"+tc.owner+"/action.yml")), &action); err != nil {
				t.Fatal(err)
			}
			var frozen []map[string]any
			active := false
			for _, step := range action.Runs.Steps {
				name, _ := step["name"].(string)
				active = active || name == tc.first
				if !active {
					continue
				}
				if _, run := step["run"]; run {
					if step["shell"] != "pwsh" {
						t.Fatal("moved Windows build commands must keep PowerShell execution")
					}
					implicit := name == "Install dependencies" || name == "Build GUI" || name == "Build CLI-only (no graphics dependencies)" || name == "Build CLI-only legacy binary" || (tc.owner == "build-windows" && name == "Run tests")
					if implicit {
						delete(step, "shell")
					}
					env, _ := step["env"].(map[string]any)
					remove := func(key, want string) {
						if env[key] != want {
							t.Fatalf("%s must bind the existing public %s value", name, key)
						}
						delete(env, key)
					}
					if tc.owner == "build-windows-legacy" {
						remove("GOTOOLCHAIN", "local")
						remove("GOEXPERIMENT", "")
						if name != "Build CLI-only legacy binary" {
							remove("GOAMD64", "v1")
						}
					}
					if name == "Compress with upx" {
						remove("UPX_SHA256", "eabc6792a347d45e945be7748423e7868fd01b0d2bcaa2f4b1031fd71ff69bda")
					}
					if name == "Add icon, manifest, and version info" {
						remove("RESHACKER_SHA256", "b611be2f35cb44efd1c29df03e7ebe62bd556a500585680e1afa5e073eaf1756")
					}
					if len(env) == 0 {
						delete(step, "env")
					}
				}
				if name == "Upload artifact" {
					with := step["with"].(map[string]any)
					if step["id"] != "signing-input" || with["name"] != tc.bundle+"-attempt-${{ github.run_attempt }}" || with["overwrite"] != false {
						t.Fatal("signing-input carrier must be immutable and distinct per attempt")
					}
					delete(step, "id")
					delete(with, "overwrite")
					with["name"] = tc.bundle
				}
				frozen = append(frozen, step)
				if name == "Upload artifact" {
					break
				}
			}
			data, err := json.Marshal(frozen)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != tc.prefix {
				t.Fatalf("unsigned Windows build/signing-input steps changed: %s, want %s", got, tc.prefix)
			}
		})
	}
}

func TestWindowsSigningReleaseChainRemainsByteIdentical(t *testing.T) {
	for _, tc := range windowsBuildCases() {
		content := mustReadWorkflow(t, ".github/workflows/"+tc.owner+".yml")
		start := strings.Index(content, "  sign:\n")
		path := "unsigned-build"
		if tc.owner == "build-windows-legacy" {
			path = "unsigned-legacy"
		}
		binding := "        artifact-ids: ${{ needs.build.outputs.signing-input-id }}\n        path: " + path + "\n        merge-multiple: true\n        digest-mismatch: error"
		original := "        name: " + tc.bundle + "\n        path: " + path
		if start < 0 || strings.Count(content[start:], binding) != 1 {
			t.Fatal("signing must download the real input bundle by exact ID with blocking digest checks")
		}
		normalized := strings.Replace(content[start:], binding, original, 1)
		if fmt.Sprintf("%x", sha256.Sum256([]byte(normalized))) != tc.tail {
			t.Fatalf("%s SignPath/NSIS/release chain changed during unsigned extraction", tc.owner)
		}
	}
}

func TestWindowsValidationArtifactsStaySeparateFromSigningInputs(t *testing.T) {
	for _, tc := range windowsBuildCases() {
		t.Run(tc.owner, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, ".github/workflows/"+tc.owner+".yml")
			job := mustJob(t, workflow, "build")
			if !reflect.DeepEqual(job.Outputs, map[string]string{"signing-input-id": "${{ steps.build.outputs.signing-input-id }}"}) {
				t.Fatal("owner must export only the consumed signing-input ID, never unused validation IDs")
			}
			producer := mustStepNamed(t, job, "Build unsigned Windows artifacts")
			if producer.Uses != "./.github/actions/"+tc.owner || producer.If != "" || producer.ContinueOnError != nil || len(producer.With) != 3 {
				t.Fatal("owner must call its blocking producer with only prepared source/version/canonical inputs")
			}
			for _, key := range []string{"source-sha", "version", "manifest-digest"} {
				if producer.With[key] != "${{ steps.source.outputs."+key+" }}" {
					t.Fatalf("%s input must come from the prepared source", key)
				}
			}
			var metadata struct {
				Inputs  map[string]struct{ Required bool } `yaml:"inputs"`
				Outputs map[string]struct{ Value string }  `yaml:"outputs"`
			}
			path := ".github/actions/" + tc.owner + "/action.yml"
			content := mustReadRepoFile(t, path)
			if err := yaml.Unmarshal([]byte(content), &metadata); err != nil {
				t.Fatal(err)
			}
			if len(metadata.Inputs) != 3 || len(metadata.Outputs) != 4 {
				t.Fatal("Windows producer must have three source inputs, three validation outputs and the separately consumed signing-input ID")
			}
			for _, key := range []string{"source-sha", "version", "manifest-digest"} {
				if !metadata.Inputs[key].Required {
					t.Fatalf("%s must be required", key)
				}
			}
			for _, key := range []string{"artifact-id", "artifact-digest"} {
				if metadata.Outputs[key].Value != "${{ steps.upload.outputs."+key+" }}" {
					t.Fatalf("%s must identify the official validation upload", key)
				}
			}
			if metadata.Outputs["run-attempt"].Value != "${{ steps.source.outputs.run-attempt }}" {
				t.Fatal("validation run-attempt must come from the source assertion")
			}
			if metadata.Outputs["signing-input-id"].Value != "${{ steps.signing-input.outputs.artifact-id }}" {
				t.Fatal("signing-input ID must come from the original bundle uploader")
			}
			for _, forbidden := range []string{"secrets.", "vars.", "inputs.publish_release", "inputs.signpath_", "signpath/github-action", "id-token:", "environment:"} {
				mustNotContain(t, content, forbidden)
			}
			action := mustReadCompositeActionDoc(t, path)
			if action.Runs.Using != "composite" {
				t.Fatal("Windows producer must execute real composite build steps")
			}
			old := mustCompositeStepNamed(t, action, "Upload artifact")
			if old.With["name"] != tc.bundle+"-attempt-${{ github.run_attempt }}" || old.With["retention-days"] != 1 {
				t.Fatal("original SignPath input bundle must keep its prefix and retention")
			}
			upload := mustCompositeStepNamed(t, action, "Upload validation artifacts")
			prefix := "validate-windows-current-amd64-attempt-${{ github.run_attempt }}"
			if tc.owner == "build-windows-legacy" {
				prefix = "validate-windows-legacy-amd64-attempt-${{ github.run_attempt }}"
			}
			want := map[string]any{"name": prefix, "path": tc.directory + "/*", "if-no-files-found": "error", "compression-level": 9, "retention-days": 7, "overwrite": false}
			if upload.ID != "upload" || !reflect.DeepEqual(upload.With, want) || upload.If != "" || upload.ContinueOnError != nil {
				t.Fatal("validation artifacts must be separate, per-attempt and immutable for seven days")
			}
		})
	}
}
