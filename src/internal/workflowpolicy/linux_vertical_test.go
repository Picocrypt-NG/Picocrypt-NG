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

// These are release policy and packaging-transfer checks, not product coverage.
func TestLinuxBuildExtractionPreservesExistingSteps(t *testing.T) {
	content := strings.ReplaceAll(mustReadRepoFile(t, ".github/actions/build-linux/action.yml"), "inputs.", "matrix.")
	var action struct {
		Runs struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal([]byte(content), &action); err != nil {
		t.Fatal(err)
	}
	var frozen []map[string]any
	active := false
	for _, step := range action.Runs.Steps {
		if step["name"] == "Setup Go" {
			active = true
		}
		if active {
			// A composite must make the formerly implicit Bash shell explicit.
			delete(step, "shell")
			if run, ok := step["run"].(string); ok {
				step["run"] = normalizeLinuxBuildRun(run)
			}
			if step["name"] == "Test browser PCV3 and legacy compatibility" && step["run"] == ".github/scripts/test-wasm.sh" {
				step["timeout-minutes"] = 45
			}
			if env, ok := step["env"].(map[string]any); ok {
				for name, value := range env {
					if value != "${{ matrix."+strings.ToLower(name)+" }}" {
						t.Fatalf("unexpected Linux step environment binding %s=%v", name, value)
					}
				}
				delete(step, "env")
			}
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
	// Frozen from the existing owner workflow before extracting its native tests,
	// WASM compatibility, GUI smoke, binaries, UPX checksum and DEB packaging.
	const want = "c4b764a51c7aaf16a75ed2a7bb06bc91fb54434475884d19af0adb0ee0d8826e"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("Linux packaging steps changed during extraction: digest %s, want %s", got, want)
	}
}

func normalizeLinuxBuildRun(run string) string {
	for _, name := range []string{"ARCH", "UPX_PKG", "UPX_SHA256", "GUI_BINARY", "CLI_BINARY", "BUILD_DEB"} {
		run = strings.ReplaceAll(run, `"$`+name+`"/upx`, "$"+name+"/upx")
		run = strings.ReplaceAll(run, "$"+name, "${{ matrix."+strings.ToLower(name)+" }}")
	}
	run = strings.ReplaceAll(run, `"https://github.com/upx/upx/releases/download/v5.2.1/${{ matrix.upx_pkg }}.tar.xz"`, `https://github.com/upx/upx/releases/download/v5.2.1/${{ matrix.upx_pkg }}.tar.xz`)
	return strings.ReplaceAll(run, "timeout --kill-after=30s 45m .github/scripts/test-wasm.sh", ".github/scripts/test-wasm.sh")
}

func linuxBuildPolicyJob(t *testing.T, path string) workflowJob {
	t.Helper()
	if path != ".github/workflows/build-linux.yml" {
		return mustJob(t, mustReadWorkflowDoc(t, path), "build")
	}
	action := mustReadCompositeActionDoc(t, ".github/actions/build-linux/action.yml")
	for i := range action.Runs.Steps {
		action.Runs.Steps[i].Run = normalizeLinuxBuildRun(action.Runs.Steps[i].Run)
	}
	return workflowJob{Steps: action.Runs.Steps}
}

func TestLinuxValidationPilotHasReadOnlyCeilingAndTwoNativeProducers(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/release.yml")
	if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read", "actions": "read"}) {
		t.Fatalf("validation permission ceiling = %#v", workflow.Permissions)
	}
	mode := workflow.On.WorkflowDispatch.Inputs["mode"]
	if mode.Default != "validation" || len(workflow.On.OtherEvents) != 0 {
		t.Fatal("the pilot must default to manual validation")
	}
	for name, job := range workflow.Jobs {
		if job.Uses != "" || job.Environment != nil || job.ContinueOnError == true || job.Permissions != nil {
			t.Fatalf("%s must remain an ordinary blocking job under the read-only ceiling", name)
		}
		for _, step := range job.Steps {
			if strings.Contains(step.Uses, "sign-and-attest") || strings.Contains(step.Uses, "stage-release") || strings.Contains(step.Run, "secrets.") {
				t.Fatalf("validation job %s contains a signing/publication capability", name)
			}
			if strings.HasPrefix(step.Uses, "actions/checkout@") && (step.With["ref"] != "${{ github.sha }}" || step.With["persist-credentials"] != false) {
				t.Fatalf("%s checkout must bind the immutable event SHA without credentials", name)
			}
		}
	}
	for _, path := range []string{".github/workflows/build-linux.yml", ".github/workflows/release.yml"} {
		w := mustReadWorkflowDoc(t, path)
		for arch, runner := range map[string]string{"amd64": "ubuntu-24.04", "arm64": "ubuntu-24.04-arm"} {
			job := mustJob(t, w, "build-"+arch)
			if job.RunsOn != runner || job.Needs != "prepare" || len(job.Strategy.Matrix.Include) != 0 {
				t.Fatalf("%s %s must expose one native producer", path, arch)
			}
			build := mustHaveStepUsingPrefix(t, job, "./.github/actions/build-linux")
			gui, cli, deb, upxHash := "Picocrypt-NG", "Picocrypt-NG-cli", "true", "402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657"
			if arch == "arm64" {
				gui, cli, deb, upxHash = "Picocrypt-NG-arm64", "Picocrypt-NG-cli-arm64", "false", "a72d112c5970a904a31da0b9c84f919bc16b9a311787c12245508544a78c7d36"
			}
			for key, want := range map[string]string{"gui_binary": gui, "cli_binary": cli, "build_deb": deb, "upx_pkg": "upx-5.2.1-" + arch + "_linux", "upx_sha256": upxHash} {
				if build.With[key] != want {
					t.Fatalf("%s %s changed frozen Linux packaging input %s", path, arch, key)
				}
			}
			if build.With["arch"] != arch || build.With["source-sha"] != "${{ needs.prepare.outputs.source-sha }}" ||
				build.With["version"] != "${{ needs.prepare.outputs.version }}" || build.With["manifest-digest"] != "${{ needs.prepare.outputs.manifest-digest }}" {
				t.Fatalf("%s %s must bind prepare outputs", path, arch)
			}
			for _, output := range []string{"artifact-id", "artifact-digest", "run-attempt"} {
				if job.Outputs[output] != "${{ steps.build.outputs."+output+" }}" {
					t.Fatalf("%s %s loses immutable producer output %s", path, arch, output)
				}
			}
		}
	}
	prepare := mustJob(t, workflow, "prepare")
	mustContain(t, mustStepNamed(t, prepare, "Bind source and canonical manifest").Run, `test "$MODE" = validation`)
	verify := mustJob(t, workflow, "verify-linux")
	if verify.If != "${{ always() }}" {
		t.Fatal("validation must reject a failed, skipped or cancelled producer")
	}
	mustContain(t, mustStepNamed(t, verify, "Require both Linux producers").Run, `[[ "$AMD64_RESULT" == success && "$ARM64_RESULT" == success ]]`)
	mustContain(t, mustStepNamed(t, verify, "Report Linux pilot scope").Run, "partial Linux pilot")
}

func TestLinuxArtifactConsumersUseExactIDsAndBlockingDigestChecks(t *testing.T) {
	for path, jobName := range map[string]string{".github/workflows/build-linux.yml": "release", ".github/workflows/release.yml": "verify-linux"} {
		job := mustJob(t, mustReadWorkflowDoc(t, path), jobName)
		var order []string
		for _, step := range job.Steps {
			if step.Name == "Verify immutable Linux artifact metadata" || step.Name == "Verify Linux payload manifests" {
				order = append(order, step.Name)
			}
			if !strings.HasPrefix(step.Uses, "actions/download-artifact@") {
				continue
			}
			order = append(order, step.Name)
			arch := "amd64"
			if strings.Contains(step.Name, "ARM64") {
				arch = "arm64"
			}
			if step.With["artifact-ids"] != "${{ needs.build-"+arch+".outputs.artifact-id }}" ||
				step.With["path"] != "artifacts/build-linux-"+arch || step.With["merge-multiple"] != true || step.With["digest-mismatch"] != "error" {
				t.Fatalf("%s %s must download one exact ID with a blocking ZIP digest and stable release path", path, step.Name)
			}
			if step.With["name"] != nil || step.With["pattern"] != nil {
				t.Fatal("artifact names must not select replacement bytes")
			}
		}
		want := []string{"Verify immutable Linux artifact metadata", "Download Linux AMD64 artifact", "Download Linux ARM64 artifact", "Verify Linux payload manifests"}
		if !reflect.DeepEqual(order, want) {
			t.Fatalf("%s artifact verification order = %v", path, order)
		}
	}
	action := mustReadCompositeActionDoc(t, ".github/actions/build-linux/action.yml")
	var outputs struct {
		Outputs map[string]struct {
			Value string `yaml:"value"`
		} `yaml:"outputs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/actions/build-linux/action.yml")), &outputs); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"artifact-id", "artifact-digest"} {
		if outputs.Outputs[name].Value != "${{ steps.upload.outputs."+name+" }}" {
			t.Fatalf("%s must come directly from the official uploader", name)
		}
	}
	upload := mustCompositeStepNamed(t, action, "Upload artifacts")
	if upload.With["name"] != "build-linux-${{ inputs.arch }}-attempt-${{ github.run_attempt }}" || upload.With["overwrite"] != false || upload.With["retention-days"] != 7 {
		t.Fatal("a rerun must keep the original immutable artifact rather than overwrite it")
	}
}

func TestLinuxArtifactConsumersInstallTheChecksumLockedGitHubCLI(t *testing.T) {
	for path, job := range map[string]string{".github/workflows/build-linux.yml": "release", ".github/workflows/release.yml": "verify-linux"} {
		mustHaveStepUsingPrefix(t, mustJob(t, mustReadWorkflowDoc(t, path), job), "./.github/actions/setup-gh")
	}
	var pin struct{ Version, URL, SHA256 string }
	if err := json.Unmarshal([]byte(mustReadRepoFile(t, ".github/toolchains/github-cli.json")), &pin); err != nil {
		t.Fatal(err)
	}
	if pin.Version != "2.102.1" || pin.URL != "https://github.com/cli/cli/releases/download/v2.102.1/gh_2.102.1_linux_amd64.tar.gz" || pin.SHA256 != "77b9e297e94c50336823d0f84de7ef1be60cba704601fa0d98f129f47a94987b" {
		t.Fatal("GitHub CLI must retain the previously verified official archive pin")
	}
	install := mustCompositeStepNamed(t, mustReadCompositeActionDoc(t, ".github/actions/setup-gh/action.yml"), "Install checksum-locked GitHub CLI")
	mustContainInOrder(t, install.Run, `test "$(uname -s)" = Linux`, `test "$(uname -m)" = x86_64`, `--proto '=https' --proto-redir '=https'`, `sha256sum --check --strict --status`, `--strip-components=2 "gh_${version}_linux_amd64/bin/gh"`, `banner=$("$destination/gh" --version)`, `echo "$destination" >> "$GITHUB_PATH"`)
	mustNotContain(t, install.Run, "head -")
}
