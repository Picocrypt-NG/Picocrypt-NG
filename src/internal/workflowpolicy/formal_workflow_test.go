package workflowpolicy

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// These checks protect CI scheduling and cache policy, not application behavior.
func TestFormalWorkflowKeepsPRContextsAndFiltersOnlyMainPushes(t *testing.T) {
	const path = ".github/workflows/verify-easycrypt-models.yml"
	var triggers struct {
		On map[string]any `yaml:"on"`
	}
	if err := yaml.Unmarshal([]byte(mustReadWorkflow(t, path)), &triggers); err != nil {
		t.Fatal(err)
	}
	if len(triggers.On) != 3 {
		t.Fatalf("formal workflow triggers = %#v, want PR, main push and manual dispatch", triggers.On)
	}
	if dispatch, exists := triggers.On["workflow_dispatch"]; !exists || dispatch != nil {
		t.Fatalf("formal workflow must retain unrestricted manual dispatch: %#v", dispatch)
	}
	pullRequest, ok := triggers.On["pull_request"].(map[string]any)
	if !ok || len(pullRequest) != 1 || !reflect.DeepEqual(pullRequest["branches"], []any{"main"}) {
		t.Fatalf("required formal PR contexts must run without path or event filters: %#v", pullRequest)
	}
	push, ok := triggers.On["push"].(map[string]any)
	if !ok || len(push) != 2 || !reflect.DeepEqual(push["branches"], []any{"main"}) {
		t.Fatalf("formal push filtering must apply only to main: %#v", push)
	}
	wantIgnored := []any{"android/**", "dist/**", "fastlane/**", "images/**", "docs/**", "*.md"}
	if !reflect.DeepEqual(push["paths-ignore"], wantIgnored) {
		t.Fatalf("formal push exclusions = %#v, want only known unrelated paths %v", push["paths-ignore"], wantIgnored)
	}
	workflow := mustReadWorkflowDoc(t, path)
	if len(workflow.Permissions) != 1 {
		t.Fatalf("formal workflow permissions = %#v, want contents: read only", workflow.Permissions)
	}
	mustPermission(t, workflow.Permissions, "contents", "read")
	for _, test := range []struct {
		id, name string
		minutes  int
	}{
		{"go-source-contract", "Go source contracts", 15},
		{"model-proofs", "EasyCrypt model proofs", 30},
	} {
		job := mustJob(t, workflow, test.id)
		if job.Name != test.name || job.RunsOn != "ubuntu-24.04" || job.TimeoutMinutes != test.minutes || job.If != "" || job.Needs != nil || (job.ContinueOnError != nil && job.ContinueOnError != false) {
			t.Fatalf("formal required context %s must remain independent and fail on errors: %+v", test.id, job)
		}
	}
}

func TestFormalWorkflowBindsCachedToolchainToFrozenInputsAndActualHost(t *testing.T) {
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/verify-easycrypt-models.yml"), "model-proofs")
	identity := mustStepNamed(t, job, "Bind proof-toolchain cache identity")
	if identity.ID != "toolchain-cache" || identity.Shell != "bash" || identity.If != "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}" {
		t.Fatalf("proof cache identity must be generated on the actual runner: %+v", identity)
	}
	for _, binding := range []string{"ImageOS", "ImageVersion", "HOME", "GITHUB_WORKSPACE", "sha256sum", "GITHUB_OUTPUT", "host="} {
		mustContain(t, identity.Run, binding)
	}
	for _, fixedPath := range []string{"/home/", "/Users/"} {
		mustNotContain(t, identity.Run, fixedPath)
	}
	setup := mustStepNamed(t, job, "Set up cached OCaml toolchain")
	if setup.Uses != "ocaml/setup-ocaml@ff66428f72b64472e749b22e0ad4dded4b2ddca6" || setup.With["ocaml-compiler"] != "5.4.0" || setup.With["opam-pin"] != false || setup.With["cache"] != "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}" || setup.With["dune-cache"] != false {
		t.Fatalf("formal cache must use the pinned OCaml action with only its opam cache enabled: %+v", setup)
	}
	prefix, ok := setup.With["cache-prefix"].(string)
	if !ok {
		t.Fatal("formal opam cache needs a source-bound prefix")
	}
	for _, binding := range []string{
		"steps.toolchain-cache.outputs.host", "hashFiles(",
		"verification/easycrypt/toolchain.json", "verification/easycrypt/toolchain.export",
		"verification/easycrypt/bootstrap.py", "verification/easycrypt/cache.py",
		"verification/easycrypt/run.py", "verification/easycrypt/policy.py", "verification/easycrypt/tests/*.py",
		".github/workflows/verify-easycrypt-models.yml",
	} {
		mustContain(t, prefix, binding)
	}
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "actions/cache") {
			t.Fatalf("formal workflow must not add a separate proof-output cache: %+v", step)
		}
	}
	uv := mustHaveStepUsingPrefix(t, job, "astral-sh/setup-uv@")
	if uv.Uses != "astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2" || uv.With["version"] != "0.13.5" || uv.With["enable-cache"] != false {
		t.Fatalf("formal Python setup must retain its pinned uncached configuration: %+v", uv)
	}
}

func TestFormalWorkflowChecksCachedFilesAndAlwaysRerunsCompleteProofs(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/verify-easycrypt-models.yml")
	source := mustStepNamed(t, mustJob(t, workflow, "go-source-contract"), "Check current source contract and overflow control")
	if source.Run != "sh verification/gobra/check.sh" || source.If != "" || (source.ContinueOnError != nil && source.ContinueOnError != false) {
		t.Fatalf("source contracts must always run and propagate failures: %+v", source)
	}
	job := mustJob(t, workflow, "model-proofs")
	previous := -1
	for _, name := range []string{
		"Install native proof-tool prerequisites", "Bind proof-toolchain cache identity",
		"Set up cached OCaml toolchain", "Verify cached EasyCrypt files",
		"Install frozen EasyCrypt toolchain", "Check proof-admission policy",
		"Check models and defect controls", "Record installed EasyCrypt files",
	} {
		step := mustStepNamed(t, job, name)
		wantIf := ""
		if name == "Bind proof-toolchain cache identity" || name == "Verify cached EasyCrypt files" || name == "Record installed EasyCrypt files" {
			wantIf = "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
		}
		if step.If != wantIf || (step.ContinueOnError != nil && step.ContinueOnError != false) {
			t.Fatalf("formal step %q must preserve cache trust scope and propagate failures: %+v", name, step)
		}
		index := slices.IndexFunc(job.Steps, func(candidate workflowStep) bool { return candidate.Name == name })
		if index <= previous {
			t.Fatalf("formal step %q must follow the preceding prerequisite", name)
		}
		previous = index
	}
	for name, command := range map[string]string{
		"Verify cached EasyCrypt files":      "uv run --no-project python verification/easycrypt/cache.py check",
		"Install frozen EasyCrypt toolchain": "uv run --no-project python verification/easycrypt/bootstrap.py",
		"Check proof-admission policy":       "uv run --no-project python -m unittest discover -s verification/easycrypt/tests -v",
		"Check models and defect controls":   "uv run --no-project python verification/easycrypt/run.py",
	} {
		if step := mustStepNamed(t, job, name); step.Run != command {
			t.Fatalf("formal step %q command = %q, want complete command %q", name, step.Run, command)
		}
	}
	record := mustStepNamed(t, job, "Record installed EasyCrypt files")
	mustContainInOrder(t, record.Run, "opam clean", "uv run --no-project python verification/easycrypt/cache.py record")
}
