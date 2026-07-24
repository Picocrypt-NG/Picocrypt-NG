package workflowpolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type workflowDoc struct {
	On          workflowTriggers       `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type compositeActionDoc struct {
	Runs compositeActionRuns `yaml:"runs"`
}

type compositeActionRuns struct {
	Using string         `yaml:"using"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowTriggers struct {
	WorkflowDispatch workflowDispatch `yaml:"workflow_dispatch"`
}

type workflowDispatch struct {
	Inputs map[string]workflowDispatchInput `yaml:"inputs"`
}

type workflowDispatchInput struct {
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
	Type        string `yaml:"type"`
	Default     any    `yaml:"default"`
}

type workflowJob struct {
	If              string              `yaml:"if"`
	Needs           any                 `yaml:"needs"`
	RunsOn          string              `yaml:"runs-on"`
	Concurrency     workflowConcurrency `yaml:"concurrency"`
	TimeoutMinutes  int                 `yaml:"timeout-minutes"`
	ContinueOnError any                 `yaml:"continue-on-error"`
	Environment     any                 `yaml:"environment"`
	Permissions     map[string]string   `yaml:"permissions"`
	Env             map[string]string   `yaml:"env"`
	Steps           []workflowStep      `yaml:"steps"`
}

type workflowConcurrency struct {
	Group            string `yaml:"group"`
	Queue            string `yaml:"queue"`
	CancelInProgress any    `yaml:"cancel-in-progress"`
}

type workflowStep struct {
	ID               string            `yaml:"id"`
	Name             string            `yaml:"name"`
	Uses             string            `yaml:"uses"`
	Run              string            `yaml:"run"`
	Shell            string            `yaml:"shell"`
	If               string            `yaml:"if"`
	TimeoutMinutes   int               `yaml:"timeout-minutes"`
	WorkingDirectory string            `yaml:"working-directory"`
	ContinueOnError  any               `yaml:"continue-on-error"`
	With             map[string]any    `yaml:"with"`
	Env              map[string]string `yaml:"env"`
}

func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	current := wd
	for {
		if _, err := os.Stat(filepath.Join(current, ".github", "workflows")); err == nil {
			return current
		}

		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("could not find repository root from test working directory")
		}
		current = parent
	}
}

func mustReadWorkflow(t *testing.T, relPath string) string {
	t.Helper()
	return mustReadRepoFile(t, relPath)
}

func mustReadRepoFile(t *testing.T, relPath string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(repoRoot(t), relPath))
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return strings.ReplaceAll(string(content), "\r\n", "\n")
}

func mustReadWorkflowDoc(t *testing.T, relPath string) workflowDoc {
	t.Helper()
	return mustParseWorkflowYAML(t, mustReadWorkflow(t, relPath))
}

func mustReadCompositeActionDoc(t *testing.T, relPath string) compositeActionDoc {
	t.Helper()

	var action compositeActionDoc
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, relPath)), &action); err != nil {
		t.Fatalf("unmarshal composite action yaml: %v", err)
	}
	return action
}

func mustParseWorkflowYAML(t *testing.T, content string) workflowDoc {
	t.Helper()

	var workflow workflowDoc
	if err := yaml.Unmarshal([]byte(content), &workflow); err != nil {
		t.Fatalf("unmarshal workflow yaml: %v", err)
	}
	return workflow
}

func mustPermission(t *testing.T, permissions map[string]string, key, want string) {
	t.Helper()

	if permissions == nil {
		t.Fatalf("expected permissions map with %q=%q, got nil", key, want)
	}
	if got := permissions[key]; got != want {
		t.Fatalf("permission %q = %q, want %q", key, got, want)
	}
}

func mustEffectivePermission(t *testing.T, workflow workflowDoc, job workflowJob, key, want string) {
	t.Helper()

	if job.Permissions != nil {
		if got, ok := job.Permissions[key]; ok {
			if got != want {
				t.Fatalf("job permission %q = %q, want %q", key, got, want)
			}
			return
		}
	}

	mustPermission(t, workflow.Permissions, key, want)
}

func mustJob(t *testing.T, workflow workflowDoc, name string) workflowJob {
	t.Helper()

	job, ok := workflow.Jobs[name]
	if !ok {
		t.Fatalf("expected workflow to contain job %q", name)
	}
	return job
}

func mustStepNamed(t *testing.T, job workflowJob, name string) workflowStep {
	t.Helper()

	for _, step := range job.Steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("expected job to contain step named %q", name)
	return workflowStep{}
}

func mustCompositeStepNamed(t *testing.T, action compositeActionDoc, name string) workflowStep {
	t.Helper()

	for _, step := range action.Runs.Steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("expected composite action to contain step named %q", name)
	return workflowStep{}
}

func mustNotHaveStepNamed(t *testing.T, job workflowJob, name string) {
	t.Helper()

	for _, step := range job.Steps {
		if step.Name == name {
			t.Fatalf("expected job not to contain step named %q", name)
		}
	}
}

func mustHaveStepUsingPrefix(t *testing.T, job workflowJob, prefix string) workflowStep {
	t.Helper()

	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, prefix) {
			return step
		}
	}
	t.Fatalf("expected job to contain step using prefix %q", prefix)
	return workflowStep{}
}

func mustContain(t *testing.T, content, substring string) {
	t.Helper()

	if !strings.Contains(content, substring) {
		t.Fatalf("expected workflow to contain %q", substring)
	}
}

func mustContainInOrder(t *testing.T, content string, substrings ...string) {
	t.Helper()

	offset := 0
	for _, substring := range substrings {
		index := strings.Index(content[offset:], substring)
		if index < 0 {
			t.Fatalf("expected workflow to contain %q after byte offset %d", substring, offset)
		}
		offset += index + len(substring)
	}
}

func mustContainActiveLines(t *testing.T, script string, want ...string) {
	t.Helper()

	active := make([]string, 0)
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			active = append(active, trimmed)
		}
	}
	for start := 0; start+len(want) <= len(active); start++ {
		if slices.Equal(active[start:start+len(want)], want) {
			return
		}
	}
	t.Fatalf("active PowerShell lines do not contain exact sequence %q", want)
}

func mustNotContain(t *testing.T, content, substring string) {
	t.Helper()

	if strings.Contains(content, substring) {
		t.Fatalf("expected workflow not to contain %q", substring)
	}
}

func mustMatch(t *testing.T, content, pattern string) {
	t.Helper()

	matched, err := regexp.MatchString(pattern, content)
	if err != nil {
		t.Fatalf("compile pattern %q: %v", pattern, err)
	}
	if !matched {
		t.Fatalf("expected workflow to match %q", pattern)
	}
}

func mustUseBoundedCurlDownload(
	t *testing.T,
	script string,
	output string,
	url string,
	hashEnv string,
	consumer string,
) {
	t.Helper()

	lines := strings.Split(script, "\n")
	curlStart := -1
	curlCount := 0
	activeLines := make([]string, 0, len(lines))
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		activeLines = append(activeLines, trimmed)
		curlCount += strings.Count(strings.ToLower(trimmed), "curl.exe")
		if curlStart < 0 && (trimmed == "curl.exe `" || strings.HasPrefix(trimmed, "curl.exe ")) {
			curlStart = index
		}
	}
	if curlCount != 1 || curlStart < 0 {
		t.Fatalf("curl.exe command count = %d, want exactly 1", curlCount)
	}
	activeCode := strings.Join(activeLines, "\n")
	lowerActiveCode := strings.ToLower(activeCode)
	urlCount := strings.Count(lowerActiveCode, "https://") + strings.Count(lowerActiveCode, "http://")
	if urlCount != 1 || strings.Count(activeCode, url) != 1 {
		t.Fatalf("active download URL count = %d, want only %q", urlCount, url)
	}
	firstStatement := -1
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			firstStatement = index
			break
		}
	}
	if firstStatement != curlStart {
		t.Fatalf("first download-step statement is line %d, want curl.exe at line %d", firstStatement+1, curlStart+1)
	}

	curlEnd := -1
	commandLines := make([]string, 0)
	for index := curlStart; index < len(lines); index++ {
		physicalLine := strings.TrimLeft(lines[index], " \t")
		continued := strings.HasSuffix(physicalLine, "`")
		commandLines = append(commandLines, strings.TrimSuffix(physicalLine, "`"))
		if !continued {
			curlEnd = index
			break
		}
	}
	if curlEnd < curlStart {
		t.Fatal("curl.exe command has no final line")
	}

	tokens := strings.Fields(strings.Join(commandLines, " "))
	if len(tokens) == 0 || tokens[0] != "curl.exe" {
		t.Fatalf("download command tokens = %q, want curl.exe first", tokens)
	}
	if tokens[len(tokens)-1] != url {
		t.Fatalf("curl.exe final URL = %q, want %q", tokens[len(tokens)-1], url)
	}

	wantTokens := []string{
		"curl.exe",
		"--fail",
		"--location",
		"--silent",
		"--show-error",
		"--retry", "3",
		"--retry-all-errors",
		"--retry-delay", "2",
		"--connect-timeout", "30",
		"--max-time", "300",
		"--retry-max-time", "600",
		"--remove-on-error",
		"--output", output,
		url,
	}
	if !slices.Equal(tokens, wantTokens) {
		t.Fatalf("curl.exe tokens = %q, want exactly %q", tokens, wantTokens)
	}

	nextMeaningful := func(start int) int {
		for index := start; index < len(lines); index++ {
			trimmed := strings.TrimSpace(lines[index])
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				return index
			}
		}
		return -1
	}
	requireLine := func(index int, want string) {
		t.Helper()
		if index < 0 || strings.TrimSpace(lines[index]) != want {
			got := "<missing>"
			if index >= 0 {
				got = strings.TrimSpace(lines[index])
			}
			t.Fatalf("PowerShell statement = %q, want %q", got, want)
		}
	}
	requireThrow := func(index int, guard string) {
		t.Helper()
		if index < 0 || !strings.HasPrefix(strings.TrimSpace(lines[index]), "throw ") {
			t.Fatalf("%s must immediately throw, got line %d", guard, index+1)
		}
	}

	exitGuard := nextMeaningful(curlEnd + 1)
	requireLine(exitGuard, "if ($LASTEXITCODE -ne 0) {")
	exitThrow := nextMeaningful(exitGuard + 1)
	requireThrow(exitThrow, "curl exit guard")
	exitClose := nextMeaningful(exitThrow + 1)
	requireLine(exitClose, "}")

	expectedHash := nextMeaningful(exitClose + 1)
	requireLine(expectedHash, "$expectedHash = $env:"+hashEnv)
	actualHash := nextMeaningful(expectedHash + 1)
	requireLine(
		actualHash,
		"$actualHash = (Get-FileHash "+output+" -Algorithm SHA256).Hash.ToLower()",
	)
	mismatchGuard := nextMeaningful(actualHash + 1)
	requireLine(mismatchGuard, "if ($actualHash -ne $expectedHash) {")
	mismatchThrow := nextMeaningful(mismatchGuard + 1)
	requireThrow(mismatchThrow, "checksum mismatch guard")
	mismatchClose := nextMeaningful(mismatchThrow + 1)
	requireLine(mismatchClose, "}")

	firstConsumer := nextMeaningful(mismatchClose + 1)
	if firstConsumer < 0 || strings.TrimSpace(lines[firstConsumer]) != consumer {
		got := "<missing>"
		if firstConsumer >= 0 {
			got = strings.TrimSpace(lines[firstConsumer])
		}
		t.Fatalf("first statement after checksum guard = %q, want exact consumer %q", got, consumer)
	}
	if strings.Contains(script, "Invoke-WebRequest") {
		t.Fatal("download step must not retain Invoke-WebRequest")
	}
}
