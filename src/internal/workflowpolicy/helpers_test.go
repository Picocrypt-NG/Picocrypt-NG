package workflowpolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type workflowDoc struct {
	Permissions map[string]string      `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	If              string            `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Environment     any               `yaml:"environment"`
	Permissions     map[string]string `yaml:"permissions"`
	Env             map[string]string `yaml:"env"`
	Steps           []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	ID               string            `yaml:"id"`
	Name             string            `yaml:"name"`
	Uses             string            `yaml:"uses"`
	Run              string            `yaml:"run"`
	If               string            `yaml:"if"`
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
