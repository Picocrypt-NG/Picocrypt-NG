package pcv3corpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	privateCorpusRootEnv      = "PCV3_PRIVATE_CORPUS_ROOT"
	privateCorpusCustodyIDEnv = "PCV3_PRIVATE_CORPUS_CUSTODY_ID"
	privateCorpusContractTest = "TestPrivateCorpusContract"
)

func TestPrivateCorpusContractHandoffFailuresAreObservable(t *testing.T) {
	tests := []struct {
		name           string
		env            func(*testing.T) []string
		wantDiagnostic string
	}{
		{
			name: "missing root",
			env: func(*testing.T) []string {
				return nil
			},
			wantDiagnostic: "PCV3 private corpus root is required",
		},
		{
			name: "missing custody ID",
			env: func(t *testing.T) []string {
				return []string{privateCorpusRootEnv + "=" + t.TempDir()}
			},
			wantDiagnostic: "PCV3 private corpus custody ID is required",
		},
		{
			name: "unapproved custody ID",
			env: func(t *testing.T) []string {
				return []string{
					privateCorpusRootEnv + "=" + t.TempDir(),
					privateCorpusCustodyIDEnv + "=intentionally-unapproved-test-id",
				}
			},
			wantDiagnostic: "PCV3 private corpus custody ID is not approved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runPrivateCorpusContractFailure(t, tt.env(t), tt.wantDiagnostic)
		})
	}
}

func runPrivateCorpusContractFailure(t *testing.T, overrides []string, wantDiagnostic string) {
	t.Helper()

	cmd := exec.Command(
		"go",
		"test",
		"-json",
		"-count=1",
		"-p=1",
		"-tags=pcv3_private_corpus",
		"-run",
		"^"+privateCorpusContractTest+"$",
		".",
	)
	cmd.Env = privateCorpusChildEnv(overrides)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard

	err := cmd.Run()
	if err == nil {
		t.Fatal("private corpus contract unexpectedly passed")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("private corpus contract did not exit through go test: %T", err)
	}

	var failed, skipped, foundDiagnostic bool
	decoder := json.NewDecoder(&stdout)
	for {
		var event struct {
			Action string
			Test   string
			Output string
		}
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal("private corpus child emitted invalid go test JSON")
		}
		if event.Test != privateCorpusContractTest {
			continue
		}
		switch event.Action {
		case "fail":
			failed = true
		case "skip":
			skipped = true
		case "output":
			foundDiagnostic = foundDiagnostic || exactTestDiagnostic(event.Output, wantDiagnostic)
		}
	}

	if !failed {
		t.Fatal("private corpus contract did not emit a test-level failure")
	}
	if skipped {
		t.Fatal("private corpus contract emitted a test-level skip")
	}
	if !foundDiagnostic {
		t.Fatalf("private corpus contract did not emit expected diagnostic %q", wantDiagnostic)
	}
}

func privateCorpusChildEnv(overrides []string) []string {
	inherited := os.Environ()
	env := make([]string, 0, len(inherited)+len(overrides)+1)
	for _, entry := range inherited {
		key, _, ok := strings.Cut(entry, "=")
		if ok && (key == privateCorpusRootEnv || key == privateCorpusCustodyIDEnv || key == "GOMAXPROCS" || key == "GOFLAGS") {
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "GOMAXPROCS=1")
	env = append(env, overrides...)
	return env
}

func exactTestDiagnostic(output, want string) bool {
	line := strings.TrimSpace(output)
	if line == want {
		return true
	}
	if separator := strings.LastIndex(line, ": "); separator >= 0 {
		return line[separator+2:] == want
	}
	return false
}

// TestD1TrackedHistoryPolicy is tooling-policy evidence only. It prevents an
// accidentally named private D1 corpus/vector/manifest/mutation artifact from
// entering tracked source, docs, or planning paths; it is not codec evidence.
func TestD1TrackedHistoryPolicy(t *testing.T) {
	for _, name := range []string{
		"src/internal/pcv3/testdata/d1-private-corpus/manifest.json",
		"src/internal/pcv3/testdata/d1-complete-vector.bin",
		"docs/d1-mutation-plan.json",
		".planning/private-d1-vectors/volume.bin",
	} {
		if !prohibitedTrackedD1ArtifactPath(name) {
			t.Fatalf("policy did not reject prohibited synthetic path %q", name)
		}
	}
	for _, name := range []string{
		"src/internal/pcv3/d1_fixture_test.go",
		"src/internal/pcv3/testdata/normal/manifest.json",
		"docs/PCV3_FORMAT_SPEC.md",
		".planning/phases/07-d1-streaming-outer-codec/07-01-PLAN.md",
	} {
		if prohibitedTrackedD1ArtifactPath(name) {
			t.Fatalf("policy rejected permitted synthetic path %q", name)
		}
	}

	repoRootCommand := exec.Command("git", "rev-parse", "--show-toplevel")
	repoRootBytes, err := repoRootCommand.Output()
	if err != nil {
		t.Fatal("tracked-history policy could not resolve the repository root")
	}
	repoRoot := strings.TrimSpace(string(repoRootBytes))
	trackedCommand := exec.Command("git", "-C", repoRoot, "ls-files", "-z", "--", "src", "docs", ".planning")
	tracked, err := trackedCommand.Output()
	if err != nil {
		t.Fatal("tracked-history policy could not enumerate tracked names")
	}
	for _, rawName := range bytes.Split(tracked, []byte{0}) {
		if len(rawName) == 0 {
			continue
		}
		name := filepath.ToSlash(string(rawName))
		if prohibitedTrackedD1ArtifactPath(name) {
			t.Fatalf("tracked private D1 artifact name is forbidden: %s", name)
		}
	}
}

func prohibitedTrackedD1ArtifactPath(name string) bool {
	name = strings.ToLower(filepath.ToSlash(name))
	inProtectedArea := strings.HasPrefix(name, "docs/") || strings.HasPrefix(name, ".planning/") ||
		strings.HasPrefix(name, "src/") && strings.Contains(name, "/testdata/")
	if !inProtectedArea || !strings.Contains(name, "d1") {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		for _, marker := range []string{"corpus", "vector", "manifest", "mutation"} {
			if strings.Contains(component, marker) {
				return true
			}
		}
	}
	return false
}
