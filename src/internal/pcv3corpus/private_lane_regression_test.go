package pcv3corpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
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
