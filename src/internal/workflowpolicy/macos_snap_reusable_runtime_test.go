//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Caller/protocol tooling only; no signing, native build or real service acceptance.
func TestMacosSnapReusableSourceRejectsAuthorityDrift(t *testing.T) {
	for _, tc := range []struct{ owner, label string }{{"build-macos", "macOS"}, {"build-snapcraft", "Snap"}} {
		step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/"+tc.owner+".yml"), "inspect"), "Validate reusable "+tc.label+" source")
		for _, defect := range []string{"none", "retry", "repository", "caller", "ref", "event", "source", "config", "checkout", "version", "canonical"} {
			t.Run(tc.owner+"/"+defect, func(t *testing.T) {
				dir := t.TempDir()
				sha := strings.Repeat("a", 40)
				if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("3.0\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				manifest := filepath.Join(dir, releaseManifestScriptPath)
				if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifest, []byte(mustReadRepoFile(t, releaseManifestScriptPath)), 0o700); err != nil {
					t.Fatal(err)
				}
				canonical, err := exec.Command("bash", manifest, "3.0").Output()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\nprintf '%s\\n' \"$FIXTURE_CHECKOUT\"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				values := map[string]string{"GITHUB_REPOSITORY": "Picocrypt-NG/Picocrypt-NG", "GITHUB_WORKFLOW_REF": "Picocrypt-NG/Picocrypt-NG/.github/workflows/release.yml@refs/heads/main", "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": sha, "GITHUB_WORKFLOW_SHA": sha, "SOURCE_SHA": sha, "SOURCE_VERSION": "3.0", "CANONICAL_MANIFEST_SHA256": fmt.Sprintf("%x", sha256.Sum256(canonical)), "FIXTURE_CHECKOUT": sha, "GITHUB_RUN_ATTEMPT": "1"}
				for name, key := range map[string]string{"repository": "GITHUB_REPOSITORY", "caller": "GITHUB_WORKFLOW_REF", "ref": "GITHUB_REF", "event": "GITHUB_EVENT_NAME", "source": "SOURCE_SHA", "config": "GITHUB_WORKFLOW_SHA", "checkout": "FIXTURE_CHECKOUT", "version": "SOURCE_VERSION", "canonical": "CANONICAL_MANIFEST_SHA256"} {
					if defect == name {
						values[key] = "wrong"
					}
				}
				if defect == "retry" {
					values["GITHUB_RUN_ATTEMPT"] = "2"
				}
				cmd := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
				for k, v := range values {
					cmd.Env = append(cmd.Env, k+"="+v)
				}
				output, err := cmd.CombinedOutput()
				if (err == nil) != (defect == "none" || defect == "retry") {
					t.Fatalf("guard %s: %v: %s", defect, err, output)
				}
			})
		}
	}
}

func TestMacosSnapReusableFreshInspectionRejectsPartialBeforeSigning(t *testing.T) {
	for _, tc := range []struct{ owner, label string }{{"build-macos", "macOS"}, {"build-snapcraft", "Snap"}} {
		workflow := mustReadWorkflowDoc(t, ".github/workflows/"+tc.owner+".yml")
		for _, job := range []string{"inspect", "attest"} {
			step := mustStepNamed(t, mustJob(t, workflow, job), "Inspect full "+tc.label+" owner")
			for _, state := range []string{"complete", "missing", "partial", "retry missing", "wrong owner"} {
				t.Run(tc.owner+"/"+job+"/"+state, func(t *testing.T) {
					dir := t.TempDir()
					sha := strings.Repeat("a", 40)
					digest := strings.Repeat("b", 64)
					owner := tc.owner + ".yml"
					status := state
					if state == "retry missing" {
						status = "missing"
					}
					if state == "wrong owner" {
						status = "complete"
						owner = "build-linux.yml"
					}
					fixture := filepath.Join(dir, "inspection.json")
					writeJSONFixture(t, fixture, map[string]any{"repository": "Picocrypt-NG/Picocrypt-NG", "source_sha": sha, "version": "3.0", "canonical_manifest_sha256": digest, "owner_workflow": owner, "status": status})
					gate := filepath.Join(dir, releaseGateScriptPath)
					if err := os.MkdirAll(filepath.Dir(gate), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(gate, []byte("#!/bin/sh\n[ \"$*\" = 'inspect-owner 3.0' ] || exit 97\ncat \"$INSPECTION_FIXTURE\"\n"), 0o700); err != nil {
						t.Fatal(err)
					}
					out := filepath.Join(dir, "output")
					attempt := "1"
					if state == "retry missing" {
						attempt = "2"
					}
					cmd := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
					cmd.Dir = dir
					cmd.Env = append(os.Environ(), "SOURCE_SHA="+sha, "SOURCE_VERSION=3.0", "CANONICAL_MANIFEST_SHA256="+digest, "GITHUB_OUTPUT="+out, "INSPECTION_FIXTURE="+fixture, "GITHUB_RUN_ATTEMPT="+attempt)
					output, err := cmd.CombinedOutput()
					ok := state == "complete" || state == "missing" || state == "retry missing"
					if (err == nil) != ok {
						t.Fatalf("inspection %s: %v: %s", state, err, output)
					}
					data, _ := os.ReadFile(out)
					if !ok {
						if len(data) != 0 {
							t.Fatal("partial/invalid state must not advertise signing or reuse authority")
						}
						return
					}
					want := "state=missing\nstaged=false\nreused=false\n"
					if state == "complete" {
						want = "state=complete\nstaged=true\nreused=true\n"
					}
					if string(data) != want {
						t.Fatalf("inspection outputs %q want%q", data, want)
					}
				})
			}
		}
	}
}
