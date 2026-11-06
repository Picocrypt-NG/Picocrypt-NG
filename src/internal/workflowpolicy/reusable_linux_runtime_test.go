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

func TestLinuxReusableSourceGuardRejectsAuthorityDrift(t *testing.T) {
	step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-linux.yml"), "inspect"), "Validate reusable Linux source")
	for _, defect := range []string{"none", "attempt2", "repository", "caller", "ref", "event", "source", "workflow SHA", "checkout", "version", "canonical"} {
		t.Run(defect, func(t *testing.T) {
			dir := t.TempDir()
			source := strings.Repeat("a", 40)
			version := "3.0"
			if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(version+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(dir, releaseManifestScriptPath)
			if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifest, []byte(mustReadRepoFile(t, releaseManifestScriptPath)), 0o700); err != nil {
				t.Fatal(err)
			}
			canonical, err := exec.Command("bash", manifest, version).Output()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\nprintf '%s\\n' \"$FIXTURE_CHECKOUT\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			values := map[string]string{"GITHUB_REPOSITORY": "Picocrypt-NG/Picocrypt-NG", "GITHUB_WORKFLOW_REF": "Picocrypt-NG/Picocrypt-NG/.github/workflows/release.yml@refs/heads/main", "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": source, "GITHUB_WORKFLOW_SHA": source, "SOURCE_SHA": source, "SOURCE_VERSION": version, "CANONICAL_MANIFEST_SHA256": fmt.Sprintf("%x", sha256.Sum256(canonical)), "FIXTURE_CHECKOUT": source, "GITHUB_RUN_ATTEMPT": "1"}
			for field, name := range map[string]string{"repository": "GITHUB_REPOSITORY", "caller": "GITHUB_WORKFLOW_REF", "ref": "GITHUB_REF", "event": "GITHUB_EVENT_NAME", "source": "SOURCE_SHA", "workflow SHA": "GITHUB_WORKFLOW_SHA", "checkout": "FIXTURE_CHECKOUT", "version": "SOURCE_VERSION", "canonical": "CANONICAL_MANIFEST_SHA256"} {
				if defect == field {
					values[name] = "wrong"
				}
			}
			if defect == "attempt2" {
				values["GITHUB_RUN_ATTEMPT"] = "2"
			}
			command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
			command.Dir = dir
			command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
			for k, v := range values {
				command.Env = append(command.Env, k+"="+v)
			}
			output, runErr := command.CombinedOutput()
			if (runErr == nil) != (defect == "none" || defect == "attempt2") {
				t.Fatalf("source guard %s err=%v: %s", defect, runErr, output)
			}
		})
	}
}

// These exercise the workflow's decision on the inspected protocol, not real release/signing services.
func TestLinuxReusableFreshInspectionHandlesCompletePartialMissingAndRetry(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-linux.yml")
	for _, job := range []string{"inspect", "attest"} {
		step := mustStepNamed(t, mustJob(t, workflow, job), "Inspect full Linux owner")
		for _, state := range []string{"complete", "partial", "missing", "retry missing", "wrong owner"} {
			t.Run(job+"/"+state, func(t *testing.T) {
				dir := t.TempDir()
				source := strings.Repeat("a", 40)
				digest := strings.Repeat("b", 64)
				status := state
				if state == "retry missing" {
					status = "missing"
				}
				owner := "build-linux.yml"
				if state == "wrong owner" {
					status = "complete"
					owner = "build-macos.yml"
				}
				report := map[string]any{"repository": "Picocrypt-NG/Picocrypt-NG", "source_sha": source, "version": "3.0", "canonical_manifest_sha256": digest, "owner_workflow": owner, "status": status}
				writeJSONFixture(t, filepath.Join(dir, "inspection.json"), report)
				gate := filepath.Join(dir, releaseGateScriptPath)
				if err := os.MkdirAll(filepath.Dir(gate), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(gate, []byte("#!/bin/sh\n[ \"$*\" = 'inspect-owner 3.0' ] || exit 97\ncat \"$INSPECTION_FIXTURE\"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				outputPath := filepath.Join(dir, "output")
				attempt := "1"
				if state == "retry missing" {
					attempt = "2"
				}
				command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
				command.Dir = dir
				command.Env = append(os.Environ(), "SOURCE_SHA="+source, "SOURCE_VERSION=3.0", "CANONICAL_MANIFEST_SHA256="+digest, "GITHUB_OUTPUT="+outputPath, "INSPECTION_FIXTURE="+filepath.Join(dir, "inspection.json"), "GITHUB_RUN_ATTEMPT="+attempt)
				output, err := command.CombinedOutput()
				wantOK := state == "complete" || state == "missing" || state == "retry missing"
				if (err == nil) != wantOK {
					t.Fatalf("inspection %s err=%v: %s", state, err, output)
				}
				data, _ := os.ReadFile(outputPath)
				if !wantOK {
					if len(data) != 0 {
						t.Fatal("invalid/partial inspection advertised successful authority state")
					}
					return
				}
				want := "state=missing\nstaged=false\nreused=false\n"
				if state == "complete" {
					want = "state=complete\nstaged=true\nreused=true\n"
				}
				if string(data) != want {
					t.Fatalf("outputs=%q want%q", data, want)
				}
			})
		}
	}
}
