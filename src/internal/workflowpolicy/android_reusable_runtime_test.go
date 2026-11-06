//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAndroidReusableSourceGuardRejectsAuthorityDrift(t *testing.T) {
	step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-android.yml"), "inspect"), "Validate reusable Android source")
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

func TestAndroidReusableCarrierMetadataRejectsWrongIDSourceDigestAttemptAndExpiry(t *testing.T) {
	w := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	for _, carrier := range []struct{ job, step, prefix string }{
		{"sign", "Verify Android signing-input metadata", "unsigned-android"},
		{"attest", "Verify signed APK carrier metadata", "signed-android"},
	} {
		step := mustStepNamed(t, mustJob(t, w, carrier.job), carrier.step)
		for _, defect := range []string{"none", "retained attempt", "id", "digest", "name", "run", "source", "expired", "future", "missing id"} {
			t.Run(carrier.job+"/"+defect, func(t *testing.T) {
				dir := t.TempDir()
				source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
				metadata := map[string]any{"id": 101, "name": carrier.prefix + "-attempt-1", "digest": "sha256:" + digest, "expired": false, "workflow_run": map[string]any{"id": 77, "head_sha": source}}
				current, attempt, id := "1", "1", "101"
				switch defect {
				case "retained attempt":
					current = "2"
				case "id":
					metadata["id"] = 102
				case "digest":
					metadata["digest"] = "sha256:" + strings.Repeat("c", 64)
				case "name":
					metadata["name"] = "different-attempt-1"
				case "run":
					metadata["workflow_run"].(map[string]any)["id"] = 78
				case "source":
					metadata["workflow_run"].(map[string]any)["head_sha"] = strings.Repeat("c", 40)
				case "expired":
					metadata["expired"] = true
				case "future":
					attempt = "2"
				case "missing id":
					id = ""
				}
				data, err := json.Marshal(metadata)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "gh"), []byte("#!/bin/sh\n[ \"$*\" = 'api --method GET repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/101' ] || exit 97\ncat \"$CARRIER_FIXTURE\"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
				command.Dir = dir
				command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG", "GITHUB_SHA="+source, "GITHUB_RUN_ID=77", "GITHUB_RUN_ATTEMPT="+current, "CARRIER_ID="+id, "CARRIER_DIGEST="+digest, "CARRIER_ATTEMPT="+attempt, "CARRIER_FIXTURE="+filepath.Join(dir, "metadata.json"))
				output, err := command.CombinedOutput()
				if (err == nil) != (defect == "none" || defect == "retained attempt") {
					t.Fatalf("carrier %s err=%v: %s", defect, err, output)
				}
			})
		}
	}
}

func TestAndroidReusableRawAPKsMustMatchEverySigningInput(t *testing.T) {
	step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-android.yml"), "sign"), "Match raw APKs to signing inputs")
	for _, defect := range []string{"none", "last APK differs", "raw matching symlink", "signing matching symlink", "missing universal"} {
		t.Run(defect, func(t *testing.T) {
			dir := t.TempDir()
			for _, folder := range []string{"artifacts/build-android", "unsigned-release"} {
				if err := os.MkdirAll(filepath.Join(dir, folder), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, abi := range []string{"armeabi-v7a", "arm64-v8a", "x86", "x86_64", "universal"} {
				for _, file := range []string{"artifacts/build-android/Picocrypt-NG-android-" + abi + ".apk", "unsigned-release/app-" + abi + "-release-unsigned.apk"} {
					if err := os.WriteFile(filepath.Join(dir, file), []byte("fixture "+abi), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			raw := filepath.Join(dir, "artifacts/build-android/Picocrypt-NG-android-universal.apk")
			unsigned := filepath.Join(dir, "unsigned-release/app-universal-release-unsigned.apk")
			switch defect {
			case "last APK differs":
				if err := os.WriteFile(raw, []byte("other"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing universal":
				if err := os.Remove(unsigned); err != nil {
					t.Fatal(err)
				}
			case "raw matching symlink", "signing matching symlink":
				path, target := raw, unsigned
				if defect == "signing matching symlink" {
					path, target = unsigned, raw
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
			command.Dir = dir
			output, err := command.CombinedOutput()
			if (err == nil) != (defect == "none") {
				t.Fatalf("raw binding %s err=%v: %s", defect, err, output)
			}
		})
	}
}

// These exercise the workflow's decision on the inspected protocol, not real release/signing services.
func TestAndroidReusableFreshInspectionHandlesCompletePartialMissingAndRetry(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	for _, job := range []string{"inspect", "sign", "attest"} {
		step := mustStepNamed(t, mustJob(t, workflow, job), "Inspect full Android owner")
		for _, state := range []string{"complete", "partial", "missing", "retry missing", "wrong owner"} {
			t.Run(job+"/"+state, func(t *testing.T) {
				dir := t.TempDir()
				source := strings.Repeat("a", 40)
				digest := strings.Repeat("b", 64)
				status := state
				if state == "retry missing" {
					status = "missing"
				}
				owner := "build-android.yml"
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
