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

func TestAppImageReusableSourceGuardRejectsAuthorityDrift(t *testing.T) {
	step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml"), "inspect"), "Validate reusable AppImage source")
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
func TestAppImageReusableFreshInspectionHandlesCompletePartialMissingAndRetry(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	for _, job := range []string{"inspect", "sign", "attest"} {
		step := mustStepNamed(t, mustJob(t, workflow, job), "Inspect full AppImage owner")
		for _, state := range []string{"complete", "partial", "missing", "retry missing", "wrong owner"} {
			t.Run(job+"/"+state, func(t *testing.T) {
				dir := t.TempDir()
				source := strings.Repeat("a", 40)
				digest := strings.Repeat("b", 64)
				status := state
				if state == "retry missing" {
					status = "missing"
				}
				owner := "build-appimage.yml"
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

func TestAppImageReusableCarrierMetadataRejectsWrongIDSourceDigestAttemptAndExpiry(t *testing.T) {
	w := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	for _, carrier := range []struct{ job, step, prefix string }{
		{"sign", "Verify AppImage signing-input metadata", "appimage-signing-input"},
		{"attest", "Verify signed AppImage carrier metadata", "signed-appimage"},
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

func TestAppImageReusableCarrierOptionRejectsNonBooleanBeforeProducer(t *testing.T) {
	step := mustCompositeStepNamed(t, mustReadCompositeActionDoc(t, ".github/actions/build-appimage/action.yml"), "Assert prepared AppImage source")
	for _, option := range []string{"true", "false", "", "TRUE", "1"} {
		t.Run("option="+option, func(t *testing.T) {
			dir := t.TempDir()
			source := strings.Repeat("a", 40)
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
			if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\nprintf '%s\\n' \"$SOURCE_SHA\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			outputPath := filepath.Join(dir, "output")
			command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
			command.Dir = dir
			command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "SOURCE_SHA="+source, "GITHUB_SHA="+source, "SOURCE_VERSION=3.0", "CANONICAL_MANIFEST_SHA256="+fmt.Sprintf("%x", sha256.Sum256(canonical)), "GITHUB_OUTPUT="+outputPath, "GITHUB_RUN_ATTEMPT=1", "RETAIN_SIGNING_INPUT="+option)
			output, err := command.CombinedOutput()
			wantOK := option == "true" || option == "false"
			if (err == nil) != wantOK {
				t.Fatalf("retention flag %q err=%v: %s", option, err, output)
			}
			data, _ := os.ReadFile(outputPath)
			if !wantOK && len(data) != 0 {
				t.Fatal("invalid retention flag advertised a source output")
			}
		})
	}
}

func TestAppImageReusableMovedTarProducerStillMatchesExactExtractorHash(t *testing.T) {
	prepare := mustCompositeStepNamed(t, mustReadCompositeActionDoc(t, ".github/actions/build-appimage/action.yml"), "Prepare signing input")
	extract := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml"), "sign"), "Check and extract signing input")
	for _, wrongHash := range []bool{false, true} {
		t.Run(fmt.Sprint("wrong hash=", wrongHash), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "AppDir", "usr"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "AppDir", "usr", "fixture"), []byte("synthetic AppDir fixture\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			outputPath := filepath.Join(dir, "output")
			command := exec.Command("bash", "-euo", "pipefail", "-c", prepare.Run)
			command.Dir = dir
			command.Env = append(os.Environ(), "GITHUB_OUTPUT="+outputPath)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("producer err=%v: %s", err, output)
			}
			archive, err := os.ReadFile(filepath.Join(dir, "AppDir.tar"))
			if err != nil {
				t.Fatal(err)
			}
			digest := fmt.Sprintf("%x", sha256.Sum256(archive))
			data, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "sha256="+digest+"\n" {
				t.Fatal("moved tar producer must export its actual bytes, not the carrier ZIP hash")
			}
			if err := os.Mkdir(filepath.Join(dir, "signing-input"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, "AppDir.tar"), filepath.Join(dir, "signing-input", "AppDir.tar")); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(dir, ".github", "scripts", "extract-appimage-appdir.py")
			if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(script, []byte(mustReadRepoFile(t, ".github/scripts/extract-appimage-appdir.py")), 0o600); err != nil {
				t.Fatal(err)
			}
			if wrongHash {
				digest = strings.Repeat("c", 64)
			}
			command = exec.Command("bash", "-euo", "pipefail", "-c", extract.Run)
			command.Dir = dir
			command.Env = append(os.Environ(), "EXPECTED_SHA256="+digest)
			output, err := command.CombinedOutput()
			if (err == nil) == wrongHash {
				t.Fatalf("extract err=%v: %s", err, output)
			}
			if wrongHash {
				if _, err := os.Stat(filepath.Join(dir, "signing-work")); !os.IsNotExist(err) {
					t.Fatal("wrong tar hash must fail before extraction creates any destination")
				}
				return
			}
			data, err = os.ReadFile(filepath.Join(dir, "signing-work", "AppDir", "usr", "fixture"))
			if err != nil || string(data) != "synthetic AppDir fixture\n" {
				t.Fatalf("real extractor did not preserve the exact synthetic AppDir: %v", err)
			}
		})
	}
}
