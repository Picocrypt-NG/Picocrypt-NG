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

func windowsReusableFixture(t *testing.T, owner string) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	manifest := filepath.Join(dir, releaseManifestScriptPath)
	writeWindowsMetadataFixture(t, manifest, mustReadRepoFile(t, releaseManifestScriptPath), 0o700)
	writeWindowsMetadataFixture(t, filepath.Join(dir, "VERSION"), "3.0\r\n", 0o600)
	source := strings.Repeat("a", 40)
	writeWindowsMetadataFixture(t, filepath.Join(dir, "bin", "git"), "#!/bin/sh\nprintf '%s\\n' \"$FIXTURE_CHECKOUT\"\n", 0o700)
	canonical, err := exec.Command("bash", manifest, "3.0").Output()
	if err != nil {
		t.Fatal(err)
	}
	return dir, map[string]string{"PATH": filepath.Join(dir, "bin") + ":" + os.Getenv("PATH"), "GITHUB_REPOSITORY": "Picocrypt-NG/Picocrypt-NG", "GITHUB_WORKFLOW_REF": "Picocrypt-NG/Picocrypt-NG/.github/workflows/release.yml@refs/heads/main", "GITHUB_WORKFLOW_SHA": source, "GITHUB_SHA": source, "SOURCE_SHA": source, "SOURCE_VERSION": "3.0", "CANONICAL_MANIFEST_SHA256": fmt.Sprintf("%x", sha256.Sum256(canonical)), "FIXTURE_CHECKOUT": source, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "OWNER_WORKFLOW": owner + ".yml", "GITHUB_WORKSPACE": dir, "GITHUB_OUTPUT": filepath.Join(dir, "output"), "GITHUB_ENV": filepath.Join(dir, "environment")}
}

func runWindowsReusableBody(t *testing.T, dir string, environment map[string]string, body string) ([]byte, error) {
	t.Helper()
	command := exec.Command("bash", "-euo", "pipefail", "-c", body)
	command.Dir = dir
	command.Env = os.Environ()
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	return command.CombinedOutput()
}

func TestWindowsReusableSourceGuardRejectsDriftOnEveryAuthorityBoundary(t *testing.T) {
	for _, owner := range windowsReusableOwners() {
		workflow := mustReadWorkflowDoc(t, ".github/workflows/"+owner+".yml")
		for _, jobName := range []string{"inspect", "sign", "attest", "stage"} {
			body := mustStepNamed(t, mustJob(t, workflow, jobName), "Validate reusable Windows source").Run
			for _, defect := range []string{"none", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_SHA", "SOURCE_SHA", "FIXTURE_CHECKOUT", "GITHUB_REF", "GITHUB_EVENT_NAME", "SOURCE_VERSION", "CANONICAL_MANIFEST_SHA256"} {
				t.Run(owner+"/"+jobName+"/"+defect, func(t *testing.T) {
					dir, env := windowsReusableFixture(t, owner)
					if defect != "none" {
						env[defect] = "wrong"
					}
					out, err := runWindowsReusableBody(t, dir, env, body)
					if (err == nil) != (defect == "none") {
						t.Fatalf("source guard %s err=%v: %s", defect, err, out)
					}
				})
			}
		}
	}
}

func TestWindowsReusableFreshInspectionUsesBinaryJQAndRefusesPartialOwners(t *testing.T) {
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range windowsReusableOwners() {
		workflow := mustReadWorkflowDoc(t, ".github/workflows/"+owner+".yml")
		for _, jobName := range []string{"inspect", "sign", "attest"} {
			body := mustStepNamed(t, mustJob(t, workflow, jobName), "Inspect full Windows owner").Run
			for _, state := range []string{"complete", "missing", "partial", "wrong owner", "windows workspace"} {
				t.Run(owner+"/"+jobName+"/"+state, func(t *testing.T) {
					dir, env := windowsReusableFixture(t, owner)
					actualOwner, status := owner+".yml", state
					if state == "windows workspace" {
						status = "missing"
					}
					if state == "wrong owner" {
						actualOwner = "build-android.yml"
						status = "complete"
					}
					report := map[string]string{"repository": env["GITHUB_REPOSITORY"], "source_sha": env["SOURCE_SHA"], "version": env["SOURCE_VERSION"], "canonical_manifest_sha256": env["CANONICAL_MANIFEST_SHA256"], "owner_workflow": actualOwner, "status": status}
					data, e := json.Marshal(report)
					if e != nil {
						t.Fatal(e)
					}
					writeWindowsMetadataFixture(t, filepath.Join(dir, "report.json"), string(data), 0o600)
					writeWindowsMetadataFixture(t, filepath.Join(dir, releaseGateScriptPath), "#!/bin/bash\nset -euo pipefail\n[ \"$*\" = 'inspect-owner 3.0' ]\n[ -z \"$GITHUB_OUTPUT\" ]\n[[ $GITHUB_WORKSPACE == /* ]]\njq . \"$FIXTURE_REPORT\"\n", 0o700)
					env["FIXTURE_REPORT"] = filepath.Join(dir, "report.json")
					if jobName == "sign" {
						writeWindowsMetadataFixture(t, filepath.Join(dir, "bin", "jq"), "#!/bin/bash\nset -euo pipefail\nexport PATH=\"$FIXTURE_REAL_PATH\"\nfor argument in \"$@\"; do\n  if [[ $argument == -b || $argument == --binary ]]; then exec \"$FIXTURE_JQ\" \"$@\"; fi\ndone\n\"$FIXTURE_JQ\" \"$@\" | sed 's/$/\\r/'\n", 0o700)
						if state == "windows workspace" {
							env["GITHUB_WORKSPACE"] = "D:\\fixture\\workspace"
							writeWindowsMetadataFixture(t, filepath.Join(dir, "bin", "cygpath"), "#!/bin/sh\nprintf '%s\\n' \"$FIXTURE_WORKSPACE\"\n", 0o700)
							env["FIXTURE_WORKSPACE"] = dir
						}
						env["FIXTURE_JQ"] = jq
						env["FIXTURE_REAL_PATH"] = os.Getenv("PATH")
					}
					out, runErr := runWindowsReusableBody(t, dir, env, body)
					want := state == "complete" || state == "missing" || state == "windows workspace"
					if (runErr == nil) != want {
						t.Fatalf("inspection err=%v: %s", runErr, out)
					}
					written, _ := os.ReadFile(env["GITHUB_OUTPUT"])
					if !want {
						if len(written) != 0 {
							t.Fatal("invalid inventory advertised success")
						}
						return
					}
					expected := "state=missing\nstaged=false\nreused=false\n"
					if state == "complete" {
						expected = "state=complete\nstaged=true\nreused=true\n"
					}
					if string(written) != expected {
						t.Fatalf("outputs=%q want%q", written, expected)
					}
				})
			}
		}
	}
}

func TestWindowsReusableSigningCarrierMustMatchValidatedRawBytes(t *testing.T) {
	for _, owner := range windowsReusableOwners() {
		body := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/"+owner+".yml"), "sign"), "Validate Windows signing carrier").Run
		for _, defect := range []string{"none", "different bytes", "missing", "extra", "symlink"} {
			t.Run(owner+"/"+defect, func(t *testing.T) {
				dir, env := windowsReusableFixture(t, owner)
				unsigned := "unsigned-build"
				files := []string{"Picocrypt-NG-portable.exe", "Picocrypt-NG-cli.exe", "Picocrypt-NG-Setup.exe"}
				if owner == "build-windows-legacy" {
					unsigned = "unsigned-legacy"
					files = []string{"Picocrypt-NG-cli-Legacy.exe"}
				}
				env["ARTIFACT_ROOT"] = "artifacts"
				for _, file := range files {
					for _, parent := range []string{unsigned, "artifacts/" + owner} {
						writeWindowsMetadataFixture(t, filepath.Join(dir, parent, file), "unsigned fixture "+file, 0o600)
					}
				}
				last := filepath.Join(dir, unsigned, files[len(files)-1])
				switch defect {
				case "different bytes":
					writeWindowsMetadataFixture(t, last, "substituted", 0o600)
				case "missing", "symlink":
					if e := os.Remove(last); e != nil {
						t.Fatal(e)
					}
					if defect == "symlink" {
						if e := os.Symlink(filepath.Join(dir, "artifacts", owner, files[len(files)-1]), last); e != nil {
							t.Fatal(e)
						}
					}
				case "extra":
					writeWindowsMetadataFixture(t, filepath.Join(dir, unsigned, "extra.exe"), "unexpected", 0o600)
				}
				out, err := runWindowsReusableBody(t, dir, env, body)
				if (err == nil) != (defect == "none") {
					t.Fatalf("carrier check err=%v: %s", err, out)
				}
			})
		}
	}
}

func TestWindowsReusableOSCarrierRejectsExpiryAndTupleSubstitution(t *testing.T) {
	for _, owner := range windowsReusableOwners() {
		body := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/"+owner+".yml"), "attest"), "Verify OS-signed Windows carrier metadata").Run
		for _, defect := range []string{"none", "empty ID", "empty digest", "empty attempt", "future attempt", "expired", "wrong name", "wrong digest", "wrong ID", "wrong source", "wrong run"} {
			t.Run(owner+"/"+defect, func(t *testing.T) {
				dir, env := windowsReusableFixture(t, owner)
				metadata := map[string]any{"id": 101, "name": "os-signed-" + owner + "-attempt-1", "digest": "sha256:" + strings.Repeat("b", 64), "expired": false, "workflow_run": map[string]any{"id": 123, "head_sha": env["SOURCE_SHA"]}}
				env["CARRIER_ID"] = "101"
				env["CARRIER_DIGEST"] = strings.Repeat("b", 64)
				env["CARRIER_ATTEMPT"] = "1"
				switch defect {
				case "empty ID":
					env["CARRIER_ID"] = ""
				case "empty digest":
					env["CARRIER_DIGEST"] = ""
				case "empty attempt":
					env["CARRIER_ATTEMPT"] = ""
				case "future attempt":
					env["CARRIER_ATTEMPT"] = "3"
				case "expired":
					metadata["expired"] = true
				case "wrong name":
					metadata["name"] = "signed-windows"
				case "wrong digest":
					metadata["digest"] = "sha256:" + strings.Repeat("c", 64)
				case "wrong ID":
					metadata["id"] = 102
				case "wrong source":
					metadata["workflow_run"].(map[string]any)["head_sha"] = strings.Repeat("c", 40)
				case "wrong run":
					metadata["workflow_run"].(map[string]any)["id"] = 124
				}
				data, e := json.Marshal(metadata)
				if e != nil {
					t.Fatal(e)
				}
				writeWindowsMetadataFixture(t, filepath.Join(dir, "metadata.json"), string(data), 0o600)
				writeWindowsMetadataFixture(t, filepath.Join(dir, "bin", "gh"), "#!/bin/bash\nset -euo pipefail\n[ \"$*\" = 'api --method GET repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/101' ]\ncat \"$FIXTURE_METADATA\"\n", 0o700)
				env["FIXTURE_METADATA"] = filepath.Join(dir, "metadata.json")
				out, err := runWindowsReusableBody(t, dir, env, body)
				if (err == nil) != (defect == "none") {
					t.Fatalf("OS carrier metadata err=%v: %s", err, out)
				}
			})
		}
	}
}
