//go:build linux

package workflowpolicy

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsSignPathResumeRejectsPendingExpiredAndSubstitutedRequests(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"bad window", "must be an integer"},
		{"pending", "Continue this run after approval"},
		{"expired", "approval window expired"},
		{"input changed", "does not match the immutable original input"},
		{"wrong request", "different request ID"},
		{"wrong commit", "origin or policy differs"},
		{"wrong attempt", "origin or policy differs"},
		{"wrong run", "origin or policy differs"},
		{"retained completion", ""},
		{"approved download", ""},
		{"unexpected filename", "Unexpected SignPath signed payload files"},
		{"extra archive member", "Unexpected SignPath signed payload files"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, env := windowsReusableFixture(t, "build-windows")
			pwsh, err := exec.LookPath("pwsh")
			if err != nil {
				t.Skip("PowerShell unavailable")
			}
			phase := "windows-binaries"
			const requestID = "11111111-2222-4333-8444-555555555555"
			digest := "sha256:" + strings.Repeat("a", 64)
			expiry := time.Now().Add(time.Hour)
			env["RUNNER_TEMP"] = dir
			env["GITHUB_STEP_SUMMARY"] = filepath.Join(dir, "summary")
			env["SIGNPATH_PHASE"], env["SIGNPATH_PROJECT_SLUG"] = phase, "test-project"
			env["SIGNPATH_INPUT_ID"], env["SIGNPATH_INPUT_DIGEST"] = "41", digest
			env["SIGNPATH_API_TOKEN"] = "fake-signpath-token"
			env["SIGNPATH_APPROVAL_WINDOW_HOURS"] = "12"
			env["SIGNPATH_COMPLETED_ARTIFACT_ID"] = ""
			env["SIGNPATH_OUTPUT_PATH"] = filepath.Join(dir, "signed-output")
			env["FIXTURE_SIGNED_ZIP"] = ""
			operation := "retrieve"
			if tc.name == "bad window" {
				operation, env["SIGNPATH_APPROVAL_WINDOW_HOURS"] = "inspect", "25"
			}
			if tc.name == "expired" || tc.name == "retained completion" {
				expiry = time.Now().Add(-time.Hour)
			}
			checkpoint := map[string]any{
				"schema": 1, "repository": env["GITHUB_REPOSITORY"], "source_sha": env["GITHUB_SHA"], "run_id": "123",
				"attempt": "1", "phase": phase, "project": env["SIGNPATH_PROJECT_SLUG"],
				"policy": "release-signing", "request_id": requestID, "input_id": "41",
				"input_digest": digest, "expires_at": expiry.Unix(),
			}
			if tc.name == "input changed" {
				checkpoint["input_digest"] = "sha256:" + strings.Repeat("b", 64)
			}
			writeWindowsMetadataFixture(t, filepath.Join(dir, "signpath-windows-binaries-request", "request.json"), signPathResumeFixtureJSON(t, checkpoint), 0o600)
			origin := map[string]string{"url": "https://github.com/" + env["GITHUB_REPOSITORY"], "branchName": "main", "commitId": env["GITHUB_SHA"]}
			if tc.name == "wrong commit" {
				origin["commitId"] = strings.Repeat("b", 40)
			}
			status, final := "WaitingForApproval", false
			if tc.name == "retained completion" {
				env["SIGNPATH_COMPLETED_ARTIFACT_ID"] = "43"
				status, final = "Completed", true
			}
			expectedFiles := map[string]string{
				"Picocrypt-NG-cli.exe":      "signed CLI fixture",
				"Picocrypt-NG-portable.exe": "signed portable fixture",
			}
			if tc.name == "approved download" || tc.name == "unexpected filename" || tc.name == "extra archive member" {
				status, final = "Completed", true
				files := maps.Clone(expectedFiles)
				if tc.name != "approved download" {
					files["unexpected.txt"] = "unexpected fixture member"
				}
				if tc.name == "unexpected filename" {
					delete(files, "Picocrypt-NG-cli.exe")
				}
				var data bytes.Buffer
				archive := zip.NewWriter(&data)
				for name, value := range files {
					entry, err := archive.Create(name)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := entry.Write([]byte(value)); err != nil {
						t.Fatal(err)
					}
				}
				if err := archive.Close(); err != nil {
					t.Fatal(err)
				}
				env["FIXTURE_SIGNED_ZIP"] = filepath.Join(dir, "signed-fixture.zip")
				writeWindowsMetadataFixture(t, env["FIXTURE_SIGNED_ZIP"], data.String(), 0o600)
				env["FIXTURE_SIGNED_URI"] = "https://app.signpath.io/Api/v1/d6e78672-6bae-47d3-b2b8-fa464705b34e/SigningRequests/" + requestID + "/SignedArtifact"
			}
			buildPath := "/actions/runs/123"
			switch tc.name {
			case "approved download":
				env["GITHUB_RUN_ATTEMPT"] = "2"
				buildPath += "/attempts/1"
			case "wrong attempt":
				env["GITHUB_RUN_ATTEMPT"] = "2"
				buildPath += "/attempts/2"
			case "wrong run":
				env["GITHUB_RUN_ATTEMPT"] = "2"
				buildPath = "/actions/runs/456/attempts/1"
			}
			detail := map[string]any{
				"projectSlug": "test-project", "signingPolicySlug": "release-signing", "artifactConfigurationSlug": phase,
				"status": status, "workflowStatus": status, "isFinalStatus": final,
				"origin": map[string]any{
					"repositoryData": origin,
					"buildData":      map[string]string{"url": "https://github.com/" + env["GITHUB_REPOSITORY"] + buildPath},
				},
			}
			statusID := requestID
			if tc.name == "wrong request" {
				statusID = "22222222-2222-4333-8444-555555555555"
			}
			env["FIXTURE_STATUS"] = signPathResumeFixtureJSON(t, map[string]any{"signingRequestId": statusID, "status": status, "workflowStatus": status, "isFinalStatus": final})
			env["FIXTURE_SIGNPATH_DETAIL"] = signPathResumeFixtureJSON(t, detail)
			const mock = "function gh { throw 'unexpected GitHub lookup' }\n" +
				"function Invoke-RestMethod {\n" +
				"    param($Uri, $Headers, $MaximumRedirection, $TimeoutSec)\n" +
				"    if ($Uri.EndsWith('/Status')) { return (ConvertFrom-Json $env:FIXTURE_STATUS) }\n" +
				"    return (ConvertFrom-Json $env:FIXTURE_SIGNPATH_DETAIL)\n" +
				"}\nfunction Invoke-WebRequest {\n" +
				"    param($Uri, $Headers, $OutFile, $MaximumRedirection, $TimeoutSec)\n" +
				"    if (!$env:FIXTURE_SIGNED_ZIP -or $Uri -cne $env:FIXTURE_SIGNED_URI) { throw 'unexpected download from fixture' }\n" +
				"    Copy-Item -LiteralPath $env:FIXTURE_SIGNED_ZIP -Destination $OutFile\n" +
				"}\n"
			writeWindowsMetadataFixture(t, filepath.Join(dir, "signpath.ps1"), mustReadRepoFile(t, ".github/actions/resumable-signpath/signpath.ps1"), 0o600)
			wrapper := filepath.Join(dir, "fixture.ps1")
			writeWindowsMetadataFixture(t, wrapper, mock+"& (Join-Path $PSScriptRoot 'signpath.ps1') -Operation "+operation+"\n", 0o600)
			cmd := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", wrapper)
			cmd.Dir = dir
			cmd.Env = os.Environ()
			for key, value := range env {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
			out, err := cmd.CombinedOutput()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("approved request refused: %v: %s", err, out)
				}
				if tc.name == "approved download" {
					files, err := os.ReadDir(env["SIGNPATH_OUTPUT_PATH"])
					if err != nil || len(files) != len(expectedFiles) {
						t.Fatalf("unexpected extracted files: %v: %v", files, err)
					}
					for name, expected := range expectedFiles {
						data, err := os.ReadFile(filepath.Join(env["SIGNPATH_OUTPUT_PATH"], name))
						if err != nil || string(data) != expected {
							t.Fatalf("incorrect payload for %s: %q: %v", name, data, err)
						}
					}
					output, err := os.ReadFile(env["GITHUB_OUTPUT"])
					if err != nil || strings.TrimSpace(string(output)) != "downloaded=true" {
						t.Fatalf("downloaded payload did not reach the artifact upload step: %q: %v", output, err)
					}
				}
				return
			}
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("continuation did not fail closed: %v: %s", err, out)
			}
			if _, err := os.Stat(env["SIGNPATH_OUTPUT_PATH"]); !os.IsNotExist(err) {
				t.Fatalf("rejected request left a signed output directory: %v", err)
			}
			if tc.name == "pending" {
				summary, readErr := os.ReadFile(env["GITHUB_STEP_SUMMARY"])
				if readErr != nil || !strings.Contains(string(summary), requestID) || !strings.Contains(string(summary), "Re-run failed jobs") {
					t.Fatalf("missing resumable signing instruction: %s: %v", summary, readErr)
				}
			}
		})
	}
}

func signPathResumeFixtureJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestWindowsSignPathRecordDoesNotWaitForGitHubReadback(t *testing.T) {
	dir, env := windowsReusableFixture(t, "build-windows")
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell unavailable")
	}
	env["RUNNER_TEMP"] = dir
	env["SIGNPATH_PHASE"], env["SIGNPATH_PROJECT_SLUG"] = "windows-binaries", "test-project"
	env["SIGNPATH_INPUT_ID"], env["SIGNPATH_INPUT_DIGEST"] = "41", strings.Repeat("a", 64)
	env["SIGNPATH_REQUEST_ID"] = "11111111-2222-4333-8444-555555555555"
	env["SIGNPATH_APPROVAL_WINDOW_HOURS"] = ""
	writeWindowsMetadataFixture(t, filepath.Join(dir, "signpath.ps1"), mustReadRepoFile(t, ".github/actions/resumable-signpath/signpath.ps1"), 0o600)
	wrapper := filepath.Join(dir, "fixture.ps1")
	writeWindowsMetadataFixture(t, wrapper, "function gh { throw 'unexpected GitHub lookup after SignPath submission' }\n& (Join-Path $PSScriptRoot 'signpath.ps1') -Operation record\n", 0o600)
	cmd := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", wrapper)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	earliest := time.Now().Add(12 * time.Hour).Unix()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fresh SignPath receipt could not be saved: %v: %s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "signpath-windows-binaries-request", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		SourceSHA   string `json:"source_sha"`
		RequestID   string `json:"request_id"`
		InputID     string `json:"input_id"`
		InputDigest string `json:"input_digest"`
		Expires     int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	latest := time.Now().Add(12 * time.Hour).Unix()
	if receipt.SourceSHA != env["GITHUB_SHA"] || receipt.RequestID != env["SIGNPATH_REQUEST_ID"] ||
		receipt.InputID != env["SIGNPATH_INPUT_ID"] || receipt.InputDigest != "sha256:"+env["SIGNPATH_INPUT_DIGEST"] ||
		receipt.Expires < earliest || receipt.Expires > latest {
		t.Fatalf("invalid default twelve-hour receipt: %+v", receipt)
	}
}
