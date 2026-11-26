//go:build linux

package workflowpolicy

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestStageReceiptResolver(t *testing.T) {
	const repo = "Picocrypt-NG/Picocrypt-NG"
	const repoID int64 = 1000000789
	const artifactID int64 = 4000000123
	const runID int64 = 5000000456
	const attempt = 2
	const releaseID = "200000073"
	const version = "3.0"

	source := strings.Repeat("a", 40)
	candidateDigest := strings.Repeat("b", 64)
	artifactRoute := fmt.Sprintf("repos/%s/actions/artifacts/%d", repo, artifactID)
	attemptRoute := fmt.Sprintf("repos/%s/actions/runs/%d/attempts/%d", repo, runID, attempt)
	jobsRoute := attemptRoute + "/jobs?per_page=100"
	routes := []string{artifactRoute, attemptRoute, jobsRoute, artifactRoute + "/zip"}
	wantOutput := fmt.Sprintf("source-sha=%s\ncandidate-digest=%s\nrelease-id=%s\nstage-run-id=%d\nstage-run-attempt=%d\n",
		source, candidateDigest, releaseID, runID, attempt)

	for _, tc := range []struct {
		defect string
		reads  int
	}{
		{"valid receipt from an exact successful attempt", 4},
		{"core receipt while Windows is pending", 4},
		{"core receipt after Windows failed", 4},
		{"core job still running", 3},
		{"core job failed", 3},
		{"core job did not verify assets", 3},
		{"core receipt uploaded before verification", 3},
		{"core job wrong attempt", 3},
		{"core receipt from full result job", 3},
		{"core receipt with full payload", 4},
		{"full receipt with core payload", 4},
		{"invalid artifact input", 0},
		{"foreign artifact repository", 1},
		{"foreign artifact head repository", 1},
		{"unbound artifact name", 1},
		{"expired artifact", 1},
		{"absent API digest", 1},
		{"failed run", 2},
		{"incomplete run", 2},
		{"wrong workflow", 2},
		{"nonmanual run", 2},
		{"foreign run head repository", 2},
		{"different run source", 2},
		{"different run attempt", 2},
		{"no result job", 3},
		{"receipt skipped in successful validation", 3},
		{"incorrect archive digest", 4},
		{"unsafe archive member", 4},
		{"extra archive member", 4},
		{"duplicate archive member", 4},
		{"oversized receipt", 4},
		{"wrong mode", 4},
		{"wrong schema", 4},
		{"different release version", 4},
		{"wrong receipt source", 4},
		{"wrong receipt attempt", 4},
		{"invalid release ID", 4},
		{"release ID with trailing newline", 4},
		{"invalid candidate digest", 4},
		{"unknown receipt field", 4},
		{"duplicate receipt field", 4},
	} {
		t.Run(tc.defect, func(t *testing.T) {
			dir := t.TempDir()
			id := strconv.FormatInt(artifactID, 10)
			members := []string{"receipt.json"}
			origin := map[string]any{
				"id": runID, "repository_id": repoID, "head_repository_id": repoID,
				"head_branch": "main", "head_sha": source,
			}
			artifact := map[string]any{
				"id": artifactID, "name": fmt.Sprintf("release-stage-receipt-attempt-%d", attempt),
				"expired": false, "workflow_run": origin,
			}
			run := map[string]any{
				"id": runID, "run_attempt": attempt, "path": ".github/workflows/release.yml",
				"event": "workflow_dispatch", "head_branch": "main", "head_sha": source,
				"status": "completed", "conclusion": "success",
				"repository": map[string]any{"id": repoID}, "head_repository": map[string]any{"id": repoID},
			}
			upload := map[string]any{"name": "Upload staged candidate receipt", "status": "completed", "conclusion": "success"}
			resultJob := map[string]any{
				"name": "result", "status": "completed", "conclusion": "success",
				"run_id": runID, "run_attempt": attempt, "head_sha": source, "steps": []any{upload},
			}
			jobs := map[string]any{"total_count": 1, "jobs": []any{resultJob}}
			receipt := map[string]any{
				"schema": 1, "mode": "stage", "repository": repo, "version": version,
				"source_sha": source, "release_id": releaseID, "candidate_digest": candidateDigest,
				"run_id": strconv.FormatInt(runID, 10), "run_attempt": strconv.Itoa(attempt),
			}
			core := strings.HasPrefix(tc.defect, "core ")
			scope := "full"
			if core {
				scope = "core"
				artifact["name"] = fmt.Sprintf("release-stage-core-receipt-attempt-%d", attempt)
				receipt["mode"] = "stage-core"
				resultJob["name"] = "verify-staged-core"
				upload["name"] = "Upload core stage receipt"
				upload["number"] = 7
				resultJob["steps"] = []any{map[string]any{
					"name": "Verify staged core candidate", "status": "completed", "conclusion": "success", "number": 4,
				}, upload}
			}
			switch tc.defect {
			case "core receipt while Windows is pending":
				run["status"] = "in_progress"
				run["conclusion"] = nil
			case "core receipt after Windows failed":
				run["conclusion"] = "failure"
			case "core job still running":
				resultJob["status"] = "in_progress"
				resultJob["conclusion"] = nil
			case "core job failed":
				resultJob["conclusion"] = "failure"
			case "core job did not verify assets":
				resultJob["steps"] = []any{upload}
			case "core receipt uploaded before verification":
				upload["number"] = 3
			case "core job wrong attempt":
				resultJob["run_attempt"] = attempt + 1
			case "core receipt from full result job":
				resultJob["name"] = "result"
			case "core receipt with full payload":
				receipt["mode"] = "stage"
			case "full receipt with core payload":
				receipt["mode"] = "stage-core"
			case "invalid artifact input":
				id = "../1234"
			case "foreign artifact repository":
				origin["repository_id"] = repoID + 1
			case "foreign artifact head repository":
				origin["head_repository_id"] = repoID + 1
			case "unbound artifact name":
				artifact["name"] = "release-stage-receipt"
			case "expired artifact":
				artifact["expired"] = true
			case "failed run":
				run["conclusion"] = "failure"
			case "incomplete run":
				run["status"] = "in_progress"
			case "wrong workflow":
				run["path"] = ".github/workflows/build-linux.yml"
			case "nonmanual run":
				run["event"] = "pull_request"
			case "foreign run head repository":
				run["head_repository"] = map[string]any{"id": repoID + 1}
			case "different run source":
				run["head_sha"] = strings.Repeat("c", 40)
			case "different run attempt":
				run["run_attempt"] = attempt + 1
			case "no result job":
				resultJob["name"] = "validation"
			case "receipt skipped in successful validation":
				upload["conclusion"] = "skipped"
			case "unsafe archive member":
				members = []string{"../receipt.json"}
			case "extra archive member":
				members = append(members, "notes.txt")
			case "duplicate archive member":
				members = append(members, "receipt.json")
			case "wrong mode":
				receipt["mode"] = "publish"
			case "wrong schema":
				receipt["schema"] = "1"
			case "different release version":
				receipt["version"] = "3.1"
			case "wrong receipt source":
				receipt["source_sha"] = strings.Repeat("c", 40)
			case "wrong receipt attempt":
				receipt["run_attempt"] = strconv.Itoa(attempt + 1)
			case "invalid release ID":
				receipt["release_id"] = "0"
			case "release ID with trailing newline":
				receipt["release_id"] = releaseID + "\n"
			case "invalid candidate digest":
				receipt["candidate_digest"] = strings.Repeat("g", 64)
			case "unknown receipt field":
				receipt["extra"] = "unexpected"
			case "oversized receipt":
				receipt["candidate_digest"] = strings.Repeat("b", 4096)
			}
			payload, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if tc.defect == "duplicate receipt field" {
				payload = append([]byte("{\"mode\":\"stage\","), payload[1:]...)
			}
			var data bytes.Buffer
			archive := zip.NewWriter(&data)
			for _, member := range members {
				writer, err := archive.Create(member)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = writer.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			if err = archive.Close(); err != nil {
				t.Fatal(err)
			}
			artifact["digest"] = fmt.Sprintf("sha256:%x", sha256.Sum256(data.Bytes()))
			artifact["size_in_bytes"] = data.Len()
			switch tc.defect {
			case "incorrect archive digest":
				artifact["digest"] = "sha256:" + strings.Repeat("0", 64)
			case "absent API digest":
				delete(artifact, "digest")
			}
			for name, fixture := range map[string]map[string]any{"artifact.json": artifact, "attempt.json": run, "jobs.json": jobs} {
				encoded, err := json.Marshal(fixture)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.WriteFile(filepath.Join(dir, "archive.zip"), data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			fakeGH := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
[[ $1 == api ]]
shift
option=
case "$1" in
  --paginate|--allow-escape-sequences) option=$1; shift ;;
esac
[[ $# == 1 ]]
printf '%%s\n' "$1" >> calls
case "$1" in
  %s) cat artifact.json ;;
  %s) cat attempt.json ;;
  "%s") [[ $option == --paginate ]]; cat jobs.json ;;
  %s/zip) [[ $option == --allow-escape-sequences ]]; cat archive.zip ;;
  *) exit 9 ;;
esac
`, artifactRoute, attemptRoute, jobsRoute, artifactRoute)
			if err = os.WriteFile(filepath.Join(dir, "gh"), []byte(fakeGH), 0o700); err != nil {
				t.Fatal(err)
			}

			outputPath := filepath.Join(dir, "output")
			command := exec.Command("bash", filepath.Join(repoRoot(t), ".github/actions/stage-release/stage-receipt.sh"), id, version)
			command.Dir = dir
			command.Env = []string{
				"PATH=" + dir + ":/usr/bin:/bin",
				"GITHUB_REPOSITORY=" + repo,
				fmt.Sprintf("GITHUB_REPOSITORY_ID=%d", repoID),
				"GITHUB_OUTPUT=" + outputPath,
			}
			diagnostic, err := command.CombinedOutput()
			accepted := tc.defect == "valid receipt from an exact successful attempt" ||
				tc.defect == "core receipt while Windows is pending" || tc.defect == "core receipt after Windows failed"
			if (err == nil) != accepted {
				t.Fatalf("receipt resolver returned %v: %s", err, diagnostic)
			}
			output, outputErr := os.ReadFile(outputPath)
			expected := wantOutput + "release-scope=" + scope + "\n"
			if accepted && (outputErr != nil || string(output) != expected) {
				t.Fatalf("candidate outputs = %q, err = %v; want %q", output, outputErr, expected)
			}
			if !accepted && !os.IsNotExist(outputErr) {
				t.Fatalf("untrusted receipt exposed outputs %q, error = %v", output, outputErr)
			}

			calls, callErr := os.ReadFile(filepath.Join(dir, "calls"))
			if tc.reads == 0 {
				if !os.IsNotExist(callErr) {
					t.Fatalf("invalid input reached the API: %q, error = %v", calls, callErr)
				}
				return
			}
			if want := strings.Join(routes[:tc.reads], "\n") + "\n"; callErr != nil || string(calls) != want {
				t.Fatalf("receipt API requests = %q, err = %v; want %q", calls, callErr, want)
			}
		})
	}
}
