//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These execute coordinator guards and reporting against fixture inputs, without
// hosted jobs, production credentials, signing, or release API writes.
func TestReleaseCoordinatorPrepareRejectsUntrustedProductionModes(t *testing.T) {
	step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "prepare"), "Bind source and canonical manifest")
	source := strings.Repeat("a", 40)
	for _, tc := range []struct {
		name, mode, defect string
		accept             bool
	}{
		{"validation on review ref", "validation", "review", true},
		{"stage on main", "stage", "", true},
		{"publish on main", "publish", "", true},
		{"unsupported mode", "other", "", false},
		{"stage on review ref", "stage", "review", false},
		{"publish on review ref", "publish", "review", false},
		{"foreign repository", "stage", "repository", false},
		{"push event", "publish", "event", false},
		{"wrong caller", "stage", "workflow", false},
		{"different workflow source", "publish", "workflow source", false},
		{"different checkout", "stage", "checkout", false},
		{"validation different checkout", "validation", "checkout", false},
		{"publish lacks candidate source", "publish", "missing source", false},
		{"publish lacks candidate digest", "publish", "missing digest", false},
		{"publish candidate source is not a commit SHA", "publish", "bad source", false},
		{"publish candidate digest is not SHA-256", "publish", "bad digest", false},
		{"stage cannot select another candidate", "stage", "unexpected source", false},
		{"validation cannot select a candidate digest", "validation", "unexpected digest", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			manifestDir := filepath.Join(dir, ".github", "actions", "stage-release")
			for _, path := range []string{bin, manifestDir} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("3.0\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/usr/bin/env bash\n[[ $* == 'rev-parse HEAD' ]]\nprintf '%s\\n' \"$CHECKOUT_SHA\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(manifestDir, "release-manifest.sh"), []byte(mustReadWorkflow(t, ".github/actions/stage-release/release-manifest.sh")), 0o600); err != nil {
				t.Fatal(err)
			}
			outputPath := filepath.Join(dir, "output")
			env := map[string]string{
				"PATH": bin + ":/usr/bin:/bin", "MODE": tc.mode, "SOURCE_SHA": source, "CHECKOUT_SHA": source,
				"GITHUB_REPOSITORY": "Picocrypt-NG/Picocrypt-NG", "GITHUB_REF": "refs/heads/main",
				"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_WORKFLOW_REF": "Picocrypt-NG/Picocrypt-NG/.github/workflows/release.yml@refs/heads/main",
				"GITHUB_WORKFLOW_SHA": source, "GITHUB_OUTPUT": outputPath,
				"CANDIDATE_SHA": "", "CANDIDATE_DIGEST": "",
			}
			if tc.mode == "publish" {
				env["CANDIDATE_SHA"] = strings.Repeat("b", 40)
				env["CANDIDATE_DIGEST"] = strings.Repeat("c", 64)
			}
			switch tc.defect {
			case "review":
				env["GITHUB_REF"] = "refs/pull/312/merge"
				env["GITHUB_WORKFLOW_REF"] = "Picocrypt-NG/Picocrypt-NG/.github/workflows/release.yml@refs/pull/312/merge"
			case "repository":
				env["GITHUB_REPOSITORY"] = "fork/Picocrypt-NG"
			case "event":
				env["GITHUB_EVENT_NAME"] = "push"
			case "workflow":
				env["GITHUB_WORKFLOW_REF"] = "Picocrypt-NG/Picocrypt-NG/.github/workflows/build-linux.yml@refs/heads/main"
			case "workflow source":
				env["GITHUB_WORKFLOW_SHA"] = strings.Repeat("b", 40)
			case "checkout":
				env["CHECKOUT_SHA"] = strings.Repeat("b", 40)
			case "missing source":
				env["CANDIDATE_SHA"] = ""
			case "missing digest":
				env["CANDIDATE_DIGEST"] = ""
			case "bad source":
				env["CANDIDATE_SHA"] = "main"
			case "bad digest":
				env["CANDIDATE_DIGEST"] = strings.Repeat("g", 64)
			case "unexpected source":
				env["CANDIDATE_SHA"] = strings.Repeat("b", 40)
			case "unexpected digest":
				env["CANDIDATE_DIGEST"] = strings.Repeat("c", 64)
			}
			output, err := runFullValidationBash(t, dir, step.Run, env)
			if (err == nil) != tc.accept {
				t.Fatalf("guard returned %v: %s", err, output)
			}
			if !tc.accept {
				if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
					t.Fatalf("untrusted request emitted prepared outputs: %v", err)
				}
				return
			}
			manifest, err := runFullValidationBash(t, repoRoot(t), `bash .github/actions/stage-release/release-manifest.sh 3.0`, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("source-sha=%s\nversion=3.0\nmanifest-digest=%x\n", source, sha256.Sum256(manifest))
			got, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Fatalf("source/version/full canonical digest not bound: %q", got)
			}
		})
	}
}

func TestReleaseCoordinatorStageGuardRequiresEveryStagedOwner(t *testing.T) {
	step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "verify-staged"), "Require every staged owner")
	for _, defect := range []string{"none", "publish mode", "validation mode", "failed owner", "skipped owner", "unstaged owner", "missing owner", "duplicate owner", "unknown owner"} {
		t.Run(defect, func(t *testing.T) {
			owners := releaseCoordinatorOwnerResults()
			mode := "stage"
			switch defect {
			case "publish mode":
				mode = "publish"
			case "validation mode":
				mode = "validation"
			case "failed owner":
				owners[0]["result"] = "failure"
			case "skipped owner":
				owners[0]["result"] = "skipped"
			case "unstaged owner":
				owners[0]["staged"] = "false"
			case "missing owner":
				owners = owners[1:]
			case "duplicate owner":
				owners[0]["owner"] = owners[1]["owner"]
			case "unknown owner":
				owners[0]["owner"] = "build-other.yml"
			}
			data, err := json.Marshal(owners)
			if err != nil {
				t.Fatal(err)
			}
			output, err := runFullValidationBash(t, t.TempDir(), step.Run, map[string]string{"MODE": mode, "OWNER_RESULTS_JSON": string(data)})
			if (err == nil) != (defect == "none") {
				t.Fatalf("guard returned %v: %s", err, output)
			}
		})
	}
}

func TestReleaseCoordinatorSummaryDistinguishesValidationStageAndPublication(t *testing.T) {
	step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "result"), "Summarize and require requested outcome")
	for _, tc := range []struct {
		name, mode, defect string
		accept             bool
	}{
		{"validation complete", "validation", "", true},
		{"stage complete", "stage", "", true},
		{"publication confirmed", "publish", "", true},
		{"remote complete reused", "stage", "reused", true},
		{"retained previous generation", "stage", "previous attempt", true},
		{"generation absent", "stage", "no generation", true},
		{"validation failed", "validation", "validation failed", false},
		{"validation unexpectedly signed", "validation", "owner ran", false},
		{"stage owner failed", "stage", "failed owner", false},
		{"stage owner unstaged", "stage", "unstaged", false},
		{"stage draft verification failed", "stage", "draft failed", false},
		{"stage no release ID", "stage", "release ID missing", false},
		{"stage no candidate digest", "stage", "digest missing", false},
		{"stage unexpectedly published", "stage", "published", false},
		{"publish skipped", "publish", "publish skipped", false},
		{"publish unconfirmed", "publish", "unconfirmed", false},
		{"publish failed after output", "publish", "publish failed", false},
		{"publication must use trusted preparation", "publish", "prepare failed", false},
		{"publish must skip native build", "publish", "producer ran", false},
		{"publish must skip validation verifier", "publish", "verifier ran", false},
		{"publish must skip validation", "publish", "validation ran", false},
		{"publish must skip staging owners", "publish", "owner ran", false},
		{"publish must skip staging verifier", "publish", "staging verifier ran", false},
		{"missing owner", "stage", "missing owner", false},
		{"duplicate owner", "stage", "duplicate owner", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owners := releaseCoordinatorOwnerResults()
			publishResult, published := "skipped", ""
			prepare, validation, stageVerification := "success", "success", "skipped"
			source, candidateDigest, releaseID := strings.Repeat("b", 40), "", ""
			if tc.mode != "stage" {
				for _, owner := range owners {
					owner["result"] = "skipped"
					owner["reused"] = ""
					owner["staged"] = ""
					owner["generation_id"] = ""
					owner["generation_digest"] = ""
					owner["generation_attempt"] = ""
				}
			}
			switch tc.mode {
			case "stage":
				stageVerification, candidateDigest, releaseID = "success", strings.Repeat("c", 64), "456"
			case "publish":
				publishResult, published = "success", "true"
				validation = "skipped"
				for _, owner := range owners {
					owner["built_results"] = []string{"skipped"}
					owner["verify_result"] = "skipped"
				}
			}
			switch tc.defect {
			case "reused":
				owners[0]["reused"] = "true"
			case "previous attempt":
				owners[0]["generation_attempt"] = "1"
			case "no generation":
				owners[0]["generation_id"] = ""
			case "validation failed":
				validation = "failure"
			case "prepare failed":
				prepare = "failure"
			case "producer ran":
				owners[0]["built_results"] = []string{"skipped", "success"}
			case "verifier ran":
				owners[0]["verify_result"] = "success"
			case "validation ran":
				validation = "success"
			case "owner ran":
				owners[0]["result"] = "success"
			case "failed owner":
				owners[0]["result"] = "failure"
			case "unstaged":
				owners[0]["staged"] = "false"
			case "draft failed":
				stageVerification = "failure"
			case "release ID missing":
				releaseID = ""
			case "digest missing":
				candidateDigest = ""
			case "staging verifier ran":
				stageVerification = "success"
			case "published":
				publishResult, published = "success", "true"
			case "publish skipped":
				publishResult, published = "skipped", ""
			case "unconfirmed":
				published = "false"
			case "publish failed":
				publishResult = "failure"
			case "missing owner":
				owners = owners[1:]
			case "duplicate owner":
				owners[0]["owner"] = owners[1]["owner"]
			}
			data, err := json.Marshal(owners)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			summaryPath := filepath.Join(dir, "summary")
			output, err := runFullValidationBash(t, dir, step.Run, map[string]string{
				"MODE": tc.mode, "VALIDATION_RESULT": validation, "PUBLISH_RESULT": publishResult, "PUBLISHED": published,
				"PREPARE_RESULT": prepare, "SOURCE_SHA": source, "STAGE_VERIFICATION_RESULT": stageVerification,
				"CANDIDATE_DIGEST": candidateDigest, "RELEASE_ID": releaseID,
				"OWNER_RESULTS_JSON": string(data), "GITHUB_STEP_SUMMARY": summaryPath, "GITHUB_RUN_ATTEMPT": "2",
			})
			if (err == nil) != tc.accept {
				t.Fatalf("outcome returned %v: %s", err, output)
			}
			summary, err := os.ReadFile(summaryPath)
			if err != nil {
				t.Fatal(err)
			}
			fresh := tc.mode == "stage" && tc.defect != "reused" && tc.defect != "previous attempt" && tc.defect != "no generation"
			reused := tc.defect == "reused"
			if tc.accept {
				want := fmt.Sprintf("| build-linux.yml | %s | %t | %t | %t | %t | %t |", owners[0]["result"], tc.mode != "publish", tc.mode != "publish", fresh, reused, tc.mode == "stage")
				if !strings.Contains(string(summary), want) {
					t.Fatalf("summary did not reflect actual build/signing/stage results: %s", summary)
				}
				if !strings.Contains(string(summary), fmt.Sprintf("Published: %t", tc.mode == "publish")) {
					t.Fatalf("summary did not reflect actual publication: %s", summary)
				}
			}
			wantReceipt := tc.accept && tc.mode == "stage"
			if strings.Contains(string(summary), "candidate_sha") != wantReceipt || strings.Contains(string(summary), "candidate_digest") != wantReceipt {
				t.Fatalf("only a successful verified stage may show a promotion receipt: %s", summary)
			}
			if wantReceipt && (!strings.Contains(string(summary), source) || !strings.Contains(string(summary), candidateDigest) || !strings.Contains(string(summary), releaseID)) {
				t.Fatalf("summary did not bind source, inventory digest and release ID: %s", summary)
			}
			if tc.defect == "publish failed" && strings.Contains(string(summary), "Published: true") {
				t.Fatalf("failed finalizer cannot report published=true: %s", summary)
			}
		})
	}
}

func releaseCoordinatorOwnerResults() []map[string]any {
	var owners []map[string]any
	for _, owner := range []string{"linux", "macos", "snapcraft", "android", "windows", "windows-legacy", "appimage"} {
		owners = append(owners, map[string]any{
			"owner": "build-" + owner + ".yml", "built_results": []string{"success"}, "verify_result": "success",
			"result": "success", "reused": "false", "staged": "true",
			"generation_id": "123", "generation_digest": strings.Repeat("a", 64), "generation_attempt": "2",
		})
	}
	return owners
}
