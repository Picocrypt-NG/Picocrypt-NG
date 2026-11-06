//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// These execute coordinator Bash against synthetic verifier reports. They do not
// exercise native payloads, hosted downloads, signing, or product cryptography.
func TestFullValidationGuardRejectsUnavailableVerifiersBeforeDownloads(t *testing.T) {
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "validation")
	step := mustStepNamed(t, job, "Require both artifact verifiers")
	if len(job.Steps) == 0 || job.Steps[0].Name != step.Name {
		t.Fatal("the result and immutable report checks must precede checkout and downloads")
	}
	for _, defect := range []string{
		"none", "prepare failure", "prepare skipped", "Linux failure", "Linux skipped", "platform failure", "platform skipped", "platform cancelled",
		"missing Linux ID", "zero Linux ID", "non-numeric Linux ID", "missing platform ID", "zero platform ID", "duplicate IDs",
		"bad Linux digest", "bad platform digest", "zero Linux attempt", "zero platform attempt", "future Linux attempt", "future platform attempt",
	} {
		t.Run(defect, func(t *testing.T) {
			env := fullValidationRuntimeEnvironment("", "", "")
			switch defect {
			case "prepare failure":
				env["PREPARE_RESULT"] = "failure"
			case "prepare skipped":
				env["PREPARE_RESULT"] = "skipped"
			case "Linux failure":
				env["LINUX_RESULT"] = "failure"
			case "Linux skipped":
				env["LINUX_RESULT"] = "skipped"
			case "platform failure":
				env["PLATFORM_RESULT"] = "failure"
			case "platform skipped":
				env["PLATFORM_RESULT"] = "skipped"
			case "platform cancelled":
				env["PLATFORM_RESULT"] = "cancelled"
			case "missing Linux ID":
				delete(env, "LINUX_REPORT_ID")
			case "zero Linux ID":
				env["LINUX_REPORT_ID"] = "0"
			case "non-numeric Linux ID":
				env["LINUX_REPORT_ID"] = "report"
			case "missing platform ID":
				delete(env, "PLATFORM_REPORT_ID")
			case "zero platform ID":
				env["PLATFORM_REPORT_ID"] = "0"
			case "duplicate IDs":
				env["PLATFORM_REPORT_ID"] = env["LINUX_REPORT_ID"]
			case "bad Linux digest":
				env["LINUX_REPORT_DIGEST"] = "not-a-sha256"
			case "bad platform digest":
				env["PLATFORM_REPORT_DIGEST"] = strings.Repeat("g", 64)
			case "zero Linux attempt":
				env["LINUX_REPORT_ATTEMPT"] = "0"
			case "zero platform attempt":
				env["PLATFORM_REPORT_ATTEMPT"] = "0"
			case "future Linux attempt":
				env["LINUX_REPORT_ATTEMPT"] = "4"
			case "future platform attempt":
				env["PLATFORM_REPORT_ATTEMPT"] = "4"
			}
			output, err := runFullValidationBash(t, t.TempDir(), step.Run, env)
			if (err == nil) != (defect == "none") {
				t.Fatalf("%s: guard returned %v: %s", defect, err, output)
			}
		})
	}
}

func TestFullValidationReportMetadataRejectsSubstitutionBeforeDownloads(t *testing.T) {
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "validation")
	step := mustStepNamed(t, job, "Verify immutable verifier report metadata")
	fixture := newFullValidationRuntimeFixture(t)
	for _, defect := range []string{
		"none", "Linux wrong ID", "Linux wrong name", "Linux wrong digest", "Linux expired", "Linux wrong run", "Linux wrong source", "Linux wrong producing attempt",
		"platform wrong ID", "platform wrong name", "platform wrong digest", "platform expired", "platform wrong run", "platform wrong source", "platform wrong producing attempt",
	} {
		t.Run(defect, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			fakeGH := `#!/usr/bin/env bash
set -euo pipefail
[[ $1 == api ]]
shift
if [[ ${1-} == --method ]]; then
  [[ ${2-} == GET ]]
  shift 2
fi
[[ $# == 1 && $1 == repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/* ]]
id=${1##*/}
[[ $id == 201 || $id == 202 ]]
printf '%s\n' "$id" >> "$FIXTURE_DIR/requests"
cat "$FIXTURE_DIR/$id.json"
`
			if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, report := range []struct {
				id, name, digest string
			}{
				{"201", "linux-validation-attempt-1", strings.Repeat("1", 64)},
				{"202", "platform-validation-attempt-1", strings.Repeat("2", 64)},
			} {
				metadata := map[string]any{
					"id": map[string]int{"201": 201, "202": 202}[report.id], "name": report.name,
					"digest": "sha256:" + report.digest, "expired": false,
					"workflow_run": map[string]any{"id": 900, "head_sha": fixture.source},
				}
				targetID := "201"
				if strings.HasPrefix(defect, "platform ") {
					targetID = "202"
				}
				if report.id == targetID {
					switch strings.TrimPrefix(strings.TrimPrefix(defect, "Linux "), "platform ") {
					case "wrong ID":
						metadata["id"] = 203
					case "wrong name":
						metadata["name"] = "replacement-report"
					case "wrong digest":
						metadata["digest"] = "sha256:" + strings.Repeat("f", 64)
					case "expired":
						metadata["expired"] = true
					case "wrong run":
						metadata["workflow_run"].(map[string]any)["id"] = 901
					case "wrong source":
						metadata["workflow_run"].(map[string]any)["head_sha"] = strings.Repeat("f", 40)
					case "wrong producing attempt":
						metadata["name"] = strings.Replace(report.name, "attempt-1", "attempt-2", 1)
					}
				}
				writeLinuxJSONFixture(t, filepath.Join(dir, report.id+".json"), metadata)
			}
			env := fullValidationRuntimeEnvironment(fixture.source, fixture.version, fixture.digest)
			env["PATH"], env["FIXTURE_DIR"] = bin+":/usr/bin:/bin:"+os.Getenv("PATH"), dir
			output, err := runFullValidationBash(t, repoRoot(t), step.Run, env)
			if (err == nil) != (defect == "none") {
				t.Fatalf("%s: report metadata returned %v: %s", defect, err, output)
			}
			if defect == "none" {
				data, err := os.ReadFile(filepath.Join(dir, "requests"))
				if err != nil {
					t.Fatal(err)
				}
				requests := strings.Fields(string(data))
				slices.Sort(requests)
				if !slices.Equal(requests, []string{"201", "202"}) {
					t.Fatalf("report metadata must GET each exact immutable ID once: %q", requests)
				}
			}
		})
	}
}

func TestFullValidationLinuxInventoryPreservesVerifiedContextAndFiveFiles(t *testing.T) {
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "verify-linux")
	step := mustStepNamed(t, job, "Record verified Linux file inventory")
	fixture := newFullValidationRuntimeFixture(t)
	dir := t.TempDir()
	manifest := filepath.Join(dir, "linux-artifacts.json")
	context := fixture.report(fixture.files[:5], true)
	delete(context, "files")
	writeLinuxJSONFixture(t, manifest, context)
	for _, arch := range []struct {
		name       string
		start, end int
	}{
		{"amd64", 0, 3}, {"arm64", 3, 5},
	} {
		payloadDir := filepath.Join(dir, "artifacts", "build-linux-"+arch.name)
		if err := os.MkdirAll(payloadDir, 0o700); err != nil {
			t.Fatal(err)
		}
		var files []map[string]any
		for _, file := range fixture.files[arch.start:arch.end] {
			files = append(files, map[string]any{"name": file["name"], "sha256": file["sha256"]})
		}
		writeLinuxJSONFixture(t, filepath.Join(payloadDir, "payload-manifest.json"), map[string]any{"files": files})
	}
	env := fullValidationRuntimeEnvironment(fixture.source, fixture.version, fixture.digest)
	env["ARTIFACT_ROOT"], env["LINUX_MANIFEST"] = filepath.Join(dir, "artifacts"), manifest
	env["GITHUB_OUTPUT"] = filepath.Join(dir, "github-output")
	output, err := runFullValidationBash(t, dir, step.Run, env)
	if err != nil {
		t.Fatalf("verified Linux inventory refused: %v: %s", err, output)
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	wantData, err := json.Marshal(fixture.report(fixture.files[:5], true))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(wantData, &want); err != nil {
		t.Fatal(err)
	}
	gotFiles, wantFiles := got["files"], want["files"]
	delete(got, "files")
	delete(want, "files")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventory changed verified context/artifacts or lost an exact Linux file: %s", data)
	}
	files := func(value any) map[string]any {
		result := make(map[string]any)
		for _, file := range value.([]any) {
			entry := file.(map[string]any)
			name := entry["name"].(string)
			if result[name] != nil {
				t.Fatalf("duplicate Linux inventory file %q", name)
			}
			result[name] = entry
		}
		return result
	}
	if !reflect.DeepEqual(files(gotFiles), files(wantFiles)) {
		t.Fatalf("Linux inventory must retain the five exact canonical records: %s", data)
	}
	if strings.Contains(string(data), dir) {
		t.Fatal("Linux inventory exposed an absolute fixture path")
	}
}

func TestFullValidationJoinRequiresExactNineteenFilesAndMatchingVerifierContexts(t *testing.T) {
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "validation")
	step := mustStepNamed(t, job, "Join complete validation manifest")
	for _, defect := range []string{
		"none", "source differs from checkout", "version differs from checkout", "wrong expected canonical digest", "wrong event source",
		"Linux source", "platform source", "Linux version", "platform version", "Linux canonical", "platform canonical",
		"Linux run", "platform run", "Linux repository", "platform repository", "wrong event run", "wrong event repository",
		"Linux schema", "platform schema", "Linux extra field", "platform extra field", "Linux missing file", "platform missing file",
		"Linux duplicate file", "platform duplicate file", "Linux extra file", "platform extra file", "Linux cross-owner", "platform cross-owner",
		"Linux absolute path", "platform absolute path", "Linux traversal path", "platform wrong relative path", "Linux malformed hash", "platform malformed hash",
		"Linux extra file field", "platform extra file field", "Linux missing report", "platform missing report", "Linux symlink report", "platform symlink report",
		"Linux malformed report", "platform malformed report",
	} {
		t.Run(defect, func(t *testing.T) {
			fixture := newFullValidationRuntimeFixture(t)
			if defect == "version differs from checkout" {
				fixture.version = "0.0"
				fixture.files, fixture.digest = fullValidationRuntimeFiles(fixture.version)
			}
			if defect == "source differs from checkout" {
				fixture.source = strings.Repeat("f", 40)
			}
			linux := fixture.report(fixture.files[:5], true)
			platform := fixture.report(fixture.files[5:], false)
			dir := t.TempDir()
			linuxPath, platformPath := filepath.Join(dir, "linux.json"), filepath.Join(dir, "platform.json")
			manifest := filepath.Join(dir, "validation.json")
			env := fullValidationRuntimeEnvironment(fixture.source, fixture.version, fixture.digest)
			env["LINUX_REPORT"], env["PLATFORM_REPORT"], env["VALIDATION_MANIFEST"] = linuxPath, platformPath, manifest
			target := linux
			if strings.HasPrefix(defect, "platform ") {
				target = platform
			}
			files := target["files"].([]map[string]any)
			switch defect {
			case "wrong expected canonical digest":
				env["CANONICAL_MANIFEST_SHA256"] = strings.Repeat("f", 64)
			case "wrong event source":
				env["GITHUB_SHA"] = strings.Repeat("e", 40)
			case "wrong event run":
				env["GITHUB_RUN_ID"] = "901"
			case "wrong event repository":
				env["GITHUB_REPOSITORY"] = "another/repository"
			case "Linux source", "platform source":
				target["source_sha"] = strings.Repeat("e", 40)
			case "Linux version", "platform version":
				target["version"] = "0.0"
			case "Linux canonical", "platform canonical":
				target["canonical_manifest_sha256"] = strings.Repeat("e", 64)
			case "Linux run", "platform run":
				target["run_id"] = "901"
			case "Linux repository", "platform repository":
				target["repository"] = "another/repository"
			case "Linux schema", "platform schema":
				target["schema_version"] = 2
			case "Linux extra field", "platform extra field":
				target["unverified"] = true
			case "Linux missing file", "platform missing file":
				target["files"] = files[1:]
			case "Linux duplicate file", "platform duplicate file":
				files[len(files)-1] = files[0]
			case "Linux extra file", "platform extra file":
				target["files"] = append(files, map[string]any{"name": "extra", "owner": "build-linux.yml", "path": "artifacts/extra", "sha256": strings.Repeat("1", 64)})
			case "Linux cross-owner":
				files[0]["owner"] = "build-windows.yml"
			case "platform cross-owner":
				files[0]["owner"] = "build-linux.yml"
			case "Linux absolute path", "platform absolute path":
				files[0]["path"] = "/untrusted/" + files[0]["name"].(string)
			case "Linux traversal path":
				files[0]["path"] = "artifacts/../" + files[0]["name"].(string)
			case "platform wrong relative path":
				files[0]["path"] = "artifacts/build-android/" + files[0]["name"].(string)
			case "Linux malformed hash":
				files[0]["sha256"] = strings.Repeat("a", 63)
			case "platform malformed hash":
				files[0]["sha256"] = strings.Repeat("g", 64)
			case "Linux extra file field", "platform extra file field":
				files[0]["unverified"] = true
			}
			writeLinuxJSONFixture(t, linuxPath, linux)
			writeLinuxJSONFixture(t, platformPath, platform)
			reportPath := linuxPath
			if strings.HasPrefix(defect, "platform ") {
				reportPath = platformPath
			}
			switch defect {
			case "Linux missing report", "platform missing report", "Linux symlink report", "platform symlink report":
				if err := os.Remove(reportPath); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(defect, "symlink") {
					target := filepath.Join(dir, "real-report.json")
					if reportPath == linuxPath {
						writeLinuxJSONFixture(t, target, linux)
					} else {
						writeLinuxJSONFixture(t, target, platform)
					}
					if err := os.Symlink(target, reportPath); err != nil {
						t.Fatal(err)
					}
				}
			case "Linux malformed report", "platform malformed report":
				if err := os.WriteFile(reportPath, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			output, err := runFullValidationBash(t, repoRoot(t), step.Run, env)
			if defect != "none" {
				if err == nil {
					t.Fatalf("%s must reject the joined manifest: %s", defect, output)
				}
				if _, err := os.Lstat(manifest); !os.IsNotExist(err) {
					t.Fatalf("%s left a validation manifest after refusal: %v", defect, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("complete source-bound reports refused: %v: %s", err, output)
			}
			data, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]any{
				"schema_version": float64(1), "repository": "Picocrypt-NG/Picocrypt-NG", "source_sha": fixture.source,
				"version": fixture.version, "canonical_manifest_sha256": fixture.digest, "run_id": "900",
				"mode": "validation", "publish_release": false, "production_signing": "not-requested",
				"macos_signing": "ad-hoc bundle seal only; no Developer ID or notarization",
			} {
				if !reflect.DeepEqual(got[name], want) {
					t.Fatalf("final manifest %s = %#v, want %#v", name, got[name], want)
				}
			}
			wantReports := map[string]any{
				"linux":     map[string]any{"id": float64(201), "digest": strings.Repeat("1", 64), "run_attempt": float64(1)},
				"platforms": map[string]any{"id": float64(202), "digest": strings.Repeat("2", 64), "run_attempt": float64(1)},
			}
			if !reflect.DeepEqual(got["verification_reports"], wantReports) {
				t.Fatalf("final manifest lost exact verifier report IDs, digests, or producing attempts: %#v", got["verification_reports"])
			}
			var inventory struct {
				Files []map[string]any `json:"files"`
			}
			if err := json.Unmarshal(data, &inventory); err != nil {
				t.Fatal(err)
			}
			if len(inventory.Files) != 19 {
				t.Fatalf("final manifest has %d files, want the exact nineteen primaries", len(inventory.Files))
			}
			byName := make(map[string]map[string]any)
			for _, file := range inventory.Files {
				name, ok := file["name"].(string)
				if !ok || byName[name] != nil {
					t.Fatalf("final inventory contains an invalid or duplicate name: %#v", file)
				}
				byName[name] = file
			}
			for _, want := range fixture.files {
				if !reflect.DeepEqual(byName[want["name"].(string)], want) {
					t.Fatalf("wrong final canonical file: %#v, want %#v", byName[want["name"].(string)], want)
				}
			}
			if strings.Contains(string(data), dir) {
				t.Fatal("final validation manifest exposed an absolute fixture path")
			}
		})
	}
}

type fullValidationRuntimeFixture struct {
	source, version, digest string
	files                   []map[string]any
}

func newFullValidationRuntimeFixture(t *testing.T) fullValidationRuntimeFixture {
	t.Helper()
	sha, err := exec.Command("git", "-C", repoRoot(t), "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(mustReadRepoFile(t, "VERSION"))
	files, digest := fullValidationRuntimeFiles(version)
	return fullValidationRuntimeFixture{source: strings.TrimSpace(string(sha)), version: version, digest: digest, files: files}
}

func fullValidationRuntimeFiles(version string) ([]map[string]any, string) {
	rows := []struct{ name, owner, path, canonicalPath string }{
		{"Picocrypt-NG", "build-linux.yml", "artifacts/build-linux-amd64/Picocrypt-NG", "artifacts/build-linux-amd64/Picocrypt-NG"},
		{"Picocrypt-NG-cli", "build-linux.yml", "artifacts/build-linux-amd64/Picocrypt-NG-cli", "artifacts/build-linux-amd64/Picocrypt-NG-cli"},
		{"Picocrypt-NG.deb", "build-linux.yml", "artifacts/build-linux-amd64/Picocrypt-NG.deb", "artifacts/build-linux-amd64/Picocrypt-NG.deb"},
		{"Picocrypt-NG-arm64", "build-linux.yml", "artifacts/build-linux-arm64/Picocrypt-NG-arm64", "artifacts/build-linux-arm64/Picocrypt-NG-arm64"},
		{"Picocrypt-NG-cli-arm64", "build-linux.yml", "artifacts/build-linux-arm64/Picocrypt-NG-cli-arm64", "artifacts/build-linux-arm64/Picocrypt-NG-cli-arm64"},
		{"Picocrypt-NG.dmg", "build-macos.yml", "artifacts/build-macos/Picocrypt-NG.dmg", "artifacts/build-macos/Picocrypt-NG.dmg"},
		{"Picocrypt-NG-cli-macos", "build-macos.yml", "artifacts/build-macos/Picocrypt-NG-cli-macos", "artifacts/build-macos/Picocrypt-NG-cli-macos"},
		{"Picocrypt-NG-portable.exe", "build-windows.yml", "artifacts/build-windows/Picocrypt-NG-portable.exe", "artifacts/build-windows/Picocrypt-NG-portable.exe"},
		{"Picocrypt-NG-cli.exe", "build-windows.yml", "artifacts/build-windows/Picocrypt-NG-cli.exe", "artifacts/build-windows/Picocrypt-NG-cli.exe"},
		{"Picocrypt-NG-Setup.exe", "build-windows.yml", "artifacts/build-windows/Picocrypt-NG-Setup.exe", "artifacts/build-windows/Picocrypt-NG-Setup.exe"},
		{"Picocrypt-NG-cli-Legacy.exe", "build-windows-legacy.yml", "artifacts/build-windows-legacy/Picocrypt-NG-cli-Legacy.exe", "artifacts/build-windows-legacy/Picocrypt-NG-cli-Legacy.exe"},
		{"Picocrypt-NG-android-armeabi-v7a.apk", "build-android.yml", "artifacts/build-android/Picocrypt-NG-android-armeabi-v7a.apk", "out/Picocrypt-NG-android-armeabi-v7a.apk"},
		{"Picocrypt-NG-android-arm64-v8a.apk", "build-android.yml", "artifacts/build-android/Picocrypt-NG-android-arm64-v8a.apk", "out/Picocrypt-NG-android-arm64-v8a.apk"},
		{"Picocrypt-NG-android-x86.apk", "build-android.yml", "artifacts/build-android/Picocrypt-NG-android-x86.apk", "out/Picocrypt-NG-android-x86.apk"},
		{"Picocrypt-NG-android-x86_64.apk", "build-android.yml", "artifacts/build-android/Picocrypt-NG-android-x86_64.apk", "out/Picocrypt-NG-android-x86_64.apk"},
		{"Picocrypt-NG-android-universal.apk", "build-android.yml", "artifacts/build-android/Picocrypt-NG-android-universal.apk", "out/Picocrypt-NG-android-universal.apk"},
		{"Picocrypt-NG-" + version + "-x86_64.AppImage", "build-appimage.yml", "artifacts/build-appimage/Picocrypt-NG-" + version + "-x86_64.AppImage", "artifacts/Picocrypt-NG-" + version + "-x86_64.AppImage"},
		{"Picocrypt-NG-" + version + "-x86_64.AppImage.zsync", "build-appimage.yml", "artifacts/build-appimage/Picocrypt-NG-" + version + "-x86_64.AppImage.zsync", "artifacts/Picocrypt-NG-" + version + "-x86_64.AppImage.zsync"},
		{"picocrypt-ng_" + version + "_amd64.snap", "build-snapcraft.yml", "artifacts/build-snapcraft/picocrypt-ng_" + version + "_amd64.snap", "out/picocrypt-ng_" + version + "_amd64.snap"},
	}
	var canonical strings.Builder
	var files []map[string]any
	for index, row := range rows {
		fmt.Fprintf(&canonical, "%s %s %s\n", row.name, row.owner, row.canonicalPath)
		files = append(files, map[string]any{"name": row.name, "owner": row.owner, "path": row.path, "sha256": fmt.Sprintf("%064x", index+1)})
	}
	return files, fmt.Sprintf("%x", sha256.Sum256([]byte(canonical.String())))
}

func (f fullValidationRuntimeFixture) report(files []map[string]any, linux bool) map[string]any {
	artifacts := []map[string]any{
		{"arch": "amd64", "id": "101", "zip_sha256": strings.Repeat("1", 64), "run_attempt": "1"},
		{"arch": "arm64", "id": "102", "zip_sha256": strings.Repeat("2", 64), "run_attempt": "1"},
	}
	if !linux {
		artifacts = []map[string]any{
			{"owner": "build-appimage.yml", "arch": "amd64", "id": 103, "zip_sha256": strings.Repeat("3", 64), "run_attempt": 1},
			{"owner": "build-snapcraft.yml", "arch": "amd64", "id": 104, "zip_sha256": strings.Repeat("4", 64), "run_attempt": 1},
			{"owner": "build-macos.yml", "arch": "arm64", "id": 105, "zip_sha256": strings.Repeat("5", 64), "run_attempt": 1},
			{"owner": "build-android.yml", "arch": "all", "id": 106, "zip_sha256": strings.Repeat("6", 64), "run_attempt": 1},
			{"owner": "build-windows.yml", "arch": "amd64", "id": 107, "zip_sha256": strings.Repeat("7", 64), "run_attempt": 1},
			{"owner": "build-windows-legacy.yml", "arch": "amd64", "id": 108, "zip_sha256": strings.Repeat("8", 64), "run_attempt": 1},
		}
	}
	return map[string]any{
		"schema_version": 1, "repository": "Picocrypt-NG/Picocrypt-NG", "source_sha": f.source,
		"version": f.version, "canonical_manifest_sha256": f.digest, "run_id": "900", "artifacts": artifacts, "files": files,
	}
}

func fullValidationRuntimeEnvironment(source, version, digest string) map[string]string {
	return map[string]string{
		"PREPARE_RESULT": "success", "LINUX_RESULT": "success", "PLATFORM_RESULT": "success",
		"SOURCE_SHA": source, "SOURCE_VERSION": version, "CANONICAL_MANIFEST_SHA256": digest,
		"GITHUB_SHA": source, "GITHUB_REPOSITORY": "Picocrypt-NG/Picocrypt-NG", "GITHUB_RUN_ID": "900", "GITHUB_RUN_ATTEMPT": "3",
		"LINUX_REPORT_ID": "201", "PLATFORM_REPORT_ID": "202", "LINUX_REPORT_DIGEST": strings.Repeat("1", 64), "PLATFORM_REPORT_DIGEST": strings.Repeat("2", 64),
		"LINUX_REPORT_ATTEMPT": "1", "PLATFORM_REPORT_ATTEMPT": "1",
	}
}

func runFullValidationBash(t *testing.T, directory, script string, env map[string]string) ([]byte, error) {
	t.Helper()
	command := exec.Command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", script)
	command.Dir = directory
	command.Env = []string{"PATH=/usr/bin:/bin:" + os.Getenv("PATH")}
	for name, value := range env {
		command.Env = append(command.Env, name+"="+value)
	}
	return command.CombinedOutput()
}
