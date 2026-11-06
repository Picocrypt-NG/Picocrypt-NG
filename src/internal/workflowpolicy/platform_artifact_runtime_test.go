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
	"strings"
	"testing"
)

// These exercise the consumer with fake GitHub metadata and real local files;
// they do not establish hosted downloads, signing or product behavior.
func TestPlatformArtifactConsumerBindsFourteenPrimariesAndRejectsSubstitution(t *testing.T) {
	root := repoRoot(t)
	consumer := ".github/actions/verify-platform-artifacts/verify-artifacts.sh"
	mustReadRepoFile(t, consumer)
	sha, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	source := strings.TrimSpace(string(sha))
	version := strings.TrimSpace(mustReadRepoFile(t, "VERSION"))
	canonical, err := exec.Command("bash", filepath.Join(root, ".github/actions/stage-release/release-manifest.sh"), version).Output()
	if err != nil {
		t.Fatal(err)
	}
	canonicalDigest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	owners := []struct {
		owner, arch, directory, artifact string
		id                               int
		files                            []string
	}{
		{"build-appimage.yml", "amd64", "build-appimage", "validate-appimage-amd64-attempt-1", 101, []string{"Picocrypt-NG-" + version + "-x86_64.AppImage", "Picocrypt-NG-" + version + "-x86_64.AppImage.zsync"}},
		{"build-snapcraft.yml", "amd64", "build-snapcraft", "build-snapcraft-attempt-1", 102, []string{"picocrypt-ng_" + version + "_amd64.snap"}},
		{"build-macos.yml", "arm64", "build-macos", "build-macos-attempt-1", 103, []string{"Picocrypt-NG.dmg", "Picocrypt-NG-cli-macos"}},
		{"build-android.yml", "all", "build-android", "validate-android-all-attempt-1", 104, []string{"Picocrypt-NG-android-armeabi-v7a.apk", "Picocrypt-NG-android-arm64-v8a.apk", "Picocrypt-NG-android-x86.apk", "Picocrypt-NG-android-x86_64.apk", "Picocrypt-NG-android-universal.apk"}},
		{"build-windows-legacy.yml", "amd64", "build-windows-legacy", "validate-windows-legacy-amd64-attempt-1", 105, []string{"Picocrypt-NG-cli-Legacy.exe"}},
		{"build-windows.yml", "amd64", "build-windows", "validate-windows-current-amd64-attempt-1", 106, []string{"Picocrypt-NG-portable.exe", "Picocrypt-NG-cli.exe", "Picocrypt-NG-Setup.exe"}},
	}
	for _, tc := range []struct {
		defect, phase string
		preflight     bool
	}{
		{defect: "none"},
		{"unknown owner", "metadata", true},
		{"duplicate owner", "metadata", true},
		{"missing owner", "metadata", true},
		{"zero ID", "metadata", true},
		{"string ID", "metadata", true},
		{"duplicate ID", "metadata", true},
		{"malformed ZIP digest", "metadata", true},
		{"zero attempt", "metadata", true},
		{"wrong descriptor arch", "metadata", true},
		{"descriptor path", "metadata", true},
		{"wrong metadata ID", "metadata", false},
		{"wrong metadata name", "metadata", false},
		{"wrong metadata source", "metadata", false},
		{"wrong metadata run", "metadata", false},
		{"expired", "metadata", false},
		{"wrong metadata digest", "metadata", false},
		{"wrong payload repository", "payload", false},
		{"wrong payload source", "payload", false},
		{"wrong payload version", "payload", false},
		{"wrong canonical digest", "payload", false},
		{"wrong payload owner", "payload", false},
		{"wrong payload arch", "payload", false},
		{"wrong payload run", "payload", false},
		{"wrong producing attempt", "payload", false},
		{"wrong schema", "payload", false},
		{"extra manifest field", "payload", false},
		{"extra file field", "payload", false},
		{"duplicate payload file", "payload", false},
		{"missing file", "payload", false},
		{"empty file", "payload", false},
		{"cross-file substitution", "payload", false},
		{"payload hash substitution", "payload", false},
		{"symlink", "payload", false},
		{"manifest symlink", "payload", false},
		{"directory", "payload", false},
		{"extra file", "payload", false},
	} {
		t.Run(tc.defect, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			fakeGH := `#!/usr/bin/env bash
set -euo pipefail
[[ $# == 4 && $1 == api && $2 == --method && $3 == GET ]]
[[ $4 == repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/+([0-9]) ]]
printf '%s\n' "$4" >> "$FIXTURE_DIR/requests"
cat "$FIXTURE_DIR/${4##*/}.json"
`
			fakeGH = strings.Replace(fakeGH, "set -euo pipefail\n", "set -euo pipefail\nshopt -s extglob\n", 1)
			if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o700); err != nil {
				t.Fatal(err)
			}
			var descriptors []map[string]any
			var wantFiles []map[string]string
			var targetManifest map[string]any
			var targetMetadata map[string]any
			var targetDirectory string
			for _, owner := range owners {
				digest := strings.Repeat("1", 64)
				descriptors = append(descriptors, map[string]any{"owner": owner.owner, "arch": owner.arch, "id": owner.id, "digest": digest, "attempt": 1})
				metadata := map[string]any{"id": owner.id, "name": owner.artifact, "digest": "sha256:" + digest, "expired": false, "workflow_run": map[string]any{"id": 900, "head_sha": source}}
				payloadDir := filepath.Join(dir, "artifacts", owner.directory)
				if err := os.MkdirAll(payloadDir, 0o700); err != nil {
					t.Fatal(err)
				}
				var files []map[string]string
				for _, name := range owner.files {
					data := []byte("payload:" + name)
					if err := os.WriteFile(filepath.Join(payloadDir, name), data, 0o600); err != nil {
						t.Fatal(err)
					}
					hash := fmt.Sprintf("%x", sha256.Sum256(data))
					files = append(files, map[string]string{"name": name, "sha256": hash})
					wantFiles = append(wantFiles, map[string]string{"name": name, "sha256": hash, "owner": owner.owner, "path": "artifacts/" + owner.directory + "/" + name})
				}
				manifest := map[string]any{
					"schema_version": 1, "repository": "Picocrypt-NG/Picocrypt-NG", "source_sha": source, "version": version,
					"canonical_manifest_sha256": canonicalDigest, "owner_workflow": owner.owner, "arch": owner.arch, "run_id": "900", "run_attempt": "1", "files": files,
				}
				if owner.id == 106 {
					targetManifest, targetMetadata, targetDirectory = manifest, metadata, payloadDir
				}
				writePlatformArtifactJSON(t, filepath.Join(dir, fmt.Sprintf("%d.json", owner.id)), metadata)
				writePlatformArtifactJSON(t, filepath.Join(payloadDir, "payload-manifest.json"), manifest)
			}
			files := targetManifest["files"].([]map[string]string)
			file := filepath.Join(targetDirectory, files[0]["name"])
			switch tc.defect {
			case "unknown owner":
				descriptors[5]["owner"] = "build-unknown.yml"
			case "duplicate owner":
				descriptors[5]["owner"] = descriptors[4]["owner"]
			case "missing owner":
				descriptors = descriptors[:5]
			case "zero ID":
				descriptors[5]["id"] = 0
			case "string ID":
				descriptors[5]["id"] = "106"
			case "duplicate ID":
				descriptors[5]["id"] = 105
			case "malformed ZIP digest":
				descriptors[5]["digest"] = strings.Repeat("A", 64)
			case "zero attempt":
				descriptors[5]["attempt"] = 0
			case "wrong descriptor arch":
				descriptors[5]["arch"] = "arm64"
			case "descriptor path":
				descriptors[5]["path"] = "../replacement"
			case "wrong metadata ID":
				targetMetadata["id"] = 999
			case "wrong metadata name":
				targetMetadata["name"] = "replacement"
			case "wrong metadata source":
				targetMetadata["workflow_run"].(map[string]any)["head_sha"] = strings.Repeat("f", 40)
			case "wrong metadata run":
				targetMetadata["workflow_run"].(map[string]any)["id"] = 901
			case "expired":
				targetMetadata["expired"] = true
			case "wrong metadata digest":
				targetMetadata["digest"] = "sha256:" + strings.Repeat("f", 64)
			case "wrong payload repository":
				targetManifest["repository"] = "other/repository"
			case "wrong payload source":
				targetManifest["source_sha"] = strings.Repeat("f", 40)
			case "wrong payload version":
				targetManifest["version"] = "0.0"
			case "wrong canonical digest":
				targetManifest["canonical_manifest_sha256"] = strings.Repeat("f", 64)
			case "wrong payload owner":
				targetManifest["owner_workflow"] = "build-windows-legacy.yml"
			case "wrong payload arch":
				targetManifest["arch"] = "arm64"
			case "wrong payload run":
				targetManifest["run_id"] = "901"
			case "wrong producing attempt":
				targetManifest["run_attempt"] = "2"
			case "wrong schema":
				targetManifest["schema_version"] = "1"
			case "extra manifest field":
				targetManifest["path"] = "../replacement"
			case "extra file field":
				files[0]["path"] = "../replacement"
			case "duplicate payload file":
				targetManifest["files"] = append(files, files[0])
			case "missing file", "symlink", "directory":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if tc.defect == "symlink" {
					outside := filepath.Join(dir, "matching-file")
					if err := os.WriteFile(outside, []byte("payload:"+files[0]["name"]), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, file); err != nil {
						t.Fatal(err)
					}
				}
				if tc.defect == "directory" {
					if err := os.Mkdir(file, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			case "empty file":
				if err := os.WriteFile(file, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				files[0]["sha256"] = fmt.Sprintf("%x", sha256.Sum256(nil))
			case "cross-file substitution":
				if err := os.WriteFile(file, []byte("payload:Picocrypt-NG.dmg"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "payload hash substitution":
				files[0]["sha256"] = strings.Repeat("f", 64)
			case "extra file":
				if err := os.WriteFile(filepath.Join(targetDirectory, "extra"), []byte("extra"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writePlatformArtifactJSON(t, filepath.Join(dir, "106.json"), targetMetadata)
			manifestPath := filepath.Join(targetDirectory, "payload-manifest.json")
			writePlatformArtifactJSON(t, manifestPath, targetManifest)
			if tc.defect == "manifest symlink" {
				data, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(manifestPath); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(dir, "matching-manifest")
				if err := os.WriteFile(outside, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, manifestPath); err != nil {
					t.Fatal(err)
				}
			}
			input, err := json.Marshal(descriptors)
			if err != nil {
				t.Fatal(err)
			}
			report := filepath.Join(dir, "platform-artifacts.json")
			env := append(os.Environ(), "PATH="+bin+":/usr/bin:/bin:"+os.Getenv("PATH"), "FIXTURE_DIR="+dir,
				"GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG", "GITHUB_SHA="+source, "GITHUB_RUN_ID=900", "GITHUB_RUN_ATTEMPT=3",
				"SOURCE_SHA="+source, "SOURCE_VERSION="+version, "CANONICAL_MANIFEST_SHA256="+canonicalDigest,
				"PLATFORM_ARTIFACTS_JSON="+string(input), "ARTIFACT_ROOT="+filepath.Join(dir, "artifacts"), "PLATFORM_MANIFEST="+report)
			failedPhase := ""
			var output []byte
			for _, phase := range []string{"metadata", "payload"} {
				command := exec.Command("bash", filepath.Join(root, consumer), phase)
				command.Dir, command.Env = root, env
				output, err = command.CombinedOutput()
				if err != nil {
					failedPhase = phase
					break
				}
				if phase == "metadata" {
					if _, err := os.Stat(report); !os.IsNotExist(err) {
						t.Fatal("metadata must not publish the final payload report")
					}
				}
			}
			if failedPhase != tc.phase {
				t.Fatalf("%s failed phase %q, want %q: %v: %s", tc.defect, failedPhase, tc.phase, err, output)
			}
			requests, readErr := os.ReadFile(filepath.Join(dir, "requests"))
			if tc.preflight && !os.IsNotExist(readErr) {
				t.Fatal("malformed descriptors must fail before any GitHub read")
			}
			if tc.defect != "none" {
				if _, err := os.Stat(report); !os.IsNotExist(err) {
					t.Fatal("refused platform set left a final report")
				}
				return
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			wantRequests := "repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/104\n" +
				"repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/101\n" +
				"repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/103\n" +
				"repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/102\n" +
				"repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/105\n" +
				"repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/106\n"
			if string(requests) != wantRequests {
				t.Fatalf("metadata reads = %q, want six exact-ID GETs %q", requests, wantRequests)
			}
			data, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Files []map[string]string
			}
			var context map[string]any
			if err := json.Unmarshal(data, &context); err != nil {
				t.Fatal(err)
			}
			if len(context) != 8 || context["schema_version"] != float64(1) || context["repository"] != "Picocrypt-NG/Picocrypt-NG" || context["source_sha"] != source || context["version"] != version || context["canonical_manifest_sha256"] != canonicalDigest || context["run_id"] != "900" {
				t.Fatalf("wrong final source context: %s", data)
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			byName := make(map[string]map[string]string)
			for _, file := range got.Files {
				byName[file["name"]] = file
			}
			if len(got.Files) != 14 || len(byName) != 14 {
				t.Fatalf("final report must contain exactly fourteen distinct primaries: %s", data)
			}
			for _, want := range wantFiles {
				if !reflect.DeepEqual(byName[want["name"]], want) {
					t.Fatalf("wrong canonical file record: %#v, want %#v", byName[want["name"]], want)
				}
			}
			artifacts := context["artifacts"].([]any)
			if len(artifacts) != 6 {
				t.Fatal("final report must bind all six producing artifacts")
			}
			byOwner := make(map[string]map[string]any)
			for _, artifact := range artifacts {
				entry := artifact.(map[string]any)
				byOwner[entry["owner"].(string)] = entry
			}
			for _, owner := range owners {
				want := map[string]any{"owner": owner.owner, "arch": owner.arch, "id": float64(owner.id), "zip_sha256": strings.Repeat("1", 64), "run_attempt": float64(1)}
				if !reflect.DeepEqual(byOwner[owner.owner], want) {
					t.Fatalf("wrong producing artifact binding: %#v, want %#v", byOwner[owner.owner], want)
				}
			}
			if strings.Contains(string(data), dir) {
				t.Fatal("final report leaked an absolute fixture path")
			}
		})
	}
}

func writePlatformArtifactJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
