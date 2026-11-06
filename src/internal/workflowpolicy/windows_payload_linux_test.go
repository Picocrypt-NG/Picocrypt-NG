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

// These run the real metadata Bash bodies against fake EXE bytes, not Windows builds.
func TestWindowsSourceAssertionRejectsUnpreparedCheckout(t *testing.T) {
	root := repoRoot(t)
	output, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	source := strings.TrimSpace(string(output))
	version := strings.TrimSpace(mustReadRepoFile(t, "VERSION"))
	canonical, err := exec.Command("bash", filepath.Join(root, ".github/actions/stage-release/release-manifest.sh"), version).Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	for _, tc := range windowsBuildCases() {
		action := mustReadCompositeActionDoc(t, ".github/actions/"+tc.owner+"/action.yml")
		step := mustCompositeStepNamed(t, action, "Assert prepared Windows source")
		for _, change := range []string{"none", "source", "event", "version", "canonical"} {
			t.Run(tc.owner+"/"+change, func(t *testing.T) {
				sha, event, v, manifest := source, source, version, digest
				switch change {
				case "source":
					sha, event = strings.Repeat("a", 40), strings.Repeat("a", 40)
				case "event":
					event = strings.Repeat("b", 40)
				case "version":
					v = "999.0"
				case "canonical":
					manifest = strings.Repeat("0", 64)
				}
				outputPath := filepath.Join(t.TempDir(), "output")
				command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
				command.Dir = root
				command.Env = append(os.Environ(), "SOURCE_SHA="+sha, "GITHUB_SHA="+event, "SOURCE_VERSION="+v,
					"CANONICAL_MANIFEST_SHA256="+manifest, "GITHUB_RUN_ATTEMPT=7", "GITHUB_OUTPUT="+outputPath)
				data, runErr := command.CombinedOutput()
				if (runErr == nil) != (change == "none") {
					t.Fatalf("source assertion error=%v: %s", runErr, data)
				}
				written, readErr := os.ReadFile(outputPath)
				if change == "none" {
					if readErr != nil || string(written) != "run-attempt=7\n" {
						t.Fatalf("source assertion output=%q, %v", written, readErr)
					}
				} else if len(written) != 0 {
					t.Fatal("rejected source advertised a validated attempt")
				}
			})
		}
	}
}

func TestWindowsPayloadMetadataUsesCanonicalBytesAndRefusesInvalidFiles(t *testing.T) {
	for _, tc := range windowsBuildCases() {
		action := mustReadCompositeActionDoc(t, ".github/actions/"+tc.owner+"/action.yml")
		step := mustCompositeStepNamed(t, action, "Record Windows payload manifest")
		for _, change := range []string{"none", "missing", "empty", "symlink", "stale output"} {
			t.Run(tc.owner+"/"+change, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "workspace with spaces")
				writeWindowsMetadataFixture(t, filepath.Join(root, ".github/actions/stage-release/release-manifest.sh"), mustReadRepoFile(t, ".github/actions/stage-release/release-manifest.sh"), 0o700)
				bin := filepath.Join(root, "bin")
				originalPath := os.Getenv("PATH")
				jq, err := exec.LookPath("jq")
				if err != nil {
					t.Fatal(err)
				}
				writeWindowsMetadataFixture(t, filepath.Join(bin, "jq"), `#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  if [[ $argument == -b || $argument == --binary ]]; then PATH="$WINDOWS_FIXTURE_PATH" exec "$WINDOWS_FIXTURE_JQ" "$@"; fi
done
PATH="$WINDOWS_FIXTURE_PATH" "$WINDOWS_FIXTURE_JQ" "$@" | sed 's/$/\r/'
`, 0o700)
				for _, tool := range []string{"find", "sort"} {
					writeWindowsMetadataFixture(t, filepath.Join(bin, tool), "#!/bin/sh\nexit 97\n", 0o700)
				}
				inputs := make(map[string]string)
				for _, name := range tc.files {
					path := filepath.Join(root, "release-staging", name)
					if tc.owner == "build-windows-legacy" {
						path = filepath.Join(root, "src", name)
					}
					inputs[name] = path
					writeWindowsMetadataFixture(t, path, "unsigned fixture "+name, 0o600)
				}
				last := inputs[tc.files[len(tc.files)-1]]
				switch change {
				case "missing", "symlink":
					if err := os.Remove(last); err != nil {
						t.Fatal(err)
					}
					if change == "symlink" {
						target := filepath.Join(root, "foreign")
						writeWindowsMetadataFixture(t, target, "foreign bytes", 0o600)
						if err := os.Symlink(target, last); err != nil {
							t.Fatal(err)
						}
					}
				case "empty":
					writeWindowsMetadataFixture(t, last, "", 0o600)
				case "stale output":
					writeWindowsMetadataFixture(t, filepath.Join(root, tc.directory, "extra.exe"), "stale bytes", 0o600)
				}
				version := "3.0"
				canonical, err := exec.Command("bash", filepath.Join(root, ".github/actions/stage-release/release-manifest.sh"), version).Output()
				if err != nil {
					t.Fatal(err)
				}
				digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
				command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
				command.Dir = root
				command.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+originalPath, "WINDOWS_FIXTURE_JQ="+jq, "WINDOWS_FIXTURE_PATH="+originalPath,
					"SOURCE_SHA="+strings.Repeat("a", 40), "SOURCE_VERSION="+version, "CANONICAL_MANIFEST_SHA256="+digest,
					"GITHUB_REPOSITORY=example/Picocrypt-NG", "GITHUB_RUN_ID=123", "GITHUB_RUN_ATTEMPT=7")
				output, runErr := command.CombinedOutput()
				if (runErr == nil) != (change == "none") {
					t.Fatalf("payload metadata error=%v: %s", runErr, output)
				}
				manifestPath := filepath.Join(root, tc.directory, "payload-manifest.json")
				if change != "none" {
					if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
						t.Fatal("invalid payload advertised a complete manifest")
					}
					return
				}
				var manifest struct {
					SchemaVersion int `json:"schema_version"`
					Files         []struct{ Name, SHA256 string }
				}
				data, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(data, &fields); err != nil {
					t.Fatal(err)
				}
				if len(fields) != 10 || json.Unmarshal(fields["schema_version"], &manifest.SchemaVersion) != nil || manifest.SchemaVersion != 1 {
					t.Fatal("payload manifest must retain the common schema")
				}
				want := map[string]string{"repository": "example/Picocrypt-NG", "source_sha": strings.Repeat("a", 40), "version": version, "canonical_manifest_sha256": digest, "owner_workflow": tc.owner + ".yml", "arch": "amd64", "run_id": "123", "run_attempt": "7"}
				for key, value := range want {
					var actual string
					if err := json.Unmarshal(fields[key], &actual); err != nil || actual != value {
						t.Fatalf("payload %s=%q, want %q: %v", key, actual, value, err)
					}
				}
				if err := json.Unmarshal(fields["files"], &manifest.Files); err != nil || len(manifest.Files) != len(tc.files) {
					t.Fatalf("payload file set: %v", err)
				}
				seen := make(map[string]bool)
				for _, file := range manifest.Files {
					path, ok := inputs[file.Name]
					if !ok || seen[file.Name] {
						t.Fatal("payload added or duplicated a canonical file")
					}
					seen[file.Name] = true
					original, err := os.ReadFile(path)
					if err != nil || file.SHA256 != fmt.Sprintf("%x", sha256.Sum256(original)) {
						t.Fatal("manifest digest does not identify the original unsigned bytes")
					}
					copied, err := os.ReadFile(filepath.Join(root, tc.directory, file.Name))
					if err != nil || string(copied) != string(original) {
						t.Fatal("validation copy changed the signing-input bytes")
					}
				}
				if _, err := os.Stat(filepath.Join(filepath.Dir(last), "payload-manifest.json")); !os.IsNotExist(err) {
					t.Fatal("validation metadata contaminated the original signing-input bundle")
				}
			})
		}
	}
}

func writeWindowsMetadataFixture(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSourceBindingAcceptsCRLFWithoutChangingVersionContent(t *testing.T) {
	for _, tc := range windowsBuildCases() {
		owner := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/"+tc.owner+".yml"), "build")
		bind := mustStepNamed(t, owner, "Bind source and canonical manifest")
		assertion := mustCompositeStepNamed(t, mustReadCompositeActionDoc(t, ".github/actions/"+tc.owner+"/action.yml"), "Assert prepared Windows source")
		for _, lineEnding := range []string{"LF", "CRLF", "embedded CR"} {
			t.Run(tc.owner+"/"+lineEnding, func(t *testing.T) {
				root := t.TempDir()
				version := "3.0\n"
				if lineEnding == "CRLF" {
					version = "3.0\r\n"
				}
				if lineEnding == "embedded CR" {
					version = "3.\r0\r\n"
				}
				writeWindowsMetadataFixture(t, filepath.Join(root, "VERSION"), version, 0o600)
				writeWindowsMetadataFixture(t, filepath.Join(root, ".github/actions/stage-release/release-manifest.sh"), mustReadRepoFile(t, ".github/actions/stage-release/release-manifest.sh"), 0o700)
				bin := filepath.Join(root, "bin")
				writeWindowsMetadataFixture(t, filepath.Join(bin, "git"), `#!/bin/sh
[ "$*" = 'rev-parse HEAD' ] || exit 97
printf '%s\n' "$WINDOWS_FIXTURE_HEAD"
`, 0o700)
				outputPath := filepath.Join(root, "output")
				source := strings.Repeat("a", 40)
				environment := append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "WINDOWS_FIXTURE_HEAD="+source, "SOURCE_SHA="+source, "GITHUB_SHA="+source, "GITHUB_RUN_ATTEMPT=7", "GITHUB_OUTPUT="+outputPath)
				command := exec.Command("bash", "-euo", "pipefail", "-c", bind.Run)
				command.Dir, command.Env = root, environment
				data, err := command.CombinedOutput()
				if lineEnding == "embedded CR" {
					if err == nil {
						t.Fatal("binding silently changed an embedded version control character")
					}
					return
				}
				if err != nil {
					t.Fatalf("source binding rejected %s: %v: %s", lineEnding, err, data)
				}
				bound, err := os.ReadFile(outputPath)
				if err != nil {
					t.Fatal(err)
				}
				inputs := make(map[string]string)
				for _, line := range strings.Split(strings.TrimSpace(string(bound)), "\n") {
					key, value, _ := strings.Cut(line, "=")
					inputs[key] = value
				}
				if inputs["version"] != "3.0" || inputs["source-sha"] != source {
					t.Fatalf("source binding changed version/source: %q", bound)
				}
				command = exec.Command("bash", "-euo", "pipefail", "-c", assertion.Run)
				command.Dir = root
				environment = append(environment, "SOURCE_VERSION="+inputs["version"], "CANONICAL_MANIFEST_SHA256="+inputs["manifest-digest"])
				command.Env = environment
				if data, err := command.CombinedOutput(); err != nil {
					t.Fatalf("composite rejected prepared %s source: %v: %s", lineEnding, err, data)
				}
			})
		}
	}
}
