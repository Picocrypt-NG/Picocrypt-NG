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

func TestMacOSPayloadManifestRejectsIncompleteOrSubstitutedPair(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/build-macos/action.yml")
	record := mustCompositeStepNamed(t, action, "Record macOS payload manifest")
	script := mustReadRepoFile(t, ".github/actions/stage-release/release-manifest.sh")
	canonical, err := exec.Command("bash", filepath.Join(repoRoot(t), ".github/actions/stage-release/release-manifest.sh"), "2.19").Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	source := strings.Repeat("1", 40)
	for _, defect := range []string{"none", "missing CLI", "empty DMG", "symlink", "hidden extra", "wrong canonical digest"} {
		t.Run(defect, func(t *testing.T) {
			dir := t.TempDir()
			scriptPath := filepath.Join(dir, ".github/actions/stage-release/release-manifest.sh")
			if err := os.MkdirAll(filepath.Dir(scriptPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			staging := filepath.Join(dir, "release-staging")
			if err := os.Mkdir(staging, 0o700); err != nil {
				t.Fatal(err)
			}
			var files []any
			for _, name := range []string{"Picocrypt-NG-cli-macos", "Picocrypt-NG.dmg"} {
				if err := os.WriteFile(filepath.Join(staging, name), []byte(name), 0o600); err != nil {
					t.Fatal(err)
				}
				files = append(files, map[string]any{"name": name, "sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(name)))})
			}
			dmg := filepath.Join(staging, "Picocrypt-NG.dmg")
			switch defect {
			case "missing CLI":
				if err := os.Remove(filepath.Join(staging, "Picocrypt-NG-cli-macos")); err != nil {
					t.Fatal(err)
				}
			case "empty DMG":
				if err := os.Truncate(dmg, 0); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(dmg); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(scriptPath, dmg); err != nil {
					t.Fatal(err)
				}
			case "hidden extra":
				if err := os.WriteFile(filepath.Join(staging, ".DS_Store"), []byte("extra"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			expectedDigest := digest
			if defect == "wrong canonical digest" {
				expectedDigest = strings.Repeat("f", 64)
			}
			command := exec.Command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", record.Run)
			command.Dir = dir
			command.Env = append(os.Environ(), "SOURCE_SHA="+source, "SOURCE_VERSION=2.19", "GOARCH=arm64",
				"CANONICAL_MANIFEST_SHA256="+expectedDigest, "GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG",
				"GITHUB_RUN_ID=local-fixture", "GITHUB_RUN_ATTEMPT=1")
			output, err := command.CombinedOutput()
			manifest := filepath.Join(staging, "payload-manifest.json")
			if defect != "none" {
				if err == nil {
					t.Fatalf("%s must prevent manifest publication: %s", defect, output)
				}
				if _, err := os.Stat(manifest); !os.IsNotExist(err) {
					t.Fatalf("refused payload left a manifest: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonical macOS pair refused: %v: %s", err, output)
			}
			data, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"schema_version": float64(1), "repository": "Picocrypt-NG/Picocrypt-NG",
				"source_sha": source, "version": "2.19", "canonical_manifest_sha256": digest,
				"owner_workflow": "build-macos.yml", "arch": "arm64", "run_id": "local-fixture", "run_attempt": "1", "files": files,
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("payload manifest = %s, want actual Go target context and source-bound hashes for the exact DMG/CLI pair", data)
			}
		})
	}
}
