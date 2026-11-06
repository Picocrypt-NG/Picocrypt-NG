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

func TestAndroidPayloadManifestPreservesSigningInputsAndRejectsSubstitution(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/build-android/action.yml")
	prepare := mustCompositeStepNamed(t, action, "Prepare Android validation artifacts")
	record := mustCompositeStepNamed(t, action, "Record Android payload manifest")
	script := mustReadRepoFile(t, ".github/actions/stage-release/release-manifest.sh")
	canonical, err := exec.Command("bash", filepath.Join(repoRoot(t), ".github/actions/stage-release/release-manifest.sh"), "3.0").Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	source := strings.Repeat("1", 40)
	for _, defect := range []string{"none", "missing APK", "symlink", "unexpected file", "wrong canonical digest"} {
		t.Run(defect, func(t *testing.T) {
			dir := t.TempDir()
			scriptPath := filepath.Join(dir, ".github/actions/stage-release/release-manifest.sh")
			if err := os.MkdirAll(filepath.Dir(scriptPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			unsigned := filepath.Join(dir, "unsigned-release")
			if err := os.Mkdir(unsigned, 0o700); err != nil {
				t.Fatal(err)
			}
			var files []any
			inputs := make(map[string][]byte)
			for _, abi := range []string{"arm64-v8a", "armeabi-v7a", "universal", "x86", "x86_64"} {
				data := []byte("unsigned:" + abi)
				name := "app-" + abi + "-release-unsigned.apk"
				inputs[name] = data
				if err := os.WriteFile(filepath.Join(unsigned, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
				files = append(files, map[string]any{"name": "Picocrypt-NG-android-" + abi + ".apk", "sha256": fmt.Sprintf("%x", sha256.Sum256(data))})
			}
			inputs["build-inputs.json"] = []byte("existing source/AAR/signing-input manifest")
			if err := os.WriteFile(filepath.Join(unsigned, "build-inputs.json"), inputs["build-inputs.json"], 0o600); err != nil {
				t.Fatal(err)
			}
			if defect == "missing APK" || defect == "symlink" {
				path := filepath.Join(unsigned, "app-arm64-v8a-release-unsigned.apk")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if defect == "symlink" {
					if err := os.Symlink(filepath.Join(unsigned, "app-x86-release-unsigned.apk"), path); err != nil {
						t.Fatal(err)
					}
				}
			}
			manifestDigest := digest
			if defect == "wrong canonical digest" {
				manifestDigest = strings.Repeat("0", 64)
			}
			run := func(script string) ([]byte, error) {
				command := exec.Command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", script)
				command.Dir = dir
				command.Env = append(os.Environ(), "SOURCE_SHA="+source, "SOURCE_VERSION=3.0",
					"CANONICAL_MANIFEST_SHA256="+manifestDigest, "GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG",
					"GITHUB_RUN_ID=local-fixture", "GITHUB_RUN_ATTEMPT=1")
				return command.CombinedOutput()
			}
			output, err := run(prepare.Run)
			if err == nil {
				if defect == "unexpected file" {
					if err := os.WriteFile(filepath.Join(dir, "validation-out/extra"), []byte("extra"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				output, err = run(record.Run)
			}
			manifest := filepath.Join(dir, "validation-out/payload-manifest.json")
			if defect != "none" {
				if err == nil {
					t.Fatalf("%s must prevent a validation manifest: %s", defect, output)
				}
				if _, err := os.Stat(manifest); !os.IsNotExist(err) {
					t.Fatalf("refused APK set left a manifest: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("complete unsigned APK set refused: %v: %s", err, output)
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
				"schema_version": float64(1), "repository": "Picocrypt-NG/Picocrypt-NG", "source_sha": source,
				"version": "3.0", "canonical_manifest_sha256": digest, "owner_workflow": "build-android.yml",
				"arch": "all", "run_id": "local-fixture", "run_attempt": "1", "files": files,
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Android validation manifest = %s, want exact source-bound canonical APK hashes", data)
			}
			for name, want := range inputs {
				got, err := os.ReadFile(filepath.Join(unsigned, name))
				if err != nil || string(got) != string(want) {
					t.Fatalf("canonical validation changed signing input %s: %v", name, err)
				}
			}
		})
	}
}
