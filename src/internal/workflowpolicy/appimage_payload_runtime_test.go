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

func TestAppImagePayloadManifestRejectsIncompleteOrSubstitutedPair(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/build-appimage/action.yml")
	record := mustCompositeStepNamed(t, action, "Record AppImage payload manifest")
	script := mustReadRepoFile(t, ".github/actions/stage-release/release-manifest.sh")
	canonical, err := exec.Command("bash", filepath.Join(repoRoot(t), ".github/actions/stage-release/release-manifest.sh"), "2.19").Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	source := strings.Repeat("1", 40)
	const image = "Picocrypt-NG-2.19-x86_64.AppImage"
	for _, defect := range []string{"none", "missing index", "symlink", "unexpected file"} {
		t.Run(defect, func(t *testing.T) {
			dir := t.TempDir()
			scriptPath := filepath.Join(dir, ".github/actions/stage-release/release-manifest.sh")
			if err := os.MkdirAll(filepath.Dir(scriptPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "out")
			if err := os.Mkdir(out, 0o700); err != nil {
				t.Fatal(err)
			}
			var files []any
			for _, name := range []string{image, image + ".zsync"} {
				if err := os.WriteFile(filepath.Join(out, name), []byte(name), 0o600); err != nil {
					t.Fatal(err)
				}
				files = append(files, map[string]any{"name": name, "sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(name)))})
			}
			switch defect {
			case "missing index", "symlink":
				index := filepath.Join(out, image+".zsync")
				if err := os.Remove(index); err != nil {
					t.Fatal(err)
				}
				if defect == "symlink" {
					if err := os.Symlink(filepath.Join(out, image), index); err != nil {
						t.Fatal(err)
					}
				}
			case "unexpected file":
				if err := os.WriteFile(filepath.Join(out, "extra"), []byte("extra"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", record.Run)
			command.Dir = dir
			command.Env = append(os.Environ(), "SOURCE_SHA="+source, "SOURCE_VERSION=2.19",
				"CANONICAL_MANIFEST_SHA256="+digest, "GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG",
				"GITHUB_RUN_ID=local-fixture", "GITHUB_RUN_ATTEMPT=1")
			output, err := command.CombinedOutput()
			manifest := filepath.Join(out, "payload-manifest.json")
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
				t.Fatalf("complete AppImage pair refused: %v: %s", err, output)
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
				"owner_workflow": "build-appimage.yml", "arch": "amd64", "run_id": "local-fixture",
				"run_attempt": "1", "files": files,
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("payload manifest = %s, want source-bound hashes for the exact AppImage/index pair", data)
			}
		})
	}
}
