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

func TestSnapcraftPayloadManifestRejectsNonCanonicalSnap(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/build-snapcraft/action.yml")
	record := mustCompositeStepNamed(t, action, "Record Snap payload manifest")
	script := mustReadRepoFile(t, ".github/actions/stage-release/release-manifest.sh")
	canonical, err := exec.Command("bash", filepath.Join(repoRoot(t), ".github/actions/stage-release/release-manifest.sh"), "2.19").Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	source := strings.Repeat("1", 40)
	const name = "picocrypt-ng_2.19_amd64.snap"
	for _, defect := range []string{"none", "missing", "empty", "symlink", "additional ARM snap", "wrong canonical digest"} {
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
			snap := filepath.Join(out, name)
			if err := os.WriteFile(snap, []byte(name), 0o600); err != nil {
				t.Fatal(err)
			}
			switch defect {
			case "missing", "symlink":
				if err := os.Remove(snap); err != nil {
					t.Fatal(err)
				}
				if defect == "symlink" {
					if err := os.Symlink(scriptPath, snap); err != nil {
						t.Fatal(err)
					}
				}
			case "empty":
				if err := os.Truncate(snap, 0); err != nil {
					t.Fatal(err)
				}
			case "additional ARM snap":
				if err := os.WriteFile(filepath.Join(out, "picocrypt-ng_2.19_arm64.snap"), []byte("extra"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			expectedDigest := digest
			if defect == "wrong canonical digest" {
				expectedDigest = strings.Repeat("f", 64)
			}
			command := exec.Command("bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", record.Run)
			command.Dir = dir
			command.Env = append(os.Environ(), "SOURCE_SHA="+source, "SOURCE_VERSION=2.19",
				"CANONICAL_MANIFEST_SHA256="+expectedDigest, "GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG",
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
				t.Fatalf("canonical AMD64 snap refused: %v: %s", err, output)
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
				"owner_workflow": "build-snapcraft.yml", "arch": "amd64", "run_id": "local-fixture", "run_attempt": "1",
				"files": []any{map[string]any{"name": name, "sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(name)))}},
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("payload manifest = %s, want source-bound hash for the single canonical AMD64 snap", data)
			}
		})
	}
}
