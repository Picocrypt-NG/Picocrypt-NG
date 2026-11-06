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

// Real shell/filesystem checks with fake crypto/HTTP, not production acceptance.
func TestSignedGenerationRetainsWholeOwnerAndRefusesRestoreMismatch(t *testing.T) {
	root := repoRoot(t)
	canonical, err := exec.Command("bash", filepath.Join(root, releaseManifestScriptPath), "2.19").Output()
	if err != nil {
		t.Fatal(err)
	}
	manifestHash := fmt.Sprintf("%x", sha256.Sum256(canonical))
	paths := []string{"artifacts/build-linux-amd64/Picocrypt-NG", "artifacts/build-linux-amd64/Picocrypt-NG-cli", "artifacts/build-linux-amd64/Picocrypt-NG.deb", "artifacts/build-linux-arm64/Picocrypt-NG-arm64", "artifacts/build-linux-arm64/Picocrypt-NG-cli-arm64"}
	for _, defect := range []string{"none", "identical existing", "different existing", "record crypto failure", "expired", "wrong metadata ID", "wrong metadata name", "wrong metadata digest", "wrong metadata source", "wrong metadata run", "hash mismatch", "missing bundle", "extra archive file", "wrong source", "wrong owner", "wrong producing attempt", "archive symlink", "restore crypto failure", "wrong caller"} {
		t.Run(defect, func(t *testing.T) {
			dir := t.TempDir()
			t.Cleanup(func() {
				calls, err := os.ReadFile(filepath.Join(dir, "calls"))
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				for _, forbidden := range []string{"sign-blob", "--method POST", "--method PATCH", "--method DELETE"} {
					if strings.Contains(string(calls), forbidden) {
						t.Fatalf("generation attempted forbidden remote/signing operation %s", forbidden)
					}
				}
			})
			if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("2.19\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			writeJSONFixture(t, filepath.Join(dir, "verified.json"), []any{releaseIdentityRow(releaseIdentityCertificate("build-linux.yml", "release.yml"))})
			for name, script := range map[string]string{
				"git":    "#!/bin/sh\n[ \"$*\" = 'rev-parse HEAD' ] || exit 97\nprintf '%s\\n' \"$GITHUB_SHA\"\n",
				"cosign": "#!/bin/sh\nprintf 'cosign %s\\n' \"$*\" >> \"$FIXTURE_DIR/calls\"\n[ \"$1\" = verify-blob ] || exit 98\nif [ -e \"$FIXTURE_DIR/crypto-fail\" ] && [ \"${2##*/}\" = Picocrypt-NG-cli-arm64 ]; then exit 99; fi\n",
				"gh":     "#!/bin/sh\nprintf 'gh %s\\n' \"$*\" >> \"$FIXTURE_DIR/calls\"\nif [ \"$1 $2\" = 'attestation verify' ]; then cat \"$FIXTURE_DIR/verified.json\"; elif [ \"$*\" = 'api --method GET repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/101' ]; then cat \"$FIXTURE_DIR/metadata.json\"; else exit 98; fi\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			want := make(map[string]string)
			for _, primary := range paths {
				for _, path := range []string{primary, primary + ".sigstore.json"} {
					want[path] = "signed fixture:" + path
					if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, path), []byte(want[path]), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			archive := filepath.Join(dir, "signed-generation")
			if defect == "record crypto failure" {
				if err := os.WriteFile(filepath.Join(dir, "crypto-fail"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			env := append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "FIXTURE_DIR="+dir,
				"GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG", "GITHUB_SHA="+releaseTestSHA, "SOURCE_SHA="+releaseTestSHA,
				"GITHUB_RUN_ID=900", "GITHUB_RUN_ATTEMPT=1", "SOURCE_VERSION=2.19", "CANONICAL_MANIFEST_SHA256="+manifestHash,
				"GENERATION_OWNER=build-linux.yml", "GENERATION_DIR="+archive, "GITHUB_OUTPUT="+filepath.Join(dir, "outputs"),
				"GENERATION_ARTIFACT_ID=101", "GENERATION_ARTIFACT_DIGEST="+strings.Repeat("1", 64), "GENERATION_ARTIFACT_ATTEMPT=1",
				"FILES="+paths[0])
			run := func(mode string, extra ...string) ([]byte, error) {
				cmd := exec.Command("bash", filepath.Join(root, ".github/actions/signed-generation/generation.sh"), mode)
				cmd.Dir, cmd.Env = dir, append(append([]string(nil), env...), extra...)
				return cmd.CombinedOutput()
			}
			output, err := run("record")
			if defect == "record crypto failure" {
				if err == nil {
					t.Fatal("rejected signature must prevent the generation archive")
				}
				if _, err := os.Stat(archive); !os.IsNotExist(err) {
					t.Fatal("record failure emitted an archive")
				}
				return
			}
			if err != nil {
				t.Fatalf("whole-owner recording refused: %v: %s", err, output)
			}
			data, err := os.ReadFile(filepath.Join(archive, "generation-manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Files []map[string]string `json:"files"`
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest.Files) != 10 {
				t.Fatal("FILES subset must not narrow the retained full Linux owner")
			}
			for _, file := range manifest.Files {
				contents, ok := want[file["path"]]
				if !ok || file["name"] != filepath.Base(file["path"]) || file["sha256"] != fmt.Sprintf("%x", sha256.Sum256([]byte(contents))) {
					t.Fatalf("wrong retained mapping: %#v", file)
				}
			}
			metadata := map[string]any{"id": 101, "name": "signed-build-linux-attempt-1", "digest": "sha256:" + strings.Repeat("1", 64), "expired": false, "workflow_run": map[string]any{"id": 900, "head_sha": releaseTestSHA}}
			switch defect {
			case "expired":
				metadata["expired"] = true
			case "wrong metadata ID":
				metadata["id"] = 102
			case "wrong metadata name":
				metadata["name"] = "replacement"
			case "wrong metadata digest":
				metadata["digest"] = "sha256:" + strings.Repeat("f", 64)
			case "wrong metadata source":
				metadata["workflow_run"].(map[string]any)["head_sha"] = strings.Repeat("f", 40)
			case "wrong metadata run":
				metadata["workflow_run"].(map[string]any)["id"] = 901
			}
			writeJSONFixture(t, filepath.Join(dir, "metadata.json"), metadata)
			output, err = run("metadata", "GITHUB_RUN_ATTEMPT=2")
			if defect == "expired" || strings.HasPrefix(defect, "wrong metadata") {
				if err == nil {
					t.Fatalf("unsafe generation metadata accepted: %s", defect)
				}
				return
			}
			if err != nil {
				t.Fatalf("retained generation metadata refused: %v: %s", err, output)
			}
			if defect != "identical existing" {
				for path := range want {
					if err := os.Remove(filepath.Join(dir, path)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if defect == "hash mismatch" || defect == "wrong source" || defect == "wrong owner" || defect == "wrong producing attempt" {
				var value map[string]any
				if err := json.Unmarshal(data, &value); err != nil {
					t.Fatal(err)
				}
				files := value["files"].([]any)
				switch defect {
				case "hash mismatch":
					files[len(files)-1].(map[string]any)["sha256"] = strings.Repeat("0", 64)
				case "wrong source":
					value["source_sha"] = strings.Repeat("f", 40)
				case "wrong owner":
					value["owner_workflow"] = "build-macos.yml"
				case "wrong producing attempt":
					value["run_attempt"] = "2"
				}
				writeJSONFixture(t, filepath.Join(archive, "generation-manifest.json"), value)
			}
			if defect == "missing bundle" {
				if err := os.Remove(filepath.Join(archive, "Picocrypt-NG.sigstore.json")); err != nil {
					t.Fatal(err)
				}
			}
			if defect == "extra archive file" {
				if err := os.WriteFile(filepath.Join(archive, "extra"), []byte("extra"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if defect == "archive symlink" {
				file := filepath.Join(archive, "Picocrypt-NG")
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(dir, "matching")
				if err := os.WriteFile(outside, []byte(want[paths[0]]), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, file); err != nil {
					t.Fatal(err)
				}
			}
			if defect == "restore crypto failure" {
				if err := os.WriteFile(filepath.Join(dir, "crypto-fail"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if defect == "wrong caller" {
				writeJSONFixture(t, filepath.Join(dir, "verified.json"), []any{releaseIdentityRow(releaseIdentityCertificate("build-linux.yml", "untrusted.yml"))})
			}
			preserved := paths[len(paths)-1]
			if defect == "different existing" {
				if err := os.WriteFile(filepath.Join(dir, preserved), []byte("original different bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			output, err = run("restore", "GITHUB_RUN_ATTEMPT=2")
			positive := defect == "none" || defect == "identical existing"
			if (err == nil) != positive {
				t.Fatalf("restore %s: %v: %s", defect, err, output)
			}
			for path, contents := range want {
				data, err := os.ReadFile(filepath.Join(dir, path))
				if positive {
					if err != nil || string(data) != contents {
						t.Fatalf("retained producing attempt restore changed %s: %v", path, err)
					}
				} else if defect == "different existing" && path == preserved {
					if err != nil || string(data) != "original different bytes" {
						t.Fatal("different original destination was overwritten")
					}
				} else if !os.IsNotExist(err) {
					t.Fatalf("late mismatch wrote canonical path %s", path)
				}
			}
			calls, err := os.ReadFile(filepath.Join(dir, "calls"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(calls), "sign-blob") || strings.Contains(string(calls), "--method POST") {
				t.Fatal("generation must never sign, attest anew or mutate remote state")
			}
		})
	}
}
