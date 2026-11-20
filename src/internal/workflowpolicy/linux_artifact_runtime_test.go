//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxWASMDeadlinePreservesFailureStatus(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/build-linux/action.yml")
	step := mustCompositeStepNamed(t, action, "Test browser PCV3 and legacy compatibility")
	if step.Run != "timeout --kill-after=30s 45m .github/scripts/test-wasm.sh" {
		t.Fatal("the composite must retain the WASM 45-minute deadline and bounded termination")
	}
	for _, status := range []int{0, 23, 124} {
		dir := t.TempDir()
		fixture := filepath.Join(dir, "wasm-fixture.sh")
		if err := os.WriteFile(fixture, []byte(fmt.Sprintf("#!/usr/bin/env bash\nexit %d\n", status)), 0o700); err != nil {
			t.Fatal(err)
		}
		command := strings.ReplaceAll(step.Run, ".github/scripts/test-wasm.sh", fixture)
		err := exec.Command("bash", "-eo", "pipefail", "-c", command).Run()
		got := 0
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				got = exit.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if got != status {
			t.Fatalf("WASM status %d became %d", status, got)
		}
	}
}

func TestLinuxArtifactVerifierRejectsSourceArchiveAndPayloadSubstitution(t *testing.T) {
	root := repoRoot(t)
	shaOut, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	source := strings.TrimSpace(string(shaOut))
	version := strings.TrimSpace(mustReadRepoFile(t, "VERSION"))
	canonical, err := exec.Command("bash", filepath.Join(root, ".github/actions/stage-release/release-manifest.sh"), version).Output()
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	for _, defect := range []string{"none", "missing ID", "duplicate ID", "wrong ZIP digest", "wrong name", "wrong source", "wrong run", "expired", "wrong payload hash", "missing file", "unexpected file", "symlink", "matching manifest symlink", "matching payload symlink", "wrong payload source", "duplicate payload file", "missing build materials", "wrong build materials", "wrong ELF architecture", "wrong deb architecture", "wrong deb executable"} {
		t.Run(defect, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			gh := "#!/usr/bin/env bash\nset -euo pipefail\n[[ $1 == api ]]\nid=${2##*/}\ncat \"$FIXTURE_DIR/$id.json\"\n"
			if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(gh), 0o700); err != nil {
				t.Fatal(err)
			}
			for arch, id := range map[string]string{"amd64": "101", "arm64": "102"} {
				metadata := map[string]any{"id": id, "name": "build-linux-" + arch + "-attempt-1", "digest": "sha256:" + strings.Repeat(id[:1], 64), "expired": false, "workflow_run": map[string]any{"id": "900", "head_sha": source}}
				if arch == "amd64" {
					switch defect {
					case "wrong ZIP digest":
						metadata["digest"] = "sha256:" + strings.Repeat("f", 64)
					case "wrong name":
						metadata["name"] = "replacement"
					case "wrong source":
						metadata["workflow_run"].(map[string]any)["head_sha"] = strings.Repeat("f", 40)
					case "wrong run":
						metadata["workflow_run"].(map[string]any)["id"] = "901"
					case "expired":
						metadata["expired"] = true
					}
				}
				writeLinuxJSONFixture(t, filepath.Join(dir, id+".json"), metadata)
				payloadDir := filepath.Join(dir, "artifacts", "build-linux-"+arch)
				if err := os.MkdirAll(payloadDir, 0o700); err != nil {
					t.Fatal(err)
				}
				var files []map[string]string
				for _, line := range strings.Split(strings.TrimSpace(string(canonical)), "\n") {
					fields := strings.Fields(line)
					if fields[1] != "build-linux.yml" || !strings.HasPrefix(fields[2], "artifacts/build-linux-"+arch+"/") {
						continue
					}
					name := fields[0]
					if strings.HasSuffix(name, ".deb") {
						continue
					}
					machine := uint16(62) // EM_X86_64
					if arch == "arm64" || defect == "wrong ELF architecture" {
						machine = 183 // EM_AARCH64
					}
					data := make([]byte, 64+len(name))
					copy(data, "\x7fELF\x02\x01\x01") // ELF64, little endian, version 1.
					binary.LittleEndian.PutUint16(data[16:], 2)
					binary.LittleEndian.PutUint16(data[18:], machine)
					binary.LittleEndian.PutUint32(data[20:], 1)
					binary.LittleEndian.PutUint16(data[52:], 64)
					copy(data[64:], name)
					if err := os.WriteFile(filepath.Join(payloadDir, name), data, 0o600); err != nil {
						t.Fatal(err)
					}
					files = append(files, map[string]string{"name": name, "sha256": fmt.Sprintf("%x", sha256.Sum256(data))})
				}
				payloadSource := source
				if arch == "amd64" {
					debRoot := filepath.Join(dir, "deb")
					binDir := filepath.Join(debRoot, "usr", "bin")
					if err := os.MkdirAll(binDir, 0o755); err != nil {
						t.Fatal(err)
					}
					controlDir := filepath.Join(debRoot, "DEBIAN")
					if err := os.Mkdir(controlDir, 0o755); err != nil {
						t.Fatal(err)
					}
					debArch := arch
					if defect == "wrong deb architecture" {
						debArch = "arm64"
					}
					control := fmt.Sprintf("Package: picocrypt-ng\nVersion: %s\nArchitecture: %s\nMaintainer: Picocrypt-NG\nDescription: Payload verification fixture\n", version, debArch)
					if err := os.WriteFile(filepath.Join(controlDir, "control"), []byte(control), 0o644); err != nil {
						t.Fatal(err)
					}
					gui := "Picocrypt-NG"
					if defect == "wrong deb executable" {
						gui = "Picocrypt-NG-cli"
					}
					data, err := os.ReadFile(filepath.Join(payloadDir, gui))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(binDir, "picocrypt-ng-gui"), data, 0o755); err != nil {
						t.Fatal(err)
					}
					const deb = "Picocrypt-NG.deb"
					debPath := filepath.Join(payloadDir, deb)
					if output, err := exec.Command("dpkg-deb", "--build", "--root-owner-group", debRoot, debPath).CombinedOutput(); err != nil {
						t.Fatalf("build .deb: %v: %s", err, output)
					}
					data, err = os.ReadFile(debPath)
					if err != nil {
						t.Fatal(err)
					}
					files = append(files, map[string]string{"name": deb, "sha256": fmt.Sprintf("%x", sha256.Sum256(data))})
					file := filepath.Join(payloadDir, files[0]["name"])
					switch defect {
					case "wrong payload hash":
						files[0]["sha256"] = strings.Repeat("f", 64)
					case "missing file", "symlink":
						if err := os.Remove(file); err != nil {
							t.Fatal(err)
						}
						if defect == "symlink" {
							if err := os.Symlink(filepath.Join(dir, "101.json"), file); err != nil {
								t.Fatal(err)
							}
						}
					case "matching payload symlink":
						// A later regular file must not hide the first sorted file's rejected link.
						name := files[0]["name"]
						for _, candidate := range files[1:] {
							if candidate["name"] < name {
								name = candidate["name"]
							}
						}
						file = filepath.Join(payloadDir, name)
						data, err := os.ReadFile(file)
						if err != nil {
							t.Fatal(err)
						}
						target := filepath.Join(dir, "matching-payload")
						if err := os.WriteFile(target, data, 0o600); err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(file); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(target, file); err != nil {
							t.Fatal(err)
						}
					case "unexpected file":
						if err := os.WriteFile(filepath.Join(payloadDir, "extra"), []byte("extra"), 0o600); err != nil {
							t.Fatal(err)
						}
					case "wrong payload source":
						payloadSource = strings.Repeat("f", 40)
					case "duplicate payload file":
						files = append(files, files[0])
					}
				}
				payload := map[string]any{
					"schema_version": 1, "repository": "Picocrypt-NG/Picocrypt-NG", "source_sha": payloadSource,
					"version": version, "canonical_manifest_sha256": manifestDigest, "owner_workflow": "build-linux.yml",
					"arch": arch, "run_id": "900", "run_attempt": "1", "files": files,
				}
				materials := releaseMaterialsFixture(t, "build-linux.yml", arch)
				payload["materials"] = materials
				if arch == "amd64" {
					switch defect {
					case "missing build materials":
						delete(payload, "materials")
					case "wrong build materials":
						materials["packages_sha256"] = strings.Repeat("f", 64)
					}
				}
				writeLinuxJSONFixture(t, filepath.Join(payloadDir, "payload-manifest.json"), payload)
				if arch == "amd64" && defect == "matching manifest symlink" {
					manifest := filepath.Join(payloadDir, "payload-manifest.json")
					data, err := os.ReadFile(manifest)
					if err != nil {
						t.Fatal(err)
					}
					target := filepath.Join(dir, "matching-manifest.json")
					if err := os.WriteFile(target, data, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(manifest); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, manifest); err != nil {
						t.Fatal(err)
					}
				}
			}
			env := append(os.Environ(), "PATH="+bin+":/usr/bin:/bin:"+os.Getenv("PATH"), "FIXTURE_DIR="+dir,
				"GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG", "GITHUB_SHA="+source, "GITHUB_RUN_ID=900", "GITHUB_RUN_ATTEMPT=2",
				"SOURCE_SHA="+source, "SOURCE_VERSION="+version, "CANONICAL_MANIFEST_SHA256="+manifestDigest,
				"AMD64_ARTIFACT_ID=101", "ARM64_ARTIFACT_ID=102", "AMD64_ARTIFACT_DIGEST="+strings.Repeat("1", 64), "ARM64_ARTIFACT_DIGEST="+strings.Repeat("1", 64),
				"AMD64_RUN_ATTEMPT=1", "ARM64_RUN_ATTEMPT=1", "ARTIFACT_ROOT="+filepath.Join(dir, "artifacts"), "LINUX_MANIFEST="+filepath.Join(dir, "linux-artifacts.json"))
			if defect == "missing ID" {
				env = append(env, "AMD64_ARTIFACT_ID=")
			}
			if defect == "duplicate ID" {
				env = append(env, "ARM64_ARTIFACT_ID=101")
			}
			var output []byte
			for _, phase := range []string{"metadata", "payload"} {
				cmd := exec.Command("bash", filepath.Join(root, ".github/actions/build-linux/verify-artifacts.sh"), phase)
				cmd.Dir, cmd.Env = root, env
				output, err = cmd.CombinedOutput()
				if err != nil {
					break
				}
			}
			if (err == nil) != (defect == "none") {
				t.Fatalf("defect %s: err=%v, output=%s", defect, err, output)
			}
		})
	}
}

func writeLinuxJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
