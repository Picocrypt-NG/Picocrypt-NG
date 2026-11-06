//go:build linux

package workflowpolicy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsReusableInputMetadataBindsBothIndependentCarriers(t *testing.T) {
	for _, owner := range windowsReusableOwners() {
		body := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/"+owner+".yml"), "sign"), "Verify immutable Windows input metadata").Run
		for _, defect := range []string{"none", "aliased IDs", "empty digest", "future attempt", "expired raw", "expired signing", "wrong signing name", "wrong signing digest", "wrong signing run", "wrong signing source"} {
			t.Run(owner+"/"+defect, func(t *testing.T) {
				dir, env := windowsReusableFixture(t, owner)
				validationName, signingName := "validate-windows-current-amd64-attempt-1", "unsigned-windows-attempt-1"
				if owner == "build-windows-legacy" {
					validationName, signingName = "validate-windows-legacy-amd64-attempt-1", "unsigned-windows-legacy-attempt-1"
				}
				env["RAW_ID"], env["SIGNING_ID"] = "101", "102"
				env["RAW_DIGEST"], env["SIGNING_DIGEST"] = strings.Repeat("b", 64), strings.Repeat("c", 64)
				env["RAW_ATTEMPT"], env["SIGNING_ATTEMPT"] = "1", "1"
				env["PLATFORM_OWNER"], env["PLATFORM_MANIFEST"] = owner+".yml", filepath.Join(dir, "platform.json")
				metadata := func(id int, name, digest string) map[string]any {
					return map[string]any{"id": id, "name": name, "digest": "sha256:" + digest, "expired": false, "workflow_run": map[string]any{"id": 123, "head_sha": env["SOURCE_SHA"]}}
				}
				raw, signing := metadata(101, validationName, env["RAW_DIGEST"]), metadata(102, signingName, env["SIGNING_DIGEST"])
				switch defect {
				case "aliased IDs":
					env["SIGNING_ID"] = "101"
				case "empty digest":
					env["SIGNING_DIGEST"] = ""
				case "future attempt":
					env["SIGNING_ATTEMPT"] = "3"
				case "expired raw":
					raw["expired"] = true
				case "expired signing":
					signing["expired"] = true
				case "wrong signing name":
					signing["name"] = "unsigned-windows"
				case "wrong signing digest":
					signing["digest"] = "sha256:" + strings.Repeat("d", 64)
				case "wrong signing run":
					signing["workflow_run"].(map[string]any)["id"] = 124
				case "wrong signing source":
					signing["workflow_run"].(map[string]any)["head_sha"] = strings.Repeat("d", 40)
				}
				for name, value := range map[string]any{"101": raw, "102": signing} {
					data, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					writeWindowsMetadataFixture(t, filepath.Join(dir, name+".json"), string(data), 0o600)
				}
				writeWindowsMetadataFixture(t, filepath.Join(dir, "bin", "gh"), "#!/bin/bash\nset -euo pipefail\n[[ $1 == api && $2 == --method && $3 == GET ]]\ncase $4 in repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/101|repos/Picocrypt-NG/Picocrypt-NG/actions/artifacts/102) ;; *) exit 97 ;; esac\ncat \"$FIXTURE_METADATA_DIR/${4##*/}.json\"\n", 0o700)
				writeWindowsMetadataFixture(t, filepath.Join(dir, ".github/actions/verify-platform-artifacts/verify-artifacts.sh"), mustReadRepoFile(t, ".github/actions/verify-platform-artifacts/verify-artifacts.sh"), 0o700)
				env["FIXTURE_METADATA_DIR"] = dir
				output, err := runWindowsReusableBody(t, dir, env, body)
				if (err == nil) != (defect == "none") {
					t.Fatalf("input metadata err=%v: %s", err, output)
				}
				bound, _ := os.ReadFile(env["GITHUB_ENV"])
				if defect != "none" && len(bound) != 0 {
					t.Fatal("invalid/expired carrier advertised verified metadata")
				}
			})
		}
	}
}

func TestWindowsReusablePinnedGHInstallerPowerShellParses(t *testing.T) {
	step := mustCompositeStepNamed(t, mustReadCompositeActionDoc(t, ".github/actions/setup-gh/action.yml"), "Install checksum-locked Windows GitHub CLI")
	command := exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-Command", `$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors); if ($errors.Count -ne 0) { $errors | Out-String | Write-Error; exit 1 }`)
	command.Stdin = strings.NewReader(step.Run)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Windows installer PowerShell parse: %v: %s", err, output)
	}
}
