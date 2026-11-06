//go:build linux

package workflowpolicy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const releaseCertificatePolicyPath = ".github/actions/sign-and-attest/verify-certificate.sh"

var releaseIdentityOwners = []string{"build-linux.yml", "build-macos.yml", "build-windows.yml", "build-windows-legacy.yml", "build-android.yml", "build-appimage.yml", "build-snapcraft.yml"}

// Synthetic rows test policy after gh verification; they are not cryptographic proof.
func releaseIdentityCertificate(owner, caller string) map[string]any {
	uri := "https://github.com/Picocrypt-NG/Picocrypt-NG/.github/workflows/"
	return map[string]any{
		"issuer":                 "https://token.actions.githubusercontent.com",
		"subjectAlternativeName": uri + owner + "@refs/heads/main", "buildSignerURI": uri + owner + "@refs/heads/main",
		"buildSignerDigest": releaseTestSHA, "buildConfigURI": uri + caller + "@refs/heads/main", "buildConfigDigest": releaseTestSHA,
		"sourceRepositoryURI": "https://github.com/Picocrypt-NG/Picocrypt-NG", "sourceRepositoryDigest": releaseTestSHA,
		"sourceRepositoryRef": "refs/heads/main", "runnerEnvironment": "github-hosted",
	}
}

func releaseIdentityRow(certificate map[string]any) map[string]any {
	return map[string]any{"verificationResult": map[string]any{"signature": map[string]any{"certificate": certificate}}}
}

func checkReleaseIdentityFixture(t *testing.T, mode, owner, caller string, rows any, want bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "verified.json")
	writeJSONFixture(t, path, rows)
	args := []string{filepath.Join(repoRoot(t), releaseCertificatePolicyPath), mode, path, owner, releaseTestSHA}
	if mode == "exact" {
		args = append(args, "Picocrypt-NG/Picocrypt-NG/.github/workflows/"+caller+"@refs/heads/main")
	}
	output, err := exec.Command("bash", args...).CombinedOutput()
	if (err == nil) != want {
		t.Fatalf("certificate policy accepted=%v, want %v: %v: %s", err == nil, want, err, output)
	}
	if !want && !strings.Contains(string(output), "verified provenance certificate policy mismatch") {
		t.Fatalf("negative did not fail for the certificate contract: %v: %s", err, output)
	}
}

func TestReleaseIdentityAcceptsFourteenExactTuples(t *testing.T) {
	for _, owner := range releaseIdentityOwners {
		for _, caller := range []string{owner, "release.yml"} {
			for _, mode := range []string{"exact", "online"} {
				t.Run(owner+"/"+caller+"/"+mode, func(t *testing.T) {
					checkReleaseIdentityFixture(t, mode, owner, caller, []any{releaseIdentityRow(releaseIdentityCertificate(owner, caller))}, true)
				})
			}
		}
	}
}

func TestReleaseIdentityRejectsMissingOrMismatchedCertificateFields(t *testing.T) {
	for field := range releaseIdentityCertificate("build-linux.yml", "release.yml") {
		for _, remove := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/remove=%v", field, remove), func(t *testing.T) {
				certificate := releaseIdentityCertificate("build-linux.yml", "release.yml")
				if remove {
					delete(certificate, field)
				} else {
					certificate[field] = "wrong"
				}
				checkReleaseIdentityFixture(t, "online", "build-linux.yml", "", []any{releaseIdentityRow(certificate)}, false)
			})
		}
	}
}

func TestReleaseIdentityRejectsWrongCallerWithoutChangingOwnerSANOrSHA(t *testing.T) {
	for _, owner := range releaseIdentityOwners {
		bad := releaseIdentityRow(releaseIdentityCertificate(owner, "untrusted.yml"))
		good := releaseIdentityRow(releaseIdentityCertificate(owner, owner))
		for _, rows := range [][]any{{bad}, {good, bad}} {
			checkReleaseIdentityFixture(t, "online", owner, "", rows, false)
		}
	}
	checkReleaseIdentityFixture(t, "exact", "build-linux.yml", "release.yml", []any{releaseIdentityRow(releaseIdentityCertificate("build-linux.yml", "build-linux.yml"))}, false)
	checkReleaseIdentityFixture(t, "online", "build-macos.yml", "", []any{releaseIdentityRow(releaseIdentityCertificate("build-linux.yml", "release.yml"))}, false)
}

func TestReleaseIdentityMultiplicityIsStrictLocallyAndAllRowsOnline(t *testing.T) {
	row := releaseIdentityRow(releaseIdentityCertificate("build-linux.yml", "release.yml"))
	for _, invalid := range []any{[]any{}, map[string]any{}, []any{nil}} {
		checkReleaseIdentityFixture(t, "online", "build-linux.yml", "", invalid, false)
	}
	checkReleaseIdentityFixture(t, "online", "build-linux.yml", "", []any{row, row}, true)
	checkReleaseIdentityFixture(t, "exact", "build-linux.yml", "release.yml", []any{row, row}, false)
}

func TestReleaseIdentityOwnershipAllowsCoordinatorButNotForeignDirectOwner(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/sign-and-attest/action.yml")
	step := mustCompositeStepNamed(t, action, "Validate exact release artifact ownership")
	canonical, err := exec.Command("bash", filepath.Join(repoRoot(t), releaseManifestScriptPath), "2.19").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range releaseIdentityOwners {
		foreign := "build-linux.yml"
		if owner == foreign {
			foreign = "build-macos.yml"
		}
		for _, caller := range []string{owner, "release.yml", foreign, "untrusted.yml"} {
			t.Run(owner+"/"+caller, func(t *testing.T) {
				root := t.TempDir()
				if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("2.19\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				path := ""
				for _, line := range strings.Split(strings.TrimSpace(string(canonical)), "\n") {
					fields := strings.Fields(line)
					if fields[1] == owner {
						path = fields[2]
						break
					}
				}
				if path == "" {
					t.Fatal("canonical owner missing")
				}
				if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, path), []byte("owner artifact fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
				bin := filepath.Join(root, "bin")
				if err := os.Mkdir(bin, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\n[ \"$*\" = 'rev-parse HEAD' ] || exit 97\nprintf '%s\\n' \"$GITHUB_SHA\"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				outputPath := filepath.Join(root, "output")
				command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
				command.Dir = root
				command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "PATHS="+path,
					"GITHUB_ACTION_PATH="+filepath.Join(repoRoot(t), ".github/actions/sign-and-attest"), "GITHUB_WORKSPACE="+root,
					"GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG", "GITHUB_SHA="+releaseTestSHA, "GITHUB_WORKFLOW_SHA="+releaseTestSHA,
					"WORKFLOW_REF=Picocrypt-NG/Picocrypt-NG/.github/workflows/"+caller+"@refs/heads/main", "GITHUB_OUTPUT="+outputPath)
				output, runErr := command.CombinedOutput()
				if (runErr == nil) != (caller == owner || caller == "release.yml") {
					t.Fatalf("ownership accepted=%v: %v: %s", runErr == nil, runErr, output)
				}
				if runErr == nil {
					written, err := os.ReadFile(outputPath)
					if err != nil || !strings.Contains(string(written), "owner="+owner+"\n") {
						t.Fatalf("ownership did not bind exactly one signer owner: %v: %q", err, written)
					}
				}
			})
		}
	}
}

func TestReleaseIdentityGateRequiresEveryVerifiedRowAndKeepsDirectReuse(t *testing.T) {
	releases := []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}
	assets := []releaseAssetFixture{newReleaseAsset(101, "Picocrypt-NG", "earlier GUI"), newReleaseAsset(102, "Picocrypt-NG.sigstore.json", "earlier bundle")}
	for _, tc := range []struct {
		name, caller, policy, workflow string
		pass                           bool
	}{
		{"direct", "", "", "", true},
		{"coordinator with direct certificates", "", "", "release.yml", true},
		{"reusable", "release.yml", "", "release.yml", true},
		{"duplicate valid", "release.yml", "duplicate", "release.yml", true},
		{"wrong caller same SAN and SHA", "untrusted.yml", "", "", false},
		{"mixed valid and wrong caller", "", "mixed", "", false},
		{"empty verified output", "", "empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, "preflight", releases, assets, releaseGateOptions{workflow: tc.workflow, attestationCaller: tc.caller, attestationPolicy: tc.policy})
			if (result.err == nil) != tc.pass {
				t.Fatalf("gate accepted=%v want%v: %v: %s", result.err == nil, tc.pass, result.err, result.output)
			}
			if !tc.pass {
				mustContain(t, result.output, "verified provenance certificate policy mismatch")
			}
			mustNotContain(t, result.calls, "--method POST")
			mustNotContain(t, result.calls, "--method PATCH")
		})
	}
}

func TestReleaseIdentityActionRequiresExactBundleAndRuntimeCallerAfterVerification(t *testing.T) {
	step := mustCompositeStepNamed(t, mustReadCompositeActionDoc(t, ".github/actions/sign-and-attest/action.yml"), "Fail-loud verify (cosign + provenance)")
	for _, mode := range []string{"valid", "wrong caller", "multiple", "crypto refused", "missing bundle"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			bundle := filepath.Join(dir, "provenance.bundle")
			if err := os.WriteFile(bundle, []byte("exact action output fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			if mode == "missing bundle" {
				if err := os.Remove(bundle); err != nil {
					t.Fatal(err)
				}
			}
			certificate := releaseIdentityCertificate("build-linux.yml", "release.yml")
			if mode == "wrong caller" {
				certificate = releaseIdentityCertificate("build-linux.yml", "build-linux.yml")
			}
			rows := []any{releaseIdentityRow(certificate)}
			if mode == "multiple" {
				rows = append(rows, rows[0])
			}
			verified := filepath.Join(dir, "verified.json")
			writeJSONFixture(t, verified, rows)
			calls := filepath.Join(dir, "calls")
			gh := `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$IDENTITY_CALLS"
[[ $1 == attestation && $2 == verify ]]
arguments=("$@")
found_bundle=false
found_format=false
for (( index=0; index<${#arguments[@]}; index++ )); do
  if [[ ${arguments[index]} == --bundle && ${arguments[index+1]} == "$PROVENANCE_BUNDLE" ]]; then found_bundle=true; fi
  if [[ ${arguments[index]} == --format && ${arguments[index+1]} == json ]]; then found_format=true; fi
done
[[ $found_bundle == true && $found_format == true ]]
[[ $IDENTITY_MODE != 'crypto refused' ]] || exit 1
cat "$IDENTITY_JSON"
`
			for name, script := range map[string]string{"gh": gh, "cosign": "#!/bin/sh\n[ \"$1\" = verify-blob ] || exit 97\n", "sleep": "#!/bin/sh\nexit 0\n"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", "-euo", "pipefail", "-c", step.Run)
			command.Dir = dir
			command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FILES=artifact", "OWNER=build-linux.yml",
				"CALLER_REF=Picocrypt-NG/Picocrypt-NG/.github/workflows/release.yml@refs/heads/main", "PROVENANCE_BUNDLE="+bundle,
				"IDENTITY=https://github.com/Picocrypt-NG/Picocrypt-NG/.github/workflows/build-linux.yml@refs/heads/main",
				"ISSUER=https://token.actions.githubusercontent.com", "REPO=Picocrypt-NG/Picocrypt-NG", "SOURCE_SHA="+releaseTestSHA,
				"GITHUB_ACTION_PATH="+filepath.Join(repoRoot(t), ".github/actions/sign-and-attest"), "IDENTITY_JSON="+verified, "IDENTITY_CALLS="+calls, "IDENTITY_MODE="+mode)
			output, err := command.CombinedOutput()
			if (err == nil) != (mode == "valid") {
				t.Fatalf("exact action mode%s accepted=%v: %v: %s", mode, err == nil, err, output)
			}
			if mode == "wrong caller" || mode == "multiple" {
				mustContain(t, string(output), "verified provenance certificate policy mismatch")
			}
			if mode == "missing bundle" {
				if data, _ := os.ReadFile(calls); len(data) != 0 {
					t.Fatal("missing exact bundle fell back to provenance lookup")
				}
			}
		})
	}
}
