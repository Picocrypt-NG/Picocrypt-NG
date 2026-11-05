package workflowpolicy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestReleaseIdentityRehearsalCannotRunInReleaseOrPRContexts(t *testing.T) {
	const branch = "ci/rehearse-release-identity"
	for _, name := range []string{"rehearse-release-identity.yml", "rehearse-release-identity-alternate.yml", "rehearse-release-identity-leaf.yml"} {
		t.Run(name, func(t *testing.T) {
			path := ".github/workflows/" + name
			workflow := mustReadWorkflowDoc(t, path)
			var events struct {
				On map[string]any `yaml:"on"`
			}
			if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, path)), &events); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read"}) {
				t.Fatalf("top-level permissions = %#v", workflow.Permissions)
			}
			if name == "rehearse-release-identity-leaf.yml" {
				if !reflect.DeepEqual(events.On, map[string]any{"workflow_call": nil}) {
					t.Fatalf("leaf must expose only an argument-free workflow_call: %#v", workflow.On)
				}
			} else {
				want := map[string]any{"push": map[string]any{"branches": []any{branch}}}
				if !reflect.DeepEqual(events.On, want) {
					t.Fatalf("rehearsal must trigger only on its exact branch: %#v", workflow.On)
				}
				call := mustJob(t, workflow, "reusable")
				if call.Uses != "./.github/workflows/rehearse-release-identity-leaf.yml" {
					t.Fatalf("callee must come from the caller commit: %q", call.Uses)
				}
			}
			for id, job := range workflow.Jobs {
				if job.Environment != nil || !reflect.DeepEqual(job.Permissions, map[string]string{"contents": "read", "id-token": "write", "attestations": "write"}) {
					t.Fatalf("%s has release environment or excess permissions: %+v", id, job)
				}
				if job.Uses != "" {
					continue
				}
				if job.RunsOn != "ubuntu-24.04" || job.TimeoutMinutes != 15 {
					t.Fatalf("probe must be bounded on a hosted runner: %+v", job)
				}
				checkout := mustStepNamed(t, job, "Checkout")
				if checkout.With["persist-credentials"] != false {
					t.Fatal("probe checkout must not persist credentials")
				}
				install := mustStepNamed(t, job, "Install cosign")
				if install.Uses != "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6" || install.With["cosign-release"] != "v3.1.3" {
					t.Fatalf("probe must exercise the production cosign pin: %+v", install)
				}
				attest := mustStepNamed(t, job, "Attest probe")
				kind := "reusable"
				if id == "direct" {
					kind = "direct"
				}
				if attest.With["subject-path"] != "rehearsal-release-identity/"+kind+"/probe.txt" {
					t.Fatalf("probe subject must be fixed, outside release artifacts: %#v", attest.With)
				}
				verify := mustStepNamed(t, job, "Verify identity and rejection controls")
				if verify.Env["PROVENANCE_BUNDLE"] != "${{ steps.attest.outputs.bundle-path }}" {
					t.Fatal("verification must consume the exact newly created provenance bundle")
				}
			}
			content := mustReadRepoFile(t, path)
			for _, forbidden := range []string{"secrets:", "secrets.", "environment:", "contents: write", "packages: write", "./.github/actions/sign-and-attest", "./.github/actions/stage-release"} {
				mustNotContain(t, content, forbidden)
			}
		})
	}
}

// These synthetic JSON fixtures test only the policy applied after gh's trusted
// verification. Real certificate and bundle rejection belongs to the hosted spike.
func TestReleaseIdentityVerifiedCertificatePolicyRejectsCallerCalleeAndSourceDrift(t *testing.T) {
	const repo = "https://github.com/Picocrypt-NG/Picocrypt-NG"
	const ref = "refs/heads/ci/rehearse-release-identity"
	const sha = "0123456789abcdef0123456789abcdef01234567"
	const caller = repo + "/.github/workflows/rehearse-release-identity.yml@" + ref
	const callee = repo + "/.github/workflows/rehearse-release-identity-leaf.yml@" + ref
	certificate := map[string]any{
		"issuer": "https://token.actions.githubusercontent.com", "subjectAlternativeName": callee,
		"buildSignerURI": callee, "buildSignerDigest": sha, "buildConfigURI": caller, "buildConfigDigest": sha,
		"sourceRepositoryURI": repo, "sourceRepositoryDigest": sha, "sourceRepositoryRef": ref, "runnerEnvironment": "github-hosted",
	}
	tests := []struct {
		name   string
		change func(map[string]any) any
		pass   bool
	}{
		{name: "exact signed fields", pass: true},
		{name: "empty result", change: func(map[string]any) any { return []any{} }},
		{name: "multiple results", change: func(c map[string]any) any { return []any{rehearsalVerification(c), rehearsalVerification(c)} }},
		{name: "not an array", change: func(c map[string]any) any { return rehearsalVerification(c) }},
	}
	for field := range certificate {
		for _, remove := range []bool{false, true} {
			tests = append(tests, struct {
				name   string
				change func(map[string]any) any
				pass   bool
			}{name: field + map[bool]string{false: " mismatch", true: " absent"}[remove], change: func(c map[string]any) any {
				if remove {
					delete(c, field)
				} else {
					c[field] = "wrong"
				}
				return []any{rehearsalVerification(c)}
			}})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := make(map[string]any, len(certificate))
			for key, value := range certificate {
				c[key] = value
			}
			var input any = []any{rehearsalVerification(c)}
			if test.change != nil {
				input = test.change(c)
			}
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "verified.json")
			if err := os.WriteFile(file, data, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", filepath.Join(repoRoot(t), ".github/scripts/rehearse-release-identity.sh"), "check-verified-certificate", file, caller, callee, sha, ref)
			output, err := command.CombinedOutput()
			if got := err == nil; got != test.pass {
				t.Fatalf("accepted=%v, want %v: %v\n%s", got, test.pass, err, output)
			}
			if !test.pass && !strings.Contains(string(output), "verified certificate policy mismatch") {
				t.Fatalf("negative must fail for identity policy, not an unrelated tool error: %s", output)
			}
		})
	}
}

func rehearsalVerification(certificate map[string]any) map[string]any {
	return map[string]any{"verificationResult": map[string]any{"signature": map[string]any{"certificate": certificate}}}
}

func TestReleaseIdentityOIDCRefusalPrecedesTokenRequest(t *testing.T) {
	for _, invalid := range []string{"repository", "ref", "event"} {
		t.Run(invalid, func(t *testing.T) {
			values := map[string]string{
				"repository": "Picocrypt-NG/Picocrypt-NG",
				"ref":        "refs/heads/ci/rehearse-release-identity",
				"event":      "push",
			}
			values[invalid] = "wrong"
			command := exec.Command("bash", filepath.Join(repoRoot(t), ".github/scripts/rehearse-release-identity.sh"), "observe-oidc", "direct")
			command.Dir = t.TempDir()
			command.Env = []string{
				"PATH=" + os.Getenv("PATH"), "GITHUB_REPOSITORY=" + values["repository"],
				"GITHUB_REF=" + values["ref"], "GITHUB_EVENT_NAME=" + values["event"],
			}
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "only the explicit same-repository rehearsal branch push is allowed") {
				t.Fatalf("context was not refused before token access: %v\n%s", err, output)
			}
			files, err := os.ReadDir(command.Dir)
			if err != nil || len(files) != 0 {
				t.Fatalf("refused context wrote evidence: files=%v err=%v", files, err)
			}
		})
	}
}

func TestReleaseIdentityGHPinMatchesReviewedOfficialAsset(t *testing.T) {
	var manifest struct {
		SchemaVersion int `json:"schema_version"`
		GH            struct {
			Version string `json:"version"`
			URL     string `json:"url"`
			AssetID int64  `json:"asset_id"`
			SHA256  string `json:"sha256"`
		} `json:"gh"`
	}
	if err := json.Unmarshal([]byte(mustReadRepoFile(t, ".github/toolchains/release-identity-rehearsal.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 || manifest.GH.Version != "2.102.1" || manifest.GH.AssetID != 660284822 || manifest.GH.SHA256 != "77b9e297e94c50336823d0f84de7ef1be60cba704601fa0d98f129f47a94987b" || manifest.GH.URL != "https://github.com/cli/cli/releases/download/v2.102.1/gh_2.102.1_linux_amd64.tar.gz" {
		t.Fatalf("gh rehearsal pin changed; review official release bytes and policy together: %+v", manifest)
	}
}

func TestReleaseIdentityOfflineGHRejectionDoesNotCountTransportOrSetupFailure(t *testing.T) {
	for _, test := range []struct {
		name string
		log  string
		pass bool
	}{
		{"public Sigstore verification", "Error: verifying with issuer \"sigstore.dev\"\n", true},
		{"GitHub Sigstore verification", "Error: verifying with issuer \"GitHub, Inc.\"\n", true},
		{"public CLI leading blank", "\nError: verifying with issuer \"sigstore.dev\"\n", true},
		{"GitHub CLI leading blank", "\nError: verifying with issuer \"GitHub, Inc.\"\n", true},
		{"unknown issuer", "Error: verifying with issuer \"unknown\"\n", false},
		{"unauthenticated", "Error: HTTP 401: Bad credentials\n", false},
		{"unauthenticated CLI leading blank", "\nError: HTTP 401: Bad credentials\n", false},
		{"network", "Error: failed to create TUF client: connection refused\n", false},
		{"root loading", "Error: error creating custom verifiers: unable to read file\n", false},
		{"bundle loading", "Error: failed to load bundle\n", false},
		{"timeout", "Error: context deadline exceeded\n", false},
		{"additional failure", "Error: verifying with issuer \"sigstore.dev\"\nError: connection refused\n", false},
		{"empty", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "negative.log")
			if err := os.WriteFile(file, []byte(test.log), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", filepath.Join(repoRoot(t), ".github/scripts/rehearse-release-identity.sh"), "check-offline-gh-rejection", file)
			output, err := command.CombinedOutput()
			if got := err == nil; got != test.pass {
				t.Fatalf("classified=%v, want %v: %v\n%s", got, test.pass, err, output)
			}
		})
	}
}
