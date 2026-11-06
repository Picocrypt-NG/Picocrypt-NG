package workflowpolicy

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestWindowsReusablePreservesDirectBuildAndReleaseRecipes(t *testing.T) {
	for _, tc := range []struct{ owner, build, release string }{
		{"build-windows", "046b0390fc51f23a49b25f2a68eb12dfd078e08af605e35f28207ae2cec19ceb", "d81113085b96d63262dbf473ed6660a0b44924c900f3a228ebc47e78fb2bfbb6"},
		{"build-windows-legacy", "709967f547ff04c3216a70fcadc882fecff2627ddbe57d514f067a3e9db731ba", "7ba368b63f66065a370f99575326478dbc9c4b7954d7eced8a8e969fa7d00e40"},
	} {
		content := mustReadWorkflow(t, ".github/workflows/"+tc.owner+".yml")
		build := strings.SplitN(strings.SplitN(content, "  build:\n", 2)[1], "  sign:\n", 2)[0]
		build = "  build:\n" + regexp.MustCompile(`(?m)^    if: .*\n`).ReplaceAllString(build, "")
		release := "  release:\n" + strings.SplitN(strings.SplitN(content, "  release:\n", 2)[1], "  inspect:\n", 2)[0]
		original := "    if: ${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && !inputs.signpath_test && !inputs.signpath_release_dry_run && inputs.publish_release }}"
		release = regexp.MustCompile(`(?m)^    if: .*`).ReplaceAllString(release, original)
		for name, actual := range map[string]string{"build": build, "release": release} {
			want := tc.build
			if name == "release" {
				want = tc.release
			}
			if got := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(actual)))); got != want {
				t.Fatalf("%s direct %s changed beyond invocation gating: %s want%s", tc.owner, name, got, want)
			}
		}
	}
}

func TestWindowsReusableVerificationPrecedesEverySigningAuthority(t *testing.T) {
	for _, owner := range windowsReusableOwners() {
		workflow := mustReadWorkflowDoc(t, ".github/workflows/"+owner+".yml")
		for _, tc := range []struct {
			job   string
			names []string
		}{
			{"sign", []string{"Validate reusable Windows source", "Inspect full Windows owner", "Verify immutable Windows input metadata", "Download Windows validation artifact", "Verify Windows validation payload", "Download unsigned build artifact", "Validate Windows signing carrier", "Require SignPath token"}},
			{"attest", []string{"Validate reusable Windows source", "Inspect full Windows owner", "Verify OS-signed Windows carrier metadata", "Download OS-signed Windows carrier", "Validate OS-signed Windows carrier payload", "Sign and attest artifacts", "Record signed Windows generation", "Upload signed Windows generation"}},
			{"stage", []string{"Validate reusable Windows source", "Verify signed generation metadata", "Download signed Windows generation", "Restore signed Windows generation", "Generate release notes", "Stage release assets"}},
		} {
			job := mustJob(t, workflow, tc.job)
			last := -1
			for _, name := range tc.names {
				index := -1
				for i, step := range job.Steps {
					if step.Name == name {
						index = i
						break
					}
				}
				if index <= last {
					t.Fatalf("%s/%s must execute %s after validation prerequisites", owner, tc.job, name)
				}
				last = index
			}
			if tc.job == "sign" {
				for index, step := range job.Steps {
					if strings.HasPrefix(step.Uses, "signpath/") && index <= last {
						t.Fatal("SignPath request precedes immutable input checks")
					}
				}
			}
		}
		attest := mustJob(t, workflow, "attest")
		record := mustStepNamed(t, attest, "Record signed Windows generation")
		if record.Env["GH_TOKEN"] != "${{ github.token }}" {
			t.Fatal("P5 online verification needs its own scoped token, not the prior composite step environment")
		}
		for _, name := range []string{"Verify OS-signed Windows carrier metadata", "Download OS-signed Windows carrier", "Validate OS-signed Windows carrier payload", "Sign and attest artifacts", "Record signed Windows generation", "Upload signed Windows generation"} {
			if mustStepNamed(t, attest, name).If != "${{ steps.inventory.outputs.state == 'missing' }}" {
				t.Fatal("fresh complete reuse must suppress every attestation and generation step")
			}
		}
		for key, want := range map[string]string{"generation-id": "${{ steps.upload-generation.outputs.artifact-id }}", "generation-digest": "${{ steps.upload-generation.outputs.artifact-digest }}", "generation-attempt": "${{ steps.generation.outputs.run-attempt }}"} {
			if attest.Outputs[key] != want {
				t.Fatal("retained generation outputs must come from real producing steps")
			}
		}
	}
}
