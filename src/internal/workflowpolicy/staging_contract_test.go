//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// These are source-only gate fixtures with fake HTTP and cryptographic tools;
// they do not establish production signing, hosted publication, or identity acceptance.
func TestStagingInspectOwnerDerivesWholeRemoteSetWithoutLocalInputs(t *testing.T) {
	for _, owner := range []string{"build-linux.yml", "build-appimage.yml"} {
		for _, state := range []string{"complete", "missing release", "missing owner", "partial", "primary without bundle", "bundle without primary"} {
			t.Run(owner+"/"+state, func(t *testing.T) {
				assets := stagingOwnerAssets(owner)
				releases := stagingDraftRelease()
				status, verified := "complete", len(assets)/2
				switch state {
				case "missing release":
					releases, assets, status, verified = nil, nil, "missing", 0
				case "missing owner":
					assets, status, verified = nil, "missing", 0
				case "partial":
					assets, status, verified = assets[:2], "partial", 1
				case "primary without bundle":
					assets = assets[:1]
				case "bundle without primary":
					assets = assets[1:2]
				}
				result := runReleaseGateWithOptions(t, "inspect-owner", releases, assets, releaseGateOptions{
					workflow: "release.yml", ownerWorkflow: owner, noLocalFiles: true, noBody: true,
				})
				stagingRequireReadOnly(t, result)
				stagingRequireOutputs(t, result, false, false)
				if strings.Contains(state, "without") {
					if result.err == nil {
						t.Fatal("a half pair must not be reusable or reported as an ordinary missing owner")
					}
					return
				}
				if result.err != nil {
					t.Fatalf("owner inspection requires no local FILES or body: %v\n%s", result.err, result.output)
				}
				stagingRequireInspection(t, result, owner, status, verified, assets)
			})
		}
	}
}

func TestStagingInspectOwnerRequiresExactCanonicalOwnerAndCoordinatorCaller(t *testing.T) {
	for _, owner := range []string{
		"build-linux.yml", "build-macos.yml", "build-windows.yml", "build-windows-legacy.yml",
		"build-android.yml", "build-appimage.yml", "build-snapcraft.yml",
	} {
		t.Run(owner, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, "inspect-owner", nil, nil, releaseGateOptions{
				workflow: "release.yml", ownerWorkflow: owner, noLocalFiles: true, noBody: true,
			})
			if result.err != nil {
				t.Fatalf("canonical owner inspection refused: %v\n%s", result.err, result.output)
			}
			stagingRequireInspection(t, result, owner, "missing", 0, nil)
			stagingRequireReadOnly(t, result)
			stagingRequireOutputs(t, result, false, false)
		})
	}
	for _, owner := range []string{"", "release.yml", "build-other.yml", "../build-linux.yml", "build-linux.yml@refs/heads/main", "build-linux.yml\nbuild-macos.yml", "BUILD-LINUX.yml"} {
		t.Run("invalid owner "+owner, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, "inspect-owner", nil, nil, releaseGateOptions{
				workflow: "release.yml", ownerWorkflow: owner, noLocalFiles: true, noBody: true,
			})
			if result.err == nil || result.calls != "" {
				t.Fatalf("an invalid explicit owner must fail before GitHub access: %v\n%s", result.err, result.calls)
			}
			stagingRequireOutputs(t, result, false, false)
		})
	}
	for _, mode := range []string{"inspect-owner", "strict-finalize"} {
		t.Run(mode+" from direct owner", func(t *testing.T) {
			result := runReleaseGateWithOptions(t, mode, stagingDraftRelease(), completeReleaseAssets("2.19"), releaseGateOptions{
				workflow: "build-linux.yml", ownerWorkflow: "build-linux.yml", noLocalFiles: true,
			})
			if result.err == nil || result.calls != "" {
				t.Fatalf("new coordinator-only mode accepted a direct owner caller: %v\n%s", result.err, result.calls)
			}
			stagingRequireOutputs(t, result, false, false)
		})
	}
}

func TestStagingInspectOwnerRejectsUntrustedOrUnstableRemotePairs(t *testing.T) {
	for _, defect := range []string{"published", "wrong source", "wrong tag", "cosign", "provenance", "empty API digest", "malformed API digest", "wrong API digest", "corrupt download", "empty asset", "unfinished asset", "snapshot changed"} {
		t.Run(defect, func(t *testing.T) {
			releases, assets := stagingDraftRelease(), stagingOwnerAssets("build-appimage.yml")
			options := releaseGateOptions{workflow: "release.yml", ownerWorkflow: "build-appimage.yml", noLocalFiles: true, noBody: true}
			switch defect {
			case "published":
				releases[0].Draft = false
			case "wrong source":
				releases[0].TargetCommitish = strings.Repeat("f", 40)
			case "wrong tag":
				options.tagTarget = strings.Repeat("f", 40)
			case "cosign":
				options.cosignFailure = assets[0].Name
			case "provenance":
				options.attestationFailure = assets[0].Name
			case "empty API digest":
				assets[0].Digest = ""
			case "malformed API digest":
				assets[0].Digest = "sha256:broken"
			case "wrong API digest":
				assets[0].Digest = "sha256:" + strings.Repeat("f", 64)
			case "corrupt download":
				assets[0].Content = strings.Repeat("x", int(assets[0].Size))
			case "empty asset":
				assets[0].Size = 0
			case "unfinished asset":
				assets[0].State = "starter"
			case "snapshot changed":
				options.assetsAfterVerify = append([]releaseAssetFixture(nil), assets...)
				options.assetsAfterVerify[0].ID = 99999
			}
			result := runReleaseGateWithOptions(t, "inspect-owner", releases, assets, options)
			if result.err == nil {
				t.Fatalf("%s was accepted as reusable owner bytes:\n%s", defect, result.output)
			}
			stagingRequireReadOnly(t, result)
			stagingRequireOutputs(t, result, false, false)
		})
	}
}

func TestStagingStrictFinalizeRequiresCompleteVerifiedInventoryAndFinalReadback(t *testing.T) {
	t.Run("complete draft without local artifacts", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "strict-finalize", stagingDraftRelease(), completeReleaseAssets("2.19"), releaseGateOptions{
			workflow: "release.yml", noLocalFiles: true, tagAbsent: true,
		})
		if result.err != nil {
			t.Fatalf("complete remotely verified release was not finalized: %v\n%s", result.err, result.output)
		}
		stagingRequireAllVerifications(t, result)
		mustContainInOrder(t, result.calls,
			"api --method POST repos/Picocrypt-NG/Picocrypt-NG/git/refs",
			"api --method PATCH repos/Picocrypt-NG/Picocrypt-NG/releases/42")
		var patch map[string]any
		if err := json.Unmarshal([]byte(result.patchInput), &patch); err != nil {
			t.Fatal(err)
		}
		if len(patch) != 3 || patch["draft"] != false || patch["make_latest"] != "true" || patch["body"] != result.expectedBody {
			t.Fatalf("strict finalize changed the deterministic publication contract: %#v", patch)
		}
		lastPatch := strings.LastIndex(result.calls, "--method PATCH")
		lastTag := strings.LastIndex(result.calls, "git/matching-refs/tags/2.19")
		if lastTag <= lastPatch {
			t.Fatal("published=true requires the final source-bound tag readback")
		}
		stagingRequireOutputs(t, result, false, true)
	})

	for _, defect := range []string{"missing pair", "half pair", "cosign", "provenance", "corrupt download", "bad PATCH", "tag drift before PATCH", "tag drift after PATCH", "missing deterministic body"} {
		t.Run(defect, func(t *testing.T) {
			assets := completeReleaseAssets("2.19")
			options := releaseGateOptions{workflow: "release.yml", noLocalFiles: true}
			switch defect {
			case "missing pair":
				assets = assets[:len(assets)-2]
			case "half pair":
				assets = assets[:len(assets)-1]
			case "cosign":
				options.cosignFailure = assets[0].Name
			case "provenance":
				options.attestationFailure = assets[0].Name
			case "corrupt download":
				assets[0].Content = strings.Repeat("x", int(assets[0].Size))
			case "bad PATCH":
				options.invalidPatchResponse = true
			case "tag drift before PATCH":
				options.tagTargetAfterVerify = strings.Repeat("f", 40)
			case "tag drift after PATCH":
				options.tagTargetAfterPublish = strings.Repeat("f", 40)
			case "missing deterministic body":
				options.noBody = true
			}
			result := runReleaseGateWithOptions(t, "strict-finalize", stagingDraftRelease(), assets, options)
			if result.err == nil {
				t.Fatalf("strict finalize accepted %s:\n%s", defect, result.output)
			}
			if defect == "bad PATCH" || defect == "tag drift after PATCH" {
				mustContain(t, result.calls, "--method PATCH")
			} else {
				mustNotContain(t, result.calls, "--method PATCH")
			}
			mustNotContain(t, result.calls, "--method DELETE")
			stagingRequireOutputs(t, result, false, false)
		})
	}

	t.Run("legacy publish still leaves an incomplete draft without failing", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "publish", stagingDraftRelease(), defaultRemoteLaneAssets(), releaseGateOptions{
			workflow: "build-linux.yml", noLocalFiles: true,
		})
		if result.err != nil {
			t.Fatalf("legacy early owner publication must retain its partial-draft behavior: %v\n%s", result.err, result.output)
		}
		stagingRequireReadOnly(t, result)
		stagingRequireOutputs(t, result, false, false)
	})
}

func TestStagingStrictFinalizePatchBodyMatchesValidatedSource(t *testing.T) {
	result := runReleaseGateWithOptions(t, "strict-finalize", stagingDraftRelease(), completeReleaseAssets("2.19"), releaseGateOptions{
		workflow: "release.yml", noLocalFiles: true, invalidPatchBody: true,
	})
	stagingRequireAllVerifications(t, result)
	mustContain(t, result.calls, "--method PATCH")
	var patch map[string]any
	if err := json.Unmarshal([]byte(result.patchInput), &patch); err != nil {
		t.Fatal(err)
	}
	if patch["body"] != result.expectedBody {
		t.Fatal("the actual PATCH must still submit the validated source body")
	}
	if result.err == nil {
		t.Fatal("strict finalize accepted a different body returned by the actual PATCH")
	}
	stagingRequireOutputs(t, result, false, false)
}

func TestStagingStrictFinalizeAlreadyPublishedRequiresExactVerifiedStableRelease(t *testing.T) {
	for _, defect := range []string{"none", "wrong body", "missing pair", "half pair", "wrong source", "wrong tag", "missing tag", "prerelease", "cosign", "provenance", "corrupt download", "empty API digest", "malformed API digest", "snapshot changed", "tag drift"} {
		t.Run(defect, func(t *testing.T) {
			releases, assets := stagingDraftRelease(), completeReleaseAssets("2.19")
			releases[0].Draft = false
			options := releaseGateOptions{workflow: "release.yml", noLocalFiles: true, publishedBodyFromSource: true}
			switch defect {
			case "wrong body":
				options.publishedBodyFromSource = false
				options.publishedBodyOverride = "foreign release notes"
			case "missing pair":
				assets = assets[:len(assets)-2]
			case "half pair":
				assets = assets[:len(assets)-1]
			case "wrong source":
				releases[0].TargetCommitish = strings.Repeat("f", 40)
			case "wrong tag":
				options.tagTarget = strings.Repeat("f", 40)
			case "missing tag":
				options.tagAbsent = true
			case "prerelease":
				releases[0].Prerelease = true
			case "cosign":
				options.cosignFailure = assets[0].Name
			case "provenance":
				options.attestationFailure = assets[0].Name
			case "corrupt download":
				assets[0].Content = strings.Repeat("x", int(assets[0].Size))
			case "empty API digest":
				assets[0].Digest = ""
			case "malformed API digest":
				assets[0].Digest = "sha256:broken"
			case "snapshot changed":
				options.assetsAfterVerify = append([]releaseAssetFixture(nil), assets...)
				options.assetsAfterVerify[0].ID = 99999
			case "tag drift":
				options.tagTargetAfterVerify = strings.Repeat("f", 40)
			}
			result := runReleaseGateWithOptions(t, "strict-finalize", releases, assets, options)
			stagingRequireReadOnly(t, result)
			if defect != "none" {
				if result.err == nil {
					t.Fatalf("already-published %s was accepted:\n%s", defect, result.output)
				}
				stagingRequireOutputs(t, result, false, false)
				return
			}
			if result.err != nil {
				t.Fatalf("exact already-published release must be a read-only idempotent success: %v\n%s", result.err, result.output)
			}
			stagingRequireAllVerifications(t, result)
			lastVerify := strings.LastIndex(result.calls, "attestation verify ")
			lastSnapshot := strings.LastIndex(result.calls, "releases/42/assets?per_page=100")
			lastTag := strings.LastIndex(result.calls, "git/matching-refs/tags/2.19")
			if lastSnapshot <= lastVerify || lastTag <= lastSnapshot {
				t.Fatal("already-published success requires stable assets and the final source-bound tag after verification")
			}
			stagingRequireOutputs(t, result, false, true)
		})
	}
}

func TestStagingUploadOutputsBecomeTrueOnlyAfterVerifiedStableStaging(t *testing.T) {
	t.Run("verified staged pair", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "upload", nil, nil, releaseGateOptions{})
		if result.err != nil {
			t.Fatalf("verified staging refused: %v\n%s", result.err, result.output)
		}
		stagingRequireOutputs(t, result, true, false)
		mustNotContain(t, result.calls, "--method PATCH")
		if result.tagCreateInput != "" {
			t.Fatal("staging must not create a publication tag")
		}
	})
	for _, defect := range []string{"half pair", "signature rejected", "provenance rejected", "corrupt uploaded bytes", "snapshot changed"} {
		t.Run(defect, func(t *testing.T) {
			assets := defaultRemoteLaneAssets()
			options := releaseGateOptions{}
			switch defect {
			case "half pair":
				assets = assets[:1]
			case "signature rejected":
				assets, options.cosignFailure = nil, "Picocrypt-NG"
			case "provenance rejected":
				assets, options.attestationFailure = nil, "Picocrypt-NG"
			case "corrupt uploaded bytes":
				assets, options.corruptUploadDownload = nil, true
			case "snapshot changed":
				options.assetsAfterVerify = append([]releaseAssetFixture(nil), assets...)
				options.assetsAfterVerify[0].ID = 99999
			}
			result := runReleaseGateWithOptions(t, "upload", stagingDraftRelease(), assets, options)
			if result.err == nil {
				t.Fatalf("unsafe %s was marked staged:\n%s", defect, result.output)
			}
			stagingRequireOutputs(t, result, false, false)
			mustNotContain(t, result.calls, "--method PATCH")
			mustNotContain(t, result.calls, "--method DELETE")
		})
	}
}

func TestStagingActionPreservesDefaultFinalizeAndExposesVerifiedOutputs(t *testing.T) {
	var action struct {
		Inputs map[string]struct {
			Default  string `yaml:"default"`
			Required bool   `yaml:"required"`
		} `yaml:"inputs"`
		Outputs map[string]struct {
			Value string `yaml:"value"`
		} `yaml:"outputs"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, releaseGateActionPath)), &action); err != nil {
		t.Fatal(err)
	}
	if input, exists := action.Inputs["finalize"]; !exists || input.Default != "true" || input.Required {
		t.Fatal("finalize must default to true so direct owners retain their existing publication behavior")
	}
	for name, want := range map[string]string{
		"staged":    "${{ steps.stage.outputs.staged || 'false' }}",
		"published": "${{ steps.publish.outputs.published || 'false' }}",
	} {
		if action.Outputs[name].Value != want {
			t.Fatalf("action %s output must report only the corresponding verified step: %q", name, action.Outputs[name].Value)
		}
	}
	steps := mustReadCompositeActionDoc(t, releaseGateActionPath).Runs.Steps
	if len(steps) != 3 || steps[0].If != "" || steps[1].ID != "stage" || steps[1].If != "" || steps[2].ID != "publish" || steps[2].If != "${{ inputs.finalize == 'true' }}" {
		t.Fatalf("stage-only selection must suppress only final publication while preserving the legacy three steps: %#v", steps)
	}
}

type stagingInspectionAsset struct {
	ID     int64  `json:"id"`
	Digest string `json:"digest"`
}

type stagingInspectionReport struct {
	Repository      string `json:"repository"`
	Version         string `json:"version"`
	SourceSHA       string `json:"source_sha"`
	CanonicalDigest string `json:"canonical_manifest_sha256"`
	OwnerWorkflow   string `json:"owner_workflow"`
	Status          string `json:"status"`
	VerifiedPairs   []struct {
		Name    string                 `json:"name"`
		Primary stagingInspectionAsset `json:"primary"`
		Bundle  stagingInspectionAsset `json:"bundle"`
	} `json:"verified_pairs"`
	MissingNames []string `json:"missing_names"`
}

func stagingDraftRelease() []releaseGateFixture {
	return []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}
}

func stagingOwnerAssets(owner string) []releaseAssetFixture {
	names := make(map[string]bool)
	for _, primary := range releasePrimaryAssets("2.19") {
		if primary.Workflow == owner {
			names[primary.Name], names[primary.Name+".sigstore.json"] = true, true
		}
	}
	var assets []releaseAssetFixture
	for _, asset := range completeReleaseAssets("2.19") {
		if names[asset.Name] {
			assets = append(assets, asset)
		}
	}
	return assets
}

func stagingRequireInspection(t *testing.T, result releaseGateResult, owner, status string, verified int, assets []releaseAssetFixture) {
	t.Helper()
	var report stagingInspectionReport
	if err := json.Unmarshal([]byte(result.stdout), &report); err != nil {
		t.Fatalf("inspect-owner stdout must be one JSON report, with diagnostics only on stderr: %v\n%s", err, result.stdout)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(result.stdout), &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"repository", "version", "source_sha", "canonical_manifest_sha256", "owner_workflow", "status", "verified_pairs", "missing_names"} {
		if _, exists := fields[name]; !exists {
			t.Fatalf("inspection omitted %s", name)
		}
	}
	for _, name := range []string{"verified_pairs", "missing_names"} {
		if !strings.HasPrefix(strings.TrimSpace(string(fields[name])), "[") {
			t.Fatalf("inspection %s must be a JSON array", name)
		}
	}
	canonical, err := exec.Command("bash", filepath.Join(repoRoot(t), releaseManifestScriptPath), "2.19").Output()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	if report.Repository != "Picocrypt-NG/Picocrypt-NG" || report.Version != "2.19" || report.SourceSHA != releaseTestSHA || report.CanonicalDigest != wantDigest || report.OwnerWorkflow != owner || report.Status != status {
		t.Fatalf("inspection lost its source/owner/status binding: %s", result.stdout)
	}
	if len(report.VerifiedPairs) != verified {
		t.Fatalf("inspection verified %d pairs, want %d from the full owner set", len(report.VerifiedPairs), verified)
	}
	byName := make(map[string]releaseAssetFixture)
	for _, asset := range assets {
		byName[asset.Name] = asset
	}
	seen := make(map[string]bool)
	for _, pair := range report.VerifiedPairs {
		if seen[pair.Name] || strings.HasSuffix(pair.Name, ".sigstore.json") {
			t.Fatalf("inspection returned an invalid or duplicate primary pair: %#v", pair)
		}
		seen[pair.Name] = true
		primary, primaryExists := byName[pair.Name]
		bundle, bundleExists := byName[pair.Name+".sigstore.json"]
		if !primaryExists || !bundleExists || pair.Primary.ID != primary.ID || pair.Primary.Digest != releaseDigest(primary.Content) || pair.Bundle.ID != bundle.ID || pair.Bundle.Digest != releaseDigest(bundle.Content) {
			t.Fatalf("inspection did not bind both verified remote IDs and computed digests: %#v", pair)
		}
	}
	var missing []string
	for _, primary := range releasePrimaryAssets("2.19") {
		if primary.Workflow == owner && !seen[primary.Name] {
			missing = append(missing, primary.Name)
		}
	}
	slices.Sort(missing)
	slices.Sort(report.MissingNames)
	if !slices.Equal(report.MissingNames, missing) {
		t.Fatalf("inspection must derive missing primary names from the whole owner set: %q, want %q", report.MissingNames, missing)
	}
	if strings.Count(result.calls, "cosign verify-blob ") != verified || strings.Count(result.calls, "attestation verify ") != verified {
		t.Fatalf("inspection must independently verify every reported pair once:\n%s", result.calls)
	}
}

func stagingRequireReadOnly(t *testing.T, result releaseGateResult) {
	t.Helper()
	for _, mutation := range []string{"--method POST", "--method PATCH", "--method DELETE", "https://uploads.github.com/"} {
		mustNotContain(t, result.calls, mutation)
	}
	if result.patchInput != "" || result.tagCreateInput != "" || result.draftCreateInput != "" {
		t.Fatal("read-only gate inspection attempted release or tag mutation")
	}
}

func stagingRequireAllVerifications(t *testing.T, result releaseGateResult) {
	t.Helper()
	if strings.Count(result.calls, "cosign verify-blob ") != 19 || strings.Count(result.calls, "attestation verify ") != 19 {
		t.Fatalf("strict finalize must verify all nineteen artifact/bundle pairs:\n%s", result.calls)
	}
}

func stagingRequireOutputs(t *testing.T, result releaseGateResult, staged, published bool) {
	t.Helper()
	first, last := make(map[string]string), make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(result.outputs), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || (name != "staged" && name != "published") {
			continue
		}
		if value != "true" && value != "false" {
			t.Fatalf("gate output %s is not a boolean: %q", name, value)
		}
		if first[name] == "" {
			first[name] = value
		}
		last[name] = value
	}
	for name, want := range map[string]bool{"staged": staged, "published": published} {
		if first[name] != "false" || last[name] != strconv.FormatBool(want) {
			t.Fatalf("%s must initialize false and become true only on verified success: %q", name, result.outputs)
		}
		if !want {
			for _, line := range strings.Split(result.outputs, "\n") {
				if line == name+"=true" {
					t.Fatalf("failed or unrequested %s was reported true before the gate finished: %q", name, result.outputs)
				}
			}
		}
	}
}
