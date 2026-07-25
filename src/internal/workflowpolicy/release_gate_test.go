//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	releaseGateActionPath = ".github/actions/stage-release/action.yml"
	releaseGateScriptPath = ".github/actions/stage-release/release-gate.sh"
	releaseTestSHA        = "0123456789abcdef0123456789abcdef01234567"
)

type releaseGateFixture struct {
	ID              int64                 `json:"id"`
	TagName         string                `json:"tag_name"`
	TargetCommitish string                `json:"target_commitish"`
	Draft           bool                  `json:"draft"`
	Prerelease      bool                  `json:"prerelease"`
	Assets          []releaseAssetFixture `json:"assets"`
}

type releaseAssetFixture struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Size    int64  `json:"size"`
	Digest  string `json:"digest"`
	Content string `json:"-"`
}

type releaseLocalFixture struct {
	Name    string
	Path    string
	Content string
	Symlink bool
}

type releaseGateOptions struct {
	localAssets             []releaseLocalFixture
	cosignFailure           string
	attestationFailure      string
	tagTarget               string
	tagTargetAfterVerify    string
	tagTargetAfterPublish   string
	tagAbsent               bool
	tagCreateConflictTarget string
	annotatedTag            bool
	tagPrefixNoise          bool
	mainVersion             string
	compareStatus           string
	assetsAfterVerify       []releaseAssetFixture
	publishAfterVerify      bool
	bodyOutsideWorkspace    bool
	symlinkLocalParent      bool
	invalidPatchResponse    bool
}

func TestReleaseWorkflowsStageAssetsBehindOnePublicationGate(t *testing.T) {
	for _, tc := range releaseWorkflowCases() {
		t.Run(tc.name, func(t *testing.T) {
			job := mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job)
			if job.RunsOn != "ubuntu-24.04" {
				t.Fatalf("release gate runner = %q, want the audited ubuntu-24.04 runtime", job.RunsOn)
			}
			step := mustStepNamed(t, job, "Stage release assets")
			if step.ContinueOnError != nil && step.ContinueOnError != false {
				t.Fatalf("stage release continue-on-error = %#v, want fail-loud default", step.ContinueOnError)
			}
			if step.If != "" {
				t.Fatalf("stage release if = %q, want no bypass condition", step.If)
			}
			if step.Uses != "./.github/actions/stage-release" {
				t.Fatalf("stage release action = %q, want local fail-closed publisher", step.Uses)
			}
			if got := step.With["version"]; got != "${{ env.VERSION }}" {
				t.Fatalf("stage release version = %#v, want exact VERSION environment value", got)
			}
			if got := step.With["body_path"]; got != "${{ github.workspace }}/release-body.md" {
				t.Fatalf("stage release body_path = %#v, want deterministic generated release body", got)
			}
			if files, ok := step.With["files"].(string); !ok || strings.TrimSpace(files) == "" {
				t.Fatalf("stage release files = %#v, want non-empty lane artifact list", step.With["files"])
			}
			if got := job.Concurrency.Group; got != "${{ github.repository }}-release-publication" {
				t.Fatalf("release concurrency group = %q, want one repository-wide publication lock", got)
			}
			if got := job.Concurrency.Queue; got != "max" {
				t.Fatalf("release concurrency queue = %q, want max so no platform lane is displaced", got)
			}
			if job.Concurrency.CancelInProgress != nil {
				t.Fatalf("release concurrency must omit cancel-in-progress when queue=max, got %#v", job.Concurrency.CancelInProgress)
			}
			for _, workflowStep := range job.Steps {
				if strings.HasPrefix(workflowStep.Uses, "softprops/action-gh-release@") {
					t.Fatal("release workflow bypasses the shared draft publication gate")
				}
			}
		})
	}
}

func TestReleaseWorkflowFileSetsAreDisjointExactManifest(t *testing.T) {
	version := strings.TrimSpace(mustReadRepoFile(t, "VERSION"))
	if version == "" {
		t.Fatal("root VERSION is empty")
	}
	expectedByWorkflow := make(map[string]map[string]struct{})
	for _, primary := range releasePrimaryAssets("${{ env.VERSION }}") {
		workflowPath := ".github/workflows/" + primary.Workflow
		if expectedByWorkflow[workflowPath] == nil {
			expectedByWorkflow[workflowPath] = make(map[string]struct{})
		}
		expectedByWorkflow[workflowPath][primary.Path] = struct{}{}
		expectedByWorkflow[workflowPath][primary.Path+".sigstore.json"] = struct{}{}
	}

	seen := make(map[string]string)
	for _, tc := range releaseWorkflowCases() {
		job := mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job)
		step := mustStepNamed(t, job, "Stage release assets")
		files, ok := step.With["files"].(string)
		if !ok {
			t.Fatalf("%s stage release files = %#v, want newline-delimited exact paths", tc.path, step.With["files"])
		}
		actual := make(map[string]struct{})
		for _, line := range strings.Split(files, "\n") {
			path := strings.TrimSpace(line)
			if path == "" {
				continue
			}
			if _, duplicate := actual[path]; duplicate {
				t.Fatalf("%s stages duplicate path %q", tc.path, path)
			}
			actual[path] = struct{}{}
			name := filepath.Base(strings.ReplaceAll(path, "${{ env.VERSION }}", version))
			if previous, exists := seen[name]; exists {
				t.Fatalf("release asset %q is owned by both %s and %s", name, previous, tc.path)
			}
			seen[name] = tc.path
		}
		expected := expectedByWorkflow[tc.path]
		for path := range actual {
			if _, ok := expected[path]; !ok {
				t.Fatalf("%s stages unexpected or non-canonical path %q", tc.path, path)
			}
			delete(expected, path)
		}
		if len(expected) != 0 {
			missing := make([]string, 0, len(expected))
			for path := range expected {
				missing = append(missing, path)
			}
			t.Fatalf("%s is missing exact release paths %v", tc.path, missing)
		}
	}

	expected := make(map[string]struct{}, 34)
	for _, name := range releasePrimaryAssetNames(version) {
		expected[name] = struct{}{}
		expected[name+".sigstore.json"] = struct{}{}
	}
	for name, owner := range seen {
		if _, ok := expected[name]; !ok {
			t.Fatalf("%s stages unexpected public asset %q", owner, name)
		}
		delete(expected, name)
	}
	if len(expected) != 0 {
		missing := make([]string, 0, len(expected))
		for name := range expected {
			missing = append(missing, name)
		}
		t.Fatalf("release workflows do not stage the complete 34-file manifest; missing %v", missing)
	}
}

func TestStageReleaseActionKeepsReleaseDraftUntilExactManifestExists(t *testing.T) {
	action := mustReadCompositeActionDoc(t, releaseGateActionPath)
	if action.Runs.Using != "composite" {
		t.Fatalf("stage-release runs.using = %q, want composite", action.Runs.Using)
	}
	wantSteps := []string{
		"Reject unsafe existing release",
		"Upload assets to draft release",
		"Publish only the complete release",
	}
	if len(action.Runs.Steps) != len(wantSteps) {
		t.Fatalf("stage-release step count = %d, want exactly %d", len(action.Runs.Steps), len(wantSteps))
	}
	for index, want := range wantSteps {
		if got := action.Runs.Steps[index].Name; got != want {
			t.Fatalf("stage-release step %d = %q, want %q", index, got, want)
		}
		if got := action.Runs.Steps[index].ContinueOnError; got != nil && got != false {
			t.Fatalf("stage-release step %q continue-on-error = %#v, want fail-loud default", want, got)
		}
		if got := action.Runs.Steps[index].If; got != "" {
			t.Fatalf("stage-release step %q if = %q, want no bypass condition", want, got)
		}
	}

	preflight := mustCompositeStepNamed(t, action, "Reject unsafe existing release")
	if preflight.Run != `bash "$GITHUB_ACTION_PATH/release-gate.sh" preflight "$VERSION"` {
		t.Fatalf("release preflight command = %q, want exact fail-closed gate", preflight.Run)
	}
	if got := preflight.Env["FILES"]; got != "${{ inputs.files }}" {
		t.Fatalf("release preflight FILES = %q, want the exact lane upload set", got)
	}
	stage := mustCompositeStepNamed(t, action, "Upload assets to draft release")
	if stage.Uses != "softprops/action-gh-release@3d0d9888cb7fd7b750713d6e236d1fcb99157228" {
		t.Fatalf("draft release action = %q, want reviewed v3.0.2 commit", stage.Uses)
	}
	for key, want := range map[string]any{
		"body_path":               "${{ inputs.body_path }}",
		"files":                   "${{ inputs.files }}",
		"tag_name":                "${{ inputs.version }}",
		"draft":                   true,
		"make_latest":             false,
		"overwrite_files":         false,
		"fail_on_unmatched_files": true,
		"target_commitish":        "${{ github.sha }}",
	} {
		got := stage.With[key]
		wantBool, isBool := want.(bool)
		if isBool && (got == wantBool || got == strconv.FormatBool(wantBool)) {
			continue
		}
		if !isBool && got == want {
			continue
		}
		{
			t.Fatalf("draft release %s = %#v, want %#v", key, got, want)
		}
	}
	publish := mustCompositeStepNamed(t, action, "Publish only the complete release")
	if publish.Run != `bash "$GITHUB_ACTION_PATH/release-gate.sh" publish "$VERSION"` {
		t.Fatalf("release publication command = %q, want exact manifest gate", publish.Run)
	}
	if got := publish.Env["BODY_PATH"]; got != "${{ inputs.body_path }}" {
		t.Fatalf("release publication BODY_PATH = %q, want deterministic generated release body", got)
	}
}

func TestReleaseGateRuntimeManifestMatchesWorkflowPolicy(t *testing.T) {
	script := mustReadRepoFile(t, releaseGateScriptPath)
	for _, primary := range releasePrimaryAssets("${version}") {
		want := primary.Name + " " + primary.Workflow + " " + primary.Path
		mustContain(t, script, want)
	}
}

func TestReleaseGatePreflightRejectsPublishedOrMismatchedRelease(t *testing.T) {
	t.Run("no existing release", func(t *testing.T) {
		result := runReleaseGate(t, "preflight", []releaseGateFixture{}, nil)
		if result.err != nil {
			t.Fatalf("preflight without an existing release failed: %v\n%s", result.err, result.output)
		}
		if strings.Contains(result.calls, "--method PATCH") {
			t.Fatal("preflight must never publish")
		}
	})

	t.Run("already published", func(t *testing.T) {
		result := runReleaseGate(t, "preflight", []releaseGateFixture{{
			ID:              42,
			TagName:         "2.19",
			TargetCommitish: releaseTestSHA,
			Draft:           false,
		}}, nil)
		if result.err == nil {
			t.Fatal("preflight accepted an already-published release")
		}
		mustContain(t, result.output, "already published")
	})

	t.Run("wrong target commit", func(t *testing.T) {
		result := runReleaseGate(t, "preflight", []releaseGateFixture{{
			ID:              42,
			TagName:         "2.19",
			TargetCommitish: "fedcba9876543210fedcba9876543210fedcba98",
			Draft:           true,
		}}, nil)
		if result.err == nil {
			t.Fatal("preflight accepted a draft from a different source commit")
		}
		mustContain(t, result.output, "targets")
	})

	t.Run("verified staged lane pair is safely reused", func(t *testing.T) {
		assets := []releaseAssetFixture{
			newReleaseAsset(100, "Picocrypt-NG", "prior nondeterministic build from the same source\n"),
			newReleaseAsset(101, "Picocrypt-NG.sigstore.json", "its valid Sigstore bundle\n"),
		}
		result := runReleaseGate(t, "preflight", []releaseGateFixture{{
			ID:              42,
			TagName:         "2.19",
			TargetCommitish: releaseTestSHA,
			Draft:           true,
		}}, assets)
		if result.err != nil {
			t.Fatalf("preflight rejected a strictly verified staged pair: %v\n%s", result.err, result.output)
		}
		mustContain(t, result.calls, "cosign verify-blob")
		mustContain(t, result.calls, "attestation verify")
	})

	t.Run("corrupt staged lane asset", func(t *testing.T) {
		assets := defaultRemoteLaneAssets()
		assets[0].Content = strings.Repeat("x", int(assets[0].Size))
		result := runReleaseGate(t, "preflight", []releaseGateFixture{{
			ID:              42,
			TagName:         "2.19",
			TargetCommitish: releaseTestSHA,
			Draft:           true,
		}}, assets)
		if result.err == nil {
			t.Fatal("preflight accepted a remote asset whose bytes do not match its API digest")
		}
		mustContain(t, result.output, assets[0].Name)
		mustContain(t, result.output, "download digest")
	})

	t.Run("incomplete staged pair", func(t *testing.T) {
		assets := defaultRemoteLaneAssets()[:1]
		result := runReleaseGate(t, "preflight", []releaseGateFixture{{
			ID:              42,
			TagName:         "2.19",
			TargetCommitish: releaseTestSHA,
			Draft:           true,
		}}, assets)
		if result.err == nil {
			t.Fatal("preflight accepted an existing primary artifact without its Sigstore bundle")
		}
		mustContain(t, result.output, "incomplete staged pair")
	})

	t.Run("wrong existing tag", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"preflight",
			[]releaseGateFixture{{
				ID:              42,
				TagName:         "2.19",
				TargetCommitish: releaseTestSHA,
				Draft:           true,
			}},
			nil,
			releaseGateOptions{
				tagTarget: "fedcba9876543210fedcba9876543210fedcba98",
			},
		)
		if result.err == nil {
			t.Fatal("preflight accepted a release tag that points to a different commit")
		}
		mustContain(t, result.output, "tag 2.19")
		mustContain(t, result.output, "expected "+releaseTestSHA)
	})

	t.Run("annotated exact tag ignores prefix matches", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"preflight",
			[]releaseGateFixture{{
				ID:              42,
				TagName:         "2.19",
				TargetCommitish: releaseTestSHA,
				Draft:           true,
			}},
			nil,
			releaseGateOptions{
				annotatedTag:   true,
				tagPrefixNoise: true,
			},
		)
		if result.err != nil {
			t.Fatalf("preflight rejected an exact annotated tag because of a prefix match: %v\n%s", result.err, result.output)
		}
		mustContain(
			t,
			result.calls,
			"api repos/Picocrypt-NG/Picocrypt-NG/git/tags/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		)
	})

	t.Run("unexpected local file", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"preflight",
			nil,
			nil,
			releaseGateOptions{localAssets: []releaseLocalFixture{{
				Name:    "debug-secrets.txt",
				Content: "must never become a public release asset",
			}}},
		)
		if result.err == nil {
			t.Fatal("preflight accepted a local file outside the public release manifest")
		}
		mustContain(t, result.output, "debug-secrets.txt")
		mustContain(t, result.output, "not in the public release manifest")
	})

	t.Run("path owned by another workflow", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"preflight",
			nil,
			nil,
			releaseGateOptions{localAssets: []releaseLocalFixture{
				{
					Name:    "Picocrypt-NG-Setup.exe",
					Path:    "artifacts/build-windows/Picocrypt-NG-Setup.exe",
					Content: "signed Windows installer",
				},
				{
					Name:    "Picocrypt-NG-Setup.exe.sigstore.json",
					Path:    "artifacts/build-windows/Picocrypt-NG-Setup.exe.sigstore.json",
					Content: "Windows installer Sigstore bundle",
				},
			}},
		)
		if result.err == nil {
			t.Fatal("Linux workflow preflight accepted exact paths owned by the Windows workflow")
		}
		mustContain(t, result.output, "does not own local path")
	})

	t.Run("symlink to confidential file", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"preflight",
			nil,
			nil,
			releaseGateOptions{localAssets: []releaseLocalFixture{
				{
					Name:    "Picocrypt-NG",
					Path:    "artifacts/build-linux-amd64/Picocrypt-NG",
					Content: "confidential runner file",
					Symlink: true,
				},
				{
					Name:    "Picocrypt-NG.sigstore.json",
					Path:    "artifacts/build-linux-amd64/Picocrypt-NG.sigstore.json",
					Content: "bundle",
				},
			}},
		)
		if result.err == nil {
			t.Fatal("preflight accepted a symlink to a confidential runner file")
		}
		mustContain(t, result.output, "regular non-symlink file")
	})

	t.Run("symlinked parent outside workspace", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"preflight",
			nil,
			nil,
			releaseGateOptions{symlinkLocalParent: true},
		)
		if result.err == nil {
			t.Fatal("preflight accepted an allowed path through a symlinked parent outside the workspace")
		}
		mustContain(t, result.output, "resolves outside the GitHub workspace")
	})
}

func TestReleaseGatePublishesOnlyExactUploadedNonEmptyManifest(t *testing.T) {
	release := []releaseGateFixture{{
		ID:              42,
		TagName:         "2.19",
		TargetCommitish: releaseTestSHA,
		Draft:           true,
	}}

	t.Run("complete", func(t *testing.T) {
		result := runReleaseGate(t, "publish", release, completeReleaseAssets("2.19"))
		if result.err != nil {
			t.Fatalf("complete release was not published: %v\n%s", result.err, result.output)
		}
		if got := strings.Count(result.calls, "cosign verify-blob "); got != 17 {
			t.Fatalf("cosign verification count = %d, want all 17 primary artifacts", got)
		}
		if got := strings.Count(result.calls, "attestation verify "); got != 17 {
			t.Fatalf("provenance verification count = %d, want all 17 primary artifacts", got)
		}
		for _, primary := range releasePrimaryAssets("2.19") {
			identity := "https://github.com/Picocrypt-NG/Picocrypt-NG/.github/workflows/" +
				primary.Workflow + "@refs/heads/main"
			mustContainCallLine(
				t,
				result.calls,
				"cosign verify-blob ",
				"/"+primary.Name+" ",
				"--certificate-identity "+identity,
				"--certificate-github-workflow-sha "+releaseTestSHA,
			)
			mustContainCallLine(
				t,
				result.calls,
				"attestation verify ",
				"/"+primary.Name+" ",
				"--cert-identity "+identity,
				"--signer-digest "+releaseTestSHA,
				"--source-digest "+releaseTestSHA,
			)
		}
		mustContain(t, result.calls, "--cert-oidc-issuer https://token.actions.githubusercontent.com")
		mustContain(t, result.calls, "--certificate-github-workflow-sha "+releaseTestSHA)
		mustContain(t, result.calls, "--certificate-github-workflow-ref refs/heads/main")
		mustContain(t, result.calls, "--certificate-github-workflow-repository Picocrypt-NG/Picocrypt-NG")
		mustContain(t, result.calls, "--signer-digest "+releaseTestSHA)
		mustContain(t, result.calls, "--source-ref refs/heads/main")
		mustContain(t, result.calls, "--source-digest "+releaseTestSHA)
		mustContain(t, result.calls, "--deny-self-hosted-runners")
		mustContain(t, result.calls, "api --method PATCH repos/Picocrypt-NG/Picocrypt-NG/releases/42 --input ")
		var patch map[string]any
		if err := json.Unmarshal([]byte(result.patchInput), &patch); err != nil {
			t.Fatalf("decode final release PATCH: %v\n%s", err, result.patchInput)
		}
		if patch["draft"] != false || patch["make_latest"] != "true" {
			t.Fatalf("final release PATCH = %#v, want draft=false and make_latest=true", patch)
		}
		if patch["body"] != "# Picocrypt-NG 2.19\n\nVerified release notes.\n" {
			t.Fatalf("final release body = %#v, want exact deterministic body", patch["body"])
		}
		if len(patch) != 3 {
			t.Fatalf("final release PATCH contains unexpected fields: %#v", patch)
		}
		lastAssets := strings.LastIndex(
			result.calls,
			"api --paginate repos/Picocrypt-NG/Picocrypt-NG/releases/42/assets?per_page=100",
		)
		mainVersion := strings.LastIndex(
			result.calls,
			"api -H Accept: application/vnd.github.raw+json repos/Picocrypt-NG/Picocrypt-NG/contents/VERSION?ref=main",
		)
		publish := strings.LastIndex(
			result.calls,
			"api --method PATCH repos/Picocrypt-NG/Picocrypt-NG/releases/42",
		)
		if lastAssets < 0 || mainVersion <= lastAssets || publish <= mainVersion {
			t.Fatalf(
				"release state must be revalidated before the final main/VERSION check and PATCH:\n%s",
				result.calls,
			)
		}
	})

	t.Run("absent tag is atomically bound to the source commit", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{tagAbsent: true},
		)
		if result.err != nil {
			t.Fatalf("complete release with an absent tag was not published: %v\n%s", result.err, result.output)
		}
		var create map[string]any
		if err := json.Unmarshal([]byte(result.tagCreateInput), &create); err != nil {
			t.Fatalf("decode tag creation request: %v\n%s", err, result.tagCreateInput)
		}
		if len(create) != 2 ||
			create["ref"] != "refs/tags/2.19" ||
			create["sha"] != releaseTestSHA {
			t.Fatalf("tag creation request = %#v, want exact source-bound ref", create)
		}
		mustContainInOrder(
			t,
			result.calls,
			"api --method POST repos/Picocrypt-NG/Picocrypt-NG/git/refs",
			"api --method PATCH repos/Picocrypt-NG/Picocrypt-NG/releases/42",
		)
	})

	t.Run("conflicting tag creation race fails closed", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{
				tagAbsent:               true,
				tagCreateConflictTarget: "fedcba9876543210fedcba9876543210fedcba98",
			},
		)
		if result.err == nil {
			t.Fatal("publication gate accepted a concurrently created tag on another commit")
		}
		mustContain(t, result.output, "tag 2.19 resolves to")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("missing asset stays draft", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		missing := assets[len(assets)-1].Name
		result := runReleaseGate(t, "publish", release, assets[:len(assets)-1])
		if result.err != nil {
			t.Fatalf("incomplete release should remain draft without failing an early lane: %v\n%s", result.err, result.output)
		}
		mustContain(t, result.output, missing)
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("unexpected asset fails closed", func(t *testing.T) {
		assets := append(
			completeReleaseAssets("2.19"),
			newReleaseAsset(9999, "debug-secrets.txt", "must never become public"),
		)
		result := runReleaseGate(t, "publish", release, assets)
		if result.err == nil {
			t.Fatal("release with an unexpected asset was published")
		}
		mustContain(t, result.output, "debug-secrets.txt")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("empty asset fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		assets[0].Size = 0
		result := runReleaseGate(t, "publish", release, assets)
		if result.err == nil {
			t.Fatal("release with an empty asset was published")
		}
		mustContain(t, result.output, assets[0].Name)
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("non-uploaded asset fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		assets[0].State = "open"
		result := runReleaseGate(t, "publish", release, assets)
		if result.err == nil {
			t.Fatal("release with a non-uploaded asset was published")
		}
		mustContain(t, result.output, assets[0].Name)
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("prerelease state fails closed", func(t *testing.T) {
		prerelease := append([]releaseGateFixture(nil), release...)
		prerelease[0].Prerelease = true
		result := runReleaseGate(t, "publish", prerelease, completeReleaseAssets("2.19"))
		if result.err == nil {
			t.Fatal("publication gate accepted a prerelease")
		}
		mustContain(t, result.output, "invalid prerelease state")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("download digest mismatch fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		assets[0].Content = strings.Repeat("x", int(assets[0].Size))
		result := runReleaseGate(t, "publish", release, assets)
		if result.err == nil {
			t.Fatal("release with remotely substituted bytes was published")
		}
		mustContain(t, result.output, assets[0].Name)
		mustContain(t, result.output, "download digest")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("cosign failure fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			assets,
			releaseGateOptions{cosignFailure: assets[0].Name},
		)
		if result.err == nil {
			t.Fatal("release was published after cosign rejected an artifact")
		}
		mustContain(t, result.calls, "cosign verify-blob")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("provenance failure fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			assets,
			releaseGateOptions{attestationFailure: assets[0].Name},
		)
		if result.err == nil {
			t.Fatal("release was published after provenance verification failed")
		}
		mustContain(t, result.calls, "attestation verify")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("release body outside workspace fails closed", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{bodyOutsideWorkspace: true},
		)
		if result.err == nil {
			t.Fatal("publication gate accepted release notes outside the generated workspace path")
		}
		mustContain(t, result.output, "release body must be")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("asset changed after verification fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		changed := append([]releaseAssetFixture(nil), assets...)
		changed[0].Digest = "sha256:" + strings.Repeat("b", 64)
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			assets,
			releaseGateOptions{assetsAfterVerify: changed},
		)
		if result.err == nil {
			t.Fatal("publication gate accepted an asset snapshot changed after verification")
		}
		mustContain(t, result.output, "release assets changed during verification")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("tag moved after verification fails closed", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{
				tagTargetAfterVerify: "fedcba9876543210fedcba9876543210fedcba98",
			},
		)
		if result.err == nil {
			t.Fatal("publication gate accepted a tag moved after artifact verification")
		}
		mustContain(t, result.output, "tag 2.19 resolves to")
		mustContain(t, result.output, "expected "+releaseTestSHA)
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("tag moved after publication fails loud", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{
				tagTargetAfterPublish: "fedcba9876543210fedcba9876543210fedcba98",
			},
		)
		if result.err == nil {
			t.Fatal("publication gate did not detect a tag moved during publication")
		}
		mustContain(t, result.calls, "--method PATCH")
		mustContain(t, result.output, "tag 2.19 resolves to")
	})

	t.Run("publication during verification fails closed", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{publishAfterVerify: true},
		)
		if result.err == nil {
			t.Fatal("publication gate accepted an externally published release after verification")
		}
		mustContain(t, result.output, "changed or was published during verification")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("concurrent external publication fails closed", func(t *testing.T) {
		published := append([]releaseGateFixture(nil), release...)
		published[0].Draft = false
		result := runReleaseGate(t, "publish", published, completeReleaseAssets("2.19"))
		if result.err == nil {
			t.Fatal("publication gate accepted a release that was already made public")
		}
		mustContain(t, result.output, "already published")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("superseded version fails closed", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{mainVersion: "2.20"},
		)
		if result.err == nil {
			t.Fatal("publication gate made an older version latest after main advanced to 2.20")
		}
		mustContain(t, result.output, "main currently declares version 2.20")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("source removed from main fails closed", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{compareStatus: "diverged"},
		)
		if result.err == nil {
			t.Fatal("publication gate accepted a source commit that is no longer on main")
		}
		mustContain(t, result.output, "is not an ancestor of main")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("unexpected publication response fails loud", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"publish",
			release,
			completeReleaseAssets("2.19"),
			releaseGateOptions{invalidPatchResponse: true},
		)
		if result.err == nil {
			t.Fatal("publication gate accepted a response that still described a draft")
		}
		mustContain(t, result.calls, "--method PATCH")
		mustContain(t, result.output, "unexpected state after publication")
	})
}

type releaseGateResult struct {
	output         string
	calls          string
	patchInput     string
	tagCreateInput string
	err            error
}

func runReleaseGate(
	t *testing.T,
	mode string,
	releases []releaseGateFixture,
	assets []releaseAssetFixture,
) releaseGateResult {
	t.Helper()
	return runReleaseGateWithOptions(t, mode, releases, assets, releaseGateOptions{})
}

func runReleaseGateWithOptions(
	t *testing.T,
	mode string,
	releases []releaseGateFixture,
	assets []releaseAssetFixture,
	options releaseGateOptions,
) releaseGateResult {
	t.Helper()

	root := repoRoot(t)
	script := filepath.Join(root, releaseGateScriptPath)
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("release gate script is missing: %v", err)
	}

	temp := t.TempDir()
	releasesPath := filepath.Join(temp, "releases.json")
	assetsPath := filepath.Join(temp, "assets.json")
	assetsAfterPath := filepath.Join(temp, "assets-after.json")
	tagRefsPath := filepath.Join(temp, "tag-refs.json")
	tagRefsAfterPath := filepath.Join(temp, "tag-refs-after.json")
	tagRefsCreatedPath := filepath.Join(temp, "tag-refs-created.json")
	tagRefsPublishedPath := filepath.Join(temp, "tag-refs-published.json")
	annotatedTagPath := filepath.Join(temp, "annotated-tag.json")
	comparePath := filepath.Join(temp, "compare.json")
	mainVersionPath := filepath.Join(temp, "main-version.txt")
	callsPath := filepath.Join(temp, "gh-calls.txt")
	patchCapturePath := filepath.Join(temp, "patch-input.json")
	tagCreateCapturePath := filepath.Join(temp, "tag-create-input.json")
	writeJSONFixture(t, releasesPath, releases)
	writeJSONFixture(t, assetsPath, assets)
	assetsAfter := options.assetsAfterVerify
	if assetsAfter == nil {
		assetsAfter = assets
	}
	writeJSONFixture(t, assetsAfterPath, assetsAfter)
	releasesAfter := append([]releaseGateFixture(nil), releases...)
	if options.publishAfterVerify && len(releasesAfter) == 1 {
		releasesAfter[0].Draft = false
	}
	releasesAfterPath := filepath.Join(temp, "releases-after.json")
	writeJSONFixture(t, releasesAfterPath, releasesAfter)
	tagTarget := options.tagTarget
	if tagTarget == "" {
		tagTarget = releaseTestSHA
	}
	const annotatedTagSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	makeExactTagRef := func(target string) []map[string]any {
		return []map[string]any{{
			"ref": "refs/tags/2.19",
			"object": map[string]any{
				"type": "commit",
				"sha":  target,
			},
		}}
	}
	makeTagRefs := func(target string, annotated bool) []map[string]any {
		refs := make([]map[string]any, 0, 2)
		if options.tagPrefixNoise {
			refs = append(refs, map[string]any{
				"ref": "refs/tags/2.190",
				"object": map[string]any{
					"type": "commit",
					"sha":  "fedcba9876543210fedcba9876543210fedcba98",
				},
			})
		}
		if options.tagAbsent || len(releases) == 0 {
			return refs
		}
		objectType := "commit"
		objectSHA := target
		if annotated {
			objectType = "tag"
			objectSHA = annotatedTagSHA
		}
		return append(refs, map[string]any{
			"ref": "refs/tags/2.19",
			"object": map[string]any{
				"type": objectType,
				"sha":  objectSHA,
			},
		})
	}
	tagRefs := makeTagRefs(tagTarget, options.annotatedTag)
	writeJSONFixture(t, tagRefsPath, tagRefs)
	tagTargetAfter := options.tagTargetAfterVerify
	if tagTargetAfter == "" {
		tagTargetAfter = tagTarget
	}
	writeJSONFixture(
		t,
		tagRefsAfterPath,
		makeTagRefs(tagTargetAfter, options.annotatedTag && options.tagTargetAfterVerify == ""),
	)
	tagCreatedTarget := releaseTestSHA
	if options.tagCreateConflictTarget != "" {
		tagCreatedTarget = options.tagCreateConflictTarget
	}
	writeJSONFixture(t, tagRefsCreatedPath, makeExactTagRef(tagCreatedTarget))
	tagPublishedTarget := tagTargetAfter
	if options.tagTargetAfterPublish != "" {
		tagPublishedTarget = options.tagTargetAfterPublish
	}
	writeJSONFixture(t, tagRefsPublishedPath, makeExactTagRef(tagPublishedTarget))
	writeJSONFixture(t, annotatedTagPath, map[string]any{
		"object": map[string]any{
			"type": "commit",
			"sha":  tagTarget,
		},
	})
	compareStatus := options.compareStatus
	if compareStatus == "" {
		compareStatus = "identical"
	}
	writeJSONFixture(t, comparePath, map[string]string{"status": compareStatus})
	mainVersion := options.mainVersion
	if mainVersion == "" {
		mainVersion = "2.19"
	}
	if err := os.WriteFile(mainVersionPath, []byte(mainVersion+"\n"), 0o600); err != nil {
		t.Fatalf("write main VERSION fixture: %v", err)
	}

	localAssets := options.localAssets
	if localAssets == nil {
		localAssets = defaultLocalLaneAssets()
	}
	workspace := filepath.Join(temp, "workspace")
	localDir := filepath.Join(workspace, "artifacts")
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		t.Fatalf("create local fixture directory: %v", err)
	}
	if options.symlinkLocalParent {
		outsideParent := filepath.Join(temp, "confidential-build-linux-amd64")
		if err := os.Mkdir(outsideParent, 0o700); err != nil {
			t.Fatalf("create outside local fixture directory: %v", err)
		}
		if err := os.Symlink(outsideParent, filepath.Join(localDir, "build-linux-amd64")); err != nil {
			t.Fatalf("create symlinked local fixture parent: %v", err)
		}
	}
	localPaths := make([]string, 0, len(localAssets))
	for _, asset := range localAssets {
		relativePath := asset.Path
		if relativePath == "" {
			relativePath = filepath.ToSlash(filepath.Join("artifacts", asset.Name))
		}
		path := filepath.Join(workspace, filepath.FromSlash(relativePath))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("create local fixture parent for %s: %v", asset.Name, err)
		}
		if asset.Symlink {
			target := filepath.Join(temp, "confidential-"+strings.ReplaceAll(asset.Name, "/", "-"))
			if err := os.WriteFile(target, []byte(asset.Content), 0o600); err != nil {
				t.Fatalf("write symlink target fixture %s: %v", asset.Name, err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatalf("create local fixture symlink %s: %v", asset.Name, err)
			}
		} else if err := os.WriteFile(path, []byte(asset.Content), 0o600); err != nil {
			t.Fatalf("write local fixture %s: %v", asset.Name, err)
		}
		localPaths = append(localPaths, relativePath)
	}
	bodyPath := filepath.Join(workspace, "release-body.md")
	if err := os.WriteFile(bodyPath, []byte("# Picocrypt-NG 2.19\n\nVerified release notes.\n"), 0o600); err != nil {
		t.Fatalf("write release body fixture: %v", err)
	}
	if options.bodyOutsideWorkspace {
		bodyPath = filepath.Join(temp, "confidential-release-notes.md")
		if err := os.WriteFile(bodyPath, []byte("must not become public\n"), 0o600); err != nil {
			t.Fatalf("write outside release body fixture: %v", err)
		}
	}

	remoteDir := filepath.Join(temp, "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatalf("create remote fixture directory: %v", err)
	}
	for _, asset := range assets {
		if asset.ID <= 0 {
			t.Fatalf("remote fixture %s has invalid id %d", asset.Name, asset.ID)
		}
		path := filepath.Join(remoteDir, strconv.FormatInt(asset.ID, 10))
		if err := os.WriteFile(path, []byte(asset.Content), 0o600); err != nil {
			t.Fatalf("write remote fixture %s: %v", asset.Name, err)
		}
	}

	ghPath := filepath.Join(temp, "gh")
	const fakeGH = `#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1" >> "$GH_CALLS"
shift
printf ' %s' "$@" >> "$GH_CALLS"
printf '\n' >> "$GH_CALLS"
case "$*" in
  "--paginate repos/Picocrypt-NG/Picocrypt-NG/releases?per_page=100")
    if [ -e "$GH_RELEASES_MARKER" ]; then
      cat "$GH_RELEASES_AFTER_JSON"
    else
      : > "$GH_RELEASES_MARKER"
      cat "$GH_RELEASES_JSON"
    fi
    ;;
  "--paginate repos/Picocrypt-NG/Picocrypt-NG/releases/42/assets?per_page=100")
    if [ -e "$GH_ASSETS_MARKER" ]; then
      cat "$GH_ASSETS_AFTER_JSON"
    else
      : > "$GH_ASSETS_MARKER"
      cat "$GH_ASSETS_JSON"
    fi
    ;;
  "repos/Picocrypt-NG/Picocrypt-NG/git/matching-refs/tags/2.19")
    if [ -e "$GH_PUBLISHED_MARKER" ]; then
      cat "$GH_TAG_REFS_PUBLISHED_JSON"
    elif [ -e "$GH_TAG_CREATED_MARKER" ]; then
      cat "$GH_TAG_REFS_CREATED_JSON"
    elif [ -e "$GH_TAG_REFS_MARKER" ]; then
      cat "$GH_TAG_REFS_AFTER_JSON"
    else
      : > "$GH_TAG_REFS_MARKER"
      cat "$GH_TAG_REFS_JSON"
    fi
    ;;
  "--method POST repos/Picocrypt-NG/Picocrypt-NG/git/refs --input "*)
    input_path="${*: -1}"
    cp "$input_path" "$GH_TAG_CREATE_CAPTURE"
    : > "$GH_TAG_CREATED_MARKER"
    if [ -n "$GH_TAG_CREATE_CONFLICT_TARGET" ]; then
      exit 1
    fi
    jq '.[0]' "$GH_TAG_REFS_CREATED_JSON"
    ;;
  "repos/Picocrypt-NG/Picocrypt-NG/git/tags/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    cat "$GH_ANNOTATED_TAG_JSON"
    ;;
  "repos/Picocrypt-NG/Picocrypt-NG/compare/0123456789abcdef0123456789abcdef01234567...main")
    cat "$GH_COMPARE_JSON"
    ;;
  "-H Accept: application/vnd.github.raw+json repos/Picocrypt-NG/Picocrypt-NG/contents/VERSION?ref=main")
    cat "$GH_MAIN_VERSION"
    ;;
  "-H Accept: application/octet-stream repos/Picocrypt-NG/Picocrypt-NG/releases/assets/"*)
    endpoint="${*: -1}"
    asset_id="${endpoint##*/}"
    cat "$GH_REMOTE_ASSETS_DIR/$asset_id"
    ;;
  "verify "*)
    if [ -n "$GH_ATTESTATION_FAILURE" ] && [[ "$*" == *"$GH_ATTESTATION_FAILURE"* ]]; then
      exit 1
    fi
    ;;
  "--method PATCH repos/Picocrypt-NG/Picocrypt-NG/releases/42 --input "*)
    input_path="${*: -1}"
    cp "$input_path" "$GH_PATCH_CAPTURE"
    : > "$GH_PUBLISHED_MARKER"
    if [ "$GH_INVALID_PATCH_RESPONSE" = "true" ]; then
      printf '%s\n' '{"id":42,"tag_name":"2.19","target_commitish":"0123456789abcdef0123456789abcdef01234567","draft":true,"prerelease":false}'
    else
      jq -c \
        --arg default_tag "2.19" \
        --arg default_target "0123456789abcdef0123456789abcdef01234567" \
        '. as $patch
         | $patch + {
             id: 42,
             tag_name: ($patch.tag_name // $default_tag),
             target_commitish: ($patch.target_commitish // $default_target),
             draft: (if ($patch | has("draft")) then $patch.draft else true end),
             prerelease: ($patch.prerelease // false)
           }' \
        "$input_path"
    fi
    ;;
  *)
    echo "unexpected gh invocation: gh $*" >&2
    exit 64
    ;;
esac
`
	if err := os.WriteFile(ghPath, []byte(fakeGH), 0o700); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}

	cosignPath := filepath.Join(temp, "cosign")
	const fakeCosign = `#!/usr/bin/env bash
set -euo pipefail
printf 'cosign' >> "$GH_CALLS"
printf ' %s' "$@" >> "$GH_CALLS"
printf '\n' >> "$GH_CALLS"
if [ "$1" != "verify-blob" ]; then
  echo "unexpected cosign invocation: cosign $*" >&2
  exit 64
fi
if [ -n "$COSIGN_FAILURE" ] && [[ "$*" == *"$COSIGN_FAILURE"* ]]; then
  exit 1
fi
`
	if err := os.WriteFile(cosignPath, []byte(fakeCosign), 0o700); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}

	command := exec.Command("bash", script, mode, "2.19")
	command.Dir = workspace
	command.Env = append(os.Environ(),
		"PATH="+temp+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FILES="+strings.Join(localPaths, "\n"),
		"BODY_PATH="+bodyPath,
		"GH_CALLS="+callsPath,
		"GH_RELEASES_JSON="+releasesPath,
		"GH_RELEASES_AFTER_JSON="+releasesAfterPath,
		"GH_RELEASES_MARKER="+filepath.Join(temp, "release-call.marker"),
		"GH_ASSETS_JSON="+assetsPath,
		"GH_ASSETS_AFTER_JSON="+assetsAfterPath,
		"GH_ASSETS_MARKER="+filepath.Join(temp, "assets-call.marker"),
		"GH_TAG_REFS_JSON="+tagRefsPath,
		"GH_TAG_REFS_AFTER_JSON="+tagRefsAfterPath,
		"GH_TAG_REFS_CREATED_JSON="+tagRefsCreatedPath,
		"GH_TAG_REFS_PUBLISHED_JSON="+tagRefsPublishedPath,
		"GH_TAG_REFS_MARKER="+filepath.Join(temp, "tag-refs-call.marker"),
		"GH_TAG_CREATED_MARKER="+filepath.Join(temp, "tag-created.marker"),
		"GH_PUBLISHED_MARKER="+filepath.Join(temp, "published.marker"),
		"GH_TAG_CREATE_CAPTURE="+tagCreateCapturePath,
		"GH_TAG_CREATE_CONFLICT_TARGET="+options.tagCreateConflictTarget,
		"GH_ANNOTATED_TAG_JSON="+annotatedTagPath,
		"GH_COMPARE_JSON="+comparePath,
		"GH_MAIN_VERSION="+mainVersionPath,
		"GH_REMOTE_ASSETS_DIR="+remoteDir,
		"GH_PATCH_CAPTURE="+patchCapturePath,
		"GH_ATTESTATION_FAILURE="+options.attestationFailure,
		"GH_INVALID_PATCH_RESPONSE="+strconv.FormatBool(options.invalidPatchResponse),
		"COSIGN_FAILURE="+options.cosignFailure,
		"GITHUB_WORKSPACE="+workspace,
		"GITHUB_WORKFLOW_REF=Picocrypt-NG/Picocrypt-NG/.github/workflows/build-linux.yml@refs/heads/main",
		"GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG",
		"GITHUB_SHA="+releaseTestSHA,
	)
	output, runErr := command.CombinedOutput()

	return releaseGateResult{
		output:         string(output),
		calls:          readOptionalFile(t, callsPath),
		patchInput:     readOptionalFile(t, patchCapturePath),
		tagCreateInput: readOptionalFile(t, tagCreateCapturePath),
		err:            runErr,
	}
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()

	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func readOptionalFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

type releasePrimaryFixture struct {
	Name     string
	Workflow string
	Path     string
}

func completeReleaseAssets(version string) []releaseAssetFixture {
	primary := releasePrimaryAssets(version)
	assets := make([]releaseAssetFixture, 0, len(primary)*2)
	id := int64(1000)
	for _, artifact := range primary {
		name := artifact.Name
		assets = append(assets,
			newReleaseAsset(id, name, "release artifact: "+name+"\n"),
			newReleaseAsset(id+1, name+".sigstore.json", "Sigstore bundle: "+name+"\n"),
		)
		id += 2
	}
	return assets
}

func releasePrimaryAssetNames(version string) []string {
	primary := releasePrimaryAssets(version)
	names := make([]string, 0, len(primary))
	for _, artifact := range primary {
		names = append(names, artifact.Name)
	}
	return names
}

func releasePrimaryAssets(version string) []releasePrimaryFixture {
	return []releasePrimaryFixture{
		{Name: "Picocrypt-NG-Setup.exe", Workflow: "build-windows.yml", Path: "artifacts/build-windows/Picocrypt-NG-Setup.exe"},
		{Name: "Picocrypt-NG-android-arm64-v8a.apk", Workflow: "build-android.yml", Path: "out/Picocrypt-NG-android-arm64-v8a.apk"},
		{Name: "Picocrypt-NG-android-universal.apk", Workflow: "build-android.yml", Path: "out/Picocrypt-NG-android-universal.apk"},
		{Name: "Picocrypt-NG-android-x86_64.apk", Workflow: "build-android.yml", Path: "out/Picocrypt-NG-android-x86_64.apk"},
		{Name: "Picocrypt-NG-cli-Legacy.exe", Workflow: "build-windows-legacy.yml", Path: "artifacts/build-windows-legacy/Picocrypt-NG-cli-Legacy.exe"},
		{Name: "Picocrypt-NG-cli-arm64", Workflow: "build-linux.yml", Path: "artifacts/build-linux-arm64/Picocrypt-NG-cli-arm64"},
		{Name: "Picocrypt-NG-cli-macos", Workflow: "build-macos.yml", Path: "artifacts/build-macos/Picocrypt-NG-cli-macos"},
		{Name: "Picocrypt-NG-cli", Workflow: "build-linux.yml", Path: "artifacts/build-linux-amd64/Picocrypt-NG-cli"},
		{Name: "Picocrypt-NG-cli.exe", Workflow: "build-windows.yml", Path: "artifacts/build-windows/Picocrypt-NG-cli.exe"},
		{Name: "Picocrypt-NG-" + version + "-x86_64.AppImage", Workflow: "build-appimage.yml", Path: "artifacts/Picocrypt-NG-" + version + "-x86_64.AppImage"},
		{Name: "Picocrypt-NG-" + version + "-x86_64.AppImage.zsync", Workflow: "build-appimage.yml", Path: "artifacts/Picocrypt-NG-" + version + "-x86_64.AppImage.zsync"},
		{Name: "Picocrypt-NG-arm64", Workflow: "build-linux.yml", Path: "artifacts/build-linux-arm64/Picocrypt-NG-arm64"},
		{Name: "Picocrypt-NG-portable.exe", Workflow: "build-windows.yml", Path: "artifacts/build-windows/Picocrypt-NG-portable.exe"},
		{Name: "Picocrypt-NG.deb", Workflow: "build-linux.yml", Path: "artifacts/build-linux-amd64/Picocrypt-NG.deb"},
		{Name: "Picocrypt-NG.dmg", Workflow: "build-macos.yml", Path: "artifacts/build-macos/Picocrypt-NG.dmg"},
		{Name: "Picocrypt-NG", Workflow: "build-linux.yml", Path: "artifacts/build-linux-amd64/Picocrypt-NG"},
		{Name: "picocrypt-ng_" + version + "_amd64.snap", Workflow: "build-snapcraft.yml", Path: "out/picocrypt-ng_" + version + "_amd64.snap"},
	}
}

func defaultLocalLaneAssets() []releaseLocalFixture {
	return []releaseLocalFixture{
		{
			Name:    "Picocrypt-NG",
			Path:    "artifacts/build-linux-amd64/Picocrypt-NG",
			Content: "current Linux artifact\n",
		},
		{
			Name:    "Picocrypt-NG.sigstore.json",
			Path:    "artifacts/build-linux-amd64/Picocrypt-NG.sigstore.json",
			Content: "current Linux Sigstore bundle\n",
		},
	}
}

func defaultRemoteLaneAssets() []releaseAssetFixture {
	local := defaultLocalLaneAssets()
	return []releaseAssetFixture{
		newReleaseAsset(100, local[0].Name, local[0].Content),
		newReleaseAsset(101, local[1].Name, local[1].Content),
	}
}

func newReleaseAsset(id int64, name, content string) releaseAssetFixture {
	return releaseAssetFixture{
		ID:      id,
		Name:    name,
		State:   "uploaded",
		Size:    int64(len(content)),
		Digest:  releaseDigest(content),
		Content: content,
	}
}

func releaseDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf("sha256:%x", sum)
}

func mustContainCallLine(t *testing.T, calls string, fragments ...string) {
	t.Helper()
	for _, line := range strings.Split(calls, "\n") {
		matches := true
		for _, fragment := range fragments {
			if !strings.Contains(line, fragment) {
				matches = false
				break
			}
		}
		if matches {
			return
		}
	}
	t.Fatalf("no invocation line contains all fragments %q", fragments)
}
