//go:build linux

package workflowpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	releaseGateActionPath     = ".github/actions/stage-release/action.yml"
	releaseGateScriptPath     = ".github/actions/stage-release/release-gate.sh"
	releaseManifestScriptPath = ".github/actions/stage-release/release-manifest.sh"
	releaseBodyScriptPath     = ".github/actions/release-body/gen-release-body.sh"
	releaseTestSHA            = "0123456789abcdef0123456789abcdef01234567"
)

type releaseGateFixture struct {
	ID              int64                 `json:"id"`
	TagName         string                `json:"tag_name"`
	TargetCommitish string                `json:"target_commitish"`
	Draft           bool                  `json:"draft"`
	Prerelease      bool                  `json:"prerelease"`
	Body            string                `json:"body"`
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
	workflow                string
	releaseScope            string
	windowsAfterCore        bool
	coreReleaseID           string
	coreDigest              string
	ownerWorkflow           string
	candidateDigest         string
	approvedReleaseID       string
	withoutApproval         bool
	driverSHA               string
	candidateNotInCheckout  bool
	noLocalFiles            bool
	noBody                  bool
	publishedBodyFromSource bool
	publishedBodyOverride   string
	cosignFailure           string
	attestationFailure      string
	attestationCaller       string
	attestationPolicy       string
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
	assetsAfterPublish      []releaseAssetFixture
	publishAfterVerify      bool
	bodyOutsideWorkspace    bool
	symlinkLocalParent      bool
	invalidPatchResponse    bool
	invalidPatchBody        bool
	rootVersion             string
	checkoutHEAD            string
	modifiedBody            bool
	releaseListingFailure   bool
	hideDraftsInList        bool
	draftCreateFailure      bool
	draftCreateResponse     string
	draftReadbackMisses     int
	draftListMisses         int
	draftReadbackStatus     string
	draftReadbackResponse   string
	draftListDuplicate      bool
	uploadFailure           string
	uploadResponse          map[string]any
	releaseIDAfterVerify    int64
	corruptUploadDownload   bool
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
			version := "${{ env.VERSION }}"
			if tc.name == "build-macos" || tc.name == "build-snapcraft" {
				version = "${{ env.SOURCE_VERSION }}"
			}
			if got := step.With["version"]; got != version {
				t.Fatalf("stage release version = %#v, want source-bound %s", got, version)
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
			if tc.name == "build-snapcraft" {
				path = strings.ReplaceAll(path, "${{ env.SOURCE_VERSION }}", "${{ env.VERSION }}")
			}
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

	expected := make(map[string]struct{}, 38)
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
		t.Fatalf("release workflows do not stage the complete 38-file manifest; missing %v", missing)
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
			t.Fatalf("stage-release step %q if = %q, want unconditional staging", want, got)
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
	if stage.Uses != "" || stage.Shell != "bash" || stage.Run != `bash "$GITHUB_ACTION_PATH/release-gate.sh" upload "$VERSION"` {
		t.Fatalf("draft upload must execute the shared Bash gate: %#v", stage)
	}
	for key, want := range map[string]string{
		"GH_TOKEN":  "${{ github.token }}",
		"BODY_PATH": "${{ inputs.body_path }}",
		"FILES":     "${{ inputs.files }}",
		"VERSION":   "${{ inputs.version }}",
	} {
		if got := stage.Env[key]; got != want {
			t.Fatalf("draft upload %s = %q, want %q", key, got, want)
		}
	}
}

func TestReleaseGateRuntimeManifestMatchesWorkflowPolicy(t *testing.T) {
	for _, version := range []string{"2.19", "3.0"} {
		t.Run(version, func(t *testing.T) {
			command := exec.Command("bash", filepath.Join(repoRoot(t), releaseManifestScriptPath), version)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("generate runtime release manifest: %v\n%s", err, output)
			}
			expected := make(map[string]releasePrimaryFixture)
			for _, primary := range releasePrimaryAssets(version) {
				expected[primary.Name] = primary
			}
			seen := make(map[string]bool)
			for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 3 {
					t.Fatalf("invalid release manifest row %q", line)
				}
				if seen[fields[0]] {
					t.Fatalf("duplicate runtime release asset %q", fields[0])
				}
				seen[fields[0]] = true
				actual := releasePrimaryFixture{Name: fields[0], Workflow: fields[1], Path: fields[2]}
				if want, exists := expected[actual.Name]; !exists || actual != want {
					t.Fatalf("runtime release mapping = %#v, want independent frozen mapping %#v", actual, want)
				}
				delete(expected, actual.Name)
			}
			if len(expected) != 0 {
				t.Fatalf("runtime manifest omitted release artifacts: %#v", expected)
			}
		})
	}
}

func TestReleaseGateRejectsMismatchedSourceBeforeGitHubAPI(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		options releaseGateOptions
		message string
	}{
		{"preflight root VERSION", "preflight", releaseGateOptions{rootVersion: "2.18"}, "root VERSION"},
		{"publish root VERSION", "strict-finalize", releaseGateOptions{rootVersion: "2.18"}, "root VERSION"},
		{"preflight checkout HEAD", "preflight", releaseGateOptions{checkoutHEAD: "fedcba9876543210fedcba9876543210fedcba98"}, "checkout commit"},
		{"publish checkout HEAD", "strict-finalize", releaseGateOptions{checkoutHEAD: "fedcba9876543210fedcba9876543210fedcba98"}, "checkout commit"},
		{"modified release verification notes", "upload", releaseGateOptions{modifiedBody: true}, "source-bound deterministic release notes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, tc.mode, nil, nil, tc.options)
			if result.err == nil {
				t.Fatal("release gate accepted mismatched source or modified verification instructions")
			}
			mustContain(t, result.output, tc.message)
			if result.calls != "" {
				t.Fatalf("source mismatch must fail before any GitHub API/signature invocation, got:\n%s", result.calls)
			}
		})
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
		result := runReleaseGate(t, "strict-finalize", release, completeReleaseAssets("2.19"))
		if result.err != nil {
			t.Fatalf("complete release was not published: %v\n%s", result.err, result.output)
		}
		if got := strings.Count(result.calls, "cosign verify-blob "); got != 19 {
			t.Fatalf("cosign verification count = %d, want all 19 primary artifacts", got)
		}
		if got := strings.Count(result.calls, "attestation verify "); got != 19 {
			t.Fatalf("provenance verification count = %d, want all 19 primary artifacts", got)
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
		if patch["body"] != result.expectedBody {
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
		if mainVersion < 0 || publish <= mainVersion || lastAssets <= publish {
			t.Fatalf(
				"publication requires the current main version before PATCH and asset readback afterwards:\n%s",
				result.calls,
			)
		}
	})

	t.Run("absent tag is atomically bound to the source commit", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"strict-finalize",
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
			"strict-finalize",
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
		result := runReleaseGate(t, "strict-finalize", release, assets[:len(assets)-1])
		if result.err == nil {
			t.Fatal("publication accepted an incomplete draft")
		}
		mustContain(t, result.output, missing)
		stagingRequireReadOnly(t, result)
	})

	t.Run("unexpected asset fails closed", func(t *testing.T) {
		assets := append(
			completeReleaseAssets("2.19"),
			newReleaseAsset(9999, "debug-secrets.txt", "must never become public"),
		)
		result := runReleaseGate(t, "strict-finalize", release, assets)
		if result.err == nil {
			t.Fatal("release with an unexpected asset was published")
		}
		mustContain(t, result.output, "debug-secrets.txt")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("empty asset fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		assets[0].Size = 0
		result := runReleaseGate(t, "strict-finalize", release, assets)
		if result.err == nil {
			t.Fatal("release with an empty asset was published")
		}
		mustContain(t, result.output, assets[0].Name)
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("non-uploaded asset fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		assets[0].State = "open"
		result := runReleaseGate(t, "strict-finalize", release, assets)
		if result.err == nil {
			t.Fatal("release with a non-uploaded asset was published")
		}
		mustContain(t, result.output, assets[0].Name)
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("prerelease state fails closed", func(t *testing.T) {
		prerelease := append([]releaseGateFixture(nil), release...)
		prerelease[0].Prerelease = true
		result := runReleaseGate(t, "strict-finalize", prerelease, completeReleaseAssets("2.19"))
		if result.err == nil {
			t.Fatal("publication gate accepted a prerelease")
		}
		mustContain(t, result.output, "invalid prerelease state")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("download digest mismatch fails closed", func(t *testing.T) {
		assets := completeReleaseAssets("2.19")
		assets[0].Content = strings.Repeat("x", int(assets[0].Size))
		result := runReleaseGate(t, "strict-finalize", release, assets)
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
			"strict-finalize",
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
			"strict-finalize",
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
			"upload",
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
			"strict-finalize",
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
			"strict-finalize",
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
			"strict-finalize",
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
			"strict-finalize",
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
		result := runReleaseGate(t, "strict-finalize", published, completeReleaseAssets("2.19"))
		if result.err == nil {
			t.Fatal("publication gate accepted a release that was already made public")
		}
		mustContain(t, result.output, "release notes do not match")
		mustNotContain(t, result.calls, "--method PATCH")
	})

	t.Run("superseded version fails closed", func(t *testing.T) {
		result := runReleaseGateWithOptions(
			t,
			"strict-finalize",
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
			"strict-finalize",
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
			"strict-finalize",
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

func TestReleaseGateListingFailureNeverAuthorizesMutation(t *testing.T) {
	for _, mode := range []string{"preflight", "upload", "strict-finalize"} {
		t.Run(mode, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, mode, nil, nil, releaseGateOptions{releaseListingFailure: true})
			if result.err == nil {
				t.Fatal("failed release listing was accepted as absence")
			}
			mustContain(t, result.output, "cannot list releases")
			mustNotContain(t, result.calls, "--method")
		})
	}
}

func TestReleaseGateUploadCreatesCommitBoundDraftAndVerifiesBinaryPair(t *testing.T) {
	local := defaultLocalLaneAssets()
	local[0].Content = "\x00release binary\xff\r\n"
	result := runReleaseGateWithOptions(t, "upload", nil, nil, releaseGateOptions{localAssets: local, tagAbsent: true})
	if result.err != nil {
		t.Fatalf("new draft staging failed: %v\n%s", result.err, result.output)
	}
	var create map[string]any
	if err := json.Unmarshal([]byte(result.draftCreateInput), &create); err != nil {
		t.Fatalf("decode draft creation payload: %v\n%s", err, result.draftCreateInput)
	}
	if len(create) != 7 || create["tag_name"] != "2.19" || create["name"] != "2.19" ||
		create["target_commitish"] != releaseTestSHA || create["draft"] != true ||
		create["prerelease"] != false || create["make_latest"] != "false" || create["body"] != result.expectedBody {
		t.Fatalf("unsafe draft creation payload: %#v", create)
	}
	if len(result.remoteAssets) != 2 {
		t.Fatalf("staged assets = %#v, want exactly the lane's artifact and bundle", result.remoteAssets)
	}
	for index, asset := range result.remoteAssets {
		if asset.Name != local[index].Name || asset.Content != local[index].Content || asset.Digest != releaseDigest(local[index].Content) {
			t.Fatalf("staged remote bytes changed: %#v", asset)
		}
	}
	mustContainCallLine(t, result.calls, "--method POST -H Content-Type: application/octet-stream", "https://uploads.github.com/repos/Picocrypt-NG/Picocrypt-NG/releases/42/assets?name=Picocrypt-NG ", "--input ")
	mustContainCallLine(t, result.calls, "cosign verify-blob", "--certificate-github-workflow-sha "+releaseTestSHA)
	mustContainCallLine(t, result.calls, "attestation verify", "--signer-digest "+releaseTestSHA)
	mustNotContain(t, result.calls, "--method PATCH")
	mustNotContain(t, result.calls, "--method DELETE")
	if result.tagCreateInput != "" {
		t.Fatal("staging created a tag before the complete release was verified")
	}

	repeated := runReleaseGate(t, "upload", []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}, result.remoteAssets)
	if repeated.err != nil {
		t.Fatalf("repeated staging failed: %v\n%s", repeated.err, repeated.output)
	}
	mustNotContain(t, repeated.calls, "--method")
	for index, asset := range repeated.remoteAssets {
		if asset != result.remoteAssets[index] {
			t.Fatalf("repeated staging replaced a verified asset: %#v", asset)
		}
	}
}

func TestReleaseGateUploadRejectsUnsafeStateAndFailedVerification(t *testing.T) {
	release := []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}
	for _, tc := range []struct {
		name    string
		options releaseGateOptions
		assets  []releaseAssetFixture
		message string
	}{
		{"incomplete existing pair", releaseGateOptions{}, defaultRemoteLaneAssets()[:1], "incomplete staged pair"},
		{"bad new signature", releaseGateOptions{cosignFailure: "Picocrypt-NG"}, nil, ""},
		{"bad new provenance", releaseGateOptions{attestationFailure: "Picocrypt-NG"}, nil, ""},
		{"upload failure", releaseGateOptions{uploadFailure: "Picocrypt-NG"}, nil, "upload failed"},
		{"published during verification", releaseGateOptions{publishAfterVerify: true}, defaultRemoteLaneAssets(), "changed or was published"},
		{"release replaced during verification", releaseGateOptions{releaseIDAfterVerify: 43}, defaultRemoteLaneAssets(), "changed or was published"},
		{"modified notes", releaseGateOptions{modifiedBody: true}, nil, "source-bound deterministic release notes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, "upload", release, tc.assets, tc.options)
			if result.err == nil {
				t.Fatalf("unsafe staging succeeded:\n%s", result.output)
			}
			if tc.message != "" {
				mustContain(t, result.output, tc.message)
			}
			mustNotContain(t, result.calls, "--method PATCH")
			mustNotContain(t, result.calls, "--method DELETE")
			if result.tagCreateInput != "" {
				t.Fatal("unsafe staging created a tag")
			}
			if tc.name == "incomplete existing pair" {
				mustNotContain(t, result.calls, "--method POST")
			}
			if tc.name == "bad new signature" {
				mustContain(t, result.calls, "cosign verify-blob")
			}
			if tc.name == "bad new provenance" {
				mustContain(t, result.calls, "attestation verify")
			}
		})
	}
	for _, tc := range []struct {
		name    string
		release releaseGateFixture
	}{
		{"published", releaseGateFixture{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA}},
		{"wrong source", releaseGateFixture{ID: 42, TagName: "2.19", TargetCommitish: strings.Repeat("f", 40), Draft: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runReleaseGate(t, "upload", []releaseGateFixture{tc.release}, nil)
			if result.err == nil {
				t.Fatal("unsafe existing release accepted")
			}
			mustNotContain(t, result.calls, "--method")
		})
	}
}

func TestReleaseGateUploadPreservesMatchingExistingPairAndAddsOnlyMissingPair(t *testing.T) {
	local := append(defaultLocalLaneAssets(),
		releaseLocalFixture{Name: "Picocrypt-NG-cli", Path: "artifacts/build-linux-amd64/Picocrypt-NG-cli", Content: "new CLI binary\n"},
		releaseLocalFixture{Name: "Picocrypt-NG-cli.sigstore.json", Path: "artifacts/build-linux-amd64/Picocrypt-NG-cli.sigstore.json", Content: "CLI bundle\n"},
	)
	assets := []releaseAssetFixture{
		newReleaseAsset(100, "Picocrypt-NG", local[0].Content),
		newReleaseAsset(101, "Picocrypt-NG.sigstore.json", "earlier verified bundle\n"),
	}
	result := runReleaseGateWithOptions(t, "upload", []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}, assets, releaseGateOptions{localAssets: local})
	if result.err != nil {
		t.Fatalf("mixed staged lane failed: %v\n%s", result.err, result.output)
	}
	if len(result.remoteAssets) != 4 || result.remoteAssets[0] != assets[0] || result.remoteAssets[1] != assets[1] {
		t.Fatalf("existing verified pair was replaced: %#v", result.remoteAssets)
	}
	for index := 2; index < 4; index++ {
		if result.remoteAssets[index].Name != local[index].Name || result.remoteAssets[index].Content != local[index].Content {
			t.Fatalf("new CLI pair was not staged exactly: %#v", result.remoteAssets)
		}
	}
	if strings.Count(result.calls, "https://uploads.github.com/") != 2 || strings.Count(result.calls, "cosign verify-blob") != 2 || strings.Count(result.calls, "attestation verify") != 2 {
		t.Fatalf("staging must upload only the missing pair and verify both pairs:\n%s", result.calls)
	}
	mustNotContain(t, result.calls, "--method DELETE")
	mustNotContain(t, result.calls, "--method PATCH")
}

func TestReleaseGateRejectsRebuiltAppImageDuringPartialStaging(t *testing.T) {
	const image = "Picocrypt-NG-2.19-x86_64.AppImage"
	local := []releaseLocalFixture{
		{Name: image, Content: "rebuilt signed AppImage\n"},
		{Name: image + ".sigstore.json", Content: "rebuilt image bundle\n"},
		{Name: image + ".zsync", Content: "index of rebuilt signed AppImage\n"},
		{Name: image + ".zsync.sigstore.json", Content: "rebuilt index bundle\n"},
	}
	assets := []releaseAssetFixture{
		newReleaseAsset(100, image, "original signed AppImage\n"),
		newReleaseAsset(101, image+".sigstore.json", "original image bundle\n"),
	}
	for _, mode := range []string{"preflight", "upload"} {
		t.Run(mode, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, mode, []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}, assets, releaseGateOptions{
				localAssets: local,
				workflow:    "build-appimage.yml",
			})
			if result.err == nil {
				t.Fatal("partial staging mixed an original AppImage with an index from a rebuilt image")
			}
			mustContain(t, result.output, "partially staged lane")
			mustNotContain(t, result.calls, "https://uploads.github.com/")
			if len(result.remoteAssets) != len(assets) {
				t.Fatal("unsafe partial staging changed remote assets")
			}
		})
	}
}

func TestReleaseGateAppImageResumeReusesOriginalOrCompleteLane(t *testing.T) {
	const image = "Picocrypt-NG-2.19-x86_64.AppImage"
	for _, complete := range []bool{false, true} {
		t.Run(strconv.FormatBool(complete), func(t *testing.T) {
			local := []releaseLocalFixture{
				{Name: image, Content: "original signed AppImage\n"},
				{Name: image + ".sigstore.json", Content: "current image bundle\n"},
				{Name: image + ".zsync", Content: "index of original signed AppImage\n"},
				{Name: image + ".zsync.sigstore.json", Content: "current index bundle\n"},
			}
			assets := []releaseAssetFixture{
				newReleaseAsset(100, image, local[0].Content),
				newReleaseAsset(101, image+".sigstore.json", "earlier valid image bundle\n"),
			}
			wantUploads := 2
			if complete {
				assets = append(assets, newReleaseAsset(102, image+".zsync", local[2].Content), newReleaseAsset(103, image+".zsync.sigstore.json", "earlier valid index bundle\n"))
				local[0].Content = "newly rebuilt signed AppImage\n"
				local[2].Content = "index of newly rebuilt signed AppImage\n"
				wantUploads = 0
			}
			result := runReleaseGateWithOptions(t, "upload", []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}, assets, releaseGateOptions{localAssets: local, workflow: "build-appimage.yml"})
			if result.err != nil {
				t.Fatalf("valid lane resume failed: %v\n%s", result.err, result.output)
			}
			if len(result.remoteAssets) != 4 || strings.Count(result.calls, "https://uploads.github.com/") != wantUploads {
				t.Fatalf("lane resume uploaded unexpected pairs: %#v\n%s", result.remoteAssets, result.calls)
			}
			for index, original := range assets {
				if result.remoteAssets[index] != original {
					t.Fatal("lane resume replaced original staged bytes")
				}
			}
		})
	}
}

func TestReleaseGateUploadRejectsInvalidLocalFilesBeforeAPI(t *testing.T) {
	for _, tc := range []struct {
		name   string
		assets []releaseLocalFixture
	}{
		{"unexpected file", []releaseLocalFixture{{Name: "secret.txt", Content: "private runner file"}}},
		{"incomplete pair", defaultLocalLaneAssets()[:1]},
		{"empty artifact", []releaseLocalFixture{{Name: "Picocrypt-NG", Path: "artifacts/build-linux-amd64/Picocrypt-NG"}, defaultLocalLaneAssets()[1]}},
		{"symlink artifact", []releaseLocalFixture{{Name: "Picocrypt-NG", Path: "artifacts/build-linux-amd64/Picocrypt-NG", Content: "confidential", Symlink: true}, defaultLocalLaneAssets()[1]}},
		{"wrong lane", []releaseLocalFixture{{Name: "Picocrypt-NG-Setup.exe", Path: "artifacts/build-windows/Picocrypt-NG-Setup.exe", Content: "installer"}, {Name: "Picocrypt-NG-Setup.exe.sigstore.json", Path: "artifacts/build-windows/Picocrypt-NG-Setup.exe.sigstore.json", Content: "bundle"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, "upload", nil, nil, releaseGateOptions{localAssets: tc.assets})
			if result.err == nil {
				t.Fatal("unsafe local files accepted for upload")
			}
			if result.calls != "" {
				t.Fatalf("local validation must fail before API calls:\n%s", result.calls)
			}
		})
	}
}

func TestReleaseGateUploadFailureLeavesDraftUnpublishedAndNeverDeletes(t *testing.T) {
	release := []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}
	t.Run("creation fails", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "upload", nil, nil, releaseGateOptions{draftCreateFailure: true})
		if result.err == nil {
			t.Fatal("failed draft creation accepted")
		}
		mustContain(t, result.output, "draft creation failed")
		mustNotContain(t, result.calls, "https://uploads.github.com/")
	})
	t.Run("bundle upload fails after primary", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "upload", release, nil, releaseGateOptions{uploadFailure: "Picocrypt-NG.sigstore.json"})
		if result.err == nil {
			t.Fatal("incomplete upload succeeded")
		}
		if len(result.remoteAssets) != 1 || result.remoteAssets[0].Name != "Picocrypt-NG" {
			t.Fatalf("unexpected partial staging: %#v", result.remoteAssets)
		}
		mustNotContain(t, result.calls, "--method DELETE")
		mustNotContain(t, result.calls, "--method PATCH")
		repeated := runReleaseGate(t, "upload", release, result.remoteAssets)
		if repeated.err == nil {
			t.Fatal("partial pair silently resumed")
		}
		mustContain(t, repeated.output, "incomplete staged pair")
		mustNotContain(t, repeated.calls, "--method")
	})
	t.Run("new remote bytes differ from uploaded digest", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "upload", release, nil, releaseGateOptions{corruptUploadDownload: true})
		if result.err == nil {
			t.Fatal("new remote pair was not checked before staging succeeded")
		}
		mustContain(t, result.output, "download")
		mustNotContain(t, result.output, "staged verified lane pairs")
		mustNotContain(t, result.calls, "--method PATCH")
		mustNotContain(t, result.calls, "--method DELETE")
	})
}

func TestStagingUploadsWithoutCreatingPublicationTag(t *testing.T) {
	preflight := runReleaseGateWithOptions(t, "preflight", nil, nil, releaseGateOptions{})
	if preflight.err != nil {
		t.Fatalf("stage-only preflight refused: %v\n%s", preflight.err, preflight.output)
	}
	stagingRequireReadOnly(t, preflight)
	staged := runReleaseGateWithOptions(t, "upload", nil, nil, releaseGateOptions{})
	if staged.err != nil {
		t.Fatalf("stage-only upload refused: %v\n%s", staged.err, staged.output)
	}
	stagingRequireOutputs(t, staged, true, false)
	mustNotContain(t, staged.calls, "--method PATCH")
	if staged.tagCreateInput != "" {
		t.Fatal("stage-only execution must not create a publication tag")
	}
}

func TestReleaseGateUploadValidatesDraftCreationResponse(t *testing.T) {
	for _, response := range []string{
		`{}`, `{"id":0}`, `{"id":42,"tag_name":"2.19","target_commitish":"0123456789abcdef0123456789abcdef01234567","draft":false,"prerelease":false}`,
		`{"id":42,"tag_name":"wrong","target_commitish":"0123456789abcdef0123456789abcdef01234567","draft":true,"prerelease":false}`,
		`{"id":42,"tag_name":"2.19","target_commitish":"wrong","draft":true,"prerelease":false}`,
		`{"id":42,"tag_name":"2.19","target_commitish":"0123456789abcdef0123456789abcdef01234567","draft":true,"prerelease":true}`,
	} {
		t.Run(response, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, "upload", nil, nil, releaseGateOptions{draftCreateResponse: response})
			if result.err == nil {
				t.Fatal("unsafe draft creation response accepted")
			}
			mustContain(t, result.output, "unexpected draft creation response")
			mustNotContain(t, result.calls, "https://uploads.github.com/")
			mustNotContain(t, result.calls, "--method PATCH")
		})
	}
}

func TestReleaseGatePublishesTheVerifiedCore(t *testing.T) {
	draft := []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}
	core := phasedReleaseAssets(false)
	options := releaseGateOptions{releaseScope: "core"}
	t.Run("approved core publishes without Windows", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "strict-finalize", draft, core, options)
		if result.err != nil {
			t.Fatalf("core publication failed: %v\n%s", result.err, result.output)
		}
		stagingRequireOutputs(t, result, false, true)
		mustContain(t, result.patchInput, `"make_latest": "true"`)
		mustNotContain(t, result.calls, ".exe")
	})
	t.Run("optional verified Windows pairs leave core approval intact", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "strict-finalize", draft, completeReleaseAssets("2.19"), options)
		if result.err != nil {
			t.Fatalf("valid Windows additions invalidated core approval: %v\n%s", result.err, result.output)
		}
		stagingRequireOutputs(t, result, false, true)
		mustContainCallLine(t, result.calls, "cosign verify-blob", "Picocrypt-NG-portable.exe")
	})
	t.Run("core may not omit any of its own assets", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "strict-finalize", draft, core[:len(core)-2], options)
		if result.err == nil {
			t.Fatal("incomplete non-Windows release was accepted")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("core may not publish an unpaired Windows binary", func(t *testing.T) {
		assets := append(append([]releaseAssetFixture(nil), core...), phasedReleaseAssets(true)[0])
		result := runReleaseGateWithOptions(t, "strict-finalize", draft, assets, options)
		if result.err == nil {
			t.Fatal("release with an unpaired Windows binary was accepted")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("final full verification can inspect a public complete release", func(t *testing.T) {
		published := append([]releaseGateFixture(nil), draft...)
		published[0].Draft = false
		result := runReleaseGateWithOptions(t, "verify-staged", published, completeReleaseAssets("2.19"), releaseGateOptions{
			publishedBodyFromSource: true,
		})
		if result.err != nil {
			t.Fatalf("inspection of public complete release failed: %v\n%s", result.err, result.output)
		}
		stagingRequireOutputs(t, result, false, false)
		mustContain(t, result.outputs, "release-id=42\n")
		mustContain(t, result.outputs, "candidate-digest=")
		mustNotContain(t, result.calls, "--method")
	})
}

func TestReleaseGateAppendsVerifiedWindowsToPublishedCore(t *testing.T) {
	const primary = "Picocrypt-NG-cli-Legacy.exe"
	const bundle = primary + ".sigstore.json"
	published := []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA}}
	core := phasedReleaseAssets(false)
	local := []releaseLocalFixture{
		{Name: primary, Path: "artifacts/build-windows-legacy/" + primary, Content: "frozen signed Windows bytes\n"},
		{Name: bundle, Path: "artifacts/build-windows-legacy/" + bundle, Content: "frozen Sigstore bundle\n"},
	}
	options := releaseGateOptions{workflow: "release.yml", localAssets: local, publishedBodyFromSource: true, windowsAfterCore: true}
	t.Run("preflight checks metadata while upload authenticates core bytes", func(t *testing.T) {
		corePrimary := core[len(core)-2].Name
		withFailure := options
		withFailure.cosignFailure = corePrimary
		preflight := runReleaseGateWithOptions(t, "preflight", published, core, withFailure)
		if preflight.err != nil {
			t.Fatalf("Windows attachment preflight failed: %v\n%s", preflight.err, preflight.output)
		}
		mustContain(t, preflight.calls, "/git/matching-refs/tags/2.19")
		mustContain(t, preflight.calls, "/releases/42/assets?per_page=100")
		mustNotContain(t, preflight.calls, "/releases/assets/")
		mustNotContain(t, preflight.calls, "cosign verify-blob")
		mustNotContain(t, preflight.calls, "--method")

		withDrift := options
		withDrift.coreDigest = strings.Repeat("f", 64)
		preflight = runReleaseGateWithOptions(t, "preflight", published, core, withDrift)
		if preflight.err == nil {
			t.Fatal("Windows attachment preflight accepted a different core digest")
		}
		mustNotContain(t, preflight.calls, "/releases/assets/")
		mustNotContain(t, preflight.calls, "--method")

		upload := runReleaseGateWithOptions(t, "upload", published, core, withFailure)
		if upload.err == nil {
			t.Fatal("Windows attachment accepted a core asset rejected by Cosign")
		}
		mustContainCallLine(t, upload.calls, "cosign verify-blob", corePrimary)
		mustNotContain(t, upload.calls, "--method")
	})
	t.Run("preverified sidecar uploaded before executable", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "upload", published, core, options)
		if result.err != nil {
			t.Fatalf("Windows attachment failed: %v\n%s", result.err, result.output)
		}
		stagingRequireOutputs(t, result, true, false)
		mustContainInOrder(t, result.calls, "cosign verify-blob", "https://uploads.github.com/repos/Picocrypt-NG/Picocrypt-NG/releases/42/assets?name="+bundle+" ", "https://uploads.github.com/repos/Picocrypt-NG/Picocrypt-NG/releases/42/assets?name="+primary+" ")
		mustNotContain(t, result.calls, "--method PATCH")
		mustNotContain(t, result.calls, "--method DELETE")
		if len(result.remoteAssets) != len(core)+2 || result.remoteAssets[len(core)].Content != local[1].Content || result.remoteAssets[len(core)+1].Content != local[0].Content {
			t.Fatalf("attachment did not preserve the core and signed pair: %#v", result.remoteAssets)
		}
	})
	t.Run("matching existing sidecar resumes without replacement", func(t *testing.T) {
		assets := append(append([]releaseAssetFixture(nil), core...), newReleaseAsset(999, bundle, local[1].Content))
		result := runReleaseGateWithOptions(t, "upload", published, assets, options)
		if result.err != nil {
			t.Fatalf("Windows attachment resume failed: %v\n%s", result.err, result.output)
		}
		if strings.Count(result.calls, "https://uploads.github.com/") != 1 {
			t.Fatalf("expected only the missing executable upload:\n%s", result.calls)
		}
		mustNotContain(t, result.calls, "/assets?name="+bundle+" ")
	})
	t.Run("different sidecar fails before upload", func(t *testing.T) {
		assets := append(append([]releaseAssetFixture(nil), core...), newReleaseAsset(999, bundle, "different signed generation"))
		result := runReleaseGateWithOptions(t, "upload", published, assets, options)
		if result.err == nil {
			t.Fatal("attachment accepted a different staged sidecar")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("locally unverified executable fails before upload", func(t *testing.T) {
		failure := options
		failure.cosignFailure = primary
		result := runReleaseGateWithOptions(t, "upload", published, core, failure)
		if result.err == nil {
			t.Fatal("attachment accepted a locally unverified executable")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("published core may not be incomplete", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "upload", published, core[:len(core)-2], options)
		if result.err == nil {
			t.Fatal("attachment accepted an incomplete published core")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("published release must match the approved core ID", func(t *testing.T) {
		wrong := options
		wrong.coreReleaseID = "43"
		result := runReleaseGateWithOptions(t, "upload", published, core, wrong)
		if result.err == nil {
			t.Fatal("attachment accepted a different release ID")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("published core cannot drift from its receipt", func(t *testing.T) {
		drift := append([]releaseAssetFixture(nil), core...)
		drift[0] = newReleaseAsset(drift[0].ID, drift[0].Name, "different contents")
		result := runReleaseGateWithOptions(t, "upload", published, drift, options)
		if result.err == nil {
			t.Fatal("attachment accepted changed core bytes")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("approved core is inspectable before and after publication", func(t *testing.T) {
		inspect := options
		inspect.ownerWorkflow = "build-windows-legacy.yml"
		for _, draft := range []bool{true, false} {
			release := append([]releaseGateFixture(nil), published...)
			release[0].Draft = draft
			result := runReleaseGateWithOptions(t, "inspect-owner", release, core, inspect)
			if result.err != nil {
				t.Fatalf("Windows inspection of approved core (draft=%t) failed: %v\n%s", draft, result.err, result.output)
			}
			mustContain(t, result.stdout, `"status": "missing"`)
			mustNotContain(t, result.calls, "--method")
		}
	})
	t.Run("direct Windows workflow may not mutate a public release", func(t *testing.T) {
		direct := options
		direct.workflow = "build-windows-legacy.yml"
		result := runReleaseGateWithOptions(t, "upload", published, core, direct)
		if result.err == nil {
			t.Fatal("direct workflow was allowed to append")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("ordinary staging mode may not mutate a public release", func(t *testing.T) {
		ordinary := options
		ordinary.windowsAfterCore = false
		result := runReleaseGateWithOptions(t, "upload", published, core, ordinary)
		if result.err == nil {
			t.Fatal("ordinary staging was allowed to append")
		}
		mustNotContain(t, result.calls, "--method")
	})
	t.Run("deferred Windows staging waits for public core", func(t *testing.T) {
		for _, drafts := range [][]releaseGateFixture{nil, {{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}} {
			result := runReleaseGateWithOptions(t, "upload", drafts, core, options)
			if result.err == nil {
				t.Fatal("deferred Windows lane touched a missing or draft core")
			}
			mustNotContain(t, result.calls, "--method")
		}
	})
}

func TestReleaseGateEarlyWindowsInspectionWithHiddenDraft(t *testing.T) {
	const primary = "Picocrypt-NG-cli-Legacy.exe"
	draft := []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}
	options := releaseGateOptions{
		workflow:         "release.yml",
		ownerWorkflow:    "build-windows-legacy.yml",
		windowsAfterCore: true,
		hideDraftsInList: true,
		tagAbsent:        true,
		localAssets: []releaseLocalFixture{
			{Name: primary, Path: "artifacts/build-windows-legacy/" + primary, Content: "frozen signed Windows bytes\n"},
			{Name: primary + ".sigstore.json", Path: "artifacts/build-windows-legacy/" + primary + ".sigstore.json", Content: "frozen Sigstore bundle\n"},
		},
	}
	core := phasedReleaseAssets(false)

	t.Run("read-only inspect reports missing before publication", func(t *testing.T) {
		result := runReleaseGateWithOptions(t, "inspect-owner", draft, core, options)
		if result.err != nil {
			t.Fatalf("inspection of a verified but hidden draft failed: %v\n%s", result.err, result.output)
		}
		var inventory struct {
			Status        string            `json:"status"`
			SourceSHA     string            `json:"source_sha"`
			OwnerWorkflow string            `json:"owner_workflow"`
			MissingNames  []string          `json:"missing_names"`
			VerifiedPairs []json.RawMessage `json:"verified_pairs"`
		}
		if err := json.Unmarshal([]byte(result.stdout), &inventory); err != nil {
			t.Fatalf("invalid inspection inventory: %v\n%s", err, result.stdout)
		}
		if inventory.Status != "missing" || inventory.SourceSHA != releaseTestSHA || inventory.OwnerWorkflow != options.ownerWorkflow ||
			len(inventory.VerifiedPairs) != 0 || len(inventory.MissingNames) != 1 || inventory.MissingNames[0] != primary {
			t.Fatalf("unexpected read-only Windows inventory: %+v", inventory)
		}
		mustNotContain(t, result.calls, "/releases/42/assets")
		mustNotContain(t, result.calls, "cosign verify-blob")
		mustNotContain(t, result.calls, "--method")
	})

	t.Run("a published tag cannot be treated as a hidden draft", func(t *testing.T) {
		tagged := options
		tagged.tagAbsent = false
		result := runReleaseGateWithOptions(t, "inspect-owner", draft, core, tagged)
		if result.err == nil {
			t.Fatal("inspection inferred a hidden draft for a visible release tag")
		}
		mustNotContain(t, result.calls, "--method")
	})

	t.Run("listing errors cannot be treated as a hidden draft", func(t *testing.T) {
		failure := options
		failure.releaseListingFailure = true
		result := runReleaseGateWithOptions(t, "inspect-owner", draft, core, failure)
		if result.err == nil {
			t.Fatal("inspection continued despite a failed release listing")
		}
		mustNotContain(t, result.calls, "--method")
	})

	for _, mode := range []string{"preflight", "upload"} {
		t.Run(mode+" requires visible published core", func(t *testing.T) {
			result := runReleaseGateWithOptions(t, mode, draft, core, options)
			if result.err == nil {
				t.Fatal("attachment gate accepted a hidden draft")
			}
			mustNotContain(t, result.calls, "--method")
		})
	}
}

func TestReleaseGateCoreConfirmToleratesOnlyPendingWindowsSidecars(t *testing.T) {
	const primary = "Picocrypt-NG-cli-Legacy.exe"
	for _, tc := range []struct {
		name       string
		assetName  string
		draft      bool
		wantPublic bool
	}{
		{name: "confirm already-published core with pending sidecar", assetName: primary + ".sigstore.json", wantPublic: true},
		{name: "reject public executable without sidecar", assetName: primary},
		{name: "reject initial publication with only sidecar", assetName: primary + ".sigstore.json", draft: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: tc.draft}}
			assets := phasedReleaseAssets(false)
			pending := newReleaseAsset(999, tc.assetName, "standalone Windows attachment fixture\n")
			assets = append(assets, pending)
			result := runReleaseGateWithOptions(t, "strict-finalize", release, assets, releaseGateOptions{
				releaseScope: "core", publishedBodyFromSource: true,
			})
			if tc.wantPublic {
				if result.err != nil {
					t.Fatalf("confirmation of the already-public core failed: %v\n%s", result.err, result.output)
				}
				stagingRequireOutputs(t, result, false, true)
				mustContainCallLine(t, result.calls, "cosign verify-blob", assets[0].Name)
				mustNotContain(t, result.calls, "/releases/assets/999")
			} else {
				if result.err == nil {
					t.Fatal("core release accepted an incomplete Windows pair")
				}
				mustContain(t, result.output, "incomplete Windows pair")
			}
			if len(result.remoteAssets) != len(assets) || result.remoteAssets[len(assets)-1] != pending {
				t.Fatal("core confirmation altered the pending attachment")
			}
			mustNotContain(t, result.calls, "--method")
		})
	}
}

func phasedReleaseAssets(windows bool) []releaseAssetFixture {
	var result []releaseAssetFixture
	for _, asset := range completeReleaseAssets("2.19") {
		if strings.HasSuffix(strings.TrimSuffix(asset.Name, ".sigstore.json"), ".exe") == windows {
			result = append(result, asset)
		}
	}
	return result
}

func TestReleaseGateUploadConfirmsJustCreatedDraft(t *testing.T) {
	const create = "api --method POST repos/Picocrypt-NG/Picocrypt-NG/releases --input -\n"
	const readback = "api --include repos/Picocrypt-NG/Picocrypt-NG/releases/42\n"
	for _, tc := range []struct {
		name      string
		options   releaseGateOptions
		reads     int
		waits     string
		wantStage bool
	}{
		{"not found then hidden from list", releaseGateOptions{draftReadbackMisses: 1, draftListMisses: 1}, 3, "sleep 1\nsleep 2\n", true},
		{"not found until deadline", releaseGateOptions{draftReadbackMisses: 5}, 5, "sleep 1\nsleep 2\nsleep 4\nsleep 8\n", false},
		{"hidden from list until deadline", releaseGateOptions{draftListMisses: 5}, 5, "sleep 1\nsleep 2\nsleep 4\nsleep 8\n", false},
		{"forbidden readback", releaseGateOptions{draftReadbackStatus: "403 Forbidden"}, 1, "", false},
		{"malformed readback", releaseGateOptions{draftReadbackResponse: "not JSON"}, 1, "", false},
		{"duplicate draft in list", releaseGateOptions{draftListDuplicate: true}, 1, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, "upload", nil, nil, tc.options)
			if (result.err == nil) != tc.wantStage {
				t.Fatalf("staging returned %v, want success %t\n%s", result.err, tc.wantStage, result.output)
			}
			if count := strings.Count(result.calls, create); count != 1 {
				t.Fatalf("draft creation count = %d, want 1\n%s", count, result.calls)
			}
			if count := strings.Count(result.calls, readback); count != tc.reads {
				t.Fatalf("exact-ID readback count = %d, want %d\n%s", count, tc.reads, result.calls)
			}
			var waits strings.Builder
			for line := range strings.SplitSeq(result.calls, "\n") {
				if strings.HasPrefix(line, "sleep ") {
					fmt.Fprintln(&waits, line)
				}
			}
			if got := waits.String(); got != tc.waits {
				t.Errorf("retry waits = %q, want %q", got, tc.waits)
			}
			mustNotContain(t, result.calls, "--method PATCH")
			mustNotContain(t, result.calls, "--method DELETE")
			if tc.wantStage {
				stagingRequireOutputs(t, result, true, false)
				mustContainInOrder(t, result.calls, create, readback, "sleep 1\n", readback, "sleep 2\n", readback,
					"https://uploads.github.com/repos/Picocrypt-NG/Picocrypt-NG/releases/42/assets")
				if len(result.remoteAssets) != 2 {
					t.Fatalf("staged assets = %#v, want exactly one verified lane pair", result.remoteAssets)
				}
			} else {
				mustNotContain(t, result.calls, "https://uploads.github.com/")
			}
		})
	}
}

func TestReleaseGateUploadRejectsChangedDraftReadback(t *testing.T) {
	for name, changed := range map[string]func(*releaseGateFixture){
		"id":         func(r *releaseGateFixture) { r.ID++ },
		"tag":        func(r *releaseGateFixture) { r.TagName = "other" },
		"source":     func(r *releaseGateFixture) { r.TargetCommitish = strings.Repeat("a", 40) },
		"draft":      func(r *releaseGateFixture) { r.Draft = false },
		"prerelease": func(r *releaseGateFixture) { r.Prerelease = true },
	} {
		t.Run(name, func(t *testing.T) {
			draft := releaseGateFixture{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}
			changed(&draft)
			data, err := json.Marshal(draft)
			if err != nil {
				t.Fatal(err)
			}
			result := runReleaseGateWithOptions(t, "upload", nil, nil, releaseGateOptions{draftReadbackResponse: string(data)})
			if result.err == nil {
				t.Fatal("staging accepted a changed draft readback")
			}
			if count := strings.Count(result.calls, "api --include repos/Picocrypt-NG/Picocrypt-NG/releases/42\n"); count != 1 {
				t.Fatalf("exact-ID readback count = %d, want 1\n%s", count, result.calls)
			}
			mustNotContain(t, result.calls, "sleep ")
			mustNotContain(t, result.calls, "https://uploads.github.com/")
			mustNotContain(t, result.calls, "--method PATCH")
			mustNotContain(t, result.calls, "--method DELETE")
		})
	}
}

func TestReleaseGateUploadValidatesAssetResponseAndStableSnapshot(t *testing.T) {
	release := []releaseGateFixture{{ID: 42, TagName: "2.19", TargetCommitish: releaseTestSHA, Draft: true}}
	for field, value := range map[string]any{"id": 0, "name": "secret.txt", "state": "starter", "size": 1, "digest": "sha256:" + strings.Repeat("a", 64)} {
		t.Run(field, func(t *testing.T) {
			result := runReleaseGateWithOptions(t, "upload", release, nil, releaseGateOptions{uploadResponse: map[string]any{field: value}})
			if result.err == nil {
				t.Fatal("unsafe upload response accepted")
			}
			mustContain(t, result.output, "unexpected upload response")
			mustNotContain(t, result.calls, "--method PATCH")
			mustNotContain(t, result.calls, "--method DELETE")
		})
	}
	t.Run("verified asset replaced", func(t *testing.T) {
		assets := defaultRemoteLaneAssets()
		changed := append([]releaseAssetFixture(nil), assets...)
		changed[0].ID = 999
		result := runReleaseGateWithOptions(t, "upload", release, assets, releaseGateOptions{assetsAfterVerify: changed})
		if result.err == nil {
			t.Fatal("changed verified asset snapshot accepted")
		}
		mustContain(t, result.output, "release assets changed during staging")
		mustNotContain(t, result.calls, "--method")
	})
}

type releaseGateResult struct {
	output           string
	stdout           string
	outputs          string
	calls            string
	patchInput       string
	tagCreateInput   string
	err              error
	expectedBody     string
	draftCreateInput string
	remoteAssets     []releaseAssetFixture
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

	releases = append([]releaseGateFixture(nil), releases...)
	root := repoRoot(t)
	temp := t.TempDir()
	releasesPath := filepath.Join(temp, "releases.json")
	assetsPath := filepath.Join(temp, "assets.json")
	assetsAfterPath := filepath.Join(temp, "assets-after.json")
	assetsPublishedPath := filepath.Join(temp, "assets-published.json")
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
	draftCreateCapturePath := filepath.Join(temp, "draft-create-input.json")
	uploadResponsePath := filepath.Join(temp, "upload-response.json")
	writeJSONFixture(t, uploadResponsePath, options.uploadResponse)
	writeJSONFixture(t, releasesPath, releases)
	writeJSONFixture(t, assetsPath, assets)
	assetsAfter := options.assetsAfterVerify
	if assetsAfter == nil {
		assetsAfter = assets
	}
	writeJSONFixture(t, assetsAfterPath, assetsAfter)
	assetsPublished := options.assetsAfterPublish
	if assetsPublished == nil {
		assetsPublished = assetsAfter
	}
	writeJSONFixture(t, assetsPublishedPath, assetsPublished)
	releasesAfter := append([]releaseGateFixture(nil), releases...)
	if options.publishAfterVerify && len(releasesAfter) == 1 {
		releasesAfter[0].Draft = false
	}
	if options.releaseIDAfterVerify != 0 && len(releasesAfter) == 1 {
		releasesAfter[0].ID = options.releaseIDAfterVerify
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
	if options.noLocalFiles {
		localAssets = nil
	}
	workspace := filepath.Join(temp, "workspace")
	localDir := filepath.Join(workspace, "artifacts")
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		t.Fatalf("create local fixture directory: %v", err)
	}
	for _, path := range []string{releaseGateScriptPath, releaseManifestScriptPath, releaseBodyScriptPath, releaseCertificatePolicyPath, ".github/actions/sign-and-attest/verify-primary.sh"} {
		content, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("read frozen release helper %s: %v", path, err)
		}
		destination := filepath.Join(workspace, path)
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			t.Fatalf("create release helper fixture directory: %v", err)
		}
		if err := os.WriteFile(destination, content, 0o600); err != nil {
			t.Fatalf("copy release helper fixture %s: %v", path, err)
		}
	}
	script := filepath.Join(workspace, releaseGateScriptPath)
	rootVersion := options.rootVersion
	if rootVersion == "" {
		rootVersion = "2.19"
	}
	if err := os.WriteFile(filepath.Join(workspace, "VERSION"), []byte(rootVersion+"\n"), 0o600); err != nil {
		t.Fatalf("write root VERSION fixture: %v", err)
	}
	const changelogFixture = "# v2.19\n<ul>\n<li>✓ Release policy fixture: source-bound verification instructions.</li>\n</ul>\n"
	changelogPath := filepath.Join(workspace, "Changelog.md")
	if err := os.WriteFile(changelogPath, []byte(changelogFixture), 0o600); err != nil {
		t.Fatalf("write changelog fixture: %v", err)
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
	expectedBody := ""
	remoteCandidate := mode == "verify-staged" || mode == "strict-finalize"
	if !options.noBody || remoteCandidate {
		bodyCommand := exec.Command("bash", filepath.Join(workspace, releaseBodyScriptPath), "2.19", changelogPath, bodyPath)
		bodyCommand.Dir = workspace
		bodyCommand.Env = append(os.Environ(), "GITHUB_SHA="+releaseTestSHA)
		if output, err := bodyCommand.CombinedOutput(); err != nil {
			t.Fatalf("generate source-bound release body fixture: %v\n%s", err, output)
		}
		expectedBody = readOptionalFile(t, bodyPath)
	}
	if remoteCandidate || options.windowsAfterCore {
		for _, snapshot := range [][]releaseGateFixture{releases, releasesAfter} {
			for index := range snapshot {
				if snapshot[index].Draft && snapshot[index].Body == "" {
					snapshot[index].Body = expectedBody
				}
			}
		}
		writeJSONFixture(t, releasesPath, releases)
		writeJSONFixture(t, releasesAfterPath, releasesAfter)
	}
	if options.modifiedBody {
		if err := os.WriteFile(bodyPath, []byte(expectedBody+"\nUnverified replacement instructions.\n"), 0o600); err != nil {
			t.Fatalf("modify release body fixture: %v", err)
		}
	}
	if options.bodyOutsideWorkspace {
		bodyPath = filepath.Join(temp, "confidential-release-notes.md")
		if err := os.WriteFile(bodyPath, []byte("must not become public\n"), 0o600); err != nil {
			t.Fatalf("write outside release body fixture: %v", err)
		}
	}

	if options.noBody {
		bodyPath = ""
	}
	if options.publishedBodyFromSource || options.publishedBodyOverride != "" {
		for index := range releases {
			if !releases[index].Draft {
				releases[index].Body = expectedBody
				if options.publishedBodyOverride != "" {
					releases[index].Body = options.publishedBodyOverride
				}
			}
		}
		for index := range releasesAfter {
			if !releasesAfter[index].Draft {
				if options.publishedBodyOverride != "" {
					releasesAfter[index].Body = options.publishedBodyOverride
				} else {
					releasesAfter[index].Body = expectedBody
				}
			}
		}
		writeJSONFixture(t, releasesPath, releases)
		writeJSONFixture(t, releasesAfterPath, releasesAfter)
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
    if [ "$GH_RELEASE_LISTING_FAILURE" = "true" ]; then
      echo 'fixture release listing failed' >&2
      exit 1
    fi
    if [ "$GH_HIDE_DRAFTS_IN_LIST" = "true" ]; then
      jq 'map(select(.draft == false))' "$GH_RELEASES_JSON"
      exit 0
    fi
    if [ -e "$GH_CREATED_RELEASE_JSON" ]; then
      list_count="$(awk '
        $0 == "api --method POST repos/Picocrypt-NG/Picocrypt-NG/releases --input -" {created = 1}
        created && $0 == "api --paginate repos/Picocrypt-NG/Picocrypt-NG/releases?per_page=100" {count++}
        END {print count + 0}
      ' "$GH_CALLS")"
      if [ "$list_count" -le "$GH_DRAFT_LIST_MISSES" ]; then
        echo '[]'
        exit 0
      fi
      if [ "$GH_DRAFT_LIST_DUPLICATE" = "true" ]; then
        jq '.[0] as $release | . + [$release + {id:43}]' "$GH_RELEASES_JSON"
        exit 0
      fi
    fi
    if [ -e "$GH_PUBLISHED_MARKER" ]; then
      jq -s '[.[0][0] + {draft:false, body:.[1].body}]' "$GH_RELEASES_JSON" "$GH_PATCH_CAPTURE"
    elif [ "$GH_UPLOAD_MODE" = "true" ]; then
      if [ -e "$GH_VERIFIED_MARKER" ]; then
        cat "$GH_RELEASES_AFTER_JSON"
      else
        cat "$GH_RELEASES_JSON"
      fi
    elif [ -e "$GH_RELEASES_MARKER" ]; then
      cat "$GH_RELEASES_AFTER_JSON"
    else
      : > "$GH_RELEASES_MARKER"
      cat "$GH_RELEASES_JSON"
    fi
    ;;
  "--include repos/Picocrypt-NG/Picocrypt-NG/releases/42")
    test -f "$GH_CREATED_RELEASE_JSON"
    readback_count="$(awk '
      $0 == "api --include repos/Picocrypt-NG/Picocrypt-NG/releases/42" {count++}
      END {print count + 0}
    ' "$GH_CALLS")"
    if [ "$readback_count" -le "$GH_DRAFT_READBACK_MISSES" ]; then
      printf 'HTTP/2.0 404 Not Found\r\nContent-Type: application/json\r\n\r\n{"message":"Not Found"}\n'
      exit 1
    fi
    printf 'HTTP/2.0 %s\r\nContent-Type: application/json\r\n\r\n' "$GH_DRAFT_READBACK_STATUS"
    if [ "$GH_DRAFT_READBACK_STATUS" != "200 OK" ]; then
      printf '%s\n' '{"message":"fixture readback rejected"}'
      exit 1
    fi
    if [ -n "$GH_DRAFT_READBACK_RESPONSE" ]; then
      printf '%s\n' "$GH_DRAFT_READBACK_RESPONSE"
    else
      cat "$GH_CREATED_RELEASE_JSON"
    fi
    ;;
  "--paginate repos/Picocrypt-NG/Picocrypt-NG/releases/42/assets?per_page=100")
    if [ -e "$GH_PUBLISHED_MARKER" ]; then
      cat "$GH_ASSETS_PUBLISHED_JSON"
    elif [ "$GH_UPLOAD_MODE" = "true" ]; then
      if [ -e "$GH_VERIFIED_MARKER" ] && [ "$GH_ASSETS_AFTER_VERIFY_SET" = "true" ]; then
        cat "$GH_ASSETS_AFTER_JSON"
      else
        cat "$GH_ASSETS_JSON"
      fi
    elif [ -e "$GH_ASSETS_MARKER" ]; then
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
    : > "$GH_VERIFIED_MARKER"
    identity=
    arguments=("$@")
    for (( index=0; index<${#arguments[@]}; index++ )); do
      if [ "${arguments[index]}" = --cert-identity ]; then identity=${arguments[index+1]}; fi
    done
    [[ $identity == https://github.com/Picocrypt-NG/Picocrypt-NG/.github/workflows/*@refs/heads/main ]]
    caller=$identity
    if [ -n "$GH_ATTESTATION_CALLER" ]; then
      caller="https://github.com/Picocrypt-NG/Picocrypt-NG/.github/workflows/$GH_ATTESTATION_CALLER@refs/heads/main"
    fi
    jq -cn --arg identity "$identity" --arg caller "$caller" --arg sha "$EXPECTED_CANDIDATE" '
      [{verificationResult:{signature:{certificate:{issuer:"https://token.actions.githubusercontent.com",
      subjectAlternativeName:$identity,buildSignerURI:$identity,buildSignerDigest:$sha,
      buildConfigURI:$caller,buildConfigDigest:$sha,sourceRepositoryURI:"https://github.com/Picocrypt-NG/Picocrypt-NG",
      sourceRepositoryDigest:$sha,sourceRepositoryRef:"refs/heads/main",runnerEnvironment:"github-hosted"}}}}]' \
      | jq --arg policy "$GH_ATTESTATION_POLICY" '
        if $policy == "empty" then []
        elif $policy == "duplicate" then . + .
        elif $policy == "mixed" then . + [.[0] | .verificationResult.signature.certificate.buildConfigURI = "https://github.com/Picocrypt-NG/Picocrypt-NG/.github/workflows/untrusted.yml@refs/heads/main"]
        else . end'
    ;;
  "--method POST repos/Picocrypt-NG/Picocrypt-NG/releases --input -")
    cat > "$GH_DRAFT_CREATE_CAPTURE"
    if [ "$GH_DRAFT_CREATE_FAILURE" = "true" ]; then
      echo 'fixture draft creation failed' >&2
      exit 1
    fi
    if [ -n "$GH_DRAFT_CREATE_RESPONSE" ]; then
      printf '%s\n' "$GH_DRAFT_CREATE_RESPONSE"
    else
      jq '. + {id:42}' "$GH_DRAFT_CREATE_CAPTURE" > "$GH_CREATED_RELEASE_JSON"
      jq '[.]' "$GH_CREATED_RELEASE_JSON" > "$GH_RELEASES_JSON"
      cp "$GH_RELEASES_JSON" "$GH_RELEASES_AFTER_JSON"
      cat "$GH_CREATED_RELEASE_JSON"
    fi
    ;;
  "--method POST -H Content-Type: application/octet-stream https://uploads.github.com/repos/Picocrypt-NG/Picocrypt-NG/releases/42/assets?name="*)
    if [ "$#" -ne 7 ] || [ "$6" != "--input" ]; then
      echo 'unexpected upload arguments' >&2
      exit 64
    fi
    name="${5##*name=}"
    input_path="$7"
    if [ "$name" != "${input_path##*/}" ]; then
      echo 'upload name does not match fixture file' >&2
      exit 64
    fi
    if [ "$GH_UPLOAD_FAILURE" = "$name" ]; then
      echo 'fixture upload failed' >&2
      exit 1
    fi
    if jq -e --arg name "$name" '(. // []) | any(.name == $name)' "$GH_ASSETS_JSON" >/dev/null; then
      echo 'fixture asset already exists (HTTP 422)' >&2
      exit 1
    fi
    id="$(jq '2000 + length' "$GH_ASSETS_JSON")"
    cp -- "$input_path" "$GH_REMOTE_ASSETS_DIR/$id"
    if [ "$GH_CORRUPT_UPLOAD_DOWNLOAD" = "true" ] && [[ "$name" != *.sigstore.json ]]; then
      printf '%s\n' 'substituted remote bytes' > "$GH_REMOTE_ASSETS_DIR/$id"
    fi
    size="$(wc -c < "$input_path")"
    digest="sha256:$(sha256sum "$input_path" | awk '{print $1}')"
    jq -n --argjson id "$id" --arg name "$name" --argjson size "$size" --arg digest "$digest" \
      '{id:$id,name:$name,state:"uploaded",size:$size,digest:$digest}' > "$GH_UPLOADED_ASSET_JSON"
    jq --slurpfile uploaded "$GH_UPLOADED_ASSET_JSON" '(. // []) + $uploaded' "$GH_ASSETS_JSON" > "$GH_ASSETS_JSON.tmp"
    mv "$GH_ASSETS_JSON.tmp" "$GH_ASSETS_JSON"
    jq -s '.[0] * (.[1] // {})' "$GH_UPLOADED_ASSET_JSON" "$GH_UPLOAD_RESPONSE_JSON"
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
        --argjson invalid_body "$GH_INVALID_PATCH_BODY" \
        '. as $patch
         | $patch + {
             id: 42,
             tag_name: ($patch.tag_name // $default_tag),
             target_commitish: ($patch.target_commitish // $default_target),
             draft: (if ($patch | has("draft")) then $patch.draft else true end),
             body: (if $invalid_body then "unverified PATCH response body" else $patch.body end),
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
	const fakeSleep = `#!/usr/bin/env bash
printf 'sleep %s\n' "$*" >> "$GH_CALLS"
`
	if err := os.WriteFile(filepath.Join(temp, "sleep"), []byte(fakeSleep), 0o700); err != nil {
		t.Fatalf("write fake sleep: %v", err)
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

	const fakeGit = `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -C && "$2" == "$EXPECTED_WORKSPACE" ]]
shift 2
case "$*" in
  "rev-parse HEAD") printf '%s\n' "$EXPECTED_HEAD" ;;
  "merge-base --is-ancestor $EXPECTED_CANDIDATE $GITHUB_SHA") [[ $CANDIDATE_NOT_IN_CHECKOUT == false ]] ;;
  "show $EXPECTED_CANDIDATE:VERSION") cat "$EXPECTED_WORKSPACE/VERSION" ;;
  "show $EXPECTED_CANDIDATE:Changelog.md") cat "$EXPECTED_WORKSPACE/Changelog.md" ;;
  *) echo "unexpected git invocation: $*" >&2; exit 64 ;;
esac
`
	if err := os.WriteFile(filepath.Join(temp, "git"), []byte(fakeGit), 0o700); err != nil {
		t.Fatalf("write controlled checkout HEAD fixture: %v", err)
	}
	driverSHA := options.driverSHA
	if driverSHA == "" {
		driverSHA = releaseTestSHA
	}
	checkoutHEAD := options.checkoutHEAD
	if checkoutHEAD == "" {
		checkoutHEAD = driverSHA
	}
	workflow := options.workflow
	if workflow == "" {
		workflow = "build-linux.yml"
		if remoteCandidate {
			workflow = "release.yml"
		}
	}
	candidateDigest := options.candidateDigest
	if mode == "strict-finalize" && candidateDigest == "" && !options.withoutApproval {
		releaseID := int64(42)
		if len(releases) == 1 {
			releaseID = releases[0].ID
		}
		candidateDigest = releaseGateFixtureCandidateDigest(t, workspace, releaseID, assets, expectedBody, options.releaseScope)
	}

	approvedReleaseID := options.approvedReleaseID
	if approvedReleaseID == "" {
		approvedReleaseID = "42"
	}
	coreReleaseID, coreDigest := options.coreReleaseID, options.coreDigest
	if options.windowsAfterCore {
		if coreReleaseID == "" {
			coreReleaseID = "42"
		}
		if coreDigest == "" {
			coreDigest = releaseGateFixtureCandidateDigest(t, workspace, 42, phasedReleaseAssets(false), expectedBody, "core")
		}
	}
	readbackStatus := options.draftReadbackStatus
	if readbackStatus == "" {
		readbackStatus = "200 OK"
	}

	command := exec.Command("bash", script, mode, "2.19")
	outputsPath := filepath.Join(temp, "gate-outputs")
	command.Dir = workspace
	command.Env = append(os.Environ(),
		"PATH="+temp+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FILES="+strings.Join(localPaths, "\n"),
		"BODY_PATH="+bodyPath,
		"OWNER_WORKFLOW="+options.ownerWorkflow,
		"RELEASE_SCOPE="+options.releaseScope,
		"RELEASE_WINDOWS_AFTER_CORE="+strconv.FormatBool(options.windowsAfterCore),
		"RELEASE_CORE_ID="+coreReleaseID,
		"RELEASE_CORE_DIGEST="+coreDigest,
		"RELEASE_CANDIDATE_DIGEST="+candidateDigest,
		"RELEASE_SOURCE_SHA="+releaseTestSHA,
		"RELEASE_DRAFT_ID="+approvedReleaseID,
		"GITHUB_OUTPUT="+outputsPath,
		"GH_CALLS="+callsPath,
		"GH_UPLOAD_MODE="+strconv.FormatBool(mode == "upload"),
		"GH_RELEASE_LISTING_FAILURE="+strconv.FormatBool(options.releaseListingFailure),
		"GH_HIDE_DRAFTS_IN_LIST="+strconv.FormatBool(options.hideDraftsInList),
		"GH_DRAFT_CREATE_FAILURE="+strconv.FormatBool(options.draftCreateFailure),
		"GH_DRAFT_CREATE_RESPONSE="+options.draftCreateResponse,
		"GH_DRAFT_READBACK_MISSES="+strconv.Itoa(options.draftReadbackMisses),
		"GH_DRAFT_LIST_MISSES="+strconv.Itoa(options.draftListMisses),
		"GH_DRAFT_READBACK_STATUS="+readbackStatus,
		"GH_DRAFT_READBACK_RESPONSE="+options.draftReadbackResponse,
		"GH_DRAFT_LIST_DUPLICATE="+strconv.FormatBool(options.draftListDuplicate),
		"GH_DRAFT_CREATE_CAPTURE="+draftCreateCapturePath,
		"GH_CREATED_RELEASE_JSON="+filepath.Join(temp, "created-release.json"),
		"GH_VERIFIED_MARKER="+filepath.Join(temp, "verified.marker"),
		"GH_ASSETS_AFTER_VERIFY_SET="+strconv.FormatBool(options.assetsAfterVerify != nil),
		"GH_UPLOAD_FAILURE="+options.uploadFailure,
		"GH_CORRUPT_UPLOAD_DOWNLOAD="+strconv.FormatBool(options.corruptUploadDownload),
		"GH_UPLOAD_RESPONSE_JSON="+uploadResponsePath,
		"GH_UPLOADED_ASSET_JSON="+filepath.Join(temp, "uploaded-asset.json"),
		"GH_RELEASES_JSON="+releasesPath,
		"GH_RELEASES_AFTER_JSON="+releasesAfterPath,
		"GH_RELEASES_MARKER="+filepath.Join(temp, "release-call.marker"),
		"GH_ASSETS_JSON="+assetsPath,
		"GH_ASSETS_AFTER_JSON="+assetsAfterPath,
		"GH_ASSETS_PUBLISHED_JSON="+assetsPublishedPath,
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
		"GH_ATTESTATION_CALLER="+options.attestationCaller,
		"GH_ATTESTATION_POLICY="+options.attestationPolicy,
		"GH_INVALID_PATCH_RESPONSE="+strconv.FormatBool(options.invalidPatchResponse),
		"GH_INVALID_PATCH_BODY="+strconv.FormatBool(options.invalidPatchBody),
		"COSIGN_FAILURE="+options.cosignFailure,
		"GITHUB_WORKSPACE="+workspace,
		"GITHUB_WORKFLOW_REF=Picocrypt-NG/Picocrypt-NG/.github/workflows/"+workflow+"@refs/heads/main",
		"GITHUB_REPOSITORY=Picocrypt-NG/Picocrypt-NG",
		"GITHUB_SHA="+driverSHA,
		"GITHUB_WORKFLOW_SHA="+driverSHA,
		"GITHUB_EVENT_NAME=workflow_dispatch",
		"GITHUB_REF=refs/heads/main",
		"EXPECTED_HEAD="+checkoutHEAD,
		"EXPECTED_WORKSPACE="+workspace,
		"EXPECTED_CANDIDATE="+releaseTestSHA,
		"CANDIDATE_NOT_IN_CHECKOUT="+strconv.FormatBool(options.candidateNotInCheckout),
	)
	var output, stdout []byte
	var runErr error
	if mode == "inspect-owner" {
		var stderr bytes.Buffer
		command.Stderr = &stderr
		stdout, runErr = command.Output()
		output = append(append([]byte(nil), stdout...), stderr.Bytes()...)
	} else {
		output, runErr = command.CombinedOutput()
	}
	var remoteAssets []releaseAssetFixture
	if content, err := os.ReadFile(assetsPath); err != nil {
		t.Fatalf("read staged assets: %v", err)
	} else if err := json.Unmarshal(content, &remoteAssets); err != nil {
		t.Fatalf("decode staged assets: %v", err)
	}
	for index := range remoteAssets {
		remoteAssets[index].Content = readOptionalFile(t, filepath.Join(remoteDir, strconv.FormatInt(remoteAssets[index].ID, 10)))
	}

	return releaseGateResult{
		output:           string(output),
		stdout:           string(stdout),
		outputs:          readOptionalFile(t, outputsPath),
		calls:            readOptionalFile(t, callsPath),
		patchInput:       readOptionalFile(t, patchCapturePath),
		tagCreateInput:   readOptionalFile(t, tagCreateCapturePath),
		err:              runErr,
		expectedBody:     expectedBody,
		draftCreateInput: readOptionalFile(t, draftCreateCapturePath),
		remoteAssets:     remoteAssets,
	}
}

func releaseGateFixtureCandidateDigest(t *testing.T, workspace string, id int64, assets []releaseAssetFixture, body, scope string) string {
	t.Helper()
	manifest, err := exec.Command("bash", filepath.Join(workspace, releaseManifestScriptPath), "2.19").Output()
	if err != nil {
		t.Fatal(err)
	}
	sorted := append([]releaseAssetFixture(nil), assets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	records := make([]map[string]any, 0, len(sorted))
	for _, asset := range sorted {
		if scope == "core" && strings.HasSuffix(strings.TrimSuffix(asset.Name, ".sigstore.json"), ".exe") {
			continue
		}
		records = append(records, map[string]any{
			"id": asset.ID, "name": asset.Name, "state": asset.State, "size": asset.Size, "digest": asset.Digest,
		})
	}
	candidate := map[string]any{
		"schema": 1, "repository": "Picocrypt-NG/Picocrypt-NG", "version": "2.19",
		"release_id": id, "source_sha": releaseTestSHA, "assets": records,
		"manifest_sha256": fmt.Sprintf("%x", sha256.Sum256(manifest)),
		"notes_sha256":    fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
	}
	if scope == "core" {
		candidate["scope"] = "core"
	}
	receipt, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(append(receipt, '\n')))
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
		{Name: "Picocrypt-NG-android-armeabi-v7a.apk", Workflow: "build-android.yml", Path: "out/Picocrypt-NG-android-armeabi-v7a.apk"},
		{Name: "Picocrypt-NG-android-universal.apk", Workflow: "build-android.yml", Path: "out/Picocrypt-NG-android-universal.apk"},
		{Name: "Picocrypt-NG-android-x86.apk", Workflow: "build-android.yml", Path: "out/Picocrypt-NG-android-x86.apk"},
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
