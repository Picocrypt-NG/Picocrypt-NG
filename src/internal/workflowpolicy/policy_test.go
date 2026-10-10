package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

func TestStaticChecksWorkflowEnforcesFormatVetLintAndVuln(t *testing.T) {
	const path = ".github/workflows/pr-static-checks.yml"
	workflow := mustReadWorkflowDoc(t, path)

	// Least-privilege, like every other PR workflow.
	mustPermission(t, workflow.Permissions, "contents", "read")

	job := mustJob(t, workflow, "static-checks")

	gofmtStep := mustStepNamed(t, job, "Check formatting (gofmt)")
	mustContain(t, gofmtStep.Run, "gofmt -l")

	vetStep := mustStepNamed(t, job, "Vet")
	mustContain(t, vetStep.Run, "go vet")
	mustContain(t, vetStep.Run, "./...")

	lintStep := mustStepNamed(t, job, "Lint (golangci-lint)")
	mustContain(t, lintStep.Run, "golangci-lint run")
	mustContain(t, lintStep.Run, "./...")
	// golangci-lint must be pinned to an explicit version (the v2 config is
	// version-sensitive); @latest would make CI non-reproducible.
	mustMatch(t, lintStep.Run, `golangci-lint/v2/cmd/golangci-lint@v[0-9]+\.[0-9]+\.[0-9]+`)
	mustNotContain(t, lintStep.Run, "golangci-lint/v2/cmd/golangci-lint@latest")

	vulnStep := mustStepNamed(t, job, "Vulnerability scan (govulncheck)")
	mustContain(t, vulnStep.Run, "govulncheck")
	mustContain(t, vulnStep.Run, "./...")

	content := mustReadWorkflow(t, path)
	mustContain(t, content, "pull_request:")
}

func TestReleaseUploadsNeverOverwriteExistingAssets(t *testing.T) {
	action := mustReadCompositeActionDoc(t, ".github/actions/stage-release/action.yml")
	uploadStep := mustCompositeStepNamed(t, action, "Upload assets to draft release")
	if got := uploadStep.With["overwrite_files"]; got != false && got != "false" {
		t.Fatalf("release overwrite_files = %#v, want false to preserve staged binaries", got)
	}
}

func TestWorkflowAndCompositeYAMLContainNoDirectReleaseMutation(t *testing.T) {
	var paths []string
	for _, pattern := range []string{
		filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"),
		filepath.Join(repoRoot(t), ".github", "workflows", "*.yaml"),
		filepath.Join(repoRoot(t), ".github", "actions", "*", "action.yml"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		paths = append(paths, matches...)
	}
	directCLI := regexp.MustCompile(`(?m)\bgh\s+release\s+(create|upload|edit)\b`)
	directAPI := regexp.MustCompile(`(?m)\bgh\s+api\b[^\n]*(/releases|releases/)`)
	for _, path := range paths {
		if filepath.Clean(path) == filepath.Join(
			repoRoot(t),
			".github",
			"actions",
			"stage-release",
			"action.yml",
		) {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		source := strings.ReplaceAll(string(content), "\\\n", " ")
		if strings.Contains(source, "softprops/action-gh-release@") {
			t.Fatalf("%s directly invokes softprops instead of the shared release gate", path)
		}
		if directCLI.MatchString(source) || directAPI.MatchString(source) {
			t.Fatalf("%s directly mutates GitHub releases instead of the shared release gate", path)
		}
	}
}

var externalActionSHARefPattern = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)

func TestExternalGitHubActionsPinnedToFullSHAWithVersionComment(t *testing.T) {
	actionRef := regexp.MustCompile(`^(?:-\s+)?uses:\s*([^@\s]+)@([0-9a-f]{40})(?:\s+#\s+v[0-9][^\s]*)?$`)
	const checkoutUses = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	const checkoutRef = checkoutUses + " # v7.0.1"
	checkoutCount := 0
	checkSteps := func(owner string, steps []workflowStep) int {
		t.Helper()
		count := 0
		for _, step := range steps {
			if step.Uses != "" && !strings.HasPrefix(step.Uses, "./") && !externalActionSHARefPattern.MatchString(step.Uses) {
				t.Fatalf("%s parsed external uses = %q; want exactly a 40-hex immutable SHA", owner, step.Uses)
			}
			if !strings.HasPrefix(step.Uses, "actions/checkout@") {
				continue
			}
			count++
			if step.Uses != checkoutUses {
				t.Fatalf("%s checkout uses = %q, want %q", owner, step.Uses, checkoutUses)
			}
		}
		return count
	}
	workflowFiles, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("glob workflows: %v", err)
	}
	actionFiles, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "actions", "*", "action.yml"))
	if err != nil {
		t.Fatalf("glob composite actions: %v", err)
	}

	files := make([]string, 0, len(workflowFiles)+len(actionFiles))
	files = append(files, workflowFiles...)
	files = append(files, actionFiles...)
	for _, absPath := range files {
		relPath, err := filepath.Rel(repoRoot(t), absPath)
		if err != nil {
			t.Fatalf("rel path for %s: %v", absPath, err)
		}
		activeCheckoutCount := 0
		if strings.HasPrefix(relPath, filepath.Join(".github", "workflows")+string(filepath.Separator)) {
			workflow := mustReadWorkflowDoc(t, relPath)
			for jobName, job := range workflow.Jobs {
				if job.Uses != "" && !strings.HasPrefix(job.Uses, "./") && !externalActionSHARefPattern.MatchString(job.Uses) {
					t.Fatalf("%s job %s parsed reusable workflow uses = %q; want an immutable full SHA", relPath, jobName, job.Uses)
				}
				activeCheckoutCount += checkSteps(relPath+" job "+jobName, job.Steps)
			}
		} else {
			action := mustReadCompositeActionDoc(t, relPath)
			activeCheckoutCount += checkSteps(relPath, action.Runs.Steps)
		}
		checkoutCount += activeCheckoutCount
		content := mustReadRepoFile(t, relPath)
		checkoutLineCount := 0
		for lineNo, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.Contains(trimmed, "uses:") {
				continue
			}
			if strings.Contains(trimmed, "uses: ./") {
				continue
			}
			if strings.Contains(trimmed, "uses: actions/checkout@") {
				if got := strings.TrimPrefix(trimmed, "- "); got != "uses: "+checkoutRef {
					t.Fatalf("%s:%d checkout ref = %q, want %q", relPath, lineNo+1, got, "uses: "+checkoutRef)
				}
				checkoutLineCount++
			}
			if !actionRef.MatchString(trimmed) {
				t.Fatalf("%s:%d external action must use a 40-hex SHA and same-line version comment, got %q", relPath, lineNo+1, trimmed)
			}
		}
		if checkoutLineCount != activeCheckoutCount {
			t.Fatalf("%s contains %d checkout uses lines but %d active checkout steps", relPath, checkoutLineCount, activeCheckoutCount)
		}
	}
	if checkoutCount == 0 {
		t.Fatal("no active actions/checkout references found")
	}
}

func TestSignAndAttestUsesApprovedCosign(t *testing.T) {
	const path = ".github/actions/sign-and-attest/action.yml"
	action := mustReadCompositeActionDoc(t, path)
	if action.Runs.Using != "composite" {
		t.Fatalf("sign-and-attest runs.using = %q, want composite", action.Runs.Using)
	}
	installStep := mustCompositeStepNamed(t, action, "Install cosign")

	const installerRef = "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6"
	if installStep.Uses != installerRef {
		t.Fatalf("Install cosign uses = %q, want %q", installStep.Uses, installerRef)
	}
	if got := installStep.With["cosign-release"]; got != "v3.1.3" {
		t.Fatalf("Install cosign cosign-release = %#v, want v3.1.3", got)
	}

	content := mustReadRepoFile(t, path)
	const installerLine = "uses: " + installerRef + " # v4.1.2"
	mustMatch(t, content, `(?m)^\s*`+regexp.QuoteMeta(installerLine)+`\s*$`)
	if got := strings.Count(content, installerLine); got != 1 {
		t.Fatalf("cosign installer line count = %d, want exactly 1", got)
	}
	mustNotContain(t, content, "cosign-release: 'v3.1.1'")
	ownership := mustCompositeStepNamed(t, action, "Validate exact release artifact ownership")
	for _, required := range []string{"release-manifest.sh", `test "$(git rev-parse HEAD)" = "$GITHUB_SHA"`, `test "$WORKFLOW_REF" = "$GITHUB_REPOSITORY/.github/workflows/$owner@refs/heads/main"`, `[ ! -L "$file" ]`, `[ -s "$file" ]`} {
		mustContain(t, ownership.Run, required)
	}
	provenance := mustCompositeStepNamed(t, action, "Generate build-provenance attestation")
	if provenance.With["subject-path"] != "${{ steps.files.outputs.paths }}" {
		t.Fatal("provenance must attest exactly the artifact paths validated for this workflow owner")
	}
	verify := mustCompositeStepNamed(t, action, "Fail-loud verify (cosign + provenance)")
	if verify.Env["SOURCE_SHA"] != "${{ github.sha }}" || verify.Env["IDENTITY"] != "https://github.com/${{ github.workflow_ref }}" {
		t.Fatal("signature and provenance must bind the current source and exact workflow identity")
	}
	for _, restriction := range []string{`--certificate-identity "$IDENTITY"`, `--certificate-github-workflow-sha "$SOURCE_SHA"`, "--certificate-github-workflow-ref refs/heads/main", `--certificate-github-workflow-repository "$REPO"`, `--cert-identity "$IDENTITY"`, `--signer-digest "$SOURCE_SHA"`, "--source-ref refs/heads/main", `--source-digest "$SOURCE_SHA"`, "--predicate-type https://slsa.dev/provenance/v1", "--deny-self-hosted-runners"} {
		mustContain(t, verify.Run, restriction)
	}
}

func TestReleaseJobsRequireMainBranchAndReleaseEnvironment(t *testing.T) {
	const releaseGuard = "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release }}"
	const signPathReleaseGuard = "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && !inputs.signpath_test && !inputs.signpath_release_dry_run && inputs.publish_release }}"

	for _, tc := range releaseWorkflowCases() {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			releaseJob := mustJob(t, workflow, tc.job)
			wantGuard := releaseGuard
			if tc.name == "build-windows" || tc.name == "build-windows-legacy" {
				wantGuard = signPathReleaseGuard
			}
			if releaseJob.If != wantGuard {
				t.Fatalf("release job if = %q, want explicit manual release on main", releaseJob.If)
			}
			if got := releaseEnvironmentName(releaseJob.Environment); got != "release" {
				t.Fatalf("release job environment = %#v, want release", releaseJob.Environment)
			}

			content := mustReadWorkflow(t, tc.path)
			mustContain(t, content, "publish_release:")
		})
	}
}

func TestReleaseWorkflowsRequireManualDispatchWithoutDefaultPublication(t *testing.T) {
	for _, tc := range releaseWorkflowCases() {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			if len(workflow.On.OtherEvents) != 0 {
				t.Fatalf("automatic release workflow triggers = %v; want only workflow_dispatch", workflow.On.OtherEvents)
			}
			input, ok := workflow.On.WorkflowDispatch.Inputs["publish_release"]
			if !ok || input.Type != "boolean" || input.Default != false || input.Required {
				t.Fatalf("publish_release input = %#v; want optional boolean default false", input)
			}
		})
	}
}

func releaseWorkflowCases() []struct {
	name string
	path string
	job  string
} {
	return []struct {
		name string
		path string
		job  string
	}{
		{name: "build-android", path: ".github/workflows/build-android.yml", job: "release"},
		{name: "build-appimage", path: ".github/workflows/build-appimage.yml", job: "release"},
		{name: "build-linux", path: ".github/workflows/build-linux.yml", job: "release"},
		{name: "build-macos", path: ".github/workflows/build-macos.yml", job: "release"},
		{name: "build-snapcraft", path: ".github/workflows/build-snapcraft.yml", job: "release"},
		{name: "build-windows", path: ".github/workflows/build-windows.yml", job: "release"},
		{name: "build-windows-legacy", path: ".github/workflows/build-windows-legacy.yml", job: "release"},
	}
}

func TestAppImageSigningSecretsRequireReleaseEnvironment(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	buildJob := mustJob(t, workflow, "build")

	if buildJob.If != "${{ github.ref == 'refs/heads/main' }}" {
		t.Fatalf("AppImage signing build job if = %q, want main branch guard", buildJob.If)
	}
	if got := releaseEnvironmentName(buildJob.Environment); got != "release" {
		t.Fatalf("AppImage signing build job environment = %#v, want release", buildJob.Environment)
	}

	importStep := mustStepNamed(t, buildJob, "Import GPG signing key")
	if _, ok := importStep.Env["GPG_PRIVATE_KEY"]; !ok {
		t.Fatal("AppImage signing build job should keep the GPG private key scoped to its import step")
	}
	buildStep := mustStepNamed(t, buildJob, "Build AppImage")
	if _, ok := buildStep.Env["APPIMAGETOOL_SIGN_PASSPHRASE"]; !ok {
		t.Fatal("AppImage signing build job should keep the AppImage passphrase scoped to its build step")
	}
}

func releaseEnvironmentName(env any) string {
	switch v := env.(type) {
	case string:
		return v
	case map[string]any:
		if name, ok := v["name"].(string); ok {
			return name
		}
	}
	return ""
}

func TestBuildPermissionsStayLeastPrivilege(t *testing.T) {
	buildAndroid := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	mustPermission(t, buildAndroid.Permissions, "contents", "read")
	mustEffectivePermission(t, buildAndroid, mustJob(t, buildAndroid, "build"), "contents", "read")
	mustPermission(t, mustJob(t, buildAndroid, "release").Permissions, "contents", "write")

	buildLinux := mustReadWorkflowDoc(t, ".github/workflows/build-linux.yml")
	mustPermission(t, buildLinux.Permissions, "contents", "read")
	mustEffectivePermission(t, buildLinux, mustJob(t, buildLinux, "build"), "contents", "read")
	mustEffectivePermission(t, buildLinux, mustJob(t, buildLinux, "release"), "contents", "write")

	buildMacOS := mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml")
	mustPermission(t, buildMacOS.Permissions, "contents", "read")
	mustEffectivePermission(t, buildMacOS, mustJob(t, buildMacOS, "build"), "contents", "read")
	mustEffectivePermission(t, buildMacOS, mustJob(t, buildMacOS, "release"), "contents", "write")

	buildWindows := mustReadWorkflowDoc(t, ".github/workflows/build-windows.yml")
	mustPermission(t, buildWindows.Permissions, "contents", "read")
	mustEffectivePermission(t, buildWindows, mustJob(t, buildWindows, "build"), "contents", "read")
	mustEffectivePermission(t, buildWindows, mustJob(t, buildWindows, "release"), "contents", "write")

	buildSnapcraft := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	mustPermission(t, buildSnapcraft.Permissions, "contents", "read")
	mustEffectivePermission(t, buildSnapcraft, mustJob(t, buildSnapcraft, "build-snapcraft"), "contents", "read")
	mustEffectivePermission(t, buildSnapcraft, mustJob(t, buildSnapcraft, "release"), "contents", "write")

	buildAppImage := mustReadWorkflowDoc(t, ".github/workflows/build-appimage.yml")
	mustPermission(t, buildAppImage.Permissions, "contents", "read")
	mustEffectivePermission(t, buildAppImage, mustJob(t, buildAppImage, "build"), "contents", "read")
	mustEffectivePermission(t, buildAppImage, mustJob(t, buildAppImage, "release"), "contents", "write")
}

func TestAppImageWorkflowIsPortableSmokeTestedAndPinned(t *testing.T) {
	const path = ".github/workflows/build-appimage.yml"
	workflow := mustReadWorkflowDoc(t, path)
	content := mustReadWorkflow(t, path)

	build := mustJob(t, workflow, "build")

	// Portability floor. AppImage was dropped once "for better portability"
	// (Changelog v1.34); building on the newest runner's glibc reproduces that, so the
	// build job pins the oldest supported runner (ubuntu-22.04, glibc 2.35).
	mustContain(t, content, "runs-on: ubuntu-22.04")

	// Supply chain: the AppImage tooling is fetched at build time, so it must be
	// sha256-pinned AND verified (fail loud), like UPX in build-linux. Asserts that a
	// pin exists and is checked -- not the exact digest -- so a tool bump does not churn
	// this test.
	mustContain(t, content, "linuxdeploy")
	mustContain(t, content, "appimagetool")
	mustMatch(t, content, `[0-9a-f]{64}`)
	mustContain(t, content, "sha256sum")
	mustContain(t, content, "--check")

	// The produced AppImage must be smoke-tested, or a broken bundle (a shared library
	// that fails to resolve) ships silently. --version drives the embedded CLI
	// (cli.Execute), which exits before Fyne/OpenGL init, so it proves every bundled and
	// host-provided library resolves at process start without needing a display.
	smoke := mustStepNamed(t, build, "Smoke test AppImage")
	mustContain(t, smoke.Run, "--version")
	mustContain(t, smoke.Run, ".AppImage")
}

func TestMacOSReleaseWorkflowInjectsRootVersionIntoBundleMetadata(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml")
	buildJob := mustJob(t, workflow, "build")
	packageStep := mustStepNamed(t, buildJob, "Package as .app in a .dmg")

	mustContain(t, packageStep.Run, `plutil -replace CFBundleShortVersionString -string "$(cat VERSION)"`)
	mustContain(t, packageStep.Run, `plutil -replace CFBundleVersion -string "$(cat VERSION)"`)
}

func TestMacOSReleaseWorkflowPublishesCLIFromFlatArtifact(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-macos.yml")
	buildJob := mustJob(t, workflow, "build")
	releaseJob := mustJob(t, workflow, "release")

	stageStep := mustStepNamed(t, buildJob, "Stage release artifacts")
	mustContain(t, stageStep.Run, "cp Picocrypt-NG.dmg release-staging/")
	mustContain(t, stageStep.Run, "cp src/Picocrypt-NG-cli-macos release-staging/")
	mustContain(t, stageStep.Run, "test -s release-staging/Picocrypt-NG-cli-macos")

	uploadStep := mustStepNamed(t, buildJob, "Upload artifacts")
	if uploadStep.With["path"] != "release-staging/" {
		t.Fatalf("macOS upload artifact path = %#v, want flat release-staging/", uploadStep.With["path"])
	}

	verifyStep := mustStepNamed(t, releaseJob, "Verify artifacts present")
	mustContain(t, verifyStep.Run, "set -euo pipefail")
	mustContain(t, verifyStep.Run, "test -s artifacts/build-macos/Picocrypt-NG-cli-macos")

	releaseStep := mustStepNamed(t, releaseJob, "Stage release assets")
	files, ok := releaseStep.With["files"].(string)
	if !ok {
		t.Fatalf("macOS release files input = %#v, want string", releaseStep.With["files"])
	}
	mustContain(t, files, "artifacts/build-macos/Picocrypt-NG-cli-macos")
}

func TestWindowsReleaseWorkflowPassesRootVersionToNSIS(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-windows.yml")
	buildJob := mustJob(t, workflow, "build")
	nsisStep := mustStepNamed(t, buildJob, "Build NSIS installer")

	mustContainInOrder(t, nsisStep.Run,
		`$version = (Get-Content -Path "VERSION" -Raw).Trim()`,
		`makensis.exe`,
		`"-DVERSION=$version"`,
	)
}

func TestWindowsReleaseAuthenticodeSigningPrecedesPackagingAndSigstore(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-windows.yml")
	buildJob := mustJob(t, workflow, "build")
	unsignedUpload := mustStepNamed(t, buildJob, "Upload artifact")
	if got := unsignedUpload.With["name"]; got != "unsigned-windows" {
		t.Fatalf("unsigned Windows artifact name = %#v, want unsigned-windows", got)
	}
	if got := unsignedUpload.With["retention-days"]; got != 1 {
		t.Fatalf("unsigned Windows artifact retention = %#v, want 1 day", got)
	}

	signJob := mustJob(t, workflow, "sign")

	if signJob.If != "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && (inputs.publish_release || inputs.signpath_test || inputs.signpath_release_dry_run) }}" {
		t.Fatalf("Windows SignPath job if = %q, want main release, test signing, or release-signing dry-run guard", signJob.If)
	}
	if signJob.TimeoutMinutes != 210 {
		t.Fatalf("Windows SignPath job timeout = %d minutes, want 210 for three one-hour approval windows plus packaging", signJob.TimeoutMinutes)
	}
	if got := releaseEnvironmentName(signJob.Environment); got != "release" {
		t.Fatalf("Windows SignPath job environment = %#v, want release", signJob.Environment)
	}
	mustPermission(t, signJob.Permissions, "actions", "read")
	mustPermission(t, signJob.Permissions, "contents", "read")
	if got := signJob.Env["SIGNPATH_PRODUCTION_CERTIFICATE_SHA256"]; got != "${{ vars.SIGNPATH_PRODUCTION_CERTIFICATE_SHA256 }}" {
		t.Fatalf("production certificate trust anchor = %q, want protected GitHub variable", got)
	}
	if got := signJob.Env["SIGNPATH_SIGNING_POLICY_SLUG"]; got != "${{ inputs.signpath_test && 'test-signing' || 'release-signing' }}" {
		t.Fatalf("Windows SignPath policy routing = %q, want explicit test/release policies", got)
	}
	if got := signJob.Env["SIGNPATH_TEST"]; got != "${{ inputs.signpath_test && 'true' || 'false' }}" {
		t.Fatalf("Windows test-signing verification mode = %q, want exact boolean routing", got)
	}
	if _, ok := signJob.Permissions["contents"]; !ok {
		t.Fatal("Windows SignPath job must declare contents: read explicitly")
	}
	validateMode := mustStepNamed(t, signJob, "Reject conflicting SignPath modes")
	if validateMode.If != "${{ inputs.signpath_test && inputs.signpath_release_dry_run }}" {
		t.Fatalf("Windows SignPath mode validation if = %q, want mutually exclusive test and release dry-run modes", validateMode.If)
	}
	mustContain(t, validateMode.Run, "cannot both be enabled")

	orderedSigningSteps := []string{
		"Download unsigned build artifact",
		"Stage unsigned binaries for SignPath",
		"Upload unsigned binaries for SignPath",
		"Sign binaries with SignPath",
		"Verify signed binaries before packaging",
		"Export unsigned NSIS uninstaller",
		"Upload unsigned uninstaller for SignPath",
		"Sign uninstaller with SignPath",
		"Verify signed uninstaller",
		"Build NSIS installer from signed components",
		"Upload unsigned installer for SignPath",
		"Sign installer with SignPath",
		"Verify final Authenticode artifacts",
		"Upload signed Windows artifacts",
	}
	lastIndex := -1
	for _, name := range orderedSigningSteps {
		index := -1
		for candidateIndex, step := range signJob.Steps {
			if step.Name == name {
				index = candidateIndex
				break
			}
		}
		if index < 0 {
			t.Fatalf("Windows SignPath job is missing step %q", name)
		}
		if index <= lastIndex {
			t.Fatalf("Windows SignPath step %q is out of order; want %s", name, strings.Join(orderedSigningSteps, " < "))
		}
		lastIndex = index
	}

	for _, tc := range []struct {
		name              string
		configurationSlug string
		uploadStepID      string
		outputDirectory   string
	}{
		{name: "Sign binaries with SignPath", configurationSlug: "windows-binaries", uploadStepID: "upload-signpath-binaries", outputDirectory: "signpath-signed-binaries"},
		{name: "Sign uninstaller with SignPath", configurationSlug: "windows-uninstaller", uploadStepID: "upload-signpath-uninstaller", outputDirectory: "signpath-signed-uninstaller"},
		{name: "Sign installer with SignPath", configurationSlug: "windows-installer", uploadStepID: "upload-signpath-installer", outputDirectory: "signpath-signed-installer"},
	} {
		step := mustStepNamed(t, signJob, tc.name)
		if step.Uses != "signpath/github-action-submit-signing-request@f6d04783b4569d051e0c80105fe66e82819d0092" {
			t.Fatalf("%s action = %q, want reviewed SignPath v3.0 commit", tc.name, step.Uses)
		}
		for key, want := range map[string]any{
			"api-token":                              "${{ secrets.SIGNPATH_API_TOKEN }}",
			"organization-id":                        "d6e78672-6bae-47d3-b2b8-fa464705b34e",
			"project-slug":                           "${{ vars.SIGNPATH_PROJECT_SLUG }}",
			"signing-policy-slug":                    "${{ env.SIGNPATH_SIGNING_POLICY_SLUG }}",
			"artifact-configuration-slug":            tc.configurationSlug,
			"github-artifact-id":                     "${{ steps." + tc.uploadStepID + ".outputs.artifact-id }}",
			"wait-for-completion":                    true,
			"wait-for-completion-timeout-in-seconds": 3600,
			"output-artifact-directory":              tc.outputDirectory,
		} {
			if got := step.With[key]; got != want {
				t.Fatalf("%s input %s = %#v, want %#v", tc.name, key, got, want)
			}
		}
	}

	verifyFinal := mustStepNamed(t, signJob, "Verify final Authenticode artifacts")
	mustContain(t, verifyFinal.Run, "Get-AuthenticodeSignature")
	mustContain(t, verifyFinal.Run, "GetCertHashString")
	mustContain(t, verifyFinal.Run, "SIGNPATH_PRODUCTION_CERTIFICATE_SHA256")
	mustContain(t, verifyFinal.Run, "TimeStamperCertificate")
	mustContain(t, verifyFinal.Run, "Picocrypt-NG-Setup.exe")
	mustContain(t, verifyFinal.Run, "7z.exe")
	mustContain(t, verifyFinal.Run, "Picocrypt-NG.exe")
	mustContain(t, verifyFinal.Run, "Picocrypt-NG-cli.exe")
	mustContain(t, verifyFinal.Run, "Uninstall.exe")
	mustContain(t, verifyFinal.Run, "Get-FileHash")
	for _, name := range []string{
		"Verify signed binaries before packaging",
		"Verify signed uninstaller",
		"Verify final Authenticode artifacts",
	} {
		if got := mustStepNamed(t, signJob, name).ContinueOnError; got != nil && got != false {
			t.Fatalf("Windows verification step %q continue-on-error = %#v, want blocking", name, got)
		}
	}

	uploadSigned := mustStepNamed(t, signJob, "Upload signed Windows artifacts")
	if got := uploadSigned.With["name"]; got != "${{ inputs.signpath_test && 'signed-windows-TEST-DO-NOT-PUBLISH' || 'signed-windows' }}" {
		t.Fatalf("signed Windows artifact name = %#v, want visibly distinct self-signed test output", got)
	}
	if got := uploadSigned.With["retention-days"]; got != 1 {
		t.Fatalf("signed Windows artifact retention = %#v, want 1 day", got)
	}

	releaseJob := mustJob(t, workflow, "release")
	needs, ok := releaseJob.Needs.([]any)
	if !ok || len(needs) != 2 || needs[0] != "build" || needs[1] != "sign" {
		t.Fatalf("Windows release needs = %#v, want [build sign] so unsigned artifacts cannot bypass SignPath", releaseJob.Needs)
	}
	mustContain(t, releaseJob.If, "!inputs.signpath_test")
	mustContain(t, releaseJob.If, "!inputs.signpath_release_dry_run")
	downloadSigned := mustStepNamed(t, releaseJob, "Download signed artifact")
	if got := downloadSigned.With["name"]; got != "signed-windows" {
		t.Fatalf("Windows release artifact name = %#v, want signed-windows", got)
	}
	orderedReleaseSteps := []string{"Download signed artifact", "Sign and attest artifacts", "Stage release assets"}
	lastIndex = -1
	for _, name := range orderedReleaseSteps {
		index := -1
		for candidateIndex, step := range releaseJob.Steps {
			if step.Name == name {
				index = candidateIndex
				break
			}
		}
		if index < 0 || index <= lastIndex {
			t.Fatalf("Windows release steps must be ordered as %s", strings.Join(orderedReleaseSteps, " < "))
		}
		lastIndex = index
	}
}

func TestWindowsLegacyReleaseUsesSignPathBeforeSigstore(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-windows-legacy.yml")
	buildJob := mustJob(t, workflow, "build")
	unsignedUpload := mustStepNamed(t, buildJob, "Upload artifact")
	if got := unsignedUpload.With["name"]; got != "unsigned-windows-legacy" {
		t.Fatalf("unsigned legacy artifact name = %#v, want unsigned-windows-legacy", got)
	}
	if got := unsignedUpload.With["retention-days"]; got != 1 {
		t.Fatalf("unsigned legacy artifact retention = %#v, want 1 day", got)
	}

	signJob := mustJob(t, workflow, "sign")
	if signJob.If != "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && (inputs.publish_release || inputs.signpath_test || inputs.signpath_release_dry_run) }}" {
		t.Fatalf("legacy SignPath job if = %q, want main release, test signing, or release-signing dry-run guard", signJob.If)
	}
	if signJob.TimeoutMinutes != 75 {
		t.Fatalf("legacy SignPath job timeout = %d minutes, want 75 for a one-hour approval window plus verification", signJob.TimeoutMinutes)
	}
	if got := releaseEnvironmentName(signJob.Environment); got != "release" {
		t.Fatalf("legacy SignPath job environment = %#v, want release", signJob.Environment)
	}
	mustPermission(t, signJob.Permissions, "actions", "read")
	mustPermission(t, signJob.Permissions, "contents", "read")
	if got := signJob.Env["SIGNPATH_PRODUCTION_CERTIFICATE_SHA256"]; got != "${{ vars.SIGNPATH_PRODUCTION_CERTIFICATE_SHA256 }}" {
		t.Fatalf("legacy production certificate trust anchor = %q, want protected GitHub variable", got)
	}
	if got := signJob.Env["SIGNPATH_SIGNING_POLICY_SLUG"]; got != "${{ inputs.signpath_test && 'test-signing' || 'release-signing' }}" {
		t.Fatalf("legacy SignPath policy routing = %q, want explicit test/release policies", got)
	}
	if got := signJob.Env["SIGNPATH_TEST"]; got != "${{ inputs.signpath_test && 'true' || 'false' }}" {
		t.Fatalf("legacy test-signing verification mode = %q, want exact boolean routing", got)
	}
	validateMode := mustStepNamed(t, signJob, "Reject conflicting SignPath modes")
	if validateMode.If != "${{ inputs.signpath_test && inputs.signpath_release_dry_run }}" {
		t.Fatalf("legacy SignPath mode validation if = %q, want mutually exclusive test and release dry-run modes", validateMode.If)
	}
	mustContain(t, validateMode.Run, "cannot both be enabled")

	signStep := mustStepNamed(t, signJob, "Sign legacy CLI with SignPath")
	if signStep.Uses != "signpath/github-action-submit-signing-request@f6d04783b4569d051e0c80105fe66e82819d0092" {
		t.Fatalf("legacy SignPath action = %q, want reviewed SignPath v3.0 commit", signStep.Uses)
	}
	for key, want := range map[string]any{
		"api-token":                              "${{ secrets.SIGNPATH_API_TOKEN }}",
		"organization-id":                        "d6e78672-6bae-47d3-b2b8-fa464705b34e",
		"project-slug":                           "${{ vars.SIGNPATH_PROJECT_SLUG }}",
		"signing-policy-slug":                    "${{ env.SIGNPATH_SIGNING_POLICY_SLUG }}",
		"artifact-configuration-slug":            "windows-legacy-cli",
		"github-artifact-id":                     "${{ steps.upload-signpath-legacy.outputs.artifact-id }}",
		"wait-for-completion":                    true,
		"wait-for-completion-timeout-in-seconds": 3600,
		"output-artifact-directory":              "signpath-signed-legacy",
	} {
		if got := signStep.With[key]; got != want {
			t.Fatalf("legacy SignPath input %s = %#v, want %#v", key, got, want)
		}
	}

	verifyStep := mustStepNamed(t, signJob, "Verify legacy Authenticode signature")
	mustContain(t, verifyStep.Run, "Get-AuthenticodeSignature")
	mustContain(t, verifyStep.Run, "GetCertHashString")
	mustContain(t, verifyStep.Run, "SIGNPATH_PRODUCTION_CERTIFICATE_SHA256")
	mustContain(t, verifyStep.Run, "TimeStamperCertificate")
	if got := verifyStep.ContinueOnError; got != nil && got != false {
		t.Fatalf("legacy verification continue-on-error = %#v, want blocking", got)
	}
	uploadSigned := mustStepNamed(t, signJob, "Upload signed Windows legacy artifact")
	if got := uploadSigned.With["name"]; got != "${{ inputs.signpath_test && 'signed-windows-legacy-TEST-DO-NOT-PUBLISH' || 'signed-windows-legacy' }}" {
		t.Fatalf("signed legacy artifact name = %#v, want visibly distinct self-signed test output", got)
	}
	if got := uploadSigned.With["retention-days"]; got != 1 {
		t.Fatalf("signed legacy artifact retention = %#v, want 1 day", got)
	}

	releaseJob := mustJob(t, workflow, "release")
	needs, ok := releaseJob.Needs.([]any)
	if !ok || len(needs) != 2 || needs[0] != "build" || needs[1] != "sign" {
		t.Fatalf("legacy release needs = %#v, want [build sign]", releaseJob.Needs)
	}
	mustContain(t, releaseJob.If, "!inputs.signpath_test")
	mustContain(t, releaseJob.If, "!inputs.signpath_release_dry_run")
	downloadStep := mustStepNamed(t, releaseJob, "Download signed artifact")
	if got := downloadStep.With["name"]; got != "signed-windows-legacy" {
		t.Fatalf("legacy signed artifact name = %#v, want signed-windows-legacy", got)
	}
}

func TestWindowsSignPathReleaseDryRunUsesProductionVerificationWithoutPublishing(t *testing.T) {
	for _, tc := range []struct {
		path             string
		signedUploadStep string
	}{
		{path: ".github/workflows/build-windows.yml", signedUploadStep: "Upload signed Windows artifacts"},
		{path: ".github/workflows/build-windows-legacy.yml", signedUploadStep: "Upload signed Windows legacy artifact"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			input, ok := workflow.On.WorkflowDispatch.Inputs["signpath_release_dry_run"]
			if !ok {
				t.Fatal("workflow_dispatch must expose signpath_release_dry_run so the production certificate path can be tested without publishing")
			}
			if input.Required || input.Default != false || input.Type != "boolean" {
				t.Fatalf("signpath_release_dry_run = %#v, want optional boolean defaulting to false", input)
			}
			mustContain(t, input.Description, "without uploading signed output or publishing a GitHub release")

			signJob := mustJob(t, workflow, "sign")
			mustContain(t, signJob.If, "inputs.signpath_release_dry_run")
			if got := signJob.Env["SIGNPATH_SIGNING_POLICY_SLUG"]; got != "${{ inputs.signpath_test && 'test-signing' || 'release-signing' }}" {
				t.Fatalf("release dry-run policy route = %q, want release-signing whenever signpath_test is false", got)
			}
			if got := signJob.Env["SIGNPATH_TEST"]; got != "${{ inputs.signpath_test && 'true' || 'false' }}" {
				t.Fatalf("release dry-run verification mode = %q, want production verification whenever signpath_test is false", got)
			}
			uploadSigned := mustStepNamed(t, signJob, tc.signedUploadStep)
			if uploadSigned.If != "${{ !inputs.signpath_release_dry_run }}" {
				t.Fatalf("release dry-run signed artifact upload if = %q, want production-signed dry-run output to remain inside the job", uploadSigned.If)
			}

			releaseJob := mustJob(t, workflow, "release")
			mustContain(t, releaseJob.If, "!inputs.signpath_release_dry_run")
		})
	}
}

type signPathArtifactConfiguration struct {
	XMLName xml.Name           `xml:"artifact-configuration"`
	ZIP     signPathZIPElement `xml:"zip-file"`
}

type signPathZIPElement struct {
	PEFiles []signPathPEFile `xml:"pe-file"`
}

type signPathPEFile struct {
	Path string                   `xml:"path,attr"`
	Sign signPathAuthenticodeSign `xml:"authenticode-sign"`
}

type signPathAuthenticodeSign struct {
	HashAlgorithm  string `xml:"hash-algorithm,attr"`
	Description    string `xml:"description,attr"`
	DescriptionURL string `xml:"description-url,attr"`
}

func mustAllowOnlySignPathElements(t *testing.T, content, namespace string, wantFiles []string) {
	t.Helper()

	decoder := xml.NewDecoder(strings.NewReader(content))
	stack := make([]xml.Name, 0, 4)
	counts := make(map[string]int)
	peIndex := 0

	checkAttributes := func(element xml.StartElement, want map[string]string, allowDefaultNamespace bool) {
		t.Helper()

		got := make(map[string]string)
		for _, attribute := range element.Attr {
			if allowDefaultNamespace && attribute.Name.Space == "" && attribute.Name.Local == "xmlns" {
				if attribute.Value != namespace {
					t.Fatalf("%s default namespace = %q, want %q", element.Name.Local, attribute.Value, namespace)
				}
				continue
			}
			if attribute.Name.Space != "" {
				t.Fatalf("%s has unexpected namespaced attribute %s:%s", element.Name.Local, attribute.Name.Space, attribute.Name.Local)
			}
			got[attribute.Name.Local] = attribute.Value
		}
		if len(got) != len(want) {
			t.Fatalf("%s attributes = %#v, want exactly %#v", element.Name.Local, got, want)
		}
		for name, value := range want {
			if got[name] != value {
				t.Fatalf("%s attribute %s = %q, want %q", element.Name.Local, name, got[name], value)
			}
		}
	}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode SignPath XML token: %v", err)
		}

		switch token := token.(type) {
		case xml.StartElement:
			if token.Name.Space != namespace {
				t.Fatalf("element %s namespace = %q, want %q", token.Name.Local, token.Name.Space, namespace)
			}
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1].Local
			}
			counts[token.Name.Local]++
			switch token.Name.Local {
			case "artifact-configuration":
				if parent != "" || counts[token.Name.Local] != 1 {
					t.Fatal("artifact-configuration must be the single root element")
				}
				checkAttributes(token, map[string]string{}, true)
			case "zip-file":
				if parent != "artifact-configuration" || counts[token.Name.Local] != 1 {
					t.Fatal("zip-file must be the single artifact-configuration child")
				}
				checkAttributes(token, map[string]string{}, false)
			case "pe-file":
				if parent != "zip-file" || peIndex >= len(wantFiles) {
					t.Fatalf("unexpected pe-file at index %d", peIndex)
				}
				checkAttributes(token, map[string]string{"path": wantFiles[peIndex]}, false)
				peIndex++
			case "authenticode-sign":
				if parent != "pe-file" || counts[token.Name.Local] > len(wantFiles) {
					t.Fatal("each pe-file must contain one authenticode-sign directive")
				}
				checkAttributes(token, map[string]string{
					"hash-algorithm": "sha256",
				}, false)
			default:
				t.Fatalf("unexpected SignPath artifact configuration element %q", token.Name.Local)
			}
			stack = append(stack, token.Name)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != token.Name {
				t.Fatalf("unexpected closing element %q", token.Name.Local)
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if strings.TrimSpace(string(token)) != "" {
				t.Fatalf("unexpected text in SignPath artifact configuration: %q", string(token))
			}
		case xml.ProcInst:
			if token.Target != "xml" {
				t.Fatalf("unexpected XML processing instruction %q", token.Target)
			}
		case xml.Directive:
			t.Fatalf("unexpected XML directive %q", string(token))
		}
	}

	if len(stack) != 0 || counts["artifact-configuration"] != 1 || counts["zip-file"] != 1 || peIndex != len(wantFiles) || counts["authenticode-sign"] != len(wantFiles) {
		t.Fatalf("SignPath XML tree counts = %#v, PE files = %d/%d", counts, peIndex, len(wantFiles))
	}
}

func TestSignPathArtifactConfigurationsAllowlistOnlyReleaseExecutables(t *testing.T) {
	const namespace = "http://signpath.io/artifact-configuration/v1"

	for _, tc := range []struct {
		path      string
		wantFiles []string
	}{
		{path: "dist/signpath/windows-binaries.xml", wantFiles: []string{"Picocrypt-NG-portable.exe", "Picocrypt-NG-cli.exe"}},
		{path: "dist/signpath/windows-uninstaller.xml", wantFiles: []string{"Uninstall.exe"}},
		{path: "dist/signpath/windows-installer.xml", wantFiles: []string{"Picocrypt-NG-Setup.exe"}},
		{path: "dist/signpath/windows-legacy-cli.xml", wantFiles: []string{"Picocrypt-NG-cli-Legacy.exe"}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			content := mustReadRepoFile(t, tc.path)
			mustAllowOnlySignPathElements(t, content, namespace, tc.wantFiles)

			var configuration signPathArtifactConfiguration
			if err := xml.Unmarshal([]byte(content), &configuration); err != nil {
				t.Fatalf("parse SignPath artifact configuration: %v", err)
			}
			if configuration.XMLName.Space != namespace {
				t.Fatalf("artifact configuration namespace = %q, want %q", configuration.XMLName.Space, namespace)
			}
			if len(configuration.ZIP.PEFiles) != len(tc.wantFiles) {
				t.Fatalf("PE file count = %d, want %d exact release files", len(configuration.ZIP.PEFiles), len(tc.wantFiles))
			}
			for i, wantFile := range tc.wantFiles {
				pe := configuration.ZIP.PEFiles[i]
				if pe.Path != wantFile {
					t.Fatalf("PE file %d path = %q, want %q", i, pe.Path, wantFile)
				}
				if pe.Sign.HashAlgorithm != "sha256" || pe.Sign.Description != "" || pe.Sign.DescriptionURL != "" {
					t.Fatalf("PE file %q Authenticode settings = %#v, want sha256 with subscription-managed identity", pe.Path, pe.Sign)
				}
			}
		})
	}
}

func TestLinuxUPXDownloadsRemainChecksumGated(t *testing.T) {
	for _, path := range []string{
		".github/workflows/build-linux.yml",
		".github/workflows/pr-test-build-linux.yml",
	} {
		content := mustReadWorkflow(t, path)
		mustContain(t, content, "upx_sha256:")
		mustContain(t, content, "sha256sum --check --strict --status")
	}
}

func TestLinuxPRGatesRequireEveryNativeTestGroup(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-linux.yml")
	gate := mustJob(t, workflow, "pr-test-build-linux")
	if gate.If != "${{ always() && !cancelled() }}" {
		t.Fatalf("Linux aggregate if = %q, want cancellation-aware always gate", gate.If)
	}

	if gate.Needs != "build" {
		t.Fatalf("Linux aggregate needs = %#v, want build matrix", gate.Needs)
	}
	build := mustJob(t, workflow, "build")
	if build.Needs != "tests" || build.If != "${{ always() && !cancelled() }}" || build.Name != "pr-test-build-linux-${{ matrix.arch }}" {
		t.Fatalf("native build must retain its check names and fail explicitly after failed test groups: %+v", build)
	}
	buildCheck := mustStepNamed(t, build, "Require all native Linux test groups to pass")
	if build.Steps[0].Name != buildCheck.Name || buildCheck.If != "" ||
		(build.ContinueOnError != nil && build.ContinueOnError != false) ||
		(buildCheck.ContinueOnError != nil && buildCheck.ContinueOnError != false) {
		t.Fatal("native build must fail immediately when a required test group fails")
	}
	mustContainInOrder(t, buildCheck.Run, `if [ "${{ needs.tests.result }}" != "success" ]; then`, "exit 1")
	tests := mustJob(t, workflow, "tests")
	if tests.If != "" || tests.Strategy.FailFast == nil || *tests.Strategy.FailFast || (tests.ContinueOnError != nil && tests.ContinueOnError != false) {
		t.Fatal("all native test groups must execute and propagate failures")
	}
	lanes := tests.Strategy.Matrix.Include
	if len(lanes) != 3 || lanes[0].Arch != "amd64" || lanes[0].Runner != "ubuntu-24.04" || lanes[0].Shard != 0 ||
		lanes[1].Arch != "amd64" || lanes[1].Runner != "ubuntu-24.04" || lanes[1].Shard != 1 ||
		lanes[2].Arch != "arm64" || lanes[2].Runner != "ubuntu-24.04-arm" || lanes[2].Shard != 0 {
		t.Fatalf("native Linux lanes = %+v, want both AMD64 race shards and native ARM64", lanes)
	}

	check := mustStepNamed(t, gate, "Require all Linux matrix jobs to pass")
	mustContainInOrder(t, check.Run,
		`if [ "${{ needs.build.result }}" != "success" ]; then`,
		`echo "Linux matrix result: ${{ needs.build.result }}"`,
		"exit 1",
	)
}

func TestLinuxWorkflowsBoundRaceParallelismAndSelectOnlyCLIIntegration(t *testing.T) {
	for _, path := range []string{
		".github/workflows/build-linux.yml",
		".github/workflows/pr-test-build-linux.yml",
	} {
		t.Run(path, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, path)
			build := mustJob(t, workflow, "build")
			testStep := mustStepNamed(t, build, "Run tests")
			testRun := testStep.Run
			raceSelector := "./..."
			if path == ".github/workflows/pr-test-build-linux.yml" {
				raceStep := mustStepNamed(t, mustJob(t, workflow, "tests"), "Run native tests")
				if raceStep.Env["SHARD_INDEX"] != "${{ matrix.shard }}" {
					t.Fatal("native race shard selection must follow its matrix index")
				}
				if raceStep.If != "" || (raceStep.ContinueOnError != nil && raceStep.ContinueOnError != false) {
					t.Fatal("native test execution must be unconditional and propagate failures")
				}
				if testStep.If != "matrix.arch == 'amd64'" || (testStep.ContinueOnError != nil && testStep.ContinueOnError != false) ||
					!strings.Contains(testStep.Run, "-count=1") {
					t.Fatal("the native AMD64 CLI integration must execute uncached and propagate failures")
				}
				for _, required := range []string{
					"set -euo pipefail",
					"CGO_ENABLED=1 go list -race -tags migrated_fynedo ./... | LC_ALL=C sort",
					"if [ -z \"$packages\" ]; then",
					"index % 2 == SHARD_INDEX",
					"selected+=(\"$package\")",
					"if (( ${#selected[@]} == 0 )); then",
					"PICOCRYPT_RUN_CLI_INTEGRATION=1 CGO_ENABLED=1 go test -v -count=1 -tags migrated_fynedo -p 1 -timeout 15m ./...",
				} {
					mustContain(t, raceStep.Run, required)
				}
				testRun = raceStep.Run + "\n" + testRun
				raceSelector = `"${selected[@]}"`
			}

			raceLineIndex := -1
			integrationLineIndex := -1
			raceLineCount := 0
			integrationLineCount := 0
			for lineIndex, line := range strings.Split(testRun, "\n") {
				if strings.Contains(line, "go test") && strings.Contains(line, "-race") {
					if path == ".github/workflows/pr-test-build-linux.yml" && !strings.Contains(line, "-count=1") {
						t.Fatal("native PR race shards must execute against the current runner")
					}
					raceLineCount++
					raceLineIndex = lineIndex
					for _, required := range []string{"-p 1", "-timeout 15m", raceSelector} {
						if !strings.Contains(line, required) {
							t.Fatalf("Linux race test line %q is missing %q", strings.TrimSpace(line), required)
						}
					}
				}
				if strings.Contains(line, "PICOCRYPT_RUN_CLI_INTEGRATION=1") &&
					strings.Contains(line, "go test") &&
					strings.Contains(line, "./internal/cli/...") {
					integrationLineCount++
					integrationLineIndex = lineIndex
					for _, required := range []string{"-timeout 15m", "-run '^TestCLIIntegration$'", "./internal/cli/..."} {
						if !strings.Contains(line, required) {
							t.Fatalf("Linux CLI integration line %q is missing %q", strings.TrimSpace(line), required)
						}
					}
					if strings.Contains(line, "-race") {
						t.Fatalf("Linux CLI integration line must not use -race: %q", strings.TrimSpace(line))
					}
				}
			}
			if raceLineCount != 1 {
				t.Fatalf("Linux Run tests race line count = %d, want exactly 1", raceLineCount)
			}
			if integrationLineCount != 1 {
				t.Fatalf("Linux Run tests CLI integration line count = %d, want exactly 1", integrationLineCount)
			}
			if integrationLineIndex <= raceLineIndex {
				t.Fatal("Linux CLI integration line must follow the race test line")
			}
		})
	}
}

func TestMacOSWorkflowsRunCLIInputContract(t *testing.T) {
	const raceCommand = "go test -v -race -p 1 -timeout 15m ./internal/encoding/... ./internal/fileops/... ./internal/header/... ./internal/keyfile/... ./internal/util/..."
	const contractCommand = "go test -v -count=1 -p 1 -timeout 15m -run '^TestCLIInputContract$' ./internal/cli/..."

	for _, tc := range []struct {
		path string
		job  string
	}{
		{path: ".github/workflows/build-macos.yml", job: "build"},
		{path: ".github/workflows/pr-test-build-macos.yml", job: "pr-test-build-macos"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			testStep := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job), "Run tests")

			raceLineIndex := -1
			contractLineIndex := -1
			contractLineCount := 0
			cliTestLineCount := 0
			for lineIndex, line := range strings.Split(testStep.Run, "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "go test") && !strings.Contains(line, "-p 1") {
					t.Fatalf("macOS KDF-heavy package commands must be serialized: %q", line)
				}
				if line == raceCommand {
					raceLineIndex = lineIndex
				}
				isCLITestLine := false
				if strings.Contains(line, "go test") {
					for _, field := range strings.Fields(line) {
						if field == "./internal/cli" || field == "./internal/cli/..." {
							isCLITestLine = true
							break
						}
					}
				}
				if isCLITestLine {
					cliTestLineCount++
					if strings.Contains(line, "PICOCRYPT_RUN_CLI_INTEGRATION") {
						t.Fatalf("macOS CLI test line must not set the integration gate: %q", line)
					}
					if strings.Contains(line, "-race") {
						t.Fatalf("macOS CLI test line must not use -race: %q", line)
					}
					if line != contractCommand {
						t.Fatalf("macOS CLI test line = %q, want only %q", line, contractCommand)
					}
					contractLineCount++
					contractLineIndex = lineIndex
				}
			}
			if raceLineIndex < 0 {
				t.Fatalf("macOS Run tests step is missing selected race command %q", raceCommand)
			}
			if cliTestLineCount != 1 {
				t.Fatalf("macOS CLI test line count = %d, want exactly 1", cliTestLineCount)
			}
			if contractLineCount != 1 {
				t.Fatalf("macOS CLI input contract line count = %d, want exactly 1", contractLineCount)
			}
			if contractLineIndex <= raceLineIndex {
				t.Fatal("macOS CLI input contract line must follow the selected race command")
			}
		})
	}
}

func TestMacOSPRAggregateGateRequiresAllTestGroups(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-macos.yml")
	gate := mustJob(t, workflow, "pr-test-build-macos")
	if gate.Needs != "pcv3-tests" || gate.If != "${{ always() }}" {
		t.Fatalf("macOS gate needs=%v if=%q; want all test groups checked even after cancellation", gate.Needs, gate.If)
	}
	check := mustStepNamed(t, gate, "Require all macOS test groups to pass")
	if len(gate.Steps) == 0 || gate.Steps[0].Name != check.Name {
		t.Fatal("macOS build must check the test result before any other step")
	}
	mustContainInOrder(t, check.Run,
		`if [ "${{ needs.pcv3-tests.result }}" != "success" ]; then`,
		"exit 1",
	)
}

func TestWindowsWorkflowsUseApprovedResourceHacker528(t *testing.T) {
	const expectedHash = "b611be2f35cb44efd1c29df03e7ebe62bd556a500585680e1afa5e073eaf1756"
	for _, tc := range []struct {
		path string
		job  string
	}{
		{path: ".github/workflows/build-windows.yml", job: "build"},
		{path: ".github/workflows/pr-test-build-windows.yml", job: "pr-test-build-windows"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			job := mustJob(t, workflow, tc.job)
			if got := job.Env["RESHACKER_SHA256"]; got != expectedHash {
				t.Fatalf("RESHACKER_SHA256 = %q, want %q", got, expectedHash)
			}
			resourceStep := mustStepNamed(t, job, "Add icon, manifest, and version info")
			if resourceStep.Shell != "pwsh" {
				t.Fatalf("Resource Hacker step shell = %q, want pwsh", resourceStep.Shell)
			}
			mustContain(t, resourceStep.Run, "https://www.angusj.com/resourcehacker/reshacker_setup.exe")
			mustNotContain(t, resourceStep.Run, "github.com/user-attachments")
			mustNotContain(t, resourceStep.Run, "reshacker_setup.zip")
			mustNotContain(t, resourceStep.Run, "Expand-Archive")
			mustContainActiveLines(t, resourceStep.Run,
				"if ($installer.ExitCode -ne 0) {",
				`throw "Resource Hacker installer failed with exit code $($installer.ExitCode)"`,
				"}",
				"if (-not (Test-Path -LiteralPath $env:P -PathType Leaf)) {",
				`throw "Resource Hacker executable was not installed at $env:P"`,
				"}",
				"function Invoke-ResourceHacker {",
			)
		})
	}
}

func TestWindowsDownloadsAreBoundedAndChecksumGated(t *testing.T) {
	const (
		resourceHackerURL = "https://www.angusj.com/resourcehacker/reshacker_setup.exe"
		upxURL            = "https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-win64.zip"
	)
	cases := []struct {
		name     string
		path     string
		job      string
		step     string
		output   string
		url      string
		hashEnv  string
		consumer string
	}{
		{
			name: "release-resource-hacker", path: ".github/workflows/build-windows.yml",
			job: "build", step: "Add icon, manifest, and version info",
			output: "reshacker_setup.exe", url: resourceHackerURL,
			hashEnv: "RESHACKER_SHA256", consumer: "$installer = Start-Process `",
		},
		{
			name: "pr-resource-hacker", path: ".github/workflows/pr-test-build-windows.yml",
			job: "pr-test-build-windows", step: "Add icon, manifest, and version info",
			output: "reshacker_setup.exe", url: resourceHackerURL,
			hashEnv: "RESHACKER_SHA256", consumer: "$installer = Start-Process `",
		},
		{
			name: "release-upx", path: ".github/workflows/build-windows.yml",
			job: "build", step: "Compress with upx",
			output: "upx.zip", url: upxURL,
			hashEnv: "UPX_SHA256", consumer: "Expand-Archive -DestinationPath upx upx.zip",
		},
		{
			name: "pr-upx", path: ".github/workflows/pr-test-build-windows.yml",
			job: "pr-test-build-windows", step: "Compress with upx",
			output: "upx.zip", url: upxURL,
			hashEnv: "UPX_SHA256", consumer: "Expand-Archive -DestinationPath upx upx.zip",
		},
		{
			name: "legacy-release-upx", path: ".github/workflows/build-windows-legacy.yml",
			job: "build", step: "Compress with upx",
			output: "upx.zip", url: upxURL,
			hashEnv: "UPX_SHA256", consumer: "Expand-Archive -DestinationPath upx upx.zip",
		},
		{
			name: "legacy-pr-upx", path: ".github/workflows/pr-test-build-windows-legacy.yml",
			job: "pr-test-build-windows-legacy", step: "Compress with upx",
			output: "upx.zip", url: upxURL,
			hashEnv: "UPX_SHA256", consumer: "Expand-Archive -DestinationPath upx upx.zip",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			step := mustStepNamed(t, mustJob(t, workflow, tc.job), tc.step)
			if step.Shell != "pwsh" {
				t.Fatalf("download step shell = %q, want pwsh", step.Shell)
			}
			mustUseBoundedCurlDownload(t, step.Run, tc.output, tc.url, tc.hashEnv, tc.consumer)
		})
	}
}

func TestWindowsResourceEditingWaitsAndFailsLoud(t *testing.T) {
	for _, tc := range []struct {
		path string
		job  string
	}{
		{path: ".github/workflows/build-windows.yml", job: "build"},
		{path: ".github/workflows/pr-test-build-windows.yml", job: "pr-test-build-windows"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			resourceStep := mustStepNamed(t, mustJob(t, workflow, tc.job), "Add icon, manifest, and version info")

			mustNotContain(t, resourceStep.Run, "Start-Sleep")
			mustNotContain(t, resourceStep.Run, "Invoke-Expression")
			if got := strings.Count(resourceStep.Run, "Start-Process"); got != 2 {
				t.Fatalf("Resource Hacker step Start-Process count = %d, want installer and CLI invocations", got)
			}
			mustContainInOrder(t, resourceStep.Run,
				"$installer = Start-Process",
				`-FilePath "reshacker_setup.exe"`,
				`-ArgumentList "/SILENT"`,
				"-Wait -PassThru",
				"if ($installer.ExitCode -ne 0)",
				"function Invoke-ResourceHacker",
				"$process = Start-Process",
				"-FilePath $env:P",
				`-ArgumentList ($Arguments + @("-log", "CONSOLE"))`,
				"-Wait -PassThru",
				"if ($process.ExitCode -ne 0)",
				"Get-Item -LiteralPath $ExpectedOutput -ErrorAction Stop",
				"if ($output.Length -eq 0)",
			)
			mustContainInOrder(t, resourceStep.Run,
				`-ExpectedOutput "src/2.exe"`,
				`-ExpectedOutput "src/3.exe"`,
				`-ExpectedOutput "src/4.exe"`,
				`-ExpectedOutput "resources.res"`,
				`-ExpectedOutput "src/5.exe"`,
			)
		})
	}
}

func TestLinuxDebPackagingDoesNotUseExternalScaffold(t *testing.T) {
	for _, path := range []string{
		".github/workflows/build-linux.yml",
		".github/workflows/pr-test-build-linux.yml",
	} {
		t.Run(path, func(t *testing.T) {
			content := mustReadWorkflow(t, path)
			mustNotContain(t, content, "github.com/user-attachments/files/21703014/Picocrypt-NG.zip")
			mustContain(t, content, "librsvg2-bin")
			mustContain(t, content, "xmllint --noout images/key.svg")
			mustContain(t, content, `cat > "$package_root/DEBIAN/control"`)
			mustContain(t, content, `install -d "$package_root/usr/share/icons/hicolor/scalable/apps"`)
			mustContain(t, content, `install -m 0644 images/key.svg`)
			mustContain(t, content, `"$package_root/usr/share/icons/hicolor/scalable/apps/io.github.picocrypt_ng.Picocrypt-NG.svg"`)
			mustContain(t, content, `install -m 0644 dist/linux/io.github.picocrypt_ng.Picocrypt-NG.desktop`)
			mustContain(t, content, `sed -i 's|^Exec=.*|Exec=/usr/bin/picocrypt-ng-gui %f|'`)
			mustNotContain(t, content, `s|^Icon=`)
			mustNotContain(t, content, `s|^StartupWMClass=`)
			mustContain(t, content, `rsvg-convert --format png --width "$size" --height "$size" --output "$app_icon_png" images/key.svg`)
			mustContain(t, content, `dpkg-deb -c "${package_root}.deb" | grep -E 'usr/share/icons/hicolor/scalable/apps/io\.github\.picocrypt_ng\.Picocrypt-NG\.svg' >/dev/null`)
			for _, size := range []string{"16", "32", "48", "64", "128", "256"} {
				mustContain(t, content, `dpkg-deb -c "${package_root}.deb" | grep -E 'usr/share/icons/hicolor/`+size+`x`+size+`/apps/io\.github\.picocrypt_ng\.Picocrypt-NG\.png' >/dev/null`)
			}
		})
	}
}

func TestSnapcraftWorkflowSmokeTestsInstalledSnap(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	buildJob := mustJob(t, workflow, "build-snapcraft")
	smokeStep := mustStepNamed(t, buildJob, "Smoke-test snap command")
	if smokeStep.Env["LANG"] != "C.UTF-8" {
		t.Fatalf("snap smoke-test LANG = %q, want C.UTF-8", smokeStep.Env["LANG"])
	}
	if smokeStep.Env["LC_ALL"] != "C.UTF-8" {
		t.Fatalf("snap smoke-test LC_ALL = %q, want C.UTF-8", smokeStep.Env["LC_ALL"])
	}
	mustContain(t, smokeStep.Run, "sudo snap install --dangerous out/*.snap")
	mustContain(t, smokeStep.Run, "snap run picocrypt-ng --version")
}

func TestAndroidPRWorkflowRunsBoundedDeviceSuites(t *testing.T) {
	const (
		runner    = "ReactiveCircus/android-emulator-runner@a421e43855164a8197daf9d8d40fe71c6996bb0d"
		command   = "bash ../.github/scripts/run-android-device-tests.sh "
		roundtrip = "io.github.picocrypt_ng.picocrypt_ng.OperationManagerIntegrationTest#encrypt_retry_save_then_decrypt_recovers_the_original_bytes"
	)

	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-android.yml")
	job := mustJob(t, workflow, "pr-test-build-android")
	wantByAPI := map[int]struct {
		arch     string
		diskSize string
		memory   string
		target   string
		script   string
	}{
		// Storage and staging must work on Picocrypt NG's Android 8 compatibility floor.
		26: {
			arch:     "x86_64",
			diskSize: "2048M",
			memory:   "3583",
			target:   "google_apis",
			script:   command + "26 " + roundtrip + " io.github.picocrypt_ng.picocrypt_ng.FileCopyServiceTest io.github.picocrypt_ng.picocrypt_ng.StagingServiceInstrumentedTest io.github.picocrypt_ng.picocrypt_ng.GoBridgeProgressMappingTest io.github.picocrypt_ng.picocrypt_ng.OperationNotificationTest io.github.picocrypt_ng.picocrypt_ng.Pcv3DeviceBehaviorTest io.github.picocrypt_ng.picocrypt_ng.ProviderCopyBoundaryTest io.github.picocrypt_ng.picocrypt_ng.ui.components.KeyfileMetadataBoundaryTest io.github.picocrypt_ng.picocrypt_ng.MainActivityStateTest",
		},
		// Activity security and Compose state must work on the target-SDK runtime.
		36: {
			arch:     "x86_64",
			diskSize: "2048M",
			memory:   "6144",
			target:   "default",
			script:   command + "36 " + roundtrip + " io.github.picocrypt_ng.picocrypt_ng.GoBridgeProgressMappingTest io.github.picocrypt_ng.picocrypt_ng.MainActivityUITest io.github.picocrypt_ng.picocrypt_ng.OperationNotificationTest io.github.picocrypt_ng.picocrypt_ng.Pcv3DeviceBehaviorTest io.github.picocrypt_ng.picocrypt_ng.Pcv3UiContractTest io.github.picocrypt_ng.picocrypt_ng.ui.components.PasswordCardTest io.github.picocrypt_ng.picocrypt_ng.ui.components.KeyfileCardWriterPolicyTest io.github.picocrypt_ng.picocrypt_ng.ui.components.ProgressCardTest io.github.picocrypt_ng.picocrypt_ng.ui.components.KeyfileClearLifecycleTest io.github.picocrypt_ng.picocrypt_ng.ui.components.WorkButtonTest io.github.picocrypt_ng.picocrypt_ng.ProviderCopyBoundaryTest io.github.picocrypt_ng.picocrypt_ng.ui.components.KeyfileMetadataBoundaryTest io.github.picocrypt_ng.picocrypt_ng.MainActivityStateTest",
		},
	}
	seen := make(map[int]struct{}, len(wantByAPI))

	for _, step := range job.Steps {
		if !strings.HasPrefix(step.Uses, "ReactiveCircus/android-emulator-runner@") {
			continue
		}
		if step.Uses != runner {
			t.Fatalf("Android emulator runner = %q, want exact reviewed SHA %q", step.Uses, runner)
		}

		apiLevel, ok := step.With["api-level"].(int)
		if !ok {
			t.Fatalf("step %q api-level = %#v, want integer", step.Name, step.With["api-level"])
		}
		want, ok := wantByAPI[apiLevel]
		if !ok {
			t.Fatalf("unexpected Android emulator API level %d", apiLevel)
		}
		if _, duplicate := seen[apiLevel]; duplicate {
			t.Fatalf("Android emulator API level %d is configured more than once", apiLevel)
		}
		seen[apiLevel] = struct{}{}

		if got := step.With["target"]; got != want.target {
			t.Errorf("API %d target = %#v, want %s", apiLevel, got, want.target)
		}
		if got := step.With["arch"]; got != want.arch {
			t.Errorf("API %d arch = %#v, want %s", apiLevel, got, want.arch)
		}
		if got := step.With["disk-size"]; got != want.diskSize {
			t.Errorf("API %d disk-size = %#v, want %s", apiLevel, got, want.diskSize)
		}
		emulatorOptions, ok := step.With["emulator-options"].(string)
		if !ok {
			t.Fatalf("API %d emulator-options = %#v, want string", apiLevel, step.With["emulator-options"])
		}
		mustMatch(t, emulatorOptions, `(?:^|\s)-memory\s+`+want.memory+`(?:\s|$)`)
		if step.TimeoutMinutes != 15 {
			t.Errorf("API %d timeout-minutes = %d, want 15", apiLevel, step.TimeoutMinutes)
		}
		if got := step.With["working-directory"]; got != "android" {
			t.Errorf("API %d working-directory = %#v, want android", apiLevel, got)
		}
		if got := step.With["script"]; got != want.script {
			t.Errorf("API %d script = %#v, want exact on-device suite %q", apiLevel, got, want.script)
		}
		if step.If != "" {
			t.Errorf("API %d step if = %q, want unconditional compatibility gate", apiLevel, step.If)
		}
		if step.ContinueOnError != nil && step.ContinueOnError != false {
			t.Errorf("API %d continue-on-error = %#v, want absent or false", apiLevel, step.ContinueOnError)
		}
	}

	for apiLevel := range wantByAPI {
		if _, ok := seen[apiLevel]; !ok {
			t.Errorf("missing on-device suite for API %d", apiLevel)
		}
	}
}

func TestAndroidPRWorkflowBuildsReleaseWithR8(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-android.yml")
	job := mustJob(t, workflow, "pr-test-build-android")
	if job.If != "" {
		t.Fatalf("PR Android job if = %q, want unconditional release-build gate", job.If)
	}
	if job.ContinueOnError != nil && job.ContinueOnError != false {
		t.Fatalf("PR Android job continue-on-error = %#v, want absent or false", job.ContinueOnError)
	}

	releaseStep := mustStepNamed(t, job, "Build Release APK")
	if got := strings.TrimSpace(releaseStep.Run); got != "./gradlew :app:assembleRelease" {
		t.Fatalf("release build step run = %q, want exact blocking release assemble command", got)
	}
	if releaseStep.If != "" {
		t.Fatalf("release build step if = %q, want unconditional PR gate", releaseStep.If)
	}
	if releaseStep.ContinueOnError != nil && releaseStep.ContinueOnError != false {
		t.Fatalf("release build step continue-on-error = %#v, want absent or false", releaseStep.ContinueOnError)
	}
	if releaseStep.WorkingDirectory != "android" {
		t.Fatalf("release build step working-directory = %q, want android", releaseStep.WorkingDirectory)
	}

	appGradle := mustReadRepoFile(t, "android/app/build.gradle.kts")
	mustContain(t, appGradle, "isMinifyEnabled = true")
	mustContain(t, appGradle, "isShrinkResources = true")
}

func TestAndroidBuildWorkflowsRunFullLint(t *testing.T) {
	testCases := []struct {
		name string
		path string
		job  string
	}{
		{name: "pull request", path: ".github/workflows/pr-test-build-android.yml", job: "pr-test-build-android"},
		{name: "release", path: ".github/workflows/build-android.yml", job: "build"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			job := mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job)
			lintStep := mustStepNamed(t, job, "Run Android Lint")
			if got := strings.TrimSpace(lintStep.Run); got != "./gradlew lint" {
				t.Fatalf("Android lint step run = %q, want exact full lint command", got)
			}
			if lintStep.WorkingDirectory != "android" {
				t.Fatalf("Android lint step working-directory = %q, want android", lintStep.WorkingDirectory)
			}
			if lintStep.If != "" {
				t.Fatalf("Android lint step if = %q, want unconditional gate", lintStep.If)
			}
			if lintStep.ContinueOnError != nil && lintStep.ContinueOnError != false {
				t.Fatalf("Android lint step continue-on-error = %#v, want absent or false", lintStep.ContinueOnError)
			}
		})
	}
}

func TestAndroidReleaseWorkflowKeepsSigningSecretsOutOfBuildJob(t *testing.T) {
	const path = ".github/workflows/build-android.yml"
	workflow := mustReadWorkflowDoc(t, path)
	buildJob := mustJob(t, workflow, "build")
	signJob := mustJob(t, workflow, "sign")
	releaseJob := mustJob(t, workflow, "release")
	mustStepNamed(t, buildJob, "Build Go Mobile AAR")
	mustStepNamed(t, buildJob, "Run Unit Tests")
	mustStepNamed(t, buildJob, "Build unsigned release APKs")
	if signJob.Needs != "build" || fmt.Sprint(releaseJob.Needs) != "[build sign]" {
		t.Fatalf("Android signing/publication dependencies = %#v/%#v, want build then [build sign]", signJob.Needs, releaseJob.Needs)
	}
	if signJob.If != "${{ github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.publish_release }}" || releaseEnvironmentName(signJob.Environment) != "release" {
		t.Fatal("Android key use must require explicit release dispatch on main and the release environment")
	}
	for name, job := range workflow.Jobs {
		if name != "build" && name != "sign" && name != "release" {
			t.Fatalf("unreviewed Android release job %q", name)
		}
		if job.Permissions == nil {
			t.Fatalf("Android %s job must declare its permissions explicitly", name)
		}
		wantPermissions := map[string]string{"contents": "read"}
		if name == "release" {
			wantPermissions = map[string]string{"contents": "write", "id-token": "write", "attestations": "write"}
		}
		if len(job.Permissions) != len(wantPermissions) {
			t.Fatalf("Android %s has permissions outside its reviewed role: %#v", name, job.Permissions)
		}
		for key, value := range wantPermissions {
			mustEffectivePermission(t, workflow, job, key, value)
		}
		if name != "release" {
			mustEffectivePermission(t, workflow, job, "contents", "read")
			for _, permission := range []string{"id-token", "attestations", "actions", "packages"} {
				mustEffectivePermission(t, workflow, job, permission, "none")
			}
		} else {
			for _, permission := range []string{"contents", "id-token", "attestations"} {
				mustEffectivePermission(t, workflow, job, permission, "write")
			}
			mustEffectivePermission(t, workflow, job, "packages", "none")
		}
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/checkout@") && step.With["persist-credentials"] != false {
				t.Fatalf("Android %s checkout must not retain Git credentials", name)
			}
			if name == "sign" || name == "release" {
				if strings.HasPrefix(step.Uses, "actions/cache@") || strings.Contains(step.Run, "gradlew") || strings.Contains(step.Uses, "gradle/actions/") {
					t.Fatalf("Android %s must not execute Gradle/plugins or restore a build cache", name)
				}
			}
		}
	}
	signing := mustStepNamed(t, signJob, "Sign verified APKs with the offline SDK")
	expectedSecrets := map[string]string{
		"ANDROID_KEYSTORE_BASE64":   "${{ secrets.ANDROID_KEYSTORE_BASE64 }}",
		"ANDROID_KEYSTORE_PASSWORD": "${{ secrets.ANDROID_KEYSTORE_PASSWORD }}",
		"ANDROID_KEY_PASSWORD":      "${{ secrets.ANDROID_KEY_PASSWORD }}",
		"ANDROID_KEY_ALIAS":         "${{ secrets.ANDROID_KEY_ALIAS }}",
	}
	if len(signing.Env) != len(expectedSecrets) {
		t.Fatal("SDK signing must receive only the four scoped Android credentials")
	}
	for key, value := range expectedSecrets {
		if signing.Env[key] != value {
			t.Fatalf("SDK signing env %s = %q, want exact scoped secret", key, signing.Env[key])
		}
	}
	// Count all secret expressions, including bracket notation and unknown YAML
	// fields: the four explicit SDK env entries are the only permitted uses.
	if got := len(regexp.MustCompile(`\bsecrets\s*(?:\.|\[)`).FindAllString(mustReadWorkflow(t, path), -1)); got != len(expectedSecrets) {
		t.Fatalf("Android release contains %d secret references; only the four SDK env entries are permitted", got)
	}
	mustContainInOrder(t, signing.Run,
		"umask 077", `signing_temp=$(mktemp -d "$RUNNER_TEMP/android-signing.XXXXXX")`,
		"trap cleanup EXIT", `printf '%s' "$ANDROID_KEYSTORE_BASE64" | base64 --decode`,
		"unset ANDROID_KEYSTORE_BASE64", "java --enable-native-access=ALL-UNNAMED", "AndroidApkSigner")
	mustContain(t, signing.Run, `rm -rf -- "$signing_temp"`)
	mustContain(t, signing.Run, `if [ "$result" -ne 0 ]; then rm -rf -- signed-apks; fi`)
	mustContain(t, signing.Run, "private signing diagnostics withheld")
	for _, forbidden := range []string{"$GITHUB_ENV", "$GITHUB_OUTPUT", "$ANDROID_KEY_ALIAS\"", "gradlew", "curl", "sdkmanager", "javac"} {
		mustNotContain(t, signing.Run, forbidden)
	}
	compile := mustStepNamed(t, signJob, "Compile the SDK signing launcher before loading secrets")
	mustContain(t, compile.Run, `.github/scripts/AndroidApkSigner.java`)
	launcher := mustReadRepoFile(t, ".github/scripts/AndroidApkSigner.java")
	for _, required := range []string{`System.getenv("ANDROID_KEY_ALIAS")`, "ApkSignerTool.main", `"env:ANDROID_KEYSTORE_PASSWORD"`, `"env:ANDROID_KEY_PASSWORD"`, `"--alignment-preserved", "true"`, `"--v1-signing-enabled", "false"`, `"--v4-signing-enabled", "false"`} {
		mustContain(t, launcher, required)
	}
	download := mustStepNamed(t, signJob, "Download source-bound unsigned APKs")
	if download.With["artifact-ids"] != "${{ needs.build.outputs.artifact-id }}" || download.With["merge-multiple"] != true || download.With["path"] != "unsigned-release" {
		t.Fatal("Android signer must download only the immutable build-job artifact ID")
	}
	if buildJob.Outputs["artifact-id"] != "${{ steps.upload-unsigned.outputs.artifact-id }}" || signJob.Outputs["artifact-id"] != "${{ steps.upload-signed.outputs.artifact-id }}" {
		t.Fatal("Android artifact IDs must come directly from their own upload actions")
	}
	validate := mustStepNamed(t, signJob, "Validate unsigned signing inputs before loading secrets")
	for key, value := range map[string]string{"MANIFEST_SHA256": "${{ needs.build.outputs.manifest-sha256 }}", "AAR_SHA256": "${{ needs.build.outputs.aar-sha256 }}", "VERSION": "${{ needs.build.outputs.version }}", "VERSION_CODE": "${{ needs.build.outputs.version-code }}"} {
		if validate.Env[key] != value {
			t.Fatalf("unsigned signing input %s is not bound to the build-job output", key)
		}
	}
	for _, oracle := range []string{`test "$(git rev-parse HEAD)" = "$GITHUB_SHA"`, `test "$(<VERSION)" = "$VERSION"`, `"$MANIFEST_SHA256"`, ".source == $source", ".aarSha256 == $aar", `"$digest"`, "zipalign\" -c -P 16", "io.github.picocrypt_ng.picocrypt_ng unsigned"} {
		mustContain(t, validate.Run, oracle)
	}
	signedDownload := mustStepNamed(t, releaseJob, "Download verified signed APKs")
	if signedDownload.With["artifact-ids"] != "${{ needs.sign.outputs.artifact-id }}" || signedDownload.With["path"] != "out" || signedDownload.With["merge-multiple"] != true {
		t.Fatal("Android publication must use only the verified signer-job artifact ID")
	}
}

func TestAndroidBuildWorkflowsUseJDK21(t *testing.T) {
	for _, path := range []string{
		".github/workflows/build-android.yml",
		".github/workflows/pr-test-build-android.yml",
		".github/workflows/android-instrumented.yml",
	} {
		workflow := mustReadWorkflowDoc(t, path)
		for jobName, job := range workflow.Jobs {
			setupSteps := 0
			for _, step := range job.Steps {
				if !strings.HasPrefix(step.Uses, "actions/setup-java@") {
					continue
				}
				setupSteps++
				if got := step.With["distribution"]; got != "temurin" {
					t.Fatalf("%s job %s setup-java distribution = %#v, want temurin", path, jobName, got)
				}
				if got := step.With["java-version"]; got != "21" {
					t.Fatalf("%s job %s setup-java java-version = %#v, want 21", path, jobName, got)
				}
			}
			if path == ".github/workflows/build-android.yml" && jobName == "release" {
				if setupSteps != 0 {
					t.Fatal("Android publisher must not set up or execute the JVM build/signing toolchain")
				}
			} else if setupSteps != 1 {
				t.Fatalf("%s job %s has %d setup-java steps, want exactly one", path, jobName, setupSteps)
			}
		}
	}

	mustContain(t, mustReadRepoFile(t, "mise.toml"), `java = "temurin-21"`)

	buildScript := mustReadRepoFile(t, "android/build-app")
	mustContain(t, buildScript, `"$JAVA_MAJOR" != "21"`)
}

func TestAndroidReleasePublishesOnly64BitAPKNames(t *testing.T) {
	releaseWorkflow := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	prepare := mustStepNamed(t, mustJob(t, releaseWorkflow, "sign"), "Verify exact signed release APK contract")
	for _, artifact := range []string{
		"Picocrypt-NG-android-arm64-v8a.apk",
		"Picocrypt-NG-android-x86_64.apk",
		"Picocrypt-NG-android-universal.apk",
	} {
		mustContain(t, prepare.Run, artifact)
	}
	for _, removed := range []string{
		"Picocrypt-NG-android-armeabi-v7a.apk",
		"Picocrypt-NG-android-x86.apk",
	} {
		mustNotContain(t, prepare.Run, removed)
	}
}

func TestAndroidReleaseWorkflowsRunExactArtifactVerifier(t *testing.T) {
	verifierPath := filepath.Join(repoRoot(t), "android", "verify-release-apks.sh")
	info, err := os.Stat(verifierPath)
	if err != nil {
		t.Fatalf("stat Android release APK verifier: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("Android release APK verifier mode = %v, want executable", info.Mode().Perm())
	}
	verifier := mustReadRepoFile(t, "android/verify-release-apks.sh")
	// Keep Java native-access warnings out of the pinned apksigner diagnostic
	// without filtering stderr, which would weaken the fail-closed check.
	mustContain(t, verifier, `apksigner_command=("$APKSIGNER" -J-enable-native-access=ALL-UNNAMED)`)
	mustContain(t, verifier, `"${apksigner_command[@]}" verify --Werr --verbose --print-certs "$apk"`)

	for _, tc := range []struct {
		name, path, job, step, kind, directory string
	}{
		{"unsigned PR build", ".github/workflows/pr-test-build-android.yml", "pr-test-build-android", "Verify exact release APK contract", "unsigned", "android"},
		{"unsigned release build", ".github/workflows/build-android.yml", "build", "Verify exact unsigned release APK contract", "unsigned", "android"},
		{"signed release", ".github/workflows/build-android.yml", "sign", "Verify exact signed release APK contract", "signed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job), tc.step)
			if step.WorkingDirectory != tc.directory {
				t.Fatalf("verifier working-directory = %q, want %q", step.WorkingDirectory, tc.directory)
			}
			if tc.kind == "signed" {
				mustContainInOrder(t, step.Run, `android/verify-release-apks.sh signed-apks "$VERSION" "$VERSION_CODE" io.github.picocrypt_ng.picocrypt_ng signed`, "mkdir out", "cp signed-apks/app-arm64-v8a-release.apk", "cp signed-apks/app-x86_64-release.apk", "cp signed-apks/app-universal-release.apk")
				if step.Env["VERSION"] != "${{ needs.build.outputs.version }}" || step.Env["VERSION_CODE"] != "${{ needs.build.outputs.version-code }}" {
					t.Fatal("signed verifier must check source-bound build version metadata")
				}
			} else {
				wantRun := strings.Join([]string{`./verify-release-apks.sh \`, `  app/build/outputs/apk/release \`, `  "$ORG_GRADLE_PROJECT_PICOCRYPT_VERSION_NAME" \`, `  "$ORG_GRADLE_PROJECT_PICOCRYPT_VERSION_CODE" \`, `  io.github.picocrypt_ng.picocrypt_ng \`, `  unsigned`}, "\n")
				if strings.TrimSpace(step.Run) != wantRun {
					t.Fatalf("unsigned verifier = %q, want %q", step.Run, wantRun)
				}
			}
			if step.If != "" || (step.ContinueOnError != nil && step.ContinueOnError != false) {
				t.Fatal("APK contract verification must be unconditional and blocking")
			}
			anchor, present := step.Env["PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE"]
			if tc.kind == "signed" {
				if !present || anchor != "android/release-signing-cert-sha256.txt" {
					t.Fatal("signed verifier must use the tracked production certificate fingerprint")
				}
			} else if present {
				t.Fatal("unsigned verifier must not have a signing trust override")
			}
		})
	}
}

func TestAndroidReleaseSigningTrustAnchorAndPublicationOrder(t *testing.T) {
	const trustedDigest = "e2f2a971231aa0b86882c63b87b689c71632c6d55168b1ce856952d07f6172b7"
	if anchor := mustReadRepoFile(t, "android/release-signing-cert-sha256.txt"); anchor != trustedDigest+"\n" {
		t.Fatalf("Android signing trust anchor = %q, want exact production certificate SHA-256", anchor)
	}
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	for _, tc := range []struct {
		job   string
		steps []string
	}{
		{"build", []string{"Build Go Mobile AAR", "Run Unit Tests", "Run Android Lint", "Build unsigned release APKs", "Verify exact unsigned release APK contract", "Bind unsigned APKs to the source and AAR", "Upload unsigned release APKs"}},
		{"sign", []string{"Download source-bound unsigned APKs", "Validate unsigned signing inputs before loading secrets", "Compile the SDK signing launcher before loading secrets", "Sign verified APKs with the offline SDK", "Verify exact signed release APK contract", "Upload signed release APKs"}},
		{"release", []string{"Download verified signed APKs", "Get version tag", "Sign and attest artifacts", "Generate release notes", "Stage release assets"}},
	} {
		job := mustJob(t, workflow, tc.job)
		last := -1
		for _, name := range tc.steps {
			index := -1
			for i, step := range job.Steps {
				if step.Name == name {
					index = i
					if step.If != "" || (step.ContinueOnError != nil && step.ContinueOnError != false) {
						t.Fatalf("Android %s step %s must run unconditionally and block on failure", tc.job, name)
					}
					break
				}
			}
			if index <= last {
				t.Fatalf("Android %s step %s missing/out of order", tc.job, name)
			}
			last = index
		}
	}
}

func TestCurrentReleaseBodyContract(t *testing.T) {
	root := repoRoot(t)
	version := strings.TrimSpace(mustReadRepoFile(t, "VERSION"))
	command := exec.Command(
		"bash",
		filepath.Join(root, ".github/actions/release-body/gen-release-body.sh"),
		version,
		filepath.Join(root, "Changelog.md"),
		"-",
	)
	const sourceSHA = "0123456789abcdef0123456789abcdef01234567"
	command.Env = append(os.Environ(), "GITHUB_SHA="+sourceSHA)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("generate release body: %v\n%s", err, output)
	}

	body := string(output)
	mustContain(t, body, "## What's new in "+version)
	mustContain(t, body, "source_commit="+sourceSHA)
	for artifact, owner := range map[string]string{
		"Picocrypt-NG": "build-linux.yml", "Picocrypt-NG-cli": "build-linux.yml", "Picocrypt-NG.deb": "build-linux.yml",
		"Picocrypt-NG-arm64": "build-linux.yml", "Picocrypt-NG-cli-arm64": "build-linux.yml",
		"Picocrypt-NG.dmg": "build-macos.yml", "Picocrypt-NG-cli-macos": "build-macos.yml",
		"Picocrypt-NG-portable.exe": "build-windows.yml", "Picocrypt-NG-cli.exe": "build-windows.yml", "Picocrypt-NG-Setup.exe": "build-windows.yml",
		"Picocrypt-NG-cli-Legacy.exe":        "build-windows-legacy.yml",
		"Picocrypt-NG-android-arm64-v8a.apk": "build-android.yml", "Picocrypt-NG-android-x86_64.apk": "build-android.yml", "Picocrypt-NG-android-universal.apk": "build-android.yml",
		"Picocrypt-NG-" + version + "-x86_64.AppImage": "build-appimage.yml", "Picocrypt-NG-" + version + "-x86_64.AppImage.zsync": "build-appimage.yml",
		"picocrypt-ng_" + version + "_amd64.snap": "build-snapcraft.yml",
	} {
		mustContain(t, body, "  "+artifact+") workflow="+owner+" ;;")
	}
	mustContain(t, body, `identity="https://github.com/Picocrypt-NG/Picocrypt-NG/.github/workflows/$workflow@refs/heads/main"`)
	for _, restriction := range []string{`--certificate-identity "$identity"`, `--certificate-github-workflow-sha "$source_commit"`, "--certificate-github-workflow-ref refs/heads/main", "--certificate-github-workflow-repository Picocrypt-NG/Picocrypt-NG", `--cert-identity "$identity"`, `--signer-digest "$source_commit"`, "--source-ref refs/heads/main", `--source-digest "$source_commit"`, "--predicate-type https://slsa.dev/provenance/v1", "--deny-self-hosted-runners"} {
		mustContain(t, body, restriction)
	}
	mustNotContain(t, body, "--certificate-identity-regexp")

	for _, rawHTML := range []string{"<ul", "</ul>", "<li", "</li>", "<strong", "</strong>", "<code", "</code>"} {
		mustNotContain(t, body, rawHTML)
	}
	mustNotContain(t, body, "production signing remains pending")

	for _, removed := range []string{
		"Picocrypt-NG-android-armeabi-v7a.apk",
		"Picocrypt-NG-android-x86.apk",
	} {
		mustNotContain(t, body, removed)
	}
	for _, supported := range []string{
		"Picocrypt-NG-android-arm64-v8a.apk",
		"Picocrypt-NG-android-x86_64.apk",
		"Picocrypt-NG-android-universal.apk",
		"Android 8.0+ on 64-bit ARM or x86-64 devices",
	} {
		mustContain(t, body, supported)
	}
}

func TestAndroidGradleSupplyChainVerificationConfigured(t *testing.T) {
	const (
		gradle980Sha256        = "bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c"
		gradleWrapperJarSha256 = "238e777fcddd7e34f9708186085def2abd6e08e658505b38718d79d74c21abd5"
	)

	wrapper := mustReadRepoFile(t, "android/gradle/wrapper/gradle-wrapper.properties")
	mustContain(t, wrapper, "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.0-bin.zip")
	mustMatch(t, wrapper, `(?m)^distributionSha256Sum=`+gradle980Sha256+`$`)
	mustMatch(t, wrapper, `(?m)^validateDistributionUrl=true$`)
	mustMatch(t, wrapper, `(?m)^networkTimeout=60000$`)

	wrapperJar, err := os.ReadFile(filepath.Join(repoRoot(t), "android/gradle/wrapper/gradle-wrapper.jar"))
	if err != nil {
		t.Fatalf("read Gradle wrapper JAR: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(wrapperJar)); got != gradleWrapperJarSha256 {
		t.Fatalf("Gradle wrapper JAR SHA-256 = %s, want official Gradle 9.8.0 checksum %s", got, gradleWrapperJarSha256)
	}

	metadata := mustReadRepoFile(t, "android/gradle/verification-metadata.xml")
	mustContain(t, metadata, "<verification-metadata")
	mustContain(t, metadata, "<verify-metadata>true</verify-metadata>")
	mustMatch(t, metadata, `<sha256 value="[0-9a-f]{64}"`)

	var dependabot struct {
		Updates []struct {
			PackageEcosystem string `yaml:"package-ecosystem"`
			Directory        string `yaml:"directory"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal([]byte(mustReadRepoFile(t, ".github/dependabot.yml")), &dependabot); err != nil {
		t.Fatalf("unmarshal dependabot yaml: %v", err)
	}
	for _, want := range []struct {
		ecosystem string
		directory string
	}{
		{ecosystem: "gomod", directory: "src/"},
		{ecosystem: "gradle", directory: "android/"},
		{ecosystem: "github-actions", directory: "/"},
	} {
		found := false
		for _, update := range dependabot.Updates {
			if update.PackageEcosystem == want.ecosystem && update.Directory == want.directory {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("dependabot updates missing package-ecosystem %q with directory %q together", want.ecosystem, want.directory)
		}
	}
}

func TestAndroidGradleVerificationPrereleaseMetadataIsExplicitlyScoped(t *testing.T) {
	var metadata struct {
		Components []struct {
			Group   string `xml:"group,attr"`
			Name    string `xml:"name,attr"`
			Version string `xml:"version,attr"`
		} `xml:"components>component"`
	}
	if err := xml.Unmarshal([]byte(mustReadRepoFile(t, "android/gradle/verification-metadata.xml")), &metadata); err != nil {
		t.Fatalf("parse Gradle verification metadata XML: %v", err)
	}

	// These are accepted build-tool/test-platform metadata entries, not app
	// runtime/library upgrades. Any future prerelease metadata needs explicit
	// review before being added here.
	allowedPrereleaseComponents := map[string]struct{}{
		"com.android.tools.build.jetifier:jetifier-core:1.0.0-beta10":              {},
		"com.android.tools.build.jetifier:jetifier-processor:1.0.0-beta10":         {},
		"com.google.testing.platform:android-device-provider-local:0.0.9-alpha03":  {},
		"com.google.testing.platform:android-device-provider-local:0.0.9-alpha04":  {},
		"com.google.testing.platform:android-driver-instrumentation:0.0.9-alpha03": {},
		"com.google.testing.platform:android-driver-instrumentation:0.0.9-alpha04": {},
		"com.google.testing.platform:android-test-plugin:0.0.9-alpha03":            {},
		"com.google.testing.platform:android-test-plugin:0.0.9-alpha04":            {},
		"com.google.testing.platform:core:0.0.9-alpha03":                           {},
		"com.google.testing.platform:core:0.0.9-alpha04":                           {},
		"com.google.testing.platform:core-proto:0.0.9-alpha03":                     {},
		"com.google.testing.platform:core-proto:0.0.9-alpha04":                     {},
		"com.google.testing.platform:launcher:0.0.9-alpha03":                       {},
		"com.google.testing.platform:launcher:0.0.9-alpha04":                       {},
		"org.junit:junit-bom:5.11.0-M2":                                            {},
	}
	presentAllowed := make(map[string]struct{}, len(allowedPrereleaseComponents))

	var unreviewed []string
	for _, component := range metadata.Components {
		if !isPrereleaseVersion(component.Version) {
			continue
		}
		id := component.Group + ":" + component.Name + ":" + component.Version
		if _, ok := allowedPrereleaseComponents[id]; ok {
			presentAllowed[id] = struct{}{}
			continue
		}
		unreviewed = append(unreviewed, id)
	}
	if len(unreviewed) > 0 {
		t.Fatalf("Gradle verification metadata contains unreviewed prerelease components:\n%s", strings.Join(unreviewed, "\n"))
	}
	for id := range allowedPrereleaseComponents {
		if _, ok := presentAllowed[id]; !ok {
			t.Fatalf("allowlisted Gradle prerelease metadata entry %q is not present", id)
		}
	}
}

func TestGradleWrapperLineEndingsAreGoverned(t *testing.T) {
	attributes := mustReadRepoFile(t, ".gitattributes")
	for _, want := range []struct {
		path string
		eol  string
	}{
		{path: "/android/gradlew", eol: "lf"},
		{path: "/android/gradlew.bat", eol: "crlf"},
	} {
		pattern := `(?m)^` + regexp.QuoteMeta(want.path) + `\s+text\s+eol=` + want.eol + `$`
		if !regexp.MustCompile(pattern).MatchString(attributes) {
			t.Errorf(".gitattributes must pin %s as text eol=%s", want.path, want.eol)
		}
	}
}

var prereleaseVersionPattern = regexp.MustCompile(`(?i)(?:^|[-.])(?:alpha|beta|rc|m[0-9]+|milestone|snapshot|eap|preview|canary|dev)(?:[0-9]+)?(?:$|[-.])`)

func isPrereleaseVersion(version string) bool {
	return prereleaseVersionPattern.MatchString(version)
}

func TestPrereleaseVersionPatternCoversCommonMarkers(t *testing.T) {
	for _, version := range []string{
		"0.0.9-alpha03",
		"1.0.0-beta10",
		"5.11.0-M2",
		"1.0.0-milestone-1",
		"1.0.0-SNAPSHOT",
		"2.0.0-eap1",
		"2.0.0-preview.1",
		"2.0.0-canary",
		"2.0.0-dev-20260707",
	} {
		if !isPrereleaseVersion(version) {
			t.Errorf("isPrereleaseVersion(%q) = false, want true", version)
		}
	}

	for _, version := range []string{
		"1.0.0",
		"1.0.0-release",
		"1.0.0-device",
		"1.0.0-previewable",
	} {
		if isPrereleaseVersion(version) {
			t.Errorf("isPrereleaseVersion(%q) = true, want false", version)
		}
	}
}

func TestAndroidGomobileBuildUsesReproducibleLinkerFlags(t *testing.T) {
	content := mustReadRepoFile(t, "android/build-gomobile.sh")

	mustContain(t, content, `REQUIRED_GO_VERSION="go1.27.2"`)
	mustContain(t, content, `-ldflags="$GOMOBILE_LDFLAGS"`)
	mustContain(t, content, `-s -w -buildid=`)
}

func TestAndroidInstrumentedWorkflowIsManualAndPinned(t *testing.T) {
	const (
		focusedClasses = "io.github.picocrypt_ng.picocrypt_ng.FileCopyServiceTest,io.github.picocrypt_ng.picocrypt_ng.StagingServiceInstrumentedTest,io.github.picocrypt_ng.picocrypt_ng.GoBridgeProgressMappingTest,io.github.picocrypt_ng.picocrypt_ng.MainActivityUITest,io.github.picocrypt_ng.picocrypt_ng.OperationNotificationTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.PasswordCardTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.KeyfileCardWriterPolicyTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.ProgressCardTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.DecryptOptionsCardTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.ErrorDialogTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.FileCardTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.KeyfileClearLifecycleTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.WorkButtonTest,io.github.picocrypt_ng.picocrypt_ng.MainActivityStateTest"
		extendedClass  = "io.github.picocrypt_ng.picocrypt_ng.OperationManagerIntegrationTest"
	)

	content := mustReadWorkflow(t, ".github/workflows/android-instrumented.yml")
	mustContain(t, content, "workflow_dispatch:")
	mustContain(t, content, "test_scope:")
	mustContain(t, content, "default: focused")
	mustContain(t, content, "- focused")
	mustContain(t, content, "- extended")
	mustMatch(t, content, `ReactiveCircus/android-emulator-runner@[0-9a-f]{40}`)
	mustNotContain(t, content, "connectedDebugAndroidTest \\")

	// Keep the manual instrumented workflow on the target-SDK runtime.
	instrJob := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/android-instrumented.yml"), "android-instrumented")
	instrEmulator := mustHaveStepUsingPrefix(t, instrJob, "ReactiveCircus/android-emulator-runner@")
	if got := instrEmulator.With["api-level"]; got != 36 {
		t.Fatalf("instrumented emulator api-level = %v, want 36", got)
	}
	if got := instrEmulator.With["disk-size"]; got != "2048M" {
		t.Fatalf("instrumented emulator disk-size = %v, want 2048M", got)
	}
	wantScript := `case "$PICOCRYPT_TEST_SCOPE" in focused|extended) ;; *) echo "Unsupported test scope" >&2; exit 1 ;; esac; bash ../.github/scripts/run-android-device-tests.sh 36 ` + strings.ReplaceAll(focusedClasses, ",", " ") + ` ${{ inputs.test_scope == 'extended' && '` + extendedClass + `' || '' }}`
	if got := instrEmulator.Env["PICOCRYPT_TEST_SCOPE"]; got != "${{ inputs.test_scope }}" {
		t.Fatalf("instrumented scope env = %q, want dispatch input", got)
	}
	if got := instrEmulator.With["script"]; got != wantScript {
		t.Fatalf("instrumented script = %#v, want exact focused and extended selectors %q", got, wantScript)
	}
}

func TestWindowsLegacyPRWorkflowIsCLIOnly(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/pr-test-build-windows-legacy.yml")
	mustContain(t, content, "Picocrypt-NG-cli-Legacy.exe")
	mustContain(t, content, "Build CLI-only legacy binary")
	mustNotContain(t, content, "Build GUI with GLES")
	mustNotContain(t, content, "Add icon, manifest, and version info")
	mustNotContain(t, content, "Mesa3D")
}

func TestWindowsLegacyReleaseWorkflowIsCLIOnly(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/build-windows-legacy.yml")
	mustContain(t, content, "Picocrypt-NG-cli-Legacy.exe")
	mustContain(t, content, "Build CLI-only legacy binary")
	mustNotContain(t, content, "Build GUI with GLES")
	mustNotContain(t, content, "Add icon, manifest, and version info")
	mustNotContain(t, content, "Mesa3D")
}

func TestWindowsLegacyWorkflowsBuildFreshSourceToolchain(t *testing.T) {
	for _, tc := range []struct{ path, job string }{
		{".github/workflows/pr-test-build-windows-legacy.yml", "pr-test-build-windows-legacy"},
		{".github/workflows/build-windows-legacy.yml", "build"},
	} {
		job := mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job)
		mustNotHaveStepNamed(t, job, "Cache go-legacy-win7")
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/cache@") && strings.Contains(fmt.Sprint(step.With["path"]), "go-legacy") {
				t.Fatalf("%s must not restore executable legacy toolchains from cache", tc.path)
			}
		}
		build := mustStepNamed(t, job, "Build patched Go 1.27.2 for Windows 7/8")
		if build.Shell != "pwsh" || build.If != "" || build.ContinueOnError != nil {
			t.Fatal("legacy compiler source build must run unconditionally and fail closed")
		}
		mustContainInOrder(t, build.Run, ".github/scripts/build-legacy-go.ps1", "-ManifestPath '.github/toolchains/legacy-go/manifest.json'", `-OutputRoot 'C:\go-legacy'`)
	}
	builder := mustReadRepoFile(t, ".github/scripts/build-legacy-go.ps1")
	mustContainInOrder(t, builder, "if (Test-Path -LiteralPath $OutputRoot)", "Refusing to reuse an existing toolchain directory", "New-Item -ItemType Directory -Path $OutputRoot")
	for _, flag := range []string{"--fail", "--location", "--proto '=https'", "--proto-redir '=https'", "--connect-timeout 30", "--max-time 300", "--retry-max-time 600", "--remove-on-error"} {
		mustContain(t, builder, flag)
	}
	mustContainInOrder(t, builder, "Get-VerifiedSource $manifest.bootstrap_windows_amd64.url", "Get-VerifiedSource $manifest.source.url", "Expand-Archive -LiteralPath $bootstrapArchive")
	mustContainInOrder(t, builder, "Get-VerifiedSource $patch.url $patch.sha256", "git -C $goRoot apply --check", "git -C $goRoot apply --")
	mustContainInOrder(t, builder, "$env:GOROOT_BOOTSTRAP = Join-Path $bootstrapRoot 'go'", "$env:GOAMD64 = 'v1'", "cmd.exe /d /c make.bat", "assert-windows-legacy-pe.ps1")
}

func TestGoToolchainsStayOnApprovedVersions(t *testing.T) {
	type workflowLane struct {
		path string
		job  string
	}
	requiredLanes := []workflowLane{
		{path: ".github/workflows/android-instrumented.yml", job: "android-instrumented"},
		{path: ".github/workflows/build-android.yml", job: "build"},
		{path: ".github/workflows/build-appimage.yml", job: "build"},
		{path: ".github/workflows/build-linux.yml", job: "build"},
		{path: ".github/workflows/build-macos.yml", job: "build"},
		{path: ".github/workflows/build-windows.yml", job: "build"},
		{path: ".github/workflows/pr-static-checks.yml", job: "static-checks"},
		{path: ".github/workflows/pr-test-build-android.yml", job: "pr-test-build-android"},
		{path: ".github/workflows/pr-test-build-linux.yml", job: "build"},
		{path: ".github/workflows/pr-test-build-linux.yml", job: "tests"},
		{path: ".github/workflows/pr-test-build-macos.yml", job: "pr-test-build-macos"},
		{path: ".github/workflows/pr-test-build-windows.yml", job: "pr-test-build-windows"},
	}

	workflowFiles, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("glob workflows: %v", err)
	}

	setupGoSteps := make(map[workflowLane]int, len(requiredLanes))
	for _, absPath := range workflowFiles {
		relPath, err := filepath.Rel(repoRoot(t), absPath)
		if err != nil {
			t.Fatalf("rel path for %s: %v", absPath, err)
		}
		relPath = filepath.ToSlash(relPath)
		workflow := mustReadWorkflowDoc(t, relPath)
		for jobName, job := range workflow.Jobs {
			lane := workflowLane{path: relPath, job: jobName}
			for _, step := range job.Steps {
				if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
					continue
				}
				setupGoSteps[lane]++
				if got := step.With["go-version"]; got != "1.27.2" {
					t.Fatalf("%s job %s go-version = %#v, want 1.27.2", relPath, jobName, got)
				}
			}
		}
	}
	for _, lane := range requiredLanes {
		if got := setupGoSteps[lane]; got != 1 {
			t.Fatalf("%s job %s setup-go steps = %d, want exactly 1", lane.path, lane.job, got)
		}
	}

	mise := mustReadRepoFile(t, "mise.toml")
	var config struct {
		Tools map[string]string
		Tasks map[string]struct{ Tools map[string]string }
	}
	if _, err := toml.Decode(mise, &config); err != nil {
		t.Fatalf("decode mise toolchain configuration: %v", err)
	}
	for tool, want := range map[string]string{
		"go":                                   "1.27.2",
		"go:golang.org/x/vuln/cmd/govulncheck": "1.8.0",
	} {
		if got := config.Tools[tool]; got != want {
			t.Errorf("desktop %s = %q, want %q", tool, got, want)
		}
	}
	// Android bindings retain the toolchain required by build-gomobile.sh,
	// even when the desktop development tools are upgraded.
	for tool, want := range map[string]string{
		"go":                                  "1.27.2",
		"go:golang.org/x/mobile/cmd/gobind":   "v0.0.0-20260908204917-8b95e45f8d3e",
		"go:golang.org/x/mobile/cmd/gomobile": "v0.0.0-20260908204917-8b95e45f8d3e",
	} {
		if got := config.Tasks["android:gomobile"].Tools[tool]; got != want {
			t.Errorf("Android %s = %q, want %q", tool, got, want)
		}
	}

	goMod := mustReadRepoFile(t, "src/go.mod")
	mustMatch(t, goMod, `(?m)^go 1\.27\.2$`)
	mustNotContain(t, goMod, "\ntoolchain ")

	staticChecks := mustReadWorkflow(t, ".github/workflows/pr-static-checks.yml")
	mustContain(t, staticChecks, "golang.org/x/vuln/cmd/govulncheck@v1.8.0")
	mustNotContain(t, staticChecks, "golang.org/x/vuln/cmd/govulncheck@latest")
}

func TestSnapcraftBuildUsesExactGoToolchain(t *testing.T) {
	content := mustReadRepoFile(t, "dist/snapcraft/snapcraft.yaml")
	mustContain(t, content, "https://go.dev/dl/go1.27.2.linux-amd64.tar.gz")
	mustContain(t, content, "sha256/ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5")
	mustContain(t, content, `PATH: "${CRAFT_STAGE}/go/bin:${PATH}"`)
	mustContain(t, content, `GOROOT: "${CRAFT_STAGE}/go"`)
	mustContain(t, content, "GOTOOLCHAIN: local")
	mustContain(t, content, `test "$(go env GOVERSION)" = "go1.27.2"`)
	mustNotContain(t, content, "source-subdir: go")
	mustNotContain(t, content, "build-snaps:\n      - go")
}

func TestWindowsLegacyWorkflowsUsePinnedLocalFork(t *testing.T) {
	for _, tc := range []struct{ path, job string }{
		{".github/workflows/build-windows-legacy.yml", "build"},
		{".github/workflows/pr-test-build-windows-legacy.yml", "pr-test-build-windows-legacy"},
	} {
		job := mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job)
		if job.Env["GOTOOLCHAIN"] != "local" || job.Env["GOAMD64"] != "v1" || job.Env["GOEXPERIMENT"] != "" {
			t.Fatalf("%s must pin local toolchain and baseline x86-64 CPU settings", tc.path)
		}
		inspect := mustStepNamed(t, job, "Verify Go installation")
		for _, required := range []string{`C:\go-legacy\go\bin\go.exe`, `C:\go-legacy\go`, "Get-Command go -CommandType Application | Select-Object -First 1", "go env -json GOROOT GOVERSION GOTOOLCHAIN GOOS GOARCH GOAMD64 GOEXPERIMENT", "$actualGo -ne $expectedGo", "$goEnvironment.GOROOT -ne $expectedRoot", "go1.27.2", "$goEnvironment.GOAMD64 -ne 'v1'", "$goEnvironment.GOTOOLCHAIN -ne 'local'"} {
			mustContain(t, inspect.Run, required)
		}
		regression := mustStepNamed(t, job, "Run native legacy toolchain regressions")
		if regression.Shell != "pwsh" || regression.If != "" || regression.ContinueOnError != nil {
			t.Fatal("native compatibility/random-source regressions must block the legacy build")
		}
		for _, required := range []string{"run-windows-native-tests.ps1", `-GoExecutable 'C:\go-legacy\go\bin\go.exe'`, "'-count=1', '-p', '1'", "'os', 'internal/syscall/windows', 'crypto/internal/sysrand'", "'^TestReadRandomFromRtlGenRandom$', 'runtime'", "if ($LASTEXITCODE -ne 0)"} {
			mustContain(t, regression.Run, required)
		}
		verify := mustStepNamed(t, job, "Verify legacy binary toolchain")
		mustContain(t, verify.Run, "go version -m")
		mustContain(t, verify.Run, `go1\.27\.2`)
		mustContain(t, verify.Run, `GOAMD64=v1`)
		mustContain(t, verify.Run, ".github/scripts/assert-windows-legacy-pe.ps1")
		mustContainInOrder(t, mustReadWorkflow(t, tc.path), "name: Build patched Go 1.27.2 for Windows 7/8", "name: Verify Go installation", "name: Run native legacy toolchain regressions", "name: Run tests", "name: Build CLI-only legacy binary", "name: Verify legacy binary toolchain", "name: Compress with upx")
	}
}

func TestWindowsLegacyToolchainInputsHaveApprovedDigests(t *testing.T) {
	var manifest struct {
		Version string `json:"version"`
		Source  struct {
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
		} `json:"source"`
		Bootstrap struct {
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
		} `json:"bootstrap_windows_amd64"`
		Vendor  string `json:"vendor_commit"`
		Patches []struct {
			Path   string `json:"path"`
			URL    string `json:"url"`
			SHA256 string `json:"sha256"`
			Local  string `json:"local"`
		} `json:"patches"`
	}
	if err := json.Unmarshal([]byte(mustReadRepoFile(t, ".github/toolchains/legacy-go/manifest.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "go1.27.2" || manifest.Source.URL != "https://go.dev/dl/go1.27.2.src.tar.gz" || manifest.Source.SHA256 != "03495da2ba64894d40f5c4992e49454fa78b50690604ff92b6afff5081b76e62" || manifest.Bootstrap.URL != "https://go.dev/dl/go1.27.2.windows-amd64.zip" || manifest.Bootstrap.SHA256 != "1314008898bd40df77af4b014f777f08873dbdfbcd3d92308728ee03304fe04f" || manifest.Vendor != "2f6cdc24e8e5c029eafebe42fcbe966cc0589f97" {
		t.Fatal("legacy source/bootstrap must retain the approved official Go release digests and compatibility source commit")
	}
	expected := map[string]string{
		"0001-cmd-link-syscall-set-pe-minimum-target-version-to-windows-7.patch":                          "570e24cd21fdf4b78acba041a1046e4ea96670fd3c306e39a469430ff60d799f",
		"0002-runtime-syscall-fall-back-to-loading-system-dlls-by-absolute-path.patch":                    "77c2c38b61a515771e056a8f33e9df3f63573d3984ea9ef22338161b61a4d143",
		"0003-runtime-crypto-internal-sysrand-fall-back-to-rtlgenrandom-when-processprng-is-absent.patch": "c205f48a3c2320fca53b382ec938f45ba0d91792824ab52b0ab29ccf0d2c6d1c",
		"0004-syscall-restore-windows-7-console-handle-handling-in-startprocess.patch":                    "3c532ff58c8eea2d99fde2cef76e32ee385ea46595ecd4a2962fe653f7e2376d",
		"0005-os-fall-back-to-file-id-both-dir-info-when-reading-directories.patch":                       "65e6094182fe38840e0cf6d115bd255d93d2612d60ee376add5ed88666493ea5",
		"0006-os-open-the-console-devices-by-the-names-windows-7-accepts.patch":                           "1c49ba65ee707641b523ceac484abb159141d62c691ffb9763c80e267c74d0fc",
		"0007-net-fall-back-when-wsa-flag-no-handle-inherit-is-rejected.patch":                            "18708da2f6ee2684c9a066d476d561bdde2f2facdb9d045390c66637c321de57",
		"0008-internal-poll-keep-a-handle-that-cannot-leave-its-completion-port.patch":                    "be08ba5bf402e73b4f920eb999e33515cbdc68075ad7e8166be0c0c4ff4803ca",
		"0009-internal-poll-do-not-skip-the-completion-port-for-datagram-sockets.patch":                   "2798fe0c8d4f3e2ad1daa0978044db22457bdbbe948adc51636d3defb3ae15e8",
		"0010-internal-poll-keep-file-handles-off-a-completion-port-they-cannot-leave.patch":              "128437a47db907b20b20944849a5b950b436e1d119c4c983eacd708bc529a66f",
		"0012-internal-syscall-windows-clear-the-read-only-attribute-on-a-directory.patch":                "def59f1e865fc30b017fe433a68a0a065545f1d2597bb5c169dec950eae4c93a",
		"0013-internal-syscall-windows-os-free-the-name-before-a-delete-completes.patch":                  "6adae4030f50e5a1b9280a65f04374ddff0a2e2bf1dc4431ca45a50e54a97d66",
		"0014-internal-syscall-windows-replace-a-rename-target-where-posix-rename-is-missing.patch":       "d51589b85ae5b5c0e1fc30d2eb99ff5eaf6d9a8900722398d50f097cfcbd897d",
		"0015-runtime-race-cmd-link-let-race-binaries-start-on-windows-7.patch":                           "be4f7ff668455394a845040695fdacec81eaaffe555496dd642695b7de4d7138",
	}
	if len(manifest.Patches) != len(expected) {
		t.Fatal("legacy compatibility patch catalog must contain the complete reviewed set")
	}
	previous := ""
	for _, patch := range manifest.Patches {
		if expected[patch.Path] != patch.SHA256 || patch.Path <= previous {
			t.Fatalf("unreviewed, duplicate, or misordered compatibility patch %s", patch.Path)
		}
		previous = patch.Path
		if strings.HasPrefix(patch.Path, "0010-") || strings.HasPrefix(patch.Path, "0013-") {
			if patch.Local != "patches/"+patch.Path || patch.URL != "" {
				t.Fatal("reviewed local compatibility fix must use its exact catalog path")
			}
			content, err := os.ReadFile(filepath.Join(repoRoot(t), ".github/toolchains/legacy-go", patch.Local))
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256(content)) != patch.SHA256 {
				t.Fatal("local compatibility patch bytes differ from their reviewed digest")
			}
		} else if patch.Local != "" || patch.URL != "https://raw.githubusercontent.com/thongtech/go-legacy-win7/"+manifest.Vendor+"/patches/"+patch.Path {
			t.Fatal("vendor compatibility patches must use the exact immutable source URL")
		}
	}
	pe := mustReadRepoFile(t, ".github/scripts/assert-windows-legacy-pe.ps1")
	for _, required := range []string{"0x8664", "0x20B", "$stream.Position = $peOffset + 64", "$stream.Position = $peOffset + 72", "$reader.ReadUInt16() -ne 6 -or $reader.ReadUInt16() -ne 1"} {
		mustContain(t, pe, required)
	}
}

func TestJobPermissionMapDisablesUnspecifiedWorkflowPermissions(t *testing.T) {
	workflow := workflowDoc{Permissions: map[string]string{"contents": "write", "id-token": "write"}}
	mustEffectivePermission(t, workflow, workflowJob{}, "id-token", "write")
	job := workflowJob{Permissions: map[string]string{"contents": "read"}}
	mustEffectivePermission(t, workflow, job, "contents", "read")
	mustEffectivePermission(t, workflow, job, "id-token", "none")
	mustEffectivePermission(t, workflow, workflowJob{Permissions: map[string]string{}}, "contents", "none")
}

func TestExternalActionSHARejectsMutableValueHiddenByYAMLComment(t *testing.T) {
	const digest = "55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
	for _, tc := range []struct {
		name, source string
		pinned       bool
	}{
		{"immutable", "uses: actions/cache@" + digest + " # v6.1.0", true},
		{"mutable comment spoof", "uses: actions/cache@" + digest + "-mutable # uses: actions/cache@" + digest + " # v6.1.0", false},
		{"mutable quoted ref", "uses: 'actions/cache@" + digest + "-mutable' # v6.1.0", false},
		{"major version", "uses: actions/cache@v6 # v6.1.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var step workflowStep
			if err := yaml.Unmarshal([]byte(tc.source), &step); err != nil {
				t.Fatal(err)
			}
			if got := externalActionSHARefPattern.MatchString(step.Uses); got != tc.pinned {
				t.Fatalf("parsed ref %q immutable = %v, want %v", step.Uses, got, tc.pinned)
			}
		})
	}
}
