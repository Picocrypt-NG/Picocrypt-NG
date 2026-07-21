package workflowpolicy

import (
	"crypto/sha256"
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
	for _, tc := range releaseWorkflowCases() {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			releaseJob := mustJob(t, workflow, tc.job)
			releaseStep := mustHaveStepUsingPrefix(t, releaseJob, "softprops/action-gh-release@")
			if got := releaseStep.With["overwrite_files"]; got != false && got != "false" {
				t.Fatalf("release overwrite_files = %#v, want false to preserve published binaries", got)
			}
		})
	}
}

func TestExternalGitHubActionsPinnedToFullSHAWithVersionComment(t *testing.T) {
	actionRef := regexp.MustCompile(`uses:\s*([^@\s]+)@([0-9a-f]{40})(?:\s+#\s+v[0-9][^\s]*)?$`)
	const checkoutUses = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	const checkoutRef = checkoutUses + " # v7.0.1"
	checkoutCount := 0
	checkSteps := func(owner string, steps []workflowStep) int {
		t.Helper()
		count := 0
		for _, step := range steps {
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
	if got := installStep.With["cosign-release"]; got != "v3.1.2" {
		t.Fatalf("Install cosign cosign-release = %#v, want v3.1.2", got)
	}

	content := mustReadRepoFile(t, path)
	const installerLine = "uses: " + installerRef + " # v4.1.2"
	mustMatch(t, content, `(?m)^\s*`+regexp.QuoteMeta(installerLine)+`\s*$`)
	if got := strings.Count(content, installerLine); got != 1 {
		t.Fatalf("cosign installer line count = %d, want exactly 1", got)
	}
	mustNotContain(t, content, "cosign-release: 'v3.1.1'")
}

func TestReleaseJobsRequireMainBranchAndReleaseEnvironment(t *testing.T) {
	const releaseGuard = "${{ github.ref == 'refs/heads/main' && (github.event_name == 'push' || inputs.publish_release) }}"
	const signPathReleaseGuard = "${{ github.ref == 'refs/heads/main' && !inputs.signpath_test && !inputs.signpath_release_dry_run && (github.event_name == 'push' || inputs.publish_release) }}"

	for _, tc := range releaseWorkflowCases() {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			releaseJob := mustJob(t, workflow, tc.job)
			wantGuard := releaseGuard
			if tc.name == "build-windows" || tc.name == "build-windows-legacy" {
				wantGuard = signPathReleaseGuard
			}
			if releaseJob.If != wantGuard {
				t.Fatalf("release job if = %q, want guarded push or explicit manual release", releaseJob.If)
			}
			if got := releaseEnvironmentName(releaseJob.Environment); got != "release" {
				t.Fatalf("release job environment = %#v, want release", releaseJob.Environment)
			}

			content := mustReadWorkflow(t, tc.path)
			mustContain(t, content, "publish_release:")
		})
	}
}

func TestMacOSReleaseWorkflowOnlyAutoRunsOnVersionChanges(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/build-macos.yml")

	mustContainInOrder(t, content,
		"on:",
		"push:",
		"paths:",
		"- \"VERSION\"",
		"branches:",
	)
	mustNotContain(t, content, "- \".github/workflows/build-macos.yml\"")
	mustNotContain(t, content, "- \".github/scripts/assert-macos-minos.sh\"")
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

	releaseStep := mustHaveStepUsingPrefix(t, releaseJob, "softprops/action-gh-release@")
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

	if signJob.If != "${{ github.ref == 'refs/heads/main' && (github.event_name == 'push' || inputs.publish_release || inputs.signpath_test || inputs.signpath_release_dry_run) }}" {
		t.Fatalf("Windows SignPath job if = %q, want main release, test signing, or release-signing dry-run guard", signJob.If)
	}
	if signJob.TimeoutMinutes != 60 {
		t.Fatalf("Windows SignPath job timeout = %d minutes, want 60 for three sequential requests", signJob.TimeoutMinutes)
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
		if step.Uses != "signpath/github-action-submit-signing-request@b9d91eadd323de506c0c81cf0c7fe7438f3360fd" {
			t.Fatalf("%s action = %q, want reviewed SignPath v2.2 commit", tc.name, step.Uses)
		}
		for key, want := range map[string]any{
			"api-token":                   "${{ secrets.SIGNPATH_API_TOKEN }}",
			"organization-id":             "d6e78672-6bae-47d3-b2b8-fa464705b34e",
			"project-slug":                "${{ vars.SIGNPATH_PROJECT_SLUG }}",
			"signing-policy-slug":         "${{ env.SIGNPATH_SIGNING_POLICY_SLUG }}",
			"artifact-configuration-slug": tc.configurationSlug,
			"github-artifact-id":          "${{ steps." + tc.uploadStepID + ".outputs.artifact-id }}",
			"wait-for-completion":         true,
			"output-artifact-directory":   tc.outputDirectory,
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
	orderedReleaseSteps := []string{"Download signed artifact", "Sign and attest artifacts", "Release"}
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
	if signJob.If != "${{ github.ref == 'refs/heads/main' && (github.event_name == 'push' || inputs.publish_release || inputs.signpath_test || inputs.signpath_release_dry_run) }}" {
		t.Fatalf("legacy SignPath job if = %q, want main release, test signing, or release-signing dry-run guard", signJob.If)
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
	if signStep.Uses != "signpath/github-action-submit-signing-request@b9d91eadd323de506c0c81cf0c7fe7438f3360fd" {
		t.Fatalf("legacy SignPath action = %q, want reviewed SignPath v2.2 commit", signStep.Uses)
	}
	for key, want := range map[string]any{
		"api-token":                   "${{ secrets.SIGNPATH_API_TOKEN }}",
		"organization-id":             "d6e78672-6bae-47d3-b2b8-fa464705b34e",
		"project-slug":                "${{ vars.SIGNPATH_PROJECT_SLUG }}",
		"signing-policy-slug":         "${{ env.SIGNPATH_SIGNING_POLICY_SLUG }}",
		"artifact-configuration-slug": "windows-legacy-cli",
		"github-artifact-id":          "${{ steps.upload-signpath-legacy.outputs.artifact-id }}",
		"wait-for-completion":         true,
		"output-artifact-directory":   "signpath-signed-legacy",
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

func TestLinuxPRAggregateGateIgnoresCancelledDuplicate(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-linux.yml")
	gate := mustJob(t, workflow, "pr-test-build-linux")
	if gate.If != "${{ always() && !cancelled() }}" {
		t.Fatalf("Linux aggregate if = %q, want cancellation-aware always gate", gate.If)
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
			testStep := mustStepNamed(t, mustJob(t, workflow, "build"), "Run tests")

			raceLineIndex := -1
			integrationLineIndex := -1
			raceLineCount := 0
			integrationLineCount := 0
			for lineIndex, line := range strings.Split(testStep.Run, "\n") {
				if strings.Contains(line, "go test") && strings.Contains(line, "-race") {
					raceLineCount++
					raceLineIndex = lineIndex
					for _, required := range []string{"-p 2", "-timeout 15m", "./..."} {
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
		upxURL            = "https://github.com/upx/upx/releases/download/v5.2.0/upx-5.2.0-win64.zip"
		legacyGoURL       = "https://github.com/thongtech/go-legacy-win7/releases/download/v1.26.5-1/go-legacy-win7-1.26.5-1.windows_amd64.zip"
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
			name: "legacy-release-go", path: ".github/workflows/build-windows-legacy.yml",
			job: "build", step: "Download go-legacy-win7",
			output: "go-legacy.zip", url: legacyGoURL,
			hashEnv: "GO_LEGACY_SHA256", consumer: `Expand-Archive -DestinationPath C:\go-legacy go-legacy.zip`,
		},
		{
			name: "legacy-pr-go", path: ".github/workflows/pr-test-build-windows-legacy.yml",
			job: "pr-test-build-windows-legacy", step: "Download go-legacy-win7",
			output: "go-legacy.zip", url: legacyGoURL,
			hashEnv: "GO_LEGACY_SHA256", consumer: `Expand-Archive -DestinationPath C:\go-legacy go-legacy.zip`,
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
		command   = "./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class="
		roundtrip = "io.github.picocrypt_ng.picocrypt_ng.OperationManagerIntegrationTest#encrypt_then_decrypt_recovers_the_original_bytes"
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
		// Storage and staging must work on Picocrypt NG's Android 7 compatibility floor.
		24: {
			arch:     "x86_64",
			diskSize: "2048M",
			memory:   "3583",
			target:   "google_apis",
			script:   command + roundtrip + ",io.github.picocrypt_ng.picocrypt_ng.FileCopyServiceTest,io.github.picocrypt_ng.picocrypt_ng.StagingServiceInstrumentedTest,io.github.picocrypt_ng.picocrypt_ng.OperationNotificationTest",
		},
		// Activity security and Compose state must work on the target-SDK runtime.
		36: {
			arch:     "x86_64",
			diskSize: "2048M",
			memory:   "6144",
			target:   "default",
			script:   command + roundtrip + ",io.github.picocrypt_ng.picocrypt_ng.MainActivityUITest,io.github.picocrypt_ng.picocrypt_ng.OperationNotificationTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.ProgressCardTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.NewKeyfileLifecycleTest,io.github.picocrypt_ng.picocrypt_ng.ui.components.WorkButtonTest",
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

func TestAndroidReleaseWorkflowKeepsSigningSecretsOutOfBuildJob(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	buildJob := mustJob(t, workflow, "build")
	releaseJob := mustJob(t, workflow, "release")

	mustStepNamed(t, buildJob, "Build Go Mobile AAR")
	mustStepNamed(t, buildJob, "Run Unit Tests")
	mustNotHaveStepNamed(t, buildJob, "Decode Android signing keystore")
	mustNotHaveStepNamed(t, buildJob, "Build Signed Release APK")

	decodeStep := mustStepNamed(t, releaseJob, "Decode Android signing keystore")
	if decodeStep.ID != "android-keystore" {
		t.Fatalf("release keystore decode step id = %q, want android-keystore", decodeStep.ID)
	}
	if _, ok := decodeStep.Env["ANDROID_KEYSTORE_BASE64"]; !ok {
		t.Fatal("release keystore decode step should declare ANDROID_KEYSTORE_BASE64")
	}
	for _, key := range []string{
		"ANDROID_KEYSTORE_PASSWORD",
		"ANDROID_KEY_ALIAS",
		"ANDROID_KEY_PASSWORD",
	} {
		if _, ok := decodeStep.Env[key]; ok {
			t.Fatalf("release keystore decode step must not declare env %q", key)
		}
		mustNotContain(t, decodeStep.Run, key)
	}
	mustNotContain(t, decodeStep.Run, "PICOCRYPT_KEYSTORE_PASSWORD")
	mustNotContain(t, decodeStep.Run, "PICOCRYPT_KEY_ALIAS")
	mustNotContain(t, decodeStep.Run, "PICOCRYPT_KEY_PASSWORD")
	mustNotContain(t, decodeStep.Run, "$GITHUB_ENV")
	mustContain(t, decodeStep.Run, "path=$KEYSTORE_PATH")
	mustMatch(t, decodeStep.Run, `(?m)>>\s*"\$GITHUB_OUTPUT"`)

	buildSignedStep := mustStepNamed(t, releaseJob, "Build Signed Release APK")
	for _, key := range []string{
		"ORG_GRADLE_PROJECT_PICOCRYPT_KEYSTORE_PATH",
		"ORG_GRADLE_PROJECT_PICOCRYPT_KEYSTORE_PASSWORD",
		"ORG_GRADLE_PROJECT_PICOCRYPT_KEY_ALIAS",
		"ORG_GRADLE_PROJECT_PICOCRYPT_KEY_PASSWORD",
	} {
		if _, ok := buildSignedStep.Env[key]; !ok {
			t.Fatalf("signed build step missing scoped env %q", key)
		}
	}
	if got := buildSignedStep.Env["ORG_GRADLE_PROJECT_PICOCRYPT_KEYSTORE_PATH"]; got != "${{ steps.android-keystore.outputs.path }}" {
		t.Fatalf("signed build keystore path env = %q, want android-keystore step output", got)
	}
	downloadStep := mustHaveStepUsingPrefix(t, releaseJob, "actions/download-artifact@")
	mustMatch(t, downloadStep.Uses, `actions/download-artifact@[0-9a-f]{40}`)
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
			if setupSteps == 0 {
				t.Fatalf("%s job %s has no actions/setup-java step", path, jobName)
			}
		}
	}

	mustContain(t, mustReadRepoFile(t, "mise.toml"), `java = "temurin-21"`)

	buildScript := mustReadRepoFile(t, "android/build-app")
	mustContain(t, buildScript, `"$JAVA_MAJOR" != "21"`)
}

func TestAndroidReleasePublishesOnly64BitAPKNames(t *testing.T) {
	releaseWorkflow := mustReadWorkflowDoc(t, ".github/workflows/build-android.yml")
	prepare := mustStepNamed(t, mustJob(t, releaseWorkflow, "release"), "Prepare artifacts")
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
		name string
		path string
		job  string
		kind string
	}{
		{name: "unsigned PR build", path: ".github/workflows/pr-test-build-android.yml", job: "pr-test-build-android", kind: "unsigned"},
		{name: "signed release", path: ".github/workflows/build-android.yml", job: "release", kind: "signed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			step := mustStepNamed(t, mustJob(t, workflow, tc.job), "Verify exact release APK contract")
			if step.WorkingDirectory != "android" {
				t.Fatalf("verifier working-directory = %q, want android", step.WorkingDirectory)
			}
			wantRun := strings.Join([]string{
				`./verify-release-apks.sh \`,
				`  app/build/outputs/apk/release \`,
				`  "$ORG_GRADLE_PROJECT_PICOCRYPT_VERSION_NAME" \`,
				`  "$ORG_GRADLE_PROJECT_PICOCRYPT_VERSION_CODE" \`,
				`  io.github.picocrypt_ng.picocrypt_ng \`,
				`  ` + tc.kind,
			}, "\n")
			if got := strings.TrimSpace(step.Run); got != wantRun {
				t.Fatalf("verifier run = %q, want %q", got, wantRun)
			}
			if step.If != "" {
				t.Fatalf("verifier if = %q, want unconditional step", step.If)
			}
			if step.ContinueOnError != nil && step.ContinueOnError != false {
				t.Fatalf("verifier continue-on-error = %#v, want absent or false", step.ContinueOnError)
			}
			trustAnchor, hasTrustAnchor := step.Env["PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE"]
			if tc.kind == "signed" {
				if !hasTrustAnchor || trustAnchor != "release-signing-cert-sha256.txt" {
					t.Fatalf("signed verifier trust anchor = %q, present %v; want release-signing-cert-sha256.txt", trustAnchor, hasTrustAnchor)
				}
			} else if hasTrustAnchor {
				t.Fatalf("unsigned verifier unexpectedly sets signing trust anchor %q", trustAnchor)
			}
		})
	}
}

func TestAndroidReleaseSigningTrustAnchorAndPublicationOrder(t *testing.T) {
	const trustedDigest = "e2f2a971231aa0b86882c63b87b689c71632c6d55168b1ce856952d07f6172b7"
	anchor := mustReadRepoFile(t, "android/release-signing-cert-sha256.txt")
	if anchor != trustedDigest+"\n" {
		t.Fatalf("Android release signing trust anchor = %q, want one exact lowercase SHA-256 digest", anchor)
	}

	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/build-android.yml"), "release")
	orderedSteps := []string{
		"Build Signed Release APK",
		"Verify exact release APK contract",
		"Prepare artifacts",
		"Sign and attest artifacts",
		"Release",
	}
	lastIndex := -1
	for _, name := range orderedSteps {
		index := -1
		for candidateIndex, step := range job.Steps {
			if step.Name == name {
				index = candidateIndex
				break
			}
		}
		if index < 0 {
			t.Fatalf("release job is missing step %q", name)
		}
		if index <= lastIndex {
			t.Fatalf("release step %q is out of order; want %s", name, strings.Join(orderedSteps, " < "))
		}
		lastIndex = index
	}
}

func TestReleaseBodyAdvertisesOnly64BitAndroid(t *testing.T) {
	root := repoRoot(t)
	command := exec.Command(
		"bash",
		filepath.Join(root, ".github/actions/release-body/gen-release-body.sh"),
		"2.18",
		filepath.Join(root, "Changelog.md"),
		"-",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("generate release body: %v\n%s", err, output)
	}

	body := string(output)
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
		"Android 7.0+ on 64-bit ARM or x86-64 devices",
	} {
		mustContain(t, body, supported)
	}
}

func TestAndroidGradleSupplyChainVerificationConfigured(t *testing.T) {
	const (
		gradle961Sha256        = "9c0f7faeeb306cb14e4279a3e084ca6b596894089a0638e68a07c945a32c9e14"
		gradleWrapperJarSha256 = "497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7"
	)

	wrapper := mustReadRepoFile(t, "android/gradle/wrapper/gradle-wrapper.properties")
	mustContain(t, wrapper, "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.6.1-bin.zip")
	mustMatch(t, wrapper, `(?m)^distributionSha256Sum=`+gradle961Sha256+`$`)
	mustMatch(t, wrapper, `(?m)^validateDistributionUrl=true$`)
	mustMatch(t, wrapper, `(?m)^networkTimeout=60000$`)

	wrapperJar, err := os.ReadFile(filepath.Join(repoRoot(t), "android/gradle/wrapper/gradle-wrapper.jar"))
	if err != nil {
		t.Fatalf("read Gradle wrapper JAR: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(wrapperJar)); got != gradleWrapperJarSha256 {
		t.Fatalf("Gradle wrapper JAR SHA-256 = %s, want official Gradle 9.6.1 checksum %s", got, gradleWrapperJarSha256)
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

	mustContain(t, content, `-ldflags="$GOMOBILE_LDFLAGS"`)
	mustContain(t, content, `-s -w -buildid=`)
}

func TestAndroidInstrumentedWorkflowIsManualAndPinned(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/android-instrumented.yml")
	mustContain(t, content, "workflow_dispatch:")
	mustContain(t, content, "test_scope:")
	mustContain(t, content, "default: focused")
	mustContain(t, content, "- focused")
	mustContain(t, content, "- extended")
	mustMatch(t, content, `ReactiveCircus/android-emulator-runner@[0-9a-f]{40}`)
	mustContain(t, content, "connectedDebugAndroidTest")
	mustContain(t, content, "PasswordCardTest")
	mustContain(t, content, "ProgressCardTest")
	mustContain(t, content, "OperationNotificationTest")
	mustContain(t, content, "NewKeyfileLifecycleTest")
	mustContain(t, content, "OperationManagerIntegrationTest")
	mustNotContain(t, content, "connectedDebugAndroidTest \\")
	mustContain(t, content, "TEST_CLASSES=")
	mustContain(t, content, "./gradlew connectedDebugAndroidTest")

	// Keep the manual instrumented workflow on the target-SDK runtime.
	instrJob := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/android-instrumented.yml"), "android-instrumented")
	instrEmulator := mustHaveStepUsingPrefix(t, instrJob, "ReactiveCircus/android-emulator-runner@")
	if got := instrEmulator.With["api-level"]; got != 36 {
		t.Fatalf("instrumented emulator api-level = %v, want 36", got)
	}
	if got := instrEmulator.With["disk-size"]; got != "2048M" {
		t.Fatalf("instrumented emulator disk-size = %v, want 2048M", got)
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

func TestWindowsLegacyWorkflowsCacheLegacyGo(t *testing.T) {
	testCases := []struct {
		path string
		job  string
	}{
		{path: ".github/workflows/pr-test-build-windows-legacy.yml", job: "pr-test-build-windows-legacy"},
		{path: ".github/workflows/build-windows-legacy.yml", job: "build"},
	}

	for _, tc := range testCases {
		workflow := mustReadWorkflowDoc(t, tc.path)
		job := mustJob(t, workflow, tc.job)
		cacheStep := mustStepNamed(t, job, "Cache go-legacy-win7")
		// actions/cache must be SHA-pinned for supply-chain safety, not floated on
		// a mutable major tag. Assert the 40-hex pin, not a specific version, so a
		// cache bump (e.g. the v4->v5 unification) does not churn this test.
		mustMatch(t, cacheStep.Uses, `actions/cache@[0-9a-f]{40}`)
		if cacheStep.With["path"] != `C:\go-legacy` {
			t.Fatalf("cache step path = %#v, want C:\\go-legacy", cacheStep.With["path"])
		}
	}
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
				if got := step.With["go-version"]; got != "1.26.5" {
					t.Fatalf("%s job %s go-version = %#v, want 1.26.5", relPath, jobName, got)
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
	mustContain(t, mise, `go = "1.26.5"`)
	mustContain(t, mise, `"go:golang.org/x/vuln/cmd/govulncheck" = "1.6.0"`)

	goMod := mustReadRepoFile(t, "src/go.mod")
	mustMatch(t, goMod, `(?m)^go 1\.26\.0$`)
	mustNotContain(t, goMod, "\ntoolchain ")

	staticChecks := mustReadWorkflow(t, ".github/workflows/pr-static-checks.yml")
	mustContain(t, staticChecks, "golang.org/x/vuln/cmd/govulncheck@v1.6.0")
	mustNotContain(t, staticChecks, "golang.org/x/vuln/cmd/govulncheck@latest")
}

func TestSnapcraftBuildUsesExactGoToolchain(t *testing.T) {
	content := mustReadRepoFile(t, "dist/snapcraft/snapcraft.yaml")
	mustContain(t, content, "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz")
	mustContain(t, content, "sha256/5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053")
	mustContain(t, content, `PATH: "${CRAFT_STAGE}/go/bin:${PATH}"`)
	mustContain(t, content, `GOROOT: "${CRAFT_STAGE}/go"`)
	mustContain(t, content, "GOTOOLCHAIN: local")
	mustContain(t, content, `test "$(go env GOVERSION)" = "go1.26.5"`)
	mustNotContain(t, content, "source-subdir: go")
	mustNotContain(t, content, "build-snaps:\n      - go")
}

func TestWindowsLegacyWorkflowsUsePinnedLocalFork(t *testing.T) {
	cases := []struct {
		path string
		job  string
	}{
		{path: ".github/workflows/build-windows-legacy.yml", job: "build"},
		{path: ".github/workflows/pr-test-build-windows-legacy.yml", job: "pr-test-build-windows-legacy"},
	}
	for _, tc := range cases {
		workflow := mustReadWorkflowDoc(t, tc.path)
		job := mustJob(t, workflow, tc.job)
		if job.Env["GOTOOLCHAIN"] != "local" {
			t.Fatalf("%s GOTOOLCHAIN = %q, want local", tc.path, job.Env["GOTOOLCHAIN"])
		}
		cache := mustStepNamed(t, job, "Cache go-legacy-win7")
		if _, ok := cache.With["restore-keys"]; ok {
			t.Fatalf("%s legacy cache must not restore an older checksum", tc.path)
		}
		content := mustReadWorkflow(t, tc.path)
		mustContain(t, content, "c9d0c79dc2b408a4ea580b62a3d093a4219f9ff95316ef891dc987827e6900e3")
		mustContain(t, content, "v1.26.5-1/go-legacy-win7-1.26.5-1.windows_amd64.zip")
		mustContain(t, content, `C:\go-legacy\go-legacy-win7\bin`)
		mustNotContain(t, content, `C:\go-legacy\go\bin`)
		mustContain(t, content, "Get-Command go")
		mustContain(t, content, "Get-Command go -CommandType Application | Select-Object -First 1")
		mustContain(t, content, "go env GOROOT")
		mustContain(t, content, "go env GOVERSION")
		mustContain(t, content, "go1.26.5")
		mustContain(t, content, "go version -m")
	}
}
