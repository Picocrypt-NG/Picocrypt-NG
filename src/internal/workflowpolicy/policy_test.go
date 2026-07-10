package workflowpolicy

import (
	"encoding/xml"
	"path/filepath"
	"regexp"
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
	mustContain(t, vetStep.Run, "go vet ./...")

	lintStep := mustStepNamed(t, job, "Lint (golangci-lint)")
	mustContain(t, lintStep.Run, "run ./...")
	// golangci-lint must be pinned to an explicit version (the v2 config is
	// version-sensitive); @latest would make CI non-reproducible.
	mustMatch(t, lintStep.Run, `golangci-lint/v2/cmd/golangci-lint@v[0-9]+\.[0-9]+\.[0-9]+`)
	mustNotContain(t, lintStep.Run, "golangci-lint/v2/cmd/golangci-lint@latest")

	vulnStep := mustStepNamed(t, job, "Vulnerability scan (govulncheck)")
	mustContain(t, vulnStep.Run, "govulncheck ./...")

	content := mustReadWorkflow(t, path)
	mustContain(t, content, "pull_request:")
}

func TestReleaseActionsPinnedToFullSHA(t *testing.T) {
	for _, tc := range releaseWorkflowCases() {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			releaseJob := mustJob(t, workflow, tc.job)
			releaseStep := mustHaveStepUsingPrefix(t, releaseJob, "softprops/action-gh-release@")
			mustMatch(t, releaseStep.Uses, `softprops/action-gh-release@[0-9a-f]{40}`)
		})
	}
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
		content := mustReadRepoFile(t, relPath)
		for lineNo, line := range strings.Split(content, "\n") {
			if !strings.Contains(line, "uses:") {
				continue
			}
			if strings.Contains(line, "uses: ./") {
				continue
			}
			if !actionRef.MatchString(strings.TrimSpace(line)) {
				t.Fatalf("%s:%d external action must use a 40-hex SHA and same-line version comment, got %q", relPath, lineNo+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestReleaseJobsRequireMainBranchAndReleaseEnvironment(t *testing.T) {
	const releaseGuard = "${{ github.ref == 'refs/heads/main' && (github.event_name == 'push' || inputs.publish_release) }}"

	for _, tc := range releaseWorkflowCases() {
		t.Run(tc.name, func(t *testing.T) {
			workflow := mustReadWorkflowDoc(t, tc.path)
			releaseJob := mustJob(t, workflow, tc.job)
			if releaseJob.If != releaseGuard {
				t.Fatalf("release job if = %q, want guarded push or explicit manual release", releaseJob.If)
			}
			if got := releaseEnvironmentName(releaseJob.Environment); got != "release" {
				t.Fatalf("release job environment = %#v, want release", releaseJob.Environment)
			}

			content := mustReadWorkflow(t, tc.path)
			mustContain(t, content, "publish_release:")
			mustContain(t, content, "Existing assets are never overwritten.")
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

func TestSnapcraftActionPinnedToFullSHA(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/build-snapcraft.yml")
	buildJob := mustJob(t, workflow, "build-snapcraft")
	buildStep := mustHaveStepUsingPrefix(t, buildJob, "snapcore/action-build@")
	mustMatch(t, buildStep.Uses, `snapcore/action-build@[0-9a-f]{40}`)
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

func TestAndroidPRWorkflowRunsCryptoRoundtripOnDevice(t *testing.T) {
	content := mustReadWorkflow(t, ".github/workflows/pr-test-build-android.yml")
	mustContain(t, content, "Run Unit Tests")
	mustContain(t, content, "./gradlew test")
	mustContain(t, content, ":app:compileDebugAndroidTestKotlin")
	mustContain(t, content, ":app:assembleDebugAndroidTest")
	// The PR gate now runs the real on-device Go encrypt/decrypt roundtrip so a crypto
	// regression on Android cannot merge green. Keep the emulator action SHA-pinned.
	mustMatch(t, content, `ReactiveCircus/android-emulator-runner@[0-9a-f]{40}`)
	mustContain(t, content, "connectedDebugAndroidTest")
	mustContain(t, content, "-Pandroid.testInstrumentationRunnerArguments.class")
	mustContain(t, content, "OperationManagerIntegrationTest")

	// The emulator must run API 36 (matching targetSdk), not 34: API 35+ behavior --
	// the foreground-service dataSync timeout and Service.onTimeout(API 35+) -- is only
	// reachable there, so gating on API 34 is a false green for that path.
	prJob := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-android.yml"), "pr-test-build-android")
	prEmulator := mustHaveStepUsingPrefix(t, prJob, "ReactiveCircus/android-emulator-runner@")
	if got := prEmulator.With["api-level"]; got != 36 {
		t.Fatalf("PR emulator api-level = %v, want 36 (>= targetSdk for FGS/onTimeout coverage)", got)
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
				if step.Name != "Set up JDK 21" {
					t.Fatalf("%s job %s setup-java step name = %q, want Set up JDK 21", path, jobName, step.Name)
				}
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
	mustContain(t, mustReadRepoFile(t, "android/README.md"), "CI and recommended local builds use JDK 21")

	buildScript := mustReadRepoFile(t, "android/build-app")
	mustContain(t, buildScript, "JDK 21 is required")
	mustContain(t, buildScript, `"$JAVA_MAJOR" != "21"`)
	mustNotContain(t, buildScript, "JDK 17 is required")
}

func TestAndroidApiFloorStaysAt24(t *testing.T) {
	gradle := mustReadRepoFile(t, "android/app/build.gradle.kts")
	mustContain(t, gradle, "minSdk = 24")

	gomobile := mustReadRepoFile(t, "android/build-gomobile.sh")
	mustContain(t, gomobile, "-androidapi 24")
	mustContain(t, gomobile, "-ldflags=\"$GOMOBILE_LDFLAGS\"")

	readme := mustReadRepoFile(t, "android/README.md")
	mustContain(t, readme, "minimum API level 24")
}

func TestAndroidGradleSupplyChainVerificationConfigured(t *testing.T) {
	const gradle931Sha256 = "b266d5ff6b90eada6dc3b20cb090e3731302e553a27c5d3e4df1f0d76beaff06"

	wrapper := mustReadRepoFile(t, "android/gradle/wrapper/gradle-wrapper.properties")
	mustContain(t, wrapper, "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.3.1-bin.zip")
	mustMatch(t, wrapper, `(?m)^distributionSha256Sum=`+gradle931Sha256+`$`)
	mustMatch(t, wrapper, `(?m)^validateDistributionUrl=true$`)
	mustMatch(t, wrapper, `(?m)^networkTimeout=60000$`)

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
	mustContain(t, content, "OperationManagerIntegrationTest")
	mustNotContain(t, content, "connectedDebugAndroidTest \\")
	mustContain(t, content, "TEST_CLASSES=")
	mustContain(t, content, "./gradlew connectedDebugAndroidTest")

	// Same API-36 requirement as the PR gate (FGS/onTimeout reachability).
	instrJob := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/android-instrumented.yml"), "android-instrumented")
	instrEmulator := mustHaveStepUsingPrefix(t, instrJob, "ReactiveCircus/android-emulator-runner@")
	if got := instrEmulator.With["api-level"]; got != 36 {
		t.Fatalf("instrumented emulator api-level = %v, want 36", got)
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
	workflowFiles, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("glob workflows: %v", err)
	}

	setupGoSteps := 0
	for _, absPath := range workflowFiles {
		relPath, err := filepath.Rel(repoRoot(t), absPath)
		if err != nil {
			t.Fatalf("rel path for %s: %v", absPath, err)
		}
		workflow := mustReadWorkflowDoc(t, relPath)
		for jobName, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
					continue
				}
				setupGoSteps++
				if got := step.With["go-version"]; got != "1.26.5" {
					t.Fatalf("%s job %s go-version = %#v, want 1.26.5", relPath, jobName, got)
				}
			}
		}
	}
	if setupGoSteps != 11 {
		t.Fatalf("setup-go steps = %d, want 11", setupGoSteps)
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
