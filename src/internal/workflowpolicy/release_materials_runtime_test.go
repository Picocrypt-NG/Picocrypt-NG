//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAndroidReleaseMaterialsRejectsMissingGradleInput(t *testing.T) {
	const script = ".github/scripts/release-materials.sh"
	gradleFiles := []string{
		"android/gradle/verification-metadata.xml",
		"android/gradle/wrapper/gradle-wrapper.jar",
		"android/gradle/wrapper/gradle-wrapper.properties",
	}
	required := append([]string{
		script,
		".github/toolchains/android-release.json",
		".github/toolchains/android-signer/manifest.json",
		".github/toolchains/release-go.json",
		"src/go.mod",
		"src/go.sum",
	}, gradleFiles...)
	for _, missing := range gradleFiles {
		t.Run(filepath.Base(missing), func(t *testing.T) {
			dir := t.TempDir()
			for _, path := range required {
				if path == missing {
					continue
				}
				target := filepath.Join(dir, path)
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(mustReadRepoFile(t, path)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", filepath.Join(dir, script), "build-android.yml", "all")
			output, err := cmd.Output()
			if err == nil || len(output) != 0 {
				t.Fatalf("missing %s should reject the release materials without producing JSON: %v, %s", missing, err, output)
			}
		})
	}
}

func releaseMaterialsFixture(t *testing.T, owner, arch string) map[string]any {
	t.Helper()
	hash := func(path string) string {
		return fmt.Sprintf("%x", sha256.Sum256([]byte(mustReadRepoFile(t, path))))
	}

	var goRelease struct {
		Archives map[string]string
	}
	if err := json.Unmarshal([]byte(mustReadRepoFile(t, ".github/toolchains/release-go.json")), &goRelease); err != nil {
		t.Fatal(err)
	}
	result := map[string]any{
		"go_mod_sha256": hash("src/go.mod"),
		"go_sum_sha256": hash("src/go.sum"),
	}
	switch owner {
	case "build-android.yml":
		const lock = ".github/toolchains/android-release.json"
		var android struct {
			Packages map[string]struct {
				SHA256 string
			}
		}
		if err := json.Unmarshal([]byte(mustReadRepoFile(t, lock)), &android); err != nil {
			t.Fatal(err)
		}
		var signer struct {
			JDK struct {
				SHA256 string
			}
		}
		if err := json.Unmarshal([]byte(mustReadRepoFile(t, ".github/toolchains/android-signer/manifest.json")), &signer); err != nil {
			t.Fatal(err)
		}
		for name, record := range android.Packages {
			result[name] = record.SHA256
		}
		result["toolchain_lock_sha256"] = hash(lock)
		result["go_sha256"] = goRelease.Archives["linux-amd64"]
		result["jdk_sha256"] = signer.JDK.SHA256
		result["gradle_verification_sha256"] = hash("android/gradle/verification-metadata.xml")
		result["gradle_wrapper_sha256"] = hash("android/gradle/wrapper/gradle-wrapper.jar")
		result["gradle_wrapper_properties_sha256"] = hash("android/gradle/wrapper/gradle-wrapper.properties")
	case "build-snapcraft.yml":
		result["go_sha256"] = goRelease.Archives["linux-amd64"]
		result["toolchain_lock_sha256"] = hash(".github/toolchains/snap-release/manifest.json")
		result["packages_sha256"] = hash(".github/toolchains/snap-release/os-packages-amd64.lock")
		result["host_lock_sha256"] = hash(".github/toolchains/snap-host/manifest.json")
		result["host_packages_sha256"] = hash(".github/toolchains/snap-host/os-packages-amd64.lock")
		result["host_dockerfile_sha256"] = hash(".github/toolchains/snap-host/Dockerfile")
	case "build-macos.yml":
		const lock = ".github/toolchains/macos-release.json"
		var xcode map[string]string
		if err := json.Unmarshal([]byte(mustReadRepoFile(t, lock)), &xcode); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"xcode_version", "xcode_build", "sdk_version"} {
			result[key] = xcode[key]
		}
		result["os_build"], result["image_version"] = "25E113", "20261102.0473.1"
		result["go_sha256"] = goRelease.Archives["darwin-"+arch]
		result["toolchain_lock_sha256"] = hash(lock)
	case "build-linux.yml":
		const lock = ".github/toolchains/linux-release/manifest.json"
		var linux struct {
			Snapshot      string
			Architectures map[string]map[string]string
		}
		if err := json.Unmarshal([]byte(mustReadRepoFile(t, lock)), &linux); err != nil {
			t.Fatal(err)
		}
		for key, value := range linux.Architectures[arch] {
			result[key] = value
		}
		result["snapshot"] = linux.Snapshot
		result["go_sha256"] = goRelease.Archives["linux-"+arch]
		result["toolchain_lock_sha256"] = hash(lock)
		result["packages_sha256"] = hash(".github/toolchains/linux-release/os-packages-" + arch + ".lock")
	default:
		t.Fatalf("no fixture for %s", owner)
	}
	return result
}
