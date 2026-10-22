package workflowpolicy

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Tool adapters isolate metadata/signature output; ZIP and ELF inspection use real files/tools.
func TestAndroidReleaseAPKVerifierFourABIContract(t *testing.T) {
	for _, kind := range []string{"unsigned", "signed"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newAndroidAPKVerifierFixture(t, kind)
			fixture.verify(t, true)
		})
	}
	for _, defect := range []string{
		"missing-arm32", "unknown-apk", "nested-duplicate-apk", "apk-symlink",
		"extra-apk-symlink", "duplicate-jni-member", "arm32-is-elf64",
		"arm64-is-elf32", "x86-wrong-machine", "universal-missing-x86", "wrong-signer",
		"arm32-wrong-version-code", "wrong-min-sdk", "signed-as-unsigned",
		"universal-legacy-base-code",
	} {
		t.Run(defect, func(t *testing.T) {
			kind := "unsigned"
			if defect == "wrong-signer" {
				kind = "signed"
			}
			fixture := newAndroidAPKVerifierFixture(t, kind)
			arm32 := fixture.apk("armeabi-v7a")
			switch defect {
			case "missing-arm32":
				mustRemoveAndroidFixture(t, arm32)
			case "unknown-apk":
				mustWriteAndroidFixture(t, fixture.apk("unknown"), []byte("unexpected APK"), 0o600)
			case "nested-duplicate-apk":
				mustWriteAndroidFixture(t, filepath.Join(fixture.directory, "nested", filepath.Base(arm32)), []byte("duplicate APK name"), 0o600)
			case "apk-symlink", "extra-apk-symlink":
				link := fixture.apk("unknown")
				if defect == "apk-symlink" {
					mustRemoveAndroidFixture(t, arm32)
					link = arm32
				}
				if err := os.Symlink(fixture.apk("arm64-v8a"), link); err != nil {
					t.Fatal(err)
				}
			case "duplicate-jni-member":
				writeAndroidFixtureAPK(t, arm32, []string{"armeabi-v7a", "armeabi-v7a"}, nil)
			case "arm32-is-elf64":
				writeAndroidFixtureAPK(t, arm32, []string{"armeabi-v7a"}, map[string][2]uint16{"armeabi-v7a": {2, 40}})
			case "arm64-is-elf32":
				writeAndroidFixtureAPK(t, fixture.apk("arm64-v8a"), []string{"arm64-v8a"}, map[string][2]uint16{"arm64-v8a": {1, 183}})
			case "x86-wrong-machine":
				writeAndroidFixtureAPK(t, fixture.apk("x86"), []string{"x86"}, map[string][2]uint16{"x86": {1, 40}})
			case "universal-missing-x86":
				writeAndroidFixtureAPK(t, fixture.apk("universal"), []string{"armeabi-v7a", "arm64-v8a", "x86_64"}, nil)
			case "wrong-signer":
				mustWriteAndroidFixture(t, arm32+".signature", []byte("Number of signers: 1\nSigner #1 certificate SHA-256 digest: "+strings.Repeat("0", 64)+"\n"), 0o600)
			case "arm32-wrong-version-code":
				mustWriteAndroidFixture(t, arm32+".badging", []byte("package: name='io.github.picocrypt_ng.picocrypt_ng' versionCode='300002' versionName='3.0'\nsdkVersion:'26'\n"), 0o600)
			case "wrong-min-sdk":
				mustWriteAndroidFixture(t, arm32+".badging", []byte("package: name='io.github.picocrypt_ng.picocrypt_ng' versionCode='300001' versionName='3.0'\nsdkVersion:'25'\n"), 0o600)
			case "signed-as-unsigned":
				mustWriteAndroidFixture(t, arm32+".signature", []byte("Verifies\n"), 0o600)
				mustWriteAndroidFixture(t, arm32+".signature-exit", []byte("0"), 0o600)
			case "universal-legacy-base-code":
				mustWriteAndroidFixture(t, fixture.apk("universal")+".badging", []byte("package: name='io.github.picocrypt_ng.picocrypt_ng' versionCode='30000' versionName='3.0'\nsdkVersion:'26'\n"), 0o600)
			}
			fixture.verify(t, false)
		})
	}
}

type androidAPKVerifierFixture struct {
	directory, kind, tools, readelf, anchor string
}

func (f androidAPKVerifierFixture) apk(abi string) string {
	suffix := ""
	if f.kind == "unsigned" {
		suffix = "-unsigned"
	}
	return filepath.Join(f.directory, "app-"+abi+"-release"+suffix+".apk")
}

func (f androidAPKVerifierFixture) verify(t *testing.T, wantSuccess bool) {
	t.Helper()
	command := exec.Command("bash", filepath.Join(repoRoot(t), "android/verify-release-apks.sh"), f.directory, "3.0", "30000", "io.github.picocrypt_ng.picocrypt_ng", f.kind)
	command.Env = append(os.Environ(), "AAPT="+filepath.Join(f.tools, "aapt"), "APKSIGNER="+filepath.Join(f.tools, "apksigner"), "READELF="+f.readelf, "PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE="+f.anchor)
	output, err := command.CombinedOutput()
	if (err == nil) != wantSuccess {
		t.Fatalf("verifier success = %v, want %v: %v\n%s", err == nil, wantSuccess, err, output)
	}
}

func newAndroidAPKVerifierFixture(t *testing.T, kind string) androidAPKVerifierFixture {
	t.Helper()
	readelf, err := exec.LookPath("readelf")
	if err != nil {
		t.Skip("verifier tooling fixture requires readelf")
	}
	root := t.TempDir()
	f := androidAPKVerifierFixture{directory: filepath.Join(root, "apks"), kind: kind, tools: filepath.Join(root, "tools"), readelf: readelf, anchor: filepath.Join(repoRoot(t), "android/release-signing-cert-sha256.txt")}
	mustWriteAndroidFixture(t, filepath.Join(f.tools, "aapt"), []byte("#!/usr/bin/env bash\nset -eu\nif [[ $1 == version ]]; then echo fixture-aapt; else cat \"${@: -1}.badging\"; fi\n"), 0o700)
	mustWriteAndroidFixture(t, filepath.Join(f.tools, "apksigner"), []byte("#!/usr/bin/env bash\nset -eu\nif [[ ${@: -1} == version ]]; then echo fixture-apksigner; exit 0; fi\ncat \"${@: -1}.signature\"\nexit \"$(cat \"${@: -1}.signature-exit\")\"\n"), 0o700)
	for abi, code := range map[string]int{"armeabi-v7a": 300001, "arm64-v8a": 300002, "x86": 300003, "x86_64": 300004, "universal": 300000} {
		abis := []string{abi}
		if abi == "universal" {
			abis = []string{"armeabi-v7a", "arm64-v8a", "x86", "x86_64"}
		}
		apk := f.apk(abi)
		writeAndroidFixtureAPK(t, apk, abis, nil)
		badging := fmt.Sprintf("package: name='io.github.picocrypt_ng.picocrypt_ng' versionCode='%d' versionName='3.0'\nsdkVersion:'26'\n", code)
		mustWriteAndroidFixture(t, apk+".badging", []byte(badging), 0o600)
		signature, exit := "DOES NOT VERIFY\nERROR: Missing META-INF/MANIFEST.MF\n", "1"
		if kind == "signed" {
			signature, exit = "Number of signers: 1\nSigner #1 certificate SHA-256 digest: "+strings.TrimSpace(mustReadRepoFile(t, "android/release-signing-cert-sha256.txt"))+"\n", "0"
		}
		mustWriteAndroidFixture(t, apk+".signature", []byte(signature), 0o600)
		mustWriteAndroidFixture(t, apk+".signature-exit", []byte(exit), 0o600)
	}
	return f
}

func writeAndroidFixtureAPK(t *testing.T, path string, abis []string, overrides map[string][2]uint16) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for _, abi := range abis {
		format := map[string][2]uint16{"armeabi-v7a": {1, 40}, "arm64-v8a": {2, 183}, "x86": {1, 3}, "x86_64": {2, 62}}[abi]
		if override, ok := overrides[abi]; ok {
			format = override
		}
		data := make([]byte, 64)
		copy(data, []byte{0x7f, 'E', 'L', 'F', byte(format[0]), 1, 1})
		binary.LittleEndian.PutUint16(data[16:], 3)
		binary.LittleEndian.PutUint16(data[18:], format[1])
		binary.LittleEndian.PutUint32(data[20:], 1)
		if format[0] == 1 {
			binary.LittleEndian.PutUint16(data[40:], 52)
		} else {
			binary.LittleEndian.PutUint16(data[52:], 64)
		}
		member, err := archive.Create("lib/" + abi + "/libgojni.so")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustWriteAndroidFixture(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func mustRemoveAndroidFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
