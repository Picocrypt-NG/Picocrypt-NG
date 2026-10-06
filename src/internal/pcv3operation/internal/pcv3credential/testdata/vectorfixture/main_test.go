package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"
)

// Every literal byte string in this file is public deterministic test data.
const (
	testInputPath       = "../vector_fixture_input.json"
	testSourcePath      = "main.go"
	testGoSumPath       = "../../../../../../go.sum"
	testXCryptoChecksum = "h1:YLIA59K4fiNzHzjnZt2tUJQjQtUWfWbeHBqKtk3eScw="
)

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode literal hex: %v", err)
	}
	return decoded
}

func mustLoadTestInput(t *testing.T) (*fixtureInput, []byte) {
	t.Helper()
	input, raw, err := loadInput(testInputPath)
	if err != nil {
		t.Fatalf("load literal input: %v", err)
	}
	return input, raw
}

func mustTestProvenance(t *testing.T, inputBytes []byte) fixtureProvenance {
	t.Helper()
	provenance, err := buildProvenance(
		inputBytes,
		testSourcePath,
		testGoSumPath,
	)
	if err != nil {
		t.Fatalf("build test provenance: %v", err)
	}
	return provenance
}

func cloneInput(t *testing.T, input *fixtureInput) *fixtureInput {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input clone: %v", err)
	}
	var clone fixtureInput
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatalf("unmarshal input clone: %v", err)
	}
	return &clone
}

func fakeArgonRoot(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 32)
}

func flipFirstHexNibble(value string) string {
	if value[0] == '0' {
		return "1" + value[1:]
	}
	return "0" + value[1:]
}

func testXCryptoBuildInfo(checksum string) *debug.BuildInfo {
	return &debug.BuildInfo{Deps: []*debug.Module{{
		Path:    "golang.org/x/crypto",
		Version: exactXCryptoVersion,
		Sum:     checksum,
	}}}
}

func testModuleRoot(t *testing.T) (string, string, []byte) {
	t.Helper()
	root := t.TempDir()
	goSumPath := filepath.Join(root, "go.sum")
	goSum := []byte(
		"golang.org/x/crypto " + exactXCryptoVersion + " " +
			testXCryptoChecksum + "\n",
	)
	if err := os.WriteFile(goSumPath, goSum, 0o600); err != nil {
		t.Fatalf("write test go.sum: %v", err)
	}
	return root, goSumPath, goSum
}

func writeTestVendorModules(t *testing.T, root string, contents string) string {
	t.Helper()
	vendorDir := filepath.Join(root, "vendor")
	if err := os.Mkdir(vendorDir, 0o700); err != nil {
		t.Fatalf("create test vendor directory: %v", err)
	}
	modulesPath := filepath.Join(vendorDir, "modules.txt")
	if err := os.WriteFile(modulesPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test vendor inventory: %v", err)
	}
	return modulesPath
}

func canonicalXCryptoVendorModules() string {
	return "# golang.org/x/crypto " + exactXCryptoVersion + "\n" +
		"## explicit; go 1.24.0\n" +
		"golang.org/x/crypto/argon2\n" +
		"golang.org/x/crypto/blake2b\n" +
		"# golang.org/x/sys v0.41.0\n" +
		"## explicit; go 1.24.0\n" +
		"golang.org/x/sys/cpu\n"
}

func TestXCryptoProvenanceRouting(t *testing.T) {
	t.Run("nonempty match does not require vendor inventory", func(t *testing.T) {
		_, goSumPath, goSum := testModuleRoot(t)
		version, checksum, err := xCryptoProvenance(
			testXCryptoBuildInfo(testXCryptoChecksum),
			goSumPath,
			goSum,
		)
		if err != nil {
			t.Fatalf("matching build provenance rejected: %v", err)
		}
		if version != exactXCryptoVersion || checksum != testXCryptoChecksum {
			t.Fatalf(
				"matching build provenance = %q/%q; want %q/%q",
				version,
				checksum,
				exactXCryptoVersion,
				testXCryptoChecksum,
			)
		}
	})

	t.Run("nonempty mismatch cannot fall back to valid vendor inventory", func(t *testing.T) {
		root, goSumPath, goSum := testModuleRoot(t)
		writeTestVendorModules(t, root, canonicalXCryptoVendorModules())
		_, _, err := xCryptoProvenance(
			testXCryptoBuildInfo(
				"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			),
			goSumPath,
			goSum,
		)
		if err == nil || !strings.Contains(err.Error(), "checksums differ") {
			t.Fatalf("mismatched build provenance error = %v; want mismatch", err)
		}
	})

	t.Run("empty checksum requires valid vendor inventory", func(t *testing.T) {
		root, goSumPath, goSum := testModuleRoot(t)
		writeTestVendorModules(t, root, canonicalXCryptoVendorModules())
		version, checksum, err := xCryptoProvenance(
			testXCryptoBuildInfo(""),
			goSumPath,
			goSum,
		)
		if err != nil {
			t.Fatalf("valid vendored provenance rejected: %v", err)
		}
		if version != exactXCryptoVersion || checksum != testXCryptoChecksum {
			t.Fatalf(
				"vendored provenance = %q/%q; want %q/%q",
				version,
				checksum,
				exactXCryptoVersion,
				testXCryptoChecksum,
			)
		}
	})

	tests := []struct {
		name    string
		prepare func(*testing.T, string)
		wantErr string
	}{
		{
			name:    "missing inventory",
			prepare: func(*testing.T, string) {},
			wantErr: "inspect vendor/modules.txt",
		},
		{
			name: "symlink inventory",
			prepare: func(t *testing.T, root string) {
				vendorDir := filepath.Join(root, "vendor")
				if err := os.Mkdir(vendorDir, 0o700); err != nil {
					t.Fatalf("create symlink vendor directory: %v", err)
				}
				realPath := filepath.Join(vendorDir, "real-modules.txt")
				if err := os.WriteFile(
					realPath,
					[]byte(canonicalXCryptoVendorModules()),
					0o600,
				); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
				if err := os.Symlink(
					filepath.Base(realPath),
					filepath.Join(vendorDir, "modules.txt"),
				); err != nil {
					t.Fatalf("create vendor inventory symlink: %v", err)
				}
			},
			wantErr: "not a bounded regular file",
		},
		{
			name: "oversized inventory",
			prepare: func(t *testing.T, root string) {
				modulesPath := writeTestVendorModules(t, root, "")
				file, err := os.OpenFile(modulesPath, os.O_WRONLY, 0)
				if err != nil {
					t.Fatalf("open oversized vendor inventory: %v", err)
				}
				if err := file.Truncate(maxToolFileBytes + 1); err != nil {
					_ = file.Close()
					t.Fatalf("grow oversized vendor inventory: %v", err)
				}
				if err := file.Close(); err != nil {
					t.Fatalf("close oversized vendor inventory: %v", err)
				}
			},
			wantErr: "not a bounded regular file",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, goSumPath, goSum := testModuleRoot(t)
			test.prepare(t, root)
			_, _, err := xCryptoProvenance(
				testXCryptoBuildInfo(""),
				goSumPath,
				goSum,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"invalid vendor inventory error = %v; want containing %q",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func TestXCryptoBuildIdentityRejectsAmbiguity(t *testing.T) {
	tests := []struct {
		name    string
		info    *debug.BuildInfo
		wantErr string
	}{
		{
			name: "duplicate target dependency",
			info: &debug.BuildInfo{Deps: []*debug.Module{
				{Path: "golang.org/x/crypto", Version: exactXCryptoVersion},
				{Path: "golang.org/x/crypto", Version: exactXCryptoVersion},
			}},
			wantErr: "duplicate",
		},
		{
			name: "replacement",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path:    "golang.org/x/crypto",
				Version: exactXCryptoVersion,
				Replace: &debug.Module{Path: "example.invalid/x/crypto"},
			}}},
			wantErr: "replacement",
		},
		{
			name: "missing version",
			info: &debug.BuildInfo{Deps: []*debug.Module{{
				Path: "golang.org/x/crypto",
			}}},
			wantErr: "incomplete",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := xCryptoBuildIdentity(test.info)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"build identity error = %v; want containing %q",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func TestXCryptoGoSumChecksumPolicy(t *testing.T) {
	canonical := "golang.org/x/crypto " + exactXCryptoVersion + " " +
		testXCryptoChecksum + "\n"
	tests := []struct {
		name    string
		goSum   string
		wantErr string
	}{
		{
			name:    "extra field",
			goSum:   strings.TrimSuffix(canonical, "\n") + " extra\n",
			wantErr: "invalid x/crypto go.sum entry",
		},
		{
			name: "duplicate exact entry",
			goSum: canonical + strings.TrimSuffix(canonical, "\n") +
				"\n",
			wantErr: "duplicate",
		},
		{
			name:    "missing exact entry",
			goSum:   "golang.org/x/sys v0.41.0 h1:AA==\n",
			wantErr: "entry missing",
		},
		{
			name: "non-h1 checksum",
			goSum: "golang.org/x/crypto " + exactXCryptoVersion +
				" z1:YLIA59K4fiNzHzjnZt2tUJQjQtUWfWbeHBqKtk3eScw=\n",
			wantErr: "invalid x/crypto go.sum checksum",
		},
		{
			name: "invalid h1 base64",
			goSum: "golang.org/x/crypto " + exactXCryptoVersion +
				" h1:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",
			wantErr: "invalid x/crypto go.sum checksum",
		},
		{
			name: "noncanonical h1 width",
			goSum: "golang.org/x/crypto " + exactXCryptoVersion +
				" h1:AA==\n",
			wantErr: "invalid x/crypto go.sum checksum",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := xCryptoGoSumChecksum([]byte(test.goSum), exactXCryptoVersion)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"go.sum policy error = %v; want containing %q",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func TestXCryptoGoSumChecksumAcceptsGoCompatibleWhitespace(t *testing.T) {
	goSum := []byte(
		"golang.org/x/crypto   " + exactXCryptoVersion + "\t" +
			testXCryptoChecksum + "  \r\n",
	)
	checksum, err := xCryptoGoSumChecksum(goSum, exactXCryptoVersion)
	if err != nil {
		t.Fatalf("Go-compatible x/crypto go.sum entry rejected: %v", err)
	}
	if checksum != testXCryptoChecksum {
		t.Fatalf("x/crypto checksum = %q; want %q", checksum, testXCryptoChecksum)
	}
}

func TestVendoredXCryptoInventoryAcceptsGoCompatibleSyntax(t *testing.T) {
	t.Run("unrelated similar module header", func(t *testing.T) {
		root, goSumPath, _ := testModuleRoot(t)
		modules := "# example.com/golang.org/x/crypto-wrapper v1.0.0\n" +
			"## explicit; go 1.24.0\n" +
			"example.com/golang.org/x/crypto-wrapper/pkg\n" +
			canonicalXCryptoVendorModules()
		writeTestVendorModules(t, root, modules)
		if err := validateVendoredXCrypto(goSumPath); err != nil {
			t.Fatalf("unrelated similar module rejected: %v", err)
		}
	})

	t.Run("target fields use whitespace", func(t *testing.T) {
		root, goSumPath, _ := testModuleRoot(t)
		modules := "#   golang.org/x/crypto   " + exactXCryptoVersion + "\r\n" +
			"## explicit; go 1.24.0\r\n" +
			"  golang.org/x/crypto/argon2\t\r\n" +
			"golang.org/x/crypto/blake2b\r\n" +
			"# golang.org/x/sys v0.41.0\r\n" +
			"## explicit; go 1.24.0\r\n" +
			"golang.org/x/sys/cpu\r\n"
		writeTestVendorModules(t, root, modules)
		if err := validateVendoredXCrypto(goSumPath); err != nil {
			t.Fatalf("Go-compatible vendor inventory rejected: %v", err)
		}
	})
}

func TestVendoredXCryptoInventoryPolicy(t *testing.T) {
	t.Run("canonical inventory", func(t *testing.T) {
		root, goSumPath, _ := testModuleRoot(t)
		writeTestVendorModules(t, root, canonicalXCryptoVendorModules())
		if err := validateVendoredXCrypto(goSumPath); err != nil {
			t.Fatalf("canonical vendor inventory rejected: %v", err)
		}
	})

	canonical := canonicalXCryptoVendorModules()
	tests := []struct {
		name    string
		modules string
		wantErr string
	}{
		{
			name: "inline replacement",
			modules: strings.Replace(
				canonical,
				"# golang.org/x/crypto "+exactXCryptoVersion,
				"# golang.org/x/crypto "+exactXCryptoVersion+" => ./crypto",
				1,
			),
			wantErr: "replacement",
		},
		{
			name:    "trailing replacement",
			modules: canonical + "# golang.org/x/crypto => ./crypto\n",
			wantErr: "replacement",
		},
		{
			name:    "duplicate target block",
			modules: canonical + canonical,
			wantErr: "duplicate",
		},
		{
			name: "wrong version",
			modules: strings.Replace(
				canonical,
				exactXCryptoVersion,
				"v0.53.0",
				1,
			),
			wantErr: "version",
		},
		{
			name: "missing explicit marker",
			modules: strings.Replace(
				canonical,
				"## explicit; go 1.24.0\n",
				"",
				1,
			),
			wantErr: "explicit marker",
		},
		{
			name: "duplicate explicit marker",
			modules: strings.Replace(
				canonical,
				"## explicit; go 1.24.0\n",
				"## explicit; explicit; go 1.24.0\n",
				1,
			),
			wantErr: "explicit marker",
		},
		{
			name: "malformed explicit metadata",
			modules: strings.Replace(
				canonical,
				"## explicit; go 1.24.0\n",
				"##garbage; explicit\n",
				1,
			),
			wantErr: "malformed",
		},
		{
			name: "missing argon2 package",
			modules: strings.Replace(
				canonical,
				"golang.org/x/crypto/argon2\n",
				"",
				1,
			),
			wantErr: "package count",
		},
		{
			name: "argon2 package owned by another module",
			modules: "# example.com/other v1.0.0\n" +
				"## explicit; go 1.24.0\n" +
				"golang.org/x/crypto/argon2\n" +
				strings.Replace(
					canonical,
					"golang.org/x/crypto/argon2\n",
					"",
					1,
				),
			wantErr: "outside target vendor block",
		},
		{
			name: "duplicate argon2 package",
			modules: strings.Replace(
				canonical,
				"golang.org/x/crypto/argon2\n",
				"golang.org/x/crypto/argon2\n"+
					"golang.org/x/crypto/argon2\n",
				1,
			),
			wantErr: "package count",
		},
		{
			name: "malformed target header",
			modules: strings.Replace(
				canonical,
				"# golang.org/x/crypto "+exactXCryptoVersion,
				"# golang.org/x/crypto "+exactXCryptoVersion+" unexpected",
				1,
			),
			wantErr: "malformed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, goSumPath, _ := testModuleRoot(t)
			writeTestVendorModules(t, root, test.modules)
			err := validateVendoredXCrypto(goSumPath)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf(
					"vendor policy error = %v; want containing %q",
					err,
					test.wantErr,
				)
			}
		})
	}
}

func TestLiteralCredentialInputKAT(t *testing.T) {
	tests := []struct {
		name       string
		transcript string
		want       string
	}{
		{
			name:       "password only NFC",
			transcript: "0101000000000005436166c3a90000",
			want:       "47156ab898a6329d3388ca7d762b35af622897e7ce3e7da960aa55f9b1051073afeb902632ea30ddef7d6da4fc6f12c34493bb5abda4ee9a3ac191cba09dd011",
		},
		{
			name:       "keyfiles only ordered",
			transcript: "0102010000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5",
			want:       "b46f148394701876e14463e4e49ea0e47a5ba76bf798f165452413902273081f466f22547c86aeca4185d13e706cd3eec72eaa59a6983fe9115ea27d25715420",
		},
		{
			name:       "combined ordered",
			transcript: "01030100000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0",
			want:       "d4ac95f6c2f0d7ddfe7eadd0a7a01d527acc8c302876884f9c5fb240446f0655d5e0201aecfb73af77e07ac7e18692271a6bec281bc8fc7b270aec30d99f1b02",
		},
		{
			name:       "combined unordered",
			transcript: "01030200000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0",
			want:       "5089ee8f6c1fcce5338e0fb2054b8ec9d461d5d5987627d866329e8bc6eb07965af1a1fdd1c3f89c92838ac6e0080629eacf5935decdaff29301678550085544",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := hex.EncodeToString(normalCredentialInput(
				mustDecodeHex(t, test.transcript),
			))
			if got != test.want {
				t.Fatalf("CredentialInputNormal = %s; want %s", got, test.want)
			}
		})
	}
}

func TestLiteralProfileTableKAT(t *testing.T) {
	input, _ := mustLoadTestInput(t)
	type literalProfile struct {
		id            string
		profileID     uint8
		suiteID       uint16
		argonVersion  uint8
		time          uint32
		memoryKiB     uint32
		parallelism   uint8
		outputBytes   uint32
		saltHex       string
		credentialID  string
		volumeIDHex   string
		volumeKeyHex  string
		scheduleCount int
	}
	want := []literalProfile{
		{
			id: "normal-1", profileID: 1, suiteID: 1, argonVersion: 0x13,
			time: 4, memoryKiB: 1048576, parallelism: 4, outputBytes: 32,
			saltHex:      "000102030405060708090a0b0c0d0e0f",
			credentialID: "combined-ordered", scheduleCount: 9,
			volumeIDHex:  "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			volumeKeyHex: "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		},
		{
			id: "paranoid-1", profileID: 2, suiteID: 2, argonVersion: 0x13,
			time: 8, memoryKiB: 1048576, parallelism: 8, outputBytes: 32,
			saltHex:      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			credentialID: "combined-unordered", scheduleCount: 12,
			volumeIDHex:  "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			volumeKeyHex: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
		},
	}
	if len(input.Profiles) != len(want) {
		t.Fatalf("profile count = %d; want %d", len(input.Profiles), len(want))
	}
	for index, expected := range want {
		actual := input.Profiles[index]
		got := literalProfile{
			id:            actual.ID,
			profileID:     actual.ProfileID,
			suiteID:       actual.SuiteID,
			argonVersion:  actual.Argon2Version,
			time:          actual.Time,
			memoryKiB:     actual.MemoryKiB,
			parallelism:   actual.Parallelism,
			outputBytes:   actual.OutputBytes,
			saltHex:       actual.ArgonSaltHex,
			credentialID:  actual.CredentialCaseID,
			volumeIDHex:   actual.VolumeIDHex,
			volumeKeyHex:  actual.VolumeKeyHex,
			scheduleCount: len(actual.Schedule),
		}
		if got != expected {
			t.Fatalf("profile %d = %+v; want literal %+v", index, got, expected)
		}
	}
}

func TestLiteralInfoEncodingKAT(t *testing.T) {
	tests := []struct {
		name string
		row  scheduleInput
		want string
	}{
		{
			name: "standard primary credential wrap",
			row: scheduleInput{
				SuiteID: 1, Role: 0, Label: "credential/wrap/xchacha20",
			},
			want: "5069636f63727970742d4e472f504356332f484b44460000030001000100001963726564656e7469616c2f777261702f786368616368613230",
		},
		{
			name: "standard backup volume replica",
			row: scheduleInput{
				SuiteID: 1, Role: 1, Label: "volume/replica/mac",
			},
			want: "5069636f63727970742d4e472f504356332f484b444600000300010001010012766f6c756d652f7265706c6963612f6d6163",
		},
		{
			name: "paranoid non-replica payload serpent",
			row: scheduleInput{
				SuiteID: 2, Role: 0xff, Label: "volume/payload/serpent",
			},
			want: "5069636f63727970742d4e472f504356332f484b444600000300010002ff0016766f6c756d652f7061796c6f61642f73657270656e74",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := encodeInfo(test.row)
			if err != nil {
				t.Fatalf("encode Info: %v", err)
			}
			if got := hex.EncodeToString(info); got != test.want {
				t.Fatalf("Info = %s; want literal %s", got, test.want)
			}
		})
	}
}

func TestLiteralRootSeparationKAT(t *testing.T) {
	volumeID := mustDecodeHex(
		t,
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
	)
	credentialRoot := mustDecodeHex(
		t,
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	)
	volumeKey := mustDecodeHex(
		t,
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	)
	result, err := deriveProfile(1, profileInput{
		ID:           "literal-root-separation",
		VolumeIDHex:  hex.EncodeToString(volumeID),
		VolumeKeyHex: hex.EncodeToString(volumeKey),
	}, "", credentialRoot)
	if err != nil {
		t.Fatalf("derive literal roots: %v", err)
	}
	const (
		wantExtractA = "6a9b141b80e2518e2de6eade9c6f8beb0caa6d90441ab42f4f81b2c38ee83d4b"
		wantExtractB = "59a0a7ad4f47977f7945d67358e0e5c9cf5a5a4e33bc9ebbef0321bfb87eafad"
	)
	if got := result.CredentialPRKHex; got != wantExtractA {
		t.Fatalf("CredentialPRK = %s; want literal %s", got, wantExtractA)
	}
	if got := result.VolumePRKHex; got != wantExtractB {
		t.Fatalf("VolumePRK = %s; want literal %s", got, wantExtractB)
	}
	if result.CredentialPRKHex == result.VolumePRKHex {
		t.Fatal("independent CredentialPRK and VolumePRK unexpectedly match")
	}
}

func TestLiteralScheduleRowsKAT(t *testing.T) {
	input, _ := mustLoadTestInput(t)
	wantRows := [][]string{
		{
			"credential-wrap-xchacha20-primary|credential-prk|1|0|credential/wrap/xchacha20|32",
			"credential-wrap-xchacha20-backup|credential-prk|1|1|credential/wrap/xchacha20|32",
			"credential-wrap-mac-primary|credential-prk|1|0|credential/wrap/mac|32",
			"credential-wrap-mac-backup|credential-prk|1|1|credential/wrap/mac|32",
			"volume-replica-mac-primary|volume-prk|1|0|volume/replica/mac|32",
			"volume-replica-mac-backup|volume-prk|1|1|volume/replica/mac|32",
			"volume-metadata-mac|volume-prk|1|255|volume/metadata/mac|32",
			"volume-payload-xchacha20|volume-prk|1|255|volume/payload/xchacha20|32",
			"volume-payload-mac|volume-prk|1|255|volume/payload/mac|32",
		},
		{
			"credential-wrap-xchacha20-primary|credential-prk|2|0|credential/wrap/xchacha20|32",
			"credential-wrap-xchacha20-backup|credential-prk|2|1|credential/wrap/xchacha20|32",
			"credential-wrap-serpent-primary|credential-prk|2|0|credential/wrap/serpent|32",
			"credential-wrap-serpent-backup|credential-prk|2|1|credential/wrap/serpent|32",
			"credential-wrap-mac-primary|credential-prk|2|0|credential/wrap/mac|32",
			"credential-wrap-mac-backup|credential-prk|2|1|credential/wrap/mac|32",
			"volume-replica-mac-primary|volume-prk|2|0|volume/replica/mac|32",
			"volume-replica-mac-backup|volume-prk|2|1|volume/replica/mac|32",
			"volume-metadata-mac|volume-prk|2|255|volume/metadata/mac|32",
			"volume-payload-xchacha20|volume-prk|2|255|volume/payload/xchacha20|32",
			"volume-payload-serpent|volume-prk|2|255|volume/payload/serpent|32",
			"volume-payload-mac|volume-prk|2|255|volume/payload/mac|32",
		},
	}
	for profileIndex, expectedRows := range wantRows {
		actualRows := input.Profiles[profileIndex].Schedule
		if len(actualRows) != len(expectedRows) {
			t.Fatalf(
				"profile %d schedule rows = %d; want %d",
				profileIndex,
				len(actualRows),
				len(expectedRows),
			)
		}
		for rowIndex, row := range actualRows {
			got := fmt.Sprintf(
				"%s|%s|%d|%d|%s|%d",
				row.ID,
				row.Root,
				row.SuiteID,
				row.Role,
				row.Label,
				row.OutputBytes,
			)
			if got != expectedRows[rowIndex] {
				t.Fatalf(
					"profile %d row %d = %q; want literal %q",
					profileIndex,
					rowIndex,
					got,
					expectedRows[rowIndex],
				)
			}
		}
	}

	const (
		extractAHex = "6a9b141b80e2518e2de6eade9c6f8beb0caa6d90441ab42f4f81b2c38ee83d4b"
		extractBHex = "59a0a7ad4f47977f7945d67358e0e5c9cf5a5a4e33bc9ebbef0321bfb87eafad"
	)
	tests := []struct {
		name       string
		schedule   scheduleInput
		wantInfo   string
		wantOutput string
	}{
		{
			name: "standard credential xchacha primary",
			schedule: scheduleInput{
				ID: "standard-credential-xchacha-primary", Root: "credential-prk",
				SuiteID: 1, Role: 0, Label: "credential/wrap/xchacha20", OutputBytes: 32,
			},
			wantInfo:   "5069636f63727970742d4e472f504356332f484b44460000030001000100001963726564656e7469616c2f777261702f786368616368613230",
			wantOutput: "e50004d55c5de716217dba37fdc8704c810bdb17a87a4fd28134a547e9153d2d",
		},
		{
			name: "standard volume replica backup",
			schedule: scheduleInput{
				ID: "standard-volume-replica-backup", Root: "volume-prk",
				SuiteID: 1, Role: 1, Label: "volume/replica/mac", OutputBytes: 32,
			},
			wantInfo:   "5069636f63727970742d4e472f504356332f484b444600000300010001010012766f6c756d652f7265706c6963612f6d6163",
			wantOutput: "0b4429ae0d21b34f3a3c8970e37d1fe3bd9a37e47a9191fbee9be08063472de6",
		},
		{
			name: "paranoid credential serpent primary",
			schedule: scheduleInput{
				ID: "paranoid-credential-serpent-primary", Root: "credential-prk",
				SuiteID: 2, Role: 0, Label: "credential/wrap/serpent", OutputBytes: 32,
			},
			wantInfo:   "5069636f63727970742d4e472f504356332f484b44460000030001000200001763726564656e7469616c2f777261702f73657270656e74",
			wantOutput: "7d59a7ab58dbf98fb7935c02d99c874c5ad7574da070f27ae488cef16fd7e8df",
		},
		{
			name: "paranoid volume payload serpent",
			schedule: scheduleInput{
				ID: "paranoid-volume-payload-serpent", Root: "volume-prk",
				SuiteID: 2, Role: 0xff, Label: "volume/payload/serpent", OutputBytes: 32,
			},
			wantInfo:   "5069636f63727970742d4e472f504356332f484b444600000300010002ff0016766f6c756d652f7061796c6f61642f73657270656e74",
			wantOutput: "362fea5e0df95cb4764075a888fc9f4fb422d867c9a997a51e9dcf1451160c86",
		},
	}
	schedule := make([]scheduleInput, len(tests))
	for index := range tests {
		schedule[index] = tests[index].schedule
	}
	rows, err := deriveRows(
		schedule,
		mustDecodeHex(t, extractAHex),
		mustDecodeHex(t, extractBHex),
	)
	if err != nil {
		t.Fatalf("derive literal schedule: %v", err)
	}
	for _, test := range tests {
		row := rows[0]
		rows = rows[1:]
		t.Run(test.name, func(t *testing.T) {
			if row.InfoHex != test.wantInfo {
				t.Fatalf("Info = %s; want literal %s", row.InfoHex, test.wantInfo)
			}
			if row.ExpandOutputHex != test.wantOutput {
				t.Fatalf(
					"derived key = %s; want literal %s",
					row.ExpandOutputHex,
					test.wantOutput,
				)
			}
		})
	}
}

func TestLiteralInputValidation(t *testing.T) {
	baseline, raw := mustLoadTestInput(t)
	if err := validateInput(baseline); err != nil {
		t.Fatalf("literal baseline rejected: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*fixtureInput)
		wantErr string
	}{
		{
			name: "duplicate credential ID",
			mutate: func(input *fixtureInput) {
				input.CredentialCases[0].ID = input.CredentialCases[1].ID
			},
			wantErr: "credential case 0 identity mismatch",
		},
		{
			name: "credential input digest",
			mutate: func(input *fixtureInput) {
				input.CredentialCases[1].NormalInputHex = "046f148394701876e14463e4e49ea0e47a5ba76bf798f165452413902273081f466f22547c86aeca4185d13e706cd3eec72eaa59a6983fe9115ea27d25715420"
			},
			wantErr: "normal credential input mismatch",
		},
		{
			name: "self-consistent credential literal drift",
			mutate: func(input *fixtureInput) {
				transcript := mustDecodeHex(t, input.CredentialCases[0].TranscriptHex)
				transcript[8] = 'D'
				input.CredentialCases[0].TranscriptHex = hex.EncodeToString(transcript)
				input.CredentialCases[0].NormalInputHex = hex.EncodeToString(normalCredentialInput(transcript))
			},
			wantErr: "credential case 0 literal mismatch",
		},
		{
			name: "password length maximum",
			mutate: func(input *fixtureInput) {
				transcript := mustDecodeHex(t, input.CredentialCases[0].TranscriptHex)
				binary.BigEndian.PutUint32(transcript[4:8], (1<<20)+1)
				input.CredentialCases[0].TranscriptHex = hex.EncodeToString(transcript)
			},
			wantErr: "password exceeds 1 MiB",
		},
		{
			name: "fixed profile",
			mutate: func(input *fixtureInput) {
				input.Profiles[0].MemoryKiB--
			},
			wantErr: "fixed profile tuple mismatch",
		},
		{
			name: "missing row",
			mutate: func(input *fixtureInput) {
				input.Profiles[0].Schedule = input.Profiles[0].Schedule[:len(input.Profiles[0].Schedule)-1]
			},
			wantErr: "schedule row count mismatch",
		},
		{
			name: "extra row",
			mutate: func(input *fixtureInput) {
				input.Profiles[1].Schedule = append(
					input.Profiles[1].Schedule,
					input.Profiles[1].Schedule[0],
				)
			},
			wantErr: "schedule row count mismatch",
		},
		{
			name: "same-count duplicate row",
			mutate: func(input *fixtureInput) {
				input.Profiles[0].Schedule[1] = input.Profiles[0].Schedule[0]
			},
			wantErr: "schedule row 1 mismatch",
		},
		{
			name: "row suite",
			mutate: func(input *fixtureInput) {
				input.Profiles[0].Schedule[0].SuiteID = 2
			},
			wantErr: "schedule row 0 mismatch",
		},
		{
			name: "row root",
			mutate: func(input *fixtureInput) {
				input.Profiles[0].Schedule[0].Root = "volume-prk"
			},
			wantErr: "schedule row 0 mismatch",
		},
		{
			name: "row role",
			mutate: func(input *fixtureInput) {
				input.Profiles[0].Schedule[0].Role = 0xff
			},
			wantErr: "schedule row 0 mismatch",
		},
		{
			name: "row label",
			mutate: func(input *fixtureInput) {
				input.Profiles[1].Schedule[2].Label = "credential/wrap/mac"
			},
			wantErr: "schedule row 2 mismatch",
		},
		{
			name: "volume ID literal",
			mutate: func(input *fixtureInput) {
				input.Profiles[0].VolumeIDHex = flipFirstHexNibble(input.Profiles[0].VolumeIDHex)
			},
			wantErr: "literal profile input mismatch",
		},
		{
			name: "volume key literal",
			mutate: func(input *fixtureInput) {
				input.Profiles[1].VolumeKeyHex = flipFirstHexNibble(input.Profiles[1].VolumeKeyHex)
			},
			wantErr: "literal profile input mismatch",
		},
		{
			name: "row width",
			mutate: func(input *fixtureInput) {
				input.Profiles[1].Schedule[2].OutputBytes = 31
			},
			wantErr: "schedule row 2 mismatch",
		},
		{
			name: "uppercase salt",
			mutate: func(input *fixtureInput) {
				input.Profiles[1].ArgonSaltHex = strings.ToUpper(input.Profiles[1].ArgonSaltHex)
			},
			wantErr: "canonical lowercase hex",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutant := cloneInput(t, baseline)
			test.mutate(mutant)
			err := validateInput(mutant)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validation error = %v; want containing %q", err, test.wantErr)
			}
		})
	}

	noncanonical := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(noncanonical, append([]byte(" "), raw...), 0o600); err != nil {
		t.Fatalf("write noncanonical input: %v", err)
	}
	_, _, err := loadInput(noncanonical)
	if err == nil || !strings.Contains(err.Error(), "noncanonical JSON") {
		t.Fatalf("noncanonical input error = %v; want canonical rejection", err)
	}
}

func TestGenerateHarness(t *testing.T) {
	input, inputBytes := mustLoadTestInput(t)
	provenance := mustTestProvenance(t, inputBytes)
	type call struct {
		id          string
		time        uint32
		memoryKiB   uint32
		parallelism uint8
		outputBytes uint32
		inputHex    string
		saltHex     string
	}
	var calls []call
	// This fake proves only exact generator control flow. It is not KDF
	// compatibility evidence.
	derive := func(
		profile profileInput,
		credentialInput []byte,
		salt []byte,
	) ([]byte, error) {
		calls = append(calls, call{
			id: profile.ID, time: profile.Time, memoryKiB: profile.MemoryKiB,
			parallelism: profile.Parallelism, outputBytes: profile.OutputBytes,
			inputHex: hex.EncodeToString(credentialInput),
			saltHex:  hex.EncodeToString(salt),
		})
		return fakeArgonRoot(byte(len(calls))), nil
	}

	value, err := generateFixture(input, provenance, derive)
	if err != nil {
		t.Fatalf("generate harness fixture: %v", err)
	}
	wantCalls := []call{
		{
			id: "normal-1", time: 4, memoryKiB: 1048576,
			parallelism: 4, outputBytes: 32,
			inputHex: "d4ac95f6c2f0d7ddfe7eadd0a7a01d527acc8c302876884f9c5fb240446f0655d5e0201aecfb73af77e07ac7e18692271a6bec281bc8fc7b270aec30d99f1b02",
			saltHex:  "000102030405060708090a0b0c0d0e0f",
		},
		{
			id: "paranoid-1", time: 8, memoryKiB: 1048576,
			parallelism: 8, outputBytes: 32,
			inputHex: "5089ee8f6c1fcce5338e0fb2054b8ec9d461d5d5987627d866329e8bc6eb07965af1a1fdd1c3f89c92838ac6e0080629eacf5935decdaff29301678550085544",
			saltHex:  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("Argon harness calls = %+v; want literal %+v", calls, wantCalls)
	}
	if len(value.Profiles) != 2 {
		t.Fatalf("generated fixture profiles = %d; want 2", len(value.Profiles))
	}
	if len(value.Profiles[0].Rows) != 9 ||
		len(value.Profiles[1].Rows) != 12 {
		t.Fatalf(
			"generated fixture row shape = %d/%d profiles=%d; want 9/12/2",
			len(value.Profiles[0].Rows),
			len(value.Profiles[1].Rows),
			len(value.Profiles),
		)
	}

	t.Run("generator source set is exact", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"main.go", "main_test.go"} {
			source, readErr := os.ReadFile(name)
			if readErr != nil {
				t.Fatalf("read %s: %v", name, readErr)
			}
			if writeErr := os.WriteFile(
				filepath.Join(dir, name),
				source,
				0o600,
			); writeErr != nil {
				t.Fatalf("write %s: %v", name, writeErr)
			}
		}
		mainPath := filepath.Join(dir, "main.go")
		if err := validateGeneratorSourceSet(mainPath); err != nil {
			t.Fatalf("exact generator source set rejected: %v", err)
		}
		if err := os.WriteFile(
			filepath.Join(dir, "extra.go"),
			[]byte("package main\n"),
			0o600,
		); err != nil {
			t.Fatalf("write extra source: %v", err)
		}
		err := validateGeneratorSourceSet(mainPath)
		if err == nil || !strings.Contains(err.Error(), "unexpected") {
			t.Fatalf("extra source error = %v; want source-set rejection", err)
		}
	})

	t.Run("final output identity rejects replacement", func(t *testing.T) {
		dir := t.TempDir()
		ownedPath := filepath.Join(dir, "owned")
		foreignPath := filepath.Join(dir, "foreign")
		if err := os.WriteFile(ownedPath, []byte("owned"), 0o600); err != nil {
			t.Fatalf("write owned fixture: %v", err)
		}
		if err := os.WriteFile(foreignPath, []byte("foreign"), 0o600); err != nil {
			t.Fatalf("write foreign fixture: %v", err)
		}
		owned, err := os.Lstat(ownedPath)
		if err != nil {
			t.Fatalf("stat owned fixture: %v", err)
		}
		err = verifyOutputIdentity(foreignPath, owned)
		if err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("foreign output error = %v; want identity rejection", err)
		}
	})

	t.Run("generate writes one canonical fixture", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "vectors.json")
		argonCalls := 0
		var stdout bytes.Buffer
		err := run([]string{
			"generate",
			"--input", testInputPath,
			"--source", testSourcePath,
			"--go-sum", testGoSumPath,
			"--output", output,
		}, &stdout, func(
			profileInput,
			[]byte,
			[]byte,
		) ([]byte, error) {
			argonCalls++
			return fakeArgonRoot(byte(argonCalls)), nil
		})
		if err != nil {
			t.Fatalf("generate canonical fixture: %v", err)
		}
		if argonCalls != 2 {
			t.Fatalf("generate caused %d Argon calls; want 2", argonCalls)
		}
		if !strings.Contains(stdout.String(), "\"status\": \"generated\"") ||
			!strings.Contains(stdout.String(), "\"argon_calls\": 2") {
			t.Fatalf("generate terminal record = %q", stdout.String())
		}
		generated, _, err := readCanonicalJSON[fixture](output)
		if err != nil {
			t.Fatalf("read generated fixture: %v", err)
		}
		if err := validateFixture(input, provenance, &generated); err != nil {
			t.Fatalf("validate generated fixture: %v", err)
		}
	})

	t.Run("occupied output rejects before Argon", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "vectors.json")
		sentinel := []byte("do not replace")
		if err := os.WriteFile(output, sentinel, 0o600); err != nil {
			t.Fatalf("write sentinel: %v", err)
		}
		argonCalls := 0
		err := run([]string{
			"generate",
			"--input", testInputPath,
			"--source", testSourcePath,
			"--go-sum", testGoSumPath,
			"--output", output,
		}, &bytes.Buffer{}, func(
			profileInput,
			[]byte,
			[]byte,
		) ([]byte, error) {
			argonCalls++
			return fakeArgonRoot(1), nil
		})
		if err == nil || !strings.Contains(err.Error(), "reserve output") {
			t.Fatalf("occupied-output error = %v; want reserve rejection", err)
		}
		if argonCalls != 0 {
			t.Fatalf("occupied output caused %d Argon calls; want 0", argonCalls)
		}
		after, readErr := os.ReadFile(output)
		if readErr != nil {
			t.Fatalf("read sentinel: %v", readErr)
		}
		if !bytes.Equal(after, sentinel) {
			t.Fatalf("occupied output changed to %q; want %q", after, sentinel)
		}
	})

	t.Run("invalid fake width leaves fail-closed reservation", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "vectors.json")
		err := run([]string{
			"generate",
			"--input", testInputPath,
			"--source", testSourcePath,
			"--go-sum", testGoSumPath,
			"--output", output,
		}, &bytes.Buffer{}, func(
			profileInput,
			[]byte,
			[]byte,
		) ([]byte, error) {
			return make([]byte, 31), nil
		})
		if err == nil || !strings.Contains(err.Error(), "invalid root width") {
			t.Fatalf("invalid-width error = %v; want width rejection", err)
		}
		info, statErr := os.Lstat(output)
		if statErr != nil {
			t.Fatalf("stat failed reservation: %v", statErr)
		}
		if !info.Mode().IsRegular() || info.Size() != 0 {
			t.Fatalf(
				"failed reservation mode/size = %v/%d; want regular empty file",
				info.Mode(),
				info.Size(),
			)
		}
		argonCalls := 0
		secondErr := run([]string{
			"generate",
			"--input", testInputPath,
			"--source", testSourcePath,
			"--go-sum", testGoSumPath,
			"--output", output,
		}, &bytes.Buffer{}, func(
			profileInput,
			[]byte,
			[]byte,
		) ([]byte, error) {
			argonCalls++
			return fakeArgonRoot(1), nil
		})
		if secondErr == nil || !strings.Contains(secondErr.Error(), "reserve output") {
			t.Fatalf("second generate error = %v; want reservation rejection", secondErr)
		}
		if argonCalls != 0 {
			t.Fatalf("failed reservation retry caused %d Argon calls; want 0", argonCalls)
		}
	})
}

func TestCheckFixture(t *testing.T) {
	const fixturePath = "../kdf_vectors.json"
	value, before, err := readCanonicalJSON[fixture](fixturePath)
	if err != nil {
		t.Fatalf("read committed fixture: %v", err)
	}
	dir := t.TempDir()
	// This callback guards dispatcher separation: check mode must not use the
	// supplied generation deriver. The terminal record below is a schema
	// assertion, not an independent call-graph proof about runCheck.
	generationDeriverCalls := 0
	var stdout bytes.Buffer
	err = run([]string{
		"check",
		"--input", testInputPath,
		"--source", testSourcePath,
		"--go-sum", testGoSumPath,
		"--fixture", fixturePath,
	}, &stdout, func(profileInput, []byte, []byte) ([]byte, error) {
		generationDeriverCalls++
		return nil, errors.New("check must not use the generation deriver")
	})
	if err != nil {
		t.Fatalf("check committed fixture: %v", err)
	}
	if generationDeriverCalls != 0 {
		t.Fatalf(
			"check used the generation deriver %d times; want 0",
			generationDeriverCalls,
		)
	}
	if !strings.Contains(stdout.String(), "\"argon_calls\": 0") {
		t.Fatalf("check terminal record = %q; want frozen-root schema", stdout.String())
	}
	after, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read checked fixture: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("check modified committed fixture bytes")
	}

	tests := []struct {
		name    string
		mutate  func(*fixture)
		wantErr string
	}{
		{
			name: "provenance",
			mutate: func(mutant *fixture) {
				mutant.Provenance.InputSHA256 = strings.Repeat("0", 64)
			},
			wantErr: "provenance mismatch",
		},
		{
			name: "credential root",
			mutate: func(mutant *fixture) {
				mutant.Profiles[0].CredentialRootHex = flipFirstHexNibble(mutant.Profiles[0].CredentialRootHex)
			},
			wantErr: "root separation mismatch",
		},
		{
			name: "Info",
			mutate: func(mutant *fixture) {
				mutant.Profiles[0].Rows[0].InfoHex = flipFirstHexNibble(mutant.Profiles[0].Rows[0].InfoHex)
			},
			wantErr: "row 0 mismatch",
		},
		{
			name: "derived output",
			mutate: func(mutant *fixture) {
				mutant.Profiles[1].Rows[11].ExpandOutputHex = flipFirstHexNibble(
					mutant.Profiles[1].Rows[11].ExpandOutputHex,
				)
			},
			wantErr: "row 11 mismatch",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutantBytes, marshalErr := json.Marshal(value)
			if marshalErr != nil {
				t.Fatalf("marshal fixture clone: %v", marshalErr)
			}
			var mutant fixture
			if unmarshalErr := json.Unmarshal(mutantBytes, &mutant); unmarshalErr != nil {
				t.Fatalf("unmarshal fixture clone: %v", unmarshalErr)
			}
			test.mutate(&mutant)
			mutantEncoded, encodeErr := canonicalJSON(mutant)
			if encodeErr != nil {
				t.Fatalf("encode mutant: %v", encodeErr)
			}
			mutantPath := filepath.Join(dir, strings.ReplaceAll(test.name, " ", "-")+".json")
			if writeErr := os.WriteFile(mutantPath, mutantEncoded, 0o600); writeErr != nil {
				t.Fatalf("write mutant: %v", writeErr)
			}
			generationDeriverCalls = 0
			checkErr := run([]string{
				"check",
				"--input", testInputPath,
				"--source", testSourcePath,
				"--go-sum", testGoSumPath,
				"--fixture", mutantPath,
			}, &bytes.Buffer{}, func(profileInput, []byte, []byte) ([]byte, error) {
				generationDeriverCalls++
				return nil, errors.New("check must not use the generation deriver")
			})
			if checkErr == nil || !strings.Contains(checkErr.Error(), test.wantErr) {
				t.Fatalf("mutant error = %v; want containing %q", checkErr, test.wantErr)
			}
			if generationDeriverCalls != 0 {
				t.Fatalf(
					"mutant check used the generation deriver %d times; want 0",
					generationDeriverCalls,
				)
			}
		})
	}

	noncanonicalPath := filepath.Join(dir, "noncanonical.json")
	if err := os.WriteFile(
		noncanonicalPath,
		append([]byte(" "), before...),
		0o600,
	); err != nil {
		t.Fatalf("write noncanonical fixture: %v", err)
	}
	generationDeriverCalls = 0
	err = run([]string{
		"check",
		"--input", testInputPath,
		"--source", testSourcePath,
		"--go-sum", testGoSumPath,
		"--fixture", noncanonicalPath,
	}, &bytes.Buffer{}, func(profileInput, []byte, []byte) ([]byte, error) {
		generationDeriverCalls++
		return nil, errors.New("check must not use the generation deriver")
	})
	if err == nil || !strings.Contains(err.Error(), "noncanonical JSON") {
		t.Fatalf("noncanonical fixture error = %v; want canonical rejection", err)
	}
	if generationDeriverCalls != 0 {
		t.Fatalf(
			"noncanonical check used the generation deriver %d times; want 0",
			generationDeriverCalls,
		)
	}
	final, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("re-read committed fixture: %v", err)
	}
	if !bytes.Equal(final, before) {
		t.Fatal("fixture checks modified committed fixture bytes")
	}
}
