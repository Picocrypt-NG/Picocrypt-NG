package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	testBaseline = "1111111111111111111111111111111111111111"
	testBase     = "2222222222222222222222222222222222222222"
)

var fixtureBinaryCache struct {
	sync.Mutex
	directory string
	paths     map[string]string
}

func TestMain(testMain *testing.M) {
	code := testMain.Run()
	fixtureBinaryCache.Lock()
	directory := fixtureBinaryCache.directory
	fixtureBinaryCache.Unlock()
	if directory != "" {
		_ = os.RemoveAll(directory)
	}
	os.Exit(code)
}

func TestInspectorValidClosure(t *testing.T) {
	fixture := newInspectorFixture(t)
	config := fixture.readConfig(t)
	var mutationEvidence fixtureStageEvidence
	readTestJSON(
		t,
		filepath.Join(
			fixture.evidenceDir,
			config.EvidenceContract.StageFilenames["mutation"],
		),
		&mutationEvidence,
	)
	t.Run("serialized mutation paths share copied module root", func(t *testing.T) {
		mutationCount := 0
		for _, command := range mutationEvidence.Commands {
			for _, mutation := range command.Mutations {
				mutationCount++
				sourceCopy := ""
				for index, argument := range mutation.Application.Argv {
					if argument != "--source-copy" {
						continue
					}
					if sourceCopy != "" || index+1 >= len(mutation.Application.Argv) {
						t.Fatalf(
							"mutation %q application has invalid --source-copy argv: %q",
							mutation.ID,
							mutation.Application.Argv,
						)
					}
					sourceCopy = mutation.Application.Argv[index+1]
				}
				moduleRoot := filepath.Join(
					fixture.evidenceDir,
					".phasegates-mutation-tmp",
					mutation.ID,
					"source",
					"src",
				)
				if sourceCopy != moduleRoot ||
					mutation.Pristine.CWD != moduleRoot ||
					mutation.Mutant.CWD != moduleRoot {
					t.Fatalf(
						"mutation %q copied module root mismatch: application=%q pristine=%q mutant=%q want=%q",
						mutation.ID,
						sourceCopy,
						mutation.Pristine.CWD,
						mutation.Mutant.CWD,
						moduleRoot,
					)
				}
			}
		}
		if mutationCount != len(config.RequiredMutationIDs) {
			t.Fatalf(
				"serialized mutation count = %d; want %d",
				mutationCount,
				len(config.RequiredMutationIDs),
			)
		}
	})
	var identity fixtureExecutionIdentity
	readTestJSON(t, fixture.identityPath, &identity)
	if identity.Runner.MainPackagePath !=
		"Picocrypt-NG/internal/pcv3credential/testdata/phasegates" {
		t.Fatalf("runner main package = %q", identity.Runner.MainPackagePath)
	}
	if identity.Inspector.MainPackagePath !=
		"Picocrypt-NG/internal/pcv3credential/testdata/phaseinspect" {
		t.Fatalf("inspector main package = %q", identity.Inspector.MainPackagePath)
	}
	if identity.Runner.File.SHA256 == identity.Inspector.File.SHA256 {
		t.Fatal("runner and inspector binaries are not distinct")
	}
	requireTrimpathWithoutLDFlags(t, fixture.runnerPath)
	requireTrimpathWithoutLDFlags(t, fixture.selfPath)
	got := fixture.inspect(t)
	if !reflect.DeepEqual(got, fixture.wantVerdict(t)) {
		t.Fatalf("normalized verdict mismatch:\n got: %#v\nwant: %#v", got, fixture.wantVerdict(t))
	}
}

func TestInspectorRejectsStageSet(t *testing.T) {
	for _, test := range []struct {
		name      string
		wantError string
		mutate    func(*testing.T, *inspectorFixture)
	}{
		{
			name:      "missing",
			wantError: "required evidence stage set mismatch",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				fixture.removeArtifact(t, "host")
			},
		},
		{
			name:      "extra terminal artifact",
			wantError: "required evidence stage set mismatch",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				fixture.writePrivate(t, filepath.Join(fixture.evidenceDir, "extra.evidence.json"), []byte("{}\n"))
			},
		},
		{
			name: "duplicate",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				fixture.rewriteEvidence(t, "mutation", func(evidence map[string]any) {
					evidence["stage"] = "normal1"
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			test.mutate(t, fixture)
			fixture.requireRejected(t, test.wantError)
		})
	}
	t.Run("real ceremony root permits stable workspace entries", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.writePrivate(
			t,
			filepath.Join(fixture.evidenceDir, "operator-note.txt"),
			[]byte("stable non-terminal entry\n"),
		)
		fixture.assertRealCeremonyRootLayout(t)
		_ = fixture.inspect(t)
	})
	t.Run("empty real-binary preflight", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.removeAllEvidence(t)
		before := fixture.snapshot(t)
		fixture.requireRejectedExact(
			t,
			"required evidence stage set mismatch",
		)
		after := fixture.snapshot(t)
		if !sameInputSnapshots(before, after) {
			t.Fatalf(
				"empty-evidence preflight changed the fixture:\n before=%#v\n after=%#v",
				before,
				after,
			)
		}
	})
}

func TestInspectorRejectsEvidenceProofBinding(t *testing.T) {
	for _, test := range []struct {
		name      string
		wantError string
		mutate    func(*testing.T, *inspectorFixture, string, string)
	}{
		{
			name:      "mutable evidence mode",
			wantError: "evidence file mode mismatch",
			mutate: func(
				t *testing.T,
				_ *inspectorFixture,
				evidencePath string,
				_ string,
			) {
				t.Helper()
				if err := os.Chmod(evidencePath, 0o600); err != nil {
					t.Fatalf("make evidence mutable: %v", err)
				}
			},
		},
		{
			name:      "mutable proof mode",
			wantError: "evidence proof mode mismatch",
			mutate: func(
				t *testing.T,
				_ *inspectorFixture,
				_ string,
				proofPath string,
			) {
				t.Helper()
				if err := os.Chmod(proofPath, 0o600); err != nil {
					t.Fatalf("make evidence proof mutable: %v", err)
				}
			},
		},
		{
			name:      "proof bound to different evidence",
			wantError: "evidence publication proof mismatch",
			mutate: func(
				t *testing.T,
				fixture *inspectorFixture,
				_ string,
				proofPath string,
			) {
				t.Helper()
				var proof fixtureEvidenceProof
				readTestJSON(t, proofPath, &proof)
				if len(proof.EvidenceSHA256) != sha256.Size*2 {
					t.Fatalf(
						"fixture proof SHA-256 length = %d",
						len(proof.EvidenceSHA256),
					)
				}
				replacement := byte('0')
				if proof.EvidenceSHA256[0] == replacement {
					replacement = '1'
				}
				proof.EvidenceSHA256 = string(replacement) +
					proof.EvidenceSHA256[1:]
				fixture.rewriteReadOnly(
					t,
					proofPath,
					canonicalTestJSON(t, proof),
					0o400,
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			config := fixture.readConfig(t)
			if len(config.EvidenceContract.RequiredStageNames) == 0 {
				t.Fatal("fixture has no required evidence stages")
			}
			evidencePath := filepath.Join(
				fixture.evidenceDir,
				config.EvidenceContract.StageFilenames[config.EvidenceContract.RequiredStageNames[0]],
			)
			proofPath := evidencePath +
				config.EvidenceContract.PublicationProofSuffix
			test.mutate(t, fixture, evidencePath, proofPath)
			fixture.requireRejectedExact(t, test.wantError)
		})
	}
}

// Kills treating the protocol's pending proof as an unrelated stable workspace
// entry after publication was left incomplete.
func TestInspectorRejectsPendingPublicationProof(t *testing.T) {
	fixture := newInspectorFixture(t)
	config := fixture.readConfig(t)
	evidenceName := config.EvidenceContract.StageFilenames["mutation"]
	proofPath := filepath.Join(
		fixture.evidenceDir,
		evidenceName+config.EvidenceContract.PublicationProofSuffix,
	)
	proofData, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("read valid proof fixture: %v", err)
	}
	fixture.writePrivate(
		t,
		filepath.Join(
			fixture.evidenceDir,
			"."+evidenceName+
				config.EvidenceContract.PublicationProofSuffix+
				".pending",
		),
		proofData,
	)
	fixture.requireRejectedExact(t, "pending evidence proof exists")
}

// Kills accepting an evidence or proof inode that remains reachable through an
// unrelated hard-link alias outside the terminal artifact namespace.
func TestInspectorRejectsEvidenceAndProofHardLinkAliases(t *testing.T) {
	for _, test := range []struct {
		name      string
		proof     bool
		wantError string
	}{
		{
			name:      "evidence inode alias",
			wantError: "evidence file link count mismatch",
		},
		{
			name:      "proof inode alias",
			proof:     true,
			wantError: "evidence proof link count mismatch",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			config := fixture.readConfig(t)
			name := config.EvidenceContract.StageFilenames["mutation"]
			if test.proof {
				name += config.EvidenceContract.PublicationProofSuffix
			}
			if err := os.Link(
				filepath.Join(fixture.evidenceDir, name),
				filepath.Join(
					fixture.evidenceDir,
					"unrelated-"+strings.ReplaceAll(test.name, " ", "-"),
				),
			); err != nil {
				t.Fatalf("create unrelated hard-link alias: %v", err)
			}
			fixture.requireRejectedExact(t, test.wantError)
		})
	}
}

func TestInspectorRejectsIdentityMismatch(t *testing.T) {
	for _, test := range []struct {
		name      string
		wantError string
		mutate    func(*testing.T, *inspectorFixture)
	}{
		{
			name: "baseline",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				replaceInspectorArg(t, fixture.args, "--baseline", strings.Repeat("3", 40))
			},
		},
		{
			name: "identity hash",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				replaceInspectorArg(
					t,
					fixture.args,
					"--execution-identity-sha256",
					strings.Repeat("4", 64),
				)
			},
		},
		{
			name: "stage identity",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
					evidence["execution_identity_sha256"] = strings.Repeat("5", 64)
				})
			},
		},
		{
			name: "live source tree",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				path := filepath.Join(
					fixture.source,
					"src",
					"internal",
					"fileops",
					"unpack_test.go",
				)
				fixture.rewriteReadOnly(
					t,
					path,
					[]byte("package fileops\n// drift\n"),
					0o400,
				)
			},
		},
		{
			name:      "non-linux platform",
			wantError: "execution identity header mismatch",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				fixture.rewriteIdentity(t, func(identity map[string]any) {
					identity["goos"] = "darwin"
				})
			},
		},
		{
			name:      "ancestor symlink",
			wantError: "path contains symlink component",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation is not reliably available on Windows")
				}
				alias := filepath.Join(fixture.root, "source-alias")
				if err := os.Symlink(fixture.source, alias); err != nil {
					t.Fatalf("create source ancestor symlink: %v", err)
				}
				aliasedConfig := filepath.Join(alias, filepath.Base(fixture.configPath))
				replaceInspectorArg(t, fixture.args, "--config", aliasedConfig)
				fixture.rewriteIdentity(t, func(identity map[string]any) {
					identity["config"] = toJSONObject(
						t,
						fixtureFileIdentityFor(t, aliasedConfig),
					)
				})
				var identity fixtureExecutionIdentity
				readTestJSON(t, fixture.identityPath, &identity)
				if got := fixtureFileIdentityFor(t, aliasedConfig); identity.Config != got {
					t.Fatalf("aliased config identity mismatch:\n got: %#v\nwant: %#v", identity.Config, got)
				}
				if got := testSHA256File(t, fixture.identityPath); fixture.args[13] != got {
					t.Fatalf("aliased execution identity hash = %s; want %s", fixture.args[13], got)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			test.mutate(t, fixture)
			fixture.requireRejected(t, test.wantError)
		})
	}
	for _, test := range []struct {
		name      string
		wantError string
		mutate    func(map[string]any)
	}{
		{
			name:      "module rebound in config and identity",
			wantError: "gate config module/version mismatch",
			mutate: func(config map[string]any) {
				config["module"] = "Not-Picocrypt-NG"
			},
		},
		{
			name:      "build attestation contract",
			wantError: "build attestation contract mismatch",
			mutate: func(config map[string]any) {
				config["build_attestation"].(map[string]any)["classification"] = "weaker"
			},
		},
		{
			name:      "runtime binding contract",
			wantError: "runtime binding contract mismatch",
			mutate: func(config map[string]any) {
				config["runtime_bindings"].(map[string]any)["baseline"] = "optional"
			},
		},
		{
			name:      "dependency contract",
			wantError: "dependency contract mismatch",
			mutate: func(config map[string]any) {
				config["dependency_contract"].(map[string]any)["mode"] = "module-cache"
			},
		},
		{
			name:      "CPU contract",
			wantError: "CPU contract mismatch",
			mutate: func(config map[string]any) {
				config["cpu_contract"].(map[string]any)["phase_jobs_formula"] = "online"
			},
		},
		{
			name:      "child environment allowlist order",
			wantError: "child environment contract mismatch",
			mutate: func(config map[string]any) {
				allowlist := config["child_environment"].(map[string]any)["allowlist"].([]any)
				allowlist[0], allowlist[1] = allowlist[1], allowlist[0]
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			fixture.rewriteConfig(t, func(config map[string]any) {
				test.mutate(config)
			})
			fixture.requireRejected(t, test.wantError)
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *inspectorFixture, map[string]any)
	}{
		{
			name: "self consistency executable key set",
			mutate: func(
				t *testing.T,
				_ *inspectorFixture,
				identity map[string]any,
			) {
				t.Helper()
				executables := identity["executables"].(map[string]any)
				executables["${EXTRA}"] = executables["${GO}"]
			},
		},
		{
			name: "self consistency working directories",
			mutate: func(
				t *testing.T,
				fixture *inspectorFixture,
				identity map[string]any,
			) {
				t.Helper()
				identity["working_directories"] = []string{fixture.source}
			},
		},
		{
			name: "self consistency stage environment",
			mutate: func(
				t *testing.T,
				_ *inspectorFixture,
				identity map[string]any,
			) {
				t.Helper()
				environments := identity["stage_child_environments"].(map[string]any)
				environments["host"] = []string{"SYSTEMROOT=malformed"}
			},
		},
		{
			name: "self consistency GOARCH",
			mutate: func(
				t *testing.T,
				_ *inspectorFixture,
				identity map[string]any,
			) {
				t.Helper()
				identity["goarch"] = "not-" + runtime.GOARCH
			},
		},
		{
			name: "self consistency online CPUs",
			mutate: func(
				t *testing.T,
				_ *inspectorFixture,
				identity map[string]any,
			) {
				t.Helper()
				online := runtime.NumCPU() + 2
				identity["online"] = online
				identity["phase_jobs"] = derivedPhaseJobs(online)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			fixture.rewriteIdentity(t, func(identity map[string]any) {
				test.mutate(t, fixture, identity)
			})
			fixture.requireRejectedExact(
				t,
				map[string]string{
					"self consistency executable key set":  "execution identity executable set mismatch",
					"self consistency working directories": "execution identity working directories mismatch",
					"self consistency stage environment":   "execution identity child environment mismatch",
					"self consistency GOARCH":              "execution identity host facts mismatch",
					"self consistency online CPUs":         "execution identity host facts mismatch",
				}[test.name],
			)
		})
	}
	t.Run("self consistency Go executable build version", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		notGo := filepath.Join(fixture.root, "not-go")
		fixture.writeExecutable(t, notGo, []byte("#!/bin/sh\nexit 0\n"))
		fixture.rebindGoExecutable(t, notGo)
		fixture.requireRejectedExact(
			t,
			"execution identity Go executable build version mismatch",
		)
	})
	t.Run("self consistency Go executable nonempty version mismatch", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteIdentity(t, func(identity map[string]any) {
			executables := identity["executables"].(map[string]any)
			goExecutable := executables["${GO}"].(map[string]any)
			goExecutable["go_build_version"] = "go1.26.4"
		})
		fixture.requireRejectedExact(
			t,
			"execution identity Go executable build version mismatch",
		)
	})
	t.Run("self consistency Go executable main package", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rebindGoExecutable(t, fixture.runnerPath)
		fixture.requireRejectedExact(
			t,
			"execution identity Go executable main package mismatch",
		)
	})
	t.Run("runner requires trimpath", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		nonTrimpath := fixtureBinaryFor(
			t,
			"./internal/pcv3credential/testdata/phasegates",
			testBaseline,
			testBase,
			testSHA256File(t, fixture.sourceManifest),
			false,
		)
		fixture.replaceExecutable(t, nonTrimpath, fixture.runnerPath)
		var identity fixtureExecutionIdentity
		readTestJSON(t, fixture.identityPath, &identity)
		identity.Runner = fixtureExecutableIdentityFor(t, fixture.runnerPath)
		fixture.writeExecutionIdentityAndEvidence(t, identity)
		fixture.requireRejectedExact(
			t,
			"runner or inspector trimpath build policy mismatch",
		)
	})
	t.Run("inspector requires trimpath", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		nonTrimpath := fixtureBinaryFor(
			t,
			"./internal/pcv3credential/testdata/phaseinspect",
			testBaseline,
			testBase,
			testSHA256File(t, fixture.sourceManifest),
			false,
		)
		fixture.replaceExecutable(t, nonTrimpath, fixture.selfPath)
		var identity fixtureExecutionIdentity
		readTestJSON(t, fixture.identityPath, &identity)
		identity.Inspector = fixtureExecutableIdentityFor(t, fixture.selfPath)
		fixture.writeExecutionIdentityAndEvidence(t, identity)
		fixture.requireRejectedExact(
			t,
			"runner or inspector trimpath build policy mismatch",
		)
	})
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *inspectorFixture, *fixtureExecutionIdentity)
	}{
		{
			name: "public evidence root",
			mutate: func(
				t *testing.T,
				fixture *inspectorFixture,
				identity *fixtureExecutionIdentity,
			) {
				t.Helper()
				if err := os.Chmod(fixture.evidenceDir, 0o755); err != nil {
					t.Fatalf("make evidence root public: %v", err)
				}
				identity.EvidenceRoot = fixtureDirectoryIdentityFor(
					t,
					fixture.evidenceDir,
				)
				identity.EvidenceRoot.ModTimeUnixNano = 0
			},
		},
		{
			name: "noncanonical evidence root timestamp",
			mutate: func(
				t *testing.T,
				_ *inspectorFixture,
				identity *fixtureExecutionIdentity,
			) {
				t.Helper()
				identity.EvidenceRoot.ModTimeUnixNano = 1
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			var identity fixtureExecutionIdentity
			readTestJSON(t, fixture.identityPath, &identity)
			test.mutate(t, fixture, &identity)
			fixture.writeExecutionIdentityAndEvidence(t, identity)
			fixture.requireRejectedExact(
				t,
				"evidence root contract mismatch",
			)
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *inspectorFixture)
	}{
		{
			name: "self consistency missing private root",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				t.Helper()
				if err := os.Remove(filepath.Join(
					fixture.evidenceDir,
					".phasegates-home",
				)); err != nil {
					t.Fatalf("remove private root: %v", err)
				}
			},
		},
		{
			name: "self consistency private root mode",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				t.Helper()
				if err := os.Chmod(filepath.Join(
					fixture.evidenceDir,
					".phasegates-go-path",
				), 0o755); err != nil {
					t.Fatalf("weaken private root mode: %v", err)
				}
			},
		},
		{
			name: "self consistency phasegates leftover",
			mutate: func(t *testing.T, fixture *inspectorFixture) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(
					fixture.evidenceDir,
					".phasegates-host-tmp",
				), 0o700); err != nil {
					t.Fatalf("create phasegates leftover: %v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			test.mutate(t, fixture)
			fixture.requireRejectedExact(
				t,
				"private workspace lifecycle mismatch",
			)
		})
	}
}

// Kills accepting the module-cache fallback sentinel based only on directory
// identity while files inside it can influence Go dependency resolution.
func TestInspectorRejectsNonemptyModuleCacheSentinel(t *testing.T) {
	fixture := newInspectorFixture(t)
	fixture.writePrivate(
		t,
		filepath.Join(
			fixture.evidenceDir,
			".phasegates-go-mod-cache",
			"unexpected-module-cache-entry",
		),
		[]byte("must remain empty\n"),
	)
	fixture.requireRejectedExact(t, "module-cache sentinel is not empty")
}

func TestInspectorRejectsSelfPathHashOrVersionMismatch(t *testing.T) {
	for _, field := range []string{"path", "sha256", "go_build_version"} {
		t.Run(field, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			fixture.rewriteIdentity(t, func(identity map[string]any) {
				inspector := identity["inspector"].(map[string]any)
				if field == "go_build_version" {
					inspector[field] = "go0.invalid"
					return
				}
				file := inspector["file"].(map[string]any)
				if field == "path" {
					file[field] = filepath.Join(fixture.root, "wrong-inspector")
				} else {
					file[field] = strings.Repeat("6", 64)
				}
			})
			fixture.requireRejected(t)
		})
	}
	for _, test := range []struct {
		name           string
		baseline       string
		base           string
		sourceManifest string
	}{
		{
			name:           "wrong linked baseline",
			baseline:       strings.Repeat("3", 40),
			base:           testBase,
			sourceManifest: "",
		},
		{
			name:           "wrong linked base",
			baseline:       testBaseline,
			base:           strings.Repeat("4", 40),
			sourceManifest: "",
		},
		{
			name:           "wrong linked source manifest",
			baseline:       testBaseline,
			base:           testBase,
			sourceManifest: strings.Repeat("5", 64),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			sourceManifest := test.sourceManifest
			if sourceManifest == "" {
				sourceManifest = testSHA256File(t, fixture.sourceManifest)
			}
			wrongInspector := fixtureBinaryFor(
				t,
				"./internal/pcv3credential/testdata/phaseinspect",
				test.baseline,
				test.base,
				sourceManifest,
				true,
			)
			fixture.replaceExecutable(t, wrongInspector, fixture.selfPath)
			fixture.rewriteIdentity(t, func(identity map[string]any) {
				identity["inspector"] = toJSONObject(
					t,
					fixtureExecutableIdentityFor(t, fixture.selfPath),
				)
			})
			fixture.removeAllEvidence(t)
			before := fixture.snapshot(t)
			fixture.requireRejectedExact(
				t,
				"running inspector build binding mismatch",
			)
			after := fixture.snapshot(t)
			if !sameInputSnapshots(before, after) {
				t.Fatalf(
					"wrong-X preflight changed the fixture:\n before=%#v\n after=%#v",
					before,
					after,
				)
			}
		})
	}
}

func TestInspectorRejectsSelfResolutionOrBuildInfoFailure(t *testing.T) {
	t.Run("symlink identity", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation is not reliably available on Windows")
		}
		fixture := newInspectorFixture(t)
		link := filepath.Join(fixture.root, "inspector-link")
		if err := os.Symlink(fixture.selfPath, link); err != nil {
			t.Fatalf("create inspector symlink: %v", err)
		}
		fixture.rewriteIdentity(t, func(identity map[string]any) {
			identity["inspector"].(map[string]any)["file"].(map[string]any)["path"] = link
		})
		fixture.requireRejected(t)
	})
	t.Run("missing build info", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		path := filepath.Join(fixture.root, "not-go")
		fixture.writeExecutable(t, path, []byte("#!/bin/sh\nexit 0\n"))
		executable := fixtureExecutableIdentityFor(t, path)
		fixture.rewriteIdentity(t, func(identity map[string]any) {
			identity["inspector"] = toJSONObject(t, executable)
		})
		fixture.requireRejected(t)
	})
}

func TestInspectorRejectsExecutionSurfaceOverlap(t *testing.T) {
	t.Run("reviewed hierarchical siblings are disjoint", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		_ = fixture.inspect(t)
	})
	t.Run("identical hierarchical selectors overlap", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteConfig(t, func(config map[string]any) {
			stages := config["stages"].(map[string]any)
			normal := stages["normal1"].(map[string]any)["commands"].([]any)[0].(map[string]any)
			paranoid := stages["paranoid1"].(map[string]any)["commands"].([]any)[0].(map[string]any)
			paranoid["execution_surface"] = normal["execution_surface"]
		})
		fixture.requireRejected(t)
	})
	t.Run("hierarchical parent and child overlap", func(t *testing.T) {
		parent := executionSurface{
			PackagePaths: []string{"./internal/pcv3credential"},
			BuildTags:    []string{"migrated_fynedo"},
			TestSelector: "^TestFoo$",
			EvidenceKind: "go-test-json",
		}
		child := parent
		child.TestSelector = "^TestFoo$/^bar$"
		if !executionSurfacesOverlap(parent, child) {
			t.Fatal("exact parent selector did not overlap its child selector")
		}
	})
	t.Run("regex metacharacter selector overlaps literal match", func(t *testing.T) {
		regex := executionSurface{
			PackagePaths: []string{"./internal/pcv3credential"},
			BuildTags:    []string{"migrated_fynedo"},
			TestSelector: "^TestFoo.$",
			EvidenceKind: "go-test-json",
		}
		literal := regex
		literal.TestSelector = "^TestFooA$"
		if !executionSurfacesOverlap(regex, literal) {
			t.Fatal("ambiguous regex selector was not treated as overlapping")
		}
	})
}

// Kills trusting a declared go-test execution surface instead of deriving it
// from the canonical argv and frozen child environment.
func TestInspectorBindsGoTestExecutionSurfaceToArgv(t *testing.T) {
	for _, test := range []struct {
		name      string
		wantError string
		mutate    func(*commandConfig)
	}{
		{
			name:      "declared package disagreement",
			wantError: "go-test execution surface does not match argv",
			mutate: func(command *commandConfig) {
				command.ExecutionSurface.PackagePaths = []string{"./internal/not-the-argv-package"}
			},
		},
		{
			name:      "declared build tag disagreement",
			wantError: "go-test execution surface does not match argv",
			mutate: func(command *commandConfig) {
				command.ExecutionSurface.BuildTags = []string{"migrated_fynedo"}
			},
		},
		{
			name:      "declared selector disagreement",
			wantError: "go-test execution surface does not match argv",
			mutate: func(command *commandConfig) {
				command.ExecutionSurface.TestSelector = "^TestDifferent$"
			},
		},
		{
			name:      "declared evidence kind disagreement",
			wantError: "go-test execution surface does not match argv",
			mutate: func(command *commandConfig) {
				command.ExecutionSurface.EvidenceKind = "go-test-race-json"
			},
		},
		{
			name:      "missing json",
			wantError: "go-test argv requires exactly one canonical -json",
			mutate: func(command *commandConfig) {
				command.Argv = removeConfigArg(command.Argv, "-json")
			},
		},
		{
			name:      "duplicate json",
			wantError: "go-test argv requires exactly one canonical -json",
			mutate: func(command *commandConfig) {
				command.Argv = append(command.Argv, "-json")
			},
		},
		{
			name:      "missing package parallelism",
			wantError: "go-test argv requires exactly one canonical -p 1",
			mutate: func(command *commandConfig) {
				command.Argv = removeConfigArgPair(command.Argv, "-p")
			},
		},
		{
			name:      "duplicate package parallelism",
			wantError: "go-test argv requires exactly one canonical -p 1",
			mutate: func(command *commandConfig) {
				command.Argv = append(command.Argv, "-p", "1")
			},
		},
		{
			name:      "noncanonical package parallelism",
			wantError: "go-test argv contains a noncanonical execution flag",
			mutate: func(command *commandConfig) {
				command.Argv = append(
					removeConfigArgPair(command.Argv, "-p"),
					"-p=1",
				)
			},
		},
		{
			name:      "nonserial package parallelism",
			wantError: "go-test argv requires exactly one canonical -p 1",
			mutate: func(command *commandConfig) {
				for index := range command.Argv {
					if command.Argv[index] == "-p" {
						command.Argv[index+1] = "2"
						return
					}
				}
			},
		},
		{
			name:      "go-test not marked Go-based",
			wantError: "go-test command must be Go-based",
			mutate: func(command *commandConfig) {
				command.GoBased = false
			},
		},
		{
			name:      "package wildcard",
			wantError: "go-test argv package is not exact",
			mutate: func(command *commandConfig) {
				for index := range command.Argv {
					if command.Argv[index] == "./internal/pcv3credential" {
						command.Argv[index] = "./internal/..."
						return
					}
				}
			},
		},
		{
			name:      "canonical race under frozen CGO-disabled environment",
			wantError: "go -race command requires CGO_ENABLED=1",
			mutate: func(command *commandConfig) {
				command.Argv = append(command.Argv, "-race")
				command.ExecutionSurface.EvidenceKind = "go-test-race-json"
			},
		},
		{
			name:      "duplicate canonical race",
			wantError: "go-test argv contains duplicate -race",
			mutate: func(command *commandConfig) {
				command.Argv = append(command.Argv, "-race", "-race")
				command.ExecutionSurface.EvidenceKind = "go-test-race-json"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := reviewedInspectorConfig(t)
			stage := config.Stages["normal1"]
			test.mutate(&stage.Commands[0])
			config.Stages["normal1"] = stage
			_, err := validateGateConfig(&config)
			if err == nil || err.Error() != test.wantError {
				t.Fatalf(
					"invalid go-test execution error = %v; want %q",
					err,
					test.wantError,
				)
			}
		})
	}
	for _, alias := range []string{"--race", "-race=true", "--race=true"} {
		t.Run("noncanonical race "+alias, func(t *testing.T) {
			config := reviewedInspectorConfig(t)
			stage := config.Stages["normal1"]
			stage.Commands[0].Argv = append(stage.Commands[0].Argv, alias)
			stage.Commands[0].ExecutionSurface.EvidenceKind = "go-test-race-json"
			config.Stages["normal1"] = stage
			_, err := validateGateConfig(&config)
			if err == nil ||
				err.Error() != "go race flag must use exact -race form" {
				t.Fatalf("noncanonical race error = %v; want exact-form rejection", err)
			}
		})
	}
	t.Run("canonical race derives race evidence under frozen CGO-enabled environment", func(t *testing.T) {
		config := reviewedInspectorConfig(t)
		command := config.Stages["normal1"].Commands[0]
		command.Argv = append(command.Argv, "-race")
		command.ExecutionSurface.EvidenceKind = "go-test-race-json"
		if err := validateGoTestExecutionSurface(command, "1"); err != nil {
			t.Fatalf("canonical CGO-enabled race command rejected: %v", err)
		}
	})
}

// Kills accepting a go-test argv without the exact reproducibility count and
// an inner Go timeout bounded by the outer command timeout.
func TestInspectorRequiresCanonicalGoTestCountAndTimeout(t *testing.T) {
	const countError = "go-test argv requires exactly one canonical -count=1"
	const timeoutError = "go-test argv requires exactly one canonical positive -timeout shorter than outer timeout"
	for _, test := range []struct {
		name      string
		wantError string
		mutate    func(*commandConfig)
	}{
		{
			name:      "missing count",
			wantError: countError,
			mutate: func(command *commandConfig) {
				command.Argv = removeConfigArg(command.Argv, "-count=1")
			},
		},
		{
			name:      "duplicate count",
			wantError: countError,
			mutate: func(command *commandConfig) {
				command.Argv = append(command.Argv, "-count=1")
			},
		},
		{
			name:      "noncanonical count",
			wantError: countError,
			mutate: func(command *commandConfig) {
				command.Argv = replaceConfigArgPrefix(
					command.Argv,
					"-count",
					"-count=2",
				)
			},
		},
		{
			name:      "missing timeout",
			wantError: timeoutError,
			mutate: func(command *commandConfig) {
				command.Argv = removeConfigArgPrefix(
					command.Argv,
					"-timeout=",
				)
			},
		},
		{
			name:      "duplicate timeout",
			wantError: timeoutError,
			mutate: func(command *commandConfig) {
				command.Argv = append(command.Argv, "-timeout=1s")
			},
		},
		{
			name:      "noncanonical timeout",
			wantError: timeoutError,
			mutate: func(command *commandConfig) {
				command.Argv = replaceConfigArgPrefix(
					command.Argv,
					"-timeout",
					"-timeout",
				)
			},
		},
		{
			name:      "zero timeout",
			wantError: timeoutError,
			mutate: func(command *commandConfig) {
				command.Argv = replaceConfigArgPrefix(
					command.Argv,
					"-timeout=",
					"-timeout=0s",
				)
			},
		},
		{
			name:      "negative timeout",
			wantError: timeoutError,
			mutate: func(command *commandConfig) {
				command.Argv = replaceConfigArgPrefix(
					command.Argv,
					"-timeout=",
					"-timeout=-1s",
				)
			},
		},
		{
			name:      "timeout not shorter than outer backstop",
			wantError: timeoutError,
			mutate: func(command *commandConfig) {
				command.Argv = replaceConfigArgPrefix(
					command.Argv,
					"-timeout=",
					"-timeout=3900s",
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := reviewedInspectorConfig(t)
			stage := config.Stages["normal1"]
			test.mutate(&stage.Commands[0])
			config.Stages["normal1"] = stage
			_, err := validateGateConfig(&config)
			if err == nil || err.Error() != test.wantError {
				t.Fatalf(
					"invalid go-test count/timeout error = %v; want %q",
					err,
					test.wantError,
				)
			}
		})
	}
}

func TestInspectorFiniteSelectorBindsRequiredInventory(t *testing.T) {
	const selector = "^(TestInspectorValidClosure|TestInspectorReadOnlyCopiesUnchanged)$"
	command := commandConfig{
		ID:   "host-controller-tests",
		Kind: "go-test",
		ExecutionSurface: executionSurface{
			PackagePaths: []string{
				"./internal/pcv3credential/testdata/phaseinspect",
			},
			BuildTags:    []string{"migrated_fynedo"},
			TestSelector: selector,
			EvidenceKind: "go-test-json",
		},
		Argv: []string{
			"${GO}", "test",
			"-tags", "migrated_fynedo",
			"-p", "1",
			"./internal/pcv3credential/testdata/phaseinspect",
			"-run", selector,
			"-count=1",
			"-timeout=5m",
			"-json",
		},
		TimeoutSeconds: 360,
		GoBased:        true,
		RequiredTestIDs: []string{
			"TestInspectorValidClosure",
			"TestInspectorReadOnlyCopiesUnchanged",
		},
		RequiredTestPackages: map[string]string{
			"TestInspectorValidClosure": pcv3PackagePath +
				"/testdata/phaseinspect",
			"TestInspectorReadOnlyCopiesUnchanged": pcv3PackagePath +
				"/testdata/phaseinspect",
		},
	}
	if err := validateGoTestExecutionSurface(command, "0"); err != nil {
		t.Fatalf("exact finite inspector selector rejected: %v", err)
	}

	command.RequiredTestIDs = command.RequiredTestIDs[:1]
	if err := validateGoTestExecutionSurface(command, "0"); err == nil {
		t.Fatal("finite selector selected a test outside the required evidence inventory")
	}
}

func TestInspectorRejectsBroadenedHostEvidence(t *testing.T) {
	const unexpectedTest = "TestUnexpectedControllerWork"
	extendControllerSelector := func(t *testing.T, command *commandConfig) {
		t.Helper()
		selector := command.ExecutionSurface.TestSelector
		if !strings.HasSuffix(selector, ")$") {
			t.Fatalf("reviewed controller selector is not a finite union: %q", selector)
		}
		selector = strings.TrimSuffix(selector, ")$") +
			"|" + unexpectedTest + ")$"
		command.ExecutionSurface.TestSelector = selector
		for index := range command.Argv {
			if command.Argv[index] == "-run" && index+1 < len(command.Argv) {
				command.Argv[index+1] = selector
				return
			}
		}
		t.Fatal("reviewed controller command has no selector argument")
	}
	for _, test := range []struct {
		name      string
		commandID string
		wantError string
		mutate    func(*testing.T, *commandConfig)
	}{
		{
			name:      "additional Phase-2 package",
			commandID: "host-phase2-tests",
			wantError: "host Phase-2 or controller test scope is not exact",
			mutate: func(t *testing.T, command *commandConfig) {
				t.Helper()
				command.ExecutionSurface.PackagePaths = append(
					command.ExecutionSurface.PackagePaths,
					"./internal/fileops",
				)
				for index, argument := range command.Argv {
					if argument != "./internal/pcv3credential" {
						continue
					}
					command.Argv = append(
						append([]string(nil), command.Argv[:index+1]...),
						append(
							[]string{"./internal/fileops"},
							command.Argv[index+1:]...,
						)...,
					)
					return
				}
				t.Fatal("reviewed Phase-2 command has no credential package argument")
			},
		},
		{
			name:      "additional auxiliary package",
			commandID: "host-fixture-schema",
			wantError: "host Phase-2 or controller test scope is not exact",
			mutate: func(t *testing.T, command *commandConfig) {
				t.Helper()
				command.ExecutionSurface.PackagePaths = append(
					command.ExecutionSurface.PackagePaths,
					"./internal/fileops",
				)
				for index, argument := range command.Argv {
					if argument !=
						"./internal/pcv3credential/testdata/mutator" {
						continue
					}
					command.Argv = append(
						append([]string(nil), command.Argv[:index+1]...),
						append(
							[]string{"./internal/fileops"},
							command.Argv[index+1:]...,
						)...,
					)
					return
				}
				t.Fatal("reviewed fixture command has no mutator package argument")
			},
		},
		{
			name:      "selector outside required inventory",
			commandID: "host-controller-tests",
			wantError: "go-test selector does not match the required evidence inventory",
			mutate:    extendControllerSelector,
		},
		{
			name:      "controller test outside threat closure",
			commandID: "host-controller-tests",
			wantError: "test command evidence inventory exceeds its threat closure",
			mutate: func(t *testing.T, command *commandConfig) {
				t.Helper()
				extendControllerSelector(t, command)
				command.RequiredTestIDs = append(
					command.RequiredTestIDs,
					unexpectedTest,
				)
				command.RequiredTestPackages[unexpectedTest] = pcv3PackagePath +
					"/testdata/phaseinspect"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := reviewedInspectorConfig(t)
			host := config.Stages["host"]
			commandFound := false
			for index := range host.Commands {
				if host.Commands[index].ID != test.commandID {
					continue
				}
				test.mutate(t, &host.Commands[index])
				commandFound = true
				break
			}
			if !commandFound {
				t.Fatalf("reviewed host command %q is missing", test.commandID)
			}
			config.Stages["host"] = host

			_, err := validateGateConfig(&config)
			if err == nil || err.Error() != test.wantError {
				t.Fatalf(
					"broadened host evidence error = %v; want %q",
					err,
					test.wantError,
				)
			}
		})
	}
}

func TestInspectorRejectsEveryRuntimeSkip(t *testing.T) {
	fixture := newInspectorFixture(t)
	_ = fixture.inspect(t)

	withSkip := newInspectorFixture(t)
	withSkip.setHostSkips(t, []fixtureSkipEvent{{
		Test:   "TestFactorModeMatrix",
		Reason: "simulated forbidden skip",
	}})
	withSkip.requireRejected(t, "runtime skip events are forbidden")
}

func TestInspectorRejectsPassWithFailureSummary(t *testing.T) {
	fixture := newInspectorFixture(t)
	fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
		command := evidence["commands"].([]any)[0].(map[string]any)
		command["go_test_failure_summary"] = map[string]any{
			"top_level_test_ids": []any{"TestInjectedFailure"},
			"classification":     "test",
			"truncated":          false,
		}
	})
	fixture.requireRejected(t, "command result is not terminal PASS evidence")
}

func TestInspectorRejectsSkipOrNoOp(t *testing.T) {
	t.Run("no commands", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
			evidence["commands"] = []any{}
		})
		fixture.requireRejected(t)
	})
	t.Run("partial command receipt", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
			command := evidence["commands"].([]any)[0].(map[string]any)
			delete(command, "contract")
		})
		fixture.requireRejected(t, "command result is not terminal PASS evidence")
	})
	t.Run("wrong command argv", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
			command := evidence["commands"].([]any)[0].(map[string]any)
			command["argv"].([]any)[1] = "not-test"
		})
		fixture.requireRejected(t, "command argv or working directory mismatch")
	})
	t.Run("missing external output hash", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
			command := evidence["commands"].([]any)[0].(map[string]any)
			delete(command, "stdout_sha256")
		})
		fixture.requireRejected(t, "external command output hash mismatch")
	})
	t.Run("null lint issues", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
			for _, value := range evidence["commands"].([]any) {
				command := value.(map[string]any)
				if command["id"] == "host-lint-normal" {
					command["lint_result"].(map[string]any)["issues"] = nil
				}
			}
		})
		fixture.requireRejected(t, "lint result mismatch")
	})
	t.Run("scan target mismatch", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
			for _, value := range evidence["commands"].([]any) {
				command := value.(map[string]any)
				if command["id"] == "host-gitleaks" {
					command["scan_result"].(map[string]any)["target"] = fixture.source
				}
			}
		})
		fixture.requireRejected(t, "scan result mismatch")
	})
	t.Run("mutation application receipt", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "mutation", func(evidence map[string]any) {
			command := evidence["commands"].([]any)[0].(map[string]any)
			mutation := command["mutations"].([]any)[0].(map[string]any)
			receipt := mutation["application_receipt"].(map[string]any)
			receipt["source_after_sha256"] = strings.Repeat("a", 64)
		})
		fixture.requireRejected(t, "mutation application receipt mismatch")
	})
	t.Run("nested command contract", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "mutation", func(evidence map[string]any) {
			command := evidence["commands"].([]any)[0].(map[string]any)
			mutation := command["mutations"].([]any)[0].(map[string]any)
			delete(mutation["pristine"].(map[string]any), "contract")
		})
		fixture.requireRejected(t, "nested mutation command receipt mismatch")
	})
	t.Run("mutation outcome mismatch", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		fixture.rewriteEvidence(t, "mutation", func(evidence map[string]any) {
			command := evidence["commands"].([]any)[0].(map[string]any)
			mutation := command["mutations"].([]any)[0].(map[string]any)
			mutation["violation_marker"] = "not-the-manifest-marker"
		})
		fixture.requireRejected(t)
	})
}

func TestInspectorRejectsInventedObservedIDs(t *testing.T) {
	for _, test := range []struct {
		name      string
		stage     string
		commandID string
	}{
		{
			name:      "single-command go-test stage",
			stage:     "normal1",
			commandID: "normal-1-exact-profile",
		},
		{
			name:      "zero-observation internal command",
			stage:     "host",
			commandID: "host-threat-closure",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			_ = fixture.inspect(t)
			fixture.spliceObservedID(t, test.stage, test.commandID, "invented-observation")
			fixture.requireRejected(t, "command observed IDs mismatch")
		})
	}
}

// Kills production mutation: trusting nested output hashes without exact events.
func TestInspectorRequiresExactNestedGoTestEvents(t *testing.T) {
	for _, test := range []struct {
		name      string
		wantError string
		mutate    func(map[string]any, map[string]any)
	}{
		{
			name:      "missing pristine",
			wantError: "nested mutation command receipt mismatch",
			mutate: func(_ map[string]any, mutation map[string]any) {
				delete(mutation["pristine"].(map[string]any), "go_test_event")
			},
		},
		{
			name:      "missing mutant",
			wantError: "nested mutation command receipt mismatch",
			mutate: func(_ map[string]any, mutation map[string]any) {
				delete(mutation["mutant"].(map[string]any), "go_test_event")
			},
		},
		{
			name:      "wrong pristine test ID",
			wantError: "nested mutation command receipt mismatch",
			mutate: func(_ map[string]any, mutation map[string]any) {
				event := mutation["pristine"].(map[string]any)["go_test_event"].(map[string]any)
				event["test_id"] = "TestWrong"
			},
		},
		{
			name:      "wrong pristine package",
			wantError: "nested mutation command receipt mismatch",
			mutate: func(_ map[string]any, mutation map[string]any) {
				event := mutation["pristine"].(map[string]any)["go_test_event"].(map[string]any)
				event["package"] = "Picocrypt-NG/internal/wrong"
			},
		},
		{
			name:      "wrong pristine terminal action",
			wantError: "nested mutation command receipt mismatch",
			mutate: func(_ map[string]any, mutation map[string]any) {
				event := mutation["pristine"].(map[string]any)["go_test_event"].(map[string]any)
				event["terminal_action"] = "fail"
			},
		},
		{
			name:      "wrong mutant package",
			wantError: "nested mutation command receipt mismatch",
			mutate: func(_ map[string]any, mutation map[string]any) {
				event := mutation["mutant"].(map[string]any)["go_test_event"].(map[string]any)
				event["package"] = "Picocrypt-NG/internal/wrong"
			},
		},
		{
			name:      "wrong mutant terminal action",
			wantError: "nested mutation command receipt mismatch",
			mutate: func(_ map[string]any, mutation map[string]any) {
				event := mutation["mutant"].(map[string]any)["go_test_event"].(map[string]any)
				event["terminal_action"] = "pass"
			},
		},
		{
			name:      "extra application",
			wantError: "nested mutation command receipt mismatch",
			mutate: func(_ map[string]any, mutation map[string]any) {
				mutation["application"].(map[string]any)["go_test_event"] = mutation["pristine"].(map[string]any)["go_test_event"]
			},
		},
		{
			name:      "misplaced top-level",
			wantError: "command result is not terminal PASS evidence",
			mutate: func(command map[string]any, mutation map[string]any) {
				command["go_test_event"] = mutation["pristine"].(map[string]any)["go_test_event"]
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			fixture.rewriteEvidence(t, "mutation", func(evidence map[string]any) {
				command := evidence["commands"].([]any)[0].(map[string]any)
				mutation := command["mutations"].([]any)[0].(map[string]any)
				test.mutate(command, mutation)
			})
			fixture.requireRejected(t, test.wantError)
		})
	}
}

func TestInspectorExactThreatClosure(t *testing.T) {
	for _, name := range []string{"missing", "extra", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			fixture := newInspectorFixture(t)
			fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
				closed := evidence["closed_threat_ids"].([]any)
				switch name {
				case "missing":
					closed = closed[1:]
				case "extra":
					closed = append(closed, "T-02-99")
				case "duplicate":
					closed = append(closed, closed[0])
				}
				evidence["closed_threat_ids"] = closed
			})
			fixture.requireRejected(t)
		})
	}
}

func TestInspectorStrictVerdictSchema(t *testing.T) {
	t.Run("observed surfaces come from receipts", func(t *testing.T) {
		want := []executionSurface{{
			PackagePaths: []string{"./receipt-only"},
			BuildTags:    []string{"migrated_fynedo"},
			TestSelector: "^TestReceipt$",
			EvidenceKind: "go-test-json",
		}}
		inspected := []inspectedStage{{
			evidence: stageEvidence{Commands: []commandResult{{
				Contract: commandEvidence{ExecutionSurface: want[0]},
			}}},
		}}
		if got := observedExecutionSurfaces(inspected); !reflect.DeepEqual(got, want) {
			t.Fatalf("observed surfaces = %#v; want receipt surfaces %#v", got, want)
		}
	})
	fixture := newInspectorFixture(t)
	stdout, stderr, err := fixture.executeBinary(t)
	if err != nil {
		t.Fatalf("inspect valid closure: %v", err)
	}
	if len(stderr) != 0 {
		t.Fatalf("valid inspector wrote stderr: %q", stderr)
	}
	var verdict inspectorVerdictLiteral
	decodeStrictLiteral(t, stdout, &verdict)
	if !reflect.DeepEqual(verdict, fixture.wantVerdict(t)) {
		t.Fatalf("strict verdict = %#v; want %#v", verdict, fixture.wantVerdict(t))
	}
	if !bytes.Equal(stdout, canonicalTestJSON(t, verdict)) {
		t.Fatal("verdict stdout is not canonical JSON")
	}
	fixture.injectDuplicateEvidenceField(t, "host", "status")
	fixture.requireRejected(t)
}

func TestInspectorNoExecOrFilesystemWrites(t *testing.T) {
	for _, test := range []struct {
		name          string
		source        string
		wantSymbol    string
		controlRemove string
	}{
		{
			name: "aliased package call",
			source: `package main
import filesystem "os"
func probe() { _ = filesystem.Remove("artifact") }
`,
			wantSymbol: "os.Remove",
		},
		{
			name: "dot import call",
			source: `package main
import . "os"
func probe() { _ = WriteFile("artifact", nil, 0o600) }
`,
			wantSymbol: "os.WriteFile",
		},
		{
			name: "method function value",
			source: `package main
import "os"
func probe(file *os.File) { write := file.Write; _, _ = write(nil) }
`,
			wantSymbol: "(*os.File).Write",
		},
		{
			name: "file mutation through io Writer",
			source: `package main
import (
	"io"
	"os"
)
func probe(file *os.File) {
	var writer io.Writer = file
	_, _ = writer.Write([]byte("mutation"))
}
`,
			wantSymbol: "writer-capability method Write",
		},
		{
			name: "file mutation through hash Hash",
			source: `package main
import (
	"hash"
	"os"
)
type evilHash struct { *os.File }
func (*evilHash) Sum(value []byte) []byte { return value }
func (*evilHash) Reset() {}
func (*evilHash) Size() int { return 0 }
func (*evilHash) BlockSize() int { return 0 }
func probe() {
	reader, writer, _ := os.Pipe()
	_ = reader
	var hasher hash.Hash = &evilHash{File: writer}
	_, _ = hasher.Write([]byte("mutation"))
}
`,
			wantSymbol: "writer-capability method Write",
		},
		{
			name: "run stdout reassignment",
			source: `package main
import (
	"fmt"
	"io"
	"os"
)
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(_ []string, stdout io.Writer) error {
	reader, writer, _ := os.Pipe()
	_ = reader
	_ = writer
	stdout = writer
	_, _ = stdout.Write([]byte("mutation"))
	return nil
}
`,
			wantSymbol:    "writer-capability method Write",
			controlRemove: "\tstdout = writer\n",
		},
		{
			name: "second run call with writable sink",
			source: `package main
import (
	"fmt"
	"io"
	"os"
)
func init() {
	reader, writer, _ := os.Pipe()
	_ = reader
	_ = writer
	_ = run(nil, writer)
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(_ []string, stdout io.Writer) error {
	_, _ = stdout.Write([]byte("mutation"))
	return nil
}
`,
			wantSymbol:    "run",
			controlRemove: "\t_ = run(nil, writer)\n",
		},
		{
			name: "run stdout method value",
			source: `package main
import (
	"fmt"
	"io"
	"os"
)
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(_ []string, stdout io.Writer) error {
	write := stdout.Write
	_, _ = write([]byte("mutation"))
	return nil
}
`,
			wantSymbol: "writer-capability method Write",
		},
		{
			name: "unbound stderr diagnostic",
			source: `package main
import (
	"fmt"
	"os"
)
func main() { _, _ = fmt.Fprintln(os.Stderr, "mutation") }
`,
			wantSymbol: "fmt.Fprintln",
		},
		{
			name: "file mutation through io WriteString",
			source: `package main
import (
	"io"
	"os"
)
func probe() { _, _ = io.WriteString(os.Stdin, "mutation") }
`,
			wantSymbol: "io.WriteString",
		},
		{
			name: "file mutation through WriteTo",
			source: `package main
import "os"
func probe(source *os.File) { _, _ = source.WriteTo(os.Stdin) }
`,
			wantSymbol: "writer-capability method WriteTo",
		},
		{
			name: "file mutation through fmt Fprintln",
			source: `package main
import (
	"fmt"
	"os"
)
func probe() { _, _ = fmt.Fprintln(os.Stdin, "mutation") }
`,
			wantSymbol: "fmt.Fprintln",
		},
		{
			name: "stderr reassignment",
			source: `package main
import (
	"fmt"
	"io"
	"os"
)
func init() {
	reader, writer, _ := os.Pipe()
	_ = reader
	_ = writer
	os.Stderr = writer
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(_ []string, stdout io.Writer) error {
	_, _ = stdout.Write([]byte("output"))
	return nil
}
`,
			wantSymbol:    "os.Stderr",
			controlRemove: "\tos.Stderr = writer\n",
		},
		{
			name: "file mutation through JSON encoder",
			source: `package main
import (
	"encoding/json"
	"os"
)
func probe() { _ = json.NewEncoder(os.Stdin).Encode("mutation") }
`,
			wantSymbol: "encoding/json.NewEncoder",
		},
		{
			name: "stored File ReadFrom method",
			source: `package main
import (
	"io"
	"os"
)
func probe(file *os.File, reader io.Reader) {
	readFrom := file.ReadFrom
	_, _ = readFrom(reader)
}
`,
			wantSymbol: "(*os.File).ReadFrom",
		},
		{
			name: "process package alias",
			source: `package main
import process "os/exec"
func probe() { _ = process.Command("forbidden") }
`,
			wantSymbol: "import os/exec",
		},
		{
			name: "stored StartProcess function",
			source: `package main
import "os"
var _ = os.StartProcess
`,
			wantSymbol: "os.StartProcess",
		},
		{
			name: "stored Root Create method",
			source: `package main
import "os"
func probe(root *os.Root) { create := root.Create; _, _ = create("artifact") }
`,
			wantSymbol: "(*os.Root).Create",
		},
		{
			name: "CopyFS function value",
			source: `package main
import "os"
var _ = os.CopyFS
`,
			wantSymbol: "os.CopyFS",
		},
		{
			name: "NewFile function value",
			source: `package main
import "os"
var _ = os.NewFile
`,
			wantSymbol: "os.NewFile",
		},
		{
			name: "root mutation through local interface",
			source: `package main
import "os"
type remover interface { Remove(string) error }
func probe(root *os.Root) {
	var target remover = root
	_ = target.Remove("artifact")
}
`,
			wantSymbol: "indirect interface method Remove",
		},
		{
			name: "root mutation through promoted interface",
			source: `package main
import "os"
type remover interface { Remove(string) error }
type wrapper struct { remover }
func probe(root *os.Root) {
	target := wrapper{remover: root}
	_ = target.Remove("artifact")
}
`,
			wantSymbol: "indirect interface method Remove",
		},
		{
			name: "root mutation through reflection",
			source: `package main
import (
	"os"
	"reflect"
)
func probe(root *os.Root) {
	method := reflect.ValueOf(root).MethodByName("Remove")
	_ = method
}
`,
			wantSymbol: "reflect.Value.MethodByName",
		},
		{
			name: "root mutation through reflection interfaces",
			source: `package main
import (
	"os"
	"reflect"
)
type methoder interface { MethodByName(string) reflect.Value }
type caller interface { Call([]reflect.Value) []reflect.Value }
func probe(root *os.Root) {
	var lookup methoder = reflect.ValueOf(root)
	method := lookup.MethodByName("Remove")
	var invoke caller = method
	_ = invoke.Call([]reflect.Value{reflect.ValueOf("artifact")})
}
`,
			wantSymbol: "indirect interface method MethodByName",
		},
		{
			name: "unreviewed unsafe import",
			source: `package main
import "unsafe"
var _ unsafe.Pointer
`,
			wantSymbol: "import unsafe",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			violations, err := analyzeInspectorSourceFiles(map[string][]byte{
				"probe.go": []byte(test.source),
			})
			if err != nil {
				t.Fatalf("analyze forbidden fixture: %v", err)
			}
			if !containsViolation(violations, test.wantSymbol) {
				t.Fatalf(
					"violations = %#v; want resolved symbol %q",
					violations,
					test.wantSymbol,
				)
			}
			if test.controlRemove == "" {
				return
			}
			if strings.Count(test.source, test.controlRemove) != 1 {
				t.Fatalf(
					"control removal %q does not occur exactly once",
					test.controlRemove,
				)
			}
			control := strings.Replace(
				test.source,
				test.controlRemove,
				"",
				1,
			)
			controlViolations, err := analyzeInspectorSourceFiles(
				map[string][]byte{"control.go": []byte(control)},
			)
			if err != nil {
				t.Fatalf("analyze mutation control: %v", err)
			}
			if len(controlViolations) != 0 {
				t.Fatalf(
					"single-edit control violations = %#v",
					controlViolations,
				)
			}
		})
	}
	t.Run("local Remove, run stdout, and hash writes are allowed", func(t *testing.T) {
		violations, err := analyzeInspectorSourceFiles(map[string][]byte{
			"allowed.go": []byte(`package main
import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)
func Remove(string) error { return nil }
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(_ []string, stdout io.Writer) error {
	hasher := sha256.New()
	_ = Remove("local")
	_, _ = stdout.Write(nil)
	_, _ = hasher.Write(nil)
	_ = hasher.Sum(nil)
	return nil
}
`),
		})
		if err != nil {
			t.Fatalf("analyze allowed fixture: %v", err)
		}
		if len(violations) != 0 {
			t.Fatalf("allowed fixture violations = %#v", violations)
		}
	})
	t.Run("all non-test inspector sources", func(t *testing.T) {
		violations, err := analyzeInspectorSourceFiles(
			readInspectorNonTestSources(t),
		)
		if err != nil {
			t.Fatalf("analyze inspector sources: %v", err)
		}
		if len(violations) != 0 {
			t.Fatalf("inspector source violations = %#v", violations)
		}
	})
	t.Run("package inventory rejects native build inputs", func(t *testing.T) {
		for _, name := range []string{"mutation_linux.s", "mutation_linux.syso"} {
			t.Run(name, func(t *testing.T) {
				directory := t.TempDir()
				if err := os.WriteFile(
					filepath.Join(directory, "main.go"),
					[]byte("package main\nfunc main() {}\n"),
					0o400,
				); err != nil {
					t.Fatalf("write inventory Go source: %v", err)
				}
				if err := os.WriteFile(
					filepath.Join(directory, name),
					[]byte("native build input"),
					0o400,
				); err != nil {
					t.Fatalf("write native build input: %v", err)
				}
				_, err := inspectorNonTestSources(directory)
				want := fmt.Sprintf(
					"inspector package contains native build inputs: [%s]",
					name,
				)
				if err == nil || err.Error() != want {
					t.Fatalf(
						"native input %q rejection = %v; want %q",
						name,
						err,
						want,
					)
				}
			})
		}
		t.Run("all reviewed go build inventory fields", func(t *testing.T) {
			for _, fieldName := range []string{
				"CgoFiles",
				"CFiles",
				"CXXFiles",
				"MFiles",
				"HFiles",
				"FFiles",
				"SFiles",
				"SwigFiles",
				"SwigCXXFiles",
				"SysoFiles",
				"IgnoredOtherFiles",
			} {
				t.Run(fieldName, func(t *testing.T) {
					pkg := &build.Package{}
					field := reflect.ValueOf(pkg).Elem().FieldByName(fieldName)
					if !field.IsValid() || !field.CanSet() {
						t.Fatalf("go/build.Package field %s is unavailable", fieldName)
					}
					field.Set(reflect.ValueOf([]string{"native.input"}))
					err := rejectInspectorNativeBuildInputs(pkg)
					want := "inspector package contains native build inputs: [native.input]"
					if err == nil || err.Error() != want {
						t.Fatalf("%s rejection = %v; want %q", fieldName, err, want)
					}
				})
			}
			pkg := &build.Package{BinaryOnly: true}
			err := rejectInspectorNativeBuildInputs(pkg)
			want := "inspector package contains native build inputs: []"
			if err == nil || err.Error() != want {
				t.Fatalf("BinaryOnly rejection = %v; want %q", err, want)
			}
		})
	})
	t.Run("fixture module mode follows vendor manifest", func(t *testing.T) {
		root := t.TempDir()
		mode, err := fixtureModuleMode(root)
		if err != nil || mode != "readonly" {
			t.Fatalf("unvendored fixture mode = %q, %v", mode, err)
		}
		vendor := filepath.Join(root, "vendor")
		if err := os.Mkdir(vendor, 0o700); err != nil {
			t.Fatalf("create fixture vendor directory: %v", err)
		}
		if err := os.WriteFile(
			filepath.Join(vendor, "modules.txt"),
			[]byte("# fixture vendor manifest\n"),
			0o400,
		); err != nil {
			t.Fatalf("write fixture vendor manifest: %v", err)
		}
		mode, err = fixtureModuleMode(root)
		if err != nil || mode != "vendor" {
			t.Fatalf("vendored fixture mode = %q, %v", mode, err)
		}
	})
	fixture := newInspectorFixture(t)
	_ = fixture.inspect(t)
}

func readInspectorNonTestSources(t *testing.T) map[string][]byte {
	t.Helper()
	sources, err := inspectorNonTestSources(".")
	if err != nil {
		t.Fatalf("read inspector package sources: %v", err)
	}
	return sources
}

func inspectorNonTestSources(directory string) (map[string][]byte, error) {
	pkg, err := build.Default.ImportDir(directory, build.ImportComment)
	if err != nil {
		return nil, err
	}
	if err := rejectInspectorNativeBuildInputs(pkg); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	sources := map[string][]byte{}
	for _, entry := range entries {
		if entry.IsDir() ||
			!strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		sources[entry.Name()] = data
	}
	if len(sources) == 0 {
		return nil, errors.New("no non-test inspector sources found")
	}
	return sources, nil
}

func rejectInspectorNativeBuildInputs(pkg *build.Package) error {
	if pkg == nil {
		return errors.New("inspector package inventory is nil")
	}
	var native []string
	for _, files := range [][]string{
		pkg.CgoFiles,
		pkg.CFiles,
		pkg.CXXFiles,
		pkg.MFiles,
		pkg.HFiles,
		pkg.FFiles,
		pkg.SFiles,
		pkg.SwigFiles,
		pkg.SwigCXXFiles,
		pkg.SysoFiles,
		pkg.IgnoredOtherFiles,
	} {
		native = append(native, files...)
	}
	if pkg.BinaryOnly || len(native) != 0 {
		sort.Strings(native)
		return fmt.Errorf(
			"inspector package contains native build inputs: %v",
			native,
		)
	}
	return nil
}

func analyzeInspectorSourceFiles(
	sources map[string][]byte,
) ([]string, error) {
	if len(sources) == 0 {
		return nil, errors.New("no inspector source files to analyze")
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	fileSet := token.NewFileSet()
	files := make([]*ast.File, 0, len(names))
	for _, name := range names {
		file, err := parser.ParseFile(
			fileSet,
			name,
			sources[name],
			parser.AllErrors,
		)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		files = append(files, file)
	}
	info := &types.Info{
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	configuration := &types.Config{Importer: importer.Default()}
	if _, err := configuration.Check(
		"Picocrypt-NG/internal/pcv3credential/testdata/phaseinspect",
		fileSet,
		files,
		info,
	); err != nil {
		return nil, fmt.Errorf("type-check inspector sources: %w", err)
	}

	seen := map[string]bool{}
	var violations []string
	addViolation := func(position token.Pos, symbol string) {
		location := fileSet.Position(position)
		violation := fmt.Sprintf(
			"%s:%d: forbidden reference %s",
			location.Filename,
			location.Line,
			symbol,
		)
		if !seen[violation] {
			seen[violation] = true
			violations = append(violations, violation)
		}
	}
	for _, file := range files {
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return nil, fmt.Errorf(
					"decode import in %s: %w",
					fileSet.Position(imported.Pos()).Filename,
					err,
				)
			}
			if !allowedInspectorImport(path) {
				addViolation(imported.Pos(), "import "+path)
			}
		}
	}
	mainFlow := exactInspectorMainFlow(files, info)
	allowedRunUses := allowedInspectorRunUses(info, mainFlow)
	allowedStandardStreamUses := allowedInspectorStandardStreamUses(
		info,
		mainFlow,
		allowedRunUses,
	)
	allowedOutputUses := allowedInspectorOutputUses(
		mainFlow,
		allowedStandardStreamUses,
	)
	allowedWriterUses := inspectorOutputWriterUses(files, info, allowedRunUses)
	allowedHashWriterUses := inspectorHashWriterUses(files, info)
	for identifier, object := range info.Uses {
		if allowedOutputUses[identifier] {
			continue
		}
		if exactInspectorRunFunction(object) {
			if !allowedRunUses[identifier] {
				addViolation(identifier.Pos(), "run")
			}
			continue
		}
		if symbol, standardStream := inspectorStandardStream(object); standardStream {
			if !allowedStandardStreamUses[identifier] {
				addViolation(identifier.Pos(), symbol)
			}
			continue
		}
		if symbol, forbidden := forbiddenInspectorObject(object); forbidden {
			addViolation(identifier.Pos(), symbol)
		}
	}
	for selector, selection := range info.Selections {
		if symbol, forbidden := forbiddenInspectorSelection(
			selector,
			selection,
			allowedWriterUses,
			allowedHashWriterUses,
		); forbidden {
			addViolation(selector.Sel.Pos(), symbol)
		}
	}
	sort.Strings(violations)
	return violations, nil
}

func allowedInspectorImport(path string) bool {
	switch path {
	case "bytes",
		"crypto/sha256",
		"debug/buildinfo",
		"encoding/hex",
		"encoding/json",
		"errors",
		"fmt",
		"go/ast",
		"go/parser",
		"go/token",
		"hash",
		"io",
		"os",
		"path/filepath",
		"reflect",
		"runtime",
		"slices",
		"sort",
		"strconv",
		"strings",
		"time":
		return true
	default:
		return false
	}
}

func forbiddenInspectorObject(
	object types.Object,
) (string, bool) {
	if builtin, ok := object.(*types.Builtin); ok {
		switch builtin.Name() {
		case "print", "println":
			return "builtin " + builtin.Name(), true
		}
	}
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil {
		return "", false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok {
		return "", false
	}
	if function.Pkg().Path() == "reflect" {
		return forbiddenReflectFunction(function, signature)
	}
	if signature.Recv() == nil {
		if function.Pkg().Path() == "os" &&
			forbiddenOSFunction(function.Name()) {
			return "os." + function.Name(), true
		}
		if forbiddenWriterFunction(function, signature) {
			return function.Pkg().Path() + "." + function.Name(), true
		}
		return "", false
	}
	receiver := types.Unalias(signature.Recv().Type())
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = types.Unalias(pointer.Elem())
	}
	named, ok := receiver.(*types.Named)
	if !ok ||
		named.Obj().Pkg() == nil ||
		named.Obj().Pkg().Path() != "os" ||
		!forbiddenOSMethod(named.Obj().Name(), function.Name()) {
		return "", false
	}
	return fmt.Sprintf(
		"(*os.%s).%s",
		named.Obj().Name(),
		function.Name(),
	), true
}

func forbiddenInspectorSelection(
	selector *ast.SelectorExpr,
	selection *types.Selection,
	allowedWriterUses map[*ast.Ident]bool,
	allowedHashWriterUses map[*ast.Ident]bool,
) (string, bool) {
	if selection == nil {
		return "", false
	}
	if allowedInspectorWriteSelection(
		selector,
		selection,
		allowedWriterUses,
		allowedHashWriterUses,
	) {
		return "", false
	}
	if symbol, forbidden := forbiddenInspectorObject(selection.Obj()); forbidden {
		return symbol, true
	}
	function, ok := selection.Obj().(*types.Func)
	if !ok {
		return "", false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return "", false
	}
	receiver := signature.Recv().Type()
	if forbiddenWriterMethod(function, signature) {
		return "writer-capability method " + function.Name(), true
	}
	if interfaceType(receiver) {
		if function.Pkg() != nil &&
			function.Pkg().Path() ==
				"Picocrypt-NG/internal/pcv3credential/testdata/phaseinspect" {
			return "indirect interface method " + function.Name(), true
		}
		if forbiddenOSMethodName(function.Name()) {
			return "indirect interface method " + function.Name(), true
		}
	}
	return "", false
}

func forbiddenReflectFunction(
	function *types.Func,
	signature *types.Signature,
) (string, bool) {
	if signature.Recv() == nil {
		switch function.Name() {
		case "DeepEqual", "ValueOf":
			return "", false
		default:
			return "reflect." + function.Name(), true
		}
	}
	receiver := types.Unalias(signature.Recv().Type())
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = types.Unalias(pointer.Elem())
	}
	named, ok := receiver.(*types.Named)
	if ok && named.Obj().Name() == "Value" {
		switch function.Name() {
		case "Elem", "FieldByName", "IsNil", "IsValid", "Kind", "Uint":
			return "", false
		}
		return "reflect.Value." + function.Name(), true
	}
	return "reflect." + function.Name(), true
}

type inspectorMainFlow struct {
	runUse        *ast.Ident
	stdoutUse     *ast.Ident
	stderrUse     *ast.Ident
	diagnosticUse *ast.Ident
}

func allowedInspectorOutputUses(
	flow inspectorMainFlow,
	allowedStandardStreamUses map[*ast.Ident]bool,
) map[*ast.Ident]bool {
	allowed := map[*ast.Ident]bool{}
	if flow.diagnosticUse != nil &&
		allowedStandardStreamUses[flow.stdoutUse] &&
		allowedStandardStreamUses[flow.stderrUse] {
		allowed[flow.diagnosticUse] = true
	}
	return allowed
}

func allowedInspectorStandardStreamUses(
	info *types.Info,
	flow inspectorMainFlow,
	allowedRunUses map[*ast.Ident]bool,
) map[*ast.Ident]bool {
	candidates := map[*ast.Ident]bool{}
	if allowedRunUses[flow.runUse] {
		candidates[flow.stdoutUse] = true
		candidates[flow.stderrUse] = true
	}
	uses := map[types.Object][]*ast.Ident{}
	for identifier, object := range info.Uses {
		if _, standardStream := inspectorStandardStream(object); standardStream {
			uses[object] = append(uses[object], identifier)
		}
	}
	allowed := map[*ast.Ident]bool{}
	for _, identifiers := range uses {
		if len(identifiers) == 1 && candidates[identifiers[0]] {
			allowed[identifiers[0]] = true
		}
	}
	return allowed
}

func allowedInspectorRunUses(
	info *types.Info,
	flow inspectorMainFlow,
) map[*ast.Ident]bool {
	uses := map[types.Object][]*ast.Ident{}
	for identifier, object := range info.Uses {
		if exactInspectorRunFunction(object) {
			uses[object] = append(uses[object], identifier)
		}
	}
	allowed := map[*ast.Ident]bool{}
	for _, identifiers := range uses {
		if len(identifiers) == 1 && identifiers[0] == flow.runUse {
			allowed[identifiers[0]] = true
		}
	}
	return allowed
}

func exactInspectorMainFlow(
	files []*ast.File,
	info *types.Info,
) inspectorMainFlow {
	var matched inspectorMainFlow
	matches := 0
	for _, file := range files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != "main" {
				continue
			}
			flow, ok := matchInspectorMainFlow(function, info)
			if !ok {
				continue
			}
			matched = flow
			matches++
		}
	}
	if matches != 1 {
		return inspectorMainFlow{}
	}
	return matched
}

func matchInspectorMainFlow(
	function *ast.FuncDecl,
	info *types.Info,
) (inspectorMainFlow, bool) {
	if function == nil ||
		function.Recv != nil ||
		function.Body == nil ||
		len(function.Type.Params.List) != 0 ||
		function.Type.Results != nil ||
		len(function.Body.List) != 1 {
		return inspectorMainFlow{}, false
	}
	condition, ok := function.Body.List[0].(*ast.IfStmt)
	if !ok ||
		condition.Else != nil ||
		len(condition.Body.List) != 2 {
		return inspectorMainFlow{}, false
	}
	initialization, ok := condition.Init.(*ast.AssignStmt)
	if !ok ||
		initialization.Tok != token.DEFINE ||
		len(initialization.Lhs) != 1 ||
		len(initialization.Rhs) != 1 {
		return inspectorMainFlow{}, false
	}
	errorIdentifier, ok := initialization.Lhs[0].(*ast.Ident)
	if !ok || errorIdentifier.Name == "_" {
		return inspectorMainFlow{}, false
	}
	errorObject := info.Defs[errorIdentifier]
	runCall, ok := initialization.Rhs[0].(*ast.CallExpr)
	if errorObject == nil || !ok || !exactInspectorRunCall(runCall, info) {
		return inspectorMainFlow{}, false
	}
	comparison, ok := condition.Cond.(*ast.BinaryExpr)
	if !ok ||
		comparison.Op != token.NEQ ||
		!exactObjectIdentifier(comparison.X, info, errorObject) ||
		!exactUniverseIdentifier(comparison.Y, info, "nil") {
		return inspectorMainFlow{}, false
	}
	diagnostic, ok := exactInspectorDiagnostic(
		condition.Body.List[0],
		info,
		errorObject,
	)
	if !ok || !exactInspectorExit(condition.Body.List[1], info) {
		return inspectorMainFlow{}, false
	}
	return inspectorMainFlow{
		runUse:        runCall.Fun.(*ast.Ident),
		stdoutUse:     exactPackageVariableIdentifier(runCall.Args[1], info, "os", "Stdout"),
		stderrUse:     diagnostic.stderr,
		diagnosticUse: diagnostic.function,
	}, true
}

type inspectorDiagnostic struct {
	stderr   *ast.Ident
	function *ast.Ident
}

func exactInspectorDiagnostic(
	statement ast.Stmt,
	info *types.Info,
	errorObject types.Object,
) (inspectorDiagnostic, bool) {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok ||
		assignment.Tok != token.ASSIGN ||
		len(assignment.Lhs) != 2 ||
		len(assignment.Rhs) != 1 {
		return inspectorDiagnostic{}, false
	}
	for _, left := range assignment.Lhs {
		identifier, ok := left.(*ast.Ident)
		if !ok || identifier.Name != "_" {
			return inspectorDiagnostic{}, false
		}
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return inspectorDiagnostic{}, false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return inspectorDiagnostic{}, false
	}
	function, ok := info.Uses[selector.Sel].(*types.Func)
	stderr := exactPackageVariableIdentifier(call.Args[0], info, "os", "Stderr")
	if !ok ||
		function.Pkg() == nil ||
		function.Pkg().Path() != "fmt" ||
		function.Name() != "Fprintln" ||
		stderr == nil ||
		!exactObjectIdentifier(call.Args[1], info, errorObject) {
		return inspectorDiagnostic{}, false
	}
	return inspectorDiagnostic{
		stderr:   stderr,
		function: selector.Sel,
	}, true
}

func exactInspectorExit(statement ast.Stmt, info *types.Info) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok ||
		!exactPackageFunctionCall(expression.X, info, "os", "Exit", 1) {
		return false
	}
	call := expression.X.(*ast.CallExpr)
	code, ok := call.Args[0].(*ast.BasicLit)
	return ok && code.Kind == token.INT && code.Value == "1"
}

func exactInspectorRunCall(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || len(call.Args) != 2 {
		return false
	}
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	if !exactInspectorRunFunction(info.Uses[identifier]) {
		return false
	}
	return exactOSArgsTail(call.Args[0], info) &&
		exactPackageVariableIdentifier(
			call.Args[1],
			info,
			"os",
			"Stdout",
		) != nil
}

func exactInspectorRunFunction(object types.Object) bool {
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil ||
		function.Pkg().Path() !=
			"Picocrypt-NG/internal/pcv3credential/testdata/phaseinspect" ||
		function.Name() != "run" {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	return ok &&
		signature.Recv() == nil &&
		!signature.Variadic() &&
		signature.Params().Len() == 2 &&
		types.Identical(
			signature.Params().At(0).Type(),
			types.NewSlice(types.Typ[types.String]),
		) &&
		exactNamedType(signature.Params().At(1).Type(), "io", "Writer") &&
		signature.Results().Len() == 1 &&
		types.Identical(
			signature.Results().At(0).Type(),
			types.Universe.Lookup("error").Type(),
		)
}

func exactOSArgsTail(expression ast.Expr, info *types.Info) bool {
	slice, ok := expression.(*ast.SliceExpr)
	if !ok ||
		slice.Slice3 ||
		slice.High != nil ||
		slice.Max != nil ||
		exactPackageVariableIdentifier(slice.X, info, "os", "Args") == nil {
		return false
	}
	low, ok := slice.Low.(*ast.BasicLit)
	return ok && low.Kind == token.INT && low.Value == "1"
}

func exactObjectIdentifier(
	expression ast.Expr,
	info *types.Info,
	object types.Object,
) bool {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = parenthesized.X
	}
	identifier, ok := expression.(*ast.Ident)
	return ok && info.Uses[identifier] == object
}

func exactUniverseIdentifier(
	expression ast.Expr,
	info *types.Info,
	name string,
) bool {
	return exactObjectIdentifier(
		expression,
		info,
		types.Universe.Lookup(name),
	)
}

func inspectorOutputWriterUses(
	files []*ast.File,
	info *types.Info,
	allowedRunUses map[*ast.Ident]bool,
) map[*ast.Ident]bool {
	directWriteUses := inspectorDirectWriteUses(files, info)
	runObjects := map[types.Object]bool{}
	for identifier := range allowedRunUses {
		runObjects[info.Uses[identifier]] = true
	}
	writerObjects := map[types.Object]bool{}
	for _, file := range files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok ||
				function.Recv != nil ||
				!runObjects[info.Defs[function.Name]] {
				continue
			}
			for _, field := range function.Type.Params.List {
				for _, name := range field.Names {
					object := info.Defs[name]
					if name.Name == "stdout" &&
						object != nil &&
						exactNamedType(object.Type(), "io", "Writer") {
						writerObjects[object] = true
					}
				}
			}
		}
	}
	uses := map[types.Object][]*ast.Ident{}
	for identifier, object := range info.Uses {
		if writerObjects[object] {
			uses[object] = append(uses[object], identifier)
		}
	}
	allowed := map[*ast.Ident]bool{}
	for _, identifiers := range uses {
		if len(identifiers) == 1 && directWriteUses[identifiers[0]] {
			allowed[identifiers[0]] = true
		}
	}
	return allowed
}

func inspectorDirectWriteUses(
	files []*ast.File,
	info *types.Info,
) map[*ast.Ident]bool {
	direct := map[*ast.Ident]bool{}
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			selection := info.Selections[selector]
			if selection == nil {
				return true
			}
			function, ok := selection.Obj().(*types.Func)
			identifier, directReceiver := selector.X.(*ast.Ident)
			if ok && directReceiver && function.Name() == "Write" {
				direct[identifier] = true
			}
			return true
		})
	}
	return direct
}

func inspectorHashWriterUses(
	files []*ast.File,
	info *types.Info,
) map[*ast.Ident]bool {
	hashObjects := map[types.Object]bool{}
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok ||
				assignment.Tok != token.DEFINE ||
				len(assignment.Lhs) != len(assignment.Rhs) {
				return true
			}
			for index, left := range assignment.Lhs {
				identifier, ok := left.(*ast.Ident)
				if !ok ||
					!exactPackageFunctionCall(
						assignment.Rhs[index],
						info,
						"crypto/sha256",
						"New",
						0,
					) {
					continue
				}
				if object := info.Defs[identifier]; object != nil &&
					exactNamedType(object.Type(), "hash", "Hash") {
					hashObjects[object] = true
				}
			}
			return true
		})
	}
	receiverMethods := map[*ast.Ident]string{}
	for selector, selection := range info.Selections {
		identifier, ok := selector.X.(*ast.Ident)
		if !ok || !hashObjects[info.Uses[identifier]] {
			continue
		}
		function, ok := selection.Obj().(*types.Func)
		if !ok || !exactNamedType(selection.Recv(), "hash", "Hash") {
			continue
		}
		receiverMethods[identifier] = function.Name()
	}
	uses := map[types.Object][]*ast.Ident{}
	for identifier, object := range info.Uses {
		if hashObjects[object] {
			uses[object] = append(uses[object], identifier)
		}
	}
	allowed := map[*ast.Ident]bool{}
	for _, identifiers := range uses {
		safe := true
		for _, identifier := range identifiers {
			switch receiverMethods[identifier] {
			case "Sum", "Write":
			default:
				safe = false
			}
		}
		if !safe {
			continue
		}
		for _, identifier := range identifiers {
			if receiverMethods[identifier] == "Write" {
				allowed[identifier] = true
			}
		}
	}
	return allowed
}

func allowedInspectorWriteSelection(
	selector *ast.SelectorExpr,
	selection *types.Selection,
	allowedWriterUses map[*ast.Ident]bool,
	allowedHashWriterUses map[*ast.Ident]bool,
) bool {
	if selector == nil || selection == nil {
		return false
	}
	function, ok := selection.Obj().(*types.Func)
	if !ok || function.Name() != "Write" {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	return (exactNamedType(selection.Recv(), "io", "Writer") &&
		allowedWriterUses[identifier]) ||
		(exactNamedType(selection.Recv(), "hash", "Hash") &&
			allowedHashWriterUses[identifier])
}

func exactPackageVariableIdentifier(
	expression ast.Expr,
	info *types.Info,
	path string,
	name string,
) *ast.Ident {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = parenthesized.X
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	variable, ok := info.Uses[selector.Sel].(*types.Var)
	if !ok ||
		variable.Pkg() == nil ||
		variable.Pkg().Path() != path ||
		variable.Name() != name {
		return nil
	}
	return selector.Sel
}

func inspectorStandardStream(object types.Object) (string, bool) {
	variable, ok := object.(*types.Var)
	if !ok || variable.Pkg() == nil || variable.Pkg().Path() != "os" {
		return "", false
	}
	switch variable.Name() {
	case "Stderr", "Stdin", "Stdout":
		return "os." + variable.Name(), true
	default:
		return "", false
	}
}

func exactPackageFunctionCall(
	expression ast.Expr,
	info *types.Info,
	path string,
	name string,
	argumentCount int,
) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != argumentCount {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	function, ok := info.Uses[selector.Sel].(*types.Func)
	return ok &&
		function.Pkg() != nil &&
		function.Pkg().Path() == path &&
		function.Name() == name
}

func interfaceType(value types.Type) bool {
	value = types.Unalias(value)
	if _, ok := value.(*types.TypeParam); ok {
		return true
	}
	if named, ok := value.(*types.Named); ok {
		value = named.Underlying()
	}
	_, ok := value.(*types.Interface)
	return ok
}

func exactNamedType(value types.Type, path string, name string) bool {
	value = types.Unalias(value)
	named, ok := value.(*types.Named)
	return ok &&
		named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == path &&
		named.Obj().Name() == name
}

func forbiddenWriterFunction(
	function *types.Func,
	signature *types.Signature,
) bool {
	if function.Pkg() == nil ||
		function.Pkg().Path() ==
			"Picocrypt-NG/internal/pcv3credential/testdata/phaseinspect" {
		return false
	}
	if function.Pkg().Path() == "fmt" {
		switch function.Name() {
		case "Fprint", "Fprintf", "Fprintln", "Print", "Printf", "Println":
			return true
		}
	}
	return signatureHasWriterCapability(signature)
}

func forbiddenWriterMethod(
	function *types.Func,
	signature *types.Signature,
) bool {
	switch function.Name() {
	case "ReadFrom", "Write", "WriteAt", "WriteString", "WriteTo":
		return true
	}
	receiver := types.Unalias(signature.Recv().Type())
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = types.Unalias(pointer.Elem())
	}
	named, ok := receiver.(*types.Named)
	if ok &&
		named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "encoding/json" &&
		named.Obj().Name() == "Encoder" &&
		function.Name() == "Encode" {
		return true
	}
	return signatureHasWriterCapability(signature)
}

func signatureHasWriterCapability(signature *types.Signature) bool {
	parameters := signature.Params()
	for index := range parameters.Len() {
		if writerCapabilityType(parameters.At(index).Type()) {
			return true
		}
	}
	return false
}

func writerCapabilityType(value types.Type) bool {
	value = types.Unalias(value)
	switch typed := value.(type) {
	case *types.Array:
		return writerCapabilityType(typed.Elem())
	case *types.Pointer:
		return writerCapabilityType(typed.Elem())
	case *types.Slice:
		return writerCapabilityType(typed.Elem())
	}
	named, ok := value.(*types.Named)
	if !ok || named.Obj().Pkg() == nil ||
		named.Obj().Pkg().Path() != "io" {
		return false
	}
	switch named.Obj().Name() {
	case "ByteWriter", "ReaderFrom", "StringWriter", "Writer", "WriterAt",
		"WriterTo":
		return true
	default:
		return false
	}
}

func forbiddenOSFunction(name string) bool {
	switch name {
	case "Chmod", "Chown", "CopyFS", "Create", "CreateTemp", "Chtimes",
		"Lchown", "Link", "Mkdir", "MkdirAll", "MkdirTemp",
		"NewFile", "OpenFile", "Remove", "RemoveAll", "Rename", "StartProcess",
		"Symlink", "Truncate", "WriteFile":
		return true
	default:
		return false
	}
}

func forbiddenOSMethod(typeName string, methodName string) bool {
	switch typeName {
	case "File":
		switch methodName {
		case "Chmod", "Chown", "ReadFrom", "Sync", "Truncate", "Write",
			"WriteAt", "WriteString":
			return true
		}
	case "Process":
		switch methodName {
		case "Kill", "Release", "Signal", "Wait":
			return true
		}
	case "Root":
		switch methodName {
		case "Chmod", "Chown", "Create", "Chtimes", "Lchown",
			"Link", "Mkdir", "MkdirAll", "OpenFile", "Remove",
			"RemoveAll", "Rename", "Symlink", "WriteFile":
			return true
		}
	}
	return false
}

func forbiddenOSMethodName(name string) bool {
	return forbiddenOSMethod("File", name) ||
		forbiddenOSMethod("Process", name) ||
		forbiddenOSMethod("Root", name)
}

func containsViolation(violations []string, want string) bool {
	for _, violation := range violations {
		if strings.Contains(violation, want) {
			return true
		}
	}
	return false
}

func TestInspectorReadOnlyCopiesUnchanged(t *testing.T) {
	t.Run("real binary preserves the complete fixture", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		before := fixture.snapshot(t)
		var identity fixtureExecutionIdentity
		readTestJSON(t, fixture.identityPath, &identity)
		goPath := identity.Executables["${GO}"].File.Path
		if !snapshotContainsPath(before, goPath) {
			t.Fatalf("complete input snapshot omits external Go executable %s", goPath)
		}
		_ = fixture.inspect(t)
		after := fixture.snapshot(t)
		if !sameInputSnapshots(after, before) {
			t.Fatalf(
				"inspector changed input bytes or metadata:\n before=%#v\n after=%#v",
				before,
				after,
			)
		}
	})
	t.Run("deterministic file replacement is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(path, []byte("bound bytes"), 0o400); err != nil {
			t.Fatalf("write snapshot input: %v", err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat snapshot input: %v", err)
		}
		session := newInspectionSession()
		defer session.close()
		if _, _, err := session.readBoundedFile(path, 1024); err != nil {
			t.Fatalf("authenticate snapshot input: %v", err)
		}
		replacement := path + ".replacement"
		if err := os.WriteFile(replacement, []byte("bound bytes"), 0o400); err != nil {
			t.Fatalf("write replacement input: %v", err)
		}
		if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
			t.Fatalf("restore replacement timestamp: %v", err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatalf("replace authenticated input: %v", err)
		}
		if err := session.verify(); err == nil ||
			!strings.Contains(err.Error(), "inspection input changed") {
			t.Fatalf("replacement verification error = %v", err)
		}
	})
	t.Run("same-metadata in-place mutation is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(path, []byte("alpha"), 0o400); err != nil {
			t.Fatalf("write snapshot input: %v", err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat snapshot input: %v", err)
		}
		session := newInspectionSession()
		defer session.close()
		if _, _, err := session.readBoundedFile(path, 1024); err != nil {
			t.Fatalf("authenticate snapshot input: %v", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("make snapshot input mutable: %v", err)
		}
		if err := os.WriteFile(path, []byte("bravo"), 0o600); err != nil {
			t.Fatalf("mutate snapshot input: %v", err)
		}
		if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
			t.Fatalf("restore snapshot timestamp: %v", err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatalf("restore snapshot mode: %v", err)
		}
		if err := session.verify(); err == nil ||
			!strings.Contains(err.Error(), "inspection input changed") {
			t.Fatalf("in-place verification error = %v", err)
		}
	})
	t.Run("evidence namespace growth is rejected", func(t *testing.T) {
		fixture := newInspectorFixture(t)
		session := newInspectionSession()
		defer session.close()
		if _, err := session.readDirectoryNames(fixture.evidenceDir); err != nil {
			t.Fatalf("snapshot evidence namespace: %v", err)
		}
		if err := os.WriteFile(
			filepath.Join(fixture.evidenceDir, "late-unrelated"),
			[]byte("late"),
			0o400,
		); err != nil {
			t.Fatalf("grow evidence namespace: %v", err)
		}
		if err := session.verify(); err == nil ||
			!strings.Contains(err.Error(), "inspection namespace changed") {
			t.Fatalf("namespace verification error = %v", err)
		}
	})
	t.Run("identity then namespace snapshot rejects restored-metadata rename", func(t *testing.T) {
		directory := t.TempDir()
		oldPath := filepath.Join(directory, "old")
		newPath := filepath.Join(directory, "new")
		if err := os.WriteFile(oldPath, []byte("bound"), 0o400); err != nil {
			t.Fatalf("write initial namespace entry: %v", err)
		}
		info, err := os.Lstat(directory)
		if err != nil {
			t.Fatalf("stat initial namespace: %v", err)
		}
		session := newInspectionSession()
		defer session.close()
		if _, err := session.directoryIdentity(directory); err != nil {
			t.Fatalf("bind directory identity: %v", err)
		}
		if _, err := session.readDirectoryNames(directory); err != nil {
			t.Fatalf("snapshot bound namespace: %v", err)
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			t.Fatalf("rename bound namespace entry: %v", err)
		}
		if err := os.Chtimes(directory, info.ModTime(), info.ModTime()); err != nil {
			t.Fatalf("restore namespace timestamp: %v", err)
		}
		if err := session.verify(); err == nil ||
			!strings.Contains(err.Error(), "inspection namespace changed") {
			t.Fatalf("restored namespace verification error = %v", err)
		}
	})
	t.Run("retained immediate root metadata is bound", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "input")
		if err := os.WriteFile(path, []byte("bound"), 0o400); err != nil {
			t.Fatalf("write retained-root input: %v", err)
		}
		session := newInspectionSession()
		defer session.close()
		if _, _, err := session.readBoundedFile(path, 1024); err != nil {
			t.Fatalf("bind retained-root input: %v", err)
		}
		info, err := os.Lstat(directory)
		if err != nil {
			t.Fatalf("stat retained root: %v", err)
		}
		if err := os.Chmod(directory, info.Mode().Perm()^0o040); err != nil {
			t.Fatalf("change retained root mode: %v", err)
		}
		if err := session.verify(); err == nil ||
			!strings.Contains(err.Error(), "inspection root changed") {
			t.Fatalf("retained root verification error = %v", err)
		}
	})
	t.Run("external ancestor metadata churn is not rebound", func(t *testing.T) {
		outer := filepath.Join(t.TempDir(), "outer")
		trusted := filepath.Join(outer, "trusted")
		if err := os.MkdirAll(trusted, 0o700); err != nil {
			t.Fatalf("create trusted input root: %v", err)
		}
		path := filepath.Join(trusted, "input")
		if err := os.WriteFile(path, []byte("bound"), 0o400); err != nil {
			t.Fatalf("write trusted-root input: %v", err)
		}
		session := newInspectionSession()
		defer session.close()
		if _, _, err := session.readBoundedFile(path, 1024); err != nil {
			t.Fatalf("bind trusted-root input: %v", err)
		}
		if err := os.WriteFile(
			filepath.Join(outer, "independent"),
			[]byte("unrelated"),
			0o400,
		); err != nil {
			t.Fatalf("change external ancestor metadata: %v", err)
		}
		if err := session.verify(); err != nil {
			t.Fatalf("external ancestor churn was rebound: %v", err)
		}
	})
	t.Run("snapshot comparator binds links and object identity", func(t *testing.T) {
		t.Run("hardlink count", func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "input")
			if err := os.WriteFile(path, []byte("bound"), 0o400); err != nil {
				t.Fatalf("write snapshot comparator input: %v", err)
			}
			before := []inputSnapshot{inputSnapshotFor(t, path)}
			if err := os.Link(path, filepath.Join(directory, "alias")); err != nil {
				t.Fatalf("hardlink snapshot comparator input: %v", err)
			}
			after := []inputSnapshot{inputSnapshotFor(t, path)}
			if sameInputSnapshots(before, after) {
				t.Fatal("snapshot comparator ignored hardlink count change")
			}
		})
		t.Run("identical replacement", func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "input")
			if err := os.WriteFile(path, []byte("bound"), 0o400); err != nil {
				t.Fatalf("write snapshot comparator input: %v", err)
			}
			before := []inputSnapshot{inputSnapshotFor(t, path)}
			replacement := filepath.Join(directory, "replacement")
			if err := os.WriteFile(
				replacement,
				[]byte("bound"),
				0o400,
			); err != nil {
				t.Fatalf("write identical snapshot replacement: %v", err)
			}
			if err := os.Chtimes(
				replacement,
				before[0].Info.ModTime(),
				before[0].Info.ModTime(),
			); err != nil {
				t.Fatalf("restore replacement timestamp: %v", err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatalf("replace snapshot comparator input: %v", err)
			}
			after := []inputSnapshot{inputSnapshotFor(t, path)}
			if sameInputSnapshots(before, after) {
				t.Fatal("snapshot comparator ignored identical replacement")
			}
		})
	})
	t.Run("oversize metadata rejects before open-file inspection", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			mode  os.FileMode
			limit int64
		}{
			{
				name:  "input",
				mode:  0o400,
				limit: maxInspectorInputBytes,
			},
			{
				name:  "executable",
				mode:  0o500,
				limit: maxExecutableBytes,
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "oversize")
				file, err := os.OpenFile(
					path,
					os.O_WRONLY|os.O_CREATE|os.O_EXCL,
					test.mode,
				)
				if err != nil {
					t.Fatalf("create sparse oversize input: %v", err)
				}
				if err := file.Truncate(test.limit + 1); err != nil {
					_ = file.Close()
					t.Fatalf("size sparse oversize input: %v", err)
				}
				if err := file.Close(); err != nil {
					t.Fatalf("close sparse oversize input: %v", err)
				}
				session := newInspectionSession()
				defer session.close()
				callbacks := 0
				_, _, err = session.captureFile(
					path,
					test.limit,
					true,
					func(*os.File) {
						callbacks++
					},
				)
				if err == nil ||
					!strings.Contains(err.Error(), "bounded reader limit") {
					t.Fatalf("sparse oversize error = %v", err)
				}
				if callbacks != 0 {
					t.Fatalf(
						"open-file inspection callbacks = %d; want 0",
						callbacks,
					)
				}
			})
		}
	})
	t.Run("oversize input is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(path, []byte("too large"), 0o400); err != nil {
			t.Fatalf("write oversize input: %v", err)
		}
		session := newInspectionSession()
		defer session.close()
		if _, _, err := session.readBoundedFile(path, 1); err == nil ||
			!strings.Contains(err.Error(), "bounded reader limit") {
			t.Fatalf("oversize read error = %v", err)
		}
	})
}

func TestInspectorHasNoExecutionOrRepairFlags(t *testing.T) {
	for _, forbidden := range []string{
		"--stage", "--evidence", "--output", "--reset", "--retry", "--resume",
		"--overwrite", "--delete", "--repair",
	} {
		args := newInspectorFixture(t).args
		args = append(args, forbidden, "value")
		if _, err := parseOptions(args); err == nil {
			t.Fatalf("parser accepted forbidden flag %s", forbidden)
		}
	}
	fixture := newInspectorFixture(t)
	_ = fixture.inspect(t)
}

type fixtureGateConfig struct {
	SchemaVersion          int                           `json:"schema_version"`
	GoVersion              string                        `json:"go_version"`
	Module                 string                        `json:"module"`
	BuildAttestation       buildAttestationContract      `json:"build_attestation"`
	RuntimeBindings        runtimeBindings               `json:"runtime_bindings"`
	DependencyContract     vendorDependencyContract      `json:"dependency_contract"`
	CPUContract            cpuContract                   `json:"cpu_contract"`
	ChildEnvironment       childEnvironment              `json:"child_environment"`
	RequiredThreatIDs      []string                      `json:"required_threat_ids"`
	ThreatClosure          []fixtureThreatClosure        `json:"threat_closure"`
	RequiredMutationIDs    []string                      `json:"required_mutation_ids"`
	RequiredExecutionUnits []string                      `json:"required_execution_units"`
	SkipAllowlist          []fixtureSkipRule             `json:"skip_allowlist"`
	SkipRuntime            fixtureSkipCardinality        `json:"skip_runtime_cardinality"`
	LintRuns               []fixtureLintRun              `json:"lint_runs"`
	Stages                 map[string]fixtureStageConfig `json:"stages"`
	EvidenceContract       fixtureEvidenceContract       `json:"evidence_contract"`
}

type fixtureThreatClosure struct {
	ID                  string   `json:"id"`
	Stage               string   `json:"stage"`
	CommandID           string   `json:"command_id"`
	RequiredObservedIDs []string `json:"required_observed_ids"`
}

type fixtureSkipRule struct {
	Test                       string `json:"test"`
	Reason                     string `json:"reason"`
	Match                      string `json:"match"`
	SourcePath                 string `json:"source_path"`
	RequiredGoTestDeclarations int    `json:"required_go_test_declarations"`
}

type fixtureSkipCardinality struct {
	Minimum int `json:"minimum"`
	Maximum int `json:"maximum"`
}

type fixtureLintRun struct {
	ID               string   `json:"id"`
	Tags             []string `json:"tags"`
	Argv             []string `json:"argv"`
	JSONPath         string   `json:"json_path"`
	JSONRequired     bool     `json:"json_required"`
	IssuesRequired   int      `json:"issues_required"`
	ExitCodeRequired int      `json:"exit_code_required"`
	TextOutput       string   `json:"text_output"`
}

type fixtureStageConfig struct {
	Commands []fixtureCommandConfig `json:"commands"`
}

type fixtureCommandConfig struct {
	ID                    string                  `json:"id"`
	Kind                  string                  `json:"kind"`
	ExecutionSurface      fixtureExecutionSurface `json:"execution_surface"`
	Argv                  []string                `json:"argv,omitempty"`
	CWD                   string                  `json:"cwd,omitempty"`
	TimeoutSeconds        int                     `json:"timeout_seconds,omitempty"`
	GoBased               bool                    `json:"go_based,omitempty"`
	MemoryHard            bool                    `json:"memory_hard,omitempty"`
	PackageParallelism    any                     `json:"package_parallelism,omitempty"`
	RequiredIDsSource     string                  `json:"required_ids_source,omitempty"`
	RequiredExitCode      int                     `json:"required_exit_code,omitempty"`
	RequiredTestIDs       []string                `json:"required_test_ids,omitempty"`
	RequiredTestPackages  map[string]string       `json:"required_test_packages,omitempty"`
	LintRun               string                  `json:"lint_run,omitempty"`
	RequiredCount         int                     `json:"required_count,omitempty"`
	RequiredOutputMarker  string                  `json:"required_output_marker,omitempty"`
	ForbiddenOutputMarker string                  `json:"forbidden_output_marker,omitempty"`
}

type fixtureExecutionSurface struct {
	PackagePaths []string `json:"package_paths"`
	BuildTags    []string `json:"build_tags"`
	TestSelector string   `json:"test_selector"`
	EvidenceKind string   `json:"evidence_kind"`
}

type fixtureEvidenceContract struct {
	SchemaVersion          int               `json:"schema_version"`
	RequiredStageNames     []string          `json:"required_stage_names"`
	StageFilenames         map[string]string `json:"stage_filenames"`
	PublicationProofSuffix string            `json:"publication_proof_suffix"`
}

type fixtureFileIdentity struct {
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	Mode            uint32 `json:"mode"`
	Size            int64  `json:"size"`
	ModTimeUnixNano int64  `json:"mod_time_unix_nano"`
}

type fixtureExecutableIdentity struct {
	File            fixtureFileIdentity `json:"file"`
	GoBuildVersion  string              `json:"go_build_version"`
	ModulePath      string              `json:"module_path"`
	MainPackagePath string              `json:"main_package_path"`
	BuildInfoSHA256 string              `json:"go_build_info_sha256"`
}

type fixtureDirectoryIdentity struct {
	Path            string `json:"path"`
	Mode            uint32 `json:"mode"`
	ModTimeUnixNano int64  `json:"mod_time_unix_nano"`
}

type fixtureTreeIdentity struct {
	SHA256     string `json:"sha256"`
	EntryCount int    `json:"entry_count"`
}

type fixtureTreeEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type fixtureSourceManifest struct {
	SchemaVersion int                 `json:"schema_version"`
	Baseline      string              `json:"baseline"`
	Base          string              `json:"base"`
	DiffSHA256    string              `json:"diff_sha256"`
	SourceTree    fixtureTreeIdentity `json:"source_tree"`
	Entries       []fixtureTreeEntry  `json:"entries"`
}

type fixtureExecutionIdentity struct {
	SchemaVersion  int                                  `json:"schema_version"`
	Baseline       string                               `json:"baseline"`
	Base           string                               `json:"base"`
	Source         fixtureDirectoryIdentity             `json:"source"`
	SourceTree     fixtureTreeIdentity                  `json:"source_tree"`
	EvidenceRoot   fixtureDirectoryIdentity             `json:"evidence_root"`
	SourceManifest fixtureFileIdentity                  `json:"source_manifest"`
	Diff           fixtureFileIdentity                  `json:"diff"`
	Config         fixtureFileIdentity                  `json:"config"`
	Spec           fixtureFileIdentity                  `json:"spec"`
	Vectors        fixtureFileIdentity                  `json:"vectors"`
	VectorInput    fixtureFileIdentity                  `json:"vector_input"`
	Mutations      fixtureFileIdentity                  `json:"mutations"`
	Runner         fixtureExecutableIdentity            `json:"runner"`
	Inspector      fixtureExecutableIdentity            `json:"inspector"`
	Executables    map[string]fixtureExecutableIdentity `json:"executables"`
	GoVersion      string                               `json:"go_version"`
	Module         string                               `json:"module"`
	GOOS           string                               `json:"goos"`
	GOARCH         string                               `json:"goarch"`
	CPUModel       string                               `json:"cpu_model"`
	CPUModelSource string                               `json:"cpu_model_source"`
	OnlineSource   string                               `json:"online_source"`
	Online         int                                  `json:"online"`
	PhaseJobs      int                                  `json:"phase_jobs"`
	WorkingDirs    []string                             `json:"working_directories"`
	Environment    map[string][]string                  `json:"stage_child_environments"`
}

type fixtureStageEvidence struct {
	SchemaVersion           int                    `json:"schema_version"`
	Stage                   string                 `json:"stage"`
	Status                  string                 `json:"status"`
	Baseline                string                 `json:"baseline"`
	Base                    string                 `json:"base"`
	ExecutionIdentitySHA256 string                 `json:"execution_identity_sha256"`
	ConfigSHA256            string                 `json:"config_sha256"`
	StartedAt               string                 `json:"started_at"`
	FinishedAt              string                 `json:"finished_at"`
	Commands                []fixtureCommandResult `json:"commands"`
	RequiredIDs             []string               `json:"required_ids"`
	ObservedIDs             []string               `json:"observed_ids"`
	SkipEvents              []fixtureSkipEvent     `json:"skip_events"`
	ClosedThreatIDs         []string               `json:"closed_threat_ids"`
}

type fixtureCommandResult struct {
	ID              string                         `json:"id"`
	Argv            []string                       `json:"argv,omitempty"`
	CWD             string                         `json:"cwd,omitempty"`
	Contract        fixtureCommandEvidence         `json:"contract"`
	ExitCode        int                            `json:"exit_code"`
	StdoutSHA256    string                         `json:"stdout_sha256,omitempty"`
	StderrSHA256    string                         `json:"stderr_sha256,omitempty"`
	ObservedIDs     []string                       `json:"observed_ids,omitempty"`
	SkipEvents      []fixtureSkipEvent             `json:"skip_events,omitempty"`
	GoTestEvent     *fixtureGoTestEventAttestation `json:"go_test_event,omitempty"`
	GoTestFailure   *fixtureGoTestFailureSummary   `json:"go_test_failure_summary,omitempty"`
	TimedOut        bool                           `json:"timed_out"`
	TerminationErr  string                         `json:"termination_error,omitempty"`
	WaitErr         string                         `json:"wait_error,omitempty"`
	Mutations       []fixtureMutationExecution     `json:"mutations,omitempty"`
	ClosedThreatIDs []string                       `json:"closed_threat_ids,omitempty"`
	LintResult      *fixtureLintEvidenceResult     `json:"lint_result,omitempty"`
	ScanResult      *fixtureScanEvidenceResult     `json:"scan_result,omitempty"`
}

type fixtureGoTestEventAttestation struct {
	Package        string `json:"package"`
	TestID         string `json:"test_id"`
	TerminalAction string `json:"terminal_action"`
}

type fixtureGoTestFailureSummary struct {
	TopLevelTestIDs []string `json:"top_level_test_ids"`
	Classification  string   `json:"classification"`
	Truncated       bool     `json:"truncated"`
}

type fixtureCommandEvidence struct {
	Kind                 string                  `json:"kind"`
	ExecutionSurface     fixtureExecutionSurface `json:"execution_surface"`
	TimeoutSeconds       int                     `json:"timeout_seconds"`
	GoBased              bool                    `json:"go_based"`
	MemoryHard           bool                    `json:"memory_hard"`
	PackageParallelism   int                     `json:"package_parallelism"`
	RequiredExitCode     int                     `json:"required_exit_code"`
	RequiredTestIDs      []string                `json:"required_test_ids"`
	RequiredTestPackages map[string]string       `json:"required_test_packages"`
}

type fixtureLintEvidenceResult struct {
	RunID          string     `json:"run_id"`
	JSONSHA256     string     `json:"json_sha256"`
	Issues         []struct{} `json:"issues"`
	EnabledLinters []string   `json:"enabled_linters"`
}

type fixtureScanEvidenceResult struct {
	Scanner  string `json:"scanner"`
	Target   string `json:"target"`
	Findings int    `json:"findings"`
}

type fixtureMutationExecution struct {
	ID                 string                           `json:"id"`
	KillingTestID      string                           `json:"killing_test_id"`
	ViolationMarker    string                           `json:"violation_marker"`
	Pristine           fixtureCommandResult             `json:"pristine"`
	Application        fixtureCommandResult             `json:"application"`
	ApplicationReceipt fixtureCampaignApplicationRecord `json:"application_receipt"`
	Mutant             fixtureCommandResult             `json:"mutant"`
}

type fixtureCampaignApplicationRecord struct {
	SchemaVersion      int                    `json:"schema_version"`
	MutationID         string                 `json:"mutation_id"`
	BaselineCommit     string                 `json:"baseline_commit"`
	SpecSHA256         string                 `json:"spec_sha256"`
	SourceSetSHA256    string                 `json:"source_set_sha256"`
	SourcePath         string                 `json:"source_path"`
	SourceBeforeSHA256 string                 `json:"source_before_sha256"`
	SourceAfterSHA256  string                 `json:"source_after_sha256"`
	AnchorMatches      int                    `json:"anchor_matches"`
	ApplicationCount   int                    `json:"application_count"`
	KillingTestID      string                 `json:"killing_test_id"`
	ViolationMarker    string                 `json:"expected_violation_marker"`
	ExpectedPristine   fixtureCampaignOutcome `json:"expected_pristine"`
	ExpectedMutant     fixtureCampaignOutcome `json:"expected_mutant"`
}

type fixtureSkipEvent struct {
	Test   string `json:"test"`
	Reason string `json:"reason"`
}

type fixtureMutationManifest struct {
	SchemaVersion   int                       `json:"schema_version"`
	SpecSHA256      string                    `json:"spec_sha256"`
	SourceSetSHA256 string                    `json:"source_set_sha256"`
	ArgvTemplate    []string                  `json:"argv_template"`
	Mutations       []fixtureCampaignMutation `json:"mutations"`
}

type fixtureCampaignMutation struct {
	ID              string                 `json:"id"`
	Requirement     string                 `json:"requirement"`
	Invariant       string                 `json:"invariant"`
	SourcePath      string                 `json:"source_path"`
	SourceSHA256    string                 `json:"source_sha256"`
	Anchor          string                 `json:"anchor"`
	Replacement     string                 `json:"replacement"`
	KillingTestID   string                 `json:"killing_test_id"`
	ViolationMarker string                 `json:"expected_violation_marker"`
	Pristine        fixtureCampaignOutcome `json:"pristine"`
	Mutant          fixtureCampaignOutcome `json:"mutant"`
}

type fixtureCampaignOutcome struct {
	Status          string   `json:"status"`
	Execution       string   `json:"execution"`
	SemanticCommand []string `json:"semantic_command"`
	TestID          string   `json:"test_id"`
	ViolationMarker string   `json:"violation_marker"`
	Stage           string   `json:"stage"`
	Reason          string   `json:"reason"`
	Skipped         bool     `json:"skipped"`
	CompileOnly     bool     `json:"compile_only"`
}

type fixtureEvidenceProof struct {
	SchemaVersion  int    `json:"schema_version"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type inspectorVerdictLiteral struct {
	SchemaVersion             int                        `json:"schema_version"`
	Status                    string                     `json:"status"`
	Baseline                  string                     `json:"baseline"`
	Base                      string                     `json:"base"`
	ConfigSHA256              string                     `json:"config_sha256"`
	SourceManifestSHA256      string                     `json:"source_manifest_sha256"`
	SpecSHA256                string                     `json:"spec_sha256"`
	ExecutionIdentitySHA256   string                     `json:"execution_identity_sha256"`
	DiffSHA256                string                     `json:"diff_sha256"`
	Inspector                 inspectorExecutableLiteral `json:"inspector"`
	Stages                    []inspectorStageLiteral    `json:"stages"`
	RequiredExecutionSurfaces []fixtureExecutionSurface  `json:"required_execution_surfaces"`
	ObservedExecutionSurfaces []fixtureExecutionSurface  `json:"observed_execution_surfaces"`
	Skip                      inspectorSkipLiteral       `json:"skip"`
	ThreatClosure             []string                   `json:"threat_closure"`
}

type inspectorExecutableLiteral struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	GoBuildVersion string `json:"go_build_version"`
}

type inspectorStageLiteral struct {
	Stage          string `json:"stage"`
	EvidenceName   string `json:"evidence_name"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	ProofName      string `json:"proof_name"`
	ProofSHA256    string `json:"proof_sha256"`
}

type inspectorSkipLiteral struct {
	ObservedCardinality int `json:"observed_cardinality"`
}

type inspectorFixture struct {
	root            string
	source          string
	evidenceDir     string
	configPath      string
	sourceManifest  string
	specPath        string
	diffPath        string
	vectorsPath     string
	vectorInputPath string
	mutationsPath   string
	runnerPath      string
	lintPath        string
	gitleaksPath    string
	identityPath    string
	selfPath        string
	args            []string
}

func reviewedInspectorConfig(t *testing.T) gateConfig {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "gates.json"))
	if err != nil {
		t.Fatalf("read reviewed inspector config: %v", err)
	}
	var config gateConfig
	if err := decodeStrictJSON(data, &config, false); err != nil {
		t.Fatalf("strict-decode reviewed inspector config: %v", err)
	}
	return config
}

func removeConfigArg(argv []string, argument string) []string {
	result := make([]string, 0, len(argv))
	for _, current := range argv {
		if current != argument {
			result = append(result, current)
		}
	}
	return result
}

func removeConfigArgPrefix(argv []string, prefix string) []string {
	result := make([]string, 0, len(argv))
	for _, current := range argv {
		if !strings.HasPrefix(current, prefix) {
			result = append(result, current)
		}
	}
	return result
}

func replaceConfigArgPrefix(
	argv []string,
	prefix string,
	replacement string,
) []string {
	result := append([]string(nil), argv...)
	for index, current := range result {
		if strings.HasPrefix(current, prefix) {
			result[index] = replacement
			return result
		}
	}
	return result
}

func removeConfigArgPair(argv []string, flagName string) []string {
	result := make([]string, 0, len(argv))
	for index := 0; index < len(argv); index++ {
		if argv[index] == flagName && index+1 < len(argv) {
			index++
			continue
		}
		result = append(result, argv[index])
	}
	return result
}

func newInspectorFixture(t *testing.T) *inspectorFixture {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	evidenceDir := filepath.Join(root, "evidence")
	if err := os.MkdirAll(
		filepath.Join(source, "src", "internal", "fileops"),
		0o700,
	); err != nil {
		t.Fatalf("create source fixture: %v", err)
	}
	if err := os.Mkdir(evidenceDir, 0o700); err != nil {
		t.Fatalf("create evidence fixture: %v", err)
	}
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	fixture := &inspectorFixture{
		root:            root,
		source:          source,
		evidenceDir:     evidenceDir,
		configPath:      filepath.Join(source, "gates.json"),
		sourceManifest:  filepath.Join(root, "source.manifest.json"),
		specPath:        filepath.Join(source, "spec.md"),
		diffPath:        filepath.Join(root, "source.diff"),
		vectorsPath:     filepath.Join(source, "vectors.json"),
		vectorInputPath: filepath.Join(source, "vector-input.json"),
		mutationsPath:   filepath.Join(source, "mutations.json"),
		runnerPath:      filepath.Join(root, "phasegates"),
		lintPath:        filepath.Join(root, "golangci-lint"),
		gitleaksPath:    filepath.Join(root, "gitleaks"),
		identityPath:    filepath.Join(evidenceDir, "execution-identity.json"),
		selfPath:        filepath.Join(root, "phaseinspect"),
	}
	configData, err := os.ReadFile(filepath.Join("..", "gates.json"))
	if err != nil {
		t.Fatalf("read reviewed gates fixture: %v", err)
	}
	fixture.writeReadOnly(t, fixture.configPath, configData)
	fixture.createRealCeremonyWorkspaceLayout(t)
	var mutationSource strings.Builder
	mutationSource.WriteString("package fileops\n")
	for index := range 20 {
		_, _ = fmt.Fprintf(&mutationSource, "// mutation-anchor-%02d\n", index)
	}
	for path, data := range map[string][]byte{
		fixture.specPath:        []byte("specification\n"),
		fixture.diffPath:        []byte("diff\n"),
		fixture.vectorsPath:     []byte("{\"vectors\":[]}\n"),
		fixture.vectorInputPath: []byte("{\"inputs\":[]}\n"),
		fixture.mutationsPath:   []byte("{\"schema_version\":1,\"mutations\":[]}\n"),
		filepath.Join(source, "src", "internal", "fileops", "unpack_test.go"): []byte(mutationSource.String()),
	} {
		fixture.writeReadOnly(t, path, data)
	}
	fixture.copyExecutable(t, testExecutable, fixture.lintPath)
	fixture.copyExecutable(t, testExecutable, fixture.gitleaksPath)
	fixture.rebuildIdentityAndEvidence(t)
	return fixture
}

func (fixture *inspectorFixture) rebuildIdentityAndEvidence(t *testing.T) {
	t.Helper()
	config := fixture.readConfig(t)
	mutationSource := filepath.Join(
		fixture.source,
		"src",
		"internal",
		"fileops",
		"unpack_test.go",
	)
	mutationManifest := fixtureMutationManifestFor(
		config.RequiredMutationIDs,
		testSHA256File(t, fixture.specPath),
		testSHA256File(t, mutationSource),
	)
	fixture.rewriteReadOnly(
		t,
		fixture.mutationsPath,
		canonicalTestJSON(t, mutationManifest),
		0o400,
	)
	sourceTree, sourceEntries := fixtureTreeSnapshot(t, fixture.source)
	sourceManifest := fixtureSourceManifest{
		SchemaVersion: 1,
		Baseline:      testBaseline,
		Base:          testBase,
		DiffSHA256:    testSHA256File(t, fixture.diffPath),
		SourceTree:    sourceTree,
		Entries:       sourceEntries,
	}
	fixture.rewriteReadOnly(
		t,
		fixture.sourceManifest,
		canonicalTestJSON(t, sourceManifest),
		0o400,
	)
	sourceManifestSHA256 := testSHA256File(t, fixture.sourceManifest)
	if _, err := os.Lstat(fixture.runnerPath); errors.Is(err, os.ErrNotExist) {
		fixture.replaceExecutable(
			t,
			fixtureBinaryFor(
				t,
				"./internal/pcv3credential/testdata/phasegates",
				testBaseline,
				testBase,
				sourceManifestSHA256,
				true,
			),
			fixture.runnerPath,
		)
	} else if err != nil {
		t.Fatalf("stat fixture runner: %v", err)
	}
	if _, err := os.Lstat(fixture.selfPath); errors.Is(err, os.ErrNotExist) {
		fixture.replaceExecutable(
			t,
			fixtureBinaryFor(
				t,
				"./internal/pcv3credential/testdata/phaseinspect",
				testBaseline,
				testBase,
				sourceManifestSHA256,
				true,
			),
			fixture.selfPath,
		)
	} else if err != nil {
		t.Fatalf("stat fixture inspector: %v", err)
	}
	goPath := testGoExecutable(t)
	phaseJobs := derivedPhaseJobs(runtime.NumCPU())
	identity := fixtureExecutionIdentity{
		SchemaVersion:  1,
		Baseline:       testBaseline,
		Base:           testBase,
		Source:         fixtureDirectoryIdentityFor(t, fixture.source),
		SourceTree:     sourceTree,
		SourceManifest: fixtureFileIdentityFor(t, fixture.sourceManifest),
		Diff:           fixtureFileIdentityFor(t, fixture.diffPath),
		Config:         fixtureFileIdentityFor(t, fixture.configPath),
		Spec:           fixtureFileIdentityFor(t, fixture.specPath),
		Vectors:        fixtureFileIdentityFor(t, fixture.vectorsPath),
		VectorInput:    fixtureFileIdentityFor(t, fixture.vectorInputPath),
		Mutations:      fixtureFileIdentityFor(t, fixture.mutationsPath),
		Runner:         fixtureExecutableIdentityFor(t, fixture.runnerPath),
		Inspector:      fixtureExecutableIdentityFor(t, fixture.selfPath),
		Executables: map[string]fixtureExecutableIdentity{
			"${GO}":            fixtureExecutableIdentityFor(t, goPath),
			"${GOLANGCI_LINT}": fixtureExecutableIdentityFor(t, fixture.lintPath),
			"${GITLEAKS}":      fixtureExecutableIdentityFor(t, fixture.gitleaksPath),
		},
		GoVersion:      config.GoVersion,
		Module:         config.Module,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		CPUModel:       "fixture CPU",
		CPUModelSource: "fixture",
		OnlineSource:   "runtime.NumCPU",
		Online:         runtime.NumCPU(),
		PhaseJobs:      phaseJobs,
		WorkingDirs:    []string{filepath.Join(fixture.source, "src")},
		Environment: fixtureChildEnvironments(
			config,
			fixture.evidenceDir,
			goPath,
			phaseJobs,
		),
	}
	identity.EvidenceRoot = fixtureDirectoryIdentityFor(t, fixture.evidenceDir)
	identity.EvidenceRoot.ModTimeUnixNano = 0
	fixture.rewriteReadOnly(t, fixture.identityPath, canonicalTestJSON(t, identity), 0o444)
	identitySHA := testSHA256File(t, fixture.identityPath)
	fixture.args = []string{
		"--config", fixture.configPath,
		"--baseline", testBaseline,
		"--base", testBase,
		"--source-manifest", fixture.sourceManifest,
		"--spec", fixture.specPath,
		"--execution-identity", fixture.identityPath,
		"--execution-identity-sha256", identitySHA,
		"--diff", fixture.diffPath,
		"--evidence-dir", fixture.evidenceDir,
	}
	for _, stage := range config.EvidenceContract.RequiredStageNames {
		fixture.writeStageEvidence(t, config, stage, identitySHA)
	}
}

func fixtureChildEnvironments(
	config fixtureGateConfig,
	evidenceRoot string,
	goPath string,
	phaseJobs int,
) map[string][]string {
	environments := make(map[string][]string, len(config.Stages))
	for stage := range config.Stages {
		replacements := map[string]string{
			"${PHASE_JOBS}":        strconv.Itoa(phaseJobs),
			"${FROZEN_SYSTEMROOT}": os.Getenv("SYSTEMROOT"),
			"${GO_DIR}":            filepath.Dir(goPath),
			"${STAGE_TMPDIR}": filepath.Join(
				evidenceRoot,
				".phasegates-"+stage+"-tmp",
			),
			"${WORKSPACE_HOME}": filepath.Join(
				evidenceRoot,
				".phasegates-home",
			),
			"${STAGE_GOCACHE}": filepath.Join(
				evidenceRoot,
				".phasegates-"+stage+"-go-cache",
			),
			"${WORKSPACE_GOMODCACHE}": filepath.Join(
				evidenceRoot,
				".phasegates-go-mod-cache",
			),
			"${WORKSPACE_GOPATH}": filepath.Join(
				evidenceRoot,
				".phasegates-go-path",
			),
			"${WORKSPACE_XDG_CACHE}": filepath.Join(
				evidenceRoot,
				".phasegates-xdg-cache",
			),
			"${WORKSPACE_XDG_CONFIG}": filepath.Join(
				evidenceRoot,
				".phasegates-xdg-config",
			),
		}
		for name, value := range config.ChildEnvironment.Required {
			environments[stage] = append(
				environments[stage],
				name+"="+fixtureReplaceAll(value, replacements),
			)
		}
		sort.Strings(environments[stage])
	}
	return environments
}

func fixtureMutationManifestFor(
	ids []string,
	specSHA256 string,
	sourceSHA256 string,
) fixtureMutationManifest {
	const sourcePath = "internal/fileops/unpack_test.go"
	argv := []string{
		"phase2-mutator",
		"--source-copy", "${SOURCE_COPY}",
		"--manifest", "${MUTATION_MANIFEST}",
		"--mutation-id", "${MUTATION_ID}",
		"--source-set-sha256", "${SOURCE_SET_SHA256}",
		"--baseline", "${BASELINE}",
		"--spec-sha256", "${SPEC_SHA256}",
		"--result", "${RESULT}",
	}
	sourceSet := sha256.New()
	_, _ = sourceSet.Write([]byte(sourcePath))
	_, _ = sourceSet.Write([]byte{0})
	_, _ = sourceSet.Write([]byte(sourceSHA256))
	_, _ = sourceSet.Write([]byte{'\n'})
	manifest := fixtureMutationManifest{
		SchemaVersion:   1,
		SpecSHA256:      specSHA256,
		SourceSetSHA256: hex.EncodeToString(sourceSet.Sum(nil)),
		ArgvTemplate:    argv,
	}
	for index, id := range ids {
		testID := "Test" + strings.ReplaceAll(id, "-", "")
		marker := "violation_" + id
		command := []string{
			"go",
			"test",
			"./internal/pcv3credential",
			"-run",
			"^" + testID + "$",
			"-count=1",
		}
		manifest.Mutations = append(manifest.Mutations, fixtureCampaignMutation{
			ID:              id,
			Requirement:     "CRD-07",
			Invariant:       "fixture semantic invariant",
			SourcePath:      sourcePath,
			SourceSHA256:    sourceSHA256,
			Anchor:          fmt.Sprintf("// mutation-anchor-%02d", index),
			Replacement:     fmt.Sprintf("// mutation-replacement-%02d", index),
			KillingTestID:   testID,
			ViolationMarker: marker,
			Pristine: fixtureCampaignOutcome{
				Status: "PASS", Execution: "semantic",
				SemanticCommand: command, TestID: testID,
				Stage: "none", Reason: "success",
			},
			Mutant: fixtureCampaignOutcome{
				Status: "FAIL", Execution: "semantic",
				SemanticCommand: command, TestID: testID,
				ViolationMarker: marker,
				Stage:           "fixture", Reason: marker,
			},
		})
	}
	return manifest
}

func (fixture *inspectorFixture) writeStageEvidence(
	t *testing.T,
	config fixtureGateConfig,
	stage string,
	identitySHA string,
) {
	t.Helper()
	var identity fixtureExecutionIdentity
	readTestJSON(t, fixture.identityPath, &identity)
	var manifest fixtureMutationManifest
	readTestJSON(t, fixture.mutationsPath, &manifest)
	stageConfig := config.Stages[stage]
	var commands []fixtureCommandResult
	var observed []string
	var closed []string
	for _, command := range stageConfig.Commands {
		effective := fixtureEffectiveCommand(t, config, command)
		replacements := fixtureStageReplacements(identity, stage)
		result := fixtureCommandResult{
			ID:       command.ID,
			CWD:      fixtureReplaceAll(effective.CWD, replacements),
			Contract: fixtureCommandEvidenceFor(t, effective),
			ExitCode: effective.RequiredExitCode,
			TimedOut: false,
		}
		switch {
		case command.Kind == "mutation-campaign":
			result.ObservedIDs = append([]string(nil), config.RequiredMutationIDs...)
			for index, id := range config.RequiredMutationIDs {
				specification := manifest.Mutations[index]
				mutationRoot := filepath.Join(
					replacements["${STAGE_TMPDIR}"],
					id,
				)
				moduleRoot := filepath.Join(mutationRoot, "source", "src")
				pristineArgv := fixtureSemanticTestArgv(
					identity.Executables["${GO}"].File.Path,
					specification.KillingTestID,
				)
				applicationArgv := []string{
					identity.Executables["${GO}"].File.Path,
					"run",
					"-tags",
					"migrated_fynedo",
					"./internal/pcv3credential/testdata/mutator",
					"--source-copy", moduleRoot,
					"--manifest", identity.Mutations.Path,
					"--mutation-id", specification.ID,
					"--source-set-sha256", manifest.SourceSetSHA256,
					"--baseline", identity.Baseline,
					"--spec-sha256", manifest.SpecSHA256,
					"--result", filepath.Join(mutationRoot, "application.json"),
				}
				sourceData, err := os.ReadFile(filepath.Join(
					identity.Source.Path,
					"src",
					filepath.FromSlash(specification.SourcePath),
				))
				if err != nil {
					t.Fatalf("read fixture mutation source: %v", err)
				}
				if bytes.Count(sourceData, []byte(specification.Anchor)) != 1 {
					t.Fatalf("fixture mutation anchor %q is not exact", specification.Anchor)
				}
				sourceAfterSHA256 := testSHA256Bytes(bytes.Replace(
					sourceData,
					[]byte(specification.Anchor),
					[]byte(specification.Replacement),
					1,
				))
				result.Mutations = append(result.Mutations, fixtureMutationExecution{
					ID:              id,
					KillingTestID:   specification.KillingTestID,
					ViolationMarker: specification.ViolationMarker,
					Pristine: fixtureStructuredResult(
						t,
						id+"/pristine",
						pristineArgv,
						moduleRoot,
						0,
						&fixtureGoTestEventAttestation{
							Package:        "Picocrypt-NG/internal/pcv3credential",
							TestID:         specification.KillingTestID,
							TerminalAction: "pass",
						},
					),
					Application: fixtureStructuredResult(
						t,
						id+"/application",
						applicationArgv,
						filepath.Join(identity.Source.Path, "src"),
						0,
						nil,
					),
					ApplicationReceipt: fixtureCampaignApplicationRecord{
						SchemaVersion:      1,
						MutationID:         id,
						BaselineCommit:     identity.Baseline,
						SpecSHA256:         manifest.SpecSHA256,
						SourceSetSHA256:    manifest.SourceSetSHA256,
						SourcePath:         specification.SourcePath,
						SourceBeforeSHA256: specification.SourceSHA256,
						SourceAfterSHA256:  sourceAfterSHA256,
						AnchorMatches:      1,
						ApplicationCount:   1,
						KillingTestID:      specification.KillingTestID,
						ViolationMarker:    specification.ViolationMarker,
						ExpectedPristine:   specification.Pristine,
						ExpectedMutant:     specification.Mutant,
					},
					Mutant: fixtureStructuredResult(
						t,
						id+"/mutant",
						pristineArgv,
						moduleRoot,
						1,
						&fixtureGoTestEventAttestation{
							Package:        "Picocrypt-NG/internal/pcv3credential",
							TestID:         specification.KillingTestID,
							TerminalAction: "fail",
						},
					),
				})
			}
		case len(command.RequiredTestIDs) != 0:
			result.ObservedIDs = append([]string(nil), command.RequiredTestIDs...)
		}
		switch command.Kind {
		case "go-test", "golangci-lint", "gitleaks":
			result.Argv = fixtureReplaceSlice(effective.Argv, replacements)
			result.StdoutSHA256 = testSHA256Bytes(nil)
			result.StderrSHA256 = testSHA256Bytes(nil)
		}
		switch command.Kind {
		case "golangci-lint":
			result.LintResult = &fixtureLintEvidenceResult{
				RunID:          command.LintRun,
				JSONSHA256:     testSHA256Bytes([]byte(command.LintRun)),
				Issues:         []struct{}{},
				EnabledLinters: []string{"govet"},
			}
		case "gitleaks":
			result.ScanResult = &fixtureScanEvidenceResult{
				Scanner:  "gitleaks",
				Target:   filepath.Join(identity.Source.Path, "src", "internal", "pcv3credential"),
				Findings: 0,
			}
		}
		for _, closure := range config.ThreatClosure {
			if closure.Stage == stage && closure.CommandID == command.ID {
				result.ClosedThreatIDs = append(result.ClosedThreatIDs, closure.ID)
			}
		}
		sort.Strings(result.ClosedThreatIDs)
		commands = append(commands, result)
		observed = append(observed, result.ObservedIDs...)
		closed = append(closed, result.ClosedThreatIDs...)
	}
	sort.Strings(closed)
	var required []string
	if stage == "mutation" {
		required = append(required, config.RequiredMutationIDs...)
	}
	if stage == "host" {
		for _, closure := range config.ThreatClosure {
			if closure.Stage == stage {
				required = append(required, closure.ID)
			}
		}
		sort.Strings(required)
	}
	evidence := fixtureStageEvidence{
		SchemaVersion:           1,
		Stage:                   stage,
		Status:                  "PASS",
		Baseline:                testBaseline,
		Base:                    testBase,
		ExecutionIdentitySHA256: identitySHA,
		ConfigSHA256:            testSHA256File(t, fixture.configPath),
		StartedAt:               "2026-07-30T00:00:00Z",
		FinishedAt:              "2026-07-30T00:01:00Z",
		Commands:                commands,
		RequiredIDs:             required,
		ObservedIDs:             observed,
		SkipEvents:              nil,
		ClosedThreatIDs:         closed,
	}
	name := config.EvidenceContract.StageFilenames[stage]
	path := filepath.Join(fixture.evidenceDir, name)
	fixture.rewriteReadOnly(t, path, canonicalTestJSON(t, evidence), 0o400)
	proof := fixtureEvidenceProof{
		SchemaVersion:  1,
		EvidenceSHA256: testSHA256File(t, path),
	}
	fixture.rewriteReadOnly(
		t,
		path+config.EvidenceContract.PublicationProofSuffix,
		canonicalTestJSON(t, proof),
		0o400,
	)
}

func fixtureEffectiveCommand(
	t *testing.T,
	config fixtureGateConfig,
	command fixtureCommandConfig,
) fixtureCommandConfig {
	t.Helper()
	if command.Kind != "golangci-lint" {
		return command
	}
	for _, lint := range config.LintRuns {
		if lint.ID != command.LintRun {
			continue
		}
		command.Argv = append([]string(nil), lint.Argv...)
		command.CWD = "${SOURCE}/src"
		command.TimeoutSeconds = 600
		command.GoBased = true
		command.PackageParallelism = json.Number("1")
		command.RequiredExitCode = lint.ExitCodeRequired
		return command
	}
	t.Fatalf("fixture command references unknown lint run %q", command.LintRun)
	return fixtureCommandConfig{}
}

func fixtureCommandEvidenceFor(
	t *testing.T,
	command fixtureCommandConfig,
) fixtureCommandEvidence {
	t.Helper()
	parallelism := 0
	switch value := command.PackageParallelism.(type) {
	case nil:
	case json.Number:
		parsed, err := strconv.Atoi(value.String())
		if err != nil {
			t.Fatalf("parse fixture command parallelism: %v", err)
		}
		parallelism = parsed
	case float64:
		parallelism = int(value)
	case string:
		if value == "${PHASE_JOBS}" {
			parallelism = 1
		} else {
			parsed, err := strconv.Atoi(value)
			if err != nil {
				t.Fatalf("parse fixture command parallelism: %v", err)
			}
			parallelism = parsed
		}
	default:
		t.Fatalf("unsupported fixture command parallelism %T", value)
	}
	surface := command.ExecutionSurface
	if surface.PackagePaths == nil {
		surface.PackagePaths = []string{}
	}
	if surface.BuildTags == nil {
		surface.BuildTags = []string{}
	}
	requiredTestIDs := append([]string(nil), command.RequiredTestIDs...)
	if requiredTestIDs == nil {
		requiredTestIDs = []string{}
	}
	requiredTestPackages := make(map[string]string, len(command.RequiredTestPackages))
	for testID, packagePath := range command.RequiredTestPackages {
		requiredTestPackages[testID] = packagePath
	}
	return fixtureCommandEvidence{
		Kind:                 command.Kind,
		ExecutionSurface:     surface,
		TimeoutSeconds:       command.TimeoutSeconds,
		GoBased:              command.GoBased,
		MemoryHard:           command.MemoryHard,
		PackageParallelism:   parallelism,
		RequiredExitCode:     command.RequiredExitCode,
		RequiredTestIDs:      requiredTestIDs,
		RequiredTestPackages: requiredTestPackages,
	}
}

func fixtureStructuredResult(
	t *testing.T,
	id string,
	argv []string,
	cwd string,
	exitCode int,
	event *fixtureGoTestEventAttestation,
) fixtureCommandResult {
	t.Helper()
	command := fixtureCommandConfig{
		ID:                 id,
		Kind:               "structured",
		Argv:               argv,
		CWD:                cwd,
		TimeoutSeconds:     120,
		GoBased:            true,
		PackageParallelism: json.Number("1"),
		RequiredExitCode:   exitCode,
	}
	return fixtureCommandResult{
		ID:           id,
		Argv:         append([]string(nil), argv...),
		CWD:          cwd,
		Contract:     fixtureCommandEvidenceFor(t, command),
		ExitCode:     exitCode,
		StdoutSHA256: testSHA256Bytes(nil),
		StderrSHA256: testSHA256Bytes(nil),
		GoTestEvent:  event,
		TimedOut:     false,
	}
}

func fixtureSemanticTestArgv(goExecutable string, testID string) []string {
	return []string{
		goExecutable,
		"test",
		"-tags",
		"migrated_fynedo",
		"-p",
		"1",
		"./internal/pcv3credential",
		"-run",
		"^" + testID + "$",
		"-count=1",
		"-timeout=60s",
		"-json",
	}
}

func fixtureStageReplacements(
	identity fixtureExecutionIdentity,
	stage string,
) map[string]string {
	replacements := map[string]string{
		"${SOURCE}":          identity.Source.Path,
		"${SOURCE_MANIFEST}": identity.SourceManifest.Path,
		"${MUTATIONS}":       identity.Mutations.Path,
		"${PHASE_JOBS}":      strconv.Itoa(identity.PhaseJobs),
		"${STAGE_TMPDIR}": filepath.Join(
			identity.EvidenceRoot.Path,
			".phasegates-"+stage+"-tmp",
		),
		"${STAGE}": stage,
	}
	for name, executable := range identity.Executables {
		replacements[name] = executable.File.Path
	}
	return replacements
}

func fixtureReplaceSlice(
	values []string,
	replacements map[string]string,
) []string {
	replaced := make([]string, len(values))
	for index, value := range values {
		replaced[index] = fixtureReplaceAll(value, replacements)
	}
	return replaced
}

func fixtureReplaceAll(value string, replacements map[string]string) string {
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value = strings.ReplaceAll(value, key, replacements[key])
	}
	return value
}

func (fixture *inspectorFixture) inspect(t *testing.T) inspectorVerdictLiteral {
	t.Helper()
	stdout, stderr, err := fixture.executeBinary(t)
	if err != nil {
		t.Fatalf("inspect valid closure: %v; stderr=%q", err, stderr)
	}
	if len(stderr) != 0 {
		t.Fatalf("valid inspector wrote stderr: %q", stderr)
	}
	var verdict inspectorVerdictLiteral
	decodeStrictLiteral(t, stdout, &verdict)
	return verdict
}

func (fixture *inspectorFixture) requireRejected(
	t *testing.T,
	wantError ...string,
) {
	t.Helper()
	diagnostic := fixture.rejectedDiagnostic(t)
	if len(wantError) != 0 && wantError[0] != "" &&
		!strings.Contains(diagnostic, wantError[0]) {
		t.Fatalf(
			"rejection error = %q; want substring %q",
			diagnostic,
			wantError[0],
		)
	}
}

func (fixture *inspectorFixture) requireRejectedExact(
	t *testing.T,
	wantError string,
) {
	t.Helper()
	if diagnostic := fixture.rejectedDiagnostic(t); diagnostic != wantError {
		t.Fatalf("rejection error = %q; want exact %q", diagnostic, wantError)
	}
}

func (fixture *inspectorFixture) rejectedDiagnostic(t *testing.T) string {
	t.Helper()
	stdout, stderr, err := fixture.executeBinary(t)
	if err == nil {
		t.Fatal("invalid evidence closure unexpectedly passed")
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("rejected closure exit = %v; want exit code 1", err)
	}
	diagnostic := strings.TrimSuffix(string(stderr), "\n")
	if diagnostic == "" || strings.Contains(diagnostic, "\n") {
		t.Fatalf("rejected closure stderr is not one diagnostic: %q", stderr)
	}
	t.Logf("rejected closure: %s", diagnostic)
	if len(stdout) != 0 {
		t.Fatalf("rejected closure wrote stdout: %q", stdout)
	}
	return diagnostic
}

func (fixture *inspectorFixture) executeBinary(
	t *testing.T,
) ([]byte, []byte, error) {
	t.Helper()
	command := exec.Command(fixture.selfPath, fixture.args...)
	command.Dir = fixture.root
	command.Env = []string{
		"GOENV=off",
		"GOMAXPROCS=1",
		"GOTOOLCHAIN=local",
		"HOME=" + fixture.root,
		"PATH=",
		"SYSTEMROOT=" + os.Getenv("SYSTEMROOT"),
		"TMPDIR=" + fixture.root,
		"XDG_CACHE_HOME=" + fixture.root,
		"XDG_CONFIG_HOME=" + fixture.root,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func (fixture *inspectorFixture) wantVerdict(t *testing.T) inspectorVerdictLiteral {
	t.Helper()
	config := fixture.readConfig(t)
	var stages []inspectorStageLiteral
	var surfaces []fixtureExecutionSurface
	for _, stage := range config.EvidenceContract.RequiredStageNames {
		name := config.EvidenceContract.StageFilenames[stage]
		proofName := name + config.EvidenceContract.PublicationProofSuffix
		stages = append(stages, inspectorStageLiteral{
			Stage:          stage,
			EvidenceName:   name,
			EvidenceSHA256: testSHA256File(t, filepath.Join(fixture.evidenceDir, name)),
			ProofName:      proofName,
			ProofSHA256:    testSHA256File(t, filepath.Join(fixture.evidenceDir, proofName)),
		})
		for _, command := range config.Stages[stage].Commands {
			surfaces = append(surfaces, command.ExecutionSurface)
		}
	}
	identitySHA := testSHA256File(t, fixture.identityPath)
	self := fixtureExecutableIdentityFor(t, fixture.selfPath)
	return inspectorVerdictLiteral{
		SchemaVersion:           1,
		Status:                  "PASS",
		Baseline:                testBaseline,
		Base:                    testBase,
		ConfigSHA256:            testSHA256File(t, fixture.configPath),
		SourceManifestSHA256:    testSHA256File(t, fixture.sourceManifest),
		SpecSHA256:              testSHA256File(t, fixture.specPath),
		ExecutionIdentitySHA256: identitySHA,
		DiffSHA256:              testSHA256File(t, fixture.diffPath),
		Inspector: inspectorExecutableLiteral{
			Path: fixture.selfPath, SHA256: self.File.SHA256,
			GoBuildVersion: self.GoBuildVersion,
		},
		Stages:                    stages,
		RequiredExecutionSurfaces: surfaces,
		ObservedExecutionSurfaces: append([]fixtureExecutionSurface(nil), surfaces...),
		Skip: inspectorSkipLiteral{
			ObservedCardinality: fixture.observedSkipCount(t),
		},
		ThreatClosure: append([]string(nil), config.RequiredThreatIDs...),
	}
}

func (fixture *inspectorFixture) rewriteEvidence(
	t *testing.T,
	stage string,
	mutate func(map[string]any),
) {
	t.Helper()
	config := fixture.readConfig(t)
	name := config.EvidenceContract.StageFilenames[stage]
	path := filepath.Join(fixture.evidenceDir, name)
	var evidence map[string]any
	readTestJSON(t, path, &evidence)
	mutate(evidence)
	var normalized fixtureStageEvidence
	decodeTestJSON(t, canonicalTestJSON(t, evidence), &normalized)
	fixture.rewriteReadOnly(t, path, canonicalTestJSON(t, normalized), 0o400)
	proofPath := path + config.EvidenceContract.PublicationProofSuffix
	proof := fixtureEvidenceProof{
		SchemaVersion:  1,
		EvidenceSHA256: testSHA256File(t, path),
	}
	fixture.rewriteReadOnly(t, proofPath, canonicalTestJSON(t, proof), 0o400)
}

func (fixture *inspectorFixture) spliceObservedID(
	t *testing.T,
	stage string,
	commandID string,
	observedID string,
) {
	t.Helper()
	fixture.rewriteEvidence(t, stage, func(evidence map[string]any) {
		commands := evidence["commands"].([]any)
		found := false
		for _, value := range commands {
			command := value.(map[string]any)
			if command["id"] != commandID {
				continue
			}
			observed, _ := command["observed_ids"].([]any)
			command["observed_ids"] = append(observed, observedID)
			found = true
		}
		if !found {
			t.Fatalf("fixture command %q is absent from stage %q", commandID, stage)
		}
		var aggregate []any
		for _, value := range commands {
			command := value.(map[string]any)
			observed, _ := command["observed_ids"].([]any)
			aggregate = append(aggregate, observed...)
		}
		evidence["observed_ids"] = aggregate
	})
}

func (fixture *inspectorFixture) injectDuplicateEvidenceField(
	t *testing.T,
	stage string,
	field string,
) {
	t.Helper()
	config := fixture.readConfig(t)
	name := config.EvidenceContract.StageFilenames[stage]
	path := filepath.Join(fixture.evidenceDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence before duplicate injection: %v", err)
	}
	needle := []byte(`"` + field + `":"PASS"`)
	replacement := []byte(`"` + field + `":"PASS","` + field + `":"PASS"`)
	if bytes.Count(data, needle) != 1 {
		t.Fatalf("evidence field %s is not unique before duplicate injection", field)
	}
	data = bytes.Replace(data, needle, replacement, 1)
	fixture.rewriteReadOnly(t, path, data, 0o400)
	proofPath := path + config.EvidenceContract.PublicationProofSuffix
	proof := fixtureEvidenceProof{
		SchemaVersion:  1,
		EvidenceSHA256: testSHA256File(t, path),
	}
	fixture.rewriteReadOnly(t, proofPath, canonicalTestJSON(t, proof), 0o400)
}

func (fixture *inspectorFixture) rewriteIdentity(
	t *testing.T,
	mutate func(map[string]any),
) {
	t.Helper()
	var identity map[string]any
	readTestJSON(t, fixture.identityPath, &identity)
	mutate(identity)
	var normalized fixtureExecutionIdentity
	decodeTestJSON(t, canonicalTestJSON(t, identity), &normalized)
	fixture.rewriteReadOnly(
		t,
		fixture.identityPath,
		canonicalTestJSON(t, normalized),
		0o444,
	)
	identitySHA := testSHA256File(t, fixture.identityPath)
	replaceInspectorArg(t, fixture.args, "--execution-identity-sha256", identitySHA)
	config := fixture.readConfig(t)
	for _, stage := range config.EvidenceContract.RequiredStageNames {
		fixture.rewriteEvidence(t, stage, func(evidence map[string]any) {
			evidence["execution_identity_sha256"] = identitySHA
		})
	}
}

func (fixture *inspectorFixture) writeExecutionIdentityAndEvidence(
	t *testing.T,
	identity fixtureExecutionIdentity,
) {
	t.Helper()
	fixture.rewriteReadOnly(
		t,
		fixture.identityPath,
		canonicalTestJSON(t, identity),
		0o444,
	)
	identitySHA := testSHA256File(t, fixture.identityPath)
	replaceInspectorArg(
		t,
		fixture.args,
		"--execution-identity-sha256",
		identitySHA,
	)
	config := fixture.readConfig(t)
	for _, stage := range config.EvidenceContract.RequiredStageNames {
		fixture.writeStageEvidence(t, config, stage, identitySHA)
	}
}

func (fixture *inspectorFixture) rebindGoExecutable(
	t *testing.T,
	path string,
) {
	t.Helper()
	var identity fixtureExecutionIdentity
	readTestJSON(t, fixture.identityPath, &identity)
	identity.Executables["${GO}"] = fixtureExecutableIdentityFor(t, path)
	identity.Environment = fixtureChildEnvironments(
		fixture.readConfig(t),
		fixture.evidenceDir,
		path,
		identity.PhaseJobs,
	)
	fixture.writeExecutionIdentityAndEvidence(t, identity)
}

func (fixture *inspectorFixture) rewriteConfig(
	t *testing.T,
	mutate func(map[string]any),
) {
	t.Helper()
	var config map[string]any
	readTestJSON(t, fixture.configPath, &config)
	mutate(config)
	fixture.rewriteReadOnly(t, fixture.configPath, canonicalTestJSON(t, config), 0o400)
	fixture.rebuildIdentityAndEvidence(t)
}

func (fixture *inspectorFixture) setHostSkips(
	t *testing.T,
	skips []fixtureSkipEvent,
) {
	t.Helper()
	fixture.rewriteEvidence(t, "host", func(evidence map[string]any) {
		evidence["skip_events"] = toJSONValue(t, skips)
		commands := evidence["commands"].([]any)
		found := false
		for _, commandValue := range commands {
			command := commandValue.(map[string]any)
			if command["id"] == "host-phase2-tests" {
				command["skip_events"] = toJSONValue(t, skips)
				found = true
			}
		}
		if !found {
			t.Fatal("host Phase-2 command is missing from the evidence fixture")
		}
	})
}

func (fixture *inspectorFixture) observedSkipCount(t *testing.T) int {
	t.Helper()
	config := fixture.readConfig(t)
	path := filepath.Join(
		fixture.evidenceDir,
		config.EvidenceContract.StageFilenames["host"],
	)
	var evidence fixtureStageEvidence
	readTestJSON(t, path, &evidence)
	return len(evidence.SkipEvents)
}

func (fixture *inspectorFixture) removeArtifact(t *testing.T, stage string) {
	t.Helper()
	config := fixture.readConfig(t)
	name := config.EvidenceContract.StageFilenames[stage]
	for _, path := range []string{
		filepath.Join(fixture.evidenceDir, name),
		filepath.Join(
			fixture.evidenceDir,
			name+config.EvidenceContract.PublicationProofSuffix,
		),
	} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove fixture artifact %s: %v", path, err)
		}
	}
}

func (fixture *inspectorFixture) removeAllEvidence(t *testing.T) {
	t.Helper()
	config := fixture.readConfig(t)
	for _, stage := range config.EvidenceContract.RequiredStageNames {
		fixture.removeArtifact(t, stage)
	}
	entries, err := os.ReadDir(fixture.evidenceDir)
	if err != nil {
		t.Fatalf("read emptied evidence fixture: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".evidence.json") ||
			strings.HasSuffix(entry.Name(), ".evidence.json.verified") {
			t.Fatalf(
				"evidence fixture still contains terminal artifact %q",
				entry.Name(),
			)
		}
	}
}

func (fixture *inspectorFixture) createRealCeremonyWorkspaceLayout(
	t *testing.T,
) {
	t.Helper()
	config := fixture.readConfig(t)
	names := []string{
		".phasegates-home",
		".phasegates-go-mod-cache",
		".phasegates-go-path",
		".phasegates-xdg-cache",
		".phasegates-xdg-config",
	}
	for stage := range config.Stages {
		names = append(names, ".phasegates-"+stage+"-go-cache")
	}
	for _, name := range names {
		if err := os.Mkdir(filepath.Join(fixture.evidenceDir, name), 0o700); err != nil {
			t.Fatalf("create ceremony workspace directory %s: %v", name, err)
		}
	}
}

func (fixture *inspectorFixture) assertRealCeremonyRootLayout(
	t *testing.T,
) {
	t.Helper()
	config := fixture.readConfig(t)
	required := map[string]bool{
		filepath.Base(fixture.identityPath): true,
		".phasegates-home":                  true,
		".phasegates-go-mod-cache":          true,
		".phasegates-go-path":               true,
		".phasegates-xdg-cache":             true,
		".phasegates-xdg-config":            true,
	}
	for stage := range config.Stages {
		required[".phasegates-"+stage+"-go-cache"] = true
	}
	entries, err := os.ReadDir(fixture.evidenceDir)
	if err != nil {
		t.Fatalf("read ceremony root layout: %v", err)
	}
	for _, entry := range entries {
		delete(required, entry.Name())
	}
	if len(required) != 0 {
		t.Fatalf("ceremony root layout misses entries: %#v", required)
	}
}

func (fixture *inspectorFixture) readConfig(t *testing.T) fixtureGateConfig {
	t.Helper()
	var config fixtureGateConfig
	readTestJSON(t, fixture.configPath, &config)
	return config
}

type inputSnapshot struct {
	Path    string
	Mode    uint32
	Size    int64
	ModTime int64
	SHA256  string
	Links   uint64
	Info    os.FileInfo
}

func (fixture *inspectorFixture) snapshot(t *testing.T) []inputSnapshot {
	t.Helper()
	var snapshots []inputSnapshot
	seen := make(map[string]struct{})
	err := filepath.WalkDir(fixture.root, func(
		path string,
		entry os.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		snapshots = append(snapshots, inputSnapshotFor(t, path))
		seen[path] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot complete fixture: %v", err)
	}
	var identity fixtureExecutionIdentity
	readTestJSON(t, fixture.identityPath, &identity)
	for _, executable := range identity.Executables {
		path := executable.File.Path
		if _, ok := seen[path]; ok {
			continue
		}
		snapshots = append(snapshots, inputSnapshotFor(t, path))
		seen[path] = struct{}{}
	}
	sort.Slice(snapshots, func(left int, right int) bool {
		return snapshots[left].Path < snapshots[right].Path
	})
	return snapshots
}

func inputSnapshotFor(t *testing.T, path string) inputSnapshot {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat snapshot input %s: %v", path, err)
	}
	links, ok := stableLinkCount(info)
	if !ok {
		t.Fatalf("snapshot input link count is unavailable: %s", path)
	}
	snapshot := inputSnapshot{
		Path: path, Mode: uint32(info.Mode()), Size: info.Size(),
		ModTime: info.ModTime().UnixNano(), Links: links, Info: info,
	}
	if info.Mode().IsRegular() {
		snapshot.SHA256 = testSHA256File(t, path)
	}
	return snapshot
}

func sameInputSnapshots(left []inputSnapshot, right []inputSnapshot) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Path != right[index].Path ||
			left[index].Mode != right[index].Mode ||
			left[index].Size != right[index].Size ||
			left[index].ModTime != right[index].ModTime ||
			left[index].SHA256 != right[index].SHA256 ||
			left[index].Links != right[index].Links ||
			left[index].Info == nil ||
			right[index].Info == nil ||
			!os.SameFile(left[index].Info, right[index].Info) {
			return false
		}
	}
	return true
}

func snapshotContainsPath(snapshots []inputSnapshot, path string) bool {
	for _, snapshot := range snapshots {
		if snapshot.Path == path {
			return true
		}
	}
	return false
}

func (fixture *inspectorFixture) writePrivate(
	t *testing.T,
	path string,
	data []byte,
) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o400); err != nil {
		t.Fatalf("write private fixture %s: %v", path, err)
	}
}

func (fixture *inspectorFixture) writeReadOnly(
	t *testing.T,
	path string,
	data []byte,
) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o400); err != nil {
		t.Fatalf("write read-only fixture %s: %v", path, err)
	}
}

func (fixture *inspectorFixture) rewriteReadOnly(
	t *testing.T,
	path string,
	data []byte,
	mode os.FileMode,
) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("make fixture writable %s: %v", path, err)
		}
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("rewrite fixture %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set fixture mode %s: %v", path, err)
	}
}

func (fixture *inspectorFixture) writeExecutable(
	t *testing.T,
	path string,
	data []byte,
) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o500); err != nil {
		t.Fatalf("write executable fixture %s: %v", path, err)
	}
}

func (fixture *inspectorFixture) copyExecutable(
	t *testing.T,
	source string,
	target string,
) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatalf("open executable fixture: %v", err)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		t.Fatalf("create executable fixture: %v", err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatalf("copy executable fixture: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close executable fixture: %v", err)
	}
}

func (fixture *inspectorFixture) replaceExecutable(
	t *testing.T,
	source string,
	target string,
) {
	t.Helper()
	if _, err := os.Lstat(target); err == nil {
		if err := os.Chmod(target, 0o700); err != nil {
			t.Fatalf("make executable fixture replaceable: %v", err)
		}
		if err := os.Remove(target); err != nil {
			t.Fatalf("remove prior executable fixture: %v", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat prior executable fixture: %v", err)
	}
	fixture.copyExecutable(t, source, target)
}

func testGoExecutable(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("resolve go executable: %v", err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatalf("make go executable path absolute: %v", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve go executable symlinks: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat go executable: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("go executable is not a regular file: %s", path)
	}
	return path
}

func fixtureBinaryFor(
	t *testing.T,
	packagePath string,
	baseline string,
	base string,
	sourceManifestSHA256 string,
	trimpath bool,
) string {
	t.Helper()
	sourceRoot, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve fixture module root: %v", err)
	}
	moduleMode, err := fixtureModuleMode(sourceRoot)
	if err != nil {
		t.Fatalf("select fixture module mode: %v", err)
	}
	key := strings.Join(
		[]string{
			packagePath,
			baseline,
			base,
			sourceManifestSHA256,
			moduleMode,
			strconv.FormatBool(trimpath),
		},
		"\x00",
	)
	fixtureBinaryCache.Lock()
	defer fixtureBinaryCache.Unlock()
	if path := fixtureBinaryCache.paths[key]; path != "" {
		return path
	}
	if fixtureBinaryCache.directory == "" {
		directory, err := os.MkdirTemp("", "pcv3-phaseinspect-builds-")
		if err != nil {
			t.Fatalf("create fixture binary cache: %v", err)
		}
		fixtureBinaryCache.directory = directory
		fixtureBinaryCache.paths = map[string]string{}
	}
	output := filepath.Join(
		fixtureBinaryCache.directory,
		testSHA256Bytes([]byte(key)),
	)
	build := fixtureBuildEnvironment(t, moduleMode, key)
	ldflags := strings.Join([]string{
		"-X=main.phase2Baseline=" + baseline,
		"-X=main.phase2Base=" + base,
		"-X=main.phase2SourceManifestSHA256=" + sourceManifestSHA256,
	}, " ")
	arguments := []string{
		"build",
		"-mod=" + moduleMode,
	}
	if trimpath {
		arguments = append(arguments, "-trimpath")
	}
	arguments = append(
		arguments,
		"-p",
		"1",
		"-ldflags",
		ldflags,
		"-o",
		output,
		packagePath,
	)
	command := exec.Command(
		testGoExecutable(t),
		arguments...,
	)
	command.Dir = sourceRoot
	command.Env = build.environment
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"build fixture binary %s: %v\n%s",
			packagePath,
			err,
			combined,
		)
	}
	if moduleMode == "vendor" &&
		!testDirectoryEmpty(t, build.moduleCache) {
		t.Fatal("vendor fixture build populated the empty module-cache sentinel")
	}
	if err := os.Chmod(output, 0o500); err != nil {
		t.Fatalf("make fixture binary read-only: %v", err)
	}
	fixtureBinaryCache.paths[key] = output
	return output
}

type fixtureBuildConfiguration struct {
	environment []string
	moduleCache string
}

func fixtureModuleMode(moduleRoot string) (string, error) {
	modules := filepath.Join(moduleRoot, "vendor", "modules.txt")
	info, err := os.Lstat(modules)
	if errors.Is(err, os.ErrNotExist) {
		return "readonly", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("vendor/modules.txt is not a regular file")
	}
	return "vendor", nil
}

func fixtureBuildEnvironment(
	t *testing.T,
	moduleMode string,
	key string,
) fixtureBuildConfiguration {
	t.Helper()
	goDirectory := filepath.Dir(testGoExecutable(t))
	if moduleMode == "vendor" {
		root := filepath.Join(
			fixtureBinaryCache.directory,
			"build-environment-"+testSHA256Bytes([]byte(key)),
		)
		directories := map[string]string{
			"cache":       filepath.Join(root, "go-build"),
			"home":        filepath.Join(root, "home"),
			"moduleCache": filepath.Join(root, "go-mod-cache"),
			"goPath":      filepath.Join(root, "go-path"),
		}
		for _, path := range directories {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatalf("create vendor fixture build root %s: %v", path, err)
			}
			if !testDirectoryEmpty(t, path) {
				t.Fatalf("vendor fixture build root is not empty: %s", path)
			}
		}
		return fixtureBuildConfiguration{
			environment: []string{
				"CGO_ENABLED=0",
				"GOCACHE=" + directories["cache"],
				"GOENV=off",
				"GOFLAGS=",
				"GOMAXPROCS=1",
				"GOMODCACHE=" + directories["moduleCache"],
				"GOPATH=" + directories["goPath"],
				"GOPROXY=off",
				"GOSUMDB=off",
				"GOTOOLCHAIN=local",
				"GOWORK=off",
				"HOME=" + directories["home"],
				"PATH=" + goDirectory,
				"TMPDIR=" + os.TempDir(),
			},
			moduleCache: directories["moduleCache"],
		}
	}
	if moduleMode != "readonly" {
		t.Fatalf("unsupported fixture module mode %q", moduleMode)
	}
	userCache, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("resolve safe Go build cache: %v", err)
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolve safe Go module cache: %v", err)
	}
	return fixtureBuildConfiguration{
		environment: []string{
			"CGO_ENABLED=0",
			"GOCACHE=" + filepath.Join(userCache, "go-build"),
			"GOENV=off",
			"GOFLAGS=",
			"GOMAXPROCS=1",
			"GOMODCACHE=" + filepath.Join(userHome, "go", "pkg", "mod"),
			"GOPATH=" + filepath.Join(userHome, "go"),
			"GOPROXY=off",
			"GOSUMDB=off",
			"GOTOOLCHAIN=local",
			"GOWORK=off",
			"HOME=" + fixtureBinaryCache.directory,
			"PATH=" + goDirectory,
			"TMPDIR=" + os.TempDir(),
		},
	}
}

func testDirectoryEmpty(t *testing.T, path string) bool {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("read fixture directory %s: %v", path, err)
	}
	return len(entries) == 0
}

func fixtureFileIdentityFor(t *testing.T, path string) fixtureFileIdentity {
	t.Helper()
	cleaned, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		t.Fatalf("resolve fixture file path: %v", err)
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		t.Fatalf("stat fixture file %s: %v", cleaned, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("fixture file is not regular: %s", cleaned)
	}
	return fixtureFileIdentity{
		Path: cleaned, SHA256: testSHA256File(t, cleaned),
		Mode: uint32(info.Mode()), Size: info.Size(),
		ModTimeUnixNano: info.ModTime().UnixNano(),
	}
}

func fixtureExecutableIdentityFor(
	t *testing.T,
	path string,
) fixtureExecutableIdentity {
	t.Helper()
	file := fixtureFileIdentityFor(t, path)
	info, err := buildinfo.ReadFile(file.Path)
	if err != nil {
		return fixtureExecutableIdentity{File: file}
	}
	return fixtureExecutableIdentity{
		File:            file,
		GoBuildVersion:  info.GoVersion,
		ModulePath:      info.Main.Path,
		MainPackagePath: info.Path,
		BuildInfoSHA256: testSHA256Bytes(canonicalTestJSON(t, info)),
	}
}

func requireTrimpathWithoutLDFlags(t *testing.T, path string) {
	t.Helper()
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture build info %s: %v", path, err)
	}
	trimpath := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "-trimpath":
			trimpath = setting.Value == "true"
		case "-ldflags":
			t.Fatalf(
				"trimpath fixture unexpectedly exposes linker flags: %q",
				setting.Value,
			)
		}
	}
	if !trimpath {
		t.Fatalf("fixture binary %s lacks -trimpath=true build info", path)
	}
}

func fixtureDirectoryIdentityFor(
	t *testing.T,
	path string,
) fixtureDirectoryIdentity {
	t.Helper()
	cleaned, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		t.Fatalf("resolve fixture directory path: %v", err)
	}
	info, err := os.Lstat(cleaned)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("fixture directory is invalid %s: %v", cleaned, err)
	}
	return fixtureDirectoryIdentity{
		Path: cleaned, Mode: uint32(info.Mode()),
		ModTimeUnixNano: info.ModTime().UnixNano(),
	}
}

func fixtureTreeSnapshot(
	t *testing.T,
	root string,
) (fixtureTreeIdentity, []fixtureTreeEntry) {
	t.Helper()
	hasher := sha256.New()
	var entries []fixtureTreeEntry
	err := filepath.WalkDir(root, func(
		path string,
		entry os.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		record := fixtureTreeEntry{
			Path: filepath.ToSlash(relative),
			Mode: uint32(info.Mode()),
			Size: info.Size(),
		}
		switch {
		case info.IsDir():
			record.Type = "directory"
		case info.Mode().IsRegular():
			record.Type = "regular"
			record.SHA256 = testSHA256File(t, path)
		default:
			return errors.New("fixture source contains an unsupported entry")
		}
		if _, err := hasher.Write(canonicalTestJSON(t, record)); err != nil {
			return err
		}
		entries = append(entries, record)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot fixture source tree: %v", err)
	}
	return fixtureTreeIdentity{
		SHA256:     hex.EncodeToString(hasher.Sum(nil)),
		EntryCount: len(entries),
	}, entries
}

func canonicalTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode canonical fixture JSON: %v", err)
	}
	return append(data, '\n')
}

func readTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture JSON %s: %v", path, err)
	}
	decodeTestJSON(t, data, value)
}

func decodeTestJSON(t *testing.T, data []byte, value any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatal("fixture JSON has trailing data")
	}
}

func decodeStrictLiteral(t *testing.T, data []byte, value any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Fatalf("strict-decode JSON: %v", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatal("JSON has trailing data")
	}
}

func testSHA256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture hash input %s: %v", path, err)
	}
	return testSHA256Bytes(data)
}

func testSHA256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func replaceInspectorArg(
	t *testing.T,
	args []string,
	name string,
	value string,
) {
	t.Helper()
	for index := 0; index < len(args); index += 2 {
		if args[index] == name {
			args[index+1] = value
			return
		}
	}
	t.Fatalf("inspector argument %s not found", name)
}

func toJSONObject(t *testing.T, value any) map[string]any {
	t.Helper()
	converted := toJSONValue(t, value)
	object, ok := converted.(map[string]any)
	if !ok {
		t.Fatalf("fixture value is not an object: %T", converted)
	}
	return object
}

func toJSONValue(t *testing.T, value any) any {
	t.Helper()
	data := canonicalTestJSON(t, value)
	var converted any
	decodeTestJSON(t, data, &converted)
	return converted
}
