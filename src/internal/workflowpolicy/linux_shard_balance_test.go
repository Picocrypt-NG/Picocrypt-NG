//go:build linux

package workflowpolicy

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Frozen from the 35-package discovery printed by successful run 42211948070.
// Package paths, rather than timings, keep this a deterministic routing oracle.
func linuxShardObservedPackages() []string {
	return strings.Fields(`
Picocrypt-NG/cmd/picocrypt
Picocrypt-NG/internal/app
Picocrypt-NG/internal/argon2
Picocrypt-NG/internal/cli
Picocrypt-NG/internal/crypto
Picocrypt-NG/internal/diskspace
Picocrypt-NG/internal/distmeta
Picocrypt-NG/internal/encoding
Picocrypt-NG/internal/errors
Picocrypt-NG/internal/fileops
Picocrypt-NG/internal/header
Picocrypt-NG/internal/keyfile
Picocrypt-NG/internal/log
Picocrypt-NG/internal/password
Picocrypt-NG/internal/password/legacyunicode15
Picocrypt-NG/internal/pcv3operation
Picocrypt-NG/internal/pcv3operation/internal/pcv3
Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact
Picocrypt-NG/internal/pcv3operation/internal/pcv3credential
Picocrypt-NG/internal/pcv3operation/internal/pcv3crypto
Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges
Picocrypt-NG/internal/pcv3operation/internal/pcv3recovery
Picocrypt-NG/internal/pcv3operation/internal/pcv3resource
Picocrypt-NG/internal/pcv3operation/internal/pcv3unicode
Picocrypt-NG/internal/pcv3operation/internal/pcv3unicode/norm18
Picocrypt-NG/internal/pcv3publication
Picocrypt-NG/internal/pcv3result
Picocrypt-NG/internal/processsecurity
Picocrypt-NG/internal/secret
Picocrypt-NG/internal/ui
Picocrypt-NG/internal/util
Picocrypt-NG/internal/volume
Picocrypt-NG/internal/wasm
Picocrypt-NG/internal/workflowpolicy
Picocrypt-NG/mobile`)
}

type linuxShardSelection struct {
	packages, commands []string
	output             string
	err                error
}

// Execute the production Bash selector. Stubs record execution dispatch without
// starting native tests, UI processes, KDFs, or additional runners.
func runLinuxShardSelection(t *testing.T, packages []string, shard, arch string) linuxShardSelection {
	t.Helper()
	step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-linux.yml"), "tests"), "Run native tests")
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	write("packages", strings.Join(packages, "\n"), 0o600)
	write("bin/go", `#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == list ]]; then
  [[ $* == 'list -race -tags migrated_fynedo ./...' && $CGO_ENABLED == 1 ]]
  cat "$SHARD_FIXTURE_PACKAGES"
elif [[ $1 == test ]]; then
  printf 'CGO=%s ISOLATE=%s INTEGRATION=%s %s\n' "$CGO_ENABLED" "${PICOCRYPT_TEST_CLI_ROUNDTRIP_ISOLATE:-}" "${PICOCRYPT_RUN_CLI_INTEGRATION:-}" "$*" >> "$SHARD_FIXTURE_CALLS"
else
  exit 97
fi
`, 0o700)
	write(".github/scripts/test-linux-ui-race.sh", "#!/bin/sh\nprintf 'UI\\n' >> \"$SHARD_FIXTURE_CALLS\"\n", 0o700)
	body := strings.ReplaceAll(step.Run, "${{ matrix.arch }}", arch)
	command := exec.Command("bash", "-euo", "pipefail", "-c", body)
	command.Dir = dir
	command.Env = append(os.Environ(), "PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"), "SHARD_INDEX="+shard,
		"SHARD_FIXTURE_PACKAGES="+filepath.Join(dir, "packages"), "SHARD_FIXTURE_CALLS="+filepath.Join(dir, "calls"),
		"PICOCRYPT_TEST_CLI_ROUNDTRIP_ISOLATE=", "PICOCRYPT_RUN_CLI_INTEGRATION=")
	output, err := command.CombinedOutput()
	result := linuxShardSelection{output: string(output), err: err}
	for _, line := range strings.Split(result.output, "\n") {
		if strings.HasPrefix(line, "Picocrypt-NG/") && !strings.ContainsAny(line, " \t") {
			result.packages = append(result.packages, line)
		}
	}
	if calls, readErr := os.ReadFile(filepath.Join(dir, "calls")); readErr == nil {
		result.commands = strings.Split(strings.TrimSpace(string(calls)), "\n")
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return result
}

func TestLinuxCLIRebalanceKeepsObservedUnionAndMovesOnlyCLI(t *testing.T) {
	packages := linuxShardObservedPackages()
	wantZero := strings.Fields(`
Picocrypt-NG/cmd/picocrypt
Picocrypt-NG/internal/argon2
Picocrypt-NG/internal/cli
Picocrypt-NG/internal/crypto
Picocrypt-NG/internal/distmeta
Picocrypt-NG/internal/errors
Picocrypt-NG/internal/header
Picocrypt-NG/internal/log
Picocrypt-NG/internal/password/legacyunicode15
Picocrypt-NG/internal/pcv3operation/internal/pcv3
Picocrypt-NG/internal/pcv3operation/internal/pcv3credential
Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges
Picocrypt-NG/internal/pcv3operation/internal/pcv3resource
Picocrypt-NG/internal/pcv3operation/internal/pcv3unicode/norm18
Picocrypt-NG/internal/pcv3result
Picocrypt-NG/internal/secret
Picocrypt-NG/internal/util
Picocrypt-NG/internal/wasm
Picocrypt-NG/mobile`)
	zero := runLinuxShardSelection(t, packages, "0", "amd64")
	one := runLinuxShardSelection(t, packages, "1", "amd64")
	if zero.err != nil || one.err != nil {
		t.Fatalf("selector failed: shard0=%v %s; shard1=%v %s", zero.err, zero.output, one.err, one.output)
	}
	if !reflect.DeepEqual(zero.packages, wantZero) || len(one.packages) != 16 {
		t.Fatalf("CLI-only move must produce the frozen 19/16 assignment: shard0=%v shard1=%v", zero.packages, one.packages)
	}
	union := append(append([]string(nil), zero.packages...), one.packages...)
	sort.Strings(union)
	if !reflect.DeepEqual(union, packages) {
		t.Fatalf("native package union changed or a package was duplicated: %v", union)
	}
	cliCommands := []string{
		"CGO=1 ISOLATE= INTEGRATION= test -v -count=1 -tags migrated_fynedo -race -p 1 -timeout 15m -skip ^TestCLIRoundTrip$ ./internal/cli",
		"CGO=1 ISOLATE=1 INTEGRATION= test -v -count=1 -tags migrated_fynedo -race -p 1 -timeout 15m -run ^TestCLIRoundTrip$ ./internal/cli",
	}
	if len(zero.commands) != 3 || !reflect.DeepEqual(zero.commands[1:], cliCommands) || len(one.commands) != 2 || one.commands[1] != "UI" {
		t.Fatalf("CLI commands must move intact to shard0 while the UI launcher stays once on shard1: zero=%v one=%v", zero.commands, one.commands)
	}
}

func TestLinuxCLIRebalanceStillDiscoversNewPackagesExactlyOnce(t *testing.T) {
	packages := append(linuxShardObservedPackages(), "Picocrypt-NG/internal/aaa_added", "Picocrypt-NG/internal/zzz_added")
	// Feed discovery in reverse order to exercise the production LC_ALL=C sort.
	sort.Sort(sort.Reverse(sort.StringSlice(packages)))
	zero := runLinuxShardSelection(t, packages, "0", "amd64")
	one := runLinuxShardSelection(t, packages, "1", "amd64")
	if zero.err != nil || one.err != nil {
		t.Fatalf("new package discovery failed: zero=%v %s one=%v %s", zero.err, zero.output, one.err, one.output)
	}
	union := append(append([]string(nil), zero.packages...), one.packages...)
	sort.Strings(union)
	sort.Strings(packages)
	if !reflect.DeepEqual(union, packages) {
		t.Fatalf("new packages must join exactly one shard: %v", union)
	}
	assignedZero := make(map[string]bool)
	for _, name := range zero.packages {
		assignedZero[name] = true
	}
	for index, name := range packages {
		wantZero := index%2 == 0 || name == "Picocrypt-NG/internal/cli"
		if assignedZero[name] != wantZero {
			t.Fatalf("%s lost sorted-index parity or the single CLI override", name)
		}
	}
}

func TestLinuxCLIRebalancePreservesFailClosedSelection(t *testing.T) {
	for _, shard := range []string{"2", "-1", "invalid", ""} {
		t.Run("invalid-index/"+shard, func(t *testing.T) {
			result := runLinuxShardSelection(t, linuxShardObservedPackages(), shard, "amd64")
			if result.err == nil || len(result.commands) != 0 {
				t.Fatalf("invalid shard started execution: err=%v commands=%v", result.err, result.commands)
			}
		})
	}
	for _, tc := range []struct {
		name, shard string
		packages    []string
	}{
		{"empty-discovery", "0", nil},
		{"empty-shard", "1", []string{"Picocrypt-NG/internal/cli"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runLinuxShardSelection(t, tc.packages, tc.shard, "amd64")
			if result.err == nil || len(result.commands) != 0 {
				t.Fatalf("empty selection started execution: err=%v commands=%v", result.err, result.commands)
			}
		})
	}
}

func TestLinuxCLIRebalancePreservesExecutionProgramsAndRunnerMatrix(t *testing.T) {
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-linux.yml"), "tests")
	step := mustStepNamed(t, job, "Run native tests")
	start := strings.Index(step.Run, "  other=()\n")
	if start < 0 {
		t.Fatal("native execution dispatch missing")
	}
	// Computed from the original source before changing its selection loop.
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(step.Run[start:]))); got != "a017e9a2c84285ecd127c1aa948ed14e778585d0d13f770955bb96bd4eaa6a9f" {
		t.Fatalf("race, isolated UI/CLI, or ARM execution commands changed: %s", got)
	}
	var lanes []string
	for _, lane := range job.Strategy.Matrix.Include {
		lanes = append(lanes, fmt.Sprintf("%s/%s/%d", lane.Arch, lane.Runner, lane.Shard))
	}
	want := []string{"amd64/ubuntu-24.04/0", "amd64/ubuntu-24.04/1", "arm64/ubuntu-24.04-arm/0"}
	if !reflect.DeepEqual(lanes, want) {
		t.Fatalf("runner count or architecture coverage changed: %v", lanes)
	}
	arm := runLinuxShardSelection(t, nil, "0", "arm64")
	if arm.err != nil || !reflect.DeepEqual(arm.commands, []string{"CGO=1 ISOLATE= INTEGRATION=1 test -v -count=1 -tags migrated_fynedo -p 1 -timeout 15m ./..."}) {
		t.Fatalf("ARM lane must keep its full native integration command: err=%v commands=%v", arm.err, arm.commands)
	}
}
