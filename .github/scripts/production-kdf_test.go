package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecutionRequiresCompiledParentsToRunAndFinish(t *testing.T) {
	discovered := discovery{
		Packages:   []string{"fixture"},
		Parents:    []testID{{"fixture", "TestVector"}},
		Production: []testID{{"fixture", "TestVector"}},
	}
	complete := `{"Action":"start","Package":"fixture"}
{"Action":"run","Package":"fixture","Test":"TestVector"}
{"Action":"run","Package":"fixture","Test":"TestVector/normal"}
{"Action":"pass","Package":"fixture","Test":"TestVector/normal"}
{"Action":"pass","Package":"fixture","Test":"TestVector"}
{"Action":"pass","Package":"fixture"}
`
	for _, tc := range []struct {
		name    string
		stream  string
		wantErr bool
	}{
		{"complete", complete, false},
		{"empty stream", "", true},
		{"missing run", strings.ReplaceAll(complete, `{"Action":"run","Package":"fixture","Test":"TestVector"}`, ""), true},
		{"missing parent pass", strings.ReplaceAll(complete, `{"Action":"pass","Package":"fixture","Test":"TestVector"}`, ""), true},
		{"missing child pass", strings.ReplaceAll(complete, `{"Action":"pass","Package":"fixture","Test":"TestVector/normal"}`, ""), true},
		{"package failure", strings.ReplaceAll(complete, `{"Action":"pass","Package":"fixture"}`, `{"Action":"fail","Package":"fixture"}`), true},
		{"production parent skip", strings.ReplaceAll(complete, `{"Action":"pass","Package":"fixture","Test":"TestVector"}`, `{"Action":"skip","Package":"fixture","Test":"TestVector"}`), true},
		{"production child skip", strings.ReplaceAll(complete, `{"Action":"pass","Package":"fixture","Test":"TestVector/normal"}`, `{"Action":"skip","Package":"fixture","Test":"TestVector/normal"}`), true},
		{"duplicate terminal", complete + `{"Action":"pass","Package":"fixture"}`, true},
		{"unknown parent", strings.ReplaceAll(complete, "TestVector", "TestUndiscovered"), true},
		{"unknown package", strings.ReplaceAll(complete, "fixture", "another"), true},
		{"malformed JSON", complete + "{", true},
		{"unknown event", complete + `{"Action":"mystery","Package":"fixture"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyExecution(strings.NewReader(tc.stream), discovered, false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("verification error = %v; want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestDiscoveryUsesCompiledBuildSelectionIncludingReplacementParents(t *testing.T) {
	dir := tinyModule(t)
	r := runner{Dir: dir, Output: t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	got, err := r.discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantParents := []testID{
		{"Picocrypt-NG/internal/cli", "TestCLI"},
		{"Picocrypt-NG/internal/pcv3operation", "Example_frozen"},
		{"Picocrypt-NG/internal/pcv3operation", "FuzzSeed"},
		{"Picocrypt-NG/internal/pcv3operation", "TestOrdinary"},
		{"Picocrypt-NG/internal/pcv3operation", "TestProduction"},
		{"Picocrypt-NG/internal/pcv3operation", "TestReplacement"},
	}
	wantProduction := []testID{
		{"Picocrypt-NG/internal/pcv3operation", "TestProduction"},
		{"Picocrypt-NG/internal/pcv3operation", "TestReplacement"},
	}
	if !reflect.DeepEqual(got.Parents, wantParents) || !reflect.DeepEqual(got.Production, wantProduction) {
		t.Fatalf("discovery = %+v; want parents %+v and production %+v", got, wantParents, wantProduction)
	}
	for _, name := range []string{"list-default.json", "list-production.json", "discovery.jsonl"} {
		data, err := os.ReadFile(filepath.Join(r.Output, name))
		if err != nil || len(data) == 0 {
			t.Fatalf("discovery evidence %s: %v", name, err)
		}
	}
}

func TestProcessPropagatesChildFailureAndCapturesUsage(t *testing.T) {
	t.Setenv("PICOCRYPT_KDF_RUNNER_PROCESS_FIXTURE", "exit")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	stats, err := runProcess(context.Background(), t.TempDir(), []string{executable, "-test.run=^TestRunnerProcessFixture$"}, &stdout, &stderr)
	if err == nil || stats.ExitCode != 7 || stats.MaxRSSKiB <= 0 || stats.ElapsedSeconds <= 0 {
		t.Fatalf("child failure/usage = %+v, %v; stdout=%s stderr=%s", stats, err, stdout.String(), stderr.String())
	}
}

func TestProcessDeadlineKillsOwnedDescendantAndPreservesPartialOutput(t *testing.T) {
	t.Setenv("PICOCRYPT_KDF_RUNNER_PROCESS_FIXTURE", "spawn")
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	t.Setenv("PICOCRYPT_KDF_RUNNER_PID_FILE", pidFile)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	started := time.Now()
	stats, err := runProcess(ctx, t.TempDir(), []string{executable, "-test.run=^TestRunnerProcessFixture$"}, &stdout, &stderr)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 5*time.Second {
		t.Fatalf("deadline result = %+v, %v", stats, err)
	}
	data, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("descendant never started: %v; stderr=%s", readErr, stderr.String())
	}
	pid, parseErr := strconv.Atoi(string(data))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if !strings.Contains(stdout.String(), "before deadline") {
		t.Fatalf("partial stdout lost: %q", stdout.String())
	}
	if processRunning(pid) {
		t.Fatalf("deadline left descendant %d running", pid)
	}
}

func TestProcessKilledChildCannotPass(t *testing.T) {
	t.Setenv("PICOCRYPT_KDF_RUNNER_PROCESS_FIXTURE", "kill")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	stats, err := runProcess(context.Background(), t.TempDir(), []string{executable, "-test.run=^TestRunnerProcessFixture$"}, &stdout, &stderr)
	if err == nil || stats.ExitCode == 0 || !strings.Contains(stdout.String(), "before kill") {
		t.Fatalf("killed child accepted or partial output lost: %+v, %v; stdout=%q", stats, err, stdout.String())
	}
}

func processRunning(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) {
		return false
	}
	if err == nil {
		fields := strings.Fields(string(data)[strings.LastIndex(string(data), ")")+1:])
		return len(fields) == 0 || fields[0] != "Z"
	}
	return syscall.Kill(pid, 0) == nil
}

func TestRunnerProcessFixture(t *testing.T) {
	switch os.Getenv("PICOCRYPT_KDF_RUNNER_PROCESS_FIXTURE") {
	case "exit":
		os.Exit(7)
	case "kill":
		fmt.Println("before kill")
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
	case "spawn":
		cmd := exec.Command(os.Args[0], "-test.run=^TestRunnerProcessFixture$")
		cmd.Env = append(os.Environ(), "PICOCRYPT_KDF_RUNNER_PROCESS_FIXTURE=descendant")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
	case "descendant":
		if err := os.WriteFile(os.Getenv("PICOCRYPT_KDF_RUNNER_PID_FILE"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Println("before deadline")
		time.Sleep(30 * time.Second)
	}
}

func TestEnvironmentRejectsCoverageNarrowingOverrides(t *testing.T) {
	variables := []string{
		"GOFLAGS", "PICOCRYPT_TEST_CLI_ROUNDTRIP_WORKER", "PICOCRYPT_TEST_CLI_ROUNDTRIP_ISOLATE", "PICOCRYPT_TEST_CLI_BINARY",
		"PICOCRYPT_INPUT_SELECTION_MEMORY_CHILD", "PICOCRYPT_TEST_NATIVE_ARCHIVE_WORKER", "PICOCRYPT_TEST_NATIVE_ARCHIVE_FIXTURES",
		"PICOCRYPT_FUTURE_HELPER", "PICOCRYPT_RUN_RECOVERY_LARGE",
	}
	for _, name := range variables {
		t.Setenv(name, "")
	}
	if err := validateEnvironment(nil); err != nil {
		t.Fatal(err)
	}
	if err := validateEnvironment([]string{"-run", "TestProduction"}); err == nil {
		t.Fatal("public selector arguments were accepted")
	}
	for _, name := range variables {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "override")
			if err := validateEnvironment(nil); err == nil {
				t.Fatalf("accepted ambient %s", name)
			}
		})
	}
	for _, name := range []string{"PICOCRYPT_RUN_CLI_INTEGRATION", "PICOCRYPT_RUN_RECOVERY_LARGE", "PICOCRYPT_PRODUCTION_KDF_REPORT_DIR"} {
		t.Run("supported "+name, func(t *testing.T) {
			t.Setenv(name, "1")
			if err := validateEnvironment(nil); err != nil {
				t.Fatalf("supported lane control rejected: %v", err)
			}
		})
	}
}

func TestLaneCleansDescendantAfterIndependentGoDriverFailure(t *testing.T) {
	for _, mode := range []string{"exit", "kill"} {
		t.Run(mode, func(t *testing.T) {
			dir := tinyModule(t)
			pidFile := filepath.Join(t.TempDir(), "descendant.pid")
			source := fmt.Sprintf(`//go:build pcv3_production_kdf

package pcv3operation
import ("fmt"; "os"; "os/exec"; "strconv"; "syscall"; "testing"; "time")
func TestProduction(t *testing.T) {
 child := exec.Command(os.Args[0], "-test.run=^TestOwnedDescendant$")
 child.Env = append(os.Environ(), "PCV3_RUNNER_DESCENDANT=1")
 if err := child.Start(); err != nil { t.Fatal(err) }
 deadline := time.Now().Add(5*time.Second)
 for { if _, err := os.Stat(%q); err == nil { break }; if time.Now().After(deadline) { t.Fatal("descendant did not start") }; time.Sleep(time.Millisecond) }
 fmt.Println("driver control is ready")
 if %q == "kill" { if err := syscall.Kill(os.Getppid(), syscall.SIGKILL); err != nil { t.Fatal(err) }; time.Sleep(30*time.Second) }
 t.Fatal("controlled driver failure")
}
func TestReplacement(t *testing.T) {}
func TestOwnedDescendant(t *testing.T) {
 if os.Getenv("PCV3_RUNNER_DESCENDANT") != "1" { return }
 if err := os.WriteFile(%q, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil { t.Fatal(err) }
 time.Sleep(30*time.Second)
}
`, pidFile, mode, pidFile)
			if err := os.WriteFile(filepath.Join(dir, "internal", "pcv3operation", "production_test.go"), []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			r := runner{Dir: dir, Output: t.TempDir()}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var report laneReport
			err := r.run(ctx, &report)
			if err == nil || ctx.Err() != nil {
				t.Fatalf("driver control was not an independent failure: err=%v context=%v", err, ctx.Err())
			}
			data, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatalf("descendant never started: %v", err)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			process, err := os.FindProcess(pid)
			if err == nil {
				t.Cleanup(func() {
					if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
						t.Error(err)
					}
					if err := process.Release(); err != nil {
						t.Error(err)
					}
				})
			}
			deadline := time.Now().Add(2 * time.Second)
			for processRunning(pid) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if processRunning(pid) {
				t.Fatalf("independent %s left descendant %d running", mode, pid)
			}
			data, err = os.ReadFile(filepath.Join(r.Output, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var retained laneReport
			if err := json.Unmarshal(data, &retained); err != nil {
				t.Fatal(err)
			}
			wantFailure := "exit status 1"
			if mode == "kill" {
				wantFailure = "signal: killed"
			}
			if retained.Status != "failed" || !strings.Contains(retained.Error, wantFailure) || !strings.Contains(retained.Error, "residual owned process group") {
				t.Fatalf("original failure or cleanup cause lost: %+v", retained)
			}
			if data, err := os.ReadFile(filepath.Join(r.Output, "execution.jsonl")); err != nil || len(data) == 0 {
				t.Fatalf("partial execution evidence lost: %v", err)
			}
		})
	}
}

func TestIdentityRejectsGoFlagsFromTemporaryGoEnvironmentFile(t *testing.T) {
	config := filepath.Join(t.TempDir(), "go-env")
	if err := os.WriteFile(config, []byte("GOFLAGS=-mod=readonly\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", config)
	t.Setenv("GOFLAGS", "")
	t.Setenv("CGO_ENABLED", "1")
	t.Setenv("PICOCRYPT_RUN_CLI_INTEGRATION", "1")
	r := runner{Dir: tinyModule(t), Output: t.TempDir()}
	var report laneReport
	if err := r.identity(context.Background(), &report); err == nil || !strings.Contains(err.Error(), "GOFLAGS") {
		t.Fatalf("effective Go configuration was not rejected: %v", err)
	}
}

func TestLaneRetainsCompleteOrFailedReportsForRealFixtureRuns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		wantErr bool
	}{
		{"complete", "frozen", false},
		{"missing fixture", "", true},
		{"corrupt fixture", "corrupt", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := tinyModule(t)
			fixture := filepath.Join(dir, "internal", "pcv3operation", "testdata", "vector")
			if tc.fixture == "" {
				if err := os.Remove(fixture); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(fixture, []byte(tc.fixture), 0o600); err != nil {
				t.Fatal(err)
			}
			r := runner{Dir: dir, Output: t.TempDir()}
			var report laneReport
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			err := r.run(ctx, &report)
			if (err != nil) != tc.wantErr {
				t.Fatalf("lane error = %v; want error %v", err, tc.wantErr)
			}
			data, err := os.ReadFile(filepath.Join(r.Output, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var retained laneReport
			if err := json.Unmarshal(data, &retained); err != nil {
				t.Fatal(err)
			}
			wantStatus := "passed"
			if tc.wantErr {
				wantStatus = "failed"
			}
			if retained.Status != wantStatus || len(retained.Commands) == 0 || len(retained.Discovery.Production) == 0 {
				t.Fatalf("retained report = %+v; want %s and real discovery/execution evidence", retained, wantStatus)
			}
			last := retained.Commands[len(retained.Commands)-1]
			if (last.ExitCode != 0) != tc.wantErr {
				t.Fatalf("execution child status = %+v; want failure %v", last, tc.wantErr)
			}
			if _, err := os.Stat(filepath.Join(r.Output, "execution.jsonl")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCompiledDiscoveryRejectsMissingTagAndNarrowSelectorControls(t *testing.T) {
	for _, tc := range []struct{ name, tags, selector string }{
		{"forgotten tag", "migrated_fynedo", ""},
		{"narrowed selector", "migrated_fynedo,pcv3_production_kdf", "^TestProduction$"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runner{Dir: tinyModule(t), Output: t.TempDir()}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			discovered, err := r.discover(ctx)
			if err != nil {
				t.Fatal(err)
			}
			arguments := []string{"go", "test", "-json", "-count=1", "-p", "1", "-parallel", "1", "-tags", tc.tags}
			if tc.selector != "" {
				arguments = append(arguments, "-run", tc.selector)
			}
			arguments = append(arguments, "./internal/pcv3operation/...", "./internal/cli")
			data, err := r.logged(ctx, "control.jsonl", arguments...)
			if err != nil {
				t.Fatalf("control Go command itself failed: %v", err)
			}
			if err := verifyExecution(bytes.NewReader(data), discovered, false); err == nil {
				t.Fatal("accepted incomplete real Go execution")
			}
		})
	}
}

func tinyModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                   "module Picocrypt-NG\n\ngo 1.27.3\n",
		"internal/cli/cli_test.go": "package cli\nimport \"testing\"\nfunc TestCLI(t *testing.T) {}\n",
		"internal/pcv3operation/ordinary_test.go": `package pcv3operation
import ("fmt"; "testing")
func TestOrdinary(t *testing.T) {}
func FuzzSeed(f *testing.F) { f.Add("seed"); f.Fuzz(func(t *testing.T, value string) {}) }
func Example_frozen() { fmt.Println("frozen"); /* Output: frozen */ }
`,
		"internal/pcv3operation/replacement_test.go": "//go:build !pcv3_production_kdf\n\npackage pcv3operation\nimport \"testing\"\nfunc TestReplacement(t *testing.T) {}\n",
		"internal/pcv3operation/production_test.go":  "//go:build pcv3_production_kdf\n\npackage pcv3operation\nimport (\"testing\"; \"os\")\nfunc TestProduction(t *testing.T) { data, err := os.ReadFile(\"testdata/vector\"); if err != nil || string(data) != \"frozen\" { t.Fatalf(\"fixture rejected: %q %v\", data, err) } }\nfunc TestReplacement(t *testing.T) {}\n",
		"internal/pcv3operation/testdata/vector":     "frozen",
	}
	for name, contents := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestExecutionRejectsSelectorThatStillRunsProductionParents(t *testing.T) {
	discovered := discovery{
		Packages:   []string{"fixture"},
		Parents:    []testID{{"fixture", "TestOrdinary"}, {"fixture", "TestProduction"}},
		Production: []testID{{"fixture", "TestProduction"}},
	}
	stream := `{"Action":"start","Package":"fixture"}
{"Action":"run","Package":"fixture","Test":"TestProduction"}
{"Action":"pass","Package":"fixture","Test":"TestProduction"}
{"Action":"pass","Package":"fixture"}`
	if err := verifyExecution(strings.NewReader(stream), discovered, false); err == nil {
		t.Fatal("accepted an execution that omitted an ordinary compiled parent")
	}
}

func TestExecutionAllowsOnlyExplicitLargeRecoveryOptInSkip(t *testing.T) {
	const pkg = "Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	discovered := discovery{
		Packages:   []string{pkg},
		Parents:    []testID{{pkg, "TestRecoveryActualBytesBeyond64GiB"}},
		Production: []testID{{pkg, "TestRecoveryActualBytesBeyond64GiB"}},
	}
	stream := `{"Action":"start","Package":"` + pkg + `"}
{"Action":"run","Package":"` + pkg + `","Test":"TestRecoveryActualBytesBeyond64GiB"}
{"Action":"skip","Package":"` + pkg + `","Test":"TestRecoveryActualBytesBeyond64GiB"}
{"Action":"pass","Package":"` + pkg + `"}`
	if err := verifyExecution(strings.NewReader(stream), discovered, true); err == nil {
		t.Fatal("production-tagged tests cannot acquire a skip exception")
	}
	discovered.Production = nil
	if err := verifyExecution(strings.NewReader(stream), discovered, true); err != nil {
		t.Fatalf("explicit opt-in skip rejected: %v", err)
	}
	if err := verifyExecution(strings.NewReader(stream), discovered, false); err == nil {
		t.Fatal("accepted the opt-in skip when the large-recovery lane was requested")
	}
	childSkip := `{"Action":"skip","Package":"` + pkg + `","Test":"TestRecoveryActualBytesBeyond64GiB/child"}`
	childStream := strings.Replace(stream, `{"Action":"skip","Package":"`+pkg+`","Test":"TestRecoveryActualBytesBeyond64GiB"}`,
		`{"Action":"run","Package":"`+pkg+`","Test":"TestRecoveryActualBytesBeyond64GiB/child"}`+"\n"+childSkip+"\n"+
			`{"Action":"pass","Package":"`+pkg+`","Test":"TestRecoveryActualBytesBeyond64GiB"}`, 1)
	if err := verifyExecution(strings.NewReader(childStream), discovered, true); err == nil {
		t.Fatal("accepted a descendant instead of the exact opt-in parent")
	}
	childPass := strings.Replace(childSkip, `"Action":"skip"`, `"Action":"pass"`, 1)
	if err := verifyExecution(strings.NewReader(strings.Replace(childStream, childSkip, childPass, 1)), discovered, true); err != nil {
		t.Fatalf("the same valid child lifecycle must pass when the child passes: %v", err)
	}
}

func TestWrapperBootstrapFailuresAndCancellationDoNotStartLaneOrLeaveChildren(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate production-KDF wrapper")
	}
	wrapper := filepath.Join(filepath.Dir(source), "test-production-kdf.sh")
	for _, mode := range []string{"non-linux", "env-failure", "build-failure", "env-signal", "build-signal"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "bootstrap.pids")
			logFile := filepath.Join(dir, "go.log")
			goScript := `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$KDF_BOOTSTRAP_LOG"
case "$1" in
  env)
    if [[ $KDF_BOOTSTRAP_MODE == env-failure ]]; then exit 7; fi
    if [[ $KDF_BOOTSTRAP_MODE != env-signal ]]; then exit 0; fi
    ;;
  build)
    if [[ $KDF_BOOTSTRAP_MODE == build-failure ]]; then exit 9; fi
    if [[ $KDF_BOOTSTRAP_MODE != build-signal ]]; then exit 53; fi
    ;;
  *) exit 54 ;;
esac
trap '' TERM
sleep 30 &
printf '%s %s\n' "$$" "$!" > "$KDF_BOOTSTRAP_PID_FILE"
wait "$!"
`
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte(goScript), 0o700); err != nil {
				t.Fatal(err)
			}
			if mode == "non-linux" {
				if err := os.WriteFile(filepath.Join(dir, "uname"), []byte("#!/bin/sh\necho Darwin\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", wrapper)
			command.WaitDelay = time.Second
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			command.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"KDF_BOOTSTRAP_MODE="+mode, "KDF_BOOTSTRAP_PID_FILE="+pidFile, "KDF_BOOTSTRAP_LOG="+logFile)
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = command.Process.Kill() })
			var pids []int
			if strings.HasSuffix(mode, "-signal") {
				deadline := time.Now().Add(3 * time.Second)
				for {
					data, err := os.ReadFile(pidFile)
					if fields := strings.Fields(string(data)); err == nil && len(fields) == 2 {
						for _, field := range fields {
							pid, err := strconv.Atoi(field)
							if err != nil {
								t.Fatal(err)
							}
							pids = append(pids, pid)
						}
						if len(pids) != 2 {
							t.Fatalf("bootstrap PID record = %q", data)
						}
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("bootstrap child did not start")
					}
					time.Sleep(time.Millisecond)
				}
				group, err := syscall.Getpgid(pids[0])
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = syscall.Kill(-group, syscall.SIGKILL) })
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			err := command.Wait()
			if err == nil || ctx.Err() != nil {
				t.Fatalf("bootstrap must fail promptly without running the lane: err=%v deadline=%v output=%s", err, ctx.Err(), output.String())
			}
			if mode == "non-linux" {
				if !strings.Contains(output.String(), "Linux") {
					t.Fatalf("unsupported host failure must explain Linux requirement: %s", output.String())
				}
				if data, err := os.ReadFile(logFile); err == nil {
					t.Fatalf("unsupported host invoked Go bootstrap: %s", data)
				}
			}
			for _, pid := range pids {
				if processRunning(pid) {
					t.Errorf("cancelled bootstrap left process %d running", pid)
				}
			}
		})
	}
}

func TestWrapperBuildsRealBootstrapRunsSyntheticLaneAndCleansTemp(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate production-KDF wrapper")
	}
	wrapper, err := os.ReadFile(filepath.Join(filepath.Dir(source), "test-production-kdf.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string][]byte{
		"src/go.mod":                             []byte("module bootstrap-fixture\n\ngo 1.27.3\n"),
		".github/scripts/test-production-kdf.sh": wrapper,
		".github/scripts/production-kdf.go":      []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"synthetic lane complete\") }\n"),
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	temporary := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", filepath.Join(dir, ".github/scripts/test-production-kdf.sh"))
	command.Env = append(os.Environ(), "GOENV=off", "GOFLAGS=", "TMPDIR="+temporary)
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "synthetic lane complete") {
		t.Fatalf("real bootstrap did not reach its synthetic lane: %v\n%s", err, output)
	}
	remaining, err := os.ReadDir(temporary)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("bootstrap left owned temporary files: %v, %v", remaining, err)
	}
}
