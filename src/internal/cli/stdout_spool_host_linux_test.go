//go:build linux && !android

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// Execute is the production embedding boundary: this test host owns its dump
// policy, while cmd/picocrypt main independently restricts executable dumps.
// Retaining dumpable=1 lets the parent inspect even unlinked staging fds.
func TestStdoutSpoolEmbeddingCLIProcess(t *testing.T) {
	if os.Getenv("PICOCRYPT_STDOUT_PROBE_CHILD") != "1" {
		return
	}
	index := slices.Index(os.Args, "--")
	if index < 0 || index+1 == len(os.Args) {
		t.Fatal("embedding CLI helper requires arguments after --")
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dumpable != 1 {
		t.Fatalf("descriptor-probe host dumpable=%d, %v; require test-owned policy 1", dumpable, err)
	}
	os.Args = append([]string{os.Args[0]}, os.Args[index+1:]...)
	if !Execute("stdout-probe-embedding-host") {
		t.Fatal("embedding host arguments did not select CLI execution")
	}
	// Keep the testing harness's PASS line out of authenticated stdout bytes.
	os.Exit(0)
}

func TestStdoutSpoolEmbeddingHostDispatchesCLI(t *testing.T) {
	cmd := stdoutSpoolProbeCommand("--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("embedding CLI version: %v\n%s", err, output)
	}
	if string(output) != "Picocrypt-NG version stdout-probe-embedding-host\n" {
		t.Fatalf("embedding CLI output=%q; want only the dispatched CLI version", output)
	}
}

func TestStdoutSpoolEmbeddingHostPropagatesCLIFailure(t *testing.T) {
	cmd := stdoutSpoolProbeCommand("decrypt", "--stdout-probe-unknown")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != ExitGeneralError || stdout.Len() != 0 ||
		!bytes.Contains(stderr.Bytes(), []byte("unknown flag: --stdout-probe-unknown")) {
		t.Fatalf("embedding host lost CLI failure: %v stdout=%q stderr=%q", err, &stdout, &stderr)
	}
}

func TestStdoutSpoolProbeRejectsExplicitCLIArtifact(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "explicit-cli")
	// If the guard regresses, this artifact exits before any KDF or application
	// work. The child must refuse artifact substitution before launching it.
	if err := os.WriteFile(artifact, []byte("#!/bin/sh\n: > \"$0.ran\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIEncryptedStdoutIntegration$/^blocked_stdout$")
	cmd.Env = append(os.Environ(), "PICOCRYPT_RUN_CLI_INTEGRATION=1", "PICOCRYPT_TEST_CLI_BINARY="+artifact)
	output, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("blocked_stdout descriptor probe requires the test-owned embedding host; unset PICOCRYPT_TEST_CLI_BINARY")) {
		t.Fatalf("explicit artifact was not refused at the descriptor-probe boundary: %v\n%s", err, output)
	}
	if _, err := os.Stat(artifact + ".ran"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor probe launched the explicitly supplied artifact: %v", err)
	}
}
