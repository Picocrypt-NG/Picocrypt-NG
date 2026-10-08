package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pcv3CLICombinedFixture returns the frozen public production-vector normal
// volume and its exact one-byte plaintext. The plaintext SHA-256 is the
// independently frozen manifest literal, not a re-derivation.
func pcv3CLICombinedFixture(t *testing.T) (volume, plaintext []byte) {
	t.Helper()
	volume, err := os.ReadFile(filepath.Join(
		"..", "pcv3operation", "internal", "pcv3", "testdata", "normal", "volumes",
		"normal-standard-combined-ordered-one.pcv",
	))
	if err != nil {
		t.Fatalf("read frozen combined volume: %v", err)
	}
	plaintext, err = os.ReadFile(filepath.Join(
		"..", "pcv3operation", "internal", "pcv3", "testdata", "normal", "plaintext",
		"normal-standard-combined-ordered-one.bin",
	))
	if err != nil {
		t.Fatalf("read frozen combined plaintext: %v", err)
	}
	digest := sha256.Sum256(plaintext)
	if hex.EncodeToString(digest[:]) != "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986" {
		t.Fatal("frozen plaintext identity drifted from the manifest literal")
	}
	return volume, plaintext
}

// TestPCV3CLIResultAndPrivacyBoundary drives the real Cobra path into the
// real operation (no frontend substitution) and proves the CLI consumes the
// same closed operation result: exact terminal bytes, exact exit codes, no
// output on refusal, and no secret or path disclosure.
func TestPCV3CLIResultAndPrivacyBoundary(t *testing.T) {
	volume, expectedPlaintext := pcv3CLICombinedFixture(t)

	t.Run("invalid claimed structure refuses before KDF with exact progress and terminal lines", func(t *testing.T) {
		dir := t.TempDir()
		input := writePCV3CLIFixture(t, dir, "claimed.pcv", []byte{'P', 'C', 'V', 0})
		output := filepath.Join(dir, "plaintext")
		result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
			Args: []string{
				"decrypt", input, "-o", output,
				"--pcv3-factors=password", "-p", "structural",
			},
			Observation:   filepath.Join(dir, "observation.json"),
			RealOperation: true,
		}, nil)
		wantStderr := "Checking operation…\n" +
			"Checking credential policy…\n" +
			"Authenticating…\n" +
			"Outcome: invalid-structure-pre-kdf\n" +
			"Publication: not-attempted\n"
		if result.exitCode != ExitGeneralError || len(result.stdout) != 0 || result.stderr != wantStderr {
			t.Fatalf(
				"invalid-structure terminal = exit %d stdout %q stderr %q; want exit 1, empty stdout, exact progress+contract",
				result.exitCode, result.stdout, result.stderr,
			)
		}
		if !observation.Called {
			t.Fatal("claimed structure did not reach the operation boundary")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("invalid structure created output: %v", err)
		}
	})

	t.Run("valid combined volume publishes exact plaintext with exact rendering", func(t *testing.T) {
		dir := t.TempDir()
		input := writePCV3CLIFixture(t, dir, "claimed.pcv", volume)
		red := writePCV3CLIFixture(t, dir, "red.key", []byte("red"))
		blue := writePCV3CLIFixture(t, dir, "blue.key", []byte("blue"))
		output := filepath.Join(dir, "plaintext")
		result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
			Args: []string{
				"decrypt", input, "-o", output,
				"--pcv3-factors=combined", "--pcv3-keyfile-order=ordered",
				"-p", "mix", "-k", red, "-k", blue, "--quiet",
			},
			Observation:   filepath.Join(dir, "observation.json"),
			RealOperation: true,
		}, nil)
		requireNativePCV3Published(t, result, "TEST ONLY comment")
		plaintext, err := os.ReadFile(output)
		if err != nil {
			t.Fatalf("read published plaintext: %v", err)
		}
		if !bytes.Equal(plaintext, expectedPlaintext) {
			t.Fatalf("published plaintext = %x; want frozen bytes %x", plaintext, expectedPlaintext)
		}
		if strings.Contains(result.stderr, "Checking ") {
			t.Fatalf("quiet mode rendered progress: %q", result.stderr)
		}
		if !observation.Called || pcv3operation.Mode(observation.Mode) != pcv3operation.ModeReadNormal ||
			observation.Password != "mix" || observation.KeyfileCount != 2 ||
			pcv3operation.CredentialMode(observation.FactorMode) != pcv3operation.CredentialModePasswordAndKeyfiles ||
			pcv3operation.KeyfileMode(observation.KeyfileMode) != pcv3operation.KeyfileModeOrdered ||
			pcv3operation.FactorPolicy(observation.ExpectedPolicy) != pcv3operation.FactorPolicyPasswordAndKeyfiles {
			t.Fatalf("real operation observation = %+v; want the intact explicit combined request at the boundary", observation)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("inspect CLI directory: %v", err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
				t.Fatalf("CLI left publication stage residue %q", entry.Name())
			}
		}
	})

	t.Run("wrong password preserves credential privacy and leaves no output", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "privacy-cli-path-51b0e2")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create sentinel directory: %v", err)
		}
		secret := "privacy-cli-secret-7d21c94af0"
		input := writePCV3CLIFixture(t, dir, "claimed.pcv", volume)
		red := writePCV3CLIFixture(t, dir, "red.key", []byte("red"))
		blue := writePCV3CLIFixture(t, dir, "blue.key", []byte("blue"))
		output := filepath.Join(dir, "plaintext")
		result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
			Args: []string{
				"decrypt", input, "-o", output,
				"--pcv3-factors=combined", "--pcv3-keyfile-order=ordered",
				"-p", secret, "-k", red, "-k", blue, "--quiet",
			},
			Observation:   filepath.Join(dir, "observation.json"),
			RealOperation: true,
		}, nil)
		if result.exitCode != ExitGeneralError || len(result.stdout) != 0 ||
			result.stderr != "Outcome: credentials-or-damage\nPublication: not-attempted\n" {
			t.Fatalf(
				"privacy terminal = exit %d stdout %q stderr %q; want exit 1, empty stdout, exact credentials-or-damage refusal",
				result.exitCode, result.stdout, result.stderr,
			)
		}
		if !observation.Called || observation.Password != secret {
			t.Fatal("the secret credential did not cross to the operation boundary intact (privacy scan would be vacuous)")
		}
		if strings.Contains(result.stderr, secret) || bytes.Contains(result.stdout, []byte(secret)) ||
			strings.Contains(result.stderr, "privacy-cli-path-51b0e2") {
			t.Fatalf("CLI output disclosed secret or path sentinel: stderr %q stdout %q", result.stderr, result.stdout)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("refused operation created output: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("inspect CLI directory: %v", err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
				t.Fatalf("CLI left refusal stage residue %q", entry.Name())
			}
		}
	})
}
