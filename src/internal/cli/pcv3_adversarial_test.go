package cli

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// phase9CLICombinedFixture returns the frozen public production-vector normal
// volume and its exact one-byte plaintext. The plaintext SHA-256 is the
// independently frozen manifest literal, not a re-derivation.
func phase9CLICombinedFixture(t *testing.T) (volume, plaintext []byte) {
	t.Helper()
	volume, err := os.ReadFile(filepath.Join(
		"..", "pcv3", "testdata", "normal", "volumes",
		"normal-standard-combined-ordered-one.pcv",
	))
	if err != nil {
		t.Fatalf("read frozen combined volume: %v", err)
	}
	plaintext, err = os.ReadFile(filepath.Join(
		"..", "pcv3", "testdata", "normal", "plaintext",
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

// TestPhase9CLIResultAndPrivacyBoundary drives the real Cobra path into the
// real operation (no frontend substitution) and proves the CLI consumes the
// same closed operation result: exact terminal bytes, exact exit codes, no
// output on refusal, and no secret or path disclosure. On this host the
// production desktop resource admission fails closed before derivation (the
// cgroup v2 root exposes no memory controller files), so the admitted real
// cases terminate with the exact operation-failed contract; the fixed-profile
// success tuples are owned by the pcv3operation matrix through the
// same-package production seam.
func TestPhase9CLIResultAndPrivacyBoundary(t *testing.T) {
	volume, _ := phase9CLICombinedFixture(t)

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

	t.Run("admitted volume fails closed at the real desktop resource boundary with exact rendering", func(t *testing.T) {
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
		if result.exitCode != ExitGeneralError || len(result.stdout) != 0 ||
			result.stderr != "Outcome: operation-failed\nPublication: not-attempted\n" {
			t.Fatalf(
				"fail-closed terminal = exit %d stdout %q stderr %q; want exit 1, empty stdout, exact quiet contract",
				result.exitCode, result.stdout, result.stderr,
			)
		}
		if strings.Contains(result.stderr, "Checking ") {
			t.Fatalf("quiet mode rendered progress: %q", result.stderr)
		}
		if !observation.Called || pcv3operation.Mode(observation.Mode) != pcv3operation.ModeReadNormal ||
			observation.Password != "mix" || observation.KeyfileCount != 2 ||
			pcv3credential.CredentialMode(observation.FactorMode) != pcv3credential.CredentialModePasswordAndKeyfiles {
			t.Fatalf("real operation observation = %+v; want the intact explicit combined request at the boundary", observation)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("fail-closed operation created output: %v", err)
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

	t.Run("secret credentials and sentinel paths never reach rendered output", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "p9cli-path-51b0e2")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create sentinel directory: %v", err)
		}
		secret := "p9cli-secret-7d21c94af0"
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
			result.stderr != "Outcome: operation-failed\nPublication: not-attempted\n" {
			t.Fatalf(
				"privacy terminal = exit %d stdout %q stderr %q; want exit 1, empty stdout, exact refusal",
				result.exitCode, result.stdout, result.stderr,
			)
		}
		if !observation.Called || observation.Password != secret {
			t.Fatal("the secret credential did not cross to the operation boundary intact (privacy scan would be vacuous)")
		}
		if strings.Contains(result.stderr, secret) || bytes.Contains(result.stdout, []byte(secret)) ||
			strings.Contains(result.stderr, "p9cli-path-51b0e2") {
			t.Fatalf("CLI output disclosed secret or path sentinel: stderr %q stdout %q", result.stderr, result.stdout)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("refused operation created output: %v", err)
		}
	})

	t.Run("the adapter projects the identical closed axes without reconstruction", func(t *testing.T) {
		dir := t.TempDir()
		source, err := os.Open(filepath.Join(
			"..", "pcv3", "testdata", "normal", "volumes",
			"normal-standard-combined-ordered-one.pcv",
		))
		if err != nil {
			t.Fatalf("open frozen combined volume: %v", err)
		}
		keyfileRed := newPCV3CLIKeyfile(t, dir, "red")
		keyfileBlue := newPCV3CLIKeyfile(t, dir, "blue")
		output := filepath.Join(dir, "plaintext")
		result := pcv3operation.Run(context.Background(), &pcv3operation.Request{
			Mode:   pcv3operation.ModeReadNormal,
			Source: source,
			Factors: &pcv3credential.FactorRequest{
				Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
				KeyfileMode:    pcv3credential.KeyfileModeOrdered,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
				Password:       []byte("mix"),
				Keyfiles: []*pcv3credential.KeyfileReader{
					pcv3credential.OwnKeyfileReader(keyfileRed),
					pcv3credential.OwnKeyfileReader(keyfileBlue),
				},
			},
			Target: output,
		})
		if result == nil {
			t.Fatal("real operation returned no closed result")
		}
		adapter := pcv3CLIResultAdapter{result: result}
		if adapter.Outcome() != result.Outcome() ||
			adapter.Stage() != result.Stage() ||
			adapter.Code() != result.Code() ||
			adapter.PublicationAttempted() != result.PublicationAttempted() ||
			adapter.PublicationState() != result.PublicationState() ||
			adapter.PublicationStage() != result.PublicationStage() ||
			adapter.PublicationCode() != result.PublicationCode() ||
			adapter.CompletionClass() != result.CompletionClass() {
			t.Fatal("CLI adapter reconstructed rather than projected the closed result axes")
		}
		adapterWarnings := adapter.Warnings()
		resultWarnings := result.Warnings()
		if len(adapterWarnings) != len(resultWarnings) {
			t.Fatal("CLI adapter changed the warning set")
		}
		for index := range adapterWarnings {
			if adapterWarnings[index] != resultWarnings[index] {
				t.Fatal("CLI adapter reordered or rewrote warnings")
			}
		}
		if (adapter.ArchiveFollowUp() != nil) != (result.ArchiveFollowUp() != nil) {
			t.Fatal("CLI adapter invented or dropped archive authority")
		}
		// This host's desktop admission fails closed before derivation, so the
		// real closed result is the exact resource-boundary refusal.
		if adapter.Outcome() != pcv3.OutcomeOperationFailed ||
			adapter.Stage() != pcv3.StageCredentialPolicy ||
			adapter.Code() != pcv3.CodeOperationFailed ||
			result.Diagnostic() != pcv3operation.DiagnosticResourceUnknown ||
			adapter.PublicationAttempted() ||
			adapter.PublicationState() != pcv3publication.State(0) ||
			adapter.CompletionClass() != pcv3operation.CompletionRefused ||
			len(adapterWarnings) != 0 {
			t.Fatalf(
				"real fail-closed operation = %v/%v/%v diagnostic=%v publication %v/%v class %v warnings %v; want the exact resource refusal",
				adapter.Outcome(), adapter.Stage(), adapter.Code(), result.Diagnostic(),
				adapter.PublicationState(), adapter.PublicationCode(),
				adapter.CompletionClass(), adapterWarnings,
			)
		}
		var rendered strings.Builder
		if exit := renderPCV3CLIResult(&rendered, adapter); exit != ExitGeneralError {
			t.Fatalf("refused adapter exit = %d; want %d", exit, ExitGeneralError)
		}
		if rendered.String() != "Outcome: operation-failed\nPublication: not-attempted\n" {
			t.Fatalf("refused adapter rendering = %q; want the exact contract", rendered.String())
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("refused adapter operation created output: %v", err)
		}
	})
}

func newPCV3CLIKeyfile(t *testing.T, dir, content string) *os.File {
	t.Helper()
	path := filepath.Join(dir, content+".key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open keyfile: %v", err)
	}
	return file
}
