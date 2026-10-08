package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The production reader and retained transport must render final cleanup truth.
// Exact-owner cleanup refusal after a complete copy is warning exit 2; a broken
// pipe remains a general transport failure.
func TestDecryptStdoutFinalizesRetainedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plaintext retained output requires a supported directory durability barrier")
	}
	for _, scenario := range []string{"clean", "path-replacement", "broken-pipe"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			fixtureRoot := "../pcv3operation/internal/pcv3/testdata/normal"
			fixture, err := os.ReadFile(filepath.Join(fixtureRoot, "volumes/normal-standard-combined-ordered-one.pcv"))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.ReadFile(filepath.Join(fixtureRoot, "plaintext/normal-standard-combined-ordered-one.bin"))
			if err != nil {
				t.Fatal(err)
			}
			sourcePath := filepath.Join(directory, "source.pcv")
			if err := os.WriteFile(sourcePath, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(directory, "plaintext")
			stdout, err := os.Create(filepath.Join(directory, "stdout"))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "broken-pipe" {
				_ = stdout.Close()
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
				stdout = writer
			}
			stderr, err := os.Create(filepath.Join(directory, "stderr"))
			if err != nil {
				t.Fatal(err)
			}
			oldStdout, oldStderr := os.Stdout, os.Stderr
			oldOutput, oldFactors, oldPassword, oldQuiet := decOutput, decPCV3Factors, decPassword, decQuiet
			oldOrder, oldKeyfiles := decPCV3Order, decKeyfiles
			originalRun := pcv3CLIRunOperation
			t.Cleanup(func() {
				os.Stdout, os.Stderr = oldStdout, oldStderr
				decOutput, decPCV3Factors, decPassword, decQuiet = oldOutput, oldFactors, oldPassword, oldQuiet
				decPCV3Order, decKeyfiles = oldOrder, oldKeyfiles
				pcv3CLIRunOperation = originalRun
				_ = stdout.Close()
				_ = stderr.Close()
			})
			os.Stdout, os.Stderr = stdout, stderr
			decOutput, decPCV3Factors, decPassword, decQuiet = target, "combined", "mix", true
			decPCV3Order = "ordered"
			decKeyfiles = []string{filepath.Join(fixtureRoot, "factors/sha256-b1f51a511f1da0cd348b8f8598db32e61cb963e5fc69e2b41485bf99590ed75a.bin"), filepath.Join(fixtureRoot, "factors/sha256-16477688c0e00699c6cfa4497a3612d7e83c532062b64b250fed8908128ed548.bin")}
			var actual *pcv3operation.Result
			replacement := []byte("foreign pathname replacement")
			pcv3CLIRunOperation = func(ctx context.Context, request *pcv3operation.Request, retain bool) pcv3CLIResult {
				result := originalRun(ctx, request, retain)
				adapter, ok := result.(pcv3CLIResultAdapter)
				if !ok {
					t.Fatal("production runner did not return its actual result")
				}
				actual = adapter.result
				if actual.OutputFollowUp() == nil {
					t.Fatalf("production reader returned no retained output: %v", actual)
				}
				t.Cleanup(func() {
					if followUp := actual.OutputFollowUp(); followUp != nil {
						followUp.Discard()
					}
				})
				if scenario == "path-replacement" {
					if err := os.Rename(target, target+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, replacement, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return result
			}
			terminalErr := runPCV3CLI(context.Background(), source, true, target, "")
			wantExit := 0
			if scenario == "path-replacement" {
				wantExit = ExitPCV3Warning
			}
			if scenario == "broken-pipe" {
				wantExit = ExitGeneralError
			}
			if exitCodeForError(terminalErr) != wantExit {
				t.Errorf("stdout terminal: %v (exit %d), want %d", terminalErr, exitCodeForError(terminalErr), wantExit)
			}
			if actual == nil {
				t.Fatal("CLI did not reach production reader")
			}
			if actual.OutputFollowUp() != nil || actual.SourceDeletionAllowed() {
				t.Fatal("stdout completion retained reusable output or source-deletion authority")
			}
			log, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			cleanupWarning := strings.Contains(string(log), pcv3CLIWarningText(pcv3operation.WarningCleanupIncomplete))
			if scenario == "path-replacement" {
				if !cleanupWarning || !slices.Contains(actual.Warnings(), pcv3operation.WarningCleanupIncomplete) {
					t.Errorf("stdout cleanup truth omitted: %s", log)
				}
				got, err := os.ReadFile(target)
				if err != nil || !bytes.Equal(got, replacement) {
					t.Fatalf("foreign replacement changed: %q %v", got, err)
				}
			} else {
				if cleanupWarning {
					t.Errorf("unexpected cleanup warning: %s", log)
				}
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("retained plaintext not cleaned: %v", err)
				}
			}
			if scenario != "broken-pipe" {
				got, err := os.ReadFile(stdout.Name())
				if err != nil || !bytes.Equal(got, expected) {
					t.Fatalf("stdout differs from frozen plaintext: %q %v", got, err)
				}
			}
			gotSource, err := os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(gotSource, fixture) {
				t.Fatalf("source volume changed: %v", err)
			}
		})
	}
}
