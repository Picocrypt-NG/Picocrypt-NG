package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The production reader and encrypted transport must render final cleanup truth.
// Exact-owner cleanup refusal after a complete copy is warning exit 2; a broken
// pipe remains a general transport failure.
func TestDecryptStdoutFinalizesEncryptedOutput(t *testing.T) {
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
			var stream *pcv3operation.EncryptedOutput
			var stagePath string
			var stageInfo os.FileInfo
			var stageBytes []byte
			replacement := []byte("foreign pathname replacement")
			pcv3CLIRunOperation = func(ctx context.Context, request *pcv3operation.Request, retain bool) pcv3CLIResult {
				result := originalRun(ctx, request, retain)
				adapter, ok := result.(pcv3CLIResultAdapter)
				if !ok {
					t.Fatal("production runner did not return its actual result")
				}
				actual = adapter.result
				stream = actual.StreamFollowUp()
				t.Cleanup(func() {
					if stream != nil {
						stream.Discard()
					}
				})
				if stream == nil || actual.CompletionClass() != pcv3operation.CompletionStreamPending {
					t.Fatalf("production reader returned no pending encrypted stream: %v", actual)
				}
				if actual.OutputFollowUp() != nil || actual.ArchiveFollowUp() != nil || actual.SourceDeletionAllowed() ||
					actual.PublicationAttempted() || actual.PublicationState() != 0 {
					t.Fatal("pending stdout granted filesystem publication or deletion authority")
				}
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("stdout preparation published its unused target: %v", err)
				}
				entries, err := os.ReadDir(filepath.Dir(target))
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".picocrypt-") {
						if stagePath != "" || !entry.Type().IsRegular() {
							t.Fatal("expected one owned ciphertext stage in the isolated output parent")
						}
						stagePath = filepath.Join(filepath.Dir(target), entry.Name())
					}
				}
				if stagePath == "" {
					t.Fatal("production reader returned no ciphertext stage")
				}
				stageFile, err := os.Open(stagePath)
				if err != nil {
					t.Fatal(err)
				}
				// File.Stat freezes the Windows file ID before pathname replacement.
				stageInfo, err = stageFile.Stat()
				closeErr := stageFile.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("capture ciphertext identity: stat=%v close=%v", err, closeErr)
				}
				stageBytes, err = os.ReadFile(stagePath)
				if err != nil {
					t.Fatal(err)
				}
				// The frozen one-byte payload is one STREAM record with its 16-byte tag.
				if len(stageBytes) != 1+16 {
					t.Fatalf("sealed ciphertext extent = %d; want one byte plus its tag", len(stageBytes))
				}
				if scenario == "path-replacement" {
					if err := os.Rename(stagePath, stagePath+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(stagePath, replacement, 0o600); err != nil {
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
			if actual.StreamFollowUp() != nil || actual.OutputFollowUp() != nil || actual.SourceDeletionAllowed() {
				t.Fatal("stdout completion retained reusable output or source-deletion authority")
			}
			if actual.PublicationAttempted() || actual.PublicationState() != 0 {
				t.Fatal("stdout transport claimed filesystem publication")
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stdout transport published its unused target: %v", err)
			}
			wantStream := pcv3operation.StreamComplete
			if scenario == "broken-pipe" {
				wantStream = pcv3operation.StreamFailed
			}
			if stream.State() != wantStream {
				t.Errorf("stdout state = %v, want %v", stream.State(), wantStream)
			}
			log, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(log), "Publication: not-attempted") {
				t.Errorf("stdout publication truth omitted: %s", log)
			}
			cleanupWarning := strings.Contains(string(log), pcv3CLIWarningText(pcv3operation.WarningCleanupIncomplete))
			if scenario == "path-replacement" {
				if !cleanupWarning || !slices.Contains(actual.Warnings(), pcv3operation.WarningCleanupIncomplete) {
					t.Errorf("stdout cleanup truth omitted: %s", log)
				}
				got, err := os.ReadFile(stagePath)
				if err != nil || !bytes.Equal(got, replacement) {
					t.Fatalf("foreign replacement changed: %q %v", got, err)
				}
				originalInfo, err := os.Stat(stagePath + ".original")
				if err != nil || !os.SameFile(stageInfo, originalInfo) {
					t.Fatalf("renamed ciphertext identity changed: %v", err)
				}
				got, err = os.ReadFile(stagePath + ".original")
				if err != nil || !bytes.Equal(got, stageBytes) {
					t.Fatalf("renamed ciphertext changed: %v", err)
				}
			} else {
				if cleanupWarning {
					t.Errorf("unexpected cleanup warning: %s", log)
				}
				if _, err := os.Stat(stagePath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("encrypted stdout stage not cleaned: %v", err)
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
