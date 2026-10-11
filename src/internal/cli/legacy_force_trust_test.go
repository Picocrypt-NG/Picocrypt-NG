package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyV2ForceWrongKeyfileReportsUntrusted(t *testing.T) {
	binary := buildCLITestBinary(t)
	golden := filepath.Join("..", "..", "testdata", "golden")
	fixture, err := os.ReadFile(filepath.Join(golden, "pico_test_v2_keyfile_single.txt.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte("There is a test file for Picocrypt validation.\n")
	for _, tc := range []struct {
		name          string
		keyfile       string
		force         bool
		verifyFirst   bool
		wantUntrusted bool
	}{
		{"wrong_keyfile_single_pass", "keyfile_beta.bin", true, false, true},
		{"wrong_keyfile_verify_first", "keyfile_beta.bin", true, true, true},
		{"correct_keyfile_force_single_pass", "keyfile_alpha.bin", true, false, false},
		{"correct_keyfile_force_verify_first", "keyfile_alpha.bin", true, true, false},
		{"correct_keyfile_normal", "keyfile_alpha.bin", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "legacy.pcv")
			output := filepath.Join(dir, "recovered.txt")
			if err := os.WriteFile(input, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"decrypt", input, "-o", output, "-p", "test", "-k", filepath.Join(golden, tc.keyfile), "-y"}
			if tc.force {
				args = append(args, "--force")
			}
			if tc.verifyFirst {
				args = append(args, "--verify-first")
			}
			result := runCLITestCommand(t, binary, args...)
			wantExit := 0
			if tc.wantUntrusted {
				wantExit = 2
			}
			if result.exitCode != wantExit {
				t.Errorf("legacy decrypt exit = %d, want %d; stderr: %s", result.exitCode, wantExit, result.stderr)
			}
			cleanSuccess := strings.Contains(result.stderr, "Decryption completed successfully")
			if tc.wantUntrusted {
				if cleanSuccess || !strings.Contains(result.stderr, "untrusted") {
					t.Errorf("forced wrong-keyfile recovery signaled clean success or lost its untrusted warning: %s", result.stderr)
				}
			} else if !cleanSuccess || strings.Contains(result.stderr, "untrusted") {
				t.Errorf("correct keyfile did not retain clean completion: %s", result.stderr)
			}
			recovered, err := os.ReadFile(output)
			if err != nil {
				t.Fatalf("read recovered output: %v", err)
			}
			if tc.wantUntrusted {
				if len(recovered) != len(expected) || bytes.Equal(recovered, expected) {
					t.Error("wrong keyfile must exercise corrupted recovered bytes, not the valid plaintext")
				}
			} else if !bytes.Equal(recovered, expected) {
				t.Error("correct keyfile changed the frozen plaintext")
			}
			preserved, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(preserved, fixture) {
				t.Fatalf("legacy recovery changed its encrypted source: %v", err)
			}
		})
	}
}
