package ui

import (
	"Picocrypt-NG/internal/app"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLegacyV2ForceWrongKeyfilePreservesEncryptedSource(t *testing.T) {
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
			// Isolate the fixed 1 GiB KDF and race shadow memory from other cases
			// and subsequent desktop resource-admission checks.
			const child = "PICOCRYPT_TEST_LEGACY_FORCE_UI_CHILD"
			if os.Getenv(child) != "1" {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				command := exec.Command(executable, "-test.run=^TestLegacyV2ForceWrongKeyfilePreservesEncryptedSource$/^"+tc.name+"$", "-test.timeout=5m", "-test.v")
				command.Env = append(os.Environ(), child+"=1")
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("isolated legacy Force UI recovery: %v\n%s", err, output)
				}
				if !bytes.Contains(output, []byte("--- PASS: "+t.Name()+" (")) {
					t.Fatalf("isolated legacy Force UI recovery did not execute and pass %s\n%s", t.Name(), output)
				}
				t.Logf("%s", output)
				return
			}
			state, err := app.NewState()
			if err != nil {
				t.Fatal(err)
			}
			a := &App{State: state}
			dir := t.TempDir()
			input := operationInput{
				mode: "decrypt", inputFile: filepath.Join(dir, "legacy.pcv"), outputFile: filepath.Join(dir, "recovered.txt"),
				password: []byte("test"), keyfiles: []string{filepath.Join(golden, tc.keyfile)},
				forceDecrypt: tc.force, verifyFirst: tc.verifyFirst, delete: true, rsCodecs: state.RSCodecs,
			}
			if err := os.WriteFile(input.inputFile, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			// Use the real legacy reader and the same deletion lifecycle as desktop work.
			result := a.runCapturedOperation(context.Background(), executeVolumeOperation, nil, input)
			if result.err != nil || !result.completed || result.cancelled || result.deleteFailed {
				t.Fatalf("legacy recovery did not reach terminal publication and cleanup: err=%v result=%+v", result.err, result)
			}
			if result.kept != tc.wantUntrusted {
				t.Errorf("legacy result kept = %v, want %v", result.kept, tc.wantUntrusted)
			}
			recovered, err := os.ReadFile(input.outputFile)
			if err != nil {
				t.Fatalf("read recovered output: %v", err)
			}
			if tc.wantUntrusted {
				if len(recovered) != len(expected) || bytes.Equal(recovered, expected) {
					t.Error("wrong keyfile must exercise corrupted recovered bytes, not the valid plaintext")
				}
				preserved, err := os.ReadFile(input.inputFile)
				if err != nil || !bytes.Equal(preserved, fixture) {
					t.Errorf("desktop delete-after-success lost the encrypted source for untrusted output: %v", err)
				}
			} else {
				if !bytes.Equal(recovered, expected) {
					t.Error("correct keyfile changed the frozen plaintext")
				}
				if _, err := os.Lstat(input.inputFile); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("clean completion did not remove its selected temporary source: %v", err)
				}
			}
			a.applyCompletedOperation(input, result)
			snapshot := state.UISnapshot()
			kept := state.WasKept()
			wantStatus := app.StatusCompleted
			if tc.wantUntrusted {
				wantStatus = app.StatusKeptOutputUnverified
			}
			if snapshot.Status.Kind != wantStatus || kept != tc.wantUntrusted {
				t.Errorf("desktop terminal status = %v kept=%v; want %v kept=%v", snapshot.Status.Kind, kept, wantStatus, tc.wantUntrusted)
			}
		})
	}
}
