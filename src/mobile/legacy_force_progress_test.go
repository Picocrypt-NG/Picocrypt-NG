package mobile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyForceProgressDistinguishesUnverifiedAndAuthenticatedOutput(t *testing.T) {
	golden := filepath.Join("..", "testdata", "golden")
	fixture, err := os.ReadFile(filepath.Join(golden, "pico_test_v2_keyfile_single.txt.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := os.ReadFile(filepath.Join(golden, "pico_test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		wrong       bool
		verifyFirst bool
		status      string
	}{
		{"wrong_keyfile", true, false, "COMPLETED_UNVERIFIED"},
		{"wrong_keyfile_verify_first", true, true, "COMPLETED_UNVERIFIED"},
		{"correct_keyfile", false, false, "COMPLETED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			input := filepath.Join(directory, "legacy.pcv")
			output := filepath.Join(directory, "recovered")
			if err := os.WriteFile(input, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			inputInfo, err := os.Stat(input)
			if err != nil {
				t.Fatal(err)
			}
			keyfile := filepath.Join(golden, "keyfile_alpha.bin")
			if tc.wrong {
				keyfile = filepath.Join(directory, "wrong.key")
				if err := os.WriteFile(keyfile, []byte("wrong public legacy factor"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			id := StartOperation()
			t.Cleanup(func() { cleanupOperation(id) })
			request, err := json.Marshal(DecryptRequestJSON{
				OperationID: id, InputFile: input, OutputFile: output,
				Keyfiles: []string{keyfile}, ForceDecrypt: true, VerifyFirst: tc.verifyFirst,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := StartDecrypt(string(request), []byte("test")); err != "" {
				t.Fatalf("start legacy recovery: %s", err)
			}
			waitForDoneTimeout(t, id, 3*time.Minute)
			result, err := GetProgress(id)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Done || result.StatusCode != tc.status || result.Error != "" || result.Code != "" {
				t.Errorf("recovery completion = %+v, want %s without a terminal error", result, tc.status)
			}
			body, err := os.ReadFile(output)
			if err != nil || len(body) == 0 {
				t.Fatalf("recoverable output missing: length=%d error=%v", len(body), err)
			}
			if bytes.Equal(body, plaintext) == tc.wrong {
				t.Errorf("wrong factor=%v recovered original plaintext=%v", tc.wrong, bytes.Equal(body, plaintext))
			}
			afterInfo, err := os.Stat(input)
			if err != nil || !os.SameFile(inputInfo, afterInfo) {
				t.Fatalf("recovery replaced encrypted source: %v", err)
			}
			after, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(after, fixture) {
				t.Fatalf("recovery changed encrypted source: %v", err)
			}
		})
	}
}
