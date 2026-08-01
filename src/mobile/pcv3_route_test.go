package mobile

import (
	"Picocrypt-NG/internal/volume"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func loadMobilePCV3Fixture(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("..", "internal", "pcv3", "testdata", "schema1-minimal.pcv"))
	if err != nil {
		t.Fatalf("read literal PCV3 fixture: %v", err)
	}
	return fixture
}

func writeMobilePCV3Input(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write mobile input: %v", err)
	}
	return path
}

func mobilePCV3ClaimedCases(t *testing.T) []struct {
	name string
	data []byte
	code string
} {
	t.Helper()
	admitted := loadMobilePCV3Fixture(t)
	unsupported := append([]byte(nil), admitted...)
	unsupported[5] = 4
	return []struct {
		name string
		data []byte
		code string
	}{
		{name: "admitted", data: admitted, code: "PCV3_UNSUPPORTED"},
		{name: "unsupported routing", data: unsupported, code: "PCV3_UNSUPPORTED"},
		{name: "invalid structure", data: []byte{'P', 'C', 'V', 0}, code: "PCV3_INVALID_STRUCTURE"},
	}
}

func TestMobilePCV3DetectOperationRoutesContentBeforeFilename(t *testing.T) {
	for _, test := range mobilePCV3ClaimedCases(t) {
		t.Run(test.name, func(t *testing.T) {
			input := writeMobilePCV3Input(t, "misleading.txt", test.data)
			isEncrypt, err := DetectOperation(input)
			if isEncrypt {
				t.Fatal("claimed PCV3 input was classified for encryption")
			}
			if err == nil || err.Error() != test.code {
				t.Fatalf("DetectOperation(claimed PCV3) error = %v; want exact %q", err, test.code)
			}
		})
	}

	for _, test := range []struct {
		name        string
		filename    string
		data        []byte
		wantEncrypt bool
	}{
		{name: "mismatched discriminator follows extension", filename: "legacy.pcv", data: []byte{'P', 'C', 'X', 0, 1}, wantEncrypt: false},
		{name: "short non-claim stays encryptable", filename: "short.bin", data: []byte{'P', 'C', 'V'}, wantEncrypt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := writeMobilePCV3Input(t, test.filename, test.data)
			isEncrypt, err := DetectOperation(input)
			if err != nil {
				t.Fatalf("DetectOperation(legacy eligible) = %v", err)
			}
			if isEncrypt != test.wantEncrypt {
				t.Fatalf("DetectOperation(legacy eligible) = %v; want %v", isEncrypt, test.wantEncrypt)
			}
		})
	}
}

func TestMobilePCV3GetDecryptionInfoReturnsOnlyRedactedCode(t *testing.T) {
	for _, test := range mobilePCV3ClaimedCases(t) {
		t.Run(test.name, func(t *testing.T) {
			input := writeMobilePCV3Input(t, "metadata-disguise.bin", test.data)
			got, err := GetDecryptionInfo(input)
			if err != nil {
				t.Fatalf("GetDecryptionInfo(claimed PCV3) = %v", err)
			}
			want := `{"errorCode":"` + test.code + `"}`
			if got != want {
				t.Fatalf("GetDecryptionInfo(claimed PCV3) = %q; want exact redacted envelope %q", got, want)
			}

			var envelope map[string]any
			if err := json.Unmarshal([]byte(got), &envelope); err != nil {
				t.Fatalf("parse metadata error envelope: %v", err)
			}
			if len(envelope) != 1 || envelope["errorCode"] != test.code {
				t.Fatalf("metadata error envelope disclosed extra fields: %#v", envelope)
			}
		})
	}

	legacy := writeMobilePCV3Input(t, "legacy.pcv", []byte("legacy metadata input"))
	got, err := GetDecryptionInfo(legacy)
	if err == nil || got != "" {
		t.Fatalf("legacy-eligible metadata result = (%q, %v); want existing reader error", got, err)
	}
}

func TestMobilePCV3StartDecryptRejectsBeforeLegacySideEffects(t *testing.T) {
	originalRunDecrypt := runDecrypt
	decryptCalls := 0
	runDecrypt = func(context.Context, *volume.DecryptRequest) error {
		decryptCalls++
		return nil
	}
	t.Cleanup(func() { runDecrypt = originalRunDecrypt })

	for _, test := range mobilePCV3ClaimedCases(t) {
		t.Run(test.name, func(t *testing.T) {
			resetProgressMap()
			input := writeMobilePCV3Input(t, "claimed-without-pcv-extension.bin", test.data)
			output := filepath.Join(t.TempDir(), "must-not-exist")
			operationID := StartOperation()
			password := []byte("must-be-zeroed")
			request, err := json.Marshal(DecryptRequestJSON{
				OperationID:  operationID,
				InputFile:    input,
				OutputFile:   "",
				Keyfiles:     []string{"must-not-be-read.key"},
				ForceDecrypt: true,
				Deniability:  true,
			})
			if err != nil {
				t.Fatal(err)
			}

			if got := StartDecrypt(string(request), password); got != test.code {
				t.Fatalf("StartDecrypt(claimed PCV3) = %q; want exact %q", got, test.code)
			}
			for index, value := range password {
				if value != 0 {
					t.Fatalf("password[%d] = %d; claimed rejection must zero caller bytes", index, value)
				}
			}
			if decryptCalls != 0 {
				t.Fatalf("legacy decrypt/KDF path called %d times; want zero", decryptCalls)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("claimed rejection created output %q: %v", output, err)
			}

			globalProgressMap.mu.RLock()
			_, operationExists := globalProgressMap.ops[operationID]
			_, contextExists := globalProgressMap.ctxs[operationID]
			_, cancelExists := globalProgressMap.cancels[operationID]
			globalProgressMap.mu.RUnlock()
			if operationExists || contextExists || cancelExists {
				t.Fatalf("claimed rejection retained progress state: op=%v ctx=%v cancel=%v", operationExists, contextExists, cancelExists)
			}
		})
	}

	resetProgressMap()
	legacy := writeMobilePCV3Input(t, "legacy.pcv", []byte("legacy input"))
	operationID := StartOperation()
	request, err := json.Marshal(DecryptRequestJSON{
		OperationID: operationID,
		InputFile:   legacy,
		OutputFile:  filepath.Join(t.TempDir(), "legacy-output"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := StartDecrypt(string(request), []byte("legacy-password")); got != "" {
		t.Fatalf("StartDecrypt(legacy eligible) = %q; want existing async path", got)
	}
	state := waitForDone(t, operationID)
	if state.Status != "Completed" || decryptCalls != 1 {
		t.Fatalf("legacy path result = status %q, decrypt calls %d; want Completed/1", state.Status, decryptCalls)
	}
}
