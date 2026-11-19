package volume

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyDeniabilityWriterPublishesOnlyAfterOuterAdmission(t *testing.T) {
	parent := t.TempDir()
	input := filepath.Join(parent, "input")
	output := filepath.Join(parent, "output")
	payload := []byte("legacy deniability publication test")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := admitLegacyKDF
	t.Cleanup(func() { admitLegacyKDF = previous })
	admissions := 0
	admitLegacyKDF = func(context.Context) error {
		admissions++
		if admissions == 2 {
			return pcv3operation.ErrLegacyKDFResource
		}
		return nil
	}
	request := &EncryptRequest{
		InputFile: input, OutputFile: output, Password: []byte("test"), Deniability: true,
		Reporter: &GoldenTestReporter{}, RSCodecs: newRSCodecsT(t),
	}
	if err := Encrypt(t.Context(), request); !errors.Is(err, pcv3operation.ErrLegacyKDFResource) || admissions != 2 {
		t.Fatalf("outer admission returned %v after %d admissions", err, admissions)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != "input" {
		t.Fatalf("denied wrapper left an inner volume or stage: %v", err)
	}

	admitLegacyKDF = previous
	if err := Encrypt(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	decrypted := filepath.Join(parent, "decrypted")
	if err := Decrypt(t.Context(), &DecryptRequest{
		InputFile: output, OutputFile: decrypted, Password: []byte("test"), Deniability: true,
		Reporter: &GoldenTestReporter{}, RSCodecs: request.RSCodecs,
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(decrypted); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("deniable round trip did not preserve the input: %v", err)
	}
}

func TestLegacyDecryptResourceRefusalLeavesNoOutput(t *testing.T) {
	for _, fixture := range []struct {
		name        string
		deniability bool
	}{
		{"pico_test_v2.txt.pcv", false},
		{"pico_test_v2_keyfile_only_deniable.pcv", true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			parent := t.TempDir()
			input := filepath.Join(parent, "input.pcv")
			frozen, err := os.ReadFile(filepath.Join(findTestdata(t), fixture.name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(input, frozen, 0o600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			restore := useTestKDF(
				func([]byte, []byte, bool) ([]byte, error) { calls++; return nil, nil },
				func([]byte, []byte) []byte { calls++; return nil },
			)
			t.Cleanup(restore)
			old := admitLegacyKDF
			admitLegacyKDF = func(context.Context) error { return pcv3operation.ErrLegacyKDFResource }
			t.Cleanup(func() { admitLegacyKDF = old })

			err = Decrypt(t.Context(), &DecryptRequest{
				InputFile:   input,
				OutputFile:  filepath.Join(parent, "out"),
				Password:    []byte("test-password"),
				Deniability: fixture.deniability,
				Reporter:    &GoldenTestReporter{},
				RSCodecs:    newRSCodecsT(t),
			})
			if !errors.Is(err, pcv3operation.ErrLegacyKDFResource) || calls != 0 {
				t.Fatalf("resource refusal = %v, KDF calls = %d", err, calls)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 || entries[0].Name() != "input.pcv" {
				t.Fatalf("resource refusal left output or lost input: %v", err)
			}
		})
	}
}
