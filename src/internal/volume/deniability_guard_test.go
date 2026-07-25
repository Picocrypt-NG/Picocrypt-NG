package volume

import (
	"Picocrypt-NG/internal/crypto"
	perrors "Picocrypt-NG/internal/errors"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func assertDeniabilityPasswordRequired(t *testing.T, err error) {
	t.Helper()

	var validationErr *perrors.ValidationError
	if !perrors.As(err, &validationErr) {
		t.Errorf("error = %v, want *errors.ValidationError", err)
		return
	}
	if got, want := validationErr.Field, "Password"; got != want {
		t.Errorf("ValidationError.Field = %q, want %q", got, want)
	}
	if got, want := validationErr.Message, "a non-empty password is required for deniability"; got != want {
		t.Errorf("ValidationError.Message = %q, want %q", got, want)
	}
	if got, want := err.Error(), "validation: Password: a non-empty password is required for deniability"; got != want {
		t.Errorf("error text = %q, want %q", got, want)
	}
}

func TestAddDeniabilityRejectsEmptyPasswordBeforeKDFAndPreservesVolume(t *testing.T) {
	volumePath := filepath.Join(t.TempDir(), "existing.pcv")
	original, err := os.ReadFile(filepath.Join(findTestdata(t), "pico_test_v2_keyfile_only.txt.pcv"))
	if err != nil {
		t.Fatalf("read source volume: %v", err)
	}
	if err := os.WriteFile(volumePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(volumePath)
	if err != nil {
		t.Fatal(err)
	}

	var deriveCalls int
	previousDeniabilityKey := deriveDeniabilityKey
	deriveDeniabilityKey = func(password, salt []byte) []byte {
		deriveCalls++
		return make([]byte, crypto.Argon2KeySize)
	}
	defer func() { deriveDeniabilityKey = previousDeniabilityKey }()

	err = AddDeniability(volumePath, nil, nil)
	assertDeniabilityPasswordRequired(t, err)

	if deriveCalls != 0 {
		t.Errorf("deriveDeniabilityKey called %d times, want 0", deriveCalls)
	}
	after, readErr := os.ReadFile(volumePath)
	if readErr != nil {
		t.Fatalf("read volume after rejected AddDeniability: %v", readErr)
	}
	if !bytes.Equal(after, original) {
		t.Errorf("rejected AddDeniability changed volume bytes:\n got: %x\nwant: %x", after, original)
	}
	afterInfo, statErr := os.Stat(volumePath)
	if statErr != nil {
		t.Fatalf("stat volume after rejected AddDeniability: %v", statErr)
	}
	if !os.SameFile(beforeInfo, afterInfo) {
		t.Error("rejected AddDeniability replaced the original file identity")
	}
}
