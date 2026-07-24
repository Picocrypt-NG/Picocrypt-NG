package wasm

import (
	cryptorand "crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

type countingZeroReader struct {
	reads int
}

func (r *countingZeroReader) Read(p []byte) (int, error) {
	r.reads++
	clear(p)
	return len(p), nil
}

func TestEncryptVolumeRejectsAllNewV2KeyfileWritesBeforeRandomness(t *testing.T) {
	originalReader := cryptorand.Reader
	reader := &countingZeroReader{}
	cryptorand.Reader = reader
	t.Cleanup(func() {
		cryptorand.Reader = originalReader
	})

	for _, tc := range []struct {
		name     string
		password []byte
	}{
		{name: "keyfile only", password: nil},
		{name: "password and keyfile", password: []byte("secret")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, code := EncryptVolume(
				[]byte("plaintext must not be encrypted"),
				tc.password,
				EncryptOptions{Keyfiles: [][]byte{[]byte("keyfile material")}},
			)

			const keyfileWritesDisabled = 12
			if code != keyfileWritesDisabled {
				t.Errorf("EncryptVolume error code = %d; want keyfile-writes-disabled code %d", code, keyfileWritesDisabled)
			}
			if ciphertext != nil {
				t.Errorf("EncryptVolume returned %d ciphertext bytes; want none", len(ciphertext))
			}
		})
	}
	if reader.reads != 0 {
		t.Errorf("crypto/rand reads = %d; keyfile writer policy must fail before generating volume material", reader.reads)
	}
}

// The direct in-memory writer still needs the independent P-02 guard when no
// keyfiles are present: the outer wrapper must never derive from an empty input.
func TestEncryptVolumeRejectsPasswordlessDeniabilityBeforeRandomness(t *testing.T) {
	originalReader := cryptorand.Reader
	reader := &countingZeroReader{}
	cryptorand.Reader = reader
	t.Cleanup(func() {
		cryptorand.Reader = originalReader
	})

	ciphertext, code := EncryptVolume(
		[]byte("plaintext must not be encrypted"),
		nil,
		EncryptOptions{Deniability: true},
	)
	const deniabilityPasswordRequired = 11
	if code != deniabilityPasswordRequired {
		t.Errorf("EncryptVolume error code = %d; want deniability-password-required code %d", code, deniabilityPasswordRequired)
	}
	if ciphertext != nil {
		t.Errorf("EncryptVolume returned %d ciphertext bytes; want none", len(ciphertext))
	}
	if reader.reads != 0 {
		t.Errorf("crypto/rand reads = %d; unsafe wrapper must fail before generating volume material", reader.reads)
	}
}

func TestEncryptVolumeRejectsEmptyPasswordBeforeRandomness(t *testing.T) {
	originalReader := cryptorand.Reader
	reader := &countingZeroReader{}
	cryptorand.Reader = reader
	t.Cleanup(func() {
		cryptorand.Reader = originalReader
	})

	ciphertext, code := EncryptVolume(
		[]byte("plaintext must not be encrypted"),
		nil,
		EncryptOptions{},
	)
	const encryptionPasswordRequired = 13
	if code != encryptionPasswordRequired {
		t.Errorf("EncryptVolume error code = %d; want encryption-password-required code %d", code, encryptionPasswordRequired)
	}
	if ciphertext != nil {
		t.Errorf("EncryptVolume returned %d ciphertext bytes; want none", len(ciphertext))
	}
	if reader.reads != 0 {
		t.Errorf("crypto/rand reads = %d; missing credential must fail before generating volume material", reader.reads)
	}
}

func TestDecryptVolumeReadsLegacyKeyfileOnlyVolume(t *testing.T) {
	useProductionTestWASMKDF(t)

	testdata := filepath.Join("..", "..", "testdata", "golden")
	volumeData, err := os.ReadFile(filepath.Join(testdata, "pico_test_v2_keyfile_only.txt.pcv"))
	if err != nil {
		t.Fatalf("read legacy keyfile-only fixture: %v", err)
	}
	keyfileData, err := os.ReadFile(filepath.Join(testdata, "keyfile_alpha.bin"))
	if err != nil {
		t.Fatalf("read legacy fixture keyfile: %v", err)
	}

	result, code := DecryptVolume(
		volumeData,
		nil,
		DecryptOptions{Keyfiles: [][]byte{keyfileData}},
	)
	if code != 0 {
		t.Fatalf("DecryptVolume legacy fixture error code = %d; want 0", code)
	}
	const expected = "There is a test file for Picocrypt validation.\n"
	if string(result.Plaintext) != expected {
		t.Fatalf("DecryptVolume legacy fixture plaintext = %q; want %q", result.Plaintext, expected)
	}
	if _, missingCode := DecryptVolume(volumeData, nil, DecryptOptions{}); missingCode != ErrKeyfilesRequired {
		t.Fatalf(
			"DecryptVolume legacy fixture without keyfile error code = %d; want %d",
			missingCode,
			ErrKeyfilesRequired,
		)
	}
	if _, wrongCode := DecryptVolume(
		volumeData,
		nil,
		DecryptOptions{Keyfiles: [][]byte{[]byte("wrong keyfile")}},
	); wrongCode != ErrKeyfilesIncorrect {
		t.Fatalf(
			"DecryptVolume legacy fixture with wrong keyfile error code = %d; want %d",
			wrongCode,
			ErrKeyfilesIncorrect,
		)
	}
}

// The writer restriction must not strand volumes produced before 2.19. This
// uses the frozen production-format fixture rather than recreating the unsafe
// wrapper with the current writer.
func TestDecryptVolumeReadsLegacyKeyfileOnlyDeniability(t *testing.T) {
	useProductionTestWASMKDF(t)

	testdata := filepath.Join("..", "..", "testdata", "golden")
	volumeData, err := os.ReadFile(filepath.Join(testdata, "pico_test_v2_keyfile_only_deniable.pcv"))
	if err != nil {
		t.Fatalf("read legacy deniable fixture: %v", err)
	}
	keyfileData, err := os.ReadFile(filepath.Join(testdata, "keyfile_alpha.bin"))
	if err != nil {
		t.Fatalf("read legacy fixture keyfile: %v", err)
	}

	result, code := DecryptVolume(
		volumeData,
		nil,
		DecryptOptions{Keyfiles: [][]byte{keyfileData}},
	)
	if code != 0 {
		t.Fatalf("DecryptVolume legacy fixture error code = %d; want 0", code)
	}
	const expected = "There is a test file for Picocrypt validation.\n"
	if string(result.Plaintext) != expected {
		t.Fatalf("DecryptVolume legacy fixture plaintext = %q; want %q", result.Plaintext, expected)
	}
	if _, missingCode := DecryptVolume(volumeData, nil, DecryptOptions{}); missingCode != ErrKeyfilesRequired {
		t.Fatalf(
			"DecryptVolume legacy deniable fixture without keyfile error code = %d; want %d",
			missingCode,
			ErrKeyfilesRequired,
		)
	}
}
