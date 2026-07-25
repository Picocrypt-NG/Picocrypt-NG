package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDecryptRejectsUnsupportedMajorBeforeKDFEvenWithForce(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	h := header.NewVolumeHeader(
		bytes.Repeat([]byte{0x11}, header.SaltSize),
		bytes.Repeat([]byte{0x22}, header.HKDFSaltSize),
		bytes.Repeat([]byte{0x33}, header.SerpentIVSize),
		bytes.Repeat([]byte{0x44}, header.NonceSize),
	)
	h.Version = "v3.11"

	var volumeBytes bytes.Buffer
	if _, err := header.NewWriter(&volumeBytes, rsCodecs).WriteHeader(h); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	dir := t.TempDir()
	input := filepath.Join(dir, "future.pcv")
	output := filepath.Join(dir, "plaintext")
	if err := os.WriteFile(input, volumeBytes.Bytes(), 0o600); err != nil {
		t.Fatalf("write future volume: %v", err)
	}

	previousVolumeKey := deriveVolumeKey
	deriveCalls := 0
	deriveVolumeKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		deriveCalls++
		return previousVolumeKey(password, salt, paranoid)
	}
	t.Cleanup(func() {
		deriveVolumeKey = previousVolumeKey
	})

	err = Decrypt(t.Context(), &DecryptRequest{
		InputFile:    input,
		OutputFile:   output,
		Password:     []byte("irrelevant"),
		ForceDecrypt: true,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	})
	if !errors.Is(err, header.ErrUnsupportedVersion) {
		t.Fatalf("Decrypt() error = %v; want errors.Is(header.ErrUnsupportedVersion)", err)
	}
	if deriveCalls != 0 {
		t.Fatalf("deriveVolumeKey calls = %d; unsupported major must fail before KDF", deriveCalls)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("unsupported volume created output %q: %v", output, statErr)
	}
}
