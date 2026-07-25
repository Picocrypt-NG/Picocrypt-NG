package wasm

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
	"testing"
)

func TestDecryptVolumeRejectsUnsupportedMajorBeforeKDF(t *testing.T) {
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

	previous := deriveWASMKey
	deriveCalls := 0
	deriveWASMKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		deriveCalls++
		return bytes.Repeat([]byte{0x55}, 32), nil
	}
	t.Cleanup(func() {
		deriveWASMKey = previous
	})

	_, code := DecryptVolume(volumeBytes.Bytes(), []byte("irrelevant"), DecryptOptions{})
	if code != ErrUnsupported {
		t.Fatalf("DecryptVolume() code = %d; want ErrUnsupported (%d)", code, ErrUnsupported)
	}
	if deriveCalls != 0 {
		t.Fatalf("deriveWASMKey calls = %d; unsupported major must fail before KDF", deriveCalls)
	}
}
