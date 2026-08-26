package wasm

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"testing"
)

func TestDecryptVolumePCV3UnsupportedBeforeKDF(t *testing.T) {
	previous := deriveWASMKey
	deriveCalls := 0
	deriveWASMKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		deriveCalls++
		return bytes.Repeat([]byte{0x55}, 32), nil
	}
	t.Cleanup(func() {
		deriveWASMKey = previous
	})

	malformedClaimed := bytes.Repeat([]byte{0xa5}, 1024)
	copy(malformedClaimed, []byte{'P', 'C', 'V', 0})

	claimed := []struct {
		name     string
		volume   []byte
		password []byte
		opts     DecryptOptions
	}{
		{
			name:     "literal prefix without later fields",
			volume:   []byte{'P', 'C', 'V', 0},
			password: []byte("irrelevant"),
			opts: DecryptOptions{
				Keyfiles: [][]byte{[]byte("misleading keyfile")},
			},
		},
		{
			name:     "hostile trailing bytes with force",
			volume:   malformedClaimed,
			password: []byte("irrelevant"),
			opts: DecryptOptions{
				Keyfiles: [][]byte{[]byte("misleading keyfile")},
				Force:    true,
			},
		},
	}

	for _, tc := range claimed {
		t.Run(tc.name, func(t *testing.T) {
			result, code := DecryptVolume(tc.volume, tc.password, tc.opts)
			if code != ErrUnsupported {
				t.Fatalf("DecryptVolume() code = %d; want ErrUnsupported (%d)", code, ErrUnsupported)
			}
			if result.Plaintext != nil || result.Comments != "" || result.Kept {
				t.Fatalf("DecryptVolume() result = %#v; want zero value", result)
			}
		})
	}

	if deriveCalls != 0 {
		t.Fatalf("deriveWASMKey calls = %d; claimed PCV3 input must fail before deniability KDF", deriveCalls)
	}

	for _, volume := range [][]byte{
		{'P', 'C', 'V'},
		{'P', 'C', 'X', 0},
	} {
		result, code := DecryptVolume(volume, nil, DecryptOptions{})
		if code != ErrCorruptedHeader {
			t.Fatalf("DecryptVolume(%q) code = %d; want legacy ErrCorruptedHeader (%d)", volume, code, ErrCorruptedHeader)
		}
		if result.Plaintext != nil || result.Comments != "" || result.Kept {
			t.Fatalf("DecryptVolume(%q) result = %#v; want zero value", volume, result)
		}
	}
}

// Explicit PCV3 operation intent is terminal before the volume bytes are
// inspected or any key is derived. The volume below is random-looking (D1
// style), so any content-based handling would report ErrCorruptedHeader
// instead; the closed pcv3operation.Mode discriminator alone must select the
// same stable unsupported result the bridge returns.
func TestExplicitPCV3IntentUnsupportedBeforeData(t *testing.T) {
	previous := deriveWASMKey
	deriveCalls := 0
	deriveWASMKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		deriveCalls++
		return bytes.Repeat([]byte{0x55}, 32), nil
	}
	t.Cleanup(func() {
		deriveWASMKey = previous
	})

	randomLooking := make([]byte, 1024)
	for i := range randomLooking {
		randomLooking[i] = byte(i*31 + 7)
	}

	modes := []struct {
		name string
		mode pcv3operation.Mode
	}{
		{"read normal", pcv3operation.ModeReadNormal},
		{"read d1", pcv3operation.ModeReadD1},
		{"recover normal", pcv3operation.ModeRecoverNormal},
		{"recover d1", pcv3operation.ModeRecoverD1},
		{"force normal", pcv3operation.ModeForceNormal},
		{"force d1", pcv3operation.ModeForceD1},
		{"force unverified normal", pcv3operation.ModeForceUnverifiedNormal},
		{"force unverified d1", pcv3operation.ModeForceUnverifiedD1},
		{"migrate", pcv3operation.ModeMigrate},
		{"outside the closed registry", pcv3operation.Mode(255)},
	}

	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			result, code := DecryptVolume(randomLooking, []byte("irrelevant"), DecryptOptions{
				PCV3Mode: tc.mode,
				Keyfiles: [][]byte{[]byte("misleading keyfile")},
				Force:    true,
			})
			if code != ErrUnsupported {
				t.Fatalf("DecryptVolume() code = %d; want ErrUnsupported (%d)", code, ErrUnsupported)
			}
			if result.Plaintext != nil || result.Comments != "" || result.Kept {
				t.Fatalf("DecryptVolume() result = %#v; want zero value", result)
			}
		})
	}

	if deriveCalls != 0 {
		t.Fatalf("deriveWASMKey calls = %d; explicit PCV3 intent must fail before any derivation", deriveCalls)
	}
}
