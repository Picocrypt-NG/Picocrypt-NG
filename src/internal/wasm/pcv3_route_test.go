package wasm

import (
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
