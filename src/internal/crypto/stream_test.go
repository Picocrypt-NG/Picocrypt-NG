package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

const (
	pcv3StreamVolumeKey = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"

	pcv3StreamStandardXKey    = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	pcv3StreamStandardNonce   = "303132333435363738393a3b3c3d3e3f4041424344454647"
	pcv3StreamStandardWrapped = "6b9af1ebed69787d3e4a26f0146dcc5f8dfe1afa505a19ba6e701c1d8ea386d3"

	pcv3StreamParanoidXKey       = "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"
	pcv3StreamParanoidNonce      = "707172737475767778797a7b7c7d7e7f8081828384858687"
	pcv3StreamParanoidSerpentKey = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	pcv3StreamParanoidIV         = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	pcv3StreamParanoidWrapped    = "b0271fd6126c77c6434caee19f48e8600008468174530e09b7283fed1287ac4d"
)

func TestPCV3StreamStandard1MatchesIndependentWrapVector(t *testing.T) {
	destination := make([]byte, 32)
	err := PCV3UnwrapStandard1(
		destination,
		mustPCV3StreamHex(t, pcv3StreamStandardWrapped),
		mustPCV3StreamHex(t, pcv3StreamStandardXKey),
		mustPCV3StreamHex(t, pcv3StreamStandardNonce),
	)
	if err != nil {
		t.Fatalf("PCV3UnwrapStandard1() error = %v", err)
	}
	if want := mustPCV3StreamHex(t, pcv3StreamVolumeKey); !bytes.Equal(destination, want) {
		t.Fatalf("PCV3UnwrapStandard1() = %x, want independent VolumeKey %x", destination, want)
	}
}

func TestPCV3StreamParanoid1MatchesIndependentWrapVector(t *testing.T) {
	destination := make([]byte, 32)
	err := PCV3UnwrapParanoid1(
		destination,
		mustPCV3StreamHex(t, pcv3StreamParanoidWrapped),
		mustPCV3StreamHex(t, pcv3StreamParanoidXKey),
		mustPCV3StreamHex(t, pcv3StreamParanoidNonce),
		mustPCV3StreamHex(t, pcv3StreamParanoidSerpentKey),
		mustPCV3StreamHex(t, pcv3StreamParanoidIV),
	)
	if err != nil {
		t.Fatalf("PCV3UnwrapParanoid1() error = %v", err)
	}
	if want := mustPCV3StreamHex(t, pcv3StreamVolumeKey); !bytes.Equal(destination, want) {
		t.Fatalf("PCV3UnwrapParanoid1() = %x, want independent VolumeKey %x", destination, want)
	}
}

func TestPCV3StreamParanoid1RejectsWrongParameters(t *testing.T) {
	want := mustPCV3StreamHex(t, pcv3StreamVolumeKey)
	tests := []struct {
		name       string
		xKey       []byte
		nonce      []byte
		serpentKey []byte
		iv         []byte
	}{
		{name: "XChaCha20 key", xKey: changedPCV3StreamValue(t, pcv3StreamParanoidXKey), nonce: mustPCV3StreamHex(t, pcv3StreamParanoidNonce), serpentKey: mustPCV3StreamHex(t, pcv3StreamParanoidSerpentKey), iv: mustPCV3StreamHex(t, pcv3StreamParanoidIV)},
		{name: "XChaCha20 nonce", xKey: mustPCV3StreamHex(t, pcv3StreamParanoidXKey), nonce: changedPCV3StreamValue(t, pcv3StreamParanoidNonce), serpentKey: mustPCV3StreamHex(t, pcv3StreamParanoidSerpentKey), iv: mustPCV3StreamHex(t, pcv3StreamParanoidIV)},
		{name: "Serpent key", xKey: mustPCV3StreamHex(t, pcv3StreamParanoidXKey), nonce: mustPCV3StreamHex(t, pcv3StreamParanoidNonce), serpentKey: changedPCV3StreamValue(t, pcv3StreamParanoidSerpentKey), iv: mustPCV3StreamHex(t, pcv3StreamParanoidIV)},
		{name: "Serpent IV", xKey: mustPCV3StreamHex(t, pcv3StreamParanoidXKey), nonce: mustPCV3StreamHex(t, pcv3StreamParanoidNonce), serpentKey: mustPCV3StreamHex(t, pcv3StreamParanoidSerpentKey), iv: changedPCV3StreamValue(t, pcv3StreamParanoidIV)},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			destination := make([]byte, 32)
			err := PCV3UnwrapParanoid1(destination, mustPCV3StreamHex(t, pcv3StreamParanoidWrapped), testCase.xKey, testCase.nonce, testCase.serpentKey, testCase.iv)
			if err != nil {
				t.Fatalf("PCV3UnwrapParanoid1() error = %v", err)
			}
			if bytes.Equal(destination, want) {
				t.Fatal("wrong stream parameter reproduced the independent VolumeKey")
			}
		})
	}
}

func TestPCV3StreamSupportsExactAndPartialOverlap(t *testing.T) {
	want := mustPCV3StreamHex(t, pcv3StreamVolumeKey)
	inPlace := mustPCV3StreamHex(t, pcv3StreamStandardWrapped)
	if err := PCV3UnwrapStandard1(inPlace, inPlace, mustPCV3StreamHex(t, pcv3StreamStandardXKey), mustPCV3StreamHex(t, pcv3StreamStandardNonce)); err != nil {
		t.Fatalf("PCV3UnwrapStandard1(in-place) error = %v", err)
	}
	if !bytes.Equal(inPlace, want) {
		t.Fatalf("in-place unwrap = %x, want %x", inPlace, want)
	}

	backing := make([]byte, 33)
	copy(backing, mustPCV3StreamHex(t, pcv3StreamParanoidWrapped))
	source, destination := backing[:32], backing[1:]
	if err := PCV3UnwrapParanoid1(destination, source, mustPCV3StreamHex(t, pcv3StreamParanoidXKey), mustPCV3StreamHex(t, pcv3StreamParanoidNonce), mustPCV3StreamHex(t, pcv3StreamParanoidSerpentKey), mustPCV3StreamHex(t, pcv3StreamParanoidIV)); err != nil {
		t.Fatalf("PCV3UnwrapParanoid1(partial overlap) error = %v", err)
	}
	if !bytes.Equal(destination, want) {
		t.Fatalf("partial-overlap unwrap = %x, want %x", destination, want)
	}
}

func TestPCV3StreamInvalidShapesLeaveDestinationUnchanged(t *testing.T) {
	standardKey := mustPCV3StreamHex(t, pcv3StreamStandardXKey)
	standardNonce := mustPCV3StreamHex(t, pcv3StreamStandardNonce)
	paranoidKey := mustPCV3StreamHex(t, pcv3StreamParanoidXKey)
	paranoidNonce := mustPCV3StreamHex(t, pcv3StreamParanoidNonce)
	serpentKey := mustPCV3StreamHex(t, pcv3StreamParanoidSerpentKey)
	serpentIV := mustPCV3StreamHex(t, pcv3StreamParanoidIV)
	source := mustPCV3StreamHex(t, pcv3StreamStandardWrapped)
	tests := []struct {
		name string
		call func(destination []byte) error
	}{
		{name: "destination length", call: func(destination []byte) error {
			return PCV3UnwrapStandard1(destination[:31], source, standardKey, standardNonce)
		}},
		{name: "XChaCha20 key length", call: func(destination []byte) error {
			return PCV3UnwrapStandard1(destination, source, standardKey[:31], standardNonce)
		}},
		{name: "XChaCha20 nonce length", call: func(destination []byte) error {
			return PCV3UnwrapStandard1(destination, source, standardKey, standardNonce[:23])
		}},
		{name: "Paranoid XChaCha20 key length", call: func(destination []byte) error {
			return PCV3UnwrapParanoid1(destination, source, paranoidKey[:31], paranoidNonce, serpentKey, serpentIV)
		}},
		{name: "Paranoid nonce length", call: func(destination []byte) error {
			return PCV3UnwrapParanoid1(destination, source, paranoidKey, paranoidNonce[:23], serpentKey, serpentIV)
		}},
		{name: "Serpent key length", call: func(destination []byte) error {
			return PCV3UnwrapParanoid1(destination, source, paranoidKey, paranoidNonce, serpentKey[:31], serpentIV)
		}},
		{name: "Serpent IV length", call: func(destination []byte) error {
			return PCV3UnwrapParanoid1(destination, source, paranoidKey, paranoidNonce, serpentKey, serpentIV[:15])
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			destination := bytes.Repeat([]byte{0xa5}, 32)
			before := append([]byte(nil), destination...)
			err := testCase.call(destination)
			if !errors.Is(err, ErrPCV3StreamShape) {
				t.Fatalf("error = %v, want ErrPCV3StreamShape", err)
			}
			if !bytes.Equal(destination, before) {
				t.Fatalf("destination changed on invalid shape: got %x, want %x", destination, before)
			}
		})
	}
}

func mustPCV3StreamHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode TEST ONLY stream fixture: %v", err)
	}
	return decoded
}

func changedPCV3StreamValue(t *testing.T, value string) []byte {
	t.Helper()
	changed := mustPCV3StreamHex(t, value)
	changed[0] ^= 0x01
	return changed
}
