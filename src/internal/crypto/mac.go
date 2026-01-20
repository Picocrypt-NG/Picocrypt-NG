package crypto

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// NewMAC creates a new MAC hash for payload authentication.
// If paranoid is true, uses HMAC-SHA3-512.
// Otherwise, uses keyed BLAKE2b-512.
//
// The subkey should be derived from HKDF (32 bytes).
func NewMAC(subkey []byte, paranoid bool) (hash.Hash, error) {
	if paranoid {
		return hmac.New(sha3.New512, subkey), nil
	}

	mac, err := blake2b.New512(subkey)
	if err != nil {
		return nil, err
	}
	return mac, nil
}

// MACSize returns the output size of the MAC (64 bytes for both modes).
const MACSize = 64
