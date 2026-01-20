package crypto

import (
	"Picocrypt-NG/internal/util"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/sha3"
)

// RekeyThreshold is the number of bytes after which rekeying must occur.
// This prevents nonce overflow in XChaCha20.
const RekeyThreshold = 60 * util.GiB

// Counter tracks bytes processed and triggers rekeying at the threshold.
type Counter struct {
	count     int64
	threshold int64
}

// NewCounter creates a new byte counter with the standard 60 GiB threshold.
func NewCounter() *Counter {
	return &Counter{
		count:     0,
		threshold: RekeyThreshold,
	}
}

// Add increments the counter by n bytes.
// Returns true if rekeying is required (threshold reached).
func (c *Counter) Add(n int) bool {
	c.count += int64(n)
	return c.count >= c.threshold
}

// Reset resets the counter to zero (after rekeying).
func (c *Counter) Reset() {
	c.count = 0
}

// Count returns the current byte count.
func (c *Counter) Count() int64 {
	return c.count
}

// DeniabilityRekey computes new nonce for deniability layer rekeying.
// Unlike regular rekeying which uses HKDF, deniability uses SHA3-256(nonce).
//
// CRITICAL: Deniability rekeying is DIFFERENT from regular rekeying!
// Regular: nonce from HKDF stream
// Deniability: nonce = SHA3-256(old_nonce)[:24]
func DeniabilityRekey(key, oldNonce []byte) (*chacha20.Cipher, []byte, error) {
	h := sha3.New256()
	h.Write(oldNonce)
	newNonce := h.Sum(nil)[:24]

	cipher, err := chacha20.NewUnauthenticatedCipher(key, newNonce)
	if err != nil {
		return nil, nil, err
	}

	return cipher, newNonce, nil
}
