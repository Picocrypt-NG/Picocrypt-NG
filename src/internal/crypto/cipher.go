package crypto

import (
	"crypto/cipher"
	"errors"
	"hash"
	"io"

	"github.com/Picocrypt/serpent"
	"golang.org/x/crypto/chacha20"
)

// CipherSuite holds the initialized ciphers and MAC for encryption/decryption.
// This manages the XChaCha20 and optional Serpent-CTR ciphers.
type CipherSuite struct {
	chacha   *chacha20.Cipher
	serpent  cipher.Stream
	serpentS cipher.Block // Keep block cipher for rekeying
	mac      hash.Hash
	hkdf     io.Reader
	paranoid bool
	key      []byte // Keep for rekeying
}

// NewCipherSuite creates a new cipher suite with the given parameters.
//
// CRITICAL: Encryption order is Serpent-CTR -> XChaCha20 -> MAC
// CRITICAL: Decryption order is MAC -> XChaCha20 -> Serpent-CTR
func NewCipherSuite(key, nonce, serpentKey, serpentIV []byte, mac hash.Hash, hkdf io.Reader, paranoid bool) (*CipherSuite, error) {
	chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}

	cs := &CipherSuite{
		chacha:   chacha,
		mac:      mac,
		hkdf:     hkdf,
		paranoid: paranoid,
		key:      key,
	}

	if paranoid {
		s, err := serpent.NewCipher(serpentKey)
		if err != nil {
			return nil, err
		}
		cs.serpentS = s
		cs.serpent = cipher.NewCTR(s, serpentIV)
	}

	return cs, nil
}

// Encrypt processes a block of data for encryption.
// Order: [Serpent-CTR if paranoid] -> XChaCha20 -> MAC(ciphertext)
//
// CRITICAL: This exact order MUST be preserved.
func (cs *CipherSuite) Encrypt(dst, src []byte) {
	if cs.paranoid {
		cs.serpent.XORKeyStream(dst, src)
		copy(src, dst) // serpent output becomes chacha input
	}

	cs.chacha.XORKeyStream(dst, src)

	// MAC the ciphertext (encrypt-then-MAC)
	cs.mac.Write(dst)
}

// Decrypt processes a block of data for decryption.
// Order: MAC(ciphertext) -> XChaCha20 -> [Serpent-CTR if paranoid]
//
// CRITICAL: This exact order MUST be preserved.
func (cs *CipherSuite) Decrypt(dst, src []byte) {
	// MAC the ciphertext first (verify-then-decrypt)
	cs.mac.Write(src)

	cs.chacha.XORKeyStream(dst, src)

	if cs.paranoid {
		copy(src, dst) // chacha output becomes serpent input
		cs.serpent.XORKeyStream(dst, src)
	}
}

// Rekey reinitializes the ciphers with new nonce/IV from HKDF stream.
// This MUST be called every 60 GiB to prevent nonce overflow.
//
// CRITICAL: Rekeying reads from the same HKDF stream in order:
//  1. nonce (24 bytes) - for XChaCha20
//  2. serpentIV (16 bytes) - for Serpent-CTR
func (cs *CipherSuite) Rekey() error {
	// Read new nonce for XChaCha20
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(cs.hkdf, nonce); err != nil {
		return errors.New("fatal hkdf.Read error during rekey (nonce)")
	}

	chacha, err := chacha20.NewUnauthenticatedCipher(cs.key, nonce)
	if err != nil {
		return err
	}
	cs.chacha = chacha

	// Read new IV for Serpent (if paranoid)
	if cs.paranoid {
		serpentIV := make([]byte, 16)
		if _, err := io.ReadFull(cs.hkdf, serpentIV); err != nil {
			return errors.New("fatal hkdf.Read error during rekey (serpent IV)")
		}
		cs.serpent = cipher.NewCTR(cs.serpentS, serpentIV)
	}

	return nil
}

// MAC returns the accumulated MAC hash.
func (cs *CipherSuite) MAC() hash.Hash {
	return cs.mac
}

// Sum returns the final MAC value.
func (cs *CipherSuite) Sum() []byte {
	return cs.mac.Sum(nil)
}

// IsParanoid returns whether paranoid mode is enabled.
func (cs *CipherSuite) IsParanoid() bool {
	return cs.paranoid
}

// Close securely zeros all sensitive key material in the cipher suite.
// This should be called via defer immediately after creating the cipher suite.
//
// SECURITY: Always call Close() when done with the cipher suite to minimize
// the window during which key material is recoverable from memory.
func (cs *CipherSuite) Close() {
	if cs == nil {
		return
	}
	SecureZero(cs.key)
	cs.key = nil
	cs.chacha = nil
	cs.serpent = nil
	cs.serpentS = nil
	SecureZeroHash(cs.mac)
	cs.mac = nil
}
