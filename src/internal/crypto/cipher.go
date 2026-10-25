package crypto

import (
	"crypto/cipher"
	"errors"
	"hash"
	"io"

	"github.com/Picocrypt-NG/serpent"
	"golang.org/x/crypto/chacha20"
)

// zeroizer is implemented by cipher blocks that can wipe their expanded key
// schedule (e.g. the Picocrypt-NG/serpent fork's *subkeys.Zero()).
type zeroizer interface{ Zero() }

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
		// #nosec G407 -- serpentIV is derived from header, not hardcoded
		cs.serpent = cipher.NewCTR(s, serpentIV)
	}

	return cs, nil
}

// Encrypt processes a block of data for encryption.
// Order: [Serpent-CTR if paranoid] -> XChaCha20 -> MAC(ciphertext)
//
// CRITICAL: This exact order MUST be preserved.
//
// Aliasing contract:
//   - Paranoid mode: dst and src MUST NOT alias (share backing memory). The
//     implementation writes intermediate Serpent output to dst and then reads it
//     back via "copy(src, dst)" before the ChaCha20 pass; aliased buffers corrupt
//     the output silently.
//   - Non-paranoid mode: in-place operation (dst == src) is permitted and is
//     relied upon by the WASM frontend.
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
//
// Aliasing contract:
//   - Paranoid mode: dst and src MUST NOT alias (share backing memory). The
//     implementation writes ChaCha20 output to dst and then reads it back via
//     "copy(src, dst)" before the Serpent pass; aliased buffers corrupt the
//     output silently.
//   - Non-paranoid mode: in-place operation (dst == src) is permitted and is
//     relied upon by the WASM frontend.
func (cs *CipherSuite) Decrypt(dst, src []byte) {
	// Accumulate the ciphertext MAC before decrypting; callers verify the final tag.
	cs.mac.Write(src)

	cs.chacha.XORKeyStream(dst, src)

	if cs.paranoid {
		copy(src, dst) // chacha output becomes serpent input
		cs.serpent.XORKeyStream(dst, src)
	}
}

// Rekey reinitializes the ciphers; callers must invoke it every 60 GiB.
// The HKDF stream supplies a 24-byte nonce, then a 16-byte IV only in Paranoid mode.
func (cs *CipherSuite) Rekey() error {
	// Read new nonce for XChaCha20
	nonce := make([]byte, RekeyNonceSize)
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
		serpentIV := make([]byte, RekeyIVSize)
		if _, err := io.ReadFull(cs.hkdf, serpentIV); err != nil {
			return errors.New("fatal hkdf.Read error during rekey (serpent IV)")
		}
		// #nosec G407 -- serpentIV is derived from HKDF, not hardcoded
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

// Close zeros the retained []byte key and drops cipher/MAC references.
//
// SECURITY — scope of zeroing: only the retained []byte key (cs.key) is wiped.
// The expanded key schedules held inside *chacha20.Cipher ([8]uint32 + HChaCha20
// subkey) and the BLAKE2b/HMAC internal key state cannot be reached from here and
// are an accepted residual (see threat model). The Serpent schedule IS wiped when
// the serpent block exposes Zero() (see Rekey/NewCipherSuite). Calling Reset() on
// the keyed MAC would RE-INSTALL its key, not clear it, so it is intentionally not
// called.
func (cs *CipherSuite) Close() {
	if cs == nil {
		return
	}
	SecureZero(cs.key)
	cs.key = nil
	cs.chacha = nil
	if z, ok := cs.serpentS.(zeroizer); ok {
		z.Zero()
	}
	cs.serpent = nil
	cs.serpentS = nil
	cs.mac = nil
}
