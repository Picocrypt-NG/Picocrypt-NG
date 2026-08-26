package crypto

import (
	"crypto/cipher"
	"errors"

	"github.com/Picocrypt-NG/serpent"
	"golang.org/x/crypto/chacha20"
)

const (
	pcv3StreamKeySize    = 32
	pcv3XChaChaNonceSize = 24
	pcv3SerpentIVSize    = 16
)

// ErrPCV3StreamShape reports an invalid caller-owned buffer, key, nonce, or IV
// shape. The fixed error deliberately does not disclose supplied material.
var ErrPCV3StreamShape = errors.New("crypto: invalid PCV3 stream shape")

// PCV3UnwrapStandard1 applies the schema-1 Standard reader transform with a
// fresh counter-zero XChaCha20 instance. Source and destination must have equal
// lengths. Exact in-place and partial overlap are both supported: the source is
// copied before destination is modified.
func PCV3UnwrapStandard1(destination, source, key, nonce []byte) error {
	return pcv3XChaCha20(destination, source, key, nonce)
}

// PCV3WrapStandard1 applies the schema-1 Standard writer transform. XChaCha20
// is symmetric, so it deliberately shares the exact counter-zero primitive
// and overlap contract with PCV3UnwrapStandard1.
func PCV3WrapStandard1(destination, source, key, nonce []byte) error {
	return pcv3XChaCha20(destination, source, key, nonce)
}

func pcv3XChaCha20(destination, source, key, nonce []byte) error {
	if len(destination) != len(source) || len(key) != pcv3StreamKeySize || len(nonce) != pcv3XChaChaNonceSize {
		return ErrPCV3StreamShape
	}
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return ErrPCV3StreamShape
	}
	input := append([]byte(nil), source...)
	defer SecureZero(input)
	stream.XORKeyStream(destination, input)
	return nil
}

// PCV3UnwrapParanoid1 applies the schema-1 Paranoid reader transform in its
// normative XChaCha20-then-Serpent-CTR order. Both fresh streams start at
// counter zero. Source and destination have the same overlap contract as the
// Standard transform.
func PCV3UnwrapParanoid1(destination, source, xChaChaKey, nonce, serpentKey, serpentIV []byte) error {
	if !validPCV3ParanoidShape(destination, source, xChaChaKey, nonce, serpentKey, serpentIV) {
		return ErrPCV3StreamShape
	}

	intermediate := make([]byte, len(source))
	defer SecureZero(intermediate)
	if err := pcv3XChaCha20(intermediate, source, xChaChaKey, nonce); err != nil {
		return err
	}
	return pcv3SerpentCTR(destination, intermediate, serpentKey, serpentIV)
}

// PCV3WrapParanoid1 applies the schema-1 Paranoid writer transform in its
// normative Serpent-CTR-then-XChaCha20 order. The order is intentionally not
// shared with the reader transform.
func PCV3WrapParanoid1(destination, source, xChaChaKey, nonce, serpentKey, serpentIV []byte) error {
	if !validPCV3ParanoidShape(destination, source, xChaChaKey, nonce, serpentKey, serpentIV) {
		return ErrPCV3StreamShape
	}

	intermediate := make([]byte, len(source))
	defer SecureZero(intermediate)
	if err := pcv3SerpentCTR(intermediate, source, serpentKey, serpentIV); err != nil {
		return err
	}
	return pcv3XChaCha20(destination, intermediate, xChaChaKey, nonce)
}

func validPCV3ParanoidShape(destination, source, xChaChaKey, nonce, serpentKey, serpentIV []byte) bool {
	return len(destination) == len(source) &&
		len(xChaChaKey) == pcv3StreamKeySize && len(nonce) == pcv3XChaChaNonceSize &&
		len(serpentKey) == pcv3StreamKeySize && len(serpentIV) == pcv3SerpentIVSize
}

func pcv3SerpentCTR(destination, source, key, iv []byte) error {
	if len(destination) != len(source) || len(key) != pcv3StreamKeySize || len(iv) != pcv3SerpentIVSize {
		return ErrPCV3StreamShape
	}
	block, err := serpent.NewCipher(key)
	if err != nil {
		return ErrPCV3StreamShape
	}
	if wipe, ok := block.(zeroizer); ok {
		defer wipe.Zero()
	}
	input := append([]byte(nil), source...)
	defer SecureZero(input)
	// #nosec G407 -- the caller supplies the independently authenticated PCV3 capsule IV.
	cipher.NewCTR(block, iv).XORKeyStream(destination, input)
	return nil
}
