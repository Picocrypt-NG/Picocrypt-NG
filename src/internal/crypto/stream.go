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
	if len(destination) != len(source) ||
		len(xChaChaKey) != pcv3StreamKeySize || len(nonce) != pcv3XChaChaNonceSize ||
		len(serpentKey) != pcv3StreamKeySize || len(serpentIV) != pcv3SerpentIVSize {
		return ErrPCV3StreamShape
	}
	xChaCha, err := chacha20.NewUnauthenticatedCipher(xChaChaKey, nonce)
	if err != nil {
		return ErrPCV3StreamShape
	}
	serpentBlock, err := serpent.NewCipher(serpentKey)
	if err != nil {
		return ErrPCV3StreamShape
	}
	if wipe, ok := serpentBlock.(zeroizer); ok {
		defer wipe.Zero()
	}

	intermediate := append([]byte(nil), source...)
	defer SecureZero(intermediate)
	xChaCha.XORKeyStream(intermediate, intermediate)
	// #nosec G407 -- the caller supplies the independently authenticated PCV3 capsule IV.
	cipher.NewCTR(serpentBlock, serpentIV).XORKeyStream(destination, intermediate)
	return nil
}
