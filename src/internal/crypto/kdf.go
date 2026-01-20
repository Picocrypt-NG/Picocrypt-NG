// Package crypto provides cryptographic primitives for Picocrypt volumes.
// This is AUDIT-CRITICAL code - changes here directly affect encryption/decryption.
package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("fatal crypto/rand error: %w", err)
	}

	// Sanity check: bytes should not be all zeros
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("fatal crypto/rand error: produced zero bytes")
	}

	return b, nil
}

// Argon2 parameters
const (
	// Normal mode parameters
	Argon2NormalPasses  = 4
	Argon2NormalMemory  = 1 << 20 // 1 GiB
	Argon2NormalThreads = 4

	// Paranoid mode parameters
	Argon2ParanoidPasses  = 8
	Argon2ParanoidMemory  = 1 << 20 // 1 GiB
	Argon2ParanoidThreads = 8

	// Output key size
	Argon2KeySize = 32
)

// DeriveKey derives an encryption key from password and salt using Argon2id.
// If paranoid is true, uses stronger parameters (8 passes, 8 threads).
//
// CRITICAL: Parameters MUST NOT change or existing volumes cannot be decrypted.
func DeriveKey(password, salt []byte, paranoid bool) ([]byte, error) {
	var key []byte

	if paranoid {
		key = argon2.IDKey(
			password,
			salt,
			Argon2ParanoidPasses,
			Argon2ParanoidMemory,
			Argon2ParanoidThreads,
			Argon2KeySize,
		)
	} else {
		key = argon2.IDKey(
			password,
			salt,
			Argon2NormalPasses,
			Argon2NormalMemory,
			Argon2NormalThreads,
			Argon2KeySize,
		)
	}

	// Sanity check: key should not be all zeros
	if bytes.Equal(key, make([]byte, Argon2KeySize)) {
		return nil, errors.New("fatal crypto/argon2 error: produced zero key")
	}

	return key, nil
}

// HKDF subkey sizes
const (
	SubkeyHeaderSize  = 64 // For v2 header HMAC
	SubkeyMACSize     = 32 // For payload MAC
	SubkeySerpentSize = 32 // For Serpent key
	RekeyNonceSize    = 24 // XChaCha20 nonce for rekeying
	RekeyIVSize       = 16 // Serpent IV for rekeying
)

// SubkeyReader provides sequential reading of subkeys from an HKDF stream.
// It tracks which subkeys have been consumed to prevent misuse.
//
// CRITICAL INVARIANT: v1 vs v2 HKDF Differences
//
// There are TWO key differences between v1.x and v2.00+ formats:
//
// DIFFERENCE 1: HKDF Initialization Timing (relative to keyfile XOR)
//
// v1.x (original Picocrypt):
//  1. key = Argon2(password, salt)
//  2. key = key XOR keyfileKey              <- XOR FIRST
//  3. hkdf = HKDF-SHA3-256(key, hkdfSalt)   <- HKDF with XORed key
//
// v2.00+ (Picocrypt-NG):
//  1. key = Argon2(password, salt)
//  2. hkdf = HKDF-SHA3-256(key, hkdfSalt)   <- HKDF FIRST (before XOR)
//  3. key = key XOR keyfileKey              <- XOR affects XChaCha only
//
// DIFFERENCE 2: Subkey Read Order from HKDF Stream
//
// v1.x subkey order:
//
//	Byte 0-31:  MAC subkey (32 bytes)
//	Byte 32-63: Serpent key (32 bytes)
//	Byte 64+:   Rekey values (nonce 24 + IV 16 per cycle)
//
// v2.00+ subkey order:
//
//	Byte 0-63:   Header subkey (64 bytes) <- NEW: for HMAC-SHA3-512 header MAC
//	Byte 64-95:  MAC subkey (32 bytes)
//	Byte 96-127: Serpent key (32 bytes)
//	Byte 128+:   Rekey values (nonce 24 + IV 16 per cycle)
//
// Violating either of these orders = inability to decrypt volumes of that version.
//
// Code locations:
//   - v1 path: volume/decrypt.go:decryptVerifyAuth() (IsLegacyV1 branch)
//   - v2 path: volume/decrypt.go:decryptVerifyAuth() (else branch)
//   - v2 encrypt: volume/encrypt.go:encryptComputeAuth()
type SubkeyReader struct {
	hkdf        io.Reader
	headerRead  bool
	macRead     bool
	serpentRead bool
	rekeyCount  int
}

// NewHKDFStream creates a new HKDF-SHA3-256 stream for subkey derivation.
// The key should be the Argon2-derived key (possibly XORed with keyfile key for v1).
// The salt is the HKDF salt from the header.
func NewHKDFStream(key, salt []byte) io.Reader {
	return hkdf.New(sha3.New256, key, salt, nil)
}

// NewSubkeyReader creates a SubkeyReader wrapping an HKDF stream.
func NewSubkeyReader(hkdfStream io.Reader) *SubkeyReader {
	return &SubkeyReader{hkdf: hkdfStream}
}

// HeaderSubkey reads the 64-byte header subkey (v2 only).
// This MUST be called first before any other subkey reads.
func (r *SubkeyReader) HeaderSubkey() ([]byte, error) {
	if r.headerRead {
		return nil, errors.New("header subkey already consumed")
	}

	subkey := make([]byte, SubkeyHeaderSize)
	if _, err := io.ReadFull(r.hkdf, subkey); err != nil {
		return nil, errors.New("fatal hkdf.Read error for header subkey")
	}

	r.headerRead = true
	return subkey, nil
}

// MACSubkey reads the 32-byte MAC subkey.
// For v2, this must be called after HeaderSubkey().
// For v1, this is the first subkey read.
func (r *SubkeyReader) MACSubkey() ([]byte, error) {
	if r.macRead {
		return nil, errors.New("MAC subkey already consumed")
	}

	subkey := make([]byte, SubkeyMACSize)
	if _, err := io.ReadFull(r.hkdf, subkey); err != nil {
		return nil, errors.New("fatal hkdf.Read error for MAC subkey")
	}

	r.macRead = true
	return subkey, nil
}

// SerpentKey reads the 32-byte Serpent key.
func (r *SubkeyReader) SerpentKey() ([]byte, error) {
	if r.serpentRead {
		return nil, errors.New("serpent key already consumed")
	}
	if !r.macRead {
		return nil, errors.New("must read MAC subkey before Serpent key")
	}

	key := make([]byte, SubkeySerpentSize)
	if _, err := io.ReadFull(r.hkdf, key); err != nil {
		return nil, errors.New("fatal hkdf.Read error for Serpent key")
	}

	r.serpentRead = true
	return key, nil
}

// RekeyValues reads new nonce (24 bytes) and IV (16 bytes) for rekeying.
// This is called every 60 GiB of data.
func (r *SubkeyReader) RekeyValues() (nonce []byte, iv []byte, err error) {
	nonce = make([]byte, RekeyNonceSize)
	if _, err := io.ReadFull(r.hkdf, nonce); err != nil {
		return nil, nil, errors.New("fatal hkdf.Read error for rekey nonce")
	}

	iv = make([]byte, RekeyIVSize)
	if _, err := io.ReadFull(r.hkdf, iv); err != nil {
		return nil, nil, errors.New("fatal hkdf.Read error for rekey IV")
	}

	r.rekeyCount++
	return nonce, iv, nil
}

// RekeyCount returns how many times rekeying has occurred.
func (r *SubkeyReader) RekeyCount() int {
	return r.rekeyCount
}

// Reader returns the underlying HKDF reader for advanced use.
// Use with caution - direct reads affect subkey derivation order.
func (r *SubkeyReader) Reader() io.Reader {
	return r.hkdf
}
