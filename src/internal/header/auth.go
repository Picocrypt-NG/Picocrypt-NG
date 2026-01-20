package header

import (
	"crypto/hmac"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// AuthResult contains the result of header authentication
type AuthResult struct {
	Valid           bool   // True if password/keyfiles are correct
	KeyHashComputed []byte // The computed key hash for storage in header
}

// CRITICAL INVARIANT: v1 vs v2 Header Authentication
//
// v1.x: Header stores SHA3-512(key) for password verification
//       No header MAC - header fields are not authenticated against tampering
//
// v2.00+: Header stores HMAC-SHA3-512(header_fields) using a 64-byte subkey
//         The subkey is the FIRST 64 bytes from HKDF stream (see crypto/kdf.go)
//         This authenticates all header fields and detects tampering
//
// See crypto/kdf.go:SubkeyReader for the full HKDF timing and subkey order documentation.

// ComputeV2HeaderMAC computes the HMAC-SHA3-512 of header fields for v2 volumes.
// The subkeyHeader is the first 64 bytes read from the HKDF stream.
//
// MAC order (MUST match exactly):
//  1. version
//  2. commentsLen (5-digit string)
//  3. comments
//  4. flags (5 bytes)
//  5. salt
//  6. hkdfSalt
//  7. serpentIV
//  8. nonce
//  9. keyfileHash
func ComputeV2HeaderMAC(subkeyHeader []byte, h *VolumeHeader, keyfileHash []byte) []byte {
	mac := hmac.New(sha3.New512, subkeyHeader)

	// Write all header fields in exact order
	mac.Write([]byte(h.Version))
	_, _ = fmt.Fprintf(mac, "%05d", len(h.Comments))
	mac.Write([]byte(h.Comments))
	mac.Write(h.Flags.ToBytes())
	mac.Write(h.Salt)
	mac.Write(h.HKDFSalt)
	mac.Write(h.SerpentIV)
	mac.Write(h.Nonce)
	mac.Write(keyfileHash)

	return mac.Sum(nil)
}

// ComputeV2HeaderMACRaw computes the HMAC-SHA3-512 using raw header field bytes.
// This is used during decryption where we need to use the exact decoded bytes.
func ComputeV2HeaderMACRaw(subkeyHeader []byte, raw *RawHeaderFields, h *VolumeHeader, keyfileHash []byte) []byte {
	mac := hmac.New(sha3.New512, subkeyHeader)

	// Write all header fields in exact order using raw bytes where available
	mac.Write(raw.Version)
	_, _ = fmt.Fprintf(mac, "%05d", raw.CommentsLen)
	mac.Write(raw.Comments)
	mac.Write(raw.Flags)
	mac.Write(h.Salt)
	mac.Write(h.HKDFSalt)
	mac.Write(h.SerpentIV)
	mac.Write(h.Nonce)
	mac.Write(keyfileHash)

	return mac.Sum(nil)
}

// ComputeV1KeyHash computes SHA3-512(key) for v1 legacy volumes.
// In v1, the header stored SHA3-512 of the derived key for password verification.
func ComputeV1KeyHash(key []byte) []byte {
	h := sha3.New512()
	h.Write(key)
	return h.Sum(nil)
}

// VerifyV2Header verifies a v2 volume header using HMAC-SHA3-512.
// Returns true if the computed MAC matches the stored keyHash.
func VerifyV2Header(subkeyHeader []byte, h *VolumeHeader, keyfileHash []byte) *AuthResult {
	computed := ComputeV2HeaderMAC(subkeyHeader, h, keyfileHash)
	valid := subtle.ConstantTimeCompare(computed, h.KeyHash) == 1

	return &AuthResult{
		Valid:           valid,
		KeyHashComputed: computed,
	}
}

// VerifyV2HeaderRaw verifies a v2 volume header using raw decoded bytes.
func VerifyV2HeaderRaw(subkeyHeader []byte, raw *RawHeaderFields, h *VolumeHeader, keyfileHash []byte) *AuthResult {
	computed := ComputeV2HeaderMACRaw(subkeyHeader, raw, h, keyfileHash)
	valid := subtle.ConstantTimeCompare(computed, h.KeyHash) == 1

	return &AuthResult{
		Valid:           valid,
		KeyHashComputed: computed,
	}
}

// VerifyV1Header verifies a v1 legacy volume header.
// For v1, we compare SHA3-512(key) with the stored keyHash.
func VerifyV1Header(key []byte, h *VolumeHeader) *AuthResult {
	computed := ComputeV1KeyHash(key)
	valid := subtle.ConstantTimeCompare(computed, h.KeyHash) == 1

	return &AuthResult{
		Valid:           valid,
		KeyHashComputed: computed,
	}
}

// VerifyKeyfileHash verifies that the provided keyfile hash matches the stored one.
// Returns true if keyfiles match or if no keyfiles are required.
func VerifyKeyfileHash(computed, stored []byte) bool {
	return subtle.ConstantTimeCompare(computed, stored) == 1
}

// AuthError represents an authentication failure with details
type AuthError struct {
	PasswordIncorrect bool
	KeyfileIncorrect  bool
	KeyfileOrdered    bool // If true, ordering matters
	Message           string
}

func (e *AuthError) Error() string {
	return e.Message
}

// NewPasswordError creates an auth error for incorrect password
func NewPasswordError() *AuthError {
	return &AuthError{
		PasswordIncorrect: true,
		Message:           "The provided password is incorrect",
	}
}

// NewV2PasswordOrTamperError creates an auth error for v2 header validation failure
func NewV2PasswordOrTamperError() *AuthError {
	return &AuthError{
		PasswordIncorrect: true,
		Message:           "The password is incorrect or header is tampered",
	}
}

// NewKeyfileError creates an auth error for incorrect keyfiles
func NewKeyfileError(ordered bool) *AuthError {
	msg := "Incorrect keyfiles"
	if ordered {
		msg = "Incorrect keyfiles or ordering"
	}
	return &AuthError{
		KeyfileIncorrect: true,
		KeyfileOrdered:   ordered,
		Message:          msg,
	}
}
