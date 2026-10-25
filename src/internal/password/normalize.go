// Package password handles legacy v1/v2 password normalization and compatibility.
// PCV3 credentials use a separate frozen profile.
//
// Writers use the linked x/text NFC normalizer. Readers also try NFD, raw bytes
// and historical Unicode 15 NFC/NFD forms to preserve earlier derived keys.
// Both normalizers retain Stream-Safe CGJ insertion for long combining sequences.
// Compatibility normalization, case folding and whitespace trimming are not applied.
// ASCII input remains byte-identical.
package password

import (
	"Picocrypt-NG/internal/password/legacyunicode15"
	"Picocrypt-NG/internal/secret"
	"bytes"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Normalize returns pw in Unicode NFC as bytes (operates on []byte to avoid an
// immutable, un-zeroable string copy of the password).
func Normalize(pw []byte) []byte {
	return norm.NFC.Bytes(pw)
}

// EncodeForKDF returns the NFC-normalized password as a FRESH, independently
// owned []byte to feed the KDF when ENCRYPTING, so new volumes derive a
// canonical, cross-platform-stable key regardless of how the password was typed.
//
// It never aliases pw, so the caller may SecureZero the result without affecting
// pw (which may still be needed downstream, e.g. the deniability path reads
// req.Password after the encrypt-path kdfInput has been deferred-zeroed). NFC of
// an ASCII or already-composed password is byte-equal to the input but a copy.
func EncodeForKDF(pw []byte) []byte {
	normalized := Normalize(pw)
	// Keep ownership when normalization allocated; copy only an input alias.
	if len(normalized) != 0 && &normalized[0] != &pw[0] {
		return normalized
	}
	return append([]byte(nil), normalized...)
}

// Candidates returns the ordered, de-duplicated password byte forms to try when
// DECRYPTING, so volumes stay decryptable across platforms and across the
// pre/post-normalization format change.
//
// For an ASCII password it returns exactly one candidate (the raw bytes): ASCII
// is invariant under every normalization form, so there is no extra KDF work
// for the common case. For a non-ASCII password it returns up to five forms,
// duplicates removed while preserving order:
//
//  1. NFC  — opens new volumes and legacy ASCII/NFC volumes; tried first so a
//     correct password matches on the first (and only) derivation.
//  2. NFD  — opens legacy volumes whose password was decomposed.
//  3. raw  — opens legacy volumes whose bytes were neither NFC nor NFD (e.g. a
//     password pasted with combining marks in non-canonical order).
//  4. Historical Unicode 15 NFC — retains keys derived before upstream
//     normalization fixes, including the old supplementary-scalar behavior.
//  5. Historical Unicode 15 NFD — retains the earlier decomposition tables.
//
// Legacy v1/v2 readers select a candidate using the password-key verifier or
// header MAC. Deniability readers first probe the decoded inner version.
// These selection checks do not replace the separate payload MAC check.
// Extra derivations occur only after an earlier candidate fails selection.
//
// Returned slices are independent allocations, so a caller may zero each one
// after use without affecting the others (none aliases pw or another candidate).
func Candidates(pw []byte) [][]byte {
	if !ContainsNonASCII(pw) {
		// ASCII is invariant under every normalization form, so a single
		// candidate suffices and there is no extra KDF work for the common case.
		return [][]byte{append([]byte(nil), pw...)}
	}

	forms := [5][]byte{
		norm.NFC.Bytes(pw),
		norm.NFD.Bytes(pw),
		pw,
		legacyunicode15.NFC.Bytes(pw),
		legacyunicode15.NFD.Bytes(pw),
	}

	candidates := make([][]byte, 0, len(forms))
	for _, f := range forms {
		// Bytes returns either the input or a fresh normalization buffer.
		// Own each returned candidate and clear temporary/duplicate copies.
		candidate := append([]byte(nil), f...)
		if len(f) != 0 && &f[0] != &pw[0] {
			secret.SecureZero(f)
		}
		if containsBytes(candidates, candidate) {
			secret.SecureZero(candidate)
		} else {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

// ContainsNonASCII reports whether pw contains any non-ASCII byte. User
// interfaces use it to advise that a non-ASCII password — while normalized to a
// canonical form for cross-platform decryption — may still be hard to reproduce
// on another device with a different keyboard or input method (NIST
// SP 800-63B-4 recommends informing users of this).
func ContainsNonASCII(pw []byte) bool {
	for _, b := range pw {
		if b >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

// containsBytes reports whether set already holds a slice byte-equal to b. A
// linear scan over at most five short slices is cheaper than a map and, unlike
// a map keyed by string(b), creates no extra in-memory copies of the password.
func containsBytes(set [][]byte, b []byte) bool {
	for _, e := range set {
		if bytes.Equal(e, b) {
			return true
		}
	}
	return false
}
