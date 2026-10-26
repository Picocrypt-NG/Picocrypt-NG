// Package pcv3unicode provides the frozen, bounded Unicode 18.0.0 NFC
// credential profile reserved for the PCV3 codec.
package pcv3unicode

import (
	norm18 "Picocrypt-NG/internal/pcv3operation/internal/pcv3unicode/norm18"
	pcsecret "Picocrypt-NG/internal/secret"
	"bytes"
	"unicode"
	"unicode/utf8"
)

const (
	// UnicodeVersion is the Unicode version encoded in the locally frozen
	// normalization and assignment data.
	UnicodeVersion = norm18.Version

	maxUTF8Bytes = 1 << 20
)

// Rejection identifies why Canonicalize refused to produce credential bytes.
// It intentionally carries no input data: callers can report the failure
// without exposing a password in logs or UI diagnostics.
type Rejection uint8

const (
	RejectionInvalidUTF8 Rejection = iota + 1
	RejectionUnassigned
	RejectionInputTooLarge
	RejectionOutputTooLarge
	RejectionCombiningSequence
)

// Error is returned when a PCV3 credential cannot be represented by the
// frozen Unicode 18.0.0 NFC profile.
type Error struct {
	Reason Rejection
}

func (e *Error) Error() string {
	switch e.Reason {
	case RejectionInvalidUTF8:
		return "pcv3unicode: invalid UTF-8"
	case RejectionUnassigned:
		return "pcv3unicode: Unicode 18.0.0-unassigned scalar"
	case RejectionInputTooLarge:
		return "pcv3unicode: input exceeds 1 MiB"
	case RejectionOutputTooLarge:
		return "pcv3unicode: normalized output exceeds 1 MiB"
	case RejectionCombiningSequence:
		return "pcv3unicode: combining sequence exceeds the normalization profile"
	default:
		return "pcv3unicode: rejected credential"
	}
}

// Canonicalize applies the pinned Unicode 18.0.0 NFC profile. Inputs requiring
// implicit CGJ insertion are rejected instead of silently changing the password.
// Malformed UTF-8, unassigned scalars and oversized values are also rejected.
func Canonicalize(input []byte) ([]byte, error) {
	if len(input) > maxUTF8Bytes {
		return nil, &Error{Reason: RejectionInputTooLarge}
	}
	if !utf8.Valid(input) {
		return nil, &Error{Reason: RejectionInvalidUTF8}
	}
	for remaining := input; len(remaining) > 0; {
		r, size := utf8.DecodeRune(remaining)
		if !unicode.Is(assigned18_0_0, r) {
			return nil, &Error{Reason: RejectionUnassigned}
		}
		remaining = remaining[size:]
	}

	return finishCanonicalization(input, norm18.NFC.Bytes(input))
}

func finishCanonicalization(input, canonical []byte) ([]byte, error) {
	if len(canonical) > maxUTF8Bytes {
		// Input was bounded before normalization, so an oversized result
		// owns a separate allocation that the caller cannot clear on error.
		pcsecret.SecureZero(canonical)
		return nil, &Error{Reason: RejectionOutputTooLarge}
	}
	if bytes.Count(canonical, []byte(norm18.GraphemeJoiner)) > bytes.Count(input, []byte(norm18.GraphemeJoiner)) {
		// Insertion changes the bytes, so the pinned Bytes path allocated a
		// separate result; clearing it cannot erase caller-owned input.
		pcsecret.SecureZero(canonical)
		return nil, &Error{Reason: RejectionCombiningSequence}
	}
	return canonical, nil
}
