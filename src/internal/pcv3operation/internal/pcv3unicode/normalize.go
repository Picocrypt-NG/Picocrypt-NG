// Package pcv3unicode provides the frozen Unicode 17.0.0 credential
// canonicalization rule reserved for the PCV3 codec.
package pcv3unicode

import (
	norm17 "Picocrypt-NG/internal/pcv3operation/internal/pcv3unicode/norm17"
	pcsecret "Picocrypt-NG/internal/secret"
	"unicode"
	"unicode/utf8"
)

const (
	// UnicodeVersion is the Unicode version encoded in the locally frozen
	// normalization and assignment data.
	UnicodeVersion = norm17.Version

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
)

// Error is returned when a PCV3 credential cannot be represented by the
// frozen Unicode 17.0.0 NFC rule.
type Error struct {
	Reason Rejection
}

func (e *Error) Error() string {
	switch e.Reason {
	case RejectionInvalidUTF8:
		return "pcv3unicode: invalid UTF-8"
	case RejectionUnassigned:
		return "pcv3unicode: Unicode 17.0.0-unassigned scalar"
	case RejectionInputTooLarge:
		return "pcv3unicode: input exceeds 1 MiB"
	case RejectionOutputTooLarge:
		return "pcv3unicode: normalized output exceeds 1 MiB"
	default:
		return "pcv3unicode: rejected credential"
	}
}

// Canonicalize accepts exactly one Unicode 17.0.0 NFC representation. It
// rejects malformed UTF-8, scalars unassigned in Unicode 17.0.0, and values
// that exceed the protocol byte limit before or after normalization.
func Canonicalize(input []byte) ([]byte, error) {
	if len(input) > maxUTF8Bytes {
		return nil, &Error{Reason: RejectionInputTooLarge}
	}
	if !utf8.Valid(input) {
		return nil, &Error{Reason: RejectionInvalidUTF8}
	}
	for remaining := input; len(remaining) > 0; {
		r, size := utf8.DecodeRune(remaining)
		if !unicode.Is(assigned17_0_0, r) {
			return nil, &Error{Reason: RejectionUnassigned}
		}
		remaining = remaining[size:]
	}

	return finishCanonicalization(norm17.NFC.Bytes(input))
}

func finishCanonicalization(canonical []byte) ([]byte, error) {
	if len(canonical) > maxUTF8Bytes {
		// Input was bounded before normalization, so an oversized result
		// owns a separate allocation that the caller cannot clear on error.
		pcsecret.SecureZero(canonical)
		return nil, &Error{Reason: RejectionOutputTooLarge}
	}
	return canonical, nil
}
