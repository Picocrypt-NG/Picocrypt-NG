package pcv3unicode

import (
	"bytes"
	"errors"
	"testing"

	norm18 "Picocrypt-NG/internal/pcv3operation/internal/pcv3unicode/norm18"
)

func TestCanonicalizeDoesNotMergeDifferentPasswordsAcrossStarter(t *testing.T) {
	// U+113C2 has CCC=0 and blocks the grave accent from composing with i.
	// Upstream x/text regression: go.dev/issue/81001.
	input := []byte("i\U000113c2\u0300\u0316")
	want := []byte("i\U000113c2\u0316\u0300")
	other := []byte("\u00ec\U000113c2\u0316")
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	otherNFC, err := Canonicalize(other)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || bytes.Equal(got, otherNFC) {
		t.Fatalf("NFC crossed a starter: got %x, want %x; different password normalized to %x", got, want, otherNFC)
	}
}

func TestCanonicalizeContinuesCompositionAfterHangul(t *testing.T) {
	// UnicodeData-18 gives 113C5 the canonical decomposition 113C2 113C2.
	// Upstream x/text regression: go.dev/issue/81021.
	got, err := Canonicalize([]byte("\u1100\u1161\U000113c2\U000113c2"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("\uac00\U000113c5")
	if !bytes.Equal(got, want) {
		t.Fatalf("NFC stopped composing after Hangul: got %x, want %x", got, want)
	}
}

func TestCanonicalizeRejectsImplicitCGJInsertion(t *testing.T) {
	for _, unit := range []string{"\u0300", "\u1161"} {
		// Reject the library's extra mapping, including backward-combining Jamo.
		input := bytes.Repeat([]byte(unit), 31)
		original := append([]byte(nil), input...)
		got, err := Canonicalize(input)
		var rejected *Error
		if got != nil || !errors.As(err, &rejected) || rejected.Reason != RejectionCombiningSequence {
			t.Fatalf("implicit CGJ mapping was accepted: got %x, error %v", got, err)
		}
		if !bytes.Equal(input, original) {
			t.Fatal("profile rejection modified the caller's password")
		}
	}
}

func TestFinishCanonicalizationClearsImplicitMappingOutput(t *testing.T) {
	input := bytes.Repeat([]byte("\u0300"), 31)
	original := append([]byte(nil), input...)
	canonical := norm18.NFC.Bytes(input)
	got, err := finishCanonicalization(input, canonical)
	var rejected *Error
	if got != nil || !errors.As(err, &rejected) || rejected.Reason != RejectionCombiningSequence {
		t.Fatalf("implicit mapping was not rejected: got %x, error %v", got, err)
	}
	if !bytes.Equal(canonical, make([]byte, len(canonical))) {
		t.Fatal("rejected password output was not cleared")
	}
	if !bytes.Equal(input, original) {
		t.Fatal("clearing rejected output changed the caller's password")
	}
}

func TestCanonicalizePreservesExplicitCGJ(t *testing.T) {
	input := append(bytes.Repeat([]byte("\u0300"), 30), []byte("\u034f\u0300")...)
	got, err := Canonicalize(input)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("explicit CGJ lost its credential meaning: got %x, error %v", got, err)
	}
}
