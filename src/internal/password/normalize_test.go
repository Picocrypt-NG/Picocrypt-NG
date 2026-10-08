package password

import (
	"bytes"
	"testing"
)

// Test vectors are built from explicit code points / bytes — never from source
// literals — so an editor re-normalizing this file cannot silently make the
// composed/decomposed distinctions vacuous. These are the UAX #15 worked
// examples behind issue #19: the same visible character in two byte forms.
var (
	eComposed    = string([]rune{0x00E9})                   // é  NFC
	eDecomposed  = string([]rune{0x0065, 0x0301})           // é  NFD (e + combining acute)
	gaComposed   = string([]rune{0xAC00})                   // 가 NFC
	gaDecomposed = string([]rune{0x1100, 0x1161})           // 가 NFD (conjoining jamo)
	devEmoji     = string([]rune{0x1F469, 0x200D, 0x1F4BB}) // 👩‍💻 ZWJ sequence
	// e + acute (ccc 230) + dot-below (ccc 220): combining marks in non-canonical
	// order, so the raw bytes equal neither the NFC nor the NFD form.
	nonCanonical = string([]rune{0x0065, 0x0301, 0x0323})

	eNFCBytes  = []byte{0xc3, 0xa9}
	eNFDBytes  = []byte{0x65, 0xcc, 0x81}
	gaNFCBytes = []byte{0xea, 0xb0, 0x80}
)

func TestNormalizeProducesNFC(t *testing.T) {
	// Composed and decomposed forms of the SAME character must normalize to
	// identical NFC bytes — that is exactly what lets a password typed on one
	// platform derive the same key as on another (the #19 fix). If Normalize
	// stopped normalizing, the decomposed cases would diverge and fail.
	cases := []struct {
		name string
		in   string
		want []byte
	}{
		{"e composed", eComposed, eNFCBytes},
		{"e decomposed", eDecomposed, eNFCBytes},
		{"ga composed", gaComposed, gaNFCBytes},
		{"ga decomposed", gaDecomposed, gaNFCBytes},
	}
	for _, tc := range cases {
		if got := Normalize([]byte(tc.in)); !bytes.Equal(got, tc.want) {
			t.Errorf("Normalize(%s) = % x, want % x", tc.name, got, tc.want)
		}
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	for _, in := range []string{eComposed, eDecomposed, gaDecomposed, devEmoji, "ascii"} {
		once := Normalize([]byte(in))
		if twice := Normalize(once); !bytes.Equal(twice, once) {
			t.Errorf("Normalize not idempotent for % x: % x != % x", []byte(in), twice, once)
		}
	}
}

func TestNormalizeLeavesASCIIUnchanged(t *testing.T) {
	// ASCII is invariant under NFC, so the millions of existing ASCII-password
	// volumes are completely unaffected by this change.
	in := "Correct Horse Battery Staple 123!@#"
	if got := Normalize([]byte(in)); !bytes.Equal(got, []byte(in)) {
		t.Errorf("Normalize(ascii) = %q, want unchanged %q", got, in)
	}
}

func TestNormalizeDoesNotCaseFoldOrTrim(t *testing.T) {
	// NFC must preserve case (RFC 8265 §4.2.2: no case mapping — folding the
	// Turkish dotless-i class reduces security) and must NOT trim whitespace
	// (silent entropy loss / lockouts). U+00DF (ß) must not fold to "ss".
	in := " stra" + string([]rune{0x00DF}) + "e " // " straße "
	if got := Normalize([]byte(in)); !bytes.Equal(got, []byte(in)) {
		t.Errorf("Normalize must preserve U+00DF and surrounding spaces: % x -> % x", []byte(in), got)
	}
}

func TestNormalizeLeavesEmojiZWJUnchanged(t *testing.T) {
	// ZWJ emoji sequences have no canonical decomposition; NFC passes them
	// through byte-for-byte, so emoji passwords are never corrupted.
	if got := Normalize([]byte(devEmoji)); !bytes.Equal(got, []byte(devEmoji)) {
		t.Errorf("Normalize altered ZWJ emoji: % x -> % x", []byte(devEmoji), got)
	}
}

func TestEncodeForKDFIsNFCBytes(t *testing.T) {
	// Encrypt must feed the KDF the NFC form regardless of how the password was
	// typed, so new volumes are cross-platform-stable.
	if got := EncodeForKDF([]byte(eDecomposed)); !bytes.Equal(got, eNFCBytes) {
		t.Errorf("EncodeForKDF(decomposed e) = % x, want NFC % x", got, eNFCBytes)
	}
}

func TestEncodeForKDFReturnsIndependentCopy(t *testing.T) {
	// The encrypt path SecureZeros the EncodeForKDF result via defer; if that
	// result aliased req.Password's backing array, the defer would wipe the
	// password BEFORE AddDeniability reads it later in the pipeline (silently
	// breaking deniability). EncodeForKDF must therefore return a fresh copy.
	cases := []struct {
		name string
		in   string
		want []byte
	}{
		{"ascii", "password123", []byte("password123")},
		{"composed", eComposed, eNFCBytes},
		{"decomposed", eDecomposed, eNFCBytes},
		{"hangul decomposed", gaDecomposed, gaNFCBytes},
		{"empty", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pw := []byte(tc.in)
			out := EncodeForKDF(pw)
			if !bytes.Equal(out, tc.want) {
				t.Fatalf("EncodeForKDF = % x, want NFC % x", out, tc.want)
			}
			if !bytes.Equal(pw, []byte(tc.in)) {
				t.Fatal("normalizing KDF input changed the caller's password")
			}
			clear(out)
			if !bytes.Equal(pw, []byte(tc.in)) {
				t.Fatal("clearing KDF input changed the caller's password")
			}
		})
	}
}

func TestCandidatesASCIISingleAttempt(t *testing.T) {
	// The common case: ASCII passwords yield exactly ONE candidate (raw bytes),
	// guaranteeing no extra Argon2 work and no behavior change. If this grew to
	// >1, every ASCII wrong-password would pay multiple 1 GiB derivations.
	got := Candidates([]byte("password123"))
	if len(got) != 1 {
		t.Fatalf("ASCII Candidates len = %d, want 1 (got % x)", len(got), got)
	}
	if !bytes.Equal(got[0], []byte("password123")) {
		t.Errorf("ASCII candidate = % x, want raw bytes", got[0])
	}
}

func TestCandidatesNonASCIIOrderAndDedup(t *testing.T) {
	// NFC must be tried FIRST (so a correct password on a new/NFC volume matches
	// on the first derivation) and duplicate forms must be collapsed (so we
	// never run the same Argon2 twice). For a composed-e password NFC == raw, so
	// after dedup we expect exactly [NFC, NFD]; same for the decomposed form
	// (there NFD == raw).
	for _, in := range []string{eComposed, eDecomposed} {
		got := Candidates([]byte(in))
		if len(got) != 2 {
			t.Fatalf("Candidates(% x) len = %d, want 2 (got % x)", []byte(in), len(got), got)
		}
		if !bytes.Equal(got[0], eNFCBytes) {
			t.Errorf("Candidates(% x)[0] = % x, want NFC % x", []byte(in), got[0], eNFCBytes)
		}
		if !bytes.Equal(got[1], eNFDBytes) {
			t.Errorf("Candidates(% x)[1] = % x, want NFD % x", []byte(in), got[1], eNFDBytes)
		}
	}
}

func TestCandidatesIncludesRawWhenNeitherNFCNorNFD(t *testing.T) {
	// A non-canonical input (combining marks out of canonical order) differs
	// from BOTH its NFC and NFD forms, so raw MUST be kept as a third candidate
	// to keep such legacy volumes decryptable.
	got := Candidates([]byte(nonCanonical))
	if len(got) != 3 {
		t.Fatalf("Candidates(non-canonical) len = %d, want 3 (got % x)", len(got), got)
	}
	if !bytes.Equal(got[2], []byte(nonCanonical)) {
		t.Errorf("Candidates[2] = % x, want raw % x", got[2], []byte(nonCanonical))
	}
	if bytes.Equal(got[0], []byte(nonCanonical)) || bytes.Equal(got[1], []byte(nonCanonical)) {
		t.Errorf("raw must be distinct from NFC/NFD candidates for a non-canonical input")
	}
}

func TestCandidatesEmptyPassword(t *testing.T) {
	got := Candidates([]byte(""))
	if len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("Candidates(\"\") = %v, want a single empty candidate", got)
	}
}

func TestContainsNonASCII(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"ascii", "Password123!@#", false},
		{"empty", "", false},
		{"high-bit-boundary 0x7f", "\x7f", false},
		{"accented", eComposed, true},
		{"decomposed", eDecomposed, true},
		{"hangul", gaComposed, true},
		{"ascii then non-ascii", "pass" + eComposed, true},
	}
	for _, tc := range cases {
		if got := ContainsNonASCII([]byte(tc.in)); got != tc.want {
			t.Errorf("ContainsNonASCII(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
