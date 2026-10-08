package pcv3unicode

import (
	norm17 "Picocrypt-NG/internal/pcv3operation/internal/pcv3unicode/norm17"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

//go:embed testdata/unicode17-literal-vectors.json
var literalVectorsJSON []byte

const literalMaxUTF8Bytes = 1 << 20

type literalPositiveVector struct {
	ID                string `json:"id"`
	InputHex          string `json:"input_hex"`
	Unicode17NFCHex   string `json:"unicode17_nfc_hex"`
	Unicode15NFCHex   string `json:"unicode15_nfc_hex"`
	Unicode15Assigned string `json:"unicode15_assignment"`
}

type literalVectorFixture struct {
	UnicodeVersion string `json:"unicode_version"`
	UAX15Revision  string `json:"uax15_revision"`
	MaxUTF8Bytes   int    `json:"max_utf8_bytes"`
	Sources        struct {
		NormalizationTestSHA256              string `json:"normalization_test_sha256"`
		DerivedAgeSHA256                     string `json:"derived_age_sha256"`
		UnicodeDataSHA256                    string `json:"unicode_data_sha256"`
		DerivedNormalizationPropertiesSHA256 string `json:"derived_normalization_properties_sha256"`
		UAX15SHA256                          string `json:"uax15_revision_57_sha256"`
	} `json:"sources"`
	Positive                      []literalPositiveVector `json:"positive"`
	SupplementaryRecompositions   []literalPositiveVector `json:"supplementary_recompositions"`
	SupplementaryAliasRegressions []literalPositiveVector `json:"supplementary_alias_regressions"`
	Negative                      []struct {
		ID        string `json:"id"`
		InputHex  string `json:"input_hex"`
		Rejection string `json:"rejection"`
	} `json:"negative"`
	PostNormalizationLimit struct {
		InputUnitHex string `json:"input_unit_hex"`
		Repeat       int    `json:"repeat"`
	} `json:"post_normalization_limit"`
}

func loadLiteralFixture(t *testing.T) literalVectorFixture {
	t.Helper()
	var fixture literalVectorFixture
	if err := json.Unmarshal(literalVectorsJSON, &fixture); err != nil {
		t.Fatalf("decode literal Unicode fixture: %v", err)
	}
	return fixture
}

func decodeLiteralHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode literal hex %q: %v", value, err)
	}
	return decoded
}

func TestLiteralUnicode17FixturePinsExternalEvidence(t *testing.T) {
	fixture := loadLiteralFixture(t)
	if fixture.UnicodeVersion != literalUnicodeVersion || fixture.UAX15Revision != literalUAX15Revision {
		t.Fatalf("literal fixture version = Unicode %q / UAX #15 rev %q; want Unicode %q / rev %q", fixture.UnicodeVersion, fixture.UAX15Revision, literalUnicodeVersion, literalUAX15Revision)
	}
	if fixture.MaxUTF8Bytes != literalMaxUTF8Bytes {
		t.Fatalf("literal fixture max UTF-8 bytes = %d, want %d", fixture.MaxUTF8Bytes, literalMaxUTF8Bytes)
	}
	if fixture.Sources.NormalizationTestSHA256 != literalNormalizationTestSHA256 ||
		fixture.Sources.DerivedAgeSHA256 != literalDerivedAgeSHA256 ||
		fixture.Sources.UnicodeDataSHA256 != literalUnicodeDataSHA256 ||
		fixture.Sources.DerivedNormalizationPropertiesSHA256 != literalDerivedNormalizationPropertiesSHA256 ||
		fixture.Sources.UAX15SHA256 != literalUAX15SHA256 {
		t.Fatal("literal fixture changed a pinned Unicode 17 source hash")
	}
}

func assertLiteralNFCVectors(t *testing.T, vectors []literalPositiveVector) {
	t.Helper()
	for _, vector := range vectors {
		input := decodeLiteralHex(t, vector.InputHex)
		original := append([]byte(nil), input...)
		want := decodeLiteralHex(t, vector.Unicode17NFCHex)
		got, err := Canonicalize(input)
		if err != nil {
			t.Fatalf("Canonicalize(%s) for %s: %v", vector.InputHex, vector.ID, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Canonicalize(%s) for %s = %x, want literal Unicode-17 NFC %x", vector.InputHex, vector.ID, got, want)
		}
		if !bytes.Equal(input, original) {
			t.Fatalf("Canonicalize(%s) for %s modified caller-owned input", vector.InputHex, vector.ID)
		}
		if vector.Unicode15NFCHex != "" {
			unicode15 := decodeLiteralHex(t, vector.Unicode15NFCHex)
			if bytes.Equal(want, unicode15) {
				t.Fatalf("%s lost its independently frozen Unicode-15 differential", vector.ID)
			}
			if bytes.Equal(got, unicode15) {
				t.Fatalf("%s selected literal Unicode-15 NFC %x instead of Unicode-17 NFC %x", vector.ID, unicode15, want)
			}
		}
	}
}

func TestCanonicalizeUsesLiteralUnicode17NFC(t *testing.T) {
	if UnicodeVersion != literalUnicodeVersion {
		t.Fatalf("compiled Unicode version = %q, want %q", UnicodeVersion, literalUnicodeVersion)
	}
	fixture := loadLiteralFixture(t)
	assertLiteralNFCVectors(t, fixture.Positive)
}

func TestCanonicalizeUsesEveryLiteralSupplementaryRecompositionWithoutAliases(t *testing.T) {
	fixture := loadLiteralFixture(t)
	if len(fixture.SupplementaryRecompositions) != 33 {
		t.Fatalf("supplementary recomposition vector count = %d, want frozen Unicode-17 count 33", len(fixture.SupplementaryRecompositions))
	}
	if len(fixture.SupplementaryAliasRegressions) != 3 {
		t.Fatalf("supplementary alias regression count = %d, want 3 independently chosen low-16 collisions", len(fixture.SupplementaryAliasRegressions))
	}
	assertLiteralNFCVectors(t, fixture.SupplementaryRecompositions)
	assertLiteralNFCVectors(t, fixture.SupplementaryAliasRegressions)
}

func TestCanonicalizeDoesNotAliasNonBMPCompositionKey(t *testing.T) {
	// U+10041 has no canonical composition with U+0300. A recomposition map
	// that truncates scalar values to 16 bits aliases U+10041 to U+0041 and
	// incorrectly produces U+00C0, collapsing two distinct credentials.
	input := []byte("\U00010041\u0300")
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize(non-BMP starter plus grave): %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("Canonicalize(non-BMP starter plus grave) = %x, want unchanged NFC %x", got, input)
	}
}

func expectedRejection(t *testing.T, name string) Rejection {
	t.Helper()
	switch name {
	case "invalid-utf8":
		return RejectionInvalidUTF8
	case "unassigned":
		return RejectionUnassigned
	default:
		t.Fatalf("unknown literal rejection %q", name)
		return 0
	}
}

func TestCanonicalizeRejectsLiteralInvalidInputsWithoutResult(t *testing.T) {
	fixture := loadLiteralFixture(t)
	for _, vector := range fixture.Negative {
		got, err := Canonicalize(decodeLiteralHex(t, vector.InputHex))
		if err == nil || got != nil {
			t.Fatalf("Canonicalize(%s) for %s = (%x, %v); want no normalized result and a rejection", vector.InputHex, vector.ID, got, err)
		}
		var rejected *Error
		if !errors.As(err, &rejected) || rejected.Reason != expectedRejection(t, vector.Rejection) {
			t.Fatalf("Canonicalize(%s) for %s returned %#v; want typed rejection %s", vector.InputHex, vector.ID, err, vector.Rejection)
		}
	}
}

func TestCanonicalizeEnforcesLiteralPreAndPostNormalizationLimits(t *testing.T) {
	fixture := loadLiteralFixture(t)
	atLimit := bytes.Repeat([]byte{'a'}, fixture.MaxUTF8Bytes)
	got, err := Canonicalize(atLimit)
	if err != nil || !bytes.Equal(got, atLimit) {
		t.Fatalf("Canonicalize(exact pre/post 1 MiB ASCII boundary) = (%d bytes, %v), want unchanged success", len(got), err)
	}

	tooLarge := append(append([]byte(nil), atLimit...), 'a')
	got, err = Canonicalize(tooLarge)
	if err == nil || got != nil {
		t.Fatalf("Canonicalize(1 MiB + 1 pre-normalization bytes) = (%d bytes, %v); want no result and a rejection", len(got), err)
	}
	var rejected *Error
	if !errors.As(err, &rejected) || rejected.Reason != RejectionInputTooLarge {
		t.Fatalf("Canonicalize(1 MiB + 1 pre-normalization bytes) rejection = %#v; want typed input-limit rejection", err)
	}

	postUnit := decodeLiteralHex(t, fixture.PostNormalizationLimit.InputUnitHex)
	postExpansion := bytes.Repeat(postUnit, fixture.PostNormalizationLimit.Repeat)
	original := append([]byte(nil), postExpansion...)
	if len(postExpansion) != fixture.MaxUTF8Bytes {
		t.Fatalf("post-normalization boundary input length = %d, want %d", len(postExpansion), fixture.MaxUTF8Bytes)
	}
	got, err = Canonicalize(postExpansion)
	if err == nil || got != nil {
		t.Fatalf("Canonicalize(U+0344 expansion at pre-normalization boundary) = (%d bytes, %v); want no result and a post-normalization rejection", len(got), err)
	}
	if !errors.As(err, &rejected) || rejected.Reason != RejectionOutputTooLarge {
		t.Fatalf("Canonicalize(U+0344 expansion at pre-normalization boundary) rejection = %#v; want typed output-limit rejection", err)
	}
	if !bytes.Equal(postExpansion, original) {
		t.Fatal("post-normalization rejection modified caller-owned input")
	}
}

func TestFinishCanonicalizationClearsRejectedOutput(t *testing.T) {
	// Retain the real NFC allocation at the ownership boundary: an oversized
	// result is otherwise lost to the caller when Canonicalize returns nil.
	input := bytes.Repeat([]byte("\u0344"), literalMaxUTF8Bytes/2)
	original := append([]byte(nil), input...)
	canonical := norm17.NFC.Bytes(input)
	if len(canonical) <= literalMaxUTF8Bytes {
		t.Fatal("U+0344 fixture did not expand beyond the normalized byte limit")
	}

	got, err := finishCanonicalization(canonical)
	var rejected *Error
	if got != nil || !errors.As(err, &rejected) || rejected.Reason != RejectionOutputTooLarge {
		t.Fatalf("oversized normalized output = (%d bytes, %v); want no result and typed output-limit rejection", len(got), err)
	}
	for _, b := range canonical {
		if b != 0 {
			t.Fatal("post-normalization rejection retained credential bytes in the owned output")
		}
	}
	if !bytes.Equal(input, original) {
		t.Fatal("clearing rejected output modified caller-owned input")
	}
}

func TestCanonicalizePreservesExpandedOutputAtLimit(t *testing.T) {
	// U+0344 expands from two to four UTF-8 bytes. This exact post-NFC
	// boundary must stay usable while the adjacent oversized case is cleared.
	input := append(bytes.Repeat([]byte{'!'}, literalMaxUTF8Bytes-4), []byte("\u0344")...)
	original := append([]byte(nil), input...)
	want := append(bytes.Repeat([]byte{'!'}, literalMaxUTF8Bytes-4), []byte("\u0308\u0301")...)
	got, err := Canonicalize(input)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("exact post-NFC limit = (%d bytes, %v); want intact normalized output", len(got), err)
	}
	if !bytes.Equal(input, original) {
		t.Fatal("successful normalization modified caller-owned input")
	}
}

func TestLiteralFixtureBytesAreNotSelfGenerated(t *testing.T) {
	// Pin an independent byte-level checksum of the public literal fixture. The
	// production canonicalizer is deliberately not consulted here: changing a
	// fixture literal must not be able to update its own expected result.
	sum := sha256.Sum256(literalVectorsJSON)
	if hex.EncodeToString(sum[:]) != "2c8afbecfa71938621298fdc23c2e0c38905bd1bb3c3cffd4a192403d88223bb" {
		t.Fatal("literal Unicode fixture changed; review its external provenance before updating this checksum")
	}
}
