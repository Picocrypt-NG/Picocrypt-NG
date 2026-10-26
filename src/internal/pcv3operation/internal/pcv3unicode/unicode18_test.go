package pcv3unicode

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

//go:embed testdata/unicode18-literal-vectors.json
var unicode18LiteralVectorsJSON []byte

type unicode18LiteralFixture struct {
	UnicodeVersion string            `json:"unicode_version"`
	UAX15Revision  string            `json:"uax15_revision"`
	MaxUTF8Bytes   int               `json:"max_utf8_bytes"`
	Sources        map[string]string `json:"sources"`
	Positive       []struct {
		ID       string `json:"id"`
		InputHex string `json:"input_hex"`
		NFCHex   string `json:"unicode18_nfc_hex"`
	} `json:"positive"`
	Negative []struct {
		ID       string `json:"id"`
		InputHex string `json:"input_hex"`
	} `json:"negative"`
}

func loadUnicode18LiteralFixture(t *testing.T) unicode18LiteralFixture {
	t.Helper()
	var fixture unicode18LiteralFixture
	if err := json.Unmarshal(unicode18LiteralVectorsJSON, &fixture); err != nil {
		t.Fatalf("decode Unicode-18 literal fixture: %v", err)
	}
	return fixture
}

func TestLiteralUnicode18FixturePinsExternalEvidence(t *testing.T) {
	fixture := loadUnicode18LiteralFixture(t)
	if fixture.UnicodeVersion != literalUnicodeVersion || fixture.UAX15Revision != literalUAX15Revision || fixture.MaxUTF8Bytes != literalMaxUTF8Bytes {
		t.Fatal("Unicode-18 fixture changed the credential profile")
	}
	for name, want := range map[string]string{
		"normalization_test_sha256":               literalNormalizationTestSHA256,
		"unicode_data_sha256":                     literalUnicodeDataSHA256,
		"derived_age_sha256":                      literalDerivedAgeSHA256,
		"derived_normalization_properties_sha256": literalDerivedNormalizationPropertiesSHA256,
		"uax15_revision_58_sha256":                literalUAX15SHA256,
	} {
		if fixture.Sources[name] != want {
			t.Fatalf("Unicode-18 fixture changed pinned source %s", name)
		}
	}
	sum := sha256.Sum256(unicode18LiteralVectorsJSON)
	if hex.EncodeToString(sum[:]) != "3d91f93708c530dc520afa76a25447b7f14dce70fef136705e012328b7c73465" {
		t.Fatal("Unicode-18 literal fixture changed; review its public-source evidence before updating this checksum")
	}
}

func TestCanonicalizeAcceptsUnicode18AssignedSymbolAndNFC(t *testing.T) {
	if UnicodeVersion != literalUnicodeVersion {
		t.Fatalf("compiled Unicode version = %q, want %q", UnicodeVersion, literalUnicodeVersion)
	}
	for _, test := range loadUnicode18LiteralFixture(t).Positive {
		t.Run(test.ID, func(t *testing.T) {
			input := decodeLiteralHex(t, test.InputHex)
			original := append([]byte(nil), input...)
			got, err := Canonicalize(input)
			if err != nil {
				t.Fatalf("Unicode-18 credential rejected: %v", err)
			}
			if want := decodeLiteralHex(t, test.NFCHex); !bytes.Equal(got, want) {
				t.Fatalf("Unicode-18 NFC = %x, want official literal %x", got, want)
			}
			if !bytes.Equal(input, original) {
				t.Fatal("normalization modified caller-owned credential")
			}
		})
	}
}

func TestCanonicalizeRejectsUnicode18UnassignedScalarsWithoutResult(t *testing.T) {
	for _, test := range loadUnicode18LiteralFixture(t).Negative {
		t.Run(test.ID, func(t *testing.T) {
			got, err := Canonicalize(decodeLiteralHex(t, test.InputHex))
			var rejection *Error
			if got != nil || !errors.As(err, &rejection) || rejection.Reason != RejectionUnassigned {
				t.Fatalf("unassigned credential = (%x, %v), want no result and typed unassigned rejection", got, err)
			}
		})
	}
}
