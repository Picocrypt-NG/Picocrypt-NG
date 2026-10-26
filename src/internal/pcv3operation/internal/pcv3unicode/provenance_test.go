package pcv3unicode

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

//go:embed provenance.json
var provenanceJSON []byte

const (
	literalUnicodeVersion = "18.0.0"
	literalUAX15Revision  = "58"

	literalNormalizationTestSHA256              = "25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3"
	literalDerivedAgeSHA256                     = "58b04334e3a31f9612694bbc3f6bff4a302b7d424565bca9c47e30aa74f8dbac"
	literalUnicodeDataSHA256                    = "0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950"
	literalDerivedNormalizationPropertiesSHA256 = "98ac7f67d985fe781e317f6182e885e94cabb0c314769e6dd73e48b226931ccd"
	literalUAX15SHA256                          = "efcf19da85342bd87fb93b590975ca422597243f2e19c6cb46e941d0d2d48d73"
)

type provenanceFixture struct {
	CredentialProfile struct {
		ArtifactPath   string `json:"artifact_path"`
		ArtifactSHA256 string `json:"artifact_sha256"`
	} `json:"credential_profile"`
	Unicode struct {
		Version       string `json:"version"`
		Normalization struct {
			UAX15Revision string `json:"uax15_revision"`
			SHA256        string `json:"sha256"`
		} `json:"normalization"`
		UCD struct {
			NormalizationTest struct {
				SHA256 string `json:"sha256"`
			} `json:"normalization_test"`
			DerivedAge struct {
				SHA256 string `json:"sha256"`
			} `json:"derived_age"`
			UnicodeData struct {
				SHA256 string `json:"sha256"`
			} `json:"unicode_data"`
			DerivedNormalizationProperties struct {
				SHA256 string `json:"sha256"`
			} `json:"derived_normalization_properties"`
		} `json:"ucd"`
	} `json:"unicode"`
	Upstream struct {
		Module         string `json:"module"`
		Version        string `json:"version"`
		Revision       string `json:"revision"`
		ModuleChecksum string `json:"module_checksum"`
	} `json:"upstream"`
	CopiedData struct {
		NormalizationTable struct {
			SourceSHA256   string `json:"source_sha256"`
			ArtifactPath   string `json:"artifact_path"`
			ArtifactSHA256 string `json:"artifact_sha256"`
			Modification   string `json:"modification"`
		} `json:"normalization_table"`
		AssignmentTable struct {
			SourceSHA256   string `json:"source_sha256"`
			ArtifactPath   string `json:"artifact_path"`
			ArtifactSHA256 string `json:"artifact_sha256"`
			Extraction     string `json:"extraction"`
		} `json:"assignment_table"`
		SupplementaryRecomposition struct {
			UnicodeDataSHA256                    string `json:"unicode_data_sha256"`
			DerivedNormalizationPropertiesSHA256 string `json:"derived_normalization_properties_sha256"`
			ArtifactPath                         string `json:"artifact_path"`
			ArtifactSHA256                       string `json:"artifact_sha256"`
			Extraction                           string `json:"extraction"`
		} `json:"supplementary_recomposition"`
		NormalizerSupport struct {
			SourceFiles            map[string]string `json:"source_files"`
			ArtifactFiles          map[string]string `json:"artifact_files"`
			LicensePath            string            `json:"license_path"`
			LicenseSHA256          string            `json:"license_sha256"`
			LocalCodeModifications string            `json:"local_code_modifications"`
		} `json:"normalizer_support"`
	} `json:"copied_data"`
}

func loadProvenanceFixture(t *testing.T) provenanceFixture {
	t.Helper()
	var provenance provenanceFixture
	if err := json.Unmarshal(provenanceJSON, &provenance); err != nil {
		t.Fatalf("decode Unicode provenance: %v", err)
	}
	return provenance
}

func TestFrozenProvenancePinsExternalEvidence(t *testing.T) {
	provenance := loadProvenanceFixture(t)
	if provenance.Unicode.Version != literalUnicodeVersion || provenance.Unicode.Normalization.UAX15Revision != literalUAX15Revision {
		t.Fatal("provenance changed the frozen Unicode or UAX #15 revision")
	}
	if provenance.Unicode.UCD.NormalizationTest.SHA256 != literalNormalizationTestSHA256 ||
		provenance.Unicode.UCD.DerivedAge.SHA256 != literalDerivedAgeSHA256 ||
		provenance.Unicode.UCD.UnicodeData.SHA256 != literalUnicodeDataSHA256 ||
		provenance.Unicode.UCD.DerivedNormalizationProperties.SHA256 != literalDerivedNormalizationPropertiesSHA256 ||
		provenance.Unicode.Normalization.SHA256 != literalUAX15SHA256 {
		t.Fatal("provenance changed a pinned Unicode source hash")
	}
	if provenance.Upstream.Module != "golang.org/x/text" || provenance.Upstream.Version != "v0.40.0" || provenance.Upstream.Revision != "724af9c35838492dcaacc1ac51a8a0187c994c54" || provenance.Upstream.ModuleChecksum != "h1:Ub2Z6/xjgF1WrYQz2nuITOEegKFtiIy+rieRJ5lHZKs=" {
		t.Fatal("provenance changed the reviewed x/text source identity")
	}
	if provenance.CopiedData.NormalizationTable.SourceSHA256 != "ccd133df45368fb3f5e305c765e8f14be4e20fda2eb1355178a24d33aac0092d" || provenance.CopiedData.AssignmentTable.SourceSHA256 != "802650bc446dc9f6e3d105a0753b12ed9d77b370a5391aa21fb2caded8dd08b9" {
		t.Fatal("provenance changed an upstream copied-data hash")
	}
	if provenance.CopiedData.NormalizationTable.ArtifactPath != "norm18/tables18.go" || provenance.CopiedData.NormalizationTable.ArtifactSHA256 != "79a8f858755c55087895e396fc9884311916953cba71c99ebd6a61548ef21261" || provenance.CopiedData.NormalizationTable.Modification != "Removed only the isolated-generator pcv3_unicode18_generation build constraint; the generated Unicode-18 table data was not rewritten." {
		t.Fatal("provenance changed the reviewed local Unicode-18 normalization artifact")
	}
	if provenance.CopiedData.AssignmentTable.ArtifactPath != "assigned18.go" || provenance.CopiedData.AssignmentTable.ArtifactSHA256 != "061bb53b54e7f1a3f110f3b62c9c924208a83e76728a5a323654c451847cba77" || provenance.CopiedData.AssignmentTable.Extraction != "Exact assigned18_0_0 declaration extracted from the generated unicode/rangetable/tables18.0.0.go; no ranges were rewritten. The upstream generator derives the repertoire from UnicodeData.txt, including its First/Last ranges, rather than DerivedAge." {
		t.Fatal("provenance changed the reviewed local Unicode-18 assignment artifact")
	}
	if provenance.CopiedData.SupplementaryRecomposition.UnicodeDataSHA256 != literalUnicodeDataSHA256 ||
		provenance.CopiedData.SupplementaryRecomposition.DerivedNormalizationPropertiesSHA256 != literalDerivedNormalizationPropertiesSHA256 ||
		provenance.CopiedData.SupplementaryRecomposition.ArtifactPath != "norm18/recomposition18.go" ||
		provenance.CopiedData.SupplementaryRecomposition.ArtifactSHA256 != "4caab3f95a033f8124fd433c14e560ba6e7b764f7a3993103f1f51618d642f34" ||
		provenance.CopiedData.SupplementaryRecomposition.Extraction != "All 33 Unicode 18 canonical two-scalar compositions with at least one supplementary-plane operand, excluding Full_Composition_Exclusion entries; unmatched supplementary pairs never use the generated lookup." {
		t.Fatal("provenance changed the reviewed supplementary recomposition guard")
	}
}

func TestFrozenArtifactHashes(t *testing.T) {
	want := map[string]string{
		"LICENSE":                   "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
		"assigned18.go":             "061bb53b54e7f1a3f110f3b62c9c924208a83e76728a5a323654c451847cba77",
		"norm18/LICENSE":            "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
		"norm18/composition.go":     "1ba0a9b1293d1401cadc37972f9db15aeebac45df32f0b1dde659a2c07f8e917",
		"norm18/forminfo.go":        "5d6b13a0ff677de6f16bbcdfb90fd42e5518ab0bbc3ef6cb67532e0cc107c49e",
		"norm18/input.go":           "965b431790bb139543d71a9c497920ef7d9a15af417456a2bbd0cdb629330e8d",
		"norm18/iter.go":            "4d580123776d78ff862131bd8c99fa5758f3cb70530619edc80ed4ee173cd83a",
		"norm18/normalize.go":       "bbe1ffda0e883750a0b507b726f6bef504cda360605091db10c783c9e87fb50f",
		"norm18/recomposition18.go": "4caab3f95a033f8124fd433c14e560ba6e7b764f7a3993103f1f51618d642f34",
		"norm18/tables18.go":        "79a8f858755c55087895e396fc9884311916953cba71c99ebd6a61548ef21261",
		"norm18/transform.go":       "6f8014595643e2acae76d47ed6abe8ace969a0c9070dbfa5a89c86bebcec812d",
		"norm18/trie.go":            "d87793d558251ee8824954f0b7bc5564803e4c9d59a8c4eebb4c3c5cfbd19492",
	}

	for path, expected := range want {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read frozen artifact %s: %v", path, err)
		}
		sum := sha256.Sum256(contents)
		if actual := hex.EncodeToString(sum[:]); actual != expected {
			t.Fatalf("frozen artifact %s SHA-256 = %s, want %s", path, actual, expected)
		}
	}

	provenance := loadProvenanceFixture(t)
	if !reflect.DeepEqual(provenance.CopiedData.NormalizerSupport.ArtifactFiles, want) {
		t.Fatal("provenance artifact hashes no longer match the frozen implementation")
	}
	wantSources := map[string]string{
		"unicode/norm/composition.go": "3d1be52960f2693926472819b747646e7d2371d2bb5f53097cf9d46c913052df",
		"unicode/norm/forminfo.go":    "844dadc7a0dc991a4b87a195699476a90655292d302abe2d2f7ddff5968f74bc",
		"unicode/norm/input.go":       "965b431790bb139543d71a9c497920ef7d9a15af417456a2bbd0cdb629330e8d",
		"unicode/norm/iter.go":        "4d580123776d78ff862131bd8c99fa5758f3cb70530619edc80ed4ee173cd83a",
		"unicode/norm/normalize.go":   "9e4fdc543d3b7aabf046ead80f2ef60746f579a7a4691c3c7d6bf69f4c4fa713",
		"unicode/norm/transform.go":   "6f8014595643e2acae76d47ed6abe8ace969a0c9070dbfa5a89c86bebcec812d",
		"unicode/norm/trie.go":        "d87793d558251ee8824954f0b7bc5564803e4c9d59a8c4eebb4c3c5cfbd19492",
	}
	if !reflect.DeepEqual(provenance.CopiedData.NormalizerSupport.SourceFiles, wantSources) {
		t.Fatal("provenance source hashes no longer match the reviewed upstream files")
	}
	if provenance.CopiedData.NormalizerSupport.LicensePath != "LICENSE and norm18/LICENSE" || provenance.CopiedData.NormalizerSupport.LicenseSHA256 != "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad" || provenance.CopiedData.NormalizerSupport.LocalCodeModifications != "Retained the pinned x/text v0.40.0 support and existing sensitive-conversion annotations outside separately documented upstream v0.43.0 extractions. Adopted its three-21-bit-field uint64 recomposition-table reader/key construction while retaining the independent full-width supplementary guard and negative-rune defense. Replaced the complete compose and combineHangul function bodies with exact x/text v0.43.0 code to fix upstream issues 81001 and 81021: track intervening starters and continue ordinary canonical composition after Hangul. These NFC correctness fixes intentionally change previously incorrect credential bytes for affected sequences before the first release; experimental PCV3 volumes made with those old bytes are not guaranteed readable with the same password. Unicode-17 literal fixtures and the frozen volume corpus remain unchanged. Regenerated Unicode 18 tables and the supplementary pair set; changed frozen-version comments and removed the isolated generation table tag. The 1 MiB limits remain unchanged. The inherited internal Stream-Safe implementation is retained as a bounded evaluator; the outer credential profile now rejects any implicit U+034F insertion instead of accepting that extra mapping, and preserves explicit input U+034F as credential data." {
		t.Fatal("provenance changed the required BSD-3-Clause license record")
	}
}

// The outer rejection rule defines the accepted credential domain separately
// from the copied normalization tables and their internal Stream-Safe bound.
func TestFrozenCredentialProfileArtifact(t *testing.T) {
	const expected = "0b9378a0b112278567de9abbe660e9490081e31d67247b9d72ef01181288a02a"
	profile := loadProvenanceFixture(t).CredentialProfile
	if profile.ArtifactPath != "normalize.go" || profile.ArtifactSHA256 != expected {
		t.Fatal("provenance changed the reviewed outer credential profile")
	}
	contents, err := os.ReadFile("normalize.go")
	if err != nil {
		t.Fatalf("read frozen credential profile: %v", err)
	}
	sum := sha256.Sum256(contents)
	if hex.EncodeToString(sum[:]) != expected {
		t.Fatal("outer credential profile changed; review its accepted domain and cleanup guarantees before updating this checksum")
	}
}

// This policy check pins the generator patch, archive, reader provenance,
// source hashes, commands, and generated outputs as one reviewed document.
func TestFrozenGeneratorProvenanceDocument(t *testing.T) {
	sum := sha256.Sum256(provenanceJSON)
	if hex.EncodeToString(sum[:]) != "028df18dabe46c3367685df0ee2da3f51faadeacd218018d6ff63357acdeab86" {
		t.Fatal("frozen generator provenance changed; review source identities and reproduction before updating this checksum")
	}
}
