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
	literalUnicodeVersion = "17.0.0"
	literalUAX15Revision  = "57"

	literalNormalizationTestSHA256              = "5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db"
	literalDerivedAgeSHA256                     = "f8ecdf768bdc210f201abd271d9bc587825618a86a7046a8146cc816393f1998"
	literalUnicodeDataSHA256                    = "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c"
	literalDerivedNormalizationPropertiesSHA256 = "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488"
	literalUAX15SHA256                          = "c0c05f91e1c4f9be3d987e27d76cf254b30003b6be41eb94977cc3fe148d4c4e"
)

type provenanceFixture struct {
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
	if provenance.CopiedData.NormalizationTable.SourceSHA256 != "26784025eb1881a4452f101a7ef34b33c8ca02bd0603bfec41d2c823494ff7cb" || provenance.CopiedData.AssignmentTable.SourceSHA256 != "59da556571457cb08fdc4913dc614bd6a342a17d693f5cc4c3a1ffb510929cbd" {
		t.Fatal("provenance changed an upstream copied-data hash")
	}
	if provenance.CopiedData.NormalizationTable.ArtifactPath != "norm17/tables17.go" || provenance.CopiedData.NormalizationTable.ArtifactSHA256 != "e2aa3a26d408ac8c3e6ed34875cdb25feafa7e9bc215d8045636013699411f60" || provenance.CopiedData.NormalizationTable.Modification != "Removed only the upstream go1.27 build constraint so the frozen Unicode-17 data compiles under the pinned Go 1.26 toolchain." {
		t.Fatal("provenance changed the reviewed local Unicode-17 normalization artifact")
	}
	if provenance.CopiedData.AssignmentTable.ArtifactPath != "assigned17.go" || provenance.CopiedData.AssignmentTable.ArtifactSHA256 != "070dd459d8fa2fcaccbd7c6ccc86acac4ad0808ef965a3041f6d2ca7b18a2114" || provenance.CopiedData.AssignmentTable.Extraction != "Exact assigned17_0_0 declaration extracted from unicode/rangetable/tables17.0.0.go; no ranges were rewritten." {
		t.Fatal("provenance changed the reviewed local Unicode-17 assignment artifact")
	}
	if provenance.CopiedData.SupplementaryRecomposition.UnicodeDataSHA256 != literalUnicodeDataSHA256 ||
		provenance.CopiedData.SupplementaryRecomposition.DerivedNormalizationPropertiesSHA256 != literalDerivedNormalizationPropertiesSHA256 ||
		provenance.CopiedData.SupplementaryRecomposition.ArtifactPath != "norm17/recomposition17.go" ||
		provenance.CopiedData.SupplementaryRecomposition.ArtifactSHA256 != "3db85120aaf91ab9f8cb7afdef408fdcfc0f0c947d98fedf0013a7e2e1a51e9e" ||
		provenance.CopiedData.SupplementaryRecomposition.Extraction != "All 33 Unicode 17 canonical two-scalar compositions with at least one supplementary-plane operand, excluding Full_Composition_Exclusion entries; unmatched supplementary pairs never use the 16-bit packed lookup." {
		t.Fatal("provenance changed the reviewed supplementary recomposition guard")
	}
}

func TestFrozenArtifactHashes(t *testing.T) {
	want := map[string]string{
		"LICENSE":                   "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
		"assigned17.go":             "070dd459d8fa2fcaccbd7c6ccc86acac4ad0808ef965a3041f6d2ca7b18a2114",
		"norm17/LICENSE":            "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
		"norm17/composition.go":     "71f32e63abefbcf84fbd6812fe87c2b1e97b5ce8b152f4c11647836661cd02f9",
		"norm17/forminfo.go":        "89d49b25c82c4fee420305b255cac9f270bbcdc1f33e8cf7853dd2a8467e42ec",
		"norm17/input.go":           "965b431790bb139543d71a9c497920ef7d9a15af417456a2bbd0cdb629330e8d",
		"norm17/iter.go":            "4d580123776d78ff862131bd8c99fa5758f3cb70530619edc80ed4ee173cd83a",
		"norm17/normalize.go":       "706fc4731c847f4b9d8b4022efd1bc5a8a4e076c44cb37442e5ac62fd6014838",
		"norm17/recomposition17.go": "3db85120aaf91ab9f8cb7afdef408fdcfc0f0c947d98fedf0013a7e2e1a51e9e",
		"norm17/tables17.go":        "e2aa3a26d408ac8c3e6ed34875cdb25feafa7e9bc215d8045636013699411f60",
		"norm17/transform.go":       "6f8014595643e2acae76d47ed6abe8ace969a0c9070dbfa5a89c86bebcec812d",
		"norm17/trie.go":            "d87793d558251ee8824954f0b7bc5564803e4c9d59a8c4eebb4c3c5cfbd19492",
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
	if provenance.CopiedData.NormalizerSupport.LicensePath != "LICENSE and norm17/LICENSE" || provenance.CopiedData.NormalizerSupport.LicenseSHA256 != "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad" || provenance.CopiedData.NormalizerSupport.LocalCodeModifications != "Removed upstream go:generate directives and canonical import comment from norm17/normalize.go; removed the Go 1.27 build constraint from tables17.go; added a provenance-pinned full-width supplementary recomposition guard for all 33 Unicode 17 mappings; documented the fixed bounds of seven inherited integer conversions for gosec." {
		t.Fatal("provenance changed the required BSD-3-Clause license record")
	}
}
