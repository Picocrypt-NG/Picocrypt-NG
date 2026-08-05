package pcv3corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const testCustodyID = "synthetic-test-custody"

const testSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pcv3.invalid/phase1/manifest.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["format", "schema_revision", "spec_revision", "test_only", "custody_id", "fixtures", "deferred_vector_classes"],
  "properties": {
    "format": {"const": "pcv3-phase1-corpus-v1"},
    "schema_revision": {"const": "1"},
    "spec_revision": {"const": "0.3"},
    "test_only": {"const": true},
    "custody_id": {"type": "string", "minLength": 1},
    "fixtures": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/fixture"}},
    "deferred_vector_classes": {
      "type": "array",
      "minItems": 1,
      "items": {"type": "string"},
      "contains": {"const": "full-pcv3-volume"}
    }
  },
  "$defs": {
    "fixture": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "path", "sha256", "provenance_path", "provenance_sha256", "category", "outcome", "failure_stage", "kdf_calls", "publication_state", "force_state", "status", "generated_at_test_time"],
      "properties": {
        "id": {"type": "string", "minLength": 1},
        "path": {"type": "string", "minLength": 1},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "provenance_path": {"type": "string", "minLength": 1},
        "provenance_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "category": {"enum": ["unicode17", "governance"]},
        "outcome": {"enum": ["accept", "reject"]},
        "failure_stage": {"enum": ["none", "canonicalization", "governance"]},
        "kdf_calls": {"const": 0},
        "publication_state": {"enum": ["not-published", "not-applicable"]},
        "force_state": {"const": "not-applicable"},
        "status": {"enum": ["required", "skipped"]},
        "generated_at_test_time": {"type": "boolean"}
      }
    }
  }
}`

const permissiveManifestSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pcv3.invalid/phase1/manifest.schema.json",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "format": {},
    "schema_revision": {},
    "spec_revision": {},
    "test_only": {},
    "custody_id": {},
    "fixtures": {"type": "array", "items": {"type": "object", "additionalProperties": true}},
    "deferred_vector_classes": {}
  }
}`

const (
	positiveFixture           = `{"test_only":true,"id":"unicode17-nfc","category":"unicode17","case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9","status":"required","generated_at_test_time":false}`
	negativeFixture           = `{"test_only":true,"id":"unicode17-unassigned","category":"unicode17","case":"unicode17-unassigned","input_hex":"cdb8","expected":"reject","status":"required","generated_at_test_time":false}`
	acceptingSecondFixture    = `{"test_only":true,"id":"unicode17-unassigned","category":"unicode17","case":"unicode17-unassigned","input_hex":"cdb8","expected_hex":"cdb8","status":"required","generated_at_test_time":false}`
	independentProvenance     = `{"test_only":true,"author":"independent-fixture-author","generator":"unicode-ucd-transcription","generator_version":"1","source_revision":"Unicode 17.0.0 NormalizationTest.txt line 141","source_sha256":"5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db","dependency_lock":"curl=8.21.0;awk=POSIX.1-2017","dependency_lock_sha256":"e2436c779e713dbe3c07487b87783edd55bad383139a9f21a7293c812d6794f6","reproduction_command":"curl --fail --proto '=https' --tlsv1.2 --silent --show-error https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt | awk 'NR==141 {print}'","independent_of_production":true,"production_code":false}`
	notTestOnlyFixture        = `{"test_only":false,"id":"unicode17-nfc","category":"unicode17","case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9","status":"required","generated_at_test_time":false}`
	generatedFixture          = `{"test_only":true,"id":"unicode17-nfc","category":"unicode17","case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9","status":"required","generated_at_test_time":true}`
	skippedFixture            = `{"test_only":true,"id":"unicode17-nfc","category":"unicode17","case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9","status":"skipped","generated_at_test_time":false}`
	vacuousFixture            = `{"test_only":true,"id":"unicode17-nfc","category":"unicode17","case":"unicode17-nfc","expected_hex":"c3a9","status":"required","generated_at_test_time":false}`
	unknownFixtureField       = `{"test_only":true,"id":"unicode17-nfc","category":"unicode17","case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9","status":"required","generated_at_test_time":false,"unexpected":true}`
	mismatchedIDFixture       = `{"test_only":true,"id":"other","category":"unicode17","case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9","status":"required","generated_at_test_time":false}`
	mismatchedCaseFixture     = `{"test_only":true,"id":"unicode17-nfc","category":"unicode17","case":"other","input_hex":"65cc81","expected_hex":"c3a9","status":"required","generated_at_test_time":false}`
	mismatchedCategoryFixture = `{"test_only":true,"id":"unicode17-nfc","category":"governance","case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9","status":"required","generated_at_test_time":false}`
	rejectingFirstFixture     = `{"test_only":true,"id":"unicode17-nfc","category":"unicode17","case":"unicode17-nfc","input_hex":"65cc81","expected":"reject","status":"required","generated_at_test_time":false}`
)

const (
	positiveFixtureSHA           = "3ed44cdcbf811e609454358071913c0219d2d32f14fb2a7278654ab04d66a432"
	negativeFixtureSHA           = "ac06da8ecaa484eccac56fe29e6c899450b1f7911b7806230189963ce8d5aaa3"
	acceptingSecondFixtureSHA    = "8ba805684f9279436360d674411a11e82f60e647896b0d62721d64d073450cdb"
	independentProvenanceSHA     = "80c540bb6a29561b7f12393afdafe7fd8b8f2d1e21f14e80b5df81ff82ddff17"
	notTestOnlyFixtureSHA        = "1dc1422c2ea10c8253cb6e395f3fff720ce550e3dfe3cc5c4b5f5acda2f4e78e"
	generatedFixtureSHA          = "45d8777389db5e6a33dbff74becd876f361fb910174d7c495ca4247744b6ef08"
	skippedFixtureSHA            = "9b6eb8713d4adda9da93527268d0ed786093c26d4de1b8b92d91e141fb6b1c5c"
	vacuousFixtureSHA            = "3547bd18423af0a2f4ba374edc11848edf8d0cc7748ff6f6a00ea7d8338fb6f6"
	unknownFixtureFieldSHA       = "6eeb55c600123c67a6391b9fd4df048a120ec210322f3f2886b82caa34e47899"
	mismatchedIDFixtureSHA       = "c67fdfff8d88b4006a2175ebd8b4621b27479e0d6e6f8e3e67d45b78ef0607aa"
	mismatchedCaseFixtureSHA     = "ba9a192f3bc5857b14b067f06b8cb8f8f2f194c5829ea9b28b76c48b878a2c82"
	mismatchedCategoryFixtureSHA = "3cdb8770651f1a4edaf15fe4c9bf3d5e27a4d3ddd760541d837ecfa702e767b1"
	rejectingFirstFixtureSHA     = "0df95fdd222fd8d56112c2b2377f093f8a31cd20b686f204ea541aa0192aaadd"
)

const testManifest = `{
  "format": "pcv3-phase1-corpus-v1",
  "schema_revision": "1",
  "spec_revision": "0.3",
  "test_only": true,
  "custody_id": "synthetic-test-custody",
  "fixtures": [
    {
      "id": "unicode17-nfc",
      "path": "positive/nfc.json",
      "sha256": "3ed44cdcbf811e609454358071913c0219d2d32f14fb2a7278654ab04d66a432",
      "provenance_path": "provenance/nfc.json",
      "provenance_sha256": "80c540bb6a29561b7f12393afdafe7fd8b8f2d1e21f14e80b5df81ff82ddff17",
      "category": "unicode17",
      "outcome": "accept",
      "failure_stage": "none",
      "kdf_calls": 0,
      "publication_state": "not-published",
      "force_state": "not-applicable",
      "status": "required",
      "generated_at_test_time": false
    },
    {
      "id": "unicode17-unassigned",
      "path": "negative/reject-unassigned.json",
      "sha256": "ac06da8ecaa484eccac56fe29e6c899450b1f7911b7806230189963ce8d5aaa3",
      "provenance_path": "provenance/reject-unassigned.json",
      "provenance_sha256": "80c540bb6a29561b7f12393afdafe7fd8b8f2d1e21f14e80b5df81ff82ddff17",
      "category": "unicode17",
      "outcome": "reject",
      "failure_stage": "canonicalization",
      "kdf_calls": 0,
      "publication_state": "not-published",
      "force_state": "not-applicable",
      "status": "required",
      "generated_at_test_time": false
    }
  ],
  "deferred_vector_classes": ["full-pcv3-volume"]
}`

func TestLoadAcceptsLiteralPhaseOneCorpus(t *testing.T) {
	root := writeTestCorpus(t)

	corpus, err := Load(root, testCustodyID)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if corpus == nil {
		t.Fatal("Load() returned nil corpus after validating literal fixtures")
	}
}

func TestLoadRefusesActualCorpusMutations(t *testing.T) {
	tests := []struct {
		name    string
		want    RefusalKind
		mutate  func(t *testing.T, root string)
		custody string
	}{
		{
			name: "missing required fixture",
			want: RefusalMissing,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "negative", "reject-unassigned.json")); err != nil {
					t.Fatalf("remove required synthetic fixture: %v", err)
				}
			},
		},
		{
			name: "extra file",
			want: RefusalExtra,
			mutate: func(t *testing.T, root string) {
				writeTestFile(t, root, "unexpected.json", "{}")
			},
		},
		{
			name: "extra directory",
			want: RefusalExtra,
			mutate: func(t *testing.T, root string) {
				if err := os.Mkdir(filepath.Join(root, "unexpected"), 0o700); err != nil {
					t.Fatalf("create extra synthetic directory: %v", err)
				}
			},
		},
		{
			name: "unknown manifest field",
			want: RefusalUnknown,
			mutate: func(t *testing.T, root string) {
				replaceManifest(t, root, `"format": "pcv3-phase1-corpus-v1"`, `"unknown": true, "format": "pcv3-phase1-corpus-v1"`)
			},
		},
		{
			name: "duplicate manifest field",
			want: RefusalDuplicate,
			mutate: func(t *testing.T, root string) {
				replaceManifest(t, root, `"format": "pcv3-phase1-corpus-v1"`, `"format": "pcv3-phase1-corpus-v1", "format": "pcv3-phase1-corpus-v1"`)
			},
		},
		{
			name: "generated expected value marker",
			want: RefusalGenerated,
			mutate: func(t *testing.T, root string) {
				replaceManifest(t, root, `"generated_at_test_time": false`, `"generated_at_test_time": true`)
			},
		},
		{
			name: "skipped required fixture",
			want: RefusalSkipped,
			mutate: func(t *testing.T, root string) {
				replaceManifest(t, root, `"status": "required"`, `"status": "skipped"`)
			},
		},
		{
			name: "unknown future category",
			want: RefusalUnknown,
			mutate: func(t *testing.T, root string) {
				replaceManifest(t, root, `"category": "unicode17"`, `"category": "future-category"`)
			},
		},
		{
			name: "duplicate fixture path",
			want: RefusalDuplicate,
			mutate: func(t *testing.T, root string) {
				replaceManifest(t, root, `"path": "negative/reject-unassigned.json"`, `"path": "positive/nfc.json"`)
			},
		},
		{
			name: "fixture hash mismatch",
			want: RefusalHash,
			mutate: func(t *testing.T, root string) {
				writeTestFile(t, root, "positive/nfc.json", `{"test_only":true,"case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"00"}`)
			},
		},
		{
			name:    "mismatched custody",
			want:    RefusalCustody,
			mutate:  func(t *testing.T, root string) {},
			custody: "different-nonsecret-custody",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestCorpus(t)
			tt.mutate(t, root)
			custody := tt.custody
			if custody == "" {
				custody = testCustodyID
			}
			_, err := Load(root, custody)
			assertRefusal(t, err, tt.want)
		})
	}
}

func TestLoadRefusesUnsafeLogicalFixturePathsBeforeFilesystemAccess(t *testing.T) {
	for _, unsafePath := range []string{
		".",
		"../escape.json",
		"positive/../escape.json",
		"/absolute.json",
		"C:relative.json",
		"C:/absolute.json",
		`\\server\\share`,
		`\\?\\C:\\extended`,
		`positive\\backslash.json`,
	} {
		t.Run(unsafePath, func(t *testing.T) {
			root := writeTestCorpus(t)
			replaceManifest(t, root, `"path": "positive/nfc.json"`, `"path": `+strconv.Quote(unsafePath))
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, RefusalPath)
		})
	}
}

func TestLoadRefusesFixturePathsOutsidePhaseOneDirectories(t *testing.T) {
	root := writeTestCorpus(t)
	replaceManifest(t, root, `"path": "positive/nfc.json"`, `"path": "other/nfc.json"`)

	_, err := Load(root, testCustodyID)
	assertRefusal(t, err, RefusalPath)
}

func TestLoadRequiresBothFixtureDirectionsAndMatchingPaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, root string)
	}{
		{
			name: "all accepting fixtures in positive directory",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "negative", "reject-unassigned.json")); err != nil {
					t.Fatalf("remove rejecting fixture: %v", err)
				}
				if err := os.Remove(filepath.Join(root, "negative")); err != nil {
					t.Fatalf("remove now-empty negative directory: %v", err)
				}
				writeTestFile(t, root, "positive/accept-unassigned.json", acceptingSecondFixture)
				manifest := strings.NewReplacer(
					`"path": "negative/reject-unassigned.json"`, `"path": "positive/accept-unassigned.json"`,
					negativeFixtureSHA, acceptingSecondFixtureSHA,
					`"outcome": "reject"`, `"outcome": "accept"`,
					`"failure_stage": "canonicalization"`, `"failure_stage": "none"`,
				).Replace(testManifest)
				writeTestFile(t, root, "manifest.json", manifest)
			},
		},
		{
			name: "all rejecting fixtures in negative directory",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "positive", "nfc.json")); err != nil {
					t.Fatalf("remove accepting fixture: %v", err)
				}
				if err := os.Remove(filepath.Join(root, "positive")); err != nil {
					t.Fatalf("remove now-empty positive directory: %v", err)
				}
				writeTestFile(t, root, "negative/reject-nfc.json", rejectingFirstFixture)
				manifest := strings.NewReplacer(
					`"path": "positive/nfc.json"`, `"path": "negative/reject-nfc.json"`,
					positiveFixtureSHA, rejectingFirstFixtureSHA,
					`"outcome": "accept"`, `"outcome": "reject"`,
					`"failure_stage": "none"`, `"failure_stage": "canonicalization"`,
				).Replace(testManifest)
				writeTestFile(t, root, "manifest.json", manifest)
			},
		},
		{
			name: "accepting fixture stored in negative directory",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Rename(filepath.Join(root, "positive", "nfc.json"), filepath.Join(root, "negative", "nfc.json")); err != nil {
					t.Fatalf("move accepting fixture to negative directory: %v", err)
				}
				if err := os.Remove(filepath.Join(root, "positive")); err != nil {
					t.Fatalf("remove now-empty positive directory: %v", err)
				}
				replaceManifest(t, root, `"path": "positive/nfc.json"`, `"path": "negative/nfc.json"`)
			},
		},
		{
			name: "rejecting fixture stored in positive directory",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Rename(filepath.Join(root, "negative", "reject-unassigned.json"), filepath.Join(root, "positive", "reject-unassigned.json")); err != nil {
					t.Fatalf("move rejecting fixture to positive directory: %v", err)
				}
				if err := os.Remove(filepath.Join(root, "negative")); err != nil {
					t.Fatalf("remove now-empty negative directory: %v", err)
				}
				replaceManifest(t, root, `"path": "negative/reject-unassigned.json"`, `"path": "positive/reject-unassigned.json"`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestCorpus(t)
			tt.mutate(t, root)
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, RefusalMalformed)
		})
	}
}

func TestLoadRefusesProvenanceHashMismatch(t *testing.T) {
	root := writeTestCorpus(t)
	tampered := strings.Replace(independentProvenance, `"author":"independent-fixture-author"`, `"author":"tampered-independent-fixture-author"`, 1)
	if tampered == independentProvenance {
		t.Fatal("test mutation did not alter the literal provenance")
	}
	writeTestFile(t, root, "provenance/nfc.json", tampered)

	_, err := Load(root, testCustodyID)
	assertRefusal(t, err, RefusalHash)
}

func TestLoadRequiresEveryProvenanceEvidenceField(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, provenance string) string
	}{
		{
			name: "test-only marker is false",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"test_only":true`, `"test_only":false`)
			},
		},
		{
			name: "author is empty",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"author":"independent-fixture-author"`, `"author":""`)
			},
		},
		{
			name: "generator is empty",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"generator":"unicode-ucd-transcription"`, `"generator":""`)
			},
		},
		{
			name: "generator version is empty",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"generator_version":"1"`, `"generator_version":""`)
			},
		},
		{
			name: "source revision is empty",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"source_revision":"Unicode 17.0.0 NormalizationTest.txt line 141"`, `"source_revision":""`)
			},
		},
		{
			name: "source hash is not a SHA-256 pin",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"source_sha256":"5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db"`, `"source_sha256":"not-a-sha256-pin"`)
			},
		},
		{
			name: "dependency lock is empty despite matching empty pin",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"dependency_lock":"curl=8.21.0;awk=POSIX.1-2017","dependency_lock_sha256":"e2436c779e713dbe3c07487b87783edd55bad383139a9f21a7293c812d6794f6"`, `"dependency_lock":"","dependency_lock_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`)
			},
		},
		{
			name: "dependency lock does not match its pin",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"dependency_lock_sha256":"e2436c779e713dbe3c07487b87783edd55bad383139a9f21a7293c812d6794f6"`, `"dependency_lock_sha256":"0000000000000000000000000000000000000000000000000000000000000000"`)
			},
		},
		{
			name: "reproduction command is empty",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"reproduction_command":"curl --fail --proto '=https' --tlsv1.2 --silent --show-error https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt | awk 'NR==141 {print}'"`, `"reproduction_command":""`)
			},
		},
		{
			name: "independence claim is false",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"independent_of_production":true`, `"independent_of_production":false`)
			},
		},
		{
			name: "production provenance is true",
			mutate: func(t *testing.T, provenance string) string {
				return replaceLiteral(t, provenance, `"production_code":false`, `"production_code":true`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestCorpus(t)
			replacePositiveProvenance(t, root, tt.mutate(t, independentProvenance))
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, RefusalProvenance)
		})
	}
}

func TestLoadRequiresTestOnlyFixtureContents(t *testing.T) {
	root := writeTestCorpus(t)
	writeTestFile(t, root, "positive/nfc.json", notTestOnlyFixture)
	replaceManifest(t, root, positiveFixtureSHA, notTestOnlyFixtureSHA)

	_, err := Load(root, testCustodyID)
	assertRefusal(t, err, RefusalMalformed)
}

func TestLoadRequiresNonVacuousFixtureEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		content string
		hash    string
		want    RefusalKind
	}{
		{
			name:    "fixture generated at test time",
			content: generatedFixture,
			hash:    generatedFixtureSHA,
			want:    RefusalGenerated,
		},
		{
			name:    "fixture skipped",
			content: skippedFixture,
			hash:    skippedFixtureSHA,
			want:    RefusalSkipped,
		},
		{
			name:    "fixture missing input",
			content: vacuousFixture,
			hash:    vacuousFixtureSHA,
			want:    RefusalMalformed,
		},
		{
			name:    "fixture unknown field",
			content: unknownFixtureField,
			hash:    unknownFixtureFieldSHA,
			want:    RefusalUnknown,
		},
		{
			name:    "fixture ID differs from manifest",
			content: mismatchedIDFixture,
			hash:    mismatchedIDFixtureSHA,
			want:    RefusalMalformed,
		},
		{
			name:    "fixture case differs from manifest ID",
			content: mismatchedCaseFixture,
			hash:    mismatchedCaseFixtureSHA,
			want:    RefusalMalformed,
		},
		{
			name:    "fixture category differs from manifest",
			content: mismatchedCategoryFixture,
			hash:    mismatchedCategoryFixtureSHA,
			want:    RefusalMalformed,
		},
		{
			name:    "fixture contradicts accepting manifest outcome",
			content: rejectingFirstFixture,
			hash:    rejectingFirstFixtureSHA,
			want:    RefusalMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestCorpus(t)
			replacePositiveFixture(t, root, tt.content, tt.hash)
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, tt.want)
		})
	}
}

func TestLoadRefusesSchemaPermittedUnknownFixtureSemantics(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		want        RefusalKind
	}{
		{
			name:        "unknown outcome",
			old:         `"outcome": "accept"`,
			replacement: `"outcome": "future-outcome"`,
			want:        RefusalUnknown,
		},
		{
			name:        "unknown failure stage",
			old:         `"failure_stage": "none"`,
			replacement: `"failure_stage": "future-stage"`,
			want:        RefusalUnknown,
		},
		{
			name:        "wrong unicode rejection failure stage",
			old:         `"failure_stage": "canonicalization"`,
			replacement: `"failure_stage": "governance"`,
			want:        RefusalMalformed,
		},
		{
			name:        "unknown publication state",
			old:         `"publication_state": "not-published"`,
			replacement: `"publication_state": "future-publication"`,
			want:        RefusalUnknown,
		},
		{
			name:        "unknown force state",
			old:         `"force_state": "not-applicable"`,
			replacement: `"force_state": "future-force"`,
			want:        RefusalUnknown,
		},
		{
			name:        "unknown fixture status",
			old:         `"status": "required"`,
			replacement: `"status": "future-status"`,
			want:        RefusalUnknown,
		},
		{
			name:        "nonzero KDF calls",
			old:         `"kdf_calls": 0`,
			replacement: `"kdf_calls": 1`,
			want:        RefusalMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestCorpus(t)
			writeTestFile(t, root, "manifest.schema.json", permissiveManifestSchema)
			replaceManifest(t, root, tt.old, tt.replacement)
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, tt.want)
		})
	}
}

func TestLoadRefusesMalformedSchemaOrManifest(t *testing.T) {
	tests := []struct {
		name   string
		want   RefusalKind
		mutate func(t *testing.T, root string)
	}{
		{
			name: "missing schema",
			want: RefusalMissing,
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "manifest.schema.json")); err != nil {
					t.Fatalf("remove synthetic schema: %v", err)
				}
			},
		},
		{
			name: "malformed schema",
			want: RefusalSchema,
			mutate: func(t *testing.T, root string) {
				writeTestFile(t, root, "manifest.schema.json", `{`)
			},
		},
		{
			name: "schema resource identity mismatch",
			want: RefusalSchema,
			mutate: func(t *testing.T, root string) {
				replaceSchema(t, root, `"$id": "https://pcv3.invalid/phase1/manifest.schema.json"`, `"$id": "https://pcv3.invalid/phase1/other.schema.json"`)
			},
		},
		{
			name: "malformed manifest",
			want: RefusalMalformed,
			mutate: func(t *testing.T, root string) {
				writeTestFile(t, root, "manifest.json", `{`)
			},
		},
		{
			name: "overly nested manifest",
			want: RefusalMalformed,
			mutate: func(t *testing.T, root string) {
				writeTestFile(t, root, "manifest.json", strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestCorpus(t)
			tt.mutate(t, root)
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, tt.want)
		})
	}
}

func TestLoadRejectsExternalSchemaReferencesWithoutFallback(t *testing.T) {
	root := writeTestCorpus(t)
	externalRoot := t.TempDir()
	externalSchema := filepath.Join(externalRoot, "permissive.json")
	if err := os.WriteFile(externalSchema, []byte(`{"type":"object"}`), 0o600); err != nil {
		t.Fatalf("write external schema sentinel: %v", err)
	}

	externalFileURL := (&url.URL{Scheme: "file", Path: externalSchema}).String()
	for _, reference := range []string{
		externalFileURL,
		"https://pcv3.invalid/external.json",
		"http://pcv3.invalid/external.json",
		"unregistered.json",
	} {
		t.Run(reference, func(t *testing.T) {
			caseRoot := copyTestCorpus(t, root)
			writeTestFile(t, caseRoot, "manifest.schema.json", schemaWithExternalReference(t, reference))
			_, err := Load(caseRoot, testCustodyID)
			assertRefusal(t, err, RefusalSchema)
		})
	}
}

func TestExternalSchemaSentinelWouldAcceptLiteralManifestWithFileFallback(t *testing.T) {
	externalRoot := t.TempDir()
	externalSchema := filepath.Join(externalRoot, "permissive.json")
	if err := os.WriteFile(externalSchema, []byte(`{"type":"object"}`), 0o600); err != nil {
		t.Fatalf("write external schema sentinel: %v", err)
	}

	schemaDocument, err := decodeStrictJSON([]byte(schemaWithExternalReference(t, (&url.URL{Scheme: "file", Path: externalSchema}).String())))
	if err != nil {
		t.Fatalf("decode hostile schema: %v", err)
	}
	manifestDocument, err := decodeStrictJSON([]byte(testManifest))
	if err != nil {
		t.Fatalf("decode literal manifest: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(jsonschema.FileLoader{})
	if err := compiler.AddResource(manifestSchemaResourceURL, schemaDocument); err != nil {
		t.Fatalf("add hostile schema resource: %v", err)
	}
	schema, err := compiler.Compile(manifestSchemaResourceURL)
	if err != nil {
		t.Fatalf("compile hostile schema with file fallback: %v", err)
	}
	if err := schema.Validate(manifestDocument); err != nil {
		t.Fatalf("hostile schema must otherwise accept the literal manifest: %v", err)
	}
}

func schemaWithExternalReference(t *testing.T, reference string) string {
	t.Helper()
	schema, found := strings.CutSuffix(strings.TrimSpace(testSchema), "}")
	if !found {
		t.Fatal("literal manifest schema must end with an object delimiter")
	}
	return schema + `,"allOf":[{"$ref":` + strconv.Quote(reference) + `}]}`
}

func TestLoadDoesNotExposeSuppliedRoot(t *testing.T) {
	root := writeTestCorpus(t)
	_, err := Load(root, "mismatched-custody")
	assertRefusal(t, err, RefusalCustody)
	if strings.Contains(err.Error(), root) {
		t.Fatal("Load() error exposed the supplied private root")
	}
}

func TestLoadDoesNotExposeUnavailableSuppliedRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-corpus-root")
	_, err := Load(root, testCustodyID)
	assertRefusal(t, err, RefusalRoot)
	if strings.Contains(err.Error(), root) {
		t.Fatal("Load() unavailable-root error exposed the supplied private root")
	}
}

func writeTestCorpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "manifest.schema.json", testSchema)
	writeTestFile(t, root, "manifest.json", testManifest)
	writeTestFile(t, root, "positive/nfc.json", positiveFixture)
	writeTestFile(t, root, "negative/reject-unassigned.json", negativeFixture)
	writeTestFile(t, root, "provenance/nfc.json", independentProvenance)
	writeTestFile(t, root, "provenance/reject-unassigned.json", independentProvenance)
	return root
}

func copyTestCorpus(t *testing.T, source string) string {
	t.Helper()
	target := t.TempDir()
	for _, name := range []string{
		"manifest.schema.json",
		"manifest.json",
		"positive/nfc.json",
		"negative/reject-unassigned.json",
		"provenance/nfc.json",
		"provenance/reject-unassigned.json",
	} {
		data, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read literal synthetic fixture: %v", err)
		}
		writeTestFile(t, target, name, string(data))
	}
	return target
}

func writeTestFile(t *testing.T, root, logicalName, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(logicalName))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create synthetic fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write synthetic fixture: %v", err)
	}
}

func replaceManifest(t *testing.T, root, old, replacement string) {
	t.Helper()
	updated := strings.Replace(testManifest, old, replacement, 1)
	if updated == testManifest {
		t.Fatal("test mutation did not alter the literal manifest")
	}
	writeTestFile(t, root, "manifest.json", updated)
}

func replacePositiveFixture(t *testing.T, root, contents, hash string) {
	t.Helper()
	writeTestFile(t, root, "positive/nfc.json", contents)
	replaceManifest(t, root, positiveFixtureSHA, hash)
}

// replacePositiveProvenance re-pins only a deliberately mutated test document.
// Its hash is computed independently from the loader so field-validation tests
// reach their intended provenance checks instead of stopping at the pin.
func replacePositiveProvenance(t *testing.T, root, contents string) {
	t.Helper()
	writeTestFile(t, root, "provenance/nfc.json", contents)
	digest := sha256.Sum256([]byte(contents))
	replaceManifest(t, root, independentProvenanceSHA, hex.EncodeToString(digest[:]))
}

func replaceLiteral(t *testing.T, value, old, replacement string) string {
	t.Helper()
	updated := strings.Replace(value, old, replacement, 1)
	if updated == value {
		t.Fatalf("test mutation did not alter literal %q", old)
	}
	return updated
}

func replaceSchema(t *testing.T, root, old, replacement string) {
	t.Helper()
	updated := strings.Replace(testSchema, old, replacement, 1)
	if updated == testSchema {
		t.Fatal("test mutation did not alter the literal schema")
	}
	writeTestFile(t, root, "manifest.schema.json", updated)
}

func assertRefusal(t *testing.T, err error, want RefusalKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("Load() unexpectedly succeeded; want refusal %q", want)
	}
	var refusal *RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("Load() error type = %T, want *RefusalError", err)
	}
	if refusal.Kind != want {
		t.Fatalf("Load() refusal = %q, want %q", refusal.Kind, want)
	}
}

const testSchemaV2 = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pcv3.invalid/cumulative/manifest.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["format", "schema_revision", "spec_revision", "test_only", "custody_id", "fixtures", "deferred_vector_classes"],
  "properties": {
    "format": {"const": "pcv3-corpus-v2"},
    "schema_revision": {"const": "2"},
    "spec_revision": {"const": "0.3"},
    "test_only": {"const": true},
    "custody_id": {"type": "string", "minLength": 1},
    "fixtures": {"type": "array", "minItems": 4, "items": {"$ref": "#/$defs/fixture"}},
    "deferred_vector_classes": {
      "type": "array",
      "minItems": 1,
      "items": {"type": "string"},
      "contains": {"const": "full-pcv3-volume"}
    }
  },
  "$defs": {
    "fixture": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "path", "sha256", "provenance_path", "provenance_sha256", "category", "outcome", "failure_stage", "kdf_calls", "publication_state", "force_state", "status", "generated_at_test_time"],
      "properties": {
        "id": {"type": "string", "minLength": 1},
        "path": {"type": "string", "minLength": 1},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "provenance_path": {"type": "string", "minLength": 1},
        "provenance_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "generator_source_path": {"type": "string", "minLength": 1},
        "generator_source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "category": {"enum": ["unicode17", "governance", "stream", "capsule"]},
        "outcome": {"enum": ["accept", "reject", "success", "authenticated-degraded", "credentials-or-damage", "invalid-structure-pre-kdf", "ambiguous-volume"]},
        "failure_stage": {"enum": ["none", "canonicalization", "governance", "wrap-auth", "replica-auth", "capsule-structure"]},
        "kdf_calls": {"type": "integer", "minimum": 0, "maximum": 1},
        "publication_state": {"enum": ["not-published", "not-applicable"]},
        "force_state": {"const": "not-applicable"},
        "status": {"const": "required"},
        "generated_at_test_time": {"const": false}
      }
    }
  }
}`

const (
	testV2GeneratorSource = "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"TEST ONLY\") }\n"
	testV2Hex32           = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testV2Hex24           = "202122232425262728292a2b2c2d2e2f3031323334353637"
	testV2Hex16           = "404142434445464748494a4b4c4d4e4f"
)

type testV2Fixture struct {
	id, category, caseName, suite string
	outcome, stage                string
	kdfCalls, authenticated       int
}

var testV2Phase4Fixtures = []testV2Fixture{
	{id: "stream-standard1-wrap", category: "stream", caseName: "standard1-wrap", suite: "standard1", outcome: "accept", stage: "none"},
	{id: "stream-paranoid1-wrap", category: "stream", caseName: "paranoid1-wrap", suite: "paranoid1", outcome: "accept", stage: "none"},
	{id: "capsule-standard1-healthy", category: "capsule", caseName: "healthy-standard1", suite: "standard1", outcome: "success", stage: "none", kdfCalls: 1, authenticated: 2},
	{id: "capsule-paranoid1-healthy", category: "capsule", caseName: "healthy-paranoid1", suite: "paranoid1", outcome: "success", stage: "none", kdfCalls: 1, authenticated: 2},
	{id: "capsule-damaged-wrap-tag", category: "capsule", caseName: "damaged-wrap-tag", suite: "standard1", outcome: "authenticated-degraded", stage: "wrap-auth", kdfCalls: 1, authenticated: 1},
	{id: "capsule-damaged-replica-tag", category: "capsule", caseName: "damaged-replica-tag", suite: "standard1", outcome: "authenticated-degraded", stage: "replica-auth", kdfCalls: 1, authenticated: 1},
	{id: "capsule-wrong-credential", category: "capsule", caseName: "wrong-credential", suite: "standard1", outcome: "credentials-or-damage", stage: "wrap-auth", kdfCalls: 1},
	{id: "capsule-divergent-public-tuple", category: "capsule", caseName: "divergent-public-tuple", suite: "standard1", outcome: "invalid-structure-pre-kdf", stage: "capsule-structure"},
	{id: "capsule-authenticated-cross-volume-splice", category: "capsule", caseName: "authenticated-cross-volume-splice", suite: "standard1", outcome: "ambiguous-volume", stage: "capsule-structure", kdfCalls: 1, authenticated: 2},
}

func TestLoadAcceptsLiteralCumulativeV2CorpusAsLegacy(t *testing.T) {
	root := writeTestCumulativeV2Corpus(t)

	corpus, err := Load(root, testCustodyID)
	if err != nil {
		t.Fatalf("Load(v2) error = %v", err)
	}
	if corpus.isCurrentPhase4() {
		t.Fatal("Load(v2) reported current after the v3 normal-volume contract became mandatory")
	}
}

func TestLoadCumulativeV2RefusesClosedVariantMutations(t *testing.T) {
	tests := []struct {
		name, old, replacement string
		want                   RefusalKind
	}{
		{name: "unknown category", old: `"category":"stream"`, replacement: `"category":"future"`, want: RefusalUnknown},
		{name: "unknown stream field", old: `"status":"required"`, replacement: `"unexpected":true,"status":"required"`, want: RefusalUnknown},
		{name: "unknown suite", old: `"suite":"standard1"`, replacement: `"suite":"future"`, want: RefusalUnknown},
		{name: "stream key width", old: `"xchacha_key_hex":"` + testV2Hex32 + `"`, replacement: `"xchacha_key_hex":"00"`, want: RefusalMalformed},
		{name: "capsule wire width", old: `"primary_decoded_hex":"` + strings.Repeat("00", 320) + `"`, replacement: `"primary_decoded_hex":"00"`, want: RefusalMalformed},
		{name: "capsule outcome", old: `"expected_outcome":"success"`, replacement: `"expected_outcome":"ambiguous-volume"`, want: RefusalMalformed},
		{name: "capsule stage", old: `"expected_stage":"none"`, replacement: `"expected_stage":"wrap-auth"`, want: RefusalMalformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestCumulativeV2Corpus(t)
			mutateFirstV2Fixture(t, root, tt.old, tt.replacement)
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, tt.want)
		})
	}
}

func TestLoadCumulativeV2BindsGeneratorSource(t *testing.T) {
	root := writeTestCumulativeV2Corpus(t)
	writeTestFile(t, root, "generator/phase4.go", testV2GeneratorSource+"// changed\n")

	_, err := Load(root, testCustodyID)
	assertRefusal(t, err, RefusalHash)
}

func writeTestCumulativeV2Corpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "manifest.schema.json", testSchemaV2)
	writeTestFile(t, root, "positive/nfc.json", positiveFixture)
	writeTestFile(t, root, "negative/reject-unassigned.json", negativeFixture)
	writeTestFile(t, root, "provenance/nfc.json", independentProvenance)
	writeTestFile(t, root, "provenance/reject-unassigned.json", independentProvenance)
	writeTestFile(t, root, "generator/phase4.go", testV2GeneratorSource)

	generatorSHA := testSHA256(testV2GeneratorSource)
	fixtures := []string{
		testV2ManifestEntry("unicode17-nfc", "positive/nfc.json", positiveFixture, "provenance/nfc.json", independentProvenance, "unicode17", "accept", "none", 0, "", ""),
		testV2ManifestEntry("unicode17-unassigned", "negative/reject-unassigned.json", negativeFixture, "provenance/reject-unassigned.json", independentProvenance, "unicode17", "reject", "canonicalization", 0, "", ""),
	}
	for _, fixture := range testV2Phase4Fixtures {
		document := testV2FixtureDocument(fixture)
		direction := "positive"
		if fixture.outcome != "accept" && fixture.outcome != "success" && fixture.outcome != "authenticated-degraded" {
			direction = "negative"
		}
		fixturePath := direction + "/" + fixture.id + ".json"
		provenancePath := "provenance/" + fixture.id + ".json"
		provenance := testV2Provenance(generatorSHA)
		writeTestFile(t, root, fixturePath, document)
		writeTestFile(t, root, provenancePath, provenance)
		fixtures = append(fixtures, testV2ManifestEntry(fixture.id, fixturePath, document, provenancePath, provenance, fixture.category, fixture.outcome, fixture.stage, fixture.kdfCalls, "generator/phase4.go", generatorSHA))
	}
	manifest := fmt.Sprintf(`{"format":"pcv3-corpus-v2","schema_revision":"2","spec_revision":"0.3","test_only":true,"custody_id":%q,"fixtures":[%s],"deferred_vector_classes":["full-pcv3-volume"]}`, testCustodyID, strings.Join(fixtures, ","))
	writeTestFile(t, root, "manifest.json", manifest)
	return root
}

func testV2ManifestEntry(id, fixturePath, document, provenancePath, provenance, category, outcome, stage string, kdfCalls int, generatorPath, generatorSHA string) string {
	generatorFields := ""
	if generatorPath != "" {
		generatorFields = fmt.Sprintf(`,"generator_source_path":%q,"generator_source_sha256":%q`, generatorPath, generatorSHA)
	}
	return fmt.Sprintf(`{"id":%q,"path":%q,"sha256":%q,"provenance_path":%q,"provenance_sha256":%q%s,"category":%q,"outcome":%q,"failure_stage":%q,"kdf_calls":%d,"publication_state":"not-applicable","force_state":"not-applicable","status":"required","generated_at_test_time":false}`, id, fixturePath, testSHA256(document), provenancePath, testSHA256(provenance), generatorFields, category, outcome, stage, kdfCalls)
}

func testV2FixtureDocument(fixture testV2Fixture) string {
	if fixture.category == "stream" {
		serpentFields := ""
		if fixture.suite == "paranoid1" {
			serpentFields = fmt.Sprintf(`,"serpent_key_hex":%q,"serpent_iv_hex":%q`, testV2Hex32, testV2Hex16)
		}
		return fmt.Sprintf(`{"test_only":true,"id":%q,"category":"stream","case":%q,"suite":%q,"xchacha_key_hex":%q,"xchacha_nonce_hex":%q%s,"volume_key_hex":%q,"wrapped_volume_key_hex":%q,"status":"required","generated_at_test_time":false}`, fixture.id, fixture.caseName, fixture.suite, testV2Hex32, testV2Hex24, serpentFields, testV2Hex32, testV2Hex32)
	}
	wire := strings.Repeat("00", 320)
	return fmt.Sprintf(`{"test_only":true,"id":%q,"category":"capsule","case":%q,"suite":%q,"password_utf8_hex":"54455354204f4e4c59","credential_root_hex":%q,"primary_decoded_hex":%q,"backup_decoded_hex":%q,"expected_volume_key_hex":%q,"expected_outcome":%q,"expected_stage":%q,"expected_kdf_calls":%d,"expected_authenticated_capsules":%d,"status":"required","generated_at_test_time":false}`, fixture.id, fixture.caseName, fixture.suite, testV2Hex32, wire, wire, testV2Hex32, fixture.outcome, fixture.stage, fixture.kdfCalls, fixture.authenticated)
}

func testV2Provenance(generatorSHA string) string {
	lock := "go=1.26.5;golang.org/x/crypto=v0.54.0;github.com/Picocrypt-NG/serpent=v0.1.0"
	return fmt.Sprintf(`{"test_only":true,"author":"independent-phase4-fixture-generator","generator":"pcv3-phase4-independent-go","generator_version":"1","source_revision":"PCV3 revision 0.3 sections 6 and 13","source_sha256":%q,"dependency_lock":%q,"dependency_lock_sha256":%q,"reproduction_command":"go run ./generator/phase4.go","independent_of_production":true,"production_code":false}`, generatorSHA, lock, testSHA256(lock))
}

func mutateFirstV2Fixture(t *testing.T, root, old, replacement string) {
	t.Helper()
	for _, fixture := range testV2Phase4Fixtures {
		path := filepath.Join(root, "positive", fixture.id+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		updated := strings.Replace(string(data), old, replacement, 1)
		if updated == string(data) {
			continue
		}
		writeTestFile(t, root, "positive/"+fixture.id+".json", updated)
		repinV2Fixture(t, root, fixture.id, testSHA256(updated))
		return
	}
	t.Fatal("test mutation did not match a cumulative v2 fixture")
}

func repinV2Fixture(t *testing.T, root, id, hash string) {
	t.Helper()
	path := filepath.Join(root, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cumulative manifest: %v", err)
	}
	needle := `"id":"` + id + `"`
	start := strings.Index(string(data), needle)
	if start < 0 {
		t.Fatal("cumulative manifest fixture missing")
	}
	const prefix = `"sha256":"`
	hashStart := strings.Index(string(data[start:]), prefix)
	if hashStart < 0 {
		t.Fatal("cumulative manifest fixture hash missing")
	}
	hashStart += start + len(prefix)
	hashEnd := hashStart + 64
	if hashEnd > len(data) {
		t.Fatal("cumulative manifest fixture hash is truncated")
	}
	updated := string(data[:hashStart]) + hash + string(data[hashEnd:])
	writeTestFile(t, root, "manifest.json", updated)
}

func testSHA256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

const testSchemaV3 = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pcv3.invalid/cumulative-v3/manifest.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["format", "schema_revision", "spec_revision", "test_only", "custody_id", "fixtures", "deferred_vector_classes", "source_artifacts"],
  "properties": {
    "format": {"const": "pcv3-corpus-v3"},
    "schema_revision": {"const": "3"},
    "spec_revision": {"const": "0.3"},
    "test_only": {"const": true},
    "custody_id": {"type": "string", "minLength": 1},
    "fixtures": {"type": "array", "minItems": 28, "items": {"$ref": "#/$defs/fixture"}},
    "deferred_vector_classes": {
      "type": "array", "minItems": 3, "maxItems": 3, "uniqueItems": true,
      "items": {"enum": ["pcv3-writer", "d1-volumes", "force-recovery"]}
    },
    "source_artifacts": {
      "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true,
      "items": {"$ref": "#/$defs/source_artifact"}
    }
  },
  "$defs": {
    "source_artifact": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "path", "sha256", "kind"],
      "properties": {
        "id": {"type": "string", "minLength": 1},
        "path": {"type": "string", "minLength": 1},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "kind": {"enum": ["generator-source", "dependency-lock", "source-vector"]}
      }
    },
    "fixture": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "path", "sha256", "provenance_path", "provenance_sha256", "category", "outcome", "failure_stage", "kdf_calls", "publication_state", "force_state", "status", "generated_at_test_time"],
      "properties": {
        "id": {"type": "string", "minLength": 1},
        "path": {"type": "string", "minLength": 1},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "provenance_path": {"type": "string", "minLength": 1},
        "provenance_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "generator_source_path": {"type": "string", "minLength": 1},
        "generator_source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "category": {"enum": ["unicode17", "governance", "stream", "capsule", "normal-volume"]},
        "outcome": {"enum": ["accept", "reject", "success", "authenticated-degraded", "credentials-or-damage", "invalid-structure-pre-kdf", "ambiguous-volume", "authentication-failed"]},
        "failure_stage": {"enum": ["none", "canonicalization", "governance", "wrap-auth", "replica-auth", "capsule-rs", "capsule-structure", "metadata", "descriptor", "record-auth", "final-record", "tail-geometry"]},
        "kdf_calls": {"type": "integer", "minimum": 0, "maximum": 1},
        "publication_state": {"enum": ["not-published", "not-applicable"]},
        "force_state": {"const": "not-applicable"},
        "status": {"const": "required"},
        "generated_at_test_time": {"const": false}
      }
    }
  }
}`

const (
	testOnlyNotice = "TEST ONLY PCV3 CONFORMANCE DATA; NOT SECRET OR OPERATIONAL"
)

var testV3KeyLiterals = struct {
	credentialRoot, volumeKey                         string
	primaryWrapX, backupWrapX                         string
	primaryWrapSerpent, backupWrapSerpent             string
	primaryWrapMAC, backupWrapMAC                     string
	primaryReplicaMAC, backupReplicaMAC               string
	metadataMAC, payloadX, payloadSerpent, payloadMAC string
}{
	credentialRoot:     strings.Repeat("e0", 32),
	volumeKey:          strings.Repeat("01", 32),
	primaryWrapX:       strings.Repeat("11", 32),
	backupWrapX:        strings.Repeat("21", 32),
	primaryWrapSerpent: strings.Repeat("31", 32),
	backupWrapSerpent:  strings.Repeat("41", 32),
	primaryWrapMAC:     strings.Repeat("51", 32),
	backupWrapMAC:      strings.Repeat("61", 32),
	primaryReplicaMAC:  strings.Repeat("71", 32),
	backupReplicaMAC:   strings.Repeat("81", 32),
	metadataMAC:        strings.Repeat("91", 32),
	payloadX:           strings.Repeat("a1", 32),
	payloadSerpent:     strings.Repeat("b1", 32),
	payloadMAC:         strings.Repeat("c1", 32),
}

type testV3NormalFixture struct {
	id, caseName, suite, credentialMode, keyfileMode, kdfEvidence string
	outcome, stage                                                string
	payloadLength                                                 int
	payloadRS, completion                                         bool
	kdfCalls, authenticatedCapsules                               int
}

var testV3NormalFixtures = []testV3NormalFixture{
	{id: "normal-standard-combined-ordered-empty", caseName: "empty", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", stage: "none", completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-one", caseName: "one-byte", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", stage: "none", payloadLength: 1, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-before-mib", caseName: "one-mib-minus-one", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", stage: "none", payloadLength: (1 << 20) - 1, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-exact-mib", caseName: "exact-one-mib", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", stage: "none", payloadLength: 1 << 20, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-after-mib", caseName: "one-mib-plus-one", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", stage: "none", payloadLength: (1 << 20) + 1, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-two-mib", caseName: "exact-two-mib", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", stage: "none", payloadLength: 2 << 20, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-standard-keyfiles-only-small", caseName: "keyfiles-only-small", suite: "standard1", credentialMode: "keyfiles-only", keyfileMode: "ordered", kdfEvidence: "fast-seam", outcome: "success", stage: "none", payloadLength: 17, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-standard-combined-unordered-rs-small", caseName: "combined-unordered-rs-small", suite: "standard1", credentialMode: "combined", keyfileMode: "unordered", kdfEvidence: "fast-seam", outcome: "success", stage: "none", payloadLength: 33, payloadRS: true, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-paranoid-combined-unordered-rs-small", caseName: "paranoid-combined-rs-small", suite: "paranoid1", credentialMode: "combined", keyfileMode: "unordered", kdfEvidence: "production-vector", outcome: "success", stage: "none", payloadLength: 65, payloadRS: true, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-degraded-capsule", caseName: "degraded-capsule", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authenticated-degraded", stage: "capsule-rs", payloadLength: 17, completion: true, kdfCalls: 1, authenticatedCapsules: 1},
	{id: "normal-degraded-metadata", caseName: "degraded-metadata", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authenticated-degraded", stage: "metadata", payloadLength: 17, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-degraded-trailer", caseName: "degraded-trailer", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authenticated-degraded", stage: "tail-geometry", payloadLength: 17, completion: true, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-negative-descriptor", caseName: "negative-descriptor", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", stage: "descriptor", payloadLength: 17, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-negative-record", caseName: "negative-record", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", stage: "record-auth", payloadLength: 17, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-negative-final", caseName: "negative-final", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", stage: "final-record", payloadLength: 17, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-negative-suffix", caseName: "negative-suffix", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", stage: "tail-geometry", payloadLength: 17, kdfCalls: 1, authenticatedCapsules: 2},
	{id: "normal-negative-extra-byte", caseName: "negative-extra-byte", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", stage: "tail-geometry", payloadLength: 17, kdfCalls: 1, authenticatedCapsules: 2},
}

func TestLoadAcceptsCumulativeV3OnlyAsCurrentPhase4(t *testing.T) {
	v1, err := Load(writeTestCorpus(t), testCustodyID)
	if err != nil {
		t.Fatalf("Load(v1) error = %v", err)
	}
	if v1.isCurrentPhase4() {
		t.Fatal("v1 corpus reported current for Phase 4")
	}

	v2, err := Load(writeTestCumulativeV2Corpus(t), testCustodyID)
	if err != nil {
		t.Fatalf("Load(v2) error = %v", err)
	}
	if v2.isCurrentPhase4() {
		t.Fatal("v2 corpus reported current after the v3 contract became mandatory")
	}

	v3, err := Load(writeTestCumulativeV3Corpus(t), testCustodyID)
	if err != nil {
		t.Fatalf("Load(v3) error = %v", err)
	}
	if !v3.isCurrentPhase4() {
		t.Fatal("v3 corpus did not retain the closed normal-volume evidence inventory")
	}
}

func TestLoadCumulativeV3RefusesBroadDeferralAndIncompleteNormalInventory(t *testing.T) {
	t.Run("broad full-volume deferral", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		mutateV3Manifest(t, root, func(manifest map[string]any) {
			manifest["deferred_vector_classes"] = []any{"full-pcv3-volume", "d1-volumes", "force-recovery"}
		})
		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalSchema)
	})

	t.Run("missing required normal fixture", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		removeV3Fixture(t, root, testV3NormalFixtures[0].id)
		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalMissing)
	})
}

func TestLoadCumulativeV3EnforcesFixtureCategorySizeBounds(t *testing.T) {
	t.Run("normal volume over sixteen MiB", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		fixture := testV3NormalFixtures[0]
		fixturePath := filepath.Join(root, "positive", fixture.id+".json")
		oversized := strings.Repeat("x", (16<<20)+1)
		if err := os.WriteFile(fixturePath, []byte(oversized), 0o600); err != nil {
			t.Fatalf("write oversized normal-volume fixture: %v", err)
		}
		repinV3Fixture(t, root, fixture.id, testSHA256(oversized))

		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalMalformed)
	})

	t.Run("legacy fixture over one MiB", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		oversized := strings.Repeat("x", (1<<20)+1)
		if err := os.WriteFile(filepath.Join(root, "positive", "nfc.json"), []byte(oversized), 0o600); err != nil {
			t.Fatalf("write oversized legacy fixture: %v", err)
		}
		repinV3Fixture(t, root, "unicode17-nfc", testSHA256(oversized))

		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalMalformed)
	})
}

func TestLoadCumulativeV3BindsSourceArtifactInventoryAndHashes(t *testing.T) {
	t.Run("pinned content corruption", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		writeTestFile(t, root, "generator/input/kdf-vectors.json", `{"test_only":true,"id":"tampered"}`)
		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalHash)
	})

	t.Run("missing bound artifact", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		if err := os.Remove(filepath.Join(root, "generator", "upstream-record", "go.sum")); err != nil {
			t.Fatalf("remove bound source artifact: %v", err)
		}
		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalMissing)
	})

	for _, field := range []string{"id", "path"} {
		t.Run("duplicate "+field, func(t *testing.T) {
			root := writeTestCumulativeV3Corpus(t)
			mutateV3Manifest(t, root, func(manifest map[string]any) {
				artifacts := manifest["source_artifacts"].([]any)
				first := artifacts[0].(map[string]any)
				second := artifacts[1].(map[string]any)
				second[field] = first[field]
			})
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, RefusalDuplicate)
		})
	}
}

func TestLoadCumulativeV3AllowsOnlyExtraByteEndMutationOffset(t *testing.T) {
	t.Run("extra byte uses the declared end sentinel", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		setV3MutationOffsetFromEnd(t, root, "normal-negative-extra-byte", 0)

		if _, err := Load(root, testCustodyID); err != nil {
			t.Fatalf("Load() rejected exact extra-byte end sentinel: %v", err)
		}
	})

	t.Run("another fixture cannot use the declared end", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		setV3MutationOffsetFromEnd(t, root, "normal-negative-suffix", 0)

		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalMalformed)
	})

	t.Run("extra byte cannot name an offset after the declared end", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		setV3MutationOffsetFromEnd(t, root, "normal-negative-extra-byte", 1)

		_, err := Load(root, testCustodyID)
		assertRefusal(t, err, RefusalMalformed)
	})
}

func TestWithNormalVolumeFixturesLendsSelectedAliasesAndZeroesThem(t *testing.T) {
	root := writeTestCumulativeV3Corpus(t)
	ids := []string{
		"normal-standard-combined-ordered-empty",
		"normal-paranoid-combined-unordered-rs-small",
	}
	var aliases [][]byte
	err := WithNormalVolumeFixtures(root, testCustodyID, ids, func(fixtures []*NormalVolumeFixture) error {
		if len(fixtures) != len(ids) {
			t.Fatalf("borrowed fixture count = %d, want %d", len(fixtures), len(ids))
		}
		for index, fixture := range fixtures {
			if fixture.ID() != ids[index] {
				t.Fatalf("borrowed fixture %d ID = %q, want %q", index, fixture.ID(), ids[index])
			}
			contract, fill := testV3FixtureContract(t, fixture.ID())
			if fixture.Case() != contract.caseName || fixture.Suite() != contract.suite ||
				fixture.CredentialMode() != contract.credentialMode || fixture.KeyfileMode() != contract.keyfileMode ||
				fixture.KDFEvidence() != contract.kdfEvidence || fixture.PayloadRS() != contract.payloadRS ||
				fixture.Outcome() != contract.outcome || fixture.FailureStage() != contract.stage ||
				fixture.KDFCalls() != contract.kdfCalls || fixture.AuthenticatedCapsules() != contract.authenticatedCapsules ||
				fixture.Completion() != contract.completion {
				t.Fatal("borrowed fixture metadata did not match its closed contract")
			}
			wantVolume, wantPlaintext := testV3SyntheticMaterial(contract, fill)
			assertBorrowedBytes(t, "volume", fixture.Volume(), wantVolume)
			assertBorrowedBytes(t, "plaintext", fixture.Plaintext(), wantPlaintext)
			assertBorrowedBytes(t, "comment", fixture.Comment(), []byte("TEST ONLY comment"))
			assertBorrowedBytes(t, "password", fixture.Password(), []byte("TEST ONLY mix"))
			wantKeyfiles := [][]byte{[]byte("TEST ONLY red"), []byte("TEST ONLY blue")}
			if contract.keyfileMode == "unordered" {
				wantKeyfiles = [][]byte{[]byte("TEST ONLY blue"), []byte("TEST ONLY red")}
			}
			if len(fixture.Keyfiles()) != len(wantKeyfiles) {
				t.Fatalf("borrowed keyfile count = %d, want %d", len(fixture.Keyfiles()), len(wantKeyfiles))
			}
			for keyfileIndex := range wantKeyfiles {
				assertBorrowedBytes(t, "keyfile", fixture.Keyfiles()[keyfileIndex], wantKeyfiles[keyfileIndex])
			}
			assertBorrowedHex(t, "credential root", fixture.CredentialRoot(), testV3KeyLiterals.credentialRoot)

			keys := fixture.Keys()
			assertBorrowedHex(t, "VolumeKey", keys.VolumeKey(), testV3KeyLiterals.volumeKey)
			assertBorrowedHex(t, "primary wrap XChaCha20", keys.PrimaryWrapXChaCha20(), testV3KeyLiterals.primaryWrapX)
			assertBorrowedHex(t, "backup wrap XChaCha20", keys.BackupWrapXChaCha20(), testV3KeyLiterals.backupWrapX)
			if contract.suite == "standard1" {
				assertBorrowedBytes(t, "primary absent Serpent wrap key", keys.PrimaryWrapSerpent(), nil)
				assertBorrowedBytes(t, "backup absent Serpent wrap key", keys.BackupWrapSerpent(), nil)
				assertBorrowedBytes(t, "absent Serpent payload key", keys.PayloadSerpent(), nil)
			} else {
				assertBorrowedHex(t, "primary wrap Serpent", keys.PrimaryWrapSerpent(), testV3KeyLiterals.primaryWrapSerpent)
				assertBorrowedHex(t, "backup wrap Serpent", keys.BackupWrapSerpent(), testV3KeyLiterals.backupWrapSerpent)
				assertBorrowedHex(t, "payload Serpent", keys.PayloadSerpent(), testV3KeyLiterals.payloadSerpent)
			}
			assertBorrowedHex(t, "primary wrap MAC", keys.PrimaryWrapMAC(), testV3KeyLiterals.primaryWrapMAC)
			assertBorrowedHex(t, "backup wrap MAC", keys.BackupWrapMAC(), testV3KeyLiterals.backupWrapMAC)
			assertBorrowedHex(t, "primary replica MAC", keys.PrimaryReplicaMAC(), testV3KeyLiterals.primaryReplicaMAC)
			assertBorrowedHex(t, "backup replica MAC", keys.BackupReplicaMAC(), testV3KeyLiterals.backupReplicaMAC)
			assertBorrowedHex(t, "metadata MAC", keys.MetadataMAC(), testV3KeyLiterals.metadataMAC)
			assertBorrowedHex(t, "payload XChaCha20", keys.PayloadXChaCha20(), testV3KeyLiterals.payloadX)
			assertBorrowedHex(t, "payload MAC", keys.PayloadMAC(), testV3KeyLiterals.payloadMAC)

			aliases = append(aliases, fixture.Volume(), fixture.Plaintext(), fixture.Comment(), fixture.Password(), fixture.CredentialRoot())
			aliases = append(aliases, fixture.Keyfiles()...)
			aliases = append(aliases,
				keys.VolumeKey(), keys.PrimaryWrapXChaCha20(), keys.BackupWrapXChaCha20(),
				keys.PrimaryWrapSerpent(), keys.BackupWrapSerpent(), keys.PrimaryWrapMAC(),
				keys.BackupWrapMAC(), keys.PrimaryReplicaMAC(), keys.BackupReplicaMAC(),
				keys.MetadataMAC(), keys.PayloadXChaCha20(), keys.PayloadSerpent(), keys.PayloadMAC(),
			)
			formatted := fmt.Sprintf("%s|%q|%v|%+v|%#v|%s|%q|%+v|%#v", fixture, fixture, fixture, fixture, fixture, keys, keys, keys, keys)
			if strings.Contains(formatted, root) || strings.Contains(formatted, "mix") || strings.Contains(formatted, "TEST ONLY") || strings.Contains(formatted, testV3KeyLiterals.volumeKey) {
				t.Fatal("borrowed fixture formatting disclosed private or test-secret material")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithNormalVolumeFixtures() error = %v", err)
	}
	if len(aliases) == 0 {
		t.Fatal("borrow callback captured no aliases")
	}
	for _, alias := range aliases {
		if !allZero(alias) {
			t.Fatal("borrowed fixture alias retained bytes after callback")
		}
	}
}

func TestWithNormalVolumeFixturesZeroesAliasesWhenCallbackFails(t *testing.T) {
	root := writeTestCumulativeV3Corpus(t)
	sentinel := errors.New("TEST ONLY callback sentinel")
	var aliases [][]byte
	err := WithNormalVolumeFixtures(root, testCustodyID, []string{"normal-standard-keyfiles-only-small"}, func(fixtures []*NormalVolumeFixture) error {
		fixture := fixtures[0]
		aliases = append(aliases, fixture.Volume(), fixture.Plaintext(), fixture.CredentialRoot())
		keyfiles := fixture.Keyfiles()
		aliases = append(aliases, keyfiles...)
		aliases = append(aliases, fixture.Keys().VolumeKey(), fixture.Keys().PayloadMAC())
		for _, alias := range aliases {
			if len(alias) == 0 || allZero(alias) {
				t.Fatal("callback-error oracle captured an empty or already-zero alias")
			}
		}
		// The callback may reorder or clear its outer view, but must not be
		// able to remove the owner's references needed for secure cleanup.
		keyfiles[0] = nil
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithNormalVolumeFixtures() error = %v, want callback sentinel", err)
	}
	for _, alias := range aliases {
		if !allZero(alias) {
			t.Fatal("callback-error alias retained bytes after callback")
		}
	}
}

func TestWithNormalVolumeFixturesRejectsDuplicateUnknownAndLegacySelections(t *testing.T) {
	v3 := writeTestCumulativeV3Corpus(t)
	for _, test := range []struct {
		name string
		root string
		ids  []string
		want RefusalKind
	}{
		{name: "duplicate", root: v3, ids: []string{testV3NormalFixtures[0].id, testV3NormalFixtures[0].id}, want: RefusalDuplicate},
		{name: "unknown", root: v3, ids: []string{"normal-future-unknown"}, want: RefusalUnknown},
		{name: "legacy corpus", root: writeTestCumulativeV2Corpus(t), ids: []string{testV3NormalFixtures[0].id}, want: RefusalUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			err := WithNormalVolumeFixtures(test.root, testCustodyID, test.ids, func([]*NormalVolumeFixture) error {
				called = true
				return nil
			})
			assertRefusal(t, err, test.want)
			if called {
				t.Fatal("rejected selection invoked the borrow callback")
			}
		})
	}
}

func TestWithNormalVolumeFixturesPreservesRequiredMutationInventories(t *testing.T) {
	// This is corpus-loader policy evidence. It does not exercise the reader or
	// establish any cryptographic coverage.
	t.Run("complete required inventories are lent in order", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		ids := []string{"normal-degraded-capsule", "normal-negative-descriptor"}
		called := false
		err := WithNormalVolumeFixtures(root, testCustodyID, ids, func(fixtures []*NormalVolumeFixture) error {
			called = true
			if len(fixtures) != len(ids) {
				t.Fatalf("borrowed fixture count = %d, want %d", len(fixtures), len(ids))
			}
			for index, fixture := range fixtures {
				if fixture.ID() != ids[index] {
					t.Fatalf("borrowed fixture %d ID = %q, want %q", index, fixture.ID(), ids[index])
				}
				first, count := uint64(16), 65
				if fixture.ID() == "normal-negative-descriptor" {
					first, count = 1112, 33
				}
				offsets := fixture.MutationOffsets()
				if len(offsets) != count {
					t.Fatalf("borrowed %s mutation count = %d, want %d", fixture.ID(), len(offsets), count)
				}
				for offsetIndex, got := range offsets {
					want := first + uint64(offsetIndex)
					if got != want {
						t.Fatalf("borrowed %s mutation offset %d = %d, want %d", fixture.ID(), offsetIndex, got, want)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WithNormalVolumeFixtures() rejected complete required mutation inventories: %v", err)
		}
		if !called {
			t.Fatal("complete required mutation inventories did not reach the borrow callback")
		}
	})

	t.Run("sixty six offsets exceed the finite boundary", func(t *testing.T) {
		root := writeTestCumulativeV3Corpus(t)
		const id = "normal-degraded-capsule"
		logicalPath := "positive/" + id + ".json"
		fixturePath := filepath.Join(root, filepath.FromSlash(logicalPath))
		fixtureData, err := os.ReadFile(fixturePath)
		if err != nil {
			t.Fatalf("read normal-volume fixture: %v", err)
		}
		var fixture map[string]any
		if err := json.Unmarshal(fixtureData, &fixture); err != nil {
			t.Fatalf("decode normal-volume fixture: %v", err)
		}
		offsets := make([]any, 66)
		for index := range offsets {
			offsets[index] = 16 + index
		}
		fixture["mutation_offsets"] = offsets
		updated, err := json.Marshal(fixture)
		if err != nil {
			t.Fatalf("encode normal-volume fixture: %v", err)
		}
		writeTestFile(t, root, logicalPath, string(updated))
		repinV3Fixture(t, root, id, testBytesSHA256(updated))

		called := false
		err = WithNormalVolumeFixtures(root, testCustodyID, []string{id}, func([]*NormalVolumeFixture) error {
			called = true
			return nil
		})
		assertRefusal(t, err, RefusalMalformed)
		if called {
			t.Fatal("over-bound mutation inventory reached the borrow callback")
		}
	})
}

func writeTestCumulativeV3Corpus(t *testing.T) string {
	t.Helper()
	root := writeTestCumulativeV2Corpus(t)
	writeTestFile(t, root, "manifest.schema.json", testSchemaV3)

	manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatalf("read cumulative v2 manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode cumulative v2 manifest: %v", err)
	}
	manifest["format"] = "pcv3-corpus-v3"
	manifest["schema_revision"] = "3"
	manifest["deferred_vector_classes"] = []any{"pcv3-writer", "d1-volumes", "force-recovery"}

	sourceArtifacts := []any{}
	for _, artifact := range []struct {
		id, path, kind, contents string
	}{
		{id: "phase4-generator-source", path: "generator/phase4-v3.go", kind: "generator-source", contents: testV2GeneratorSource},
		{id: "phase4-generator-lock", path: "generator/phase4-v3.lock", kind: "dependency-lock", contents: "go=1.26.5;x-crypto=v0.54.0;serpent=v0.1.0"},
		{id: "record-generator-source", path: "generator/upstream-record/main.go", kind: "generator-source", contents: testV2GeneratorSource},
		{id: "record-generator-go-mod", path: "generator/upstream-record/go.mod", kind: "dependency-lock", contents: "module test-only-record-generator\n"},
		{id: "record-generator-go-sum", path: "generator/upstream-record/go.sum", kind: "dependency-lock", contents: "TEST ONLY dependency checksum\n"},
		{id: "phase2-kdf-vectors", path: "generator/input/kdf-vectors.json", kind: "source-vector", contents: `{"test_only":true,"id":"kdf-vectors"}`},
		{id: "phase2-vector-input", path: "generator/input/vector-input.json", kind: "source-vector", contents: `{"test_only":true,"id":"vector-input"}`},
	} {
		writeTestFile(t, root, artifact.path, artifact.contents)
		sourceArtifacts = append(sourceArtifacts, map[string]any{
			"id": artifact.id, "path": artifact.path, "sha256": testSHA256(artifact.contents), "kind": artifact.kind,
		})
	}
	manifest["source_artifacts"] = sourceArtifacts

	fixtures, ok := manifest["fixtures"].([]any)
	if !ok {
		t.Fatal("cumulative v2 manifest fixtures have unexpected type")
	}
	generatorSHA := testSHA256(testV2GeneratorSource)
	provenance := testV3Provenance(generatorSHA)
	for index, fixture := range testV3NormalFixtures {
		document := testV3NormalFixtureDocument(fixture, byte(index+1))
		direction := "positive"
		if fixture.outcome == "authentication-failed" {
			direction = "negative"
		}
		fixturePath := direction + "/" + fixture.id + ".json"
		provenancePath := "provenance/" + fixture.id + ".json"
		writeTestFile(t, root, fixturePath, document)
		writeTestFile(t, root, provenancePath, provenance)
		var entry map[string]any
		entryJSON := testV2ManifestEntry(fixture.id, fixturePath, document, provenancePath, provenance, "normal-volume", fixture.outcome, fixture.stage, fixture.kdfCalls, "generator/phase4-v3.go", generatorSHA)
		if err := json.Unmarshal([]byte(entryJSON), &entry); err != nil {
			t.Fatalf("decode test v3 fixture entry: %v", err)
		}
		fixtures = append(fixtures, entry)
	}
	manifest["fixtures"] = fixtures
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode cumulative v3 manifest: %v", err)
	}
	writeTestFile(t, root, "manifest.json", string(encoded))
	return root
}

func testV3NormalFixtureDocument(fixture testV3NormalFixture, fill byte) string {
	volume, plaintext := testV3SyntheticMaterial(fixture, fill)
	password := []byte("TEST ONLY mix")
	keyfiles := []string{hex.EncodeToString([]byte("TEST ONLY red")), hex.EncodeToString([]byte("TEST ONLY blue"))}
	if fixture.credentialMode == "keyfiles-only" {
		password = nil
	}
	if fixture.keyfileMode == "unordered" {
		keyfiles[0], keyfiles[1] = keyfiles[1], keyfiles[0]
	}
	comment := []byte("TEST ONLY comment")
	if fixture.stage == "metadata" {
		comment = nil
	}
	mutationOffsets := []int{}
	switch fixture.id {
	case "normal-degraded-capsule":
		mutationOffsets = make([]int, 65)
		for index := range mutationOffsets {
			mutationOffsets[index] = 16 + index
		}
	case "normal-negative-descriptor":
		mutationOffsets = make([]int, 33)
		for index := range mutationOffsets {
			mutationOffsets[index] = 1112 + index
		}
	case "normal-negative-extra-byte":
		mutationOffsets = []int{len(volume)}
	case "normal-degraded-metadata", "normal-degraded-trailer", "normal-negative-record", "normal-negative-final", "normal-negative-suffix":
		mutationOffsets = []int{16}
	}
	document := map[string]any{
		"test_only": true, "public_test_data_notice": testOnlyNotice,
		"id": fixture.id, "category": "normal-volume", "case": fixture.caseName,
		"suite": fixture.suite, "payload_rs": fixture.payloadRS,
		"credential_mode": fixture.credentialMode, "keyfile_mode": fixture.keyfileMode,
		"kdf_evidence": fixture.kdfEvidence, "password_utf8_hex": hex.EncodeToString(password),
		"keyfiles_hex": keyfiles, "credential_root_hex": testV3KeyLiterals.credentialRoot,
		"volume_hex": hex.EncodeToString(volume), "volume_sha256": testBytesSHA256(volume),
		"plaintext_hex": hex.EncodeToString(plaintext), "plaintext_sha256": testBytesSHA256(plaintext),
		"comment_utf8_hex":      hex.EncodeToString(comment),
		"payload_length_hex":    fmt.Sprintf("%016x", fixture.payloadLength),
		"data_record_count_hex": fmt.Sprintf("%016x", testRecordCount(fixture.payloadLength)),
		"expected_outcome":      fixture.outcome, "expected_stage": fixture.stage,
		"expected_kdf_calls":              fixture.kdfCalls,
		"expected_authenticated_capsules": fixture.authenticatedCapsules,
		"expected_completion":             fixture.completion, "mutation_offsets": mutationOffsets,
		"keys":   testV3NormalKeys(fixture.suite),
		"status": "required", "generated_at_test_time": false,
	}
	encoded, _ := json.Marshal(document)
	return string(encoded)
}

func testV3NormalKeys(suite string) map[string]any {
	primarySerpent, backupSerpent, payloadSerpent := "", "", ""
	if suite == "paranoid1" {
		primarySerpent = testV3KeyLiterals.primaryWrapSerpent
		backupSerpent = testV3KeyLiterals.backupWrapSerpent
		payloadSerpent = testV3KeyLiterals.payloadSerpent
	}
	return map[string]any{
		"volume_key_hex":             testV3KeyLiterals.volumeKey,
		"primary_wrap_xchacha20_hex": testV3KeyLiterals.primaryWrapX, "backup_wrap_xchacha20_hex": testV3KeyLiterals.backupWrapX,
		"primary_wrap_serpent_hex": primarySerpent, "backup_wrap_serpent_hex": backupSerpent,
		"primary_wrap_mac_hex": testV3KeyLiterals.primaryWrapMAC, "backup_wrap_mac_hex": testV3KeyLiterals.backupWrapMAC,
		"primary_replica_mac_hex": testV3KeyLiterals.primaryReplicaMAC, "backup_replica_mac_hex": testV3KeyLiterals.backupReplicaMAC,
		"metadata_mac_hex": testV3KeyLiterals.metadataMAC, "payload_xchacha20_hex": testV3KeyLiterals.payloadX,
		"payload_serpent_hex": payloadSerpent, "payload_mac_hex": testV3KeyLiterals.payloadMAC,
	}
}

func testV3SyntheticMaterial(fixture testV3NormalFixture, fill byte) ([]byte, []byte) {
	plaintext := bytes.Repeat([]byte{fill}, fixture.payloadLength)
	overhead := 2232
	if fixture.payloadRS {
		overhead = 2304
	}
	volume := bytes.Repeat([]byte{fill ^ 0xff}, fixture.payloadLength+overhead)
	copy(volume, []byte("PCV\x00TEST ONLY SYNTHETIC LOADER CONTRACT"))
	return volume, plaintext
}

func testV3Provenance(generatorSHA string) string {
	lock := "go=1.26.5;golang.org/x/crypto=v0.54.0;github.com/Picocrypt-NG/serpent=v0.1.0;record-generator=hash-pinned"
	return fmt.Sprintf(`{"test_only":true,"author":"independent-phase4-normal-generator","generator":"pcv3-phase4-independent-go","generator_version":"3","source_revision":"PCV3 revision 0.3 sections 4-17 and 25-28","source_sha256":%q,"dependency_lock":%q,"dependency_lock_sha256":%q,"reproduction_command":"go run ./generator/phase4-v3.go ROOT","independent_of_production":true,"production_code":false}`, generatorSHA, lock, testSHA256(lock))
}

func mutateV3Manifest(t *testing.T, root string, mutate func(map[string]any)) {
	t.Helper()
	manifestPath := filepath.Join(root, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read cumulative v3 manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode cumulative v3 manifest: %v", err)
	}
	mutate(manifest)
	updated, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode mutated cumulative v3 manifest: %v", err)
	}
	writeTestFile(t, root, "manifest.json", string(updated))
}

func removeV3Fixture(t *testing.T, root, id string) {
	t.Helper()
	mutateV3Manifest(t, root, func(manifest map[string]any) {
		fixtures := manifest["fixtures"].([]any)
		kept := make([]any, 0, len(fixtures)-1)
		for _, raw := range fixtures {
			fixture := raw.(map[string]any)
			if fixture["id"] == id {
				for _, field := range []string{"path", "provenance_path"} {
					name := fixture[field].(string)
					if err := os.Remove(filepath.Join(root, filepath.FromSlash(name))); err != nil {
						t.Fatalf("remove test v3 fixture artifact: %v", err)
					}
				}
				continue
			}
			kept = append(kept, fixture)
		}
		manifest["fixtures"] = kept
	})
}

func repinV3Fixture(t *testing.T, root, id, hash string) {
	t.Helper()
	mutateV3Manifest(t, root, func(manifest map[string]any) {
		for _, raw := range manifest["fixtures"].([]any) {
			fixture := raw.(map[string]any)
			if fixture["id"] == id {
				fixture["sha256"] = hash
				return
			}
		}
		t.Fatal("cumulative v3 manifest fixture missing")
	})
}

func setV3MutationOffsetFromEnd(t *testing.T, root, id string, delta int) {
	t.Helper()
	manifestPath := filepath.Join(root, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read cumulative v3 manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("decode cumulative v3 manifest: %v", err)
	}
	for _, raw := range manifest["fixtures"].([]any) {
		entry := raw.(map[string]any)
		if entry["id"] != id {
			continue
		}
		logicalPath := entry["path"].(string)
		fixturePath := filepath.Join(root, filepath.FromSlash(logicalPath))
		fixtureData, err := os.ReadFile(fixturePath)
		if err != nil {
			t.Fatalf("read normal-volume fixture: %v", err)
		}
		var fixture map[string]any
		if err := json.Unmarshal(fixtureData, &fixture); err != nil {
			t.Fatalf("decode normal-volume fixture: %v", err)
		}
		volumeBytes := len(fixture["volume_hex"].(string)) / 2
		fixture["mutation_offsets"] = []any{volumeBytes + delta}
		updated, err := json.Marshal(fixture)
		if err != nil {
			t.Fatalf("encode normal-volume fixture: %v", err)
		}
		if err := os.WriteFile(fixturePath, updated, 0o600); err != nil {
			t.Fatalf("write normal-volume fixture: %v", err)
		}
		repinV3Fixture(t, root, id, testBytesSHA256(updated))
		return
	}
	t.Fatalf("cumulative v3 fixture %q missing", id)
}

func testBytesSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func testRecordCount(length int) int {
	if length == 0 {
		return 0
	}
	return (length + (1 << 20) - 1) / (1 << 20)
}

func testV3FixtureContract(t *testing.T, id string) (testV3NormalFixture, byte) {
	t.Helper()
	for index, fixture := range testV3NormalFixtures {
		if fixture.id == id {
			return fixture, byte(index + 1)
		}
	}
	t.Fatalf("test v3 fixture contract %q is missing", id)
	return testV3NormalFixture{}, 0
}

func assertBorrowedHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode literal %s: %v", name, err)
	}
	assertBorrowedBytes(t, name, got, want)
}

func assertBorrowedBytes(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("borrowed %s did not match its literal fixture value", name)
	}
	if len(got) != 0 && allZero(got) {
		t.Fatalf("borrowed %s was already zero inside the callback", name)
	}
}

func allZero(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}
