package pcv3corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
