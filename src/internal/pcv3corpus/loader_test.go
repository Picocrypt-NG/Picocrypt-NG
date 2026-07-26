package pcv3corpus

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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

const (
	positiveFixture       = `{"test_only":true,"case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9"}`
	negativeFixture       = `{"test_only":true,"case":"unicode17-unassigned","input_hex":"cdb8","expected":"reject"}`
	independentProvenance = `{"test_only":true,"author":"independent-fixture-author","generator":"literal-fixture","independent_of_production":true,"production_code":false}`
	productionProvenance  = `{"test_only":true,"author":"independent-fixture-author","generator":"literal-fixture","independent_of_production":true,"production_code":true}`
	dependentProvenance   = `{"test_only":true,"author":"independent-fixture-author","generator":"literal-fixture","independent_of_production":false,"production_code":false}`
	notTestOnlyFixture    = `{"test_only":false,"case":"unicode17-nfc","input_hex":"65cc81","expected_hex":"c3a9"}`
)

const (
	positiveFixtureSHA       = "c74829a1638ebce9c677adc8330ce04c3cc054c4bd64ba0f0bf888ffbafaa536"
	negativeFixtureSHA       = "300745b4aa750e1d8fdf2312637030f3643c7ce9a7eb2fc7b0e405ac101e54a8"
	independentProvenanceSHA = "e16942735c8971b8ec510d2fe9a14daf8527314d8649aacbdabd1c496cf07931"
	productionProvenanceSHA  = "16578c50368861b4cacaf4e9d9aec5e04fd5d61b6193298e7d83f9293aef68ac"
	dependentProvenanceSHA   = "2d33b86c00cf27727a1f27da38cc72ca43c84f1c6c469790f57678372f3f9c09"
	notTestOnlyFixtureSHA    = "a79f3fb7462911a84e2e18eca6591839be73d902dbe58de6a92b21065cb7fa6a"
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
      "sha256": "c74829a1638ebce9c677adc8330ce04c3cc054c4bd64ba0f0bf888ffbafaa536",
      "provenance_path": "provenance/nfc.json",
      "provenance_sha256": "e16942735c8971b8ec510d2fe9a14daf8527314d8649aacbdabd1c496cf07931",
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
      "sha256": "300745b4aa750e1d8fdf2312637030f3643c7ce9a7eb2fc7b0e405ac101e54a8",
      "provenance_path": "provenance/reject-unassigned.json",
      "provenance_sha256": "e16942735c8971b8ec510d2fe9a14daf8527314d8649aacbdabd1c496cf07931",
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

func TestLoadRefusesUnsafeOrUnpinnedProvenance(t *testing.T) {
	tests := []struct {
		name    string
		content string
		hash    string
		want    RefusalKind
	}{
		{
			name:    "production provenance",
			content: productionProvenance,
			hash:    productionProvenanceSHA,
			want:    RefusalProvenance,
		},
		{
			name:    "dependent provenance",
			content: dependentProvenance,
			hash:    dependentProvenanceSHA,
			want:    RefusalProvenance,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTestCorpus(t)
			writeTestFile(t, root, "provenance/nfc.json", tt.content)
			replaceManifest(t, root, independentProvenanceSHA, tt.hash)
			_, err := Load(root, testCustodyID)
			assertRefusal(t, err, tt.want)
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
			writeTestFile(t, caseRoot, "manifest.schema.json", `{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"$ref":"`+reference+`"}`)
			_, err := Load(caseRoot, testCustodyID)
			assertRefusal(t, err, RefusalSchema)
		})
	}
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
