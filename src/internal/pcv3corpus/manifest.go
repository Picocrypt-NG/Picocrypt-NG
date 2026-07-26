// Package pcv3corpus validates the private, Phase-1 PCV3 conformance corpus.
// It deliberately does not implement or generate PCV3 volume vectors.
package pcv3corpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	corpusFormat              = "pcv3-phase1-corpus-v1"
	phaseOneSchemaRevision    = "1"
	phaseOneSpecRevision      = "0.3"
	maxJSONNesting            = 64
	manifestSchemaName        = "manifest.schema.json"
	manifestName              = "manifest.json"
	manifestSchemaResourceURL = "https://pcv3.invalid/phase1/manifest.schema.json"
	draft2020URL              = "https://json-schema.org/draft/2020-12/schema"
)

// RefusalKind identifies a fixed, non-secret reason for rejecting a corpus.
// It never contains a caller-supplied root, fixture contents, or credentials.
type RefusalKind string

const (
	RefusalMissing    RefusalKind = "missing"
	RefusalExtra      RefusalKind = "extra"
	RefusalMalformed  RefusalKind = "malformed"
	RefusalUnknown    RefusalKind = "unknown"
	RefusalDuplicate  RefusalKind = "duplicate"
	RefusalGenerated  RefusalKind = "generated"
	RefusalSkipped    RefusalKind = "skipped"
	RefusalPath       RefusalKind = "path"
	RefusalSymlink    RefusalKind = "symlink"
	RefusalSchema     RefusalKind = "schema"
	RefusalCustody    RefusalKind = "custody"
	RefusalHash       RefusalKind = "hash"
	RefusalProvenance RefusalKind = "provenance"
	RefusalRoot       RefusalKind = "root"
)

// RefusalError intentionally exposes only a stable refusal kind. In
// particular, it must not wrap filesystem errors because those can reveal a
// private root supplied to Load.
type RefusalError struct {
	Kind RefusalKind
}

func (e *RefusalError) Error() string {
	if e == nil {
		return "pcv3 corpus: refused"
	}
	switch e.Kind {
	case RefusalMissing:
		return "pcv3 corpus: missing required entry"
	case RefusalExtra:
		return "pcv3 corpus: unexpected entry"
	case RefusalMalformed:
		return "pcv3 corpus: malformed input"
	case RefusalUnknown:
		return "pcv3 corpus: unknown input"
	case RefusalDuplicate:
		return "pcv3 corpus: duplicate input"
	case RefusalGenerated:
		return "pcv3 corpus: generated fixture is forbidden"
	case RefusalSkipped:
		return "pcv3 corpus: skipped fixture is forbidden"
	case RefusalPath:
		return "pcv3 corpus: invalid logical path"
	case RefusalSymlink:
		return "pcv3 corpus: symlink is forbidden"
	case RefusalSchema:
		return "pcv3 corpus: invalid schema"
	case RefusalCustody:
		return "pcv3 corpus: custody mismatch"
	case RefusalHash:
		return "pcv3 corpus: fixture hash mismatch"
	case RefusalProvenance:
		return "pcv3 corpus: invalid provenance"
	case RefusalRoot:
		return "pcv3 corpus: unavailable root"
	default:
		return "pcv3 corpus: refused"
	}
}

func refusal(kind RefusalKind) error {
	return &RefusalError{Kind: kind}
}

// Corpus is a verified Phase-1 corpus handle. It deliberately retains no
// filesystem root or fixture bytes after Load returns.
type Corpus struct {
	fixtureCount int
	specRevision string
}

type corpusManifest struct {
	format                string
	schemaRevision        string
	specRevision          string
	testOnly              bool
	custodyID             string
	fixtures              []fixtureManifest
	deferredVectorClasses []string
}

type fixtureManifest struct {
	id                  string
	path                string
	sha256              string
	provenancePath      string
	provenanceSHA256    string
	category            string
	outcome             string
	failureStage        string
	kdfCalls            json.Number
	publicationState    string
	forceState          string
	status              string
	generatedAtTestTime bool
}

var (
	errDuplicateJSONField = errors.New("duplicate JSON field")
	errMalformedJSON      = errors.New("malformed JSON")
)

func decodeStrictJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errMalformedJSON
	}
	return value, nil
}

func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth >= maxJSONNesting {
		return nil, errMalformedJSON
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errMalformedJSON
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, errMalformedJSON
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errMalformedJSON
				}
				if _, exists := object[key]; exists {
					return nil, errDuplicateJSONField
				}
				value, err := decodeJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errMalformedJSON
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				value, err := decodeJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errMalformedJSON
			}
			return array, nil
		default:
			return nil, errMalformedJSON
		}
	case string, bool, nil, json.Number:
		return token, nil
	default:
		return nil, errMalformedJSON
	}
}

type denyURLLoader struct{}

func (denyURLLoader) Load(string) (any, error) {
	return nil, errors.New("external schema references are forbidden")
}

func validateManifestSchema(schemaDocument, manifestDocument any) error {
	schemaObject, ok := schemaDocument.(map[string]any)
	if !ok {
		return refusal(RefusalSchema)
	}
	if schemaObject["$schema"] != draft2020URL {
		return refusal(RefusalSchema)
	}
	if schemaObject["$id"] != manifestSchemaResourceURL {
		return refusal(RefusalSchema)
	}
	closed, ok := schemaObject["additionalProperties"].(bool)
	if !ok || closed {
		return refusal(RefusalSchema)
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(denyURLLoader{})
	if err := compiler.AddResource(manifestSchemaResourceURL, schemaDocument); err != nil {
		return refusal(RefusalSchema)
	}
	schema, err := compiler.Compile(manifestSchemaResourceURL)
	if err != nil {
		return refusal(RefusalSchema)
	}
	if err := schema.Validate(manifestDocument); err != nil {
		return refusal(RefusalSchema)
	}
	return nil
}

func validateManifestPreconditions(document any) error {
	object, ok := document.(map[string]any)
	if !ok {
		return nil
	}
	if err := rejectUnknownFields(object, manifestFields); err != nil {
		return err
	}
	fixtures, ok := object["fixtures"].([]any)
	if !ok {
		return nil
	}
	for _, rawFixture := range fixtures {
		fixture, ok := rawFixture.(map[string]any)
		if !ok {
			continue
		}
		if err := rejectUnknownFields(fixture, fixtureFields); err != nil {
			return err
		}
		if category, ok := fixture["category"].(string); ok && category != "unicode17" && category != "governance" {
			return refusal(RefusalUnknown)
		}
		if status, ok := fixture["status"].(string); ok && status == "skipped" {
			return refusal(RefusalSkipped)
		}
		if generated, ok := fixture["generated_at_test_time"].(bool); ok && generated {
			return refusal(RefusalGenerated)
		}
		for _, field := range []string{"path", "provenance_path"} {
			if logicalPath, ok := fixture[field].(string); ok && !validPhaseOneFixturePath(field, logicalPath) {
				return refusal(RefusalPath)
			}
		}
	}
	return nil
}

var manifestFields = map[string]struct{}{
	"format": {}, "schema_revision": {}, "spec_revision": {}, "test_only": {},
	"custody_id": {}, "fixtures": {}, "deferred_vector_classes": {},
}

var fixtureFields = map[string]struct{}{
	"id": {}, "path": {}, "sha256": {}, "provenance_path": {}, "provenance_sha256": {},
	"category": {}, "outcome": {}, "failure_stage": {}, "kdf_calls": {}, "publication_state": {},
	"force_state": {}, "status": {}, "generated_at_test_time": {},
}

func rejectUnknownFields(object map[string]any, allowed map[string]struct{}) error {
	for field := range object {
		if _, ok := allowed[field]; !ok {
			return refusal(RefusalUnknown)
		}
	}
	return nil
}

func decodeManifest(document any) (corpusManifest, error) {
	object, ok := document.(map[string]any)
	if !ok {
		return corpusManifest{}, refusal(RefusalMalformed)
	}

	manifest := corpusManifest{}
	var err error
	if manifest.format, err = requiredString(object, "format"); err != nil {
		return corpusManifest{}, err
	}
	if manifest.schemaRevision, err = requiredString(object, "schema_revision"); err != nil {
		return corpusManifest{}, err
	}
	if manifest.specRevision, err = requiredString(object, "spec_revision"); err != nil {
		return corpusManifest{}, err
	}
	if manifest.testOnly, err = requiredBool(object, "test_only"); err != nil {
		return corpusManifest{}, err
	}
	if manifest.custodyID, err = requiredString(object, "custody_id"); err != nil {
		return corpusManifest{}, err
	}
	if manifest.deferredVectorClasses, err = requiredStrings(object, "deferred_vector_classes"); err != nil {
		return corpusManifest{}, err
	}

	fixtures, ok := object["fixtures"].([]any)
	if !ok || len(fixtures) == 0 {
		return corpusManifest{}, refusal(RefusalMalformed)
	}
	manifest.fixtures = make([]fixtureManifest, 0, len(fixtures))
	for _, rawFixture := range fixtures {
		fixture, err := decodeFixture(rawFixture)
		if err != nil {
			return corpusManifest{}, err
		}
		manifest.fixtures = append(manifest.fixtures, fixture)
	}
	if manifest.format != corpusFormat || manifest.schemaRevision != phaseOneSchemaRevision || manifest.specRevision != phaseOneSpecRevision || !manifest.testOnly || !contains(manifest.deferredVectorClasses, "full-pcv3-volume") {
		return corpusManifest{}, refusal(RefusalMalformed)
	}
	return manifest, nil
}

func decodeFixture(document any) (fixtureManifest, error) {
	object, ok := document.(map[string]any)
	if !ok {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}
	fixture := fixtureManifest{}
	var err error
	if fixture.id, err = requiredString(object, "id"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.path, err = requiredString(object, "path"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.sha256, err = requiredString(object, "sha256"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.provenancePath, err = requiredString(object, "provenance_path"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.provenanceSHA256, err = requiredString(object, "provenance_sha256"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.category, err = requiredString(object, "category"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.outcome, err = requiredString(object, "outcome"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.failureStage, err = requiredString(object, "failure_stage"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.publicationState, err = requiredString(object, "publication_state"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.forceState, err = requiredString(object, "force_state"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.status, err = requiredString(object, "status"); err != nil {
		return fixtureManifest{}, err
	}
	if fixture.generatedAtTestTime, err = requiredBool(object, "generated_at_test_time"); err != nil {
		return fixtureManifest{}, err
	}
	var okNumber bool
	if fixture.kdfCalls, okNumber = object["kdf_calls"].(json.Number); !okNumber {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}

	if fixture.id == "" || !validSHA256(fixture.sha256) || !validSHA256(fixture.provenanceSHA256) {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}
	if !validPhaseOneFixturePath("path", fixture.path) || !validPhaseOneFixturePath("provenance_path", fixture.provenancePath) {
		return fixtureManifest{}, refusal(RefusalPath)
	}
	if fixture.category != "unicode17" && fixture.category != "governance" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.outcome != "accept" && fixture.outcome != "reject" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.failureStage != "none" && fixture.failureStage != "canonicalization" && fixture.failureStage != "governance" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.publicationState != "not-published" && fixture.publicationState != "not-applicable" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.forceState != "not-applicable" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.status == "skipped" {
		return fixtureManifest{}, refusal(RefusalSkipped)
	}
	if fixture.status != "required" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.generatedAtTestTime {
		return fixtureManifest{}, refusal(RefusalGenerated)
	}
	if fixture.kdfCalls.String() != "0" {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}
	if fixture.outcome == "accept" && fixture.failureStage != "none" {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}
	if fixture.outcome == "reject" && ((fixture.category == "unicode17" && fixture.failureStage != "canonicalization") || (fixture.category == "governance" && fixture.failureStage != "governance")) {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}
	return fixture, nil
}

func validateFixtureSet(fixtures []fixtureManifest) error {
	var accepting, rejecting bool
	for _, fixture := range fixtures {
		directory, _, _ := strings.Cut(fixture.path, "/")
		switch fixture.outcome {
		case "accept":
			if directory != "positive" {
				return refusal(RefusalMalformed)
			}
			accepting = true
		case "reject":
			if directory != "negative" {
				return refusal(RefusalMalformed)
			}
			rejecting = true
		default:
			return refusal(RefusalUnknown)
		}
	}
	if !accepting || !rejecting {
		return refusal(RefusalMalformed)
	}
	return nil
}

func requiredString(object map[string]any, field string) (string, error) {
	value, ok := object[field].(string)
	if !ok || value == "" {
		return "", refusal(RefusalMalformed)
	}
	return value, nil
}

func requiredBool(object map[string]any, field string) (bool, error) {
	value, ok := object[field].(bool)
	if !ok {
		return false, refusal(RefusalMalformed)
	}
	return value, nil
}

func requiredStrings(object map[string]any, field string) ([]string, error) {
	rawValues, ok := object[field].([]any)
	if !ok || len(rawValues) == 0 {
		return nil, refusal(RefusalMalformed)
	}
	values := make([]string, 0, len(rawValues))
	for _, rawValue := range rawValues {
		value, ok := rawValue.(string)
		if !ok || value == "" {
			return nil, refusal(RefusalMalformed)
		}
		values = append(values, value)
	}
	return values, nil
}

func validSHA256(value string) bool {
	return len(value) == 64 && validLowerHex(value)
}

func validLowerHex(value string) bool {
	if len(value)%2 != 0 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
