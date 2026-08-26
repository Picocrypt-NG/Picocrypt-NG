// Package pcv3corpus validates the private PCV3 conformance corpus.
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
	corpusFormat                       = "pcv3-phase1-corpus-v1"
	cumulativeCorpusFormat             = "pcv3-corpus-v2"
	currentCorpusFormat                = "pcv3-corpus-v3"
	phaseOneSchemaRevision             = "1"
	cumulativeSchemaRevision           = "2"
	currentSchemaRevision              = "3"
	phaseOneSpecRevision               = "0.3"
	maxJSONNesting                     = 64
	manifestSchemaName                 = "manifest.schema.json"
	manifestName                       = "manifest.json"
	manifestSchemaResourceURL          = "https://pcv3.invalid/phase1/manifest.schema.json"
	cumulativeSchemaResourceURL        = "https://pcv3.invalid/cumulative/manifest.schema.json"
	currentSchemaResourceURL           = "https://pcv3.invalid/cumulative-v3/manifest.schema.json"
	draft2020URL                       = "https://json-schema.org/draft/2020-12/schema"
	phase4RequiredEvidence      uint64 = (1 << (len(phase4FixtureContracts) + len(normalFixtureContracts))) - 1
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

// Corpus is a verified corpus handle. It deliberately retains no
// filesystem root or fixture bytes after Load returns.
type Corpus struct {
	fixtureCount   int
	specRevision   string
	format         string
	phase4Evidence uint64
	d1Complete     bool
}

func (c *Corpus) isCurrentPhase4() bool {
	return c != nil && (c.format == currentCorpusFormat || c.format == d1CorpusFormat) && c.phase4Evidence == phase4RequiredEvidence
}

func (c *Corpus) isCurrentD1() bool {
	return c != nil && c.format == d1CorpusFormat && c.phase4Evidence == phase4RequiredEvidence && c.d1Complete
}

type corpusManifest struct {
	format                string
	schemaRevision        string
	specRevision          string
	testOnly              bool
	custodyID             string
	fixtures              []fixtureManifest
	deferredVectorClasses []string
	sourceArtifacts       []sourceArtifactManifest
}

type sourceArtifactManifest struct {
	id     string
	path   string
	sha256 string
	kind   string
}

type fixtureManifest struct {
	id                  string
	path                string
	sha256              string
	provenancePath      string
	provenanceSHA256    string
	generatorSourcePath string
	generatorSourceSHA  string
	category            string
	outcome             string
	failureStage        string
	kdfCalls            json.Number
	publicationState    string
	forceState          string
	status              string
	generatedAtTestTime bool
}

type phase4FixtureContract struct {
	id                    string
	category              string
	caseName              string
	suite                 string
	outcome               string
	failureStage          string
	kdfCalls              string
	authenticatedCapsules string
}

var phase4FixtureContracts = [...]phase4FixtureContract{
	{id: "stream-standard1-wrap", category: "stream", caseName: "standard1-wrap", suite: "standard1", outcome: "accept", failureStage: "none", kdfCalls: "0", authenticatedCapsules: "0"},
	{id: "stream-paranoid1-wrap", category: "stream", caseName: "paranoid1-wrap", suite: "paranoid1", outcome: "accept", failureStage: "none", kdfCalls: "0", authenticatedCapsules: "0"},
	{id: "capsule-standard1-healthy", category: "capsule", caseName: "healthy-standard1", suite: "standard1", outcome: "success", failureStage: "none", kdfCalls: "1", authenticatedCapsules: "2"},
	{id: "capsule-paranoid1-healthy", category: "capsule", caseName: "healthy-paranoid1", suite: "paranoid1", outcome: "success", failureStage: "none", kdfCalls: "1", authenticatedCapsules: "2"},
	{id: "capsule-damaged-wrap-tag", category: "capsule", caseName: "damaged-wrap-tag", suite: "standard1", outcome: "authenticated-degraded", failureStage: "wrap-auth", kdfCalls: "1", authenticatedCapsules: "1"},
	{id: "capsule-damaged-replica-tag", category: "capsule", caseName: "damaged-replica-tag", suite: "standard1", outcome: "authenticated-degraded", failureStage: "replica-auth", kdfCalls: "1", authenticatedCapsules: "1"},
	{id: "capsule-wrong-credential", category: "capsule", caseName: "wrong-credential", suite: "standard1", outcome: "credentials-or-damage", failureStage: "wrap-auth", kdfCalls: "1", authenticatedCapsules: "0"},
	{id: "capsule-divergent-public-tuple", category: "capsule", caseName: "divergent-public-tuple", suite: "standard1", outcome: "invalid-structure-pre-kdf", failureStage: "capsule-structure", kdfCalls: "0", authenticatedCapsules: "0"},
	{id: "capsule-authenticated-cross-volume-splice", category: "capsule", caseName: "authenticated-cross-volume-splice", suite: "standard1", outcome: "ambiguous-volume", failureStage: "capsule-structure", kdfCalls: "1", authenticatedCapsules: "2"},
}

func phase4Contract(id string) (phase4FixtureContract, uint64, bool) {
	for index, contract := range phase4FixtureContracts {
		if contract.id == id {
			return contract, uint64(1) << index, true
		}
	}
	return phase4FixtureContract{}, 0, false
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
	resourceURL, err := schemaResourceURL(manifestDocument)
	if err != nil {
		return err
	}
	schemaObject, ok := schemaDocument.(map[string]any)
	if !ok {
		return refusal(RefusalSchema)
	}
	if schemaObject["$schema"] != draft2020URL {
		return refusal(RefusalSchema)
	}
	if schemaObject["$id"] != resourceURL {
		return refusal(RefusalSchema)
	}
	closed, ok := schemaObject["additionalProperties"].(bool)
	if !ok || closed {
		return refusal(RefusalSchema)
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(denyURLLoader{})
	if err := compiler.AddResource(resourceURL, schemaDocument); err != nil {
		return refusal(RefusalSchema)
	}
	schema, err := compiler.Compile(resourceURL)
	if err != nil {
		return refusal(RefusalSchema)
	}
	if err := schema.Validate(manifestDocument); err != nil {
		return refusal(RefusalSchema)
	}
	return nil
}

func schemaResourceURL(manifestDocument any) (string, error) {
	object, ok := manifestDocument.(map[string]any)
	if !ok {
		return "", refusal(RefusalMalformed)
	}
	format, ok := object["format"].(string)
	if !ok {
		return "", refusal(RefusalMalformed)
	}
	switch format {
	case corpusFormat:
		return manifestSchemaResourceURL, nil
	case cumulativeCorpusFormat:
		return cumulativeSchemaResourceURL, nil
	case currentCorpusFormat:
		return currentSchemaResourceURL, nil
	case d1CorpusFormat:
		return d1SchemaResourceURL, nil
	default:
		return "", refusal(RefusalUnknown)
	}
}

func validateManifestPreconditions(document any) error {
	object, ok := document.(map[string]any)
	if !ok {
		return nil
	}
	format, ok := object["format"].(string)
	if !ok {
		return nil
	}
	if format != corpusFormat && format != cumulativeCorpusFormat && format != currentCorpusFormat && format != d1CorpusFormat {
		return refusal(RefusalUnknown)
	}
	allowedManifestFields := legacyManifestFields
	if format == currentCorpusFormat || format == d1CorpusFormat {
		allowedManifestFields = currentManifestFields
	}
	if err := rejectUnknownFields(object, allowedManifestFields); err != nil {
		return err
	}
	fixtures, ok := object["fixtures"].([]any)
	if !ok {
		return nil
	}
	var normalEvidence uint64
	for _, rawFixture := range fixtures {
		fixture, ok := rawFixture.(map[string]any)
		if !ok {
			continue
		}
		allowedFields := fixtureFields
		if format == cumulativeCorpusFormat || format == currentCorpusFormat || format == d1CorpusFormat {
			allowedFields = cumulativeFixtureFields
		}
		if err := rejectUnknownFields(fixture, allowedFields); err != nil {
			return err
		}
		if category, ok := fixture["category"].(string); ok && !validCategory(format, category) {
			return refusal(RefusalUnknown)
		}
		if status, ok := fixture["status"].(string); ok && status == "skipped" {
			return refusal(RefusalSkipped)
		}
		if generated, ok := fixture["generated_at_test_time"].(bool); ok && generated {
			return refusal(RefusalGenerated)
		}
		for _, field := range []string{"path", "provenance_path", "generator_source_path"} {
			if logicalPath, ok := fixture[field].(string); ok && !validCorpusEntryPath(field, logicalPath) {
				return refusal(RefusalPath)
			}
		}
		if format == currentCorpusFormat || format == d1CorpusFormat {
			id, idOK := fixture["id"].(string)
			category, categoryOK := fixture["category"].(string)
			if idOK && categoryOK && category == "normal-volume" {
				_, evidence, found := findNormalFixtureContract(id)
				if !found {
					return refusal(RefusalUnknown)
				}
				if normalEvidence&evidence != 0 {
					return refusal(RefusalDuplicate)
				}
				normalEvidence |= evidence
			}
		}
	}
	if format == currentCorpusFormat || format == d1CorpusFormat {
		if normalEvidence != normalRequiredEvidence {
			return refusal(RefusalMissing)
		}
		if err := validateSourceArtifactPreconditions(object["source_artifacts"]); err != nil {
			return err
		}
	}
	return nil
}

var legacyManifestFields = map[string]struct{}{
	"format": {}, "schema_revision": {}, "spec_revision": {}, "test_only": {},
	"custody_id": {}, "fixtures": {}, "deferred_vector_classes": {},
}

var currentManifestFields = map[string]struct{}{
	"format": {}, "schema_revision": {}, "spec_revision": {}, "test_only": {},
	"custody_id": {}, "fixtures": {}, "deferred_vector_classes": {}, "source_artifacts": {},
}

var fixtureFields = map[string]struct{}{
	"id": {}, "path": {}, "sha256": {}, "provenance_path": {}, "provenance_sha256": {},
	"category": {}, "outcome": {}, "failure_stage": {}, "kdf_calls": {}, "publication_state": {},
	"force_state": {}, "status": {}, "generated_at_test_time": {},
}

var cumulativeFixtureFields = map[string]struct{}{
	"id": {}, "path": {}, "sha256": {}, "provenance_path": {}, "provenance_sha256": {},
	"generator_source_path": {}, "generator_source_sha256": {}, "category": {}, "outcome": {},
	"failure_stage": {}, "kdf_calls": {}, "publication_state": {}, "force_state": {}, "status": {},
	"generated_at_test_time": {},
}

func validCategory(format, category string) bool {
	if category == "unicode17" || category == "governance" {
		return true
	}
	if category == "stream" || category == "capsule" {
		return format == cumulativeCorpusFormat || format == currentCorpusFormat || format == d1CorpusFormat
	}
	if category == "normal-volume" {
		return format == currentCorpusFormat || format == d1CorpusFormat
	}
	return format == d1CorpusFormat && (category == "d1-volume" || category == "d1-mutation-plan")
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
	if manifest.format == currentCorpusFormat || manifest.format == d1CorpusFormat {
		if manifest.sourceArtifacts, err = decodeSourceArtifacts(object["source_artifacts"]); err != nil {
			return corpusManifest{}, err
		}
	} else if _, exists := object["source_artifacts"]; exists {
		return corpusManifest{}, refusal(RefusalUnknown)
	}

	fixtures, ok := object["fixtures"].([]any)
	if !ok || len(fixtures) == 0 {
		return corpusManifest{}, refusal(RefusalMalformed)
	}
	manifest.fixtures = make([]fixtureManifest, 0, len(fixtures))
	for _, rawFixture := range fixtures {
		fixture, err := decodeFixture(rawFixture, manifest.format)
		if err != nil {
			return corpusManifest{}, err
		}
		manifest.fixtures = append(manifest.fixtures, fixture)
	}
	validVersion := (manifest.format == corpusFormat && manifest.schemaRevision == phaseOneSchemaRevision) ||
		(manifest.format == cumulativeCorpusFormat && manifest.schemaRevision == cumulativeSchemaRevision) ||
		(manifest.format == currentCorpusFormat && manifest.schemaRevision == currentSchemaRevision) ||
		(manifest.format == d1CorpusFormat && manifest.schemaRevision == d1SchemaRevision)
	validDeferrals := contains(manifest.deferredVectorClasses, "full-pcv3-volume")
	if manifest.format == currentCorpusFormat {
		validDeferrals = sameStringSet(manifest.deferredVectorClasses, []string{"pcv3-writer", "d1-volumes", "force-recovery"})
	} else if manifest.format == d1CorpusFormat {
		validDeferrals = sameStringSet(manifest.deferredVectorClasses, []string{"pcv3-writer"})
	}
	validSpecRevision := manifest.specRevision == phaseOneSpecRevision
	if manifest.format == d1CorpusFormat {
		validSpecRevision = manifest.specRevision == d1SpecRevision
	}
	if !validVersion || !validSpecRevision || !manifest.testOnly || !validDeferrals {
		return corpusManifest{}, refusal(RefusalMalformed)
	}
	return manifest, nil
}

func decodeFixture(document any, format string) (fixtureManifest, error) {
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
	if _, exists := object["generator_source_path"]; exists {
		if fixture.generatorSourcePath, err = requiredString(object, "generator_source_path"); err != nil {
			return fixtureManifest{}, err
		}
	}
	if _, exists := object["generator_source_sha256"]; exists {
		if fixture.generatorSourceSHA, err = requiredString(object, "generator_source_sha256"); err != nil {
			return fixtureManifest{}, err
		}
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
	if !validCorpusEntryPath("path", fixture.path) || !validCorpusEntryPath("provenance_path", fixture.provenancePath) {
		return fixtureManifest{}, refusal(RefusalPath)
	}
	if !validCategory(format, fixture.category) {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.publicationState != "not-published" && fixture.publicationState != "not-applicable" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.category != "d1-volume" && fixture.forceState != "not-applicable" {
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
	if fixture.category == "stream" || fixture.category == "capsule" {
		contract, _, found := phase4Contract(fixture.id)
		if !found {
			return fixtureManifest{}, refusal(RefusalUnknown)
		}
		if fixture.generatorSourcePath == "" || !validCorpusEntryPath("generator_source_path", fixture.generatorSourcePath) || !validSHA256(fixture.generatorSourceSHA) {
			return fixtureManifest{}, refusal(RefusalMalformed)
		}
		if fixture.category != contract.category || fixture.outcome != contract.outcome || fixture.failureStage != contract.failureStage || fixture.kdfCalls.String() != contract.kdfCalls {
			return fixtureManifest{}, refusal(RefusalMalformed)
		}
		return fixture, nil
	}
	if fixture.category == "normal-volume" {
		contract, _, found := findNormalFixtureContract(fixture.id)
		if !found {
			return fixtureManifest{}, refusal(RefusalUnknown)
		}
		if fixture.generatorSourcePath == "" || !validCorpusEntryPath("generator_source_path", fixture.generatorSourcePath) || !validSHA256(fixture.generatorSourceSHA) {
			return fixtureManifest{}, refusal(RefusalMalformed)
		}
		if fixture.outcome != contract.outcome || fixture.failureStage != contract.failureStage || fixture.kdfCalls.String() != contract.kdfCalls || fixture.publicationState != "not-applicable" {
			return fixtureManifest{}, refusal(RefusalMalformed)
		}
		return fixture, nil
	}
	if fixture.category == "d1-volume" {
		_, _, found := findD1Artifact(fixture.id)
		if !found {
			return fixtureManifest{}, refusal(RefusalUnknown)
		}
		if fixture.generatorSourcePath == "" || !validCorpusEntryPath("generator_source_path", fixture.generatorSourcePath) || !validSHA256(fixture.generatorSourceSHA) {
			return fixtureManifest{}, refusal(RefusalMalformed)
		}
		kdfCalls, err := fixture.kdfCalls.Int64()
		if !contains([]string{"success", "authenticated-degraded", "credentials-or-damage", "authentication-failed", "ambiguous-volume"}, fixture.outcome) ||
			!contains([]string{"none", "d1-bootstrap", "d1-body", "inner-volume"}, fixture.failureStage) ||
			err != nil || kdfCalls < 0 || kdfCalls > 4 || fixture.publicationState != "not-applicable" ||
			!contains([]string{"not-applicable", "verified", "partial", "unverified"}, fixture.forceState) {
			return fixtureManifest{}, refusal(RefusalMalformed)
		}
		return fixture, nil
	}
	if fixture.category == "d1-mutation-plan" {
		if fixture.id != d1MutationPlanID || fixture.generatorSourcePath == "" ||
			!validCorpusEntryPath("generator_source_path", fixture.generatorSourcePath) || !validSHA256(fixture.generatorSourceSHA) ||
			fixture.outcome != "accept" || fixture.failureStage != "none" || fixture.kdfCalls.String() != "0" ||
			fixture.publicationState != "not-applicable" || fixture.forceState != "not-applicable" {
			return fixtureManifest{}, refusal(RefusalMalformed)
		}
		return fixture, nil
	}
	if fixture.generatorSourcePath != "" || fixture.generatorSourceSHA != "" {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}
	if fixture.outcome != "accept" && fixture.outcome != "reject" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.failureStage != "none" && fixture.failureStage != "canonicalization" && fixture.failureStage != "governance" {
		return fixtureManifest{}, refusal(RefusalUnknown)
	}
	if fixture.kdfCalls.String() != "0" || fixture.outcome == "accept" && fixture.failureStage != "none" {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}
	if fixture.outcome == "reject" && ((fixture.category == "unicode17" && fixture.failureStage != "canonicalization") || (fixture.category == "governance" && fixture.failureStage != "governance")) {
		return fixtureManifest{}, refusal(RefusalMalformed)
	}
	return fixture, nil
}

func validateFixtureSet(manifest corpusManifest) error {
	var accepting, rejecting bool
	var evidence uint64
	for _, fixture := range manifest.fixtures {
		directory, _, _ := strings.Cut(fixture.path, "/")
		switch fixture.outcome {
		case "accept", "success", "authenticated-degraded":
			if directory != "positive" {
				return refusal(RefusalMalformed)
			}
			if fixture.outcome == "accept" && (fixture.category == "unicode17" || fixture.category == "governance") {
				accepting = true
			}
		case "reject", "credentials-or-damage", "invalid-structure-pre-kdf", "ambiguous-volume", "authentication-failed":
			if directory != "negative" {
				return refusal(RefusalMalformed)
			}
			if fixture.outcome == "reject" {
				rejecting = true
			}
		default:
			return refusal(RefusalUnknown)
		}
		if _, fixtureEvidence, found := phase4Contract(fixture.id); found {
			evidence |= fixtureEvidence
		}
		if _, fixtureEvidence, found := findNormalFixtureContract(fixture.id); found {
			evidence |= fixtureEvidence
		}
	}
	if !accepting || !rejecting {
		return refusal(RefusalMalformed)
	}
	if (manifest.format == currentCorpusFormat || manifest.format == d1CorpusFormat) && evidence != phase4RequiredEvidence {
		return refusal(RefusalMissing)
	}
	d1Complete, err := validateD1FixtureInventory(manifest.fixtures)
	if err != nil {
		return err
	}
	if manifest.format == d1CorpusFormat && !d1Complete {
		return refusal(RefusalMissing)
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

func sameStringSet(values, wanted []string) bool {
	if len(values) != len(wanted) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	for _, value := range wanted {
		if _, found := seen[value]; !found {
			return false
		}
	}
	return true
}
