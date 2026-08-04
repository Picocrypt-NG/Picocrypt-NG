package pcv3corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxManifestFileBytes       = 1 << 20
	maxLegacyFixtureFileBytes  = 1 << 20
	maxStreamFixtureFileBytes  = 64 << 10
	maxCapsuleFixtureFileBytes = 64 << 10
	maxNormalFixtureFileBytes  = 16 << 20
	maxProvenanceFileBytes     = 256 << 10
	maxGeneratorFileBytes      = 1 << 20
	maxDependencyLockBytes     = 1 << 20
	maxSourceVectorBytes       = 4 << 20
)

// Load validates a caller-selected private corpus root and opaque custody ID.
// The root is opened once through os.Root, is never retained, and is never
// included in returned errors.
func Load(rootPath, custodyID string) (*Corpus, error) {
	corpus, _, err := loadCorpus(rootPath, custodyID, nil)
	return corpus, err
}

func loadCorpus(rootPath, custodyID string, selected map[string]struct{}) (*Corpus, map[string][]byte, error) {
	if rootPath == "" {
		return nil, nil, refusal(RefusalRoot)
	}
	if custodyID == "" {
		return nil, nil, refusal(RefusalCustody)
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, nil, refusal(RefusalRoot)
	}
	defer root.Close()

	schemaBytes, err := readRegular(root, manifestSchemaName, maxManifestFileBytes)
	if err != nil {
		return nil, nil, err
	}
	manifestBytes, err := readRegular(root, manifestName, maxManifestFileBytes)
	if err != nil {
		return nil, nil, err
	}

	schemaDocument, err := decodeStrictJSON(schemaBytes)
	if err != nil {
		return nil, nil, refusalForSchemaJSON(err)
	}
	manifestDocument, err := decodeStrictJSON(manifestBytes)
	if err != nil {
		return nil, nil, refusalForManifestJSON(err)
	}
	if err := validateManifestPreconditions(manifestDocument); err != nil {
		return nil, nil, err
	}
	if err := validateManifestSchema(schemaDocument, manifestDocument); err != nil {
		return nil, nil, err
	}
	manifest, err := decodeManifest(manifestDocument)
	if err != nil {
		return nil, nil, err
	}
	if manifest.custodyID != custodyID {
		return nil, nil, refusal(RefusalCustody)
	}

	expectedFiles, expectedDirectories, err := expectedInventory(manifest)
	if err != nil {
		return nil, nil, err
	}
	if err := validateFixtureSet(manifest); err != nil {
		return nil, nil, err
	}
	actualFiles, actualDirectories, err := enumerateRoot(root)
	if err != nil {
		return nil, nil, err
	}
	if err := compareInventory(expectedFiles, expectedDirectories, actualFiles, actualDirectories); err != nil {
		return nil, nil, err
	}

	if err := validateSourceArtifacts(root, manifest.sourceArtifacts); err != nil {
		return nil, nil, err
	}
	selectedDocuments := make(map[string][]byte, len(selected))
	for _, fixture := range manifest.fixtures {
		_, keep := selected[fixture.id]
		document, err := validateFixture(root, fixture, keep)
		if err != nil {
			zeroDocumentMap(selectedDocuments)
			return nil, nil, err
		}
		if keep {
			selectedDocuments[fixture.id] = document
		}
	}
	if selected != nil && manifest.format != currentCorpusFormat {
		zeroDocumentMap(selectedDocuments)
		return nil, nil, refusal(RefusalUnknown)
	}
	var phase4Evidence uint64
	for _, fixture := range manifest.fixtures {
		if _, evidence, found := phase4Contract(fixture.id); found {
			phase4Evidence |= evidence
		}
		if _, evidence, found := findNormalFixtureContract(fixture.id); found {
			phase4Evidence |= evidence
		}
	}
	return &Corpus{
		fixtureCount:   len(manifest.fixtures),
		specRevision:   manifest.specRevision,
		format:         manifest.format,
		phase4Evidence: phase4Evidence,
	}, selectedDocuments, nil
}

func refusalForSchemaJSON(err error) error {
	if errors.Is(err, errDuplicateJSONField) {
		return refusal(RefusalDuplicate)
	}
	return refusal(RefusalSchema)
}

func refusalForManifestJSON(err error) error {
	if errors.Is(err, errDuplicateJSONField) {
		return refusal(RefusalDuplicate)
	}
	return refusal(RefusalMalformed)
}

func readRegular(root *os.Root, logicalName string, maxBytes int64) ([]byte, error) {
	if !validLogicalPath(logicalName) {
		return nil, refusal(RefusalPath)
	}
	name := filepath.FromSlash(logicalName)
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, refusal(RefusalMissing)
	}
	if err != nil {
		return nil, refusal(RefusalMalformed)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, refusal(RefusalSymlink)
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, refusal(RefusalMalformed)
	}

	file, err := root.Open(name)
	if err != nil {
		return nil, refusal(RefusalMalformed)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, refusal(RefusalMalformed)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, refusal(RefusalMalformed)
	}
	return data, nil
}

func validLogicalPath(value string) bool {
	if value == "" || value == "." || !fs.ValidPath(value) {
		return false
	}
	if filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return false
	}
	return !strings.Contains(value, "\\") && !strings.Contains(value, ":")
}

func validCorpusEntryPath(field, value string) bool {
	if !validLogicalPath(value) {
		return false
	}
	component, remainder, nested := strings.Cut(value, "/")
	if !nested || remainder == "" {
		return false
	}
	switch field {
	case "path":
		return component == "positive" || component == "negative"
	case "provenance_path":
		return component == "provenance"
	case "generator_source_path":
		return component == "generator" && strings.HasSuffix(remainder, ".go")
	case "source_artifact_path":
		return component == "generator"
	default:
		return false
	}
}

func expectedInventory(manifest corpusManifest) (map[string]struct{}, map[string]struct{}, error) {
	files := map[string]struct{}{
		manifestSchemaName: {},
		manifestName:       {},
	}
	identifiers := make(map[string]struct{}, len(manifest.fixtures))
	for _, fixture := range manifest.fixtures {
		if _, exists := identifiers[fixture.id]; exists {
			return nil, nil, refusal(RefusalDuplicate)
		}
		identifiers[fixture.id] = struct{}{}
		for _, name := range []string{fixture.path, fixture.provenancePath} {
			if _, exists := files[name]; exists {
				return nil, nil, refusal(RefusalDuplicate)
			}
			files[name] = struct{}{}
		}
		if fixture.generatorSourcePath != "" {
			files[fixture.generatorSourcePath] = struct{}{}
		}
	}
	artifactIDs := make(map[string]struct{}, len(manifest.sourceArtifacts))
	artifactPaths := make(map[string]struct{}, len(manifest.sourceArtifacts))
	for _, artifact := range manifest.sourceArtifacts {
		if _, exists := artifactIDs[artifact.id]; exists {
			return nil, nil, refusal(RefusalDuplicate)
		}
		artifactIDs[artifact.id] = struct{}{}
		if _, exists := artifactPaths[artifact.path]; exists {
			return nil, nil, refusal(RefusalDuplicate)
		}
		artifactPaths[artifact.path] = struct{}{}
		files[artifact.path] = struct{}{}
	}

	directories := make(map[string]struct{})
	for name := range files {
		for directory := path.Dir(name); directory != "."; directory = path.Dir(directory) {
			directories[directory] = struct{}{}
		}
	}
	return files, directories, nil
}

func enumerateRoot(root *os.Root) (map[string]struct{}, map[string]struct{}, error) {
	files := make(map[string]struct{})
	directories := make(map[string]struct{})
	var walk func(directory string) error
	walk = func(directory string) error {
		entries, err := fs.ReadDir(root.FS(), directory)
		if err != nil {
			return refusal(RefusalMalformed)
		}
		for _, entry := range entries {
			logicalName := entry.Name()
			if directory != "." {
				logicalName = path.Join(directory, logicalName)
			}
			if !validLogicalPath(logicalName) {
				return refusal(RefusalPath)
			}
			info, err := root.Lstat(filepath.FromSlash(logicalName))
			if err != nil {
				return refusal(RefusalMalformed)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return refusal(RefusalSymlink)
			}
			if info.IsDir() {
				directories[logicalName] = struct{}{}
				if err := walk(logicalName); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() {
				return refusal(RefusalMalformed)
			}
			files[logicalName] = struct{}{}
		}
		return nil
	}
	if err := walk("."); err != nil {
		return nil, nil, err
	}
	return files, directories, nil
}

func compareInventory(expectedFiles, expectedDirectories, actualFiles, actualDirectories map[string]struct{}) error {
	for name := range actualFiles {
		if _, ok := expectedFiles[name]; !ok {
			return refusal(RefusalExtra)
		}
	}
	for name := range actualDirectories {
		if _, ok := expectedDirectories[name]; !ok {
			return refusal(RefusalExtra)
		}
	}
	for name := range expectedFiles {
		if _, ok := actualFiles[name]; !ok {
			return refusal(RefusalMissing)
		}
	}
	for name := range expectedDirectories {
		if _, ok := actualDirectories[name]; !ok {
			return refusal(RefusalMissing)
		}
	}
	return nil
}

func validateFixture(root *os.Root, fixture fixtureManifest, keep bool) ([]byte, error) {
	fixtureData, err := readRegular(root, fixture.path, fixtureFileLimit(fixture.category))
	if err != nil {
		return nil, err
	}
	retainFixtureData := false
	defer func() {
		if !retainFixtureData {
			zeroBytes(fixtureData)
		}
	}()
	if !matchesSHA256(fixtureData, fixture.sha256) {
		return nil, refusal(RefusalHash)
	}
	if err := validateFixtureDocument(fixtureData, fixture); err != nil {
		return nil, err
	}

	if fixture.generatorSourcePath != "" {
		generatorData, err := readRegular(root, fixture.generatorSourcePath, maxGeneratorFileBytes)
		if err != nil {
			return nil, err
		}
		defer zeroBytes(generatorData)
		if !matchesSHA256(generatorData, fixture.generatorSourceSHA) {
			return nil, refusal(RefusalHash)
		}
		if err := validateGeneratorSource(generatorData); err != nil {
			return nil, err
		}
	}

	provenanceData, err := readRegular(root, fixture.provenancePath, maxProvenanceFileBytes)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(provenanceData)
	if !matchesSHA256(provenanceData, fixture.provenanceSHA256) {
		return nil, refusal(RefusalHash)
	}
	if err := validateProvenanceDocument(provenanceData, fixture.generatorSourceSHA); err != nil {
		return nil, err
	}
	if keep {
		retainFixtureData = true
		return fixtureData, nil
	}
	return nil, nil
}

func fixtureFileLimit(category string) int64 {
	switch category {
	case "stream":
		return maxStreamFixtureFileBytes
	case "capsule":
		return maxCapsuleFixtureFileBytes
	case "normal-volume":
		return maxNormalFixtureFileBytes
	default:
		return maxLegacyFixtureFileBytes
	}
}

func matchesSHA256(data []byte, expected string) bool {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]) == expected
}

func validateFixtureDocument(data []byte, fixture fixtureManifest) error {
	document, err := decodeStrictJSON(data)
	if err != nil {
		return refusalForManifestJSON(err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return refusal(RefusalMalformed)
	}
	category, err := requiredString(object, "category")
	if err != nil {
		return err
	}
	allowedFields := fixtureDocumentFields
	switch category {
	case "unicode17", "governance":
	case "stream":
		allowedFields = streamFixtureDocumentFields
	case "capsule":
		allowedFields = capsuleFixtureDocumentFields
	case "normal-volume":
		allowedFields = normalFixtureDocumentFields
	default:
		return refusal(RefusalUnknown)
	}
	if err := rejectUnknownFields(object, allowedFields); err != nil {
		return err
	}
	testOnly, ok := object["test_only"].(bool)
	if !ok || !testOnly {
		return refusal(RefusalMalformed)
	}
	fixtureID, err := requiredString(object, "id")
	if err != nil {
		return err
	}
	caseID, err := requiredString(object, "case")
	if err != nil {
		return err
	}
	status, err := requiredString(object, "status")
	if err != nil {
		return err
	}
	generated, err := requiredBool(object, "generated_at_test_time")
	if err != nil {
		return err
	}
	if fixtureID != fixture.id || category != fixture.category {
		return refusal(RefusalMalformed)
	}
	if status == "skipped" {
		return refusal(RefusalSkipped)
	}
	if status != "required" {
		return refusal(RefusalUnknown)
	}
	if generated {
		return refusal(RefusalGenerated)
	}

	if category == "stream" || category == "capsule" {
		contract, _, found := phase4Contract(fixture.id)
		if !found {
			return refusal(RefusalUnknown)
		}
		if caseID != contract.caseName {
			return refusal(RefusalMalformed)
		}
		if category == "stream" {
			return validateStreamFixtureDocument(object, fixture, contract)
		}
		return validateCapsuleFixtureDocument(object, fixture, contract)
	}
	if category == "normal-volume" {
		contract, _, found := findNormalFixtureContract(fixture.id)
		if !found {
			return refusal(RefusalUnknown)
		}
		if caseID != contract.caseName {
			return refusal(RefusalMalformed)
		}
		return validateNormalFixtureDocument(object, fixture, contract)
	}
	if caseID != fixture.id {
		return refusal(RefusalMalformed)
	}
	inputHex, err := requiredHex(object, "input_hex")
	if err != nil || !validLowerHex(inputHex) {
		return refusal(RefusalMalformed)
	}
	switch fixture.outcome {
	case "accept":
		if _, exists := object["expected"]; exists {
			return refusal(RefusalMalformed)
		}
		expectedHex, err := requiredHex(object, "expected_hex")
		if err != nil || !validLowerHex(expectedHex) {
			return refusal(RefusalMalformed)
		}
		return nil
	case "reject":
		if _, exists := object["expected_hex"]; exists {
			return refusal(RefusalMalformed)
		}
		expected, err := requiredString(object, "expected")
		if err != nil || expected != "reject" {
			return refusal(RefusalMalformed)
		}
		return nil
	default:
		return refusal(RefusalUnknown)
	}
}

func validateStreamFixtureDocument(object map[string]any, fixture fixtureManifest, contract phase4FixtureContract) error {
	suite, err := requiredString(object, "suite")
	if err != nil {
		return err
	}
	if suite != "standard1" && suite != "paranoid1" {
		return refusal(RefusalUnknown)
	}
	if suite != contract.suite || fixture.outcome != "accept" || fixture.failureStage != "none" || fixture.kdfCalls.String() != "0" {
		return refusal(RefusalMalformed)
	}
	for field, size := range map[string]int{
		"xchacha_key_hex": 32, "xchacha_nonce_hex": 24,
		"volume_key_hex": 32, "wrapped_volume_key_hex": 32,
	} {
		if _, err := requiredSizedHex(object, field, size); err != nil {
			return err
		}
	}
	if suite == "standard1" {
		if _, exists := object["serpent_key_hex"]; exists {
			return refusal(RefusalMalformed)
		}
		if _, exists := object["serpent_iv_hex"]; exists {
			return refusal(RefusalMalformed)
		}
		return nil
	}
	if _, err := requiredSizedHex(object, "serpent_key_hex", 32); err != nil {
		return err
	}
	if _, err := requiredSizedHex(object, "serpent_iv_hex", 16); err != nil {
		return err
	}
	return nil
}

func validateCapsuleFixtureDocument(object map[string]any, fixture fixtureManifest, contract phase4FixtureContract) error {
	suite, err := requiredString(object, "suite")
	if err != nil {
		return err
	}
	if suite != "standard1" && suite != "paranoid1" {
		return refusal(RefusalUnknown)
	}
	if suite != contract.suite {
		return refusal(RefusalMalformed)
	}
	passwordHex, err := requiredHex(object, "password_utf8_hex")
	if err != nil || passwordHex == "" || !validLowerHex(passwordHex) {
		return refusal(RefusalMalformed)
	}
	password, err := hex.DecodeString(passwordHex)
	if err != nil || !utf8.Valid(password) {
		return refusal(RefusalMalformed)
	}
	for field, size := range map[string]int{
		"credential_root_hex": 32, "primary_decoded_hex": 320,
		"backup_decoded_hex": 320, "expected_volume_key_hex": 32,
	} {
		if _, err := requiredSizedHex(object, field, size); err != nil {
			return err
		}
	}
	expectedOutcome, err := requiredString(object, "expected_outcome")
	if err != nil {
		return err
	}
	expectedStage, err := requiredString(object, "expected_stage")
	if err != nil {
		return err
	}
	expectedKDFCalls, err := requiredNumberString(object, "expected_kdf_calls")
	if err != nil {
		return err
	}
	authenticatedCapsules, err := requiredNumberString(object, "expected_authenticated_capsules")
	if err != nil {
		return err
	}
	if expectedOutcome != contract.outcome || expectedStage != contract.failureStage || expectedKDFCalls != contract.kdfCalls || authenticatedCapsules != contract.authenticatedCapsules {
		return refusal(RefusalMalformed)
	}
	if fixture.outcome != expectedOutcome || fixture.failureStage != expectedStage || fixture.kdfCalls.String() != expectedKDFCalls {
		return refusal(RefusalMalformed)
	}
	return nil
}

var fixtureDocumentFields = map[string]struct{}{
	"test_only": {}, "id": {}, "category": {}, "case": {}, "input_hex": {},
	"expected": {}, "expected_hex": {}, "status": {}, "generated_at_test_time": {},
}

var streamFixtureDocumentFields = map[string]struct{}{
	"test_only": {}, "id": {}, "category": {}, "case": {}, "suite": {},
	"xchacha_key_hex": {}, "xchacha_nonce_hex": {}, "serpent_key_hex": {}, "serpent_iv_hex": {},
	"volume_key_hex": {}, "wrapped_volume_key_hex": {}, "status": {}, "generated_at_test_time": {},
}

var capsuleFixtureDocumentFields = map[string]struct{}{
	"test_only": {}, "id": {}, "category": {}, "case": {}, "suite": {}, "password_utf8_hex": {},
	"credential_root_hex": {}, "primary_decoded_hex": {}, "backup_decoded_hex": {}, "expected_volume_key_hex": {},
	"expected_outcome": {}, "expected_stage": {}, "expected_kdf_calls": {}, "expected_authenticated_capsules": {},
	"status": {}, "generated_at_test_time": {},
}

func requiredHex(object map[string]any, field string) (string, error) {
	value, ok := object[field].(string)
	if !ok {
		return "", refusal(RefusalMalformed)
	}
	return value, nil
}

func requiredSizedHex(object map[string]any, field string, size int) (string, error) {
	value, err := requiredHex(object, field)
	if err != nil || len(value) != size*2 || !validLowerHex(value) {
		return "", refusal(RefusalMalformed)
	}
	return value, nil
}

func requiredNumberString(object map[string]any, field string) (string, error) {
	value, ok := object[field].(json.Number)
	if !ok {
		return "", refusal(RefusalMalformed)
	}
	return value.String(), nil
}

func validateProvenanceDocument(data []byte, expectedSourceSHA string) error {
	document, err := decodeStrictJSON(data)
	if err != nil {
		if errors.Is(err, errDuplicateJSONField) {
			return refusal(RefusalDuplicate)
		}
		return refusal(RefusalProvenance)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return refusal(RefusalProvenance)
	}
	if err := rejectUnknownFields(object, provenanceFields); err != nil {
		return err
	}
	testOnly, testOnlyOK := object["test_only"].(bool)
	author, authorOK := object["author"].(string)
	generator, generatorOK := object["generator"].(string)
	generatorVersion, generatorVersionOK := object["generator_version"].(string)
	sourceRevision, sourceRevisionOK := object["source_revision"].(string)
	sourceSHA256, sourceSHA256OK := object["source_sha256"].(string)
	dependencyLock, dependencyLockOK := object["dependency_lock"].(string)
	dependencyLockSHA256, dependencyLockSHA256OK := object["dependency_lock_sha256"].(string)
	reproductionCommand, reproductionCommandOK := object["reproduction_command"].(string)
	independent, independentOK := object["independent_of_production"].(bool)
	production, productionOK := object["production_code"].(bool)
	if !testOnlyOK || !authorOK || author == "" || !generatorOK || generator == "" || !generatorVersionOK || generatorVersion == "" || !sourceRevisionOK || sourceRevision == "" || !sourceSHA256OK || !validSHA256(sourceSHA256) || !dependencyLockOK || dependencyLock == "" || !dependencyLockSHA256OK || !validSHA256(dependencyLockSHA256) || !reproductionCommandOK || reproductionCommand == "" || !independentOK || !productionOK || !testOnly || !independent || production {
		return refusal(RefusalProvenance)
	}
	digest := sha256.Sum256([]byte(dependencyLock))
	if hex.EncodeToString(digest[:]) != dependencyLockSHA256 {
		return refusal(RefusalProvenance)
	}
	if expectedSourceSHA != "" && sourceSHA256 != expectedSourceSHA {
		return refusal(RefusalProvenance)
	}
	return nil
}

func validateGeneratorSource(data []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "", data, parser.ImportsOnly)
	if err != nil || file.Name == nil || file.Name.Name != "main" {
		return refusal(RefusalProvenance)
	}
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil || importPath == "Picocrypt-NG" || strings.HasPrefix(importPath, "Picocrypt-NG/") {
			return refusal(RefusalProvenance)
		}
	}
	return nil
}

var provenanceFields = map[string]struct{}{
	"test_only": {}, "author": {}, "generator": {}, "generator_version": {}, "source_revision": {}, "source_sha256": {}, "dependency_lock": {}, "dependency_lock_sha256": {}, "reproduction_command": {}, "independent_of_production": {}, "production_code": {},
}
