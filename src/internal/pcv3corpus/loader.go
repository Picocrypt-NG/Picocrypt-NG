package pcv3corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxPhaseOneFileBytes = 1 << 20

// Load validates a caller-selected private corpus root and opaque custody ID.
// The root is opened once through os.Root, is never retained, and is never
// included in returned errors.
func Load(rootPath, custodyID string) (*Corpus, error) {
	if rootPath == "" {
		return nil, refusal(RefusalRoot)
	}
	if custodyID == "" {
		return nil, refusal(RefusalCustody)
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, refusal(RefusalRoot)
	}
	defer root.Close()

	schemaBytes, err := readRegular(root, manifestSchemaName)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := readRegular(root, manifestName)
	if err != nil {
		return nil, err
	}

	schemaDocument, err := decodeStrictJSON(schemaBytes)
	if err != nil {
		return nil, refusalForSchemaJSON(err)
	}
	manifestDocument, err := decodeStrictJSON(manifestBytes)
	if err != nil {
		return nil, refusalForManifestJSON(err)
	}
	if err := validateManifestPreconditions(manifestDocument); err != nil {
		return nil, err
	}
	if err := validateManifestSchema(schemaDocument, manifestDocument); err != nil {
		return nil, err
	}
	manifest, err := decodeManifest(manifestDocument)
	if err != nil {
		return nil, err
	}
	if manifest.custodyID != custodyID {
		return nil, refusal(RefusalCustody)
	}

	expectedFiles, expectedDirectories, err := expectedInventory(manifest)
	if err != nil {
		return nil, err
	}
	if err := validateFixtureSet(manifest.fixtures); err != nil {
		return nil, err
	}
	actualFiles, actualDirectories, err := enumerateRoot(root)
	if err != nil {
		return nil, err
	}
	if err := compareInventory(expectedFiles, expectedDirectories, actualFiles, actualDirectories); err != nil {
		return nil, err
	}

	for _, fixture := range manifest.fixtures {
		if err := validateFixture(root, fixture); err != nil {
			return nil, err
		}
	}
	return &Corpus{fixtureCount: len(manifest.fixtures), specRevision: manifest.specRevision}, nil
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

func readRegular(root *os.Root, logicalName string) ([]byte, error) {
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
	if !info.Mode().IsRegular() || info.Size() > maxPhaseOneFileBytes {
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
	data, err := io.ReadAll(io.LimitReader(file, maxPhaseOneFileBytes+1))
	if err != nil || len(data) > maxPhaseOneFileBytes {
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

func validPhaseOneFixturePath(field, value string) bool {
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

func validateFixture(root *os.Root, fixture fixtureManifest) error {
	fixtureData, err := readRegular(root, fixture.path)
	if err != nil {
		return err
	}
	if !matchesSHA256(fixtureData, fixture.sha256) {
		return refusal(RefusalHash)
	}
	if err := validateFixtureDocument(fixtureData, fixture); err != nil {
		return err
	}

	provenanceData, err := readRegular(root, fixture.provenancePath)
	if err != nil {
		return err
	}
	if !matchesSHA256(provenanceData, fixture.provenanceSHA256) {
		return refusal(RefusalHash)
	}
	return validateProvenanceDocument(provenanceData)
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
	if err := rejectUnknownFields(object, fixtureDocumentFields); err != nil {
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
	category, err := requiredString(object, "category")
	if err != nil {
		return err
	}
	caseID, err := requiredString(object, "case")
	if err != nil {
		return err
	}
	inputHex, err := requiredHex(object, "input_hex")
	if err != nil || !validLowerHex(inputHex) {
		return refusal(RefusalMalformed)
	}
	status, err := requiredString(object, "status")
	if err != nil {
		return err
	}
	generated, err := requiredBool(object, "generated_at_test_time")
	if err != nil {
		return err
	}
	if fixtureID != fixture.id || category != fixture.category || caseID != fixture.id {
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

var fixtureDocumentFields = map[string]struct{}{
	"test_only": {}, "id": {}, "category": {}, "case": {}, "input_hex": {},
	"expected": {}, "expected_hex": {}, "status": {}, "generated_at_test_time": {},
}

func requiredHex(object map[string]any, field string) (string, error) {
	value, ok := object[field].(string)
	if !ok {
		return "", refusal(RefusalMalformed)
	}
	return value, nil
}

func validateProvenanceDocument(data []byte) error {
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
	return nil
}

var provenanceFields = map[string]struct{}{
	"test_only": {}, "author": {}, "generator": {}, "generator_version": {}, "source_revision": {}, "source_sha256": {}, "dependency_lock": {}, "dependency_lock_sha256": {}, "reproduction_command": {}, "independent_of_production": {}, "production_code": {},
}
