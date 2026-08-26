package pcv3corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	normalRequiredEvidence          uint64 = ((1 << len(normalFixtureContracts)) - 1) << len(phase4FixtureContracts)
	maxFixturePayloadBytes                 = 2 << 20
	maxFixtureVolumeOverhead               = 1 << 20
	maxFixtureKeyfileBytes                 = 4 << 10
	maxFixtureKeyfiles                     = 64
	maxNormalFixtureMutationOffsets        = 65
	testOnlyFixtureNotice                  = "TEST ONLY PCV3 CONFORMANCE DATA; NOT SECRET OR OPERATIONAL"
)

type normalFixtureContract struct {
	id, caseName, suite, credentialMode, keyfileMode, kdfEvidence string
	outcome, failureStage, kdfCalls                               string
	payloadLength                                                 uint64
	payloadRS, completion                                         bool
	authenticatedCapsules                                         int
}

var normalFixtureContracts = [...]normalFixtureContract{
	{id: "normal-standard-combined-ordered-empty", caseName: "empty", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", failureStage: "none", kdfCalls: "1", completion: true, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-one", caseName: "one-byte", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", failureStage: "none", kdfCalls: "1", payloadLength: 1, completion: true, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-before-mib", caseName: "one-mib-minus-one", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", failureStage: "none", kdfCalls: "1", payloadLength: (1 << 20) - 1, completion: true, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-exact-mib", caseName: "exact-one-mib", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", failureStage: "none", kdfCalls: "1", payloadLength: 1 << 20, completion: true, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-after-mib", caseName: "one-mib-plus-one", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", failureStage: "none", kdfCalls: "1", payloadLength: (1 << 20) + 1, completion: true, authenticatedCapsules: 2},
	{id: "normal-standard-combined-ordered-two-mib", caseName: "exact-two-mib", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "success", failureStage: "none", kdfCalls: "1", payloadLength: 2 << 20, completion: true, authenticatedCapsules: 2},
	{id: "normal-standard-keyfiles-only-small", caseName: "keyfiles-only-small", suite: "standard1", credentialMode: "keyfiles-only", keyfileMode: "ordered", kdfEvidence: "fast-seam", outcome: "success", failureStage: "none", kdfCalls: "1", payloadLength: 17, completion: true, authenticatedCapsules: 2},
	{id: "normal-standard-combined-unordered-rs-small", caseName: "combined-unordered-rs-small", suite: "standard1", credentialMode: "combined", keyfileMode: "unordered", kdfEvidence: "fast-seam", outcome: "success", failureStage: "none", kdfCalls: "1", payloadLength: 33, payloadRS: true, completion: true, authenticatedCapsules: 2},
	{id: "normal-paranoid-combined-unordered-rs-small", caseName: "paranoid-combined-rs-small", suite: "paranoid1", credentialMode: "combined", keyfileMode: "unordered", kdfEvidence: "production-vector", outcome: "success", failureStage: "none", kdfCalls: "1", payloadLength: 65, payloadRS: true, completion: true, authenticatedCapsules: 2},
	{id: "normal-degraded-capsule", caseName: "degraded-capsule", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authenticated-degraded", failureStage: "capsule-rs", kdfCalls: "1", payloadLength: 17, completion: true, authenticatedCapsules: 1},
	{id: "normal-degraded-metadata", caseName: "degraded-metadata", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authenticated-degraded", failureStage: "metadata", kdfCalls: "1", payloadLength: 17, completion: true, authenticatedCapsules: 2},
	{id: "normal-degraded-trailer", caseName: "degraded-trailer", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authenticated-degraded", failureStage: "tail-geometry", kdfCalls: "1", payloadLength: 17, completion: true, authenticatedCapsules: 2},
	{id: "normal-negative-descriptor", caseName: "negative-descriptor", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", failureStage: "descriptor", kdfCalls: "1", payloadLength: 17, authenticatedCapsules: 2},
	{id: "normal-negative-record", caseName: "negative-record", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", failureStage: "record-auth", kdfCalls: "1", payloadLength: 17, authenticatedCapsules: 2},
	{id: "normal-negative-final", caseName: "negative-final", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", failureStage: "final-record", kdfCalls: "1", payloadLength: 17, authenticatedCapsules: 2},
	{id: "normal-negative-suffix", caseName: "negative-suffix", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", failureStage: "tail-geometry", kdfCalls: "1", payloadLength: 17, authenticatedCapsules: 2},
	{id: "normal-negative-extra-byte", caseName: "negative-extra-byte", suite: "standard1", credentialMode: "combined", keyfileMode: "ordered", kdfEvidence: "production-vector", outcome: "authentication-failed", failureStage: "tail-geometry", kdfCalls: "1", payloadLength: 17, authenticatedCapsules: 2},
}

func findNormalFixtureContract(id string) (normalFixtureContract, uint64, bool) {
	for index, contract := range normalFixtureContracts {
		if contract.id == id {
			bit := uint64(1) << (len(phase4FixtureContracts) + index)
			return contract, bit, true
		}
	}
	return normalFixtureContract{}, 0, false
}

type sourceArtifactContract struct {
	id, path, kind string
}

var sourceArtifactContracts = [...]sourceArtifactContract{
	{id: "phase4-generator-source", path: "generator/phase4-v3.go", kind: "generator-source"},
	{id: "phase4-generator-lock", path: "generator/phase4-v3.lock", kind: "dependency-lock"},
	{id: "record-generator-source", path: "generator/upstream-record/main.go", kind: "generator-source"},
	{id: "record-generator-go-mod", path: "generator/upstream-record/go.mod", kind: "dependency-lock"},
	{id: "record-generator-go-sum", path: "generator/upstream-record/go.sum", kind: "dependency-lock"},
	{id: "phase2-kdf-vectors", path: "generator/input/kdf-vectors.json", kind: "source-vector"},
	{id: "phase2-vector-input", path: "generator/input/vector-input.json", kind: "source-vector"},
}

var sourceArtifactFields = map[string]struct{}{
	"id": {}, "path": {}, "sha256": {}, "kind": {},
}

func validateSourceArtifactPreconditions(document any) error {
	artifacts, ok := document.([]any)
	if !ok {
		return refusal(RefusalMalformed)
	}
	ids := make(map[string]struct{}, len(artifacts))
	paths := make(map[string]struct{}, len(artifacts))
	var evidence uint16
	for _, raw := range artifacts {
		artifact, ok := raw.(map[string]any)
		if !ok {
			return refusal(RefusalMalformed)
		}
		if err := rejectUnknownFields(artifact, sourceArtifactFields); err != nil {
			return err
		}
		id, err := requiredString(artifact, "id")
		if err != nil {
			return err
		}
		logicalPath, err := requiredString(artifact, "path")
		if err != nil {
			return err
		}
		if _, duplicate := ids[id]; duplicate {
			return refusal(RefusalDuplicate)
		}
		ids[id] = struct{}{}
		if _, duplicate := paths[logicalPath]; duplicate {
			return refusal(RefusalDuplicate)
		}
		paths[logicalPath] = struct{}{}
		contract, index, found := sourceArtifactContractForID(id)
		if !found {
			return refusal(RefusalUnknown)
		}
		kind, err := requiredString(artifact, "kind")
		if err != nil {
			return err
		}
		hash, err := requiredString(artifact, "sha256")
		if err != nil {
			return err
		}
		if logicalPath != contract.path || kind != contract.kind || !validSHA256(hash) || !validCorpusEntryPath("source_artifact_path", logicalPath) {
			return refusal(RefusalMalformed)
		}
		evidence |= uint16(1) << index
	}
	if evidence != (uint16(1)<<len(sourceArtifactContracts))-1 {
		return refusal(RefusalMissing)
	}
	return nil
}

func sourceArtifactContractForID(id string) (sourceArtifactContract, int, bool) {
	for index, contract := range sourceArtifactContracts {
		if contract.id == id {
			return contract, index, true
		}
	}
	return sourceArtifactContract{}, 0, false
}

func decodeSourceArtifacts(document any) ([]sourceArtifactManifest, error) {
	if err := validateSourceArtifactPreconditions(document); err != nil {
		return nil, err
	}
	rawArtifacts := document.([]any)
	artifacts := make([]sourceArtifactManifest, 0, len(rawArtifacts))
	for _, raw := range rawArtifacts {
		object := raw.(map[string]any)
		id, _ := requiredString(object, "id")
		logicalPath, _ := requiredString(object, "path")
		hash, _ := requiredString(object, "sha256")
		kind, _ := requiredString(object, "kind")
		artifacts = append(artifacts, sourceArtifactManifest{id: id, path: logicalPath, sha256: hash, kind: kind})
	}
	return artifacts, nil
}

func validateSourceArtifacts(root *os.Root, artifacts []sourceArtifactManifest) error {
	for _, artifact := range artifacts {
		data, err := readRegular(root, artifact.path, sourceArtifactLimit(artifact.kind))
		if err != nil {
			return err
		}
		if !matchesSHA256(data, artifact.sha256) {
			zeroBytes(data)
			return refusal(RefusalHash)
		}
		if artifact.kind == "generator-source" {
			if err := validateGeneratorSource(data); err != nil {
				zeroBytes(data)
				return err
			}
		}
		zeroBytes(data)
	}
	return nil
}

func sourceArtifactLimit(kind string) int64 {
	switch kind {
	case "generator-source":
		return maxGeneratorFileBytes
	case "dependency-lock":
		return maxDependencyLockBytes
	case "source-vector":
		return maxSourceVectorBytes
	default:
		return 0
	}
}

var normalFixtureDocumentFields = map[string]struct{}{
	"test_only": {}, "public_test_data_notice": {}, "id": {}, "category": {}, "case": {},
	"suite": {}, "payload_rs": {}, "credential_mode": {}, "keyfile_mode": {}, "kdf_evidence": {},
	"password_utf8_hex": {}, "keyfiles_hex": {}, "credential_root_hex": {}, "volume_hex": {},
	"volume_sha256": {}, "plaintext_hex": {}, "plaintext_sha256": {}, "comment_utf8_hex": {},
	"payload_length_hex": {}, "data_record_count_hex": {}, "expected_outcome": {}, "expected_stage": {},
	"expected_kdf_calls": {}, "expected_authenticated_capsules": {}, "expected_completion": {},
	"mutation_offsets": {}, "keys": {}, "status": {}, "generated_at_test_time": {},
}

var normalKeysFields = map[string]struct{}{
	"volume_key_hex": {}, "primary_wrap_xchacha20_hex": {}, "backup_wrap_xchacha20_hex": {},
	"primary_wrap_serpent_hex": {}, "backup_wrap_serpent_hex": {}, "primary_wrap_mac_hex": {},
	"backup_wrap_mac_hex": {}, "primary_replica_mac_hex": {}, "backup_replica_mac_hex": {},
	"metadata_mac_hex": {}, "payload_xchacha20_hex": {}, "payload_serpent_hex": {}, "payload_mac_hex": {},
}

func validateNormalFixtureDocument(object map[string]any, fixture fixtureManifest, contract normalFixtureContract) error {
	notice, err := requiredString(object, "public_test_data_notice")
	if err != nil || notice != testOnlyFixtureNotice {
		return refusal(RefusalMalformed)
	}
	for field, wanted := range map[string]string{
		"suite": contract.suite, "credential_mode": contract.credentialMode, "keyfile_mode": contract.keyfileMode,
		"kdf_evidence": contract.kdfEvidence, "expected_outcome": contract.outcome, "expected_stage": contract.failureStage,
	} {
		value, err := requiredString(object, field)
		if err != nil || value != wanted {
			return refusal(RefusalMalformed)
		}
	}
	payloadRS, err := requiredBool(object, "payload_rs")
	if err != nil || payloadRS != contract.payloadRS {
		return refusal(RefusalMalformed)
	}
	completion, err := requiredBool(object, "expected_completion")
	if err != nil || completion != contract.completion {
		return refusal(RefusalMalformed)
	}
	kdfCalls, err := requiredNumberString(object, "expected_kdf_calls")
	if err != nil || kdfCalls != contract.kdfCalls || fixture.kdfCalls.String() != contract.kdfCalls {
		return refusal(RefusalMalformed)
	}
	authenticated, err := requiredNumberString(object, "expected_authenticated_capsules")
	if err != nil || authenticated != strconv.Itoa(contract.authenticatedCapsules) {
		return refusal(RefusalMalformed)
	}

	payloadLength, err := requiredU64Hex(object, "payload_length_hex")
	if err != nil || payloadLength != contract.payloadLength || payloadLength > maxFixturePayloadBytes {
		return refusal(RefusalMalformed)
	}
	recordCount, err := requiredU64Hex(object, "data_record_count_hex")
	if err != nil || recordCount != expectedFixtureRecordCount(payloadLength) {
		return refusal(RefusalMalformed)
	}

	passwordHex, err := requiredHex(object, "password_utf8_hex")
	if err != nil || !validBoundedHex(passwordHex, 1<<20) {
		return refusal(RefusalMalformed)
	}
	password, err := hex.DecodeString(passwordHex)
	if err != nil || !utf8.Valid(password) {
		return refusal(RefusalMalformed)
	}
	defer zeroBytes(password)
	keyfileHex, err := requiredHexStrings(object, "keyfiles_hex", maxFixtureKeyfiles)
	if err != nil || !validFixtureFactors(contract.credentialMode, contract.keyfileMode, password, keyfileHex) {
		return refusal(RefusalMalformed)
	}
	if err := requiredSizedHex(object, "credential_root_hex", 32); err != nil {
		return err
	}

	plaintextHex, err := requiredHex(object, "plaintext_hex")
	if err != nil || uint64(len(plaintextHex)) != payloadLength*2 || !validLowerHex(plaintextHex) {
		return refusal(RefusalMalformed)
	}
	plaintextHash, err := requiredString(object, "plaintext_sha256")
	if err != nil || !validSHA256(plaintextHash) || !matchesHexSHA256(plaintextHex, plaintextHash) {
		return refusal(RefusalHash)
	}
	volumeHex, err := requiredHex(object, "volume_hex")
	if err != nil || !validLowerHex(volumeHex) {
		return refusal(RefusalMalformed)
	}
	volumeBytes := uint64(len(volumeHex) / 2)
	minimumOverhead := uint64(2232)
	if payloadRS {
		minimumOverhead = 2304
	}
	if volumeBytes < payloadLength+minimumOverhead || volumeBytes > payloadLength+maxFixtureVolumeOverhead {
		return refusal(RefusalMalformed)
	}
	volumeHash, err := requiredString(object, "volume_sha256")
	if err != nil || !validSHA256(volumeHash) || !matchesHexSHA256(volumeHex, volumeHash) {
		return refusal(RefusalHash)
	}
	commentHex, err := requiredHex(object, "comment_utf8_hex")
	if err != nil || !validBoundedHex(commentHex, 99_999) {
		return refusal(RefusalMalformed)
	}
	comment, err := hex.DecodeString(commentHex)
	if err != nil || !utf8.Valid(comment) {
		return refusal(RefusalMalformed)
	}
	zeroBytes(comment)

	allowEndOffset := contract.id == "normal-negative-extra-byte"
	mutationOffsets, err := requiredOffsets(object, "mutation_offsets", volumeBytes, allowEndOffset)
	if err != nil || (contract.outcome == "success" && len(mutationOffsets) != 0) || (contract.outcome != "success" && len(mutationOffsets) == 0) {
		return refusal(RefusalMalformed)
	}
	if allowEndOffset && (len(mutationOffsets) != 1 || mutationOffsets[0] != volumeBytes) {
		return refusal(RefusalMalformed)
	}
	keys, ok := object["keys"].(map[string]any)
	if !ok || validateNormalKeys(keys, contract.suite) != nil {
		return refusal(RefusalMalformed)
	}
	return nil
}

func validateNormalKeys(object map[string]any, suite string) error {
	if err := rejectUnknownFields(object, normalKeysFields); err != nil {
		return err
	}
	for _, field := range []string{
		"volume_key_hex", "primary_wrap_xchacha20_hex", "backup_wrap_xchacha20_hex",
		"primary_wrap_mac_hex", "backup_wrap_mac_hex", "primary_replica_mac_hex",
		"backup_replica_mac_hex", "metadata_mac_hex", "payload_xchacha20_hex", "payload_mac_hex",
	} {
		if err := requiredSizedHex(object, field, 32); err != nil {
			return err
		}
	}
	for _, field := range []string{"primary_wrap_serpent_hex", "backup_wrap_serpent_hex", "payload_serpent_hex"} {
		value, err := requiredHex(object, field)
		if err != nil {
			return err
		}
		if suite == "standard1" {
			if value != "" {
				return refusal(RefusalMalformed)
			}
		} else if len(value) != 64 || !validLowerHex(value) {
			return refusal(RefusalMalformed)
		}
	}
	return nil
}

func validFixtureFactors(mode, keyfileMode string, password []byte, keyfiles []string) bool {
	if len(keyfiles) > maxFixtureKeyfiles {
		return false
	}
	seen := make(map[string]struct{}, len(keyfiles))
	for _, keyfile := range keyfiles {
		if !validBoundedHex(keyfile, maxFixtureKeyfileBytes) || keyfile == "" {
			return false
		}
		if _, duplicate := seen[keyfile]; duplicate {
			return false
		}
		seen[keyfile] = struct{}{}
	}
	switch mode {
	case "keyfiles-only":
		return len(password) == 0 && (keyfileMode == "ordered" || keyfileMode == "unordered") && len(keyfiles) > 0
	case "combined":
		return len(password) > 0 && (keyfileMode == "ordered" || keyfileMode == "unordered") && len(keyfiles) > 0
	default:
		return false
	}
}

func requiredHexStrings(object map[string]any, field string, maximum int) ([]string, error) {
	raw, ok := object[field].([]any)
	if !ok || len(raw) > maximum {
		return nil, refusal(RefusalMalformed)
	}
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		value, ok := item.(string)
		if !ok {
			return nil, refusal(RefusalMalformed)
		}
		values = append(values, value)
	}
	return values, nil
}

func requiredU64Hex(object map[string]any, field string) (uint64, error) {
	value, err := requiredString(object, field)
	if err != nil || len(value) != 16 || !validLowerHex(value) {
		return 0, refusal(RefusalMalformed)
	}
	parsed, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return 0, refusal(RefusalMalformed)
	}
	return parsed, nil
}

func requiredOffsets(object map[string]any, field string, volumeBytes uint64, allowEnd bool) ([]uint64, error) {
	raw, ok := object[field].([]any)
	if !ok || len(raw) > maxNormalFixtureMutationOffsets {
		return nil, refusal(RefusalMalformed)
	}
	offsets := make([]uint64, 0, len(raw))
	for _, item := range raw {
		number, ok := item.(json.Number)
		if !ok {
			return nil, refusal(RefusalMalformed)
		}
		offset, err := strconv.ParseUint(number.String(), 10, 64)
		if err != nil || offset > volumeBytes || offset == volumeBytes && !allowEnd {
			return nil, refusal(RefusalMalformed)
		}
		offsets = append(offsets, offset)
	}
	return offsets, nil
}

func validBoundedHex(value string, maximumBytes int) bool {
	return len(value) <= maximumBytes*2 && validLowerHex(value)
}

func matchesHexSHA256(value, expected string) bool {
	digest := sha256.New()
	written, err := io.Copy(digest, hex.NewDecoder(strings.NewReader(value)))
	if err != nil || written != int64(len(value)/2) {
		return false
	}
	return hex.EncodeToString(digest.Sum(nil)) == expected
}

func expectedFixtureRecordCount(length uint64) uint64 {
	if length == 0 {
		return 0
	}
	return (length + (1 << 20) - 1) / (1 << 20)
}

// NormalVolumeFixture is a callback-scoped, verified TEST ONLY fixture. Every
// byte slice returned by its accessors is borrowed and zeroed when the callback
// passed to WithNormalVolumeFixtures returns or unwinds.
type NormalVolumeFixture struct {
	id, caseName, suite, credentialMode, keyfileMode, kdfEvidence string
	outcome, failureStage                                         string
	payloadRS, completion                                         bool
	kdfCalls, authenticatedCapsules                               int
	volume, plaintext, comment, password, credentialRoot          []byte
	keyfiles                                                      [][]byte
	mutationOffsets                                               []uint64
	keys                                                          *NormalVolumeKeys
}

// NormalVolumeKeys contains callback-scoped TEST ONLY key material.
type NormalVolumeKeys struct {
	volumeKey                                         []byte
	primaryWrapX, backupWrapX                         []byte
	primaryWrapSerpent, backupWrapSerpent             []byte
	primaryWrapMAC, backupWrapMAC                     []byte
	primaryReplicaMAC, backupReplicaMAC               []byte
	metadataMAC, payloadX, payloadSerpent, payloadMAC []byte
}

// WithNormalVolumeFixtures validates the closed v3 corpus once and lends only
// the requested stable fixture IDs. It never exposes or retains a logical path
// or the caller-supplied root.
func WithNormalVolumeFixtures(rootPath, custodyID string, fixtureIDs []string, use func([]*NormalVolumeFixture) error) error {
	if len(fixtureIDs) == 0 {
		return refusal(RefusalMissing)
	}
	if use == nil {
		return refusal(RefusalMalformed)
	}
	selected := make(map[string]struct{}, len(fixtureIDs))
	for _, id := range fixtureIDs {
		if _, _, found := findNormalFixtureContract(id); !found {
			return refusal(RefusalUnknown)
		}
		if _, duplicate := selected[id]; duplicate {
			return refusal(RefusalDuplicate)
		}
		selected[id] = struct{}{}
	}
	corpus, documents, err := loadCorpus(rootPath, custodyID, selected)
	if err != nil {
		return err
	}
	defer zeroDocumentMap(documents)
	if !corpus.isCurrentPhase4() {
		return refusal(RefusalUnknown)
	}
	fixtures := make([]*NormalVolumeFixture, 0, len(fixtureIDs))
	defer func() {
		closeNormalFixtures(fixtures)
	}()
	for _, id := range fixtureIDs {
		document, found := documents[id]
		if !found {
			return refusal(RefusalMissing)
		}
		fixture, err := decodeNormalVolumeFixture(document)
		if err != nil {
			return err
		}
		fixtures = append(fixtures, fixture)
	}
	return use(fixtures)
}

func decodeNormalVolumeFixture(data []byte) (*NormalVolumeFixture, error) {
	document, err := decodeStrictJSON(data)
	if err != nil {
		return nil, refusalForManifestJSON(err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return nil, refusal(RefusalMalformed)
	}
	decode := func(field string) ([]byte, error) {
		value, err := requiredHex(object, field)
		if err != nil {
			return nil, err
		}
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return nil, refusal(RefusalMalformed)
		}
		return decoded, nil
	}
	fixture := &NormalVolumeFixture{}
	fixture.id, _ = requiredString(object, "id")
	fixture.caseName, _ = requiredString(object, "case")
	fixture.suite, _ = requiredString(object, "suite")
	fixture.credentialMode, _ = requiredString(object, "credential_mode")
	fixture.keyfileMode, _ = requiredString(object, "keyfile_mode")
	fixture.kdfEvidence, _ = requiredString(object, "kdf_evidence")
	fixture.outcome, _ = requiredString(object, "expected_outcome")
	fixture.failureStage, _ = requiredString(object, "expected_stage")
	fixture.payloadRS, _ = requiredBool(object, "payload_rs")
	fixture.completion, _ = requiredBool(object, "expected_completion")
	kdfCalls, _ := requiredNumberString(object, "expected_kdf_calls")
	fixture.kdfCalls, _ = strconv.Atoi(kdfCalls)
	authenticated, _ := requiredNumberString(object, "expected_authenticated_capsules")
	fixture.authenticatedCapsules, _ = strconv.Atoi(authenticated)
	fixture.volume, err = decode("volume_hex")
	if err != nil {
		return nil, err
	}
	fixture.plaintext, _ = decode("plaintext_hex")
	fixture.comment, _ = decode("comment_utf8_hex")
	fixture.password, _ = decode("password_utf8_hex")
	fixture.credentialRoot, _ = decode("credential_root_hex")
	keyfileHex, _ := requiredHexStrings(object, "keyfiles_hex", maxFixtureKeyfiles)
	for _, value := range keyfileHex {
		decoded, _ := hex.DecodeString(value)
		fixture.keyfiles = append(fixture.keyfiles, decoded)
	}
	fixture.mutationOffsets, _ = requiredOffsets(
		object,
		"mutation_offsets",
		uint64(len(fixture.volume)),
		fixture.id == "normal-negative-extra-byte",
	)
	keysObject := object["keys"].(map[string]any)
	fixture.keys, err = decodeNormalVolumeKeys(keysObject)
	if err != nil {
		fixture.close()
		return nil, err
	}
	return fixture, nil
}

func decodeNormalVolumeKeys(object map[string]any) (*NormalVolumeKeys, error) {
	decode := func(field string) ([]byte, error) {
		value, err := requiredHex(object, field)
		if err != nil {
			return nil, err
		}
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return nil, refusal(RefusalMalformed)
		}
		return decoded, nil
	}
	keys := &NormalVolumeKeys{}
	var err error
	fields := []struct {
		name string
		dst  *[]byte
	}{
		{"volume_key_hex", &keys.volumeKey},
		{"primary_wrap_xchacha20_hex", &keys.primaryWrapX},
		{"backup_wrap_xchacha20_hex", &keys.backupWrapX},
		{"primary_wrap_serpent_hex", &keys.primaryWrapSerpent},
		{"backup_wrap_serpent_hex", &keys.backupWrapSerpent},
		{"primary_wrap_mac_hex", &keys.primaryWrapMAC},
		{"backup_wrap_mac_hex", &keys.backupWrapMAC},
		{"primary_replica_mac_hex", &keys.primaryReplicaMAC},
		{"backup_replica_mac_hex", &keys.backupReplicaMAC},
		{"metadata_mac_hex", &keys.metadataMAC},
		{"payload_xchacha20_hex", &keys.payloadX},
		{"payload_serpent_hex", &keys.payloadSerpent},
		{"payload_mac_hex", &keys.payloadMAC},
	}
	for _, field := range fields {
		*field.dst, err = decode(field.name)
		if err != nil {
			keys.close()
			return nil, err
		}
	}
	return keys, nil
}

func closeNormalFixtures(fixtures []*NormalVolumeFixture) {
	for _, fixture := range fixtures {
		fixture.close()
	}
}

func (f *NormalVolumeFixture) close() {
	if f == nil {
		return
	}
	for _, value := range [][]byte{f.volume, f.plaintext, f.comment, f.password, f.credentialRoot} {
		zeroBytes(value)
	}
	for _, keyfile := range f.keyfiles {
		zeroBytes(keyfile)
	}
	if f.keys != nil {
		f.keys.close()
	}
}

func (k *NormalVolumeKeys) close() {
	if k == nil {
		return
	}
	for _, value := range [][]byte{
		k.volumeKey, k.primaryWrapX, k.backupWrapX, k.primaryWrapSerpent, k.backupWrapSerpent,
		k.primaryWrapMAC, k.backupWrapMAC, k.primaryReplicaMAC, k.backupReplicaMAC,
		k.metadataMAC, k.payloadX, k.payloadSerpent, k.payloadMAC,
	} {
		zeroBytes(value)
	}
}

func zeroDocumentMap(documents map[string][]byte) {
	for id, document := range documents {
		zeroBytes(document)
		delete(documents, id)
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (f *NormalVolumeFixture) ID() string                 { return f.id }
func (f *NormalVolumeFixture) Case() string               { return f.caseName }
func (f *NormalVolumeFixture) Suite() string              { return f.suite }
func (f *NormalVolumeFixture) CredentialMode() string     { return f.credentialMode }
func (f *NormalVolumeFixture) KeyfileMode() string        { return f.keyfileMode }
func (f *NormalVolumeFixture) KDFEvidence() string        { return f.kdfEvidence }
func (f *NormalVolumeFixture) PayloadRS() bool            { return f.payloadRS }
func (f *NormalVolumeFixture) Outcome() string            { return f.outcome }
func (f *NormalVolumeFixture) FailureStage() string       { return f.failureStage }
func (f *NormalVolumeFixture) KDFCalls() int              { return f.kdfCalls }
func (f *NormalVolumeFixture) AuthenticatedCapsules() int { return f.authenticatedCapsules }
func (f *NormalVolumeFixture) Completion() bool           { return f.completion }
func (f *NormalVolumeFixture) Volume() []byte             { return f.volume }
func (f *NormalVolumeFixture) Plaintext() []byte          { return f.plaintext }
func (f *NormalVolumeFixture) Comment() []byte            { return f.comment }
func (f *NormalVolumeFixture) Password() []byte           { return f.password }
func (f *NormalVolumeFixture) CredentialRoot() []byte     { return f.credentialRoot }
func (f *NormalVolumeFixture) Keyfiles() [][]byte {
	return append([][]byte(nil), f.keyfiles...)
}
func (f *NormalVolumeFixture) MutationOffsets() []uint64 { return f.mutationOffsets }
func (f *NormalVolumeFixture) Keys() *NormalVolumeKeys   { return f.keys }
func (f *NormalVolumeFixture) String() string            { return "pcv3 normal-volume fixture: redacted" }
func (f *NormalVolumeFixture) GoString() string          { return f.String() }
func (f *NormalVolumeFixture) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, f.String())
}

func (k *NormalVolumeKeys) VolumeKey() []byte              { return k.volumeKey }
func (k *NormalVolumeKeys) PrimaryWrapXChaCha20() []byte   { return k.primaryWrapX }
func (k *NormalVolumeKeys) BackupWrapXChaCha20() []byte    { return k.backupWrapX }
func (k *NormalVolumeKeys) PrimaryWrapSerpent() []byte     { return k.primaryWrapSerpent }
func (k *NormalVolumeKeys) BackupWrapSerpent() []byte      { return k.backupWrapSerpent }
func (k *NormalVolumeKeys) PrimaryWrapMAC() []byte         { return k.primaryWrapMAC }
func (k *NormalVolumeKeys) BackupWrapMAC() []byte          { return k.backupWrapMAC }
func (k *NormalVolumeKeys) PrimaryReplicaMAC() []byte      { return k.primaryReplicaMAC }
func (k *NormalVolumeKeys) BackupReplicaMAC() []byte       { return k.backupReplicaMAC }
func (k *NormalVolumeKeys) MetadataMAC() []byte            { return k.metadataMAC }
func (k *NormalVolumeKeys) PayloadXChaCha20() []byte       { return k.payloadX }
func (k *NormalVolumeKeys) PayloadSerpent() []byte         { return k.payloadSerpent }
func (k *NormalVolumeKeys) PayloadMAC() []byte             { return k.payloadMAC }
func (k *NormalVolumeKeys) String() string                 { return "pcv3 normal-volume keys: redacted" }
func (k *NormalVolumeKeys) GoString() string               { return k.String() }
func (k *NormalVolumeKeys) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, k.String()) }
