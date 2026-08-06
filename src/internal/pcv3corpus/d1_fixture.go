package pcv3corpus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	d1CorpusFormat          = "pcv3-corpus-v4"
	d1SchemaRevision        = "4"
	d1SpecRevision          = "0.4"
	d1SchemaResourceURL     = "https://pcv3.invalid/cumulative-v4/manifest.schema.json"
	d1MutationPlanID        = "d1-mutation-plan-v1"
	d1PrivateFixtureNotice  = "TEST ONLY PRIVATE PCV3 D1 CONFORMANCE DATA; NOT SECRET OR OPERATIONAL"
	d1MutationGrammarNotice = "TEST ONLY SYNTHETIC GRAMMAR; NOT A D1 MUTATION CAMPAIGN"

	d1BootstrapBytes         = 224
	maxD1CredentialBytes     = 8 << 20
	maxD1ScheduleBytes       = 4 << 20
	maxD1VolumeArtifactBytes = 64 << 20
	maxD1MutationPlanBytes   = 256 << 10
	maxD1MutationCount       = 256
	maxD1MutationBytes       = 64 << 10
	maxD1ScheduleOperations  = 16
	maxD1ExpectedRanges      = 65
)

var d1ArtifactRoles = [...]string{
	"credentials",
	"schedule",
	"front-bootstrap",
	"tail-bootstrap",
	"body",
	"volume",
	"inner-volume",
	"plaintext",
}

type d1VolumeContract struct {
	id, caseName, credentialMode, keyfileMode string
	outcome, failureStage, detailStage        string
	forceState                                string
	kdfCalls, authenticatedBootstraps         int
	completion, frontBootstrap, tailBootstrap bool
}

// These stable identities describe the complete private D1 evidence matrix.
// They deliberately contain no vector bytes, credentials, keys, or paths.
var d1VolumeContracts = [...]d1VolumeContract{
	{id: "d1-paranoid-password-only-healthy", caseName: "password-only-healthy", credentialMode: "password-only", keyfileMode: "none", outcome: "success", failureStage: "none", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 2, completion: true, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-paranoid-keyfiles-only-healthy", caseName: "keyfiles-only-healthy", credentialMode: "keyfiles-only", keyfileMode: "ordered", outcome: "success", failureStage: "none", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 2, completion: true, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-paranoid-combined-ordered-healthy", caseName: "combined-ordered-healthy", credentialMode: "combined", keyfileMode: "ordered", outcome: "success", failureStage: "none", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 2, completion: true, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-paranoid-combined-unordered-healthy", caseName: "combined-unordered-healthy", credentialMode: "combined", keyfileMode: "unordered", outcome: "success", failureStage: "none", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 2, completion: true, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-degraded-front-bootstrap-only", caseName: "front-bootstrap-only", credentialMode: "combined", keyfileMode: "ordered", outcome: "authenticated-degraded", failureStage: "d1-bootstrap", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 1, completion: true, frontBootstrap: true},
	{id: "d1-degraded-tail-bootstrap-only", caseName: "tail-bootstrap-only", credentialMode: "combined", keyfileMode: "ordered", outcome: "authenticated-degraded", failureStage: "d1-bootstrap", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 1, completion: true, tailBootstrap: true},
	{id: "d1-negative-wrong-credential", caseName: "wrong-credential", credentialMode: "combined", keyfileMode: "ordered", outcome: "credentials-or-damage", failureStage: "d1-bootstrap", detailStage: "none", forceState: "unverified", kdfCalls: 2, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-record-tamper", caseName: "record-tamper", credentialMode: "combined", keyfileMode: "ordered", outcome: "authentication-failed", failureStage: "d1-body", detailStage: "none", forceState: "partial", kdfCalls: 1, authenticatedBootstraps: 2, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-record-reorder", caseName: "record-reorder", credentialMode: "combined", keyfileMode: "ordered", outcome: "authentication-failed", failureStage: "d1-body", detailStage: "none", forceState: "partial", kdfCalls: 1, authenticatedBootstraps: 2, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-body-truncation", caseName: "body-truncation", credentialMode: "combined", keyfileMode: "ordered", outcome: "authentication-failed", failureStage: "d1-body", detailStage: "none", forceState: "partial", kdfCalls: 1, authenticatedBootstraps: 2, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-final-loss", caseName: "final-loss", credentialMode: "combined", keyfileMode: "ordered", outcome: "authentication-failed", failureStage: "d1-body", detailStage: "none", forceState: "partial", kdfCalls: 1, authenticatedBootstraps: 2, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-bootstrap-splice", caseName: "bootstrap-splice", credentialMode: "combined", keyfileMode: "ordered", outcome: "ambiguous-volume", failureStage: "d1-bootstrap", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 2, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-anchored-ambiguity", caseName: "body-anchored-ambiguity", credentialMode: "combined", keyfileMode: "ordered", outcome: "ambiguous-volume", failureStage: "d1-body", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 0, frontBootstrap: true, tailBootstrap: true},
	{id: "d1-negative-inner-volume", caseName: "inner-volume-failure", credentialMode: "combined", keyfileMode: "ordered", outcome: "authentication-failed", failureStage: "inner-volume", detailStage: "record-auth", forceState: "verified", kdfCalls: 2, authenticatedBootstraps: 2, frontBootstrap: true, tailBootstrap: true},
}

func findD1VolumeContract(id string) (d1VolumeContract, bool) {
	for _, contract := range d1VolumeContracts {
		if contract.id == id {
			return contract, true
		}
	}
	return d1VolumeContract{}, false
}

func d1ArtifactID(vectorID, role string) string {
	return vectorID + "--" + role
}

func findD1ArtifactContract(id string) (d1VolumeContract, string, bool) {
	for _, contract := range d1VolumeContracts {
		for _, role := range d1ArtifactRoles {
			if id == d1ArtifactID(contract.id, role) {
				return contract, role, true
			}
		}
	}
	return d1VolumeContract{}, "", false
}

func validateD1FixtureInventory(fixtures []fixtureManifest) (bool, error) {
	seen := make(map[string]struct{}, len(d1VolumeContracts)*len(d1ArtifactRoles)+1)
	for _, fixture := range fixtures {
		if fixture.category != "d1-volume" && fixture.category != "d1-mutation-plan" {
			continue
		}
		if _, duplicate := seen[fixture.id]; duplicate {
			return false, refusal(RefusalDuplicate)
		}
		seen[fixture.id] = struct{}{}
		if fixture.category == "d1-mutation-plan" {
			if fixture.id != d1MutationPlanID {
				return false, refusal(RefusalUnknown)
			}
			continue
		}
		if _, _, found := findD1ArtifactContract(fixture.id); !found {
			return false, refusal(RefusalUnknown)
		}
	}
	if len(seen) == 0 {
		return false, nil
	}
	if _, found := seen[d1MutationPlanID]; !found {
		return false, refusal(RefusalMissing)
	}
	for _, contract := range d1VolumeContracts {
		for _, role := range d1ArtifactRoles {
			if _, found := seen[d1ArtifactID(contract.id, role)]; !found {
				return false, refusal(RefusalMissing)
			}
		}
	}
	want := len(d1VolumeContracts)*len(d1ArtifactRoles) + 1
	if len(seen) != want {
		return false, refusal(RefusalExtra)
	}
	return true, nil
}

// D1VolumeFixture lends complete TEST ONLY private D1 material. Every byte
// accessor aliases loader-owned memory and becomes zero after the callback.
type D1VolumeFixture struct {
	contract                             d1VolumeContract
	credentials, schedule                []byte
	frontBootstrap, tailBootstrap        []byte
	body, volume, innerVolume, plaintext []byte
	correct, wrong                       d1FixtureFactors
	operations                           []D1OperationExpectation
}

type d1FixtureFactors struct {
	password []byte
	keyfiles [][]byte
}

// D1ExpectedRange is one independently supplied expected recovery interval.
// It contains public indices and states only, never recovered bytes.
type D1ExpectedRange struct {
	recordIndex uint64
	start       uint64
	end         uint64
	state       string
}

// D1OperationExpectation is one independently supplied production operation.
// All fields are fixed public classifications; credentials remain on the
// callback-scoped D1VolumeFixture.
type D1OperationExpectation struct {
	name, mode, factors, keyfileOrder, unverifiedRole           string
	expectedOutcome, expectedStage, expectedDetailStage         string
	expectedCode, expectedD1Provenance, expectedForceProvenance string
	expectedOutput, expectedFinalState                          string
	expectedKDFCalls                                            int
	expectedCompletion                                          bool
	expectedPlaintextLength                                     uint64
	expectedRanges                                              []D1ExpectedRange
}

// WithD1VolumeFixtures validates the complete v4 corpus once and lends only
// the requested logical vectors. The caller must not use returned aliases
// after use returns or unwinds.
func WithD1VolumeFixtures(rootPath, custodyID string, fixtureIDs []string, use func([]*D1VolumeFixture) error) error {
	if len(fixtureIDs) == 0 {
		return refusal(RefusalMissing)
	}
	if use == nil {
		return refusal(RefusalMalformed)
	}
	contracts := make([]d1VolumeContract, 0, len(fixtureIDs))
	selected := make(map[string]struct{}, len(fixtureIDs)*len(d1ArtifactRoles))
	logicalIDs := make(map[string]struct{}, len(fixtureIDs))
	for _, id := range fixtureIDs {
		contract, found := findD1VolumeContract(id)
		if !found {
			return refusal(RefusalUnknown)
		}
		if _, duplicate := logicalIDs[id]; duplicate {
			return refusal(RefusalDuplicate)
		}
		logicalIDs[id] = struct{}{}
		contracts = append(contracts, contract)
		for _, role := range d1ArtifactRoles {
			selected[d1ArtifactID(id, role)] = struct{}{}
		}
	}

	corpus, documents, err := loadCorpus(rootPath, custodyID, selected)
	if err != nil {
		return err
	}
	defer zeroDocumentMap(documents)
	if !corpus.isCurrentD1() {
		return refusal(RefusalUnknown)
	}

	fixtures := make([]*D1VolumeFixture, 0, len(contracts))
	defer func() {
		closeD1VolumeFixtures(fixtures)
	}()
	for _, contract := range contracts {
		fixture, err := assembleD1VolumeFixture(contract, documents)
		if err != nil {
			return err
		}
		fixtures = append(fixtures, fixture)
	}
	return use(fixtures)
}

func assembleD1VolumeFixture(contract d1VolumeContract, documents map[string][]byte) (*D1VolumeFixture, error) {
	artifact := func(role string) ([]byte, error) {
		document, found := documents[d1ArtifactID(contract.id, role)]
		if !found {
			return nil, refusal(RefusalMissing)
		}
		return document, nil
	}
	fixture := &D1VolumeFixture{contract: contract}
	fields := []struct {
		role string
		dst  *[]byte
	}{
		{"credentials", &fixture.credentials},
		{"schedule", &fixture.schedule},
		{"front-bootstrap", &fixture.frontBootstrap},
		{"tail-bootstrap", &fixture.tailBootstrap},
		{"body", &fixture.body},
		{"volume", &fixture.volume},
		{"inner-volume", &fixture.innerVolume},
		{"plaintext", &fixture.plaintext},
	}
	for _, field := range fields {
		value, err := artifact(field.role)
		if err != nil {
			return nil, err
		}
		*field.dst = value
	}
	if err := validateD1VolumeGeometry(fixture); err != nil {
		fixture.close()
		return nil, err
	}
	correct, wrong, err := decodeD1Credentials(fixture.credentials, contract)
	if err != nil {
		fixture.close()
		return nil, err
	}
	fixture.correct = correct
	fixture.wrong = wrong
	fixture.operations, err = decodeD1Schedule(fixture.schedule, contract)
	if err != nil {
		fixture.close()
		return nil, err
	}
	return fixture, nil
}

func validateD1VolumeGeometry(fixture *D1VolumeFixture) error {
	if fixture == nil {
		return refusal(RefusalMalformed)
	}
	want := len(fixture.frontBootstrap) + len(fixture.body) + len(fixture.tailBootstrap)
	if len(fixture.volume) != want {
		return refusal(RefusalMalformed)
	}
	offset := 0
	for _, part := range [][]byte{fixture.frontBootstrap, fixture.body, fixture.tailBootstrap} {
		end := offset + len(part)
		if !bytes.Equal(fixture.volume[offset:end], part) {
			return refusal(RefusalMalformed)
		}
		offset = end
	}
	return nil
}

// D1MutationPlan lends the private semantic-mutation description as a
// validated raw document. Parsing/execution remains in the private evidence
// lane so this package never retains or serializes the campaign.
type D1MutationPlan struct {
	document []byte
}

func WithD1MutationPlan(rootPath, custodyID string, use func(*D1MutationPlan) error) error {
	if use == nil {
		return refusal(RefusalMalformed)
	}
	selected := map[string]struct{}{d1MutationPlanID: {}}
	corpus, documents, err := loadCorpus(rootPath, custodyID, selected)
	if err != nil {
		return err
	}
	defer zeroDocumentMap(documents)
	if !corpus.isCurrentD1() {
		return refusal(RefusalUnknown)
	}
	document, found := documents[d1MutationPlanID]
	if !found {
		return refusal(RefusalMissing)
	}
	return use(&D1MutationPlan{document: document})
}

func validateD1ArtifactDocument(data []byte, fixture fixtureManifest) error {
	contract, role, found := findD1ArtifactContract(fixture.id)
	if !found || fixture.category != "d1-volume" {
		return refusal(RefusalUnknown)
	}
	switch role {
	case "credentials":
		if len(data) == 0 || len(data) > maxD1CredentialBytes {
			return refusal(RefusalMalformed)
		}
		return validateD1CredentialsDocument(data, fixture, contract)
	case "schedule":
		if len(data) == 0 || len(data) > maxD1ScheduleBytes {
			return refusal(RefusalMalformed)
		}
		return validateD1ScheduleDocument(data, fixture, contract)
	case "front-bootstrap":
		want := 0
		if contract.frontBootstrap {
			want = d1BootstrapBytes
		}
		if len(data) != want {
			return refusal(RefusalMalformed)
		}
	case "tail-bootstrap":
		want := 0
		if contract.tailBootstrap {
			want = d1BootstrapBytes
		}
		if len(data) != want {
			return refusal(RefusalMalformed)
		}
	case "body":
		if len(data) < 64 || len(data) > maxD1VolumeArtifactBytes {
			return refusal(RefusalMalformed)
		}
	case "volume":
		if len(data) < 64 || len(data) > maxD1VolumeArtifactBytes {
			return refusal(RefusalMalformed)
		}
	case "inner-volume":
		if len(data) == 0 || len(data) > maxD1VolumeArtifactBytes {
			return refusal(RefusalMalformed)
		}
	case "plaintext":
		if len(data) > maxD1VolumeArtifactBytes {
			return refusal(RefusalMalformed)
		}
	default:
		return refusal(RefusalUnknown)
	}
	return nil
}

var d1CredentialsFields = map[string]struct{}{
	"test_only": {}, "public_test_data_notice": {}, "id": {}, "category": {},
	"credential_mode": {}, "keyfile_mode": {}, "correct": {}, "wrong": {},
	"status": {}, "generated_at_test_time": {},
}

var d1FactorFields = map[string]struct{}{
	"password_utf8_hex": {}, "keyfiles_hex": {},
}

var d1ScheduleFields = map[string]struct{}{
	"test_only": {}, "public_test_data_notice": {}, "id": {}, "category": {},
	"operations": {}, "status": {}, "generated_at_test_time": {},
}

var d1OperationFields = map[string]struct{}{
	"name": {}, "mode": {}, "factors": {}, "keyfile_order": {}, "unverified_role": {},
	"expected_outcome": {}, "expected_stage": {}, "expected_detail_stage": {},
	"expected_code": {}, "expected_d1_provenance": {}, "expected_force_provenance": {},
	"expected_kdf_calls": {}, "expected_completion": {}, "expected_output": {},
	"expected_plaintext_length_hex": {}, "expected_final_state": {}, "expected_ranges": {},
}

var d1ExpectedRangeFields = map[string]struct{}{
	"record_index_hex": {}, "start_hex": {}, "end_hex": {}, "state": {},
}

func validateD1CredentialsDocument(data []byte, fixture fixtureManifest, contract d1VolumeContract) error {
	correct, wrong, err := decodeD1CredentialsForManifest(data, fixture, contract)
	correct.close()
	wrong.close()
	return err
}

func decodeD1Credentials(data []byte, contract d1VolumeContract) (d1FixtureFactors, d1FixtureFactors, error) {
	return decodeD1CredentialsForManifest(data, fixtureManifest{id: contract.id, category: "d1-volume"}, contract)
}

func decodeD1CredentialsForManifest(
	data []byte,
	_ fixtureManifest,
	contract d1VolumeContract,
) (d1FixtureFactors, d1FixtureFactors, error) {
	document, err := decodeStrictJSON(data)
	if err != nil {
		return d1FixtureFactors{}, d1FixtureFactors{}, refusalForManifestJSON(err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return d1FixtureFactors{}, d1FixtureFactors{}, refusal(RefusalMalformed)
	}
	if err := rejectUnknownFields(object, d1CredentialsFields); err != nil {
		return d1FixtureFactors{}, d1FixtureFactors{}, err
	}
	if err := validateD1DocumentEnvelope(object, contract.id, "d1-credentials"); err != nil {
		return d1FixtureFactors{}, d1FixtureFactors{}, err
	}
	credentialMode, err := requiredString(object, "credential_mode")
	if err != nil || credentialMode != contract.credentialMode {
		return d1FixtureFactors{}, d1FixtureFactors{}, refusal(RefusalMalformed)
	}
	keyfileMode, err := requiredString(object, "keyfile_mode")
	if err != nil || keyfileMode != contract.keyfileMode {
		return d1FixtureFactors{}, d1FixtureFactors{}, refusal(RefusalMalformed)
	}
	correctObject, correctOK := object["correct"].(map[string]any)
	wrongObject, wrongOK := object["wrong"].(map[string]any)
	if !correctOK || !wrongOK {
		return d1FixtureFactors{}, d1FixtureFactors{}, refusal(RefusalMalformed)
	}
	correct, err := decodeD1Factors(correctObject, credentialMode, keyfileMode)
	if err != nil {
		return d1FixtureFactors{}, d1FixtureFactors{}, err
	}
	wrong, err := decodeD1Factors(wrongObject, credentialMode, keyfileMode)
	if err != nil {
		correct.close()
		return d1FixtureFactors{}, d1FixtureFactors{}, err
	}
	if sameD1Factors(correct, wrong) {
		correct.close()
		wrong.close()
		return d1FixtureFactors{}, d1FixtureFactors{}, refusal(RefusalMalformed)
	}
	return correct, wrong, nil
}

func decodeD1Factors(object map[string]any, credentialMode, keyfileMode string) (d1FixtureFactors, error) {
	if err := rejectUnknownFields(object, d1FactorFields); err != nil {
		return d1FixtureFactors{}, err
	}
	passwordHex, err := requiredHex(object, "password_utf8_hex")
	if err != nil || !validBoundedHex(passwordHex, 1<<20) {
		return d1FixtureFactors{}, refusal(RefusalMalformed)
	}
	password, err := hex.DecodeString(passwordHex)
	if err != nil || !utf8.Valid(password) {
		zeroBytes(password)
		return d1FixtureFactors{}, refusal(RefusalMalformed)
	}
	keyfileHex, err := requiredHexStrings(object, "keyfiles_hex", maxFixtureKeyfiles)
	if err != nil || !validD1FixtureFactors(credentialMode, keyfileMode, password, keyfileHex) {
		zeroBytes(password)
		return d1FixtureFactors{}, refusal(RefusalMalformed)
	}
	factors := d1FixtureFactors{password: password, keyfiles: make([][]byte, 0, len(keyfileHex))}
	for _, value := range keyfileHex {
		decoded, decodeErr := hex.DecodeString(value)
		if decodeErr != nil {
			factors.close()
			return d1FixtureFactors{}, refusal(RefusalMalformed)
		}
		factors.keyfiles = append(factors.keyfiles, decoded)
	}
	return factors, nil
}

func validD1FixtureFactors(mode, keyfileMode string, password []byte, keyfiles []string) bool {
	if len(keyfiles) > maxFixtureKeyfiles {
		return false
	}
	seen := make(map[string]struct{}, len(keyfiles))
	for _, keyfile := range keyfiles {
		if keyfile == "" || !validBoundedHex(keyfile, maxFixtureKeyfileBytes) {
			return false
		}
		if _, duplicate := seen[keyfile]; duplicate {
			return false
		}
		seen[keyfile] = struct{}{}
	}
	switch mode {
	case "password-only":
		return len(password) > 0 && keyfileMode == "none" && len(keyfiles) == 0
	case "keyfiles-only":
		return len(password) == 0 && (keyfileMode == "ordered" || keyfileMode == "unordered") && len(keyfiles) > 0
	case "combined":
		return len(password) > 0 && (keyfileMode == "ordered" || keyfileMode == "unordered") && len(keyfiles) > 0
	default:
		return false
	}
}

func sameD1Factors(left, right d1FixtureFactors) bool {
	if !bytes.Equal(left.password, right.password) || len(left.keyfiles) != len(right.keyfiles) {
		return false
	}
	for index := range left.keyfiles {
		if !bytes.Equal(left.keyfiles[index], right.keyfiles[index]) {
			return false
		}
	}
	return true
}

func validateD1ScheduleDocument(data []byte, fixture fixtureManifest, contract d1VolumeContract) error {
	_, err := decodeD1ScheduleForManifest(data, fixture, contract)
	return err
}

func decodeD1Schedule(data []byte, contract d1VolumeContract) ([]D1OperationExpectation, error) {
	return decodeD1ScheduleForManifest(data, fixtureManifest{id: contract.id, category: "d1-volume"}, contract)
}

func decodeD1ScheduleForManifest(
	data []byte,
	_ fixtureManifest,
	contract d1VolumeContract,
) ([]D1OperationExpectation, error) {
	document, err := decodeStrictJSON(data)
	if err != nil {
		return nil, refusalForManifestJSON(err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return nil, refusal(RefusalMalformed)
	}
	if err := rejectUnknownFields(object, d1ScheduleFields); err != nil {
		return nil, err
	}
	if err := validateD1DocumentEnvelope(object, contract.id, "d1-schedule"); err != nil {
		return nil, err
	}
	rawOperations, ok := object["operations"].([]any)
	if !ok || len(rawOperations) < 2 || len(rawOperations) > maxD1ScheduleOperations {
		return nil, refusal(RefusalMalformed)
	}
	operations := make([]D1OperationExpectation, 0, len(rawOperations))
	seen := make(map[string]struct{}, len(rawOperations))
	for _, raw := range rawOperations {
		operationObject, ok := raw.(map[string]any)
		if !ok {
			return nil, refusal(RefusalMalformed)
		}
		operation, err := decodeD1Operation(operationObject, contract)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[operation.name]; duplicate {
			return nil, refusal(RefusalDuplicate)
		}
		seen[operation.name] = struct{}{}
		operations = append(operations, operation)
	}
	for _, required := range []string{"normal-correct", "force-correct"} {
		if _, found := seen[required]; !found {
			return nil, refusal(RefusalMissing)
		}
	}
	return operations, nil
}

func decodeD1Operation(object map[string]any, contract d1VolumeContract) (D1OperationExpectation, error) {
	if err := rejectUnknownFields(object, d1OperationFields); err != nil {
		return D1OperationExpectation{}, err
	}
	operation := D1OperationExpectation{}
	var err error
	operation.name, err = requiredString(object, "name")
	if err != nil || !validD1MutationID(operation.name) {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	operation.mode, err = requiredString(object, "mode")
	if err != nil || !contains([]string{"normal", "force", "force-unverified"}, operation.mode) {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	operation.factors, err = requiredString(object, "factors")
	if err != nil || !contains([]string{"correct", "wrong"}, operation.factors) {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	operation.keyfileOrder, err = requiredString(object, "keyfile_order")
	if err != nil || !contains([]string{"manifest", "reversed"}, operation.keyfileOrder) ||
		(operation.keyfileOrder == "reversed" && contract.keyfileMode == "none") {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	operation.unverifiedRole, err = requiredString(object, "unverified_role")
	if err != nil || !validD1OperationAuthority(operation.mode, operation.unverifiedRole) {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	stringFields := []struct {
		field   string
		dst     *string
		allowed []string
	}{
		{"expected_outcome", &operation.expectedOutcome, []string{"success", "authenticated-degraded", "credentials-or-damage", "authentication-failed", "ambiguous-volume", "force-partial", "force-unverified"}},
		{"expected_stage", &operation.expectedStage, []string{"none", "d1-bootstrap", "d1-body", "inner-volume"}},
		{"expected_detail_stage", &operation.expectedDetailStage, []string{"none", "preamble", "capsule-rs", "capsule-structure", "tail-geometry", "wrap-auth", "replica-auth", "metadata", "descriptor", "record-body-rs", "record-auth", "final-record"}},
		{"expected_code", &operation.expectedCode, []string{"PCV3_CREDENTIALS_OR_DAMAGE", "PCV3_AUTHENTICATED_DEGRADED", "PCV3_AMBIGUOUS_VOLUME", "PCV3_SUCCESS", "PCV3_AUTHENTICATION_FAILED", "PCV3_FORCE_PARTIAL", "PCV3_FORCE_UNVERIFIED"}},
		{"expected_d1_provenance", &operation.expectedD1Provenance, []string{"none", "front", "tail", "matching"}},
		{"expected_force_provenance", &operation.expectedForceProvenance, []string{"none", "verified", "partial", "unverified"}},
		{"expected_output", &operation.expectedOutput, []string{"none", "plaintext", "outer-inner"}},
		{"expected_final_state", &operation.expectedFinalState, []string{"none", "verified", "unverified", "missing"}},
	}
	for _, field := range stringFields {
		*field.dst, err = requiredString(object, field.field)
		if err != nil || !contains(field.allowed, *field.dst) {
			return D1OperationExpectation{}, refusal(RefusalMalformed)
		}
	}
	kdfCalls, err := requiredNumberString(object, "expected_kdf_calls")
	if err != nil {
		return D1OperationExpectation{}, err
	}
	operation.expectedKDFCalls, err = strconv.Atoi(kdfCalls)
	if err != nil || operation.expectedKDFCalls < 0 || operation.expectedKDFCalls > 4 {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	operation.expectedCompletion, err = requiredBool(object, "expected_completion")
	if err != nil || operation.expectedCompletion != (operation.expectedOutput != "none") {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	operation.expectedPlaintextLength, err = requiredU64Hex(object, "expected_plaintext_length_hex")
	if err != nil || operation.expectedPlaintextLength > maxD1VolumeArtifactBytes {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	operation.expectedRanges, err = decodeD1ExpectedRanges(object, operation.expectedPlaintextLength)
	if err != nil {
		return D1OperationExpectation{}, err
	}
	if operation.expectedPlaintextLength == 0 &&
		(len(operation.expectedRanges) != 0 || operation.expectedFinalState != "none") {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	if operation.expectedPlaintextLength != 0 &&
		(len(operation.expectedRanges) == 0 || operation.expectedFinalState == "none") {
		return D1OperationExpectation{}, refusal(RefusalMalformed)
	}
	return operation, nil
}

func decodeD1ExpectedRanges(object map[string]any, plaintextLength uint64) ([]D1ExpectedRange, error) {
	rawRanges, ok := object["expected_ranges"].([]any)
	if !ok || len(rawRanges) > maxD1ExpectedRanges {
		return nil, refusal(RefusalMalformed)
	}
	ranges := make([]D1ExpectedRange, 0, len(rawRanges))
	nextStart := uint64(0)
	for index, raw := range rawRanges {
		rangeObject, ok := raw.(map[string]any)
		if !ok {
			return nil, refusal(RefusalMalformed)
		}
		if err := rejectUnknownFields(rangeObject, d1ExpectedRangeFields); err != nil {
			return nil, err
		}
		recoveryRange := D1ExpectedRange{}
		var err error
		recoveryRange.recordIndex, err = requiredU64Hex(rangeObject, "record_index_hex")
		if err != nil || recoveryRange.recordIndex != uint64(index) {
			return nil, refusal(RefusalMalformed)
		}
		recoveryRange.start, err = requiredU64Hex(rangeObject, "start_hex")
		if err != nil || recoveryRange.start != nextStart {
			return nil, refusal(RefusalMalformed)
		}
		recoveryRange.end, err = requiredU64Hex(rangeObject, "end_hex")
		if err != nil || recoveryRange.end <= recoveryRange.start || recoveryRange.end > plaintextLength {
			return nil, refusal(RefusalMalformed)
		}
		recoveryRange.state, err = requiredString(rangeObject, "state")
		if err != nil || !contains([]string{"verified", "unverified", "missing"}, recoveryRange.state) {
			return nil, refusal(RefusalMalformed)
		}
		nextStart = recoveryRange.end
		ranges = append(ranges, recoveryRange)
	}
	if len(ranges) != 0 && nextStart != plaintextLength {
		return nil, refusal(RefusalMalformed)
	}
	return ranges, nil
}

func validateD1DocumentEnvelope(object map[string]any, id, category string) error {
	testOnly, err := requiredBool(object, "test_only")
	if err != nil || !testOnly {
		return refusal(RefusalMalformed)
	}
	notice, err := requiredString(object, "public_test_data_notice")
	if err != nil || (notice != d1PrivateFixtureNotice && notice != d1MutationGrammarNotice) {
		return refusal(RefusalMalformed)
	}
	documentID, err := requiredString(object, "id")
	if err != nil || documentID != id {
		return refusal(RefusalMalformed)
	}
	documentCategory, err := requiredString(object, "category")
	if err != nil || documentCategory != category {
		return refusal(RefusalMalformed)
	}
	status, err := requiredString(object, "status")
	if err != nil || status != "required" {
		return refusal(RefusalMalformed)
	}
	generated, err := requiredBool(object, "generated_at_test_time")
	if err != nil || generated {
		return refusal(RefusalMalformed)
	}
	return nil
}

func validD1OperationAuthority(mode, role string) bool {
	if mode == "force-unverified" {
		return role == "front" || role == "tail"
	}
	return role == "none"
}

func closeD1VolumeFixtures(fixtures []*D1VolumeFixture) {
	for _, fixture := range fixtures {
		fixture.close()
	}
}

func (f *D1VolumeFixture) close() {
	if f == nil {
		return
	}
	f.correct.close()
	f.wrong.close()
	for index := range f.operations {
		for rangeIndex := range f.operations[index].expectedRanges {
			f.operations[index].expectedRanges[rangeIndex] = D1ExpectedRange{}
		}
		f.operations[index] = D1OperationExpectation{}
	}
	f.operations = nil
}

func (f *d1FixtureFactors) close() {
	if f == nil {
		return
	}
	zeroBytes(f.password)
	for _, keyfile := range f.keyfiles {
		zeroBytes(keyfile)
	}
	f.password = nil
	f.keyfiles = nil
}

var d1MutationPlanFields = map[string]struct{}{
	"test_only": {}, "public_test_data_notice": {}, "id": {}, "category": {},
	"mutations": {}, "status": {}, "generated_at_test_time": {},
}

var d1MutationFields = map[string]struct{}{
	"id": {}, "source_path": {}, "source_sha256": {}, "before_hex": {},
	"after_hex": {}, "package": {}, "test_name": {}, "timeout_seconds": {},
}

func validateD1MutationPlanDocument(data []byte, fixture fixtureManifest) error {
	document, err := decodeStrictJSON(data)
	if err != nil {
		return refusalForManifestJSON(err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return refusal(RefusalMalformed)
	}
	if err := rejectUnknownFields(object, d1MutationPlanFields); err != nil {
		return err
	}
	testOnly, testOnlyOK := object["test_only"].(bool)
	notice, noticeOK := object["public_test_data_notice"].(string)
	id, idOK := object["id"].(string)
	category, categoryOK := object["category"].(string)
	status, statusOK := object["status"].(string)
	generated, generatedOK := object["generated_at_test_time"].(bool)
	mutations, mutationsOK := object["mutations"].([]any)
	validNotice := notice == d1PrivateFixtureNotice || notice == d1MutationGrammarNotice
	if !testOnlyOK || !testOnly || !noticeOK || !validNotice || !idOK || id != fixture.id || id != d1MutationPlanID ||
		!categoryOK || category != fixture.category || category != "d1-mutation-plan" || !statusOK || status != "required" ||
		!generatedOK || generated || !mutationsOK || len(mutations) == 0 || len(mutations) > maxD1MutationCount {
		return refusal(RefusalMalformed)
	}
	seen := make(map[string]struct{}, len(mutations))
	for _, rawMutation := range mutations {
		mutation, ok := rawMutation.(map[string]any)
		if !ok {
			return refusal(RefusalMalformed)
		}
		if err := rejectUnknownFields(mutation, d1MutationFields); err != nil {
			return err
		}
		mutationID, mutationIDOK := mutation["id"].(string)
		sourcePath, sourcePathOK := mutation["source_path"].(string)
		sourceSHA, sourceSHAOK := mutation["source_sha256"].(string)
		packageName, packageOK := mutation["package"].(string)
		testName, testNameOK := mutation["test_name"].(string)
		before, beforeOK := mutation["before_hex"].(string)
		after, afterOK := mutation["after_hex"].(string)
		timeout, timeoutOK := mutation["timeout_seconds"].(json.Number)
		if !mutationIDOK || !validD1MutationID(mutationID) || !sourcePathOK || !validD1MutationSource(sourcePath, packageName) ||
			!sourceSHAOK || !validSHA256(sourceSHA) || !packageOK || !testNameOK || !validD1TestName(testName) ||
			!beforeOK || !afterOK || before == after || before == "" || len(before) > maxD1MutationBytes*2 ||
			len(after) > maxD1MutationBytes*2 || !validLowerHex(before) || !validLowerHex(after) || !timeoutOK {
			return refusal(RefusalMalformed)
		}
		seconds, err := timeout.Int64()
		if err != nil || seconds < 1 || seconds > 300 {
			return refusal(RefusalMalformed)
		}
		if _, duplicate := seen[mutationID]; duplicate {
			return refusal(RefusalDuplicate)
		}
		seen[mutationID] = struct{}{}
	}
	return nil
}

func validD1MutationID(value string) bool {
	if value == "" || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func validD1MutationSource(sourcePath, packageName string) bool {
	if !validLogicalPath(sourcePath) || !strings.HasSuffix(sourcePath, ".go") {
		return false
	}
	switch {
	case strings.HasPrefix(sourcePath, "internal/pcv3/"):
		return packageName == "./internal/pcv3"
	case strings.HasPrefix(sourcePath, "internal/pcv3credential/"):
		return packageName == "./internal/pcv3credential"
	default:
		return false
	}
}

func validD1TestName(value string) bool {
	if !strings.HasPrefix(value, "TestD1") || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func (f *D1VolumeFixture) ID() string                   { return f.contract.id }
func (f *D1VolumeFixture) Case() string                 { return f.contract.caseName }
func (f *D1VolumeFixture) CredentialMode() string       { return f.contract.credentialMode }
func (f *D1VolumeFixture) KeyfileMode() string          { return f.contract.keyfileMode }
func (f *D1VolumeFixture) Outcome() string              { return f.contract.outcome }
func (f *D1VolumeFixture) FailureStage() string         { return f.contract.failureStage }
func (f *D1VolumeFixture) DetailStage() string          { return f.contract.detailStage }
func (f *D1VolumeFixture) ForceState() string           { return f.contract.forceState }
func (f *D1VolumeFixture) KDFCalls() int                { return f.contract.kdfCalls }
func (f *D1VolumeFixture) AuthenticatedBootstraps() int { return f.contract.authenticatedBootstraps }
func (f *D1VolumeFixture) Completion() bool             { return f.contract.completion }
func (f *D1VolumeFixture) Credentials() []byte          { return f.credentials }
func (f *D1VolumeFixture) Schedule() []byte             { return f.schedule }
func (f *D1VolumeFixture) FrontBootstrap() []byte       { return f.frontBootstrap }
func (f *D1VolumeFixture) TailBootstrap() []byte        { return f.tailBootstrap }
func (f *D1VolumeFixture) Body() []byte                 { return f.body }
func (f *D1VolumeFixture) Volume() []byte               { return f.volume }
func (f *D1VolumeFixture) InnerVolume() []byte          { return f.innerVolume }
func (f *D1VolumeFixture) Plaintext() []byte            { return f.plaintext }
func (f *D1VolumeFixture) Password() []byte             { return f.correct.password }
func (f *D1VolumeFixture) WrongPassword() []byte        { return f.wrong.password }
func (f *D1VolumeFixture) Keyfiles() [][]byte {
	return append([][]byte(nil), f.correct.keyfiles...)
}
func (f *D1VolumeFixture) WrongKeyfiles() [][]byte {
	return append([][]byte(nil), f.wrong.keyfiles...)
}
func (f *D1VolumeFixture) Operations() []D1OperationExpectation {
	return append([]D1OperationExpectation(nil), f.operations...)
}
func (f *D1VolumeFixture) Operation(name string) (D1OperationExpectation, bool) {
	for _, operation := range f.operations {
		if operation.name == name {
			return operation, true
		}
	}
	return D1OperationExpectation{}, false
}
func (f *D1VolumeFixture) String() string                 { return "pcv3 D1 volume fixture: redacted" }
func (f *D1VolumeFixture) GoString() string               { return f.String() }
func (f *D1VolumeFixture) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, f.String()) }
func (p *D1MutationPlan) ID() string                      { return d1MutationPlanID }
func (p *D1MutationPlan) Document() []byte                { return p.document }
func (p *D1MutationPlan) String() string                  { return "pcv3 D1 mutation plan: redacted" }
func (p *D1MutationPlan) GoString() string                { return p.String() }
func (p *D1MutationPlan) Format(state fmt.State, _ rune)  { _, _ = io.WriteString(state, p.String()) }

func (r D1ExpectedRange) RecordIndex() uint64 { return r.recordIndex }
func (r D1ExpectedRange) Start() uint64       { return r.start }
func (r D1ExpectedRange) End() uint64         { return r.end }
func (r D1ExpectedRange) State() string       { return r.state }

func (o D1OperationExpectation) Name() string                    { return o.name }
func (o D1OperationExpectation) Mode() string                    { return o.mode }
func (o D1OperationExpectation) Factors() string                 { return o.factors }
func (o D1OperationExpectation) KeyfileOrder() string            { return o.keyfileOrder }
func (o D1OperationExpectation) UnverifiedRole() string          { return o.unverifiedRole }
func (o D1OperationExpectation) ExpectedOutcome() string         { return o.expectedOutcome }
func (o D1OperationExpectation) ExpectedStage() string           { return o.expectedStage }
func (o D1OperationExpectation) ExpectedDetailStage() string     { return o.expectedDetailStage }
func (o D1OperationExpectation) ExpectedCode() string            { return o.expectedCode }
func (o D1OperationExpectation) ExpectedD1Provenance() string    { return o.expectedD1Provenance }
func (o D1OperationExpectation) ExpectedForceProvenance() string { return o.expectedForceProvenance }
func (o D1OperationExpectation) ExpectedKDFCalls() int           { return o.expectedKDFCalls }
func (o D1OperationExpectation) ExpectedCompletion() bool        { return o.expectedCompletion }
func (o D1OperationExpectation) ExpectedOutput() string          { return o.expectedOutput }
func (o D1OperationExpectation) ExpectedPlaintextLength() uint64 { return o.expectedPlaintextLength }
func (o D1OperationExpectation) ExpectedFinalState() string      { return o.expectedFinalState }
func (o D1OperationExpectation) ExpectedRanges() []D1ExpectedRange {
	return append([]D1ExpectedRange(nil), o.expectedRanges...)
}
