package pcv3corpus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
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
	{id: "d1-negative-anchored-ambiguity", caseName: "body-anchored-ambiguity", credentialMode: "combined", keyfileMode: "ordered", outcome: "ambiguous-volume", failureStage: "d1-body", detailStage: "none", forceState: "not-applicable", kdfCalls: 2, authenticatedBootstraps: 2, frontBootstrap: true, tailBootstrap: true},
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
	case "schedule":
		if len(data) == 0 || len(data) > maxD1ScheduleBytes {
			return refusal(RefusalMalformed)
		}
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

func (f *D1VolumeFixture) ID() string                     { return f.contract.id }
func (f *D1VolumeFixture) Case() string                   { return f.contract.caseName }
func (f *D1VolumeFixture) CredentialMode() string         { return f.contract.credentialMode }
func (f *D1VolumeFixture) KeyfileMode() string            { return f.contract.keyfileMode }
func (f *D1VolumeFixture) Outcome() string                { return f.contract.outcome }
func (f *D1VolumeFixture) FailureStage() string           { return f.contract.failureStage }
func (f *D1VolumeFixture) DetailStage() string            { return f.contract.detailStage }
func (f *D1VolumeFixture) ForceState() string             { return f.contract.forceState }
func (f *D1VolumeFixture) KDFCalls() int                  { return f.contract.kdfCalls }
func (f *D1VolumeFixture) AuthenticatedBootstraps() int   { return f.contract.authenticatedBootstraps }
func (f *D1VolumeFixture) Completion() bool               { return f.contract.completion }
func (f *D1VolumeFixture) Credentials() []byte            { return f.credentials }
func (f *D1VolumeFixture) Schedule() []byte               { return f.schedule }
func (f *D1VolumeFixture) FrontBootstrap() []byte         { return f.frontBootstrap }
func (f *D1VolumeFixture) TailBootstrap() []byte          { return f.tailBootstrap }
func (f *D1VolumeFixture) Body() []byte                   { return f.body }
func (f *D1VolumeFixture) Volume() []byte                 { return f.volume }
func (f *D1VolumeFixture) InnerVolume() []byte            { return f.innerVolume }
func (f *D1VolumeFixture) Plaintext() []byte              { return f.plaintext }
func (f *D1VolumeFixture) String() string                 { return "pcv3 D1 volume fixture: redacted" }
func (f *D1VolumeFixture) GoString() string               { return f.String() }
func (f *D1VolumeFixture) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, f.String()) }
func (p *D1MutationPlan) ID() string                      { return d1MutationPlanID }
func (p *D1MutationPlan) Document() []byte                { return p.document }
func (p *D1MutationPlan) String() string                  { return "pcv3 D1 mutation plan: redacted" }
func (p *D1MutationPlan) GoString() string                { return p.String() }
func (p *D1MutationPlan) Format(state fmt.State, _ rune)  { _, _ = io.WriteString(state, p.String()) }
