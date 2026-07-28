package pcv3governance

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
)

const baselineSchema = "pcv3-governance-baseline-v1"

//go:embed baseline.json
var embeddedBaseline []byte

type promotionStatus string

const (
	StatusReviewCandidate promotionStatus = "review-candidate"
	StatusFinal           promotionStatus = "final"
)

type gate string

const (
	gateFinalSpecification                                gate = "final_specification"
	gateImmutableRegistry                                 gate = "immutable_registry"
	gatePinnedNormativeVectors                            gate = "pinned_normative_vectors"
	gateIndependentInteroperability                       gate = "independent_interoperability"
	gateRequiredTestsWithoutSkip                          gate = "required_tests_without_skip"
	gateSequentialProductionArgon                         gate = "sequential_production_argon"
	gateNonVacuousMutationTesting                         gate = "non_vacuous_mutation_testing"
	gateV1V2GoldenReaderCompatibility                     gate = "v1_v2_golden_reader_compatibility"
	gateForceRSD1Matrices                                 gate = "force_rs_d1_matrices"
	gateZeroingCancellationStagingRaceFuzzConfidentiality gate = "zeroing_cancellation_staging_race_fuzz_confidentiality"
	gateSharedCoreCodecOrWASMFailLoud                     gate = "shared_core_codec_or_wasm_fail_loud"
	gateTransitionalFuturePCVRouting                      gate = "transitional_future_pcv_routing"
	gateIndependentCryptographicReview                    gate = "independent_cryptographic_review"
	gateCriticalHighFindingsRechecked                     gate = "critical_high_findings_rechecked"
)

var requiredGates = [...]gate{
	gateFinalSpecification,
	gateImmutableRegistry,
	gatePinnedNormativeVectors,
	gateIndependentInteroperability,
	gateRequiredTestsWithoutSkip,
	gateSequentialProductionArgon,
	gateNonVacuousMutationTesting,
	gateV1V2GoldenReaderCompatibility,
	gateForceRSD1Matrices,
	gateZeroingCancellationStagingRaceFuzzConfidentiality,
	gateSharedCoreCodecOrWASMFailLoud,
	gateTransitionalFuturePCVRouting,
	gateIndependentCryptographicReview,
	gateCriticalHighFindingsRechecked,
}

type toolchain struct {
	goVersion         string
	xMobileVersion    string
	androidNDKVersion string
	jdk               string
	gradleVersion     string
	aarIdentity       string
}

type constraints struct {
	fixedKDFProfile string
	androidEvidence string
}

// PromotionRecord is a strictly decoded, immutable-input candidate for a
// future promotion. Its fields are deliberately opaque so untrusted callers
// must use DecodePromotionRecord rather than constructing a partial record.
type PromotionRecord struct {
	schema               string
	status               promotionStatus
	specRevision         string
	specSHA256           string
	implementationCommit string
	ownerApprovalRef     string
	constraints          constraints
	toolchain            toolchain
	gates                map[gate]bool
}

var rootFields = [...]string{
	"schema",
	"status",
	"spec_revision",
	"spec_sha256",
	"implementation_commit",
	"owner_approval_ref",
	"constraints",
	"toolchain",
	"gates",
}

var toolchainFields = [...]string{
	"go_version",
	"x_mobile_version",
	"android_ndk_version",
	"jdk",
	"gradle_version",
	"aar_identity",
}

var constraintFields = [...]string{
	"d04_fixed_kdf_profile",
	"d05_android_evidence",
}

// WriterStatus is intentionally independent of release metadata, CI state,
// and environment variables. The embedded revision 0.3 baseline is a review
// candidate and no runtime input can enable a writer from this package.
func WriterStatus() WriterState {
	return WriterDisabled
}

// DecodePromotionRecord rejects unknown, duplicate, or missing fields before
// a record can be considered for promotion. The record contains no secret or
// signing material; owner_approval_ref is an opaque, non-secret identifier.
func DecodePromotionRecord(input []byte) (PromotionRecord, error) {
	fields, err := decodeObject(input, "", rootFields[:])
	if err != nil {
		return PromotionRecord{}, err
	}

	schema, err := decodeString(fields["schema"], "schema")
	if err != nil {
		return PromotionRecord{}, err
	}
	if schema != baselineSchema {
		return PromotionRecord{}, refusal(ReasonInvalidField, "schema")
	}

	statusValue, err := decodeString(fields["status"], "status")
	if err != nil {
		return PromotionRecord{}, err
	}
	status := promotionStatus(statusValue)
	if status != StatusReviewCandidate && status != StatusFinal {
		return PromotionRecord{}, refusal(ReasonInvalidField, "status")
	}

	specRevision, err := decodeRequiredString(fields["spec_revision"], "spec_revision")
	if err != nil {
		return PromotionRecord{}, err
	}
	specSHA256, err := decodeRequiredString(fields["spec_sha256"], "spec_sha256")
	if err != nil {
		return PromotionRecord{}, err
	}
	if !isLowerHex(specSHA256, 64) {
		return PromotionRecord{}, refusal(ReasonInvalidField, "spec_sha256")
	}
	implementationCommit, err := decodeRequiredString(fields["implementation_commit"], "implementation_commit")
	if err != nil {
		return PromotionRecord{}, err
	}
	if !isLowerHex(implementationCommit, 40) {
		return PromotionRecord{}, refusal(ReasonInvalidField, "implementation_commit")
	}
	ownerApprovalRef, err := decodeString(fields["owner_approval_ref"], "owner_approval_ref")
	if err != nil {
		return PromotionRecord{}, err
	}
	if ownerApprovalRef != "" && !validOwnerApprovalRef(ownerApprovalRef) {
		return PromotionRecord{}, refusal(ReasonOwnerApprovalInvalid, "owner_approval_ref")
	}
	decodedConstraints, err := decodeConstraints(fields["constraints"])
	if err != nil {
		return PromotionRecord{}, err
	}
	decodedToolchain, err := decodeToolchain(fields["toolchain"])
	if err != nil {
		return PromotionRecord{}, err
	}
	gates, err := decodeGates(fields["gates"])
	if err != nil {
		return PromotionRecord{}, err
	}

	return PromotionRecord{
		schema:               schema,
		status:               status,
		specRevision:         specRevision,
		specSHA256:           specSHA256,
		implementationCommit: implementationCommit,
		ownerApprovalRef:     ownerApprovalRef,
		constraints:          decodedConstraints,
		toolchain:            decodedToolchain,
		gates:                gates,
	}, nil
}

// ValidatePromotion returns the only public capability constructor. It does
// not change WriterStatus and cannot itself enable a PCV3 writer: no writer
// exists in this phase. The embedded review candidate is not Final, so this
// function currently always refuses after checking every supplied record input.
func ValidatePromotion(record PromotionRecord) (*EmissionAuthorization, error) {
	baseline, err := DecodePromotionRecord(embeddedBaseline)
	if err != nil || !validPromotionBaseline(baseline) {
		return nil, refusal(ReasonBaselineInvalid, "")
	}
	return validatePromotionAgainst(baseline, record)
}

// validatePromotionAgainst is the same predicate used by ValidatePromotion.
// It stays private so tests can model a separately reviewed future Final
// baseline without making caller-supplied baselines a production API.
func validatePromotionAgainst(baseline, record PromotionRecord) (*EmissionAuthorization, error) {
	if !validPromotionBaseline(baseline) {
		return nil, refusal(ReasonBaselineInvalid, "")
	}
	if record.schema != baseline.schema {
		return nil, refusal(ReasonSchemaMismatch, "")
	}
	if record.status != StatusFinal {
		return nil, refusal(ReasonStatusNotFinal, "")
	}
	if record.specRevision != baseline.specRevision {
		return nil, refusal(ReasonSpecRevisionMismatch, "")
	}
	if record.specSHA256 != baseline.specSHA256 {
		return nil, refusal(ReasonSpecHashMismatch, "")
	}
	if record.implementationCommit != baseline.implementationCommit {
		return nil, refusal(ReasonImplementationCommitMismatch, "")
	}
	if record.ownerApprovalRef == "" {
		return nil, refusal(ReasonOwnerApprovalMissing, "")
	}
	if !validOwnerApprovalRef(record.ownerApprovalRef) {
		return nil, refusal(ReasonOwnerApprovalInvalid, "")
	}
	if baseline.status == StatusFinal && record.ownerApprovalRef != baseline.ownerApprovalRef {
		return nil, refusal(ReasonOwnerApprovalMismatch, "")
	}
	if field := constraintMismatch(record.constraints, baseline.constraints); field != "" {
		return nil, refusal(ReasonConstraintMismatch, field)
	}
	if field := toolchainMismatch(record.toolchain, baseline.toolchain); field != "" {
		return nil, refusal(ReasonToolchainMismatch, field)
	}
	for _, required := range requiredGates {
		if !record.gates[required] {
			return nil, refusal(ReasonGateUnsatisfied, string(required))
		}
	}
	if baseline.status != StatusFinal {
		return nil, refusal(ReasonBaselineNotFinal, "")
	}
	return newEmissionAuthorization(), nil
}

func validPromotionBaseline(record PromotionRecord) bool {
	switch record.status {
	case StatusReviewCandidate:
		if record.ownerApprovalRef != "" {
			return false
		}
		for _, required := range requiredGates {
			if record.gates[required] {
				return false
			}
		}
		return true
	case StatusFinal:
		if !validOwnerApprovalRef(record.ownerApprovalRef) {
			return false
		}
		for _, required := range requiredGates {
			if !record.gates[required] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func toolchainMismatch(actual, expected toolchain) string {
	switch {
	case actual.goVersion != expected.goVersion:
		return "go_version"
	case actual.xMobileVersion != expected.xMobileVersion:
		return "x_mobile_version"
	case actual.androidNDKVersion != expected.androidNDKVersion:
		return "android_ndk_version"
	case actual.jdk != expected.jdk:
		return "jdk"
	case actual.gradleVersion != expected.gradleVersion:
		return "gradle_version"
	case actual.aarIdentity != expected.aarIdentity:
		return "aar_identity"
	default:
		return ""
	}
}

func constraintMismatch(actual, expected constraints) string {
	switch {
	case actual.fixedKDFProfile != expected.fixedKDFProfile:
		return "d04_fixed_kdf_profile"
	case actual.androidEvidence != expected.androidEvidence:
		return "d05_android_evidence"
	default:
		return ""
	}
}

func decodeConstraints(input json.RawMessage) (constraints, error) {
	fields, err := decodeObject(input, "constraints", constraintFields[:])
	if err != nil {
		return constraints{}, err
	}
	fixedKDFProfile, err := decodeRequiredString(fields["d04_fixed_kdf_profile"], "constraints.d04_fixed_kdf_profile")
	if err != nil {
		return constraints{}, err
	}
	androidEvidence, err := decodeRequiredString(fields["d05_android_evidence"], "constraints.d05_android_evidence")
	if err != nil {
		return constraints{}, err
	}
	return constraints{
		fixedKDFProfile: fixedKDFProfile,
		androidEvidence: androidEvidence,
	}, nil
}

func decodeToolchain(input json.RawMessage) (toolchain, error) {
	fields, err := decodeObject(input, "toolchain", toolchainFields[:])
	if err != nil {
		return toolchain{}, err
	}
	goVersion, err := decodeRequiredString(fields["go_version"], "toolchain.go_version")
	if err != nil {
		return toolchain{}, err
	}
	xMobileVersion, err := decodeRequiredString(fields["x_mobile_version"], "toolchain.x_mobile_version")
	if err != nil {
		return toolchain{}, err
	}
	androidNDKVersion, err := decodeRequiredString(fields["android_ndk_version"], "toolchain.android_ndk_version")
	if err != nil {
		return toolchain{}, err
	}
	jdk, err := decodeRequiredString(fields["jdk"], "toolchain.jdk")
	if err != nil {
		return toolchain{}, err
	}
	gradleVersion, err := decodeRequiredString(fields["gradle_version"], "toolchain.gradle_version")
	if err != nil {
		return toolchain{}, err
	}
	aarIdentity, err := decodeRequiredString(fields["aar_identity"], "toolchain.aar_identity")
	if err != nil {
		return toolchain{}, err
	}
	return toolchain{
		goVersion:         goVersion,
		xMobileVersion:    xMobileVersion,
		androidNDKVersion: androidNDKVersion,
		jdk:               jdk,
		gradleVersion:     gradleVersion,
		aarIdentity:       aarIdentity,
	}, nil
}

func decodeGates(input json.RawMessage) (map[gate]bool, error) {
	requiredFields := make([]string, 0, len(requiredGates))
	for _, required := range requiredGates {
		requiredFields = append(requiredFields, string(required))
	}
	fields, err := decodeObject(input, "gates", requiredFields)
	if err != nil {
		return nil, err
	}
	gates := make(map[gate]bool, len(requiredGates))
	for _, required := range requiredGates {
		value, err := decodeBoolean(fields[string(required)], "gates."+string(required))
		if err != nil {
			return nil, err
		}
		gates[required] = value
	}
	return gates, nil
}

func decodeObject(input []byte, scope string, required []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, refusal(ReasonInvalidJSON, scope)
	}

	allowed := make(map[string]struct{}, len(required))
	for _, field := range required {
		allowed[field] = struct{}{}
	}
	values := make(map[string]json.RawMessage, len(required))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, refusal(ReasonInvalidJSON, scope)
		}
		field, ok := token.(string)
		if !ok {
			return nil, refusal(ReasonInvalidJSON, scope)
		}
		qualified := qualify(scope, field)
		if _, known := allowed[field]; !known {
			return nil, refusal(ReasonUnknownField, qualified)
		}
		if _, duplicate := values[field]; duplicate {
			return nil, refusal(ReasonDuplicateField, qualified)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, refusal(ReasonInvalidJSON, qualified)
		}
		values[field] = raw
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, refusal(ReasonInvalidJSON, scope)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, refusal(ReasonInvalidJSON, scope)
	}
	for _, field := range required {
		if _, present := values[field]; !present {
			return nil, refusal(ReasonMissingField, qualify(scope, field))
		}
	}
	return values, nil
}

func decodeString(input json.RawMessage, field string) (string, error) {
	if bytes.Equal(bytes.TrimSpace(input), []byte("null")) {
		return "", refusal(ReasonInvalidField, field)
	}
	var value string
	if err := json.Unmarshal(input, &value); err != nil {
		return "", refusal(ReasonInvalidField, field)
	}
	return value, nil
}

func decodeRequiredString(input json.RawMessage, field string) (string, error) {
	value, err := decodeString(input, field)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", refusal(ReasonInvalidField, field)
	}
	return value, nil
}

func decodeBoolean(input json.RawMessage, field string) (bool, error) {
	if bytes.Equal(bytes.TrimSpace(input), []byte("null")) {
		return false, refusal(ReasonInvalidField, field)
	}
	var value bool
	if err := json.Unmarshal(input, &value); err != nil {
		return false, refusal(ReasonInvalidField, field)
	}
	return value, nil
}

func qualify(scope, field string) string {
	if scope == "" {
		return field
	}
	return scope + "." + field
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for index := range len(value) {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

func validOwnerApprovalRef(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func refusal(reason Reason, field string) *RefusalError {
	return &RefusalError{Reason: reason, Field: field}
}
