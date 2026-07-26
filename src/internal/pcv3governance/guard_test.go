package pcv3governance

import (
	"bytes"
	"errors"
	"testing"
)

const (
	literalCandidateRevision = "0.3"
	literalCandidateSHA256   = "9b0c7cac133e1e349ed58bd2232ebff860d1e567348611d09c79d295bd81ad73"
	literalImplementation    = "95d53df58490c3dd81221457bad87488b7846a24"
)

func readBaseline(t *testing.T) []byte {
	t.Helper()
	return bytes.Clone(embeddedBaseline)
}

func candidateBaseline(t *testing.T) PromotionRecord {
	t.Helper()
	record, err := DecodePromotionRecord(readBaseline(t))
	if err != nil {
		t.Fatalf("decode governance baseline: %v", err)
	}
	return record
}

func completePromotion(t *testing.T) PromotionRecord {
	t.Helper()
	record := candidateBaseline(t)
	record.status = StatusFinal
	record.ownerApprovalRef = "owner-approval-test-only"
	for gate := range record.gates {
		record.gates[gate] = true
	}
	return record
}

func finalBaseline(t *testing.T) PromotionRecord {
	t.Helper()
	baseline := candidateBaseline(t)
	baseline.status = StatusFinal
	baseline.ownerApprovalRef = "owner-approval-test-only"
	for gate := range baseline.gates {
		baseline.gates[gate] = true
	}
	return baseline
}

func requireRefusal(t *testing.T, record PromotionRecord, want Reason, wantField string) {
	t.Helper()
	authorization, err := ValidatePromotion(record)
	if authorization != nil {
		t.Fatalf("ValidatePromotion returned an authorization for refused %s/%s record", want, wantField)
	}
	var refusal *RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("ValidatePromotion error = %v, want typed refusal %s/%s", err, want, wantField)
	}
	if refusal.Reason != want || refusal.Field != wantField {
		t.Fatalf("ValidatePromotion refusal = %s/%s, want %s/%s", refusal.Reason, refusal.Field, want, wantField)
	}
}

func replaceOnce(t *testing.T, input, old, replacement []byte) []byte {
	t.Helper()
	result := bytes.Replace(input, old, replacement, 1)
	if bytes.Equal(result, input) {
		t.Fatalf("literal governance fixture does not contain %q", old)
	}
	return result
}

func requireDecodeRefusal(t *testing.T, input []byte, want Reason, wantField string) {
	t.Helper()
	_, err := DecodePromotionRecord(input)
	var refusal *RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("DecodePromotionRecord error = %v, want typed refusal %s/%s", err, want, wantField)
	}
	if refusal.Reason != want || refusal.Field != wantField {
		t.Fatalf("DecodePromotionRecord refusal = %s/%s, want %s/%s", refusal.Reason, refusal.Field, want, wantField)
	}
}

func TestBaselinePinsCandidateIdentityAndEvidence(t *testing.T) {
	record := candidateBaseline(t)
	if record.schema != baselineSchema || record.status != StatusReviewCandidate {
		t.Fatalf("baseline identity = %q/%q, want %q/%q", record.schema, record.status, baselineSchema, StatusReviewCandidate)
	}
	if record.specRevision != literalCandidateRevision || record.specSHA256 != literalCandidateSHA256 || record.implementationCommit != literalImplementation {
		t.Fatalf("baseline immutable identity changed: revision=%q hash=%q commit=%q", record.specRevision, record.specSHA256, record.implementationCommit)
	}
	if record.ownerApprovalRef != "" {
		t.Fatal("review-candidate baseline must not contain an owner approval reference")
	}
	wantConstraints := constraints{
		fixedKDFProfile: "no-adaptive-downgrade",
		androidEvidence: "future-representative-device-evidence-required",
	}
	if record.constraints != wantConstraints {
		t.Fatalf("baseline constraints = %#v, want %#v", record.constraints, wantConstraints)
	}
	wantToolchain := toolchain{
		goVersion:         "go1.26.5",
		xMobileVersion:    "v0.0.0-20260709172247-6129f5bee9d5",
		androidNDKVersion: "29.0.14206865",
		jdk:               "temurin-21",
		gradleVersion:     "9.6.1",
		aarIdentity:       "picocrypt-mobile.aar;android/arm64,android/amd64;api=24",
	}
	if record.toolchain != wantToolchain {
		t.Fatalf("baseline toolchain = %#v, want %#v", record.toolchain, wantToolchain)
	}
	for gate, satisfied := range record.gates {
		if satisfied {
			t.Fatalf("review-candidate baseline marks %s satisfied", gate)
		}
	}
	if len(record.gates) != len(requiredGates) {
		t.Fatalf("baseline gate count = %d, want %d", len(record.gates), len(requiredGates))
	}
}

func TestReviewCandidateRemainsWriterDisabled(t *testing.T) {
	if got := WriterStatus(); got != WriterDisabled {
		t.Fatalf("WriterStatus() = %v, want WriterDisabled", got)
	}
	requireRefusal(t, candidateBaseline(t), ReasonStatusNotFinal, "")
}

func TestCompleteRecordCannotPromoteReviewCandidateBaseline(t *testing.T) {
	requireRefusal(t, completePromotion(t), ReasonBaselineNotFinal, "")
}

func TestValidatePromotionRefusesEachMaterialMutation(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*PromotionRecord)
		reason    Reason
		fieldName string
	}{
		{
			name: "spec revision",
			mutate: func(record *PromotionRecord) {
				record.specRevision = "0.4"
			},
			reason: ReasonSpecRevisionMismatch,
		},
		{
			name: "spec digest",
			mutate: func(record *PromotionRecord) {
				record.specSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			reason: ReasonSpecHashMismatch,
		},
		{
			name: "implementation commit",
			mutate: func(record *PromotionRecord) {
				record.implementationCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			},
			reason: ReasonImplementationCommitMismatch,
		},
		{
			name: "owner approval",
			mutate: func(record *PromotionRecord) {
				record.ownerApprovalRef = ""
			},
			reason: ReasonOwnerApprovalMissing,
		},
		{
			name: "fixed kdf constraint",
			mutate: func(record *PromotionRecord) {
				record.constraints.fixedKDFProfile = "adaptive"
			},
			reason:    ReasonConstraintMismatch,
			fieldName: "d04_fixed_kdf_profile",
		},
		{
			name: "android evidence constraint",
			mutate: func(record *PromotionRecord) {
				record.constraints.androidEvidence = "claimed"
			},
			reason:    ReasonConstraintMismatch,
			fieldName: "d05_android_evidence",
		},
		{
			name: "go version",
			mutate: func(record *PromotionRecord) {
				record.toolchain.goVersion = "go1.26.6"
			},
			reason:    ReasonToolchainMismatch,
			fieldName: "go_version",
		},
		{
			name: "x mobile version",
			mutate: func(record *PromotionRecord) {
				record.toolchain.xMobileVersion = "v0.0.0-test"
			},
			reason:    ReasonToolchainMismatch,
			fieldName: "x_mobile_version",
		},
		{
			name: "android ndk version",
			mutate: func(record *PromotionRecord) {
				record.toolchain.androidNDKVersion = "0"
			},
			reason:    ReasonToolchainMismatch,
			fieldName: "android_ndk_version",
		},
		{
			name: "jdk",
			mutate: func(record *PromotionRecord) {
				record.toolchain.jdk = "temurin-22"
			},
			reason:    ReasonToolchainMismatch,
			fieldName: "jdk",
		},
		{
			name: "gradle version",
			mutate: func(record *PromotionRecord) {
				record.toolchain.gradleVersion = "9.6.2"
			},
			reason:    ReasonToolchainMismatch,
			fieldName: "gradle_version",
		},
		{
			name: "aar identity",
			mutate: func(record *PromotionRecord) {
				record.toolchain.aarIdentity = "different.aar"
			},
			reason:    ReasonToolchainMismatch,
			fieldName: "aar_identity",
		},
	}
	for _, gate := range requiredGates {
		tests = append(tests, struct {
			name      string
			mutate    func(*PromotionRecord)
			reason    Reason
			fieldName string
		}{
			name: "gate " + string(gate),
			mutate: func(record *PromotionRecord) {
				record.gates[gate] = false
			},
			reason:    ReasonGateUnsatisfied,
			fieldName: string(gate),
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := completePromotion(t)
			test.mutate(&record)
			requireRefusal(t, record, test.reason, test.fieldName)
		})
	}
}

func TestStrictDecoderRejectsNonAuthoritativeAndAmbiguousFields(t *testing.T) {
	baseline := readBaseline(t)
	for _, field := range []struct {
		json []byte
		name string
	}{
		{json: []byte(`"approved":true`), name: "approved"},
		{json: []byte(`"release_version":"v999.999.999"`), name: "release_version"},
		{json: []byte(`"ci_status":"green"`), name: "ci_status"},
	} {
		input := replaceOnce(t, baseline, []byte("\n}"), append([]byte(",\n  "), append(field.json, []byte("\n}")...)...))
		requireDecodeRefusal(t, input, ReasonUnknownField, field.name)
	}

	duplicate := replaceOnce(t, baseline, []byte(`"status": "review-candidate"`), []byte(`"status": "review-candidate", "status": "review-candidate"`))
	requireDecodeRefusal(t, duplicate, ReasonDuplicateField, "status")

	missing := replaceOnce(t, baseline, []byte("\n  \"implementation_commit\": \"95d53df58490c3dd81221457bad87488b7846a24\","), nil)
	requireDecodeRefusal(t, missing, ReasonMissingField, "implementation_commit")

	duplicateGradle := replaceOnce(t, baseline, []byte(`"gradle_version": "9.6.1"`), []byte(`"gradle_version": "9.6.1", "gradle_version": "9.6.1"`))
	requireDecodeRefusal(t, duplicateGradle, ReasonDuplicateField, "toolchain.gradle_version")

	wrongCase := replaceOnce(t, baseline, []byte(`"status": "review-candidate"`), []byte(`"Status": "review-candidate"`))
	requireDecodeRefusal(t, wrongCase, ReasonUnknownField, "Status")

	nullApproval := replaceOnce(t, baseline, []byte(`"owner_approval_ref": ""`), []byte(`"owner_approval_ref": null`))
	requireDecodeRefusal(t, nullApproval, ReasonInvalidField, "owner_approval_ref")

	nullGate := replaceOnce(t, baseline, []byte(`"final_specification": false`), []byte(`"final_specification": null`))
	requireDecodeRefusal(t, nullGate, ReasonInvalidField, "gates.final_specification")

	trailingValue := append(append([]byte(nil), baseline...), []byte(" {}")...)
	requireDecodeRefusal(t, trailingValue, ReasonInvalidJSON, "")
}

func TestFinalBaselineRequiresExactOwnerApprovalReference(t *testing.T) {
	record := completePromotion(t)
	record.ownerApprovalRef = "different-owner-approval-ref"
	_, err := validatePromotionAgainst(finalBaseline(t), record)
	var refusal *RefusalError
	if !errors.As(err, &refusal) || refusal.Reason != ReasonOwnerApprovalMismatch {
		t.Fatalf("future final baseline owner mismatch = %v, want typed owner-approval mismatch", err)
	}
}

func TestReleaseAndEnvironmentStringsCannotEnableCandidate(t *testing.T) {
	t.Setenv("PICOCRYPT_PCV3_RELEASE_VERSION", "v999.999.999")
	t.Setenv("PICOCRYPT_PCV3_CI_STATUS", "green")
	if got := WriterStatus(); got != WriterDisabled {
		t.Fatalf("WriterStatus() after arbitrary release/CI environment strings = %v, want WriterDisabled", got)
	}
}
