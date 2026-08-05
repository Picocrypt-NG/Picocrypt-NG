package pcv3

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRecoveryResultRejectsSemanticAuthorityLaundering(t *testing.T) {
	const plaintextLength = uint64(recordPlaintextMax + 7)
	verified := []RecoveryRange{
		{recordIndex: 0, start: 0, end: recordPlaintextMax, state: RecoveryRangeVerified},
		{recordIndex: 1, start: recordPlaintextMax, end: plaintextLength, state: RecoveryRangeVerified},
	}
	partial := []RecoveryRange{
		{recordIndex: 0, start: 0, end: recordPlaintextMax, state: RecoveryRangeVerified},
		{recordIndex: 1, start: recordPlaintextMax, end: plaintextLength, state: RecoveryRangeMissing},
	}
	unverified := []RecoveryRange{
		{recordIndex: 0, start: 0, end: recordPlaintextMax, state: RecoveryRangeUnverified},
		{recordIndex: 1, start: recordPlaintextMax, end: plaintextLength, state: RecoveryRangeMissing},
	}

	forceVerified, err := newRecoveryResult(
		OutcomeAuthenticatedDegraded,
		ForceProvenanceVerified,
		StageWrapAuth,
		plaintextLength,
		verified,
		RecoveryFinalVerified,
	)
	if err != nil {
		t.Fatalf("construct fully verified Force result: %v", err)
	}
	t.Cleanup(forceVerified.Close)
	if forceVerified.Outcome() != OutcomeAuthenticatedDegraded ||
		forceVerified.ForceProvenance() != ForceProvenanceVerified ||
		forceVerified.Code() != CodeAuthenticatedDegraded {
		t.Fatalf(
			"fully verified Force result = %v/%v/%v; want authenticated-degraded/verified/authenticated-degraded code",
			forceVerified.Outcome(), forceVerified.ForceProvenance(), forceVerified.Code(),
		)
	}

	forcePartial, err := newRecoveryResult(
		OutcomeForcePartial,
		ForceProvenancePartial,
		StageRecordAuth,
		plaintextLength,
		partial,
		RecoveryFinalVerified,
	)
	if err != nil {
		t.Fatalf("construct partially verified Force result: %v", err)
	}
	t.Cleanup(forcePartial.Close)
	if forcePartial.Code() != CodeForcePartial {
		t.Fatalf("partial Force adapter code = %v; want %v", forcePartial.Code(), CodeForcePartial)
	}

	forceUnverified, err := newRecoveryResult(
		OutcomeForceUnverified,
		ForceProvenanceUnverified,
		StageWrapAuth,
		plaintextLength,
		unverified,
		RecoveryFinalMissing,
	)
	if err != nil {
		t.Fatalf("construct unverified Force result: %v", err)
	}
	t.Cleanup(forceUnverified.Close)
	if forceUnverified.Code() != CodeForceUnverified || forceUnverified.Code() == forcePartial.Code() {
		t.Fatalf(
			"unverified/partial Force adapter codes = %v/%v; want distinct stable codes",
			forceUnverified.Code(), forcePartial.Code(),
		)
	}

	tests := []struct {
		name       string
		outcome    Outcome
		provenance ForceProvenance
		stage      Stage
		ranges     []RecoveryRange
		final      RecoveryFinalState
	}{
		{
			name:    "Force-verified relabelled healthy",
			outcome: OutcomeSuccess, provenance: ForceProvenanceVerified,
			stage: StageNone, ranges: verified, final: RecoveryFinalVerified,
		},
		{
			name:    "Force-verified with unverified bytes",
			outcome: OutcomeAuthenticatedDegraded, provenance: ForceProvenanceVerified,
			stage: StageWrapAuth, ranges: unverified, final: RecoveryFinalVerified,
		},
		{
			name:    "partial without a payload anchor",
			outcome: OutcomeForcePartial, provenance: ForceProvenancePartial,
			stage: StageRecordAuth, ranges: unverified, final: RecoveryFinalMissing,
		},
		{
			name:    "partial with no damaged evidence",
			outcome: OutcomeForcePartial, provenance: ForceProvenancePartial,
			stage: StageRecordAuth, ranges: verified, final: RecoveryFinalVerified,
		},
		{
			name:    "unverified carrying verified bytes",
			outcome: OutcomeForceUnverified, provenance: ForceProvenanceUnverified,
			stage: StageWrapAuth, ranges: partial, final: RecoveryFinalMissing,
		},
		{
			name:    "partial outcome with unverified provenance",
			outcome: OutcomeForcePartial, provenance: ForceProvenanceUnverified,
			stage: StageRecordAuth, ranges: unverified, final: RecoveryFinalMissing,
		},
		{
			name:    "noncanonical gap",
			outcome: OutcomeForceUnverified, provenance: ForceProvenanceUnverified,
			stage: StageWrapAuth,
			ranges: []RecoveryRange{
				{recordIndex: 0, start: 0, end: recordPlaintextMax - 1, state: RecoveryRangeUnverified},
				{recordIndex: 1, start: recordPlaintextMax, end: plaintextLength, state: RecoveryRangeMissing},
			},
			final: RecoveryFinalMissing,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := newRecoveryResult(
				test.outcome,
				test.provenance,
				test.stage,
				plaintextLength,
				test.ranges,
				test.final,
			)
			if !errors.Is(err, errInvalidRecoveryResult) {
				t.Fatalf("invalid recovery result error = %v; want closed-constructor rejection", err)
			}
			if result != nil {
				result.Close()
				t.Fatal("invalid recovery state returned a usable semantic result")
			}
		})
	}
}

func TestRecoveryResultCopiesAndClearsOwnedEvidence(t *testing.T) {
	ranges := []RecoveryRange{
		{recordIndex: 0, start: 0, end: 37, state: RecoveryRangeUnverified},
	}
	result, err := newRecoveryResult(
		OutcomeForceUnverified,
		ForceProvenanceUnverified,
		StageReplicaAuth,
		37,
		ranges,
		RecoveryFinalMissing,
	)
	if err != nil {
		t.Fatalf("construct result for ownership test: %v", err)
	}

	ranges[0] = RecoveryRange{}
	got := result.Ranges()
	if len(got) != 1 || got[0].RecordIndex() != 0 || got[0].Start() != 0 ||
		got[0].End() != 37 || got[0].State() != RecoveryRangeUnverified {
		result.Close()
		t.Fatalf("result retained caller-owned range mutation: %#v", got)
	}
	got[0] = RecoveryRange{}
	if copied := result.Ranges(); len(copied) != 1 || copied[0].End() != 37 {
		result.Close()
		t.Fatalf("Ranges returned a mutable internal alias: %#v", copied)
	}

	formatted := []string{
		result.Error(),
		result.String(),
		result.GoString(),
		fmt.Sprintf("%v", result),
		fmt.Sprintf("%+v", result),
		fmt.Sprintf("%#v", result),
		fmt.Sprintf("%d", result),
	}
	for _, output := range formatted {
		for _, disclosed := range []string{"37", "record_index", "plaintext", "credential", "candidate"} {
			if strings.Contains(output, disclosed) {
				result.Close()
				t.Fatalf("recovery formatting disclosed %q in %q", disclosed, output)
			}
		}
	}

	owned := result.ranges
	result.Close()
	if result.Outcome() != 0 || result.Stage() != 0 || result.ForceProvenance() != 0 ||
		result.FinalRecordState() != 0 || result.PlaintextLength() != 0 || result.Ranges() != nil {
		t.Fatal("closed recovery result retained live semantic evidence")
	}
	for index, evidence := range owned {
		if evidence != (RecoveryRange{}) {
			t.Fatalf("owned range %d survived Close: %#v", index, evidence)
		}
	}
}

func TestUnverifiedRecoveryConsentIsRoleBoundAndExpires(t *testing.T) {
	zero := recoveryRequest{}
	if zero.valid() || zero.authorizesUnverified(CapsuleRolePrimary) {
		t.Fatal("zero recovery request authorized unverified bytes")
	}

	ordinary, err := newRecoveryRequest(RecoveryModeForce)
	if err != nil || !ordinary.valid() {
		t.Fatalf("ordinary Force request = %v, %v; want valid non-unverified request", ordinary, err)
	}
	if ordinary.authorizesUnverified(CapsuleRolePrimary) || ordinary.authorizesUnverified(CapsuleRoleBackup) {
		t.Fatal("ordinary Force request authorized unverified bytes")
	}
	if request, err := newRecoveryRequest(RecoveryModeForceUnverified); !errors.Is(err, errInvalidRecoveryRequest) || request.valid() {
		t.Fatalf("unverified request without capability = %v, %v; want fail-closed rejection", request, err)
	}

	called := false
	if err := withUnverifiedRecoveryRequest(CapsuleRole(255), func(recoveryRequest) error {
		called = true
		return nil
	}); !errors.Is(err, errInvalidRecoveryRequest) || called {
		t.Fatalf("invalid-role consent = called %v, error %v; want rejection before callback", called, err)
	}

	var retained recoveryRequest
	if err := withUnverifiedRecoveryRequest(CapsuleRolePrimary, func(request recoveryRequest) error {
		retained = request
		if !request.valid() || request.Mode() != RecoveryModeForceUnverified {
			return errors.New("live capability did not carry the explicit unverified mode")
		}
		if !request.authorizesUnverified(CapsuleRolePrimary) || request.authorizesUnverified(CapsuleRoleBackup) {
			return errors.New("live capability was not bound only to its explicit physical role")
		}

		encoded, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("serialize private request: %w", err)
		}
		var decoded recoveryRequest
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return fmt.Errorf("deserialize private request: %w", err)
		}
		if decoded.valid() || decoded.authorizesUnverified(CapsuleRolePrimary) {
			return errors.New("serialized request minted unverified authority")
		}
		return nil
	}); err != nil {
		t.Fatalf("scoped unverified request: %v", err)
	}
	if retained.valid() || retained.authorizesUnverified(CapsuleRolePrimary) {
		t.Fatal("copied request retained authority after its operation callback")
	}

	panicValue := &struct{ label string }{label: "TEST ONLY consent panic"}
	var panicRetained recoveryRequest
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = withUnverifiedRecoveryRequest(CapsuleRoleBackup, func(request recoveryRequest) error {
			panicRetained = request
			panic(panicValue)
		})
	}()
	if recovered != panicValue {
		t.Fatalf("consent callback panic = %#v; want original %#v", recovered, panicValue)
	}
	if panicRetained.valid() || panicRetained.authorizesUnverified(CapsuleRoleBackup) {
		t.Fatal("panic-retained request kept authority after callback unwind")
	}
}
