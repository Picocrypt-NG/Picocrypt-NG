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

func TestD1RecoveryRegistryKeepsWrapperStagesOutOfOrdinaryConstructors(t *testing.T) {
	ordinary := []struct {
		name    string
		outcome Outcome
		stage   Stage
	}{
		{name: "D1 bootstrap", outcome: OutcomeAmbiguousVolume, stage: StageD1Bootstrap},
		{name: "D1 body", outcome: OutcomeAuthenticationFailed, stage: StageD1Body},
		{name: "inner volume", outcome: OutcomeAuthenticationFailed, stage: StageInnerVolume},
	}
	for _, test := range ordinary {
		t.Run("ordinary result rejects "+test.name, func(t *testing.T) {
			result, err := newRecoveryResult(
				test.outcome,
				ForceProvenanceNone,
				test.stage,
				0,
				nil,
				0,
			)
			if !errors.Is(err, errInvalidRecoveryResult) || result != nil {
				if result != nil {
					result.Close()
				}
				t.Fatalf("ordinary result accepted D1 wrapper %v/%v: result=%v error=%v", test.outcome, test.stage, result, err)
			}
		})
	}

	for _, stage := range []Stage{StageD1Bootstrap, StageD1Body, StageInnerVolume} {
		t.Run("invalid-structure rejects "+stage.String(), func(t *testing.T) {
			if err := NewInvalidStructureError(stage); !errors.Is(err, ErrInvalidFailureMapping) {
				t.Fatalf("NewInvalidStructureError(%v) = %v; want invalid mapping", stage, err)
			}
		})
	}
}

func TestD1RecoveryRegistryAcceptsOnlyFrozenFullTuples(t *testing.T) {
	legal := []struct {
		name         string
		outcome      Outcome
		stage        Stage
		d1Provenance D1BootstrapProvenance
		detail       Stage
		code         Code
	}{
		{
			name: "matching success", outcome: OutcomeSuccess, stage: StageNone,
			d1Provenance: D1BootstrapProvenanceMatching, detail: StageNone, code: CodeSuccess,
		},
		{
			name: "front bootstrap degraded", outcome: OutcomeAuthenticatedDegraded, stage: StageD1Bootstrap,
			d1Provenance: D1BootstrapProvenanceFront, detail: StageNone, code: CodeAuthenticatedDegraded,
		},
		{
			name: "tail bootstrap degraded", outcome: OutcomeAuthenticatedDegraded, stage: StageD1Bootstrap,
			d1Provenance: D1BootstrapProvenanceTail, detail: StageNone, code: CodeAuthenticatedDegraded,
		},
		{
			name: "bootstrap credentials or damage", outcome: OutcomeCredentialsOrDamage, stage: StageD1Bootstrap,
			d1Provenance: D1BootstrapProvenanceNone, detail: StageNone, code: CodeCredentialsOrDamage,
		},
		{
			name: "selected body authentication failure", outcome: OutcomeAuthenticationFailed, stage: StageD1Body,
			d1Provenance: D1BootstrapProvenanceFront, detail: StageNone, code: CodeAuthenticationFailed,
		},
		{
			name: "bootstrap ambiguity", outcome: OutcomeAmbiguousVolume, stage: StageD1Bootstrap,
			d1Provenance: D1BootstrapProvenanceNone, detail: StageNone, code: CodeAmbiguousVolume,
		},
		{
			name: "body ambiguity", outcome: OutcomeAmbiguousVolume, stage: StageD1Body,
			d1Provenance: D1BootstrapProvenanceNone, detail: StageNone, code: CodeAmbiguousVolume,
		},
		{
			name: "selected inner record authentication failure", outcome: OutcomeAuthenticationFailed, stage: StageInnerVolume,
			d1Provenance: D1BootstrapProvenanceTail, detail: StageRecordAuth, code: CodeAuthenticationFailed,
		},
	}
	for _, test := range legal {
		t.Run("legal "+test.name, func(t *testing.T) {
			result, err := newD1RecoveryResult(
				test.outcome,
				ForceProvenanceNone,
				test.stage,
				test.d1Provenance,
				test.detail,
				0,
				nil,
				0,
			)
			if err != nil {
				t.Fatalf("legal D1 tuple rejected: %v", err)
			}
			defer result.Close()
			if result.Outcome() != test.outcome || result.Stage() != test.stage ||
				result.D1BootstrapProvenance() != test.d1Provenance ||
				result.DetailStage() != test.detail || result.Code() != test.code {
				t.Fatalf(
					"D1 tuple = %v/%v/%v/%v code %v; want %v/%v/%v/%v code %v",
					result.Outcome(),
					result.Stage(),
					result.D1BootstrapProvenance(),
					result.DetailStage(),
					result.Code(),
					test.outcome,
					test.stage,
					test.d1Provenance,
					test.detail,
					test.code,
				)
			}
		})
	}

	illegal := []struct {
		name         string
		outcome      Outcome
		stage        Stage
		d1Provenance D1BootstrapProvenance
		detail       Stage
	}{
		{
			name:    "credentials outcome with record-auth detail",
			outcome: OutcomeCredentialsOrDamage, stage: StageInnerVolume,
			d1Provenance: D1BootstrapProvenanceFront, detail: StageRecordAuth,
		},
		{
			name:    "authentication outcome with wrap-auth detail",
			outcome: OutcomeAuthenticationFailed, stage: StageInnerVolume,
			d1Provenance: D1BootstrapProvenanceFront, detail: StageWrapAuth,
		},
		{
			name:    "ordinary stage with D1 provenance",
			outcome: OutcomeAuthenticationFailed, stage: StageRecordAuth,
			d1Provenance: D1BootstrapProvenanceFront, detail: StageNone,
		},
		{
			name:    "selected success without provenance",
			outcome: OutcomeSuccess, stage: StageNone,
			d1Provenance: D1BootstrapProvenanceNone, detail: StageNone,
		},
		{
			name:    "ambiguity with selected provenance",
			outcome: OutcomeAmbiguousVolume, stage: StageD1Bootstrap,
			d1Provenance: D1BootstrapProvenanceFront, detail: StageNone,
		},
	}
	for _, test := range illegal {
		t.Run("illegal "+test.name, func(t *testing.T) {
			result, err := newD1RecoveryResult(
				test.outcome,
				ForceProvenanceNone,
				test.stage,
				test.d1Provenance,
				test.detail,
				0,
				nil,
				0,
			)
			if !errors.Is(err, errInvalidRecoveryResult) || result != nil {
				if result != nil {
					result.Close()
				}
				t.Fatalf("illegal D1 tuple accepted: result=%v error=%v", result, err)
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
	valueCopy := *result
	formatted = append(
		formatted,
		fmt.Sprintf("%v", valueCopy),
		fmt.Sprintf("%+v", valueCopy),
		fmt.Sprintf("%#v", valueCopy),
		fmt.Sprintf("%d", valueCopy),
	)
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

		//nolint:staticcheck // The empty serialized form is the authority-loss behavior under test.
		encoded, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("serialize private request: %w", err)
		}
		var decoded recoveryRequest
		//nolint:staticcheck // Decoding the empty form must not mint private authority.
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
