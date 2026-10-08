package pcv3

import "testing"

// Raw outer authority must never disappear when inner authentication succeeds
// in full or in part; the actual authenticated and missing intervals survive.
func TestRawD1SelectionCannotBePromotedByInnerForceEvidence(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "fully verified"
		outcome, provenance := OutcomeAuthenticatedDegraded, ForceProvenanceVerified
		final := RecoveryFinalVerified
		if partial {
			name, outcome, provenance, final = "partial", OutcomeForcePartial, ForceProvenancePartial, RecoveryFinalMissing
		}
		t.Run(name, func(t *testing.T) {
			ranges := testRecoveryMap([]RecoveryRange{{recordIndex: 0, start: 0, end: 7, state: RecoveryRangeVerified}})
			inner, err := newRecoveryResult(outcome, provenance, StageWrapAuth, 7, ranges, final)
			if err != nil {
				t.Fatal(err)
			}
			defer inner.Close()
			selection := d1ForceSelection{analysis: &d1ForceCandidateAnalysis{}, provenance: D1BootstrapProvenanceFront, outerProvenance: D1OuterProvenanceRawSelected}
			mapped, err := mapD1ForceInnerResult(selection, inner, recoveryRecordAnalysis{ranges: ranges, final: final})
			if err != nil {
				t.Fatal(err)
			}
			defer mapped.Close()
			if mapped.Outcome() != OutcomeForceUnverified || mapped.ForceProvenance() != ForceProvenanceUnverified ||
				mapped.D1OuterProvenance() != D1OuterProvenanceRawSelected ||
				mapped.FinalRecordState() != final || mapped.Ranges().Summary().Verified != 1 || mapped.Ranges().Summary().Unverified != 0 {
				t.Fatalf("raw selection promoted or inner evidence changed: outcome=%v force=%v final=%v ranges=%#v", mapped.Outcome(), mapped.ForceProvenance(), mapped.FinalRecordState(), mapped.Ranges().Summary())
			}
		})
	}
}
