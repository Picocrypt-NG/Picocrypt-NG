package pcv3

import (
	"bytes"
	"testing"
)

type forceTestIdentity struct{ value byte }

func (identity *forceTestIdentity) sameVolumeKey(other forceCandidateIdentity) bool {
	candidate, ok := other.(*forceTestIdentity)
	return ok && identity != nil && candidate != nil && identity.value == candidate.value
}

func TestResolveForceCandidatesUsesOnlyPayloadAndFinalAnchors(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	structure := inspectNormalFixture(t, fixture)
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	request, err := newRecoveryRequest(RecoveryModeForce)
	if err != nil {
		t.Fatalf("new Force request: %v", err)
	}

	analysis := forceCandidateAnalysis{
		identity:    &forceTestIdentity{value: 1},
		candidate:   candidate,
		geometry:    geometry,
		damageStage: StageRecordAuth,
		ranges: []RecoveryRange{{
			recordIndex: 0,
			start:       0,
			end:         9,
			state:       RecoveryRangeMissing,
		}},
		final: RecoveryFinalVerified,
	}
	resolution, err := resolveForceCandidates(request, []forceCandidateAnalysis{analysis})
	if err != nil {
		t.Fatalf("resolve Force candidate: %v", err)
	}
	if resolution.selected != 0 || resolution.result.Outcome() != OutcomeForcePartial ||
		resolution.result.ForceProvenance() != ForceProvenancePartial ||
		resolution.result.Stage() != StageRecordAuth {
		t.Fatalf("resolution = selected %d, %v/%v/%v; want candidate 0 Force-partial at record-auth", resolution.selected, resolution.result.Outcome(), resolution.result.ForceProvenance(), resolution.result.Stage())
	}
}

func TestResolveForceCandidatesRejectsOrdinaryNoAnchorAndRoleMismatch(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	structure := inspectNormalFixture(t, fixture)
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	noAnchor := forceCandidateAnalysis{
		identity:    &forceTestIdentity{value: 1},
		candidate:   candidate,
		geometry:    geometry,
		damageStage: StageRecordAuth,
		ranges:      []RecoveryRange{{recordIndex: 0, start: 0, end: 9, state: RecoveryRangeMissing}},
		final:       RecoveryFinalMissing,
	}
	ordinary, _ := newRecoveryRequest(RecoveryModeForce)
	resolution, err := resolveForceCandidates(ordinary, []forceCandidateAnalysis{noAnchor})
	if err != nil {
		t.Fatalf("resolve ordinary no-anchor Force: %v", err)
	}
	if resolution.selected != -1 || resolution.result.Outcome() != OutcomeCredentialsOrDamage {
		t.Fatalf("ordinary no-anchor resolution = %d/%v; want no selection/credentials-or-damage", resolution.selected, resolution.result.Outcome())
	}

	if err := withUnverifiedRecoveryRequest(CapsuleRoleBackup, func(request recoveryRequest) error {
		resolution, resolveErr := resolveForceCandidates(request, []forceCandidateAnalysis{noAnchor})
		if resolveErr != nil {
			return resolveErr
		}
		if resolution.selected != -1 || resolution.result.Outcome() != OutcomeCredentialsOrDamage {
			t.Fatalf("role-mismatched unverified resolution = %d/%v; want no selection/credentials-or-damage", resolution.selected, resolution.result.Outcome())
		}
		return nil
	}); err != nil {
		t.Fatalf("role-mismatched unverified request: %v", err)
	}
}

func TestResolveForceCandidatesRequiresLiveRoleBoundConsentForUnverifiedBytes(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	structure := inspectNormalFixture(t, fixture)
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	analysis := forceCandidateAnalysis{
		identity:    &forceTestIdentity{value: 1},
		candidate:   candidate,
		geometry:    geometry,
		damageStage: StageRecordAuth,
		ranges:      []RecoveryRange{{recordIndex: 0, start: 0, end: 9, state: RecoveryRangeUnverified}},
		final:       RecoveryFinalUnverified,
	}

	if err := withUnverifiedRecoveryRequest(CapsuleRolePrimary, func(request recoveryRequest) error {
		resolution, resolveErr := resolveForceCandidates(request, []forceCandidateAnalysis{analysis})
		if resolveErr != nil {
			return resolveErr
		}
		if resolution.selected != 0 || resolution.role != CapsuleRolePrimary ||
			resolution.result.Outcome() != OutcomeForceUnverified ||
			resolution.result.ForceProvenance() != ForceProvenanceUnverified {
			t.Fatalf("unverified resolution = %d/%v/%v/%v; want selected primary Force-unverified", resolution.selected, resolution.role, resolution.result.Outcome(), resolution.result.ForceProvenance())
		}
		return nil
	}); err != nil {
		t.Fatalf("live unverified request: %v", err)
	}
}

func TestResolveForceCandidatesRejectsDistinctAnchoredIdentityBeforeOutput(t *testing.T) {
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	empty := inspectNormalFixture(t, fixtures["normal-standard-combined-ordered-empty"])
	one := inspectNormalFixture(t, fixtures["normal-standard-combined-ordered-one"])
	emptyCandidate, _ := empty.CandidateAt(0)
	emptyGeometry, _ := empty.GeometryAt(0)
	oneCandidate, _ := one.CandidateAt(0)
	oneGeometry, _ := one.GeometryAt(0)
	analyses := []forceCandidateAnalysis{
		{
			identity: &forceTestIdentity{value: 7}, candidate: emptyCandidate, geometry: emptyGeometry,
			final: RecoveryFinalVerified,
		},
		{
			identity: &forceTestIdentity{value: 7}, candidate: oneCandidate, geometry: oneGeometry,
			ranges: []RecoveryRange{{recordIndex: 0, start: 0, end: 1, state: RecoveryRangeVerified}},
			final:  RecoveryFinalVerified,
		},
	}
	request, _ := newRecoveryRequest(RecoveryModeForce)
	resolution, err := resolveForceCandidates(request, analyses)
	if err != nil {
		t.Fatalf("resolve distinct anchored identities: %v", err)
	}
	if resolution.selected != -1 || resolution.result.Outcome() != OutcomeAmbiguousVolume ||
		resolution.result.Stage() != StageCapsuleStructure {
		t.Fatalf("distinct identity resolution = %d/%v/%v; want terminal ambiguity/no selection", resolution.selected, resolution.result.Outcome(), resolution.result.Stage())
	}
}

func TestResolveForceCandidatesPreservesLiteralRecordRangesWithoutCoalescing(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-combined-ordered-two-mib"]
	structure := inspectNormalFixture(t, fixture)
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	analysis := forceCandidateAnalysis{
		identity: &forceTestIdentity{value: 9}, candidate: candidate, geometry: geometry,
		damageStage: StageFinalRecord,
		ranges: []RecoveryRange{
			{recordIndex: 0, start: 0, end: 1048576, state: RecoveryRangeVerified},
			{recordIndex: 1, start: 1048576, end: 2097152, state: RecoveryRangeMissing},
		},
		final: RecoveryFinalMissing,
	}
	request, _ := newRecoveryRequest(RecoveryModeForce)
	resolution, err := resolveForceCandidates(request, []forceCandidateAnalysis{analysis})
	if err != nil {
		t.Fatalf("resolve two-record partial: %v", err)
	}
	want := []RecoveryRange{
		{recordIndex: 0, start: 0, end: 1048576, state: RecoveryRangeVerified},
		{recordIndex: 1, start: 1048576, end: 2097152, state: RecoveryRangeMissing},
	}
	if got := resolution.result.Ranges(); !bytes.Equal(recoveryRangeBytes(got), recoveryRangeBytes(want)) {
		t.Fatalf("recovery ranges = %#v; want exact per-record map %#v", got, want)
	}
}

func inspectNormalFixture(t *testing.T, fixture normalFixture) Structure {
	t.Helper()
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	route, structure, err := Probe(bytes.NewReader(volume), int64(len(volume)))
	if err != nil || route != RouteNormalPCV {
		t.Fatalf("Probe(%s) = %v, %v", fixture.ID, route, err)
	}
	return structure
}

func recoveryRangeBytes(ranges []RecoveryRange) []byte {
	encoded := make([]byte, 0, len(ranges)*4)
	for _, recoveryRange := range ranges {
		encoded = append(encoded, byte(recoveryRange.RecordIndex()), byte(recoveryRange.Start()/1048576), byte(recoveryRange.End()/1048576), byte(recoveryRange.State()))
	}
	return encoded
}
