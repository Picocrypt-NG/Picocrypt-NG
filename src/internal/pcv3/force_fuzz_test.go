package pcv3

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
)

// Z06 FuzzResolveForceRecords: real Force anchor/range/role analysis plus
// resolution policy. The production analyzeRecoveryRecords evaluator traverses
// every canonical record (observable descriptor reads) before
// resolveForceCandidates classifies anchors, ranges, and live role-bound
// consent. Unverified bytes never become output authority without consent.

var phase9ForceFixtureIDs = [...]string{
	"normal-standard-password-only-small",
	"normal-negative-record",
	"normal-negative-final",
}

// Z06 modes: ordinary Force, live role-bound unverified consent, Force over
// payload-tampered bytes, and divergent-identity ambiguity.
const (
	phase9ForceModeForce uint8 = iota
	phase9ForceModeUnverified
	phase9ForceModeTampered
	phase9ForceModeAmbiguous
)

// phase9ForceSeed is one compact Z06 selector tuple. The frozen volumes and
// keys stay outside the fuzz arguments; the manifest binds their hashes.
type phase9ForceSeed struct {
	id              string
	fixtureSelector uint32
	mode            uint8
	consentSelector uint8
	offset          uint64
	word            uint64
}

func (seed phase9ForceSeed) phase9Identity() (string, string) {
	return seed.id, phase9SeedDigest(
		phase9Uint32(seed.fixtureSelector),
		phase9Uint8(seed.mode),
		phase9Uint8(seed.consentSelector),
		phase9Uint64(seed.offset),
		phase9Uint64(seed.word),
	)
}

func phase9Z06Seeds() []phase9SeedIdentity {
	const (
		pristine       = 0
		negativeRecord = 1
		negativeFinal  = 2
	)
	return []phase9SeedIdentity{
		phase9ForceSeed{id: "Z06-S01", fixtureSelector: pristine, mode: phase9ForceModeForce},
		phase9ForceSeed{id: "Z06-S02", fixtureSelector: negativeRecord, mode: phase9ForceModeForce},
		phase9ForceSeed{id: "Z06-S03", fixtureSelector: negativeFinal, mode: phase9ForceModeForce},
		phase9ForceSeed{id: "Z06-S04", fixtureSelector: negativeRecord, mode: phase9ForceModeUnverified, consentSelector: uint8(CapsuleRolePrimary)},
		phase9ForceSeed{id: "Z06-S05", fixtureSelector: negativeRecord, mode: phase9ForceModeUnverified, consentSelector: uint8(CapsuleRoleBackup)},
		phase9ForceSeed{id: "Z06-S06", fixtureSelector: negativeFinal, mode: phase9ForceModeUnverified, consentSelector: uint8(CapsuleRolePrimary)},
		phase9ForceSeed{id: "Z06-S07", fixtureSelector: pristine, mode: phase9ForceModeAmbiguous},
		phase9ForceSeed{id: "Z06-S08", fixtureSelector: negativeRecord, mode: phase9ForceModeTampered, offset: 200, word: 0x80},
	}
}

// FuzzResolveForceRecords explores Force anchor/range/role analysis and
// resolution over admitted frozen structures. Canonical ranges, closed
// outcomes, exact role-bound consent, and no unverified output authority are
// the oracles.
func FuzzResolveForceRecords(f *testing.F) {
	prepared := make([]*phase9PreparedNormalVolume, 0, len(phase9ForceFixtureIDs))
	for _, id := range phase9ForceFixtureIDs {
		prepared = append(prepared, preparePhase9NormalVolume(f, id))
	}
	for _, seed := range phase9Z06Seeds() {
		canonical := seed.(phase9ForceSeed)
		f.Add(
			canonical.fixtureSelector,
			canonical.mode,
			canonical.consentSelector,
			canonical.offset,
			canonical.word,
		)
	}

	f.Fuzz(func(
		t *testing.T,
		fixtureSelector uint32,
		mode uint8,
		consentSelector uint8,
		offset uint64,
		word uint64,
	) {
		runPhase9ForceCase(
			t,
			prepared[uint64(fixtureSelector)%uint64(len(prepared))],
			mode,
			consentSelector,
			offset,
			word,
			"",
			nil,
		)
	})
}

func TestPhase9ForceFuzzSeedsReachAnalysis(t *testing.T) {
	manifest := loadPhase9SeedManifest(t)
	entry := requirePhase9Target(t, manifest, "Z06")
	prepared := make([]*phase9PreparedNormalVolume, 0, len(phase9ForceFixtureIDs))
	for _, id := range phase9ForceFixtureIDs {
		prepared = append(prepared, preparePhase9NormalVolume(t, id))
	}
	seeds := phase9Z06Seeds()
	requirePhase9Seeds(t, entry, seeds)

	for index := range seeds {
		canonical := seeds[index].(phase9ForceSeed)
		expect := entry.Seeds[index].Expect
		t.Run(canonical.id, func(t *testing.T) {
			runPhase9ForceCase(
				t,
				prepared[uint64(canonical.fixtureSelector)%uint64(len(prepared))],
				canonical.mode,
				canonical.consentSelector,
				canonical.offset,
				canonical.word,
				canonical.id,
				&expect,
			)
		})
	}
}

// runPhase9ForceCase executes the production Force record analysis and
// candidate resolution for one case, then checks the closed anchor/range/role
// invariants. The payload observer proves the analysis evaluated every
// canonical record instead of fabricating ranges.
func runPhase9ForceCase(
	t *testing.T,
	prepared *phase9PreparedNormalVolume,
	mode uint8,
	consentSelector uint8,
	offset uint64,
	word uint64,
	seedID string,
	expect *phase9SeedExpectation,
) {
	t.Helper()
	front, payloadLength := prepared.payloadGeometry(t)
	volume := prepared.volume
	if mode%4 == phase9ForceModeTampered {
		volume = make([]byte, len(prepared.volume))
		copy(volume, prepared.volume)
		phase9XORWordPayload(volume, front, payloadLength, offset, word)
	}
	candidate, ok := prepared.structure.CandidateAt(0)
	if !ok {
		t.Fatal("admitted structure lost its primary candidate")
	}
	geometry, ok := prepared.structure.GeometryAt(0)
	if !ok {
		t.Fatal("admitted structure lost its primary geometry")
	}
	provider := newNormalFixtureCredentialProvider(t, prepared.fixture.Keys)
	provider.access.adopted = true
	defer provider.close()

	maximumRequest, ok := encodedRecordBodyLength(recordPlaintextMax, true)
	if !ok || maximumRequest > uint64(math.MaxInt) {
		t.Fatal("derive TEST ONLY Force record request bound")
	}
	observer := &phase9PayloadObserver{
		reader:     bytes.NewReader(volume),
		base:       int64(front),
		end:        int64(front + payloadLength),
		maxRequest: int(maximumRequest),
	}

	var analysis recoveryRecordAnalysis
	var resolution forceResolution
	var resolveErr error
	run := func(request recoveryRequest) {
		var err error
		analysis, err = analyzeRecoveryRecords(
			context.Background(),
			observer,
			candidate,
			geometry,
			provider,
			request,
			candidate.Role(),
		)
		if err != nil {
			t.Fatalf("analyze Force records: %v", err)
		}
		analyses := []forceCandidateAnalysis{{
			identity:    &forceTestIdentity{value: 13},
			candidate:   candidate,
			geometry:    geometry,
			damageStage: analysis.damageStage,
			ranges:      analysis.ranges,
			final:       analysis.final,
		}}
		if mode%4 == phase9ForceModeAmbiguous {
			ambiguous := analyses[0]
			ambiguous.identity = &forceTestIdentity{value: 14}
			analyses = append(analyses, ambiguous)
		}
		resolution, resolveErr = resolveForceCandidates(request, analyses)
	}
	requestMode := RecoveryModeForce
	if mode%4 == phase9ForceModeUnverified {
		role := CapsuleRole(consentSelector % 2)
		if err := withUnverifiedRecoveryRequest(role, func(request recoveryRequest) error {
			run(request)
			return nil
		}); err != nil {
			t.Fatalf("live unverified consent: %v", err)
		}
		requestMode = RecoveryModeForceUnverified
	} else {
		request, err := newRecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("new Force request: %v", err)
		}
		run(request)
	}

	observer.assertBounded(t)
	recordCount := int64(candidate.RecordCount())
	if observer.descriptorReads != recordCount+1 {
		t.Fatalf("Force analysis descriptor reads = %d; want exactly %d (one per canonical record plus final)", observer.descriptorReads, recordCount+1)
	}
	if observer.bodyReads > recordCount+1 {
		t.Fatalf("Force analysis body reads = %d; canonical bound is %d", observer.bodyReads, recordCount+1)
	}
	if !validCanonicalRecoveryRanges(candidate.PlaintextLength(), analysis.ranges) ||
		!validRecoveryFinalState(analysis.final) {
		t.Fatalf("Force analysis ranges/final = %#v/%v; want canonical evidence", analysis.ranges, analysis.final)
	}

	var verifiedRanges, unverifiedRanges, missingRanges int64
	for _, recoveryRange := range analysis.ranges {
		switch recoveryRange.State() {
		case RecoveryRangeVerified:
			verifiedRanges++
		case RecoveryRangeUnverified:
			unverifiedRanges++
		case RecoveryRangeMissing:
			missingRanges++
		}
	}
	counters := map[string]int64{
		"body_reads":        observer.bodyReads,
		"descriptor_reads":  observer.descriptorReads,
		"missing_ranges":    missingRanges,
		"unverified_ranges": unverifiedRanges,
		"verified_ranges":   verifiedRanges,
	}
	detail := "final-missing"
	switch analysis.final {
	case RecoveryFinalVerified:
		detail = "final-verified"
	case RecoveryFinalUnverified:
		detail = "final-unverified"
	}

	if resolveErr != nil {
		if !errors.Is(resolveErr, errInvalidForceAnalysis) || resolution.result != nil || resolution.selected != -1 {
			t.Fatalf("Force resolution rejection = %v with result %v/selected %d; want closed invalid-analysis rejection", resolveErr, resolution.result != nil, resolution.selected)
		}
		if expect != nil {
			requirePhase9Expectation(t, seedID, *expect, "resolution-rejected", "none", detail, counters)
		}
		return
	}
	if resolution.result == nil {
		t.Fatal("Force resolution returned no typed result")
	}
	defer resolution.result.Close()
	result := resolution.result
	if _, ok := codeFor(result.Outcome(), result.Stage()); !ok {
		t.Fatalf("Force outcome/stage = %v/%v; not a legal closed mapping", result.Outcome(), result.Stage())
	}
	outcome := phase9ForceOutcomeName(result.Outcome())
	stage := phase9StageName(result.Stage())

	switch result.Outcome() {
	case OutcomeAuthenticatedDegraded:
		if result.ForceProvenance() != ForceProvenanceVerified {
			t.Fatalf("Force-verified outcome carried provenance %v", result.ForceProvenance())
		}
		if unverifiedRanges != 0 || missingRanges != 0 || analysis.final != RecoveryFinalVerified {
			t.Fatal("Force-verified outcome retained damaged or unverified evidence")
		}
	case OutcomeForcePartial:
		if result.ForceProvenance() != ForceProvenancePartial || verifiedRanges+int64(boolToInt64(analysis.final == RecoveryFinalVerified)) == 0 {
			t.Fatalf("Force-partial outcome = provenance %v with %d verified ranges; want partial with an anchor", result.ForceProvenance(), verifiedRanges)
		}
	case OutcomeForceUnverified:
		if result.ForceProvenance() != ForceProvenanceUnverified || verifiedRanges != 0 || unverifiedRanges == 0 {
			t.Fatalf("Force-unverified outcome = provenance %v with %d verified/%d unverified; want unverified-only", result.ForceProvenance(), verifiedRanges, unverifiedRanges)
		}
		if requestMode != RecoveryModeForceUnverified || !isSupportedCapsuleRole(resolution.role) {
			t.Fatalf("Force-unverified outcome without live role consent: mode %v, role %v", requestMode, resolution.role)
		}
	case OutcomeCredentialsOrDamage, OutcomeAmbiguousVolume:
		if result.ForceProvenance() != ForceProvenanceNone || result.Ranges() != nil || result.PlaintextLength() != 0 {
			t.Fatalf("%v outcome emitted ranges/length; want withheld evidence", result.Outcome())
		}
	default:
		t.Fatalf("Force outcome = %v; outside the closed Force set", result.Outcome())
	}
	if result.Outcome() != OutcomeCredentialsOrDamage && result.Outcome() != OutcomeAmbiguousVolume {
		if !validCanonicalRecoveryRanges(result.PlaintextLength(), result.Ranges()) {
			t.Fatalf("Force result ranges are not canonical for length %d", result.PlaintextLength())
		}
	}
	// No unverified output authority without live role-bound consent.
	if requestMode != RecoveryModeForceUnverified {
		for _, recoveryRange := range result.Ranges() {
			if recoveryRange.State() == RecoveryRangeUnverified {
				t.Fatal("Force result carried an unverified range without unverified consent")
			}
		}
		if result.FinalRecordState() == RecoveryFinalUnverified {
			t.Fatal("Force result carried an unverified final record without unverified consent")
		}
	}
	if unverifiedRanges != 0 && requestMode == RecoveryModeForceUnverified && resolution.role != candidate.Role() {
		t.Fatalf("Force unverified evidence bound to role %v; want candidate role %v", resolution.role, candidate.Role())
	}
	if expect != nil {
		requirePhase9Expectation(t, seedID, *expect, outcome, stage, detail, counters)
	}
}

func phase9ForceOutcomeName(outcome Outcome) string {
	switch outcome {
	case OutcomeAuthenticatedDegraded:
		return "authenticated-degraded"
	case OutcomeForcePartial:
		return "force-partial"
	case OutcomeForceUnverified:
		return "force-unverified"
	case OutcomeCredentialsOrDamage:
		return "credentials-or-damage"
	case OutcomeAmbiguousVolume:
		return "ambiguous-volume"
	default:
		return "unknown"
	}
}

func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
