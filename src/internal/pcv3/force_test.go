package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
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

func TestResolveForceCandidatesDoesNotTreatReplicaAuthenticationAsAnchor(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	structure := inspectNormalFixture(t, fixture)
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	analysis := forceCandidateAnalysis{
		identity:      &forceTestIdentity{value: 1},
		candidate:     candidate,
		geometry:      geometry,
		damageStage:   StageRecordAuth,
		replicaValid:  true,
		metadataValid: true,
		ranges:        []RecoveryRange{{recordIndex: 0, start: 0, end: 9, state: RecoveryRangeMissing}},
		final:         RecoveryFinalMissing,
	}
	request, _ := newRecoveryRequest(RecoveryModeForce)
	resolution, err := resolveForceCandidates(request, []forceCandidateAnalysis{analysis})
	if err != nil {
		t.Fatalf("resolve replica-authenticated no-anchor Force: %v", err)
	}
	if resolution.selected != -1 || resolution.result.Outcome() != OutcomeCredentialsOrDamage {
		t.Fatalf("replica-authenticated no-anchor resolution = %d/%v; want no selection/credentials-or-damage", resolution.selected, resolution.result.Outcome())
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

func TestResolveForceCandidatesSelectsExactlyTheLiveConsentedAnchoredRole(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-combined-ordered-two-mib"]
	structure := inspectNormalFixture(t, fixture)
	primary, ok := structure.CandidateAt(0)
	if !ok || primary.Role() != CapsuleRolePrimary {
		t.Fatal("TEST ONLY two-record fixture has no primary candidate")
	}
	backup, ok := structure.CandidateAt(1)
	if !ok || backup.Role() != CapsuleRoleBackup {
		t.Fatal("TEST ONLY two-record fixture has no backup candidate")
	}
	if primary.core != backup.core {
		t.Fatal("TEST ONLY fixture replicas carry divergent logical cores")
	}
	geometry, ok := structure.GeometryAt(0)
	if !ok {
		t.Fatal("TEST ONLY two-record fixture has no primary geometry")
	}

	// Both anchored candidates share the frozen identity and logical core and
	// carry the same partial map: record 0 verified, record 1 and the final
	// record unverified. Only the live consent role may be selected.
	analysisFor := func(candidate Candidate) forceCandidateAnalysis {
		return forceCandidateAnalysis{
			identity:  &forceTestIdentity{value: 21},
			candidate: candidate,
			geometry:  geometry,
			ranges: []RecoveryRange{
				{recordIndex: 0, start: 0, end: 1048576, state: RecoveryRangeVerified},
				{recordIndex: 1, start: 1048576, end: 2097152, state: RecoveryRangeUnverified},
			},
			final: RecoveryFinalUnverified,
		}
	}
	analyses := []forceCandidateAnalysis{analysisFor(primary), analysisFor(backup)}
	wantRanges := []RecoveryRange{
		{recordIndex: 0, start: 0, end: 1048576, state: RecoveryRangeVerified},
		{recordIndex: 1, start: 1048576, end: 2097152, state: RecoveryRangeUnverified},
	}

	tests := []struct {
		name         string
		consent      CapsuleRole
		wantSelected int
	}{
		{name: "live primary consent selects the primary anchor", consent: CapsuleRolePrimary, wantSelected: 0},
		{name: "live backup consent selects the backup anchor", consent: CapsuleRoleBackup, wantSelected: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := withUnverifiedRecoveryRequest(test.consent, func(request recoveryRequest) error {
				resolution, resolveErr := resolveForceCandidates(request, analyses)
				if resolveErr != nil {
					return resolveErr
				}
				if resolution.selected != test.wantSelected || resolution.role != test.consent {
					t.Fatalf(
						"anchored unverified selection = %d/%v; want exactly %d/%v",
						resolution.selected, resolution.role, test.wantSelected, test.consent,
					)
				}
				result := resolution.result
				if result == nil {
					t.Fatal("anchored unverified resolution returned no typed result")
				}
				defer result.Close()
				if result.Outcome() != OutcomeForcePartial ||
					result.ForceProvenance() != ForceProvenancePartial ||
					result.Stage() != StageFinalRecord || result.Code() != CodeForcePartial ||
					result.PlaintextLength() != 2097152 ||
					result.FinalRecordState() != RecoveryFinalUnverified {
					t.Fatalf(
						"anchored unverified result = %v/%v/%v/%v, length %d, final %v; want partial/partial/final-record/force-partial, 2097152, unverified",
						result.Outcome(), result.ForceProvenance(), result.Stage(),
						result.Code(), result.PlaintextLength(), result.FinalRecordState(),
					)
				}
				if got := result.Ranges(); !bytes.Equal(recoveryRangeBytes(got), recoveryRangeBytes(wantRanges)) {
					t.Fatalf("anchored unverified ranges = %#v; want exact two-record map %#v", got, wantRanges)
				}
				return nil
			}); err != nil {
				t.Fatalf("live %v consent resolution: %v", test.consent, err)
			}
		})
	}
}

func TestRecoveryDamageStagePreservesProtocolOrder(t *testing.T) {
	tests := []struct {
		name        string
		left, right Stage
		want        Stage
	}{
		{name: "metadata precedes tail geometry", left: StageTailGeometry, right: StageMetadata, want: StageMetadata},
		{name: "tail geometry precedes record authentication", left: StageTailGeometry, right: StageRecordAuth, want: StageTailGeometry},
		{name: "record body precedes final record", left: StageRecordBodyRS, right: StageFinalRecord, want: StageRecordBodyRS},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := earlierRecoveryDamageStage(test.left, test.right); got != test.want {
				t.Fatalf("earlier recovery damage stage = %v; want %v", got, test.want)
			}
		})
	}
}

func TestRecoverNormalV3RetainsFixedPrimaryDamageThroughHealthyBackup(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-degraded-capsule"]
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	frozenVolume := append([]byte(nil), volume...)
	wantPlaintext := readNormalFixturePlaintext(t, fixture.Plaintext)

	password := []byte("mix")
	red := &literalKeyfileReadCloser{reader: bytes.NewReader([]byte("red"))}
	blue := &literalKeyfileReadCloser{reader: bytes.NewReader([]byte("blue"))}
	factors := &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
		KeyfileMode:    pcv3credential.KeyfileModeOrdered,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
		Password:       password,
		Keyfiles: []*pcv3credential.KeyfileReader{
			pcv3credential.OwnKeyfileReader(red),
			pcv3credential.OwnKeyfileReader(blue),
		},
	}
	admitter := &literalKDFAdmitter{}
	callbackCalls := 0
	callbackRole := CapsuleRolePrimary
	var emitted []byte

	result, err := Recover(
		context.Background(),
		bytes.NewReader(volume),
		int64(len(volume)),
		factors,
		admitter,
		RecoveryModeNormalV3,
		func(got *RecoveryResult, role CapsuleRole, emit RecoveryEmitter) error {
			callbackCalls++
			callbackRole = role
			return emit(func(_ RecoveryRange, plaintext []byte) error {
				emitted = append(emitted, plaintext...)
				return nil
			})
		},
	)
	if err != nil {
		t.Fatalf("Recover NormalV3 through frozen backup: %v", err)
	}
	t.Cleanup(result.Close)
	if result.Outcome() != OutcomeAuthenticatedDegraded ||
		result.Stage() != StageCapsuleRS || callbackRole != CapsuleRoleBackup {
		t.Fatalf(
			"NormalV3 result = %v/%v/%v; want authenticated-degraded/capsule-rs/backup",
			result.Outcome(), result.Stage(), callbackRole,
		)
	}
	if callbackCalls != 1 || !bytes.Equal(emitted, wantPlaintext) {
		t.Fatalf(
			"NormalV3 output = callbacks %d, plaintext %x; want one callback and frozen plaintext %x",
			callbackCalls, emitted, wantPlaintext,
		)
	}
	if admitter.calls != 1 || factors.Password != nil || factors.Keyfiles != nil ||
		!allZero(password) || red.closes != 1 || blue.closes != 1 {
		t.Fatalf(
			"NormalV3 credential cleanup = admissions %d, password retained %v/%v, keyfiles retained %v, closes %d/%d; want 1, false/zero, false, 1/1",
			admitter.calls, factors.Password != nil, !allZero(password), factors.Keyfiles != nil,
			red.closes, blue.closes,
		)
	}
	if !bytes.Equal(volume, frozenVolume) {
		t.Fatal("NormalV3 recovery modified the frozen source")
	}
}

func TestRecoverNormalV3PreservesLaterAuthenticationFailureAfterFixedPrimaryDamage(t *testing.T) {
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	degraded := requireNormalFixture(t, fixtures, "normal-degraded-capsule")
	tests := []struct {
		name     string
		mutation string
		stage    Stage
	}{
		{name: "data record", mutation: "normal-negative-record", stage: StageRecordAuth},
		{name: "final record", mutation: "normal-negative-final", stage: StageFinalRecord},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			volume := readNormalFixtureArtifact(t, degraded.Volume)
			mutation := requireNormalFixture(t, fixtures, test.mutation)
			applyNormalFrozenXOR(t, volume, mutation.Mutations)
			frozenVolume := append([]byte(nil), volume...)

			password := []byte("mix")
			red := &literalKeyfileReadCloser{reader: bytes.NewReader([]byte("red"))}
			blue := &literalKeyfileReadCloser{reader: bytes.NewReader([]byte("blue"))}
			factors := &pcv3credential.FactorRequest{
				Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
				KeyfileMode:    pcv3credential.KeyfileModeOrdered,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
				Password:       password,
				Keyfiles: []*pcv3credential.KeyfileReader{
					pcv3credential.OwnKeyfileReader(red),
					pcv3credential.OwnKeyfileReader(blue),
				},
			}
			admitter := &literalKDFAdmitter{}
			outputCalls := 0

			result, err := Recover(
				context.Background(),
				bytes.NewReader(volume),
				int64(len(volume)),
				factors,
				admitter,
				RecoveryModeNormalV3,
				func(*RecoveryResult, CapsuleRole, RecoveryEmitter) error {
					outputCalls++
					return nil
				},
			)
			if err != nil {
				t.Fatalf("Recover compound frozen mutation: %v", err)
			}
			t.Cleanup(result.Close)
			if result.Outcome() != OutcomeAuthenticationFailed || result.Stage() != test.stage ||
				result.Code() != CodeAuthenticationFailed {
				t.Fatalf(
					"compound recovery result = %v/%v/%v; want authentication-failed/%v/authentication-failed",
					result.Outcome(), result.Stage(), result.Code(), test.stage,
				)
			}
			if outputCalls != 0 {
				t.Fatalf("compound recovery output callbacks = %d; want zero", outputCalls)
			}
			if admitter.calls != 1 || factors.Password != nil || factors.Keyfiles != nil ||
				!allZero(password) || red.closes != 1 || blue.closes != 1 {
				t.Fatalf(
					"compound recovery cleanup = admissions %d, password retained %v/%v, keyfiles retained %v, closes %d/%d; want 1, false/zero, false, 1/1",
					admitter.calls, factors.Password != nil, !allZero(password), factors.Keyfiles != nil,
					red.closes, blue.closes,
				)
			}
			if !bytes.Equal(volume, frozenVolume) {
				t.Fatal("compound recovery modified the frozen source")
			}
		})
	}
}

func TestForceRecordAnalysisPrecedesAndConstrainsSecondPassOutput(t *testing.T) {
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	tests := []struct {
		name          string
		fixture       string
		wantRange     RecoveryRangeState
		wantFinal     RecoveryFinalState
		wantStage     Stage
		wantEmissions int
	}{
		{
			name: "damaged data is missing and never emitted", fixture: "normal-negative-record",
			wantRange: RecoveryRangeMissing, wantFinal: RecoveryFinalVerified,
			wantStage: StageRecordAuth, wantEmissions: 0,
		},
		{
			name: "verified data survives a missing final without inventing final bytes", fixture: "normal-negative-final",
			wantRange: RecoveryRangeVerified, wantFinal: RecoveryFinalMissing,
			wantStage: StageFinalRecord, wantEmissions: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := fixtures[test.fixture]
			volume := readNormalFixtureArtifact(t, fixture.Volume)
			structure := inspectNormalFixture(t, fixture)
			candidate, _ := structure.CandidateAt(0)
			geometry, _ := structure.GeometryAt(0)
			provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
			provider.access.adopted = true
			defer provider.close()
			request, _ := newRecoveryRequest(RecoveryModeForce)

			analysis, err := analyzeRecoveryRecords(
				context.Background(), bytes.NewReader(volume), candidate, geometry,
				provider, request, candidate.Role(),
			)
			if err != nil {
				t.Fatalf("analyze frozen Force records: %v", err)
			}
			if len(analysis.ranges) != 1 || analysis.ranges[0].State() != test.wantRange ||
				analysis.final != test.wantFinal || analysis.damageStage != test.wantStage {
				t.Fatalf("analysis = %#v/%v/%v; want one %v range, final %v, stage %v", analysis.ranges, analysis.final, analysis.damageStage, test.wantRange, test.wantFinal, test.wantStage)
			}

			emissions := 0
			var emitted []byte
			err = emitRecoveryRecords(
				context.Background(), bytes.NewReader(volume), candidate, geometry,
				provider, request, candidate.Role(), analysis,
				func(recoveryRange RecoveryRange, plaintext []byte) error {
					emissions++
					if recoveryRange.State() == RecoveryRangeMissing {
						t.Fatal("second pass emitted a missing range")
					}
					emitted = append(emitted, plaintext...)
					return nil
				},
			)
			if err != nil {
				t.Fatalf("emit frozen Force records: %v", err)
			}
			if emissions != test.wantEmissions {
				t.Fatalf("emissions = %d; want %d", emissions, test.wantEmissions)
			}
			if test.wantEmissions != 0 {
				wantPlaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
				if !bytes.Equal(emitted, wantPlaintext) {
					t.Fatalf("emitted bytes = %x; want original-offset frozen plaintext %x", emitted, wantPlaintext)
				}
			}
		})
	}
}

func TestForceMiddleMissingRecordDoesNotSuppressLaterVerifiedEmission(t *testing.T) {
	const (
		recordPlaintextLength  = 1048576
		plaintextLength        = 3145728
		frontHeaderLength      = 1112
		middleDescriptorOffset = 1049800
		middleBodyOffset       = 1049848
		middleTagOffset        = 2098424
		volumeLength           = 3148296
	)

	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-two-mib")
	frozenVolume := readNormalFixtureArtifact(t, fixture.Volume)
	writeRequest, material, entropy := decodeNormalWriterFixtureInputs(t, fixture, frozenVolume)
	defer material.keys.close()
	if writeRequest.suite != SuiteStandard || writeRequest.payloadBodyRS {
		t.Fatal("middle-hole seed must use the standard suite without payload Reed-Solomon")
	}
	writeRequest.plaintextLength = plaintextLength

	plaintext := make([]byte, 0, plaintextLength)
	plaintext = append(plaintext, bytes.Repeat([]byte{0x41}, recordPlaintextLength)...)
	plaintext = append(plaintext, bytes.Repeat([]byte{0x42}, recordPlaintextLength)...)
	plaintext = append(plaintext, bytes.Repeat([]byte{0x43}, recordPlaintextLength)...)
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("create TEST ONLY RS codecs: %v", err)
	}
	var serialized bytes.Buffer
	completion, err := serializeNormalVolume(
		context.Background(),
		writeRequest,
		bytes.NewReader(plaintext),
		&serialized,
		material,
		normalWriteSeams{entropy: bytes.NewReader(entropy), codecs: codecs},
	)
	if err != nil || completion == nil {
		t.Fatalf("serialize three-record Force volume = completion %v, error %v", completion != nil, err)
	}
	volume := append([]byte(nil), serialized.Bytes()...)
	if len(volume) != volumeLength {
		t.Fatalf("three-record volume length = %d; want literal format length %d", len(volume), volumeLength)
	}

	route, structure, err := Probe(bytes.NewReader(volume), int64(len(volume)))
	if err != nil || route != RouteNormalPCV {
		t.Fatalf("Probe(three-record Force volume) = %v, %v; want normal PCV admission", route, err)
	}
	candidate, ok := structure.CandidateAt(0)
	if !ok {
		t.Fatal("three-record Force volume has no primary candidate")
	}
	geometry, ok := structure.GeometryAt(0)
	if !ok {
		t.Fatal("three-record Force volume has no primary geometry")
	}
	if geometry.PayloadBodyRS() || geometry.RecordCount() != 3 ||
		geometry.FrontHeaderLength() != frontHeaderLength || geometry.FileSize() != volumeLength {
		t.Fatalf(
			"three-record geometry = RS %v, records %d, front %d, file %d; want false, 3, %d, %d",
			geometry.PayloadBodyRS(), geometry.RecordCount(), geometry.FrontHeaderLength(),
			geometry.FileSize(), frontHeaderLength, volumeLength,
		)
	}
	middle, err := expectedRecord(candidate.core, geometry, 1)
	if err != nil {
		t.Fatalf("derive middle record geometry: %v", err)
	}
	if middle.final || middle.descriptorOffset != middleDescriptorOffset ||
		middle.bodyOffset != middleBodyOffset ||
		middle.encodedBodyLength != recordPlaintextLength+64 ||
		middle.bodyOffset+recordPlaintextLength != middleTagOffset {
		t.Fatalf(
			"middle record geometry = final %v, descriptor %d, body %d, encoded body %d, tag %d; want false, %d, %d, %d, %d",
			middle.final, middle.descriptorOffset, middle.bodyOffset, middle.encodedBodyLength,
			middle.bodyOffset+recordPlaintextLength, middleDescriptorOffset, middleBodyOffset,
			recordPlaintextLength+64, middleTagOffset,
		)
	}
	volume[middleTagOffset] ^= 0x80

	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	provider.access.adopted = true
	defer provider.close()
	forceRequest, err := newRecoveryRequest(RecoveryModeForce)
	if err != nil {
		t.Fatalf("new Force request: %v", err)
	}
	analysis, err := analyzeRecoveryRecords(
		context.Background(), bytes.NewReader(volume), candidate, geometry,
		provider, forceRequest, candidate.Role(),
	)
	if err != nil {
		t.Fatalf("analyze three-record Force volume: %v", err)
	}
	resolution, err := resolveForceCandidates(forceRequest, []forceCandidateAnalysis{{
		identity:    &forceTestIdentity{value: 13},
		candidate:   candidate,
		geometry:    geometry,
		damageStage: analysis.damageStage,
		ranges:      analysis.ranges,
		final:       analysis.final,
	}})
	if err != nil {
		t.Fatalf("resolve three-record Force volume: %v", err)
	}
	if resolution.result == nil {
		t.Fatal("three-record Force resolution returned no typed result")
	}
	defer resolution.result.Close()
	wantRanges := []RecoveryRange{
		{recordIndex: 0, start: 0, end: 1048576, state: RecoveryRangeVerified},
		{recordIndex: 1, start: 1048576, end: 2097152, state: RecoveryRangeMissing},
		{recordIndex: 2, start: 2097152, end: 3145728, state: RecoveryRangeVerified},
	}
	gotRanges := resolution.result.Ranges()
	if len(gotRanges) != len(wantRanges) {
		t.Fatalf("resolved recovery ranges = %#v; want exact three-record map %#v", gotRanges, wantRanges)
	}
	for index := range wantRanges {
		if gotRanges[index] != wantRanges[index] {
			t.Fatalf("resolved recovery range %d = %#v; want %#v", index, gotRanges[index], wantRanges[index])
		}
	}
	if resolution.selected != 0 ||
		resolution.result.Outcome() != OutcomeForcePartial ||
		resolution.result.ForceProvenance() != ForceProvenancePartial ||
		resolution.result.Stage() != StageRecordAuth ||
		resolution.result.Code() != CodeForcePartial ||
		resolution.result.PlaintextLength() != plaintextLength ||
		resolution.result.FinalRecordState() != RecoveryFinalVerified {
		t.Fatalf(
			"Force resolution = selected %d, %v/%v/%v/%v, length %d, final %v; want 0, partial/partial/record-auth/force-partial, %d, verified",
			resolution.selected, resolution.result.Outcome(), resolution.result.ForceProvenance(),
			resolution.result.Stage(), resolution.result.Code(), resolution.result.PlaintextLength(),
			resolution.result.FinalRecordState(), plaintextLength,
		)
	}

	type emission struct {
		recoveryRange RecoveryRange
		plaintext     []byte
	}
	var emissions []emission
	err = emitRecoveryRecords(
		context.Background(), bytes.NewReader(volume), candidate, geometry,
		provider, forceRequest, candidate.Role(), analysis,
		func(recoveryRange RecoveryRange, emitted []byte) error {
			if recoveryRange.State() == RecoveryRangeMissing {
				t.Fatal("Force emitted bytes for the missing middle record")
			}
			emissions = append(emissions, emission{
				recoveryRange: recoveryRange,
				plaintext:     append([]byte(nil), emitted...),
			})
			return nil
		},
	)
	if err != nil {
		t.Fatalf("emit three-record Force volume: %v", err)
	}
	if len(emissions) != 2 {
		t.Fatalf("Force emissions = %d; want record 0 and record 2 around one literal hole", len(emissions))
	}
	wantEmissionRanges := []RecoveryRange{wantRanges[0], wantRanges[2]}
	wantEmissionBytes := [][]byte{
		bytes.Repeat([]byte{0x41}, recordPlaintextLength),
		bytes.Repeat([]byte{0x43}, recordPlaintextLength),
	}
	for index := range emissions {
		if emissions[index].recoveryRange != wantEmissionRanges[index] {
			t.Fatalf("Force emission %d range = %#v; want %#v", index, emissions[index].recoveryRange, wantEmissionRanges[index])
		}
		if !bytes.Equal(emissions[index].plaintext, wantEmissionBytes[index]) {
			t.Fatalf("Force emission %d did not preserve the verified record bytes at their original range", index)
		}
	}
}

func TestUnverifiedRecordAnalysisRequiresExactLiveRole(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-negative-record"]
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	structure := inspectNormalFixture(t, fixture)
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	provider.access.adopted = true
	defer provider.close()

	if err := withUnverifiedRecoveryRequest(CapsuleRolePrimary, func(request recoveryRequest) error {
		analysis, err := analyzeRecoveryRecords(
			context.Background(), bytes.NewReader(volume), candidate, geometry,
			provider, request, CapsuleRolePrimary,
		)
		if err != nil {
			return err
		}
		if len(analysis.ranges) != 1 || analysis.ranges[0].State() != RecoveryRangeUnverified ||
			analysis.final != RecoveryFinalVerified {
			t.Fatalf("authorized unverified analysis = %#v/%v; want unverified data plus verified final anchor", analysis.ranges, analysis.final)
		}
		return nil
	}); err != nil {
		t.Fatalf("live primary consent: %v", err)
	}

	if err := withUnverifiedRecoveryRequest(CapsuleRoleBackup, func(request recoveryRequest) error {
		analysis, err := analyzeRecoveryRecords(
			context.Background(), bytes.NewReader(volume), candidate, geometry,
			provider, request, CapsuleRolePrimary,
		)
		if err != nil {
			return err
		}
		if analysis.ranges[0].State() != RecoveryRangeMissing {
			t.Fatalf("role-mismatched analysis state = %v; want missing", analysis.ranges[0].State())
		}
		return nil
	}); err != nil {
		t.Fatalf("live backup consent: %v", err)
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

func TestRecoveryOperationFailureFallsBackToTypedPolicyFailure(t *testing.T) {
	result := recoveryOperationFailure(Stage(255))
	if result == nil {
		t.Fatal("invalid-stage operation failure returned no typed result")
	}
	if result.Outcome() != OutcomeOperationFailed ||
		result.Stage() != StageCredentialPolicy || result.Code() != CodeOperationFailed {
		t.Fatalf("invalid-stage operation failure = %v/%v/%v; want typed policy failure", result.Outcome(), result.Stage(), result.Code())
	}
}
