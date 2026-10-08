package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestD1ForceCandidatesBootstrapBinderPreservesPolicyEvidenceAndSecretScope(t *testing.T) {
	const bodyLength = uint64(4096)
	outerKey := bytes.Repeat([]byte{0x2f}, 32)
	defer pcv3crypto.SecureZero(outerKey)
	tests := []struct {
		name     string
		mutate   func(*testing.T, []byte, *d1TestBootstrapCredentialAccess)
		evidence d1ForceTestBootstrapEvidence
	}{
		{
			name: "wrap damage preserves replica evidence",
			mutate: func(_ *testing.T, raw []byte, _ *d1TestBootstrapCredentialAccess) {
				raw[d1BootstrapWrapTagOffset] ^= 0x01
			},
			evidence: d1ForceTestBootstrapEvidence{replicaVerified: true},
		},
		{
			name: "replica damage preserves wrap evidence",
			mutate: func(t *testing.T, raw []byte, access *d1TestBootstrapCredentialAccess) {
				raw[d1BootstrapReplicaTagOffset] ^= 0x01
				recomputeD1BootstrapWrapTag(t, raw, D1BootstrapFront, access.keys.mac[:])
			},
			evidence: d1ForceTestBootstrapEvidence{wrapVerified: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, access := newD1BootstrapTestFixture(
				t,
				D1BootstrapFront,
				0x24,
				outerKey,
				bodyLength,
			)
			test.mutate(t, raw, access)
			bootstrap, err := parseD1Bootstrap(raw, D1BootstrapFront)
			if err != nil {
				t.Fatalf("parse D1 Force bridge fixture: %v", err)
			}

			var retained *d1ForceCandidate
			var borrowed *pcv3credential.BorrowedD1OuterKeys
			callbackCalls := 0
			err = bindD1ForceCandidateWithAccess(
				context.Background(),
				bootstrap,
				access,
				defaultD1BootstrapAuthSeams(),
				func(candidate *d1ForceCandidate) error {
					callbackCalls++
					retained = candidate
					if candidate == nil || candidate.role != D1BootstrapFront ||
						candidate.bodyLength != bodyLength ||
						candidate.wrapVerified != test.evidence.wrapVerified ||
						candidate.replicaVerified != test.evidence.replicaVerified {
						return errors.New("D1 Force bridge lost role, body length, or named bootstrap evidence")
					}
					var gotOuterKey [32]byte
					defer pcv3crypto.SecureZero(gotOuterKey[:])
					if borrowErr := candidate.withOuterKeys(
						context.Background(),
						func(keys *pcv3credential.BorrowedD1OuterKeys) error {
							borrowed = keys
							return keys.CopyOuterKey(gotOuterKey[:])
						},
					); borrowErr != nil {
						return fmt.Errorf("borrow D1 Force bridge OuterKey: %w", borrowErr)
					}
					if !bytes.Equal(gotOuterKey[:], outerKey) {
						return errors.New("D1 Force bridge did not expose the complete OuterSecret")
					}
					return nil
				},
			)
			if err != nil || callbackCalls != 1 {
				t.Fatalf("bind D1 Force candidate = error %v, callbacks %d; want nil/1", err, callbackCalls)
			}
			if retained == nil || borrowed == nil {
				t.Fatal("D1 Force bridge did not expose its callback-scoped policy view")
			}
			postScopeCalls := 0
			if err := retained.withOuterKeys(
				context.Background(),
				func(*pcv3credential.BorrowedD1OuterKeys) error {
					postScopeCalls++
					return nil
				},
			); err == nil || postScopeCalls != 0 || retained.bodyLength != 0 ||
				retained.wrapVerified || retained.replicaVerified {
				t.Fatalf(
					"expired D1 Force bridge = error %v, callbacks %d, length %d, evidence %t/%t; want closed zero policy view",
					err,
					postScopeCalls,
					retained.bodyLength,
					retained.wrapVerified,
					retained.replicaVerified,
				)
			}
			var postScopeKey [32]byte
			if err := borrowed.CopyOuterKey(postScopeKey[:]); err == nil {
				pcv3crypto.SecureZero(postScopeKey[:])
				t.Fatal("borrowed D1 Force OuterKey survived the binder callback")
			}
			pcv3crypto.SecureZero(postScopeKey[:])
		})
	}
}

func TestD1ForceCandidatesNormalAnalysisHandoff(t *testing.T) {
	t.Run("complete analysis is reused while every requested record is reauthenticated", func(t *testing.T) {
		inner := bytes.Repeat([]byte("TEST ONLY normal D1 analysis handoff; "), 70_000)
		candidate, body := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapFront,
			0x39,
			inner,
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		defer candidate.Close()
		physical := d1ForceCanonicalPhysicalFile(body)
		source := &d1ForceObservedReader{bytes: physical}
		sourceSize := int64(len(physical))
		analysis, selection, selected, err := selectNormalD1Front(
			context.Background(),
			source,
			sourceSize,
			candidate,
		)
		if err != nil || analysis == nil || !selected ||
			!analysis.outerAnchored || !analysis.outerFullyAuthenticated ||
			selection.analysis != analysis {
			t.Fatalf(
				"normal front analysis = analysis %#v, selected %v, selection %#v, error %v; want one complete selected analysis",
				analysis, selected, selection, err,
			)
		}
		analysisReads := len(source.requests)
		reader, err := newD1InnerReaderFromCompleteAnalysis(
			context.Background(),
			source,
			sourceSize,
			analysis,
		)
		if err != nil {
			t.Fatalf("open analyzed normal D1 body: %v", err)
		}
		defer reader.Close()
		if len(source.requests) != analysisReads+2 {
			t.Fatalf(
				"analyzed reader constructor added %d reads; want only first-record ciphertext and tag, not a second full pass",
				len(source.requests)-analysisReads,
			)
		}

		const innerOffset = int64(d1OuterChunkSize)
		destination := make([]byte, 97)
		count, err := reader.ReadAt(destination, innerOffset)
		if err != nil || count != len(destination) ||
			!bytes.Equal(destination, inner[innerOffset:innerOffset+int64(len(destination))]) {
			t.Fatalf("analyzed reader late read = %d, %v; want exact authenticated bytes", count, err)
		}
		outerOffset := uint64(d1OuterPrefixLength) + uint64(innerOffset)
		recordIndex := outerOffset / d1OuterChunkSize
		expected, err := expectedD1OuterRecord(analysis.geometry, recordIndex)
		if err != nil {
			t.Fatalf("locate reauthenticated normal D1 record: %v", err)
		}
		tagOffset := uint64(d1BootstrapLength) + expected.offset + uint64(expected.ciphertextLength)
		source.bytes[tagOffset] ^= 0x01
		for index := range destination {
			destination[index] = 0xa5
		}
		count, err = reader.ReadAt(destination, innerOffset)
		if err == nil || count != 0 || !allZero(destination) {
			t.Fatalf(
				"post-handoff tag mutation = %d, %v, zeroed %v; want fail-closed reauthentication",
				count, err, allZero(destination),
			)
		}
	})

	t.Run("persistent short reads become one reusable damage analysis per candidate", func(t *testing.T) {
		inner := bytes.Repeat([]byte("TEST ONLY short normal D1 analysis; "), 70_000)
		front, tail, body := newMatchingD1ForceTestBodyCandidates(
			t,
			0x49,
			inner,
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		defer front.Close()
		defer tail.Close()
		physical := d1ForceCanonicalPhysicalFile(body)
		source := &d1ForceFaultReader{bytes: physical, fault: d1ForceSourceShortRead}
		sourceSize := int64(len(physical))
		frontAnalysis, _, selected, err := selectNormalD1Front(
			context.Background(),
			source,
			sourceSize,
			front,
		)
		if err != nil || frontAnalysis == nil || selected ||
			frontAnalysis.outerAnchored || frontAnalysis.outerFullyAuthenticated {
			t.Fatalf(
				"short front analysis = %#v, selected %v, error %v; want reusable unanchored damage",
				frontAnalysis, selected, err,
			)
		}
		frontReads := len(source.requests)
		if frontReads != int(frontAnalysis.geometry.recordCount) {
			t.Fatalf("short front reads = %d; want one failed load for each of %d records", frontReads, frontAnalysis.geometry.recordCount)
		}
		request, err := newD1RecoveryRequest(RecoveryModeNormalV3)
		if err != nil {
			t.Fatalf("create normal D1 recovery request: %v", err)
		}
		selection, terminal, err := selectD1ForceCandidateWithPreanalysis(
			context.Background(),
			source,
			sourceSize,
			request,
			[]*d1ForceCandidate{front, tail},
			defaultD1ForceSeams(),
			frontAnalysis,
		)
		if err != nil || terminal == nil || selection.analysis != nil {
			if terminal != nil {
				terminal.Close()
			}
			t.Fatalf("short candidate resolution = selection %#v, terminal %#v, error %v", selection, terminal, err)
		}
		defer terminal.Close()
		if terminal.Outcome() != OutcomeAuthenticationFailed || terminal.Stage() != StageD1Body ||
			terminal.D1BootstrapProvenance() != D1BootstrapProvenanceMatching {
			t.Fatalf(
				"short candidate result = %v/%v/%v; want authentication-failed/d1-body/matching",
				terminal.Outcome(), terminal.Stage(), terminal.D1BootstrapProvenance(),
			)
		}
		if len(source.requests) != 2*frontReads {
			t.Fatalf(
				"short candidate reads = %d; want one reused front pass plus one tail pass (%d total)",
				len(source.requests), 2*frontReads,
			)
		}
	})
}

func TestD1ForceConsent(t *testing.T) {
	t.Run("raw outer semantic requires physical selection", testD1ForceConsentRawOuterSemantic)
	t.Run("raw outer emission preserves authentication truth", testD1ForceRawOuterEmission)
}

func testD1ForceRawOuterEmission(t *testing.T) {
	inner := bytes.Repeat([]byte("TEST ONLY D1 raw outer evidence; "), 40_000)
	candidate, body := newD1ForceTestBodyCandidate(
		t,
		D1BootstrapFront,
		0xc3,
		inner,
		d1ForceTestBootstrapEvidence{replicaVerified: true},
	)
	defer candidate.Close()
	geometry, err := parseD1OuterGeometry(candidate.bodyLength)
	if err != nil || geometry.recordCount < 2 {
		t.Fatalf("parse multi-record raw geometry = %#v, %v; want at least two records", geometry, err)
	}
	damaged, err := expectedD1OuterRecord(geometry, 1)
	if err != nil || damaged.ciphertextLength == 0 {
		t.Fatalf("select damaged data record = %#v, %v", damaged, err)
	}
	tagOffset := damaged.offset + uint64(damaged.ciphertextLength)
	body[tagOffset] ^= 0x01
	physical := d1ForceCanonicalPhysicalFile(body)
	window, err := deriveD1ForceBodyWindow(
		int64(len(physical)),
		candidate.bodyLength,
		candidate.role,
	)
	if err != nil {
		t.Fatalf("derive raw body window: %v", err)
	}
	analysis, err := analyzeD1ForceCandidate(
		context.Background(),
		bytes.NewReader(physical),
		window,
		candidate,
		defaultD1ForceSeams(),
	)
	if err != nil || !analysis.outerAnchored || analysis.outerFullyAuthenticated {
		t.Fatalf("damaged raw analysis = %#v, %v; want anchored partial body", analysis, err)
	}
	selection := d1ForceSelection{
		analysis:         analysis,
		provenance:       D1BootstrapProvenanceFront,
		bootstrapHealthy: false,
		outerHealthy:     false,
	}
	wantOuter := make([]byte, d1OuterPrefixLength+len(inner))
	copy(wantOuter, []byte("PCVOUT3\x00"))
	binary.BigEndian.PutUint64(wantOuter[8:d1OuterPrefixLength], uint64(len(inner)))
	copy(wantOuter[d1OuterPrefixLength:], inner)

	assertEmission := func(
		t *testing.T,
		request d1RecoveryRequest,
		wantOutcome Outcome,
		wantProvenance ForceProvenance,
		wantStates []RecoveryRangeState,
		wantFinal RecoveryFinalState,
		wantPlaintext []byte,
	) {
		t.Helper()
		result, err := analyzeD1RawOuter(
			context.Background(),
			bytes.NewReader(physical),
			request,
			selection,
			defaultD1ForceSeams(),
		)
		if err != nil {
			t.Fatalf("analyze raw outer: %v", err)
		}
		if result == nil {
			t.Fatal("anchored damaged outer produced no recovery evidence")
		}
		defer result.Close()
		ranges := testRecoveryRanges(result.Ranges())
		if result.Outcome() != wantOutcome || result.ForceProvenance() != wantProvenance ||
			result.Stage() != StageD1Bootstrap || result.FinalRecordState() != wantFinal ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceFront ||
			len(ranges) != len(wantStates) {
			t.Fatalf(
				"raw evidence = %v/%v/%v/%v final %v ranges %#v; want %v/%v/d1-bootstrap/front final %v and %v",
				result.Outcome(), result.ForceProvenance(), result.Stage(), result.D1BootstrapProvenance(),
				result.FinalRecordState(), ranges, wantOutcome, wantProvenance, wantFinal, wantStates,
			)
		}
		for index, wantState := range wantStates {
			if ranges[index].State() != wantState {
				t.Fatalf("raw range %d state = %v; want %v", index, ranges[index].State(), wantState)
			}
		}
		var emitted []byte
		returned, emitErr := emitD1RawOuter(
			context.Background(),
			bytes.NewReader(physical),
			request,
			selection,
			defaultD1ForceSeams(),
			result,
			func(got *RecoveryResult, role D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
				if got != result || role != D1BootstrapFront {
					return errors.New("TEST ONLY raw output lost semantic or physical role")
				}
				return emitter(func(recoveryRange RecoveryRange, plaintext []byte) error {
					if recoveryRange.State() == RecoveryRangeMissing {
						return errors.New("TEST ONLY missing range was emitted")
					}
					emitted = append(emitted, plaintext...)
					return nil
				})
			},
		)
		if emitErr != nil || returned != result {
			t.Fatalf("emit raw outer = result %p, error %v; want original semantic", returned, emitErr)
		}
		if !bytes.Equal(emitted, wantPlaintext) {
			t.Fatalf("emitted raw plaintext length = %d; want exact %d authenticated/authorized bytes", len(emitted), len(wantPlaintext))
		}
	}

	ordinary, err := newD1RecoveryRequest(RecoveryModeForce)
	if err != nil {
		t.Fatalf("create ordinary raw request: %v", err)
	}
	assertEmission(
		t,
		ordinary,
		OutcomeForcePartial,
		ForceProvenancePartial,
		[]RecoveryRangeState{RecoveryRangeVerified, RecoveryRangeMissing},
		RecoveryFinalMissing,
		wantOuter[:d1OuterChunkSize],
	)
	if err := withUnverifiedD1RecoveryRequest(D1BootstrapFront, func(request d1RecoveryRequest) error {
		assertEmission(
			t,
			request,
			OutcomeForcePartial,
			ForceProvenancePartial,
			[]RecoveryRangeState{RecoveryRangeVerified, RecoveryRangeUnverified},
			RecoveryFinalUnverified,
			wantOuter,
		)
		return nil
	}); err != nil {
		t.Fatalf("exact-role raw emission: %v", err)
	}
	if err := withUnverifiedD1RecoveryRequest(D1BootstrapTail, func(request d1RecoveryRequest) error {
		assertEmission(
			t,
			request,
			OutcomeForcePartial,
			ForceProvenancePartial,
			[]RecoveryRangeState{RecoveryRangeVerified, RecoveryRangeMissing},
			RecoveryFinalMissing,
			wantOuter[:d1OuterChunkSize],
		)
		return nil
	}); err != nil {
		t.Fatalf("wrong-role raw emission: %v", err)
	}

	t.Run("emitter capability expires when the output callback panics", func(t *testing.T) {
		result, err := analyzeD1RawOuter(
			context.Background(),
			bytes.NewReader(physical),
			ordinary,
			selection,
			defaultD1ForceSeams(),
		)
		if err != nil || result == nil {
			t.Fatalf("prepare panic-path raw output = result %#v, error %v", result, err)
		}
		defer result.Close()

		var retained RecoveryEmitter
		panicObserved := false
		func() {
			defer func() {
				panicObserved = recover() != nil
			}()
			_, _ = emitD1RawOuter(
				context.Background(),
				bytes.NewReader(physical),
				ordinary,
				selection,
				defaultD1ForceSeams(),
				result,
				func(_ *RecoveryResult, _ D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
					retained = emitter
					panic("TEST ONLY output callback panic")
				},
			)
		}()
		if !panicObserved || retained == nil {
			t.Fatalf("panic-path output = panic %v, retained emitter %v; want propagated panic and captured scoped emitter", panicObserved, retained != nil)
		}
		sinkCalls := 0
		if err := retained(func(RecoveryRange, []byte) error {
			sinkCalls++
			return nil
		}); err == nil || sinkCalls != 0 {
			t.Fatalf("retained panic-path emitter = error %v, sink calls %d; want expired before any plaintext callback", err, sinkCalls)
		}
	})

	t.Run("final evidence cannot contradict its positive-length range", func(t *testing.T) {
		analyzed, err := analyzeD1RawOuter(
			context.Background(),
			bytes.NewReader(physical),
			ordinary,
			selection,
			defaultD1ForceSeams(),
		)
		if err != nil || analyzed == nil {
			t.Fatalf("prepare final-evidence regression = result %#v, error %v", analyzed, err)
		}
		ranges := testRecoveryRanges(analyzed.Ranges())
		analyzed.Close()
		for index := range ranges {
			ranges[index].state = RecoveryRangeMissing
		}
		inconsistent, err := newD1RecoveryResult(
			OutcomeForcePartial,
			ForceProvenancePartial,
			StageD1Bootstrap,
			D1BootstrapProvenanceFront,
			StageNone,
			analysis.geometry.plaintextLength,
			testRecoveryMap(ranges),
			RecoveryFinalVerified,
		)
		if err != nil {
			t.Fatalf("construct contradictory final evidence: %v", err)
		}
		defer inconsistent.Close()
		sinkCalls := 0
		returned, emitErr := emitD1RawOuter(
			context.Background(),
			bytes.NewReader(physical),
			ordinary,
			selection,
			defaultD1ForceSeams(),
			inconsistent,
			func(_ *RecoveryResult, _ D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
				return emitter(func(RecoveryRange, []byte) error {
					sinkCalls++
					return nil
				})
			},
		)
		if returned != nil && returned != inconsistent {
			defer returned.Close()
		}
		if emitErr == nil || sinkCalls != 0 {
			t.Fatalf(
				"contradictory final evidence = error %v, sink calls %d; want rejection before plaintext emission",
				emitErr, sinkCalls,
			)
		}
	})

	allDamaged := append([]byte(nil), body...)
	corruptEveryD1ForceTestTag(t, allDamaged)
	allDamaged[tagOffset] ^= 0x01 // The selected tag was already damaged before the all-tag mutation.
	allPhysical := d1ForceCanonicalPhysicalFile(allDamaged)
	allAnalysis, err := analyzeD1ForceCandidate(
		context.Background(),
		bytes.NewReader(allPhysical),
		window,
		candidate,
		defaultD1ForceSeams(),
	)
	if err != nil || allAnalysis.outerAnchored {
		t.Fatalf("all-damaged raw analysis = %#v, %v; want no authenticated anchor", allAnalysis, err)
	}
	selection.analysis = allAnalysis
	result, err := analyzeD1RawOuter(
		context.Background(),
		bytes.NewReader(allPhysical),
		ordinary,
		selection,
		defaultD1ForceSeams(),
	)
	if err != nil || result != nil {
		if result != nil {
			result.Close()
		}
		t.Fatalf("ordinary all-damaged raw analysis = result %#v, error %v; want no output authority", result, err)
	}
	physical = allPhysical
	selection.requiresRawAuthority = true
	if err := withUnverifiedD1RecoveryRequest(D1BootstrapFront, func(request d1RecoveryRequest) error {
		assertEmission(
			t,
			request,
			OutcomeForceUnverified,
			ForceProvenanceUnverified,
			[]RecoveryRangeState{RecoveryRangeUnverified, RecoveryRangeUnverified},
			RecoveryFinalUnverified,
			wantOuter,
		)
		return nil
	}); err != nil {
		t.Fatalf("all-damaged exact-role raw emission: %v", err)
	}

	t.Run("publication error preserves live raw semantic", func(t *testing.T) {
		publicationErr := errors.New("TEST ONLY publication failure")
		var returned *RecoveryResult
		var delivered *RecoveryResult
		var recoverErr error
		var retained RecoveryEmitter
		var emitted []byte
		err := withUnverifiedD1RecoveryRequest(D1BootstrapFront, func(request d1RecoveryRequest) error {
			// The deliberately non-PCV inner bytes fail inspection before these
			// credential-session inputs can be reached.
			returned, recoverErr = recoverD1Selection(
				context.Background(),
				bytes.NewReader(physical),
				int64(len(physical)),
				nil,
				nil,
				nil,
				request,
				selection,
				defaultD1ForceSeams(),
				func(got *RecoveryResult, role D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
					if got == nil || role != D1BootstrapFront {
						return errors.New("TEST ONLY raw publication lost semantic or physical role")
					}
					delivered = got
					retained = emitter
					if err := emitter(func(recoveryRange RecoveryRange, plaintext []byte) error {
						if recoveryRange.State() == RecoveryRangeMissing {
							return errors.New("TEST ONLY raw publication emitted a missing range")
						}
						emitted = append(emitted, plaintext...)
						return nil
					}); err != nil {
						return err
					}
					return publicationErr
				},
			)
			return nil
		})
		if err != nil {
			t.Fatalf("publication-error exact-role authority: %v", err)
		}
		if returned == nil || returned != delivered {
			t.Fatalf("publication error returned result %p; delivered %p", returned, delivered)
		}
		defer returned.Close()
		var engineErr *recoveryEngineError
		if !errors.As(recoverErr, &engineErr) || engineErr.stage != StageOutputWrite {
			t.Fatalf("publication error = %T %v; want output-write engine error", recoverErr, recoverErr)
		}
		if returned.Outcome() != OutcomeForceUnverified ||
			returned.ForceProvenance() != ForceProvenanceUnverified ||
			returned.Stage() != StageD1Bootstrap ||
			returned.D1BootstrapProvenance() != D1BootstrapProvenanceFront ||
			returned.FinalRecordState() != RecoveryFinalUnverified {
			t.Fatalf(
				"publication error changed raw semantic to %v/%v/%v/%v final %v",
				returned.Outcome(), returned.ForceProvenance(), returned.Stage(),
				returned.D1BootstrapProvenance(), returned.FinalRecordState(),
			)
		}
		if !bytes.Equal(emitted, wantOuter) {
			t.Fatalf("publication-error raw output length = %d; want exact %d bytes", len(emitted), len(wantOuter))
		}
		if retained == nil {
			t.Fatal("publication callback did not receive its scoped emitter")
		}
		sinkCalls := 0
		if err := retained(func(RecoveryRange, []byte) error {
			sinkCalls++
			return nil
		}); err == nil || sinkCalls != 0 {
			t.Fatalf("retained publication emitter = error %v, sink calls %d; want expired", err, sinkCalls)
		}
	})
}

func testD1ForceConsentRawOuterSemantic(t *testing.T) {
	const plaintextLength = uint64(17)
	ranges := []RecoveryRange{{
		recordIndex: 0,
		start:       0,
		end:         plaintextLength,
		state:       RecoveryRangeUnverified,
	}}
	result, err := newD1RecoveryResult(
		OutcomeForceUnverified,
		ForceProvenanceUnverified,
		StageD1Body,
		D1BootstrapProvenanceFront,
		StageNone,
		plaintextLength,
		testRecoveryMap(ranges),
		RecoveryFinalUnverified,
	)
	if err != nil {
		t.Fatalf("construct consented D1 raw semantic: %v", err)
	}
	if result.Outcome() != OutcomeForceUnverified || result.Stage() != StageD1Body ||
		result.D1BootstrapProvenance() != D1BootstrapProvenanceFront ||
		result.ForceProvenance() != ForceProvenanceUnverified {
		result.Close()
		t.Fatalf(
			"raw D1 semantic = %v/%v/%v/%v; want Force-unverified/d1-body/front/unverified",
			result.Outcome(), result.Stage(), result.D1BootstrapProvenance(), result.ForceProvenance(),
		)
	}
	result.Close()

	for _, provenance := range []D1BootstrapProvenance{
		D1BootstrapProvenanceNone,
		D1BootstrapProvenanceMatching,
	} {
		result, err := newD1RecoveryResult(
			OutcomeForceUnverified,
			ForceProvenanceUnverified,
			StageD1Body,
			provenance,
			StageNone,
			plaintextLength,
			testRecoveryMap(ranges),
			RecoveryFinalUnverified,
		)
		if err == nil || result != nil {
			if result != nil {
				result.Close()
			}
			t.Fatalf("raw D1 semantic accepted nonphysical provenance %v", provenance)
		}
	}
}

func TestD1ForceNestedOutcomePreservesOuterInnerAndRangeTruth(t *testing.T) {
	t.Run("inner ordinary result precedes Force without rebinding candidates", func(t *testing.T) {
		fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		structure, err := InspectRecovery(bytes.NewReader(volume), int64(len(volume)))
		if err != nil {
			t.Fatalf("inspect TEST ONLY ordinary-first recovery fixture: %v", err)
		}
		analyses := make([]forceCandidateAnalysis, 0, structure.CandidateCount())
		for index := range structure.CandidateCount() {
			candidate, candidateOK := structure.CandidateAt(index)
			geometry, geometryOK := structure.GeometryAt(index)
			if !candidateOK || !geometryOK {
				t.Fatal("TEST ONLY ordinary-first fixture omitted a bounded candidate")
			}
			ranges := make([]RecoveryRange, 0, candidate.RecordCount())
			for recordIndex := range candidate.RecordCount() {
				start := recordIndex * recordPlaintextMax
				end := min(start+recordPlaintextMax, candidate.PlaintextLength())
				ranges = append(ranges, RecoveryRange{
					recordIndex: recordIndex,
					start:       start,
					end:         end,
					state:       RecoveryRangeVerified,
				})
			}
			analyses = append(analyses, forceCandidateAnalysis{
				identity:      &forceTestIdentity{value: 0x71},
				candidate:     candidate,
				geometry:      geometry,
				wrapVerified:  true,
				replicaValid:  true,
				metadataValid: true,
				ranges:        testRecoveryMap(ranges),
				final:         RecoveryFinalVerified,
			})
		}

		resolution, resolved, request, err := resolveD1InnerRecoveryAnalyses(structure, analyses)
		if err != nil {
			t.Fatalf("resolve healthy ordinary-first evidence: %v", err)
		}
		if resolution.result == nil {
			t.Fatal("healthy ordinary-first evidence returned no semantic result")
		}
		if resolution.result.Outcome() != OutcomeSuccess ||
			resolution.result.ForceProvenance() != ForceProvenanceNone ||
			request.Mode() != RecoveryModeNormalV3 || resolution.selected < 0 || len(resolved) == 0 {
			resolution.result.Close()
			t.Fatalf(
				"healthy ordinary-first evidence = %v/%v mode %v selected %d; want success/none/normal",
				resolution.result.Outcome(), resolution.result.ForceProvenance(), request.Mode(), resolution.selected,
			)
		}
		resolution.result.Close()

		damaged := append([]forceCandidateAnalysis(nil), analyses...)
		for index := range damaged {
			changed := testRecoveryRanges(analyses[index].ranges)
			changed[0].state = RecoveryRangeMissing
			damaged[index].ranges = testRecoveryMap(changed)
			damaged[index].damageStage = StageRecordAuth
			damaged[index].payloadDamageStage = StageRecordAuth
		}
		resolution, resolved, request, err = resolveD1InnerRecoveryAnalyses(structure, damaged)
		if err != nil {
			t.Fatalf("resolve anchored ordinary failure: %v", err)
		}
		if resolution.result == nil {
			t.Fatal("anchored ordinary failure returned no semantic result")
		}
		if resolution.result.Outcome() != OutcomeForcePartial ||
			resolution.result.ForceProvenance() != ForceProvenancePartial ||
			request.Mode() != RecoveryModeForce || resolution.selected < 0 || len(resolved) == 0 {
			resolution.result.Close()
			t.Fatalf(
				"anchored ordinary failure = %v/%v mode %v selected %d; want Force-partial/partial/Force",
				resolution.result.Outcome(), resolution.result.ForceProvenance(), request.Mode(), resolution.selected,
			)
		}
		resolution.result.Close()

		unanchored := append([]forceCandidateAnalysis(nil), damaged...)
		for index := range unanchored {
			changed := testRecoveryRanges(damaged[index].ranges)
			for i := range changed {
				changed[i].state = RecoveryRangeMissing
			}
			unanchored[index].ranges = testRecoveryMap(changed)
			unanchored[index].final = RecoveryFinalMissing
		}
		resolution, resolved, request, err = resolveD1InnerRecoveryAnalyses(structure, unanchored)
		if err != nil {
			t.Fatalf("resolve unanchored ordinary failure: %v", err)
		}
		if resolution.result == nil {
			t.Fatal("unanchored ordinary failure returned no semantic result")
		}
		if resolution.result.Outcome() != OutcomeAuthenticationFailed ||
			resolution.result.ForceProvenance() != ForceProvenanceNone ||
			request.Mode() != RecoveryModeNormalV3 || resolution.selected != -1 || len(resolved) == 0 {
			resolution.result.Close()
			t.Fatalf(
				"unanchored ordinary failure = %v/%v mode %v selected %d; want authentication-failed/none/normal",
				resolution.result.Outcome(), resolution.result.ForceProvenance(), request.Mode(), resolution.selected,
			)
		}
		resolution.result.Close()
	})

	t.Run("physical final-ciphertext deletion preserves bootstrap and body truth", func(t *testing.T) {
		inner := bytes.Repeat([]byte{0x7b}, d1OuterChunkSize+257)
		front, tail, body := newMatchingD1ForceTestBodyCandidates(
			t,
			0xb7,
			inner,
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		defer front.Close()
		defer tail.Close()
		geometry, err := parseD1OuterGeometry(uint64(len(body)))
		if err != nil || geometry.recordCount != 2 {
			t.Fatalf("parse deletion geometry = %#v, %v; want exactly two outer records", geometry, err)
		}
		finalRecord, err := expectedD1OuterRecord(geometry, geometry.recordCount-1)
		if err != nil || !finalRecord.final || finalRecord.ciphertextLength < 2 {
			t.Fatalf("select deletion target = %#v, %v; want non-empty final ciphertext", finalRecord, err)
		}
		physical := d1ForceCanonicalPhysicalFile(body)
		deletedAt64 := uint64(d1BootstrapLength) + finalRecord.offset +
			uint64(finalRecord.ciphertextLength/2)
		if deletedAt64 >= uint64(len(physical)) {
			t.Fatalf("deletion offset %d exceeds physical fixture size %d", deletedAt64, len(physical))
		}
		deletedAt := int(deletedAt64) //nolint:gosec // The physical fixture length bound proves this conversion.
		physical = append(physical[:deletedAt], physical[deletedAt+1:]...)
		sourceSize := int64(len(physical))
		frontWindow, err := deriveD1ForceBodyWindow(sourceSize, front.bodyLength, front.role)
		if err != nil {
			t.Fatalf("derive front deletion window: %v", err)
		}
		tailWindow, err := deriveD1ForceBodyWindow(sourceSize, tail.bodyLength, tail.role)
		if err != nil || frontWindow == tailWindow {
			t.Fatalf("deletion windows = front %#v tail %#v, %v; want distinct bounded contexts", frontWindow, tailWindow, err)
		}

		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create deletion recovery request: %v", err)
		}
		selection, terminal, err := selectD1ForceCandidateWithPreanalysis(
			context.Background(),
			bytes.NewReader(physical),
			sourceSize,
			request,
			[]*d1ForceCandidate{front, tail},
			defaultD1ForceSeams(),
			nil,
		)
		if terminal != nil {
			defer terminal.Close()
		}
		if err != nil || terminal != nil || selection.analysis == nil ||
			selection.analysis.candidate != front || selection.provenance != D1BootstrapProvenanceFront ||
			!selection.bootstrapHealthy || selection.outerHealthy {
			t.Fatalf(
				"deletion selection = %#v, terminal %#v, error %v; want healthy bootstrap pair, damaged body, and front anchor",
				selection, terminal, err,
			)
		}

		wantOuter := make([]byte, d1OuterPrefixLength+len(inner))
		copy(wantOuter, []byte("PCVOUT3\x00"))
		binary.BigEndian.PutUint64(wantOuter[8:d1OuterPrefixLength], uint64(len(inner)))
		copy(wantOuter[d1OuterPrefixLength:], inner)
		wantRanges := []RecoveryRange{
			{
				recordIndex: 0,
				start:       0,
				end:         d1OuterChunkSize,
				state:       RecoveryRangeVerified,
			},
			{
				recordIndex: 1,
				start:       d1OuterChunkSize,
				end:         uint64(len(wantOuter)),
				state:       RecoveryRangeMissing,
			},
		}
		var emittedRanges []RecoveryRange
		var emittedPlaintext []byte
		result, recoverErr := d1InnerUnavailableResult(
			context.Background(),
			bytes.NewReader(physical),
			request,
			selection,
			defaultD1ForceSeams(),
			nil,
			func(got *RecoveryResult, role D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
				if got == nil || role != D1BootstrapFront {
					return errors.New("TEST ONLY deletion fallback lost its selected physical role")
				}
				return emitter(func(recoveryRange RecoveryRange, plaintext []byte) error {
					if recoveryRange.State() != RecoveryRangeVerified {
						return errors.New("TEST ONLY deletion fallback emitted unauthenticated plaintext")
					}
					emittedRanges = append(emittedRanges, recoveryRange)
					emittedPlaintext = append(emittedPlaintext, plaintext...)
					return nil
				})
			},
		)
		if recoverErr != nil || result == nil {
			if result != nil {
				result.Close()
			}
			t.Fatalf("deletion fallback = result %#v, error %v", result, recoverErr)
		}
		defer result.Close()
		if result.Outcome() != OutcomeForcePartial || result.Stage() != StageD1Body ||
			result.ForceProvenance() != ForceProvenancePartial ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceFront ||
			result.FinalRecordState() != RecoveryFinalMissing ||
			!slices.Equal(testRecoveryRanges(result.Ranges()), wantRanges) {
			t.Fatalf(
				"deletion result = %v/%v/%v/%v final %v ranges %#v; want Force-partial/d1-body/partial/front and exact missing final range",
				result.Outcome(), result.Stage(), result.ForceProvenance(), result.D1BootstrapProvenance(),
				result.FinalRecordState(), testRecoveryRanges(result.Ranges()),
			)
		}
		if !slices.Equal(emittedRanges, wantRanges[:1]) ||
			!bytes.Equal(emittedPlaintext, wantOuter[:d1OuterChunkSize]) {
			t.Fatalf(
				"deletion emission = ranges %#v, plaintext %d bytes; want only the exact verified prefix",
				emittedRanges, len(emittedPlaintext),
			)
		}
	})

	t.Run("late outer authentication damage falls back without operational laundering", func(t *testing.T) {
		inner := bytes.Repeat([]byte("TEST ONLY late D1 authentication boundary; "), 30_000)
		front, tail, body := newMatchingD1ForceTestBodyCandidates(
			t,
			0xd5,
			inner,
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		defer front.Close()
		defer tail.Close()
		geometry, err := parseD1OuterGeometry(uint64(len(body)))
		if err != nil || geometry.recordCount < 2 {
			t.Fatalf("parse late-damage outer geometry = %#v, %v; want at least two records", geometry, err)
		}
		damagedRecord, err := expectedD1OuterRecord(geometry, 1)
		if err != nil || damagedRecord.ciphertextLength == 0 {
			t.Fatalf("select late damaged record = %#v, %v", damagedRecord, err)
		}
		body[damagedRecord.offset+uint64(damagedRecord.ciphertextLength)] ^= 0x01
		physical := d1ForceCanonicalPhysicalFile(body)
		window, err := deriveD1ForceBodyWindow(int64(len(physical)), front.bodyLength, front.role)
		if err != nil {
			t.Fatalf("derive late-damage body window: %v", err)
		}
		analysis, err := analyzeD1ForceCandidate(
			context.Background(), bytes.NewReader(physical), window, front, defaultD1ForceSeams(),
		)
		if err != nil || !analysis.outerAnchored || analysis.outerFullyAuthenticated {
			t.Fatalf("analyze late-damage body = %#v, %v; want anchored partial body", analysis, err)
		}
		selection := d1ForceSelection{
			analysis:         analysis,
			provenance:       D1BootstrapProvenanceMatching,
			bootstrapHealthy: true,
			outerHealthy:     false,
		}
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create late-damage request: %v", err)
		}
		reader, err := openD1SelectedInner(
			context.Background(), bytes.NewReader(physical), int64(len(physical)), request, selection, defaultD1ForceSeams(),
		)
		if err != nil {
			t.Fatalf("open authenticated outer prefix: %v", err)
		}
		probe := bytes.Repeat([]byte{0xa5}, 64)
		_, cause := reader.ReadAt(probe, int64(d1OuterChunkSize-d1OuterPrefixLength))
		reader.Close()
		if cause == nil || !allZero(probe) {
			t.Fatalf("late damaged read = error %v, zeroed %v; want fail-closed authentication cause", cause, allZero(probe))
		}

		outerPlaintext := make([]byte, d1OuterPrefixLength+len(inner))
		copy(outerPlaintext, []byte("PCVOUT3\x00"))
		binary.BigEndian.PutUint64(outerPlaintext[8:d1OuterPrefixLength], uint64(len(inner)))
		copy(outerPlaintext[d1OuterPrefixLength:], inner)
		emittedRanges := make([]RecoveryRange, 0)
		result, recoverErr := d1InnerUnavailableResult(
			context.Background(),
			bytes.NewReader(physical),
			request,
			selection,
			defaultD1ForceSeams(),
			cause,
			func(got *RecoveryResult, role D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
				if role != D1BootstrapFront || got == nil {
					return errors.New("TEST ONLY late fallback lost its physical role or semantic result")
				}
				return emitter(func(recoveryRange RecoveryRange, plaintext []byte) error {
					if recoveryRange.State() != RecoveryRangeVerified ||
						!bytes.Equal(plaintext, outerPlaintext[recoveryRange.Start():recoveryRange.End()]) {
						return errors.New("TEST ONLY late fallback emitted unauthenticated or noncanonical bytes")
					}
					emittedRanges = append(emittedRanges, recoveryRange)
					return nil
				})
			},
		)
		if recoverErr != nil || result == nil {
			if result != nil {
				result.Close()
			}
			t.Fatalf("late authentication fallback = result %#v, error %v", result, recoverErr)
		}
		if result.Outcome() != OutcomeForcePartial || result.Stage() != StageD1Body ||
			result.ForceProvenance() != ForceProvenancePartial ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceMatching || len(emittedRanges) == 0 {
			gotOutcome := result.Outcome()
			gotStage := result.Stage()
			gotForce := result.ForceProvenance()
			gotD1 := result.D1BootstrapProvenance()
			result.Close()
			t.Fatalf(
				"late authentication fallback = %v/%v/%v/%v emitted %d; want Force-partial/d1-body/partial/matching with authenticated prefix",
				gotOutcome, gotStage, gotForce, gotD1, len(emittedRanges),
			)
		}
		for _, recoveryRange := range testRecoveryRanges(result.Ranges()) {
			if recoveryRange.State() == RecoveryRangeMissing && slices.Contains(emittedRanges, recoveryRange) {
				result.Close()
				t.Fatal("late authentication fallback emitted a missing range")
			}
		}
		result.Close()

		assertFallbackOperation := func(
			t *testing.T,
			ctx context.Context,
			source io.ReaderAt,
			wantStage Stage,
		) {
			t.Helper()
			outputCalls := 0
			result, recoverErr := d1InnerUnavailableResult(
				ctx, source, request, selection, defaultD1ForceSeams(), cause,
				func(*RecoveryResult, D1BootstrapRole, string, RecoveryOutputPlan, RecoveryEmitter) error {
					outputCalls++
					return nil
				},
			)
			var engineErr *recoveryEngineError
			if result == nil || result.Outcome() != OutcomeOperationFailed || result.Stage() != wantStage ||
				!errors.As(recoverErr, &engineErr) || engineErr.stage != wantStage || outputCalls != 0 {
				if result != nil {
					result.Close()
				}
				t.Fatalf(
					"fallback operational boundary = result %#v error %T/%v output %d; want operation-failed/%v and no output",
					result, recoverErr, recoverErr, outputCalls, wantStage,
				)
			}
			result.Close()
		}

		t.Run("internal reader invariant fails closed without fallback", func(t *testing.T) {
			source := &d1ForceObservedReader{bytes: physical}
			outputCalls := 0
			result, recoverErr := d1InnerUnavailableResult(
				context.Background(), source, request, selection, defaultD1ForceSeams(),
				newD1OuterFailure(StageD1Body, errD1ReaderProgress),
				func(*RecoveryResult, D1BootstrapRole, string, RecoveryOutputPlan, RecoveryEmitter) error {
					outputCalls++
					return nil
				},
			)
			var engineErr *recoveryEngineError
			if result == nil || result.Outcome() != OutcomeOperationFailed ||
				result.Stage() != StageCredentialPolicy ||
				!errors.As(recoverErr, &engineErr) || engineErr.stage != StageCredentialPolicy ||
				len(source.requests) != 0 || outputCalls != 0 {
				if result != nil {
					result.Close()
				}
				t.Fatalf(
					"internal reader invariant = result %#v error %T/%v reads %d output %d; want operation-failed/credential-policy and no fallback activity",
					result, recoverErr, recoverErr, len(source.requests), outputCalls,
				)
			}
			result.Close()
		})

		t.Run("non-EOF input failure during re-analysis remains operational", func(t *testing.T) {
			fault := &d1ForceFaultReader{bytes: physical, fault: d1ForceSourceNonEOF}
			assertFallbackOperation(t, context.Background(), fault, StageInputIO)
			if len(fault.requests) == 0 {
				t.Fatal("non-EOF fault was not injected through fallback re-analysis")
			}
		})

		t.Run("prior cancellation precedes authentication fallback", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			source := &d1ForceObservedReader{bytes: physical}
			assertFallbackOperation(t, ctx, source, StageCancellation)
			if len(source.requests) != 0 {
				t.Fatalf("prior cancellation performed %d fallback reads; want none", len(source.requests))
			}
		})

		t.Run("cancellation during re-analysis remains operational", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			fault := &d1ForceFaultReader{
				bytes:  physical,
				fault:  d1ForceSourceCancellation,
				cancel: cancel,
			}
			assertFallbackOperation(t, ctx, fault, StageCancellation)
			if len(fault.requests) == 0 {
				t.Fatal("cancellation was not injected through fallback re-analysis")
			}
		})
	})
}

func TestD1ForceNestedOutcomeRegistryIsClosedOwnedAndRedacted(t *testing.T) {
	innerFailure, err := newD1RecoveryResult(
		OutcomeAuthenticationFailed,
		ForceProvenanceNone,
		StageInnerVolume,
		D1BootstrapProvenanceMatching,
		StageRecordAuth,
		0,
		nil,
		0,
	)
	if err != nil {
		t.Fatalf("construct nested inner failure: %v", err)
	}
	if innerFailure.DetailStage() != StageRecordAuth ||
		innerFailure.D1BootstrapProvenance() != D1BootstrapProvenanceMatching {
		innerFailure.Close()
		t.Fatal("nested result lost its closed inner stage or physical provenance")
	}
	for _, rendered := range []string{
		innerFailure.Error(),
		innerFailure.String(),
		innerFailure.GoString(),
		fmt.Sprintf("%v", innerFailure),
		fmt.Sprintf("%+v", innerFailure),
		fmt.Sprintf("%#v", innerFailure),
		fmt.Sprintf("%d", innerFailure),
	} {
		for _, forbidden := range []string{"record-auth", "matching", "OuterKey", "PCVOUT3", "candidate"} {
			if strings.Contains(rendered, forbidden) {
				innerFailure.Close()
				t.Fatalf("D1 recovery formatting exposed %q in %q", forbidden, rendered)
			}
		}
	}
	innerFailure.Close()
	if innerFailure.DetailStage() != StageNone ||
		innerFailure.D1BootstrapProvenance() != D1BootstrapProvenanceNone {
		t.Fatal("Close retained nested D1 semantic dimensions")
	}

	invalid := []struct {
		name   string
		stage  Stage
		detail Stage
	}{
		{name: "recursive D1 detail", stage: StageD1Body, detail: StageD1Bootstrap},
		{name: "missing inner detail", stage: StageInnerVolume, detail: StageNone},
		{name: "D1 detail under inner", stage: StageInnerVolume, detail: StageD1Bootstrap},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			result, err := newD1RecoveryResult(
				OutcomeAuthenticationFailed,
				ForceProvenanceNone,
				test.stage,
				D1BootstrapProvenanceFront,
				test.detail,
				0,
				nil,
				0,
			)
			if err == nil || result != nil {
				if result != nil {
					result.Close()
				}
				t.Fatal("invalid nested D1 dimensions minted a semantic result")
			}
		})
	}
}

type d1ForceTestBootstrapEvidence struct {
	wrapVerified    bool
	replicaVerified bool
}

type d1ForceObservedReader struct {
	bytes    []byte
	requests []d1ForceReadRequest
}

type d1ForceReadRequest struct {
	offset int64
	length int
}

func (reader *d1ForceObservedReader) ReadAt(destination []byte, offset int64) (int, error) {
	reader.requests = append(reader.requests, d1ForceReadRequest{offset: offset, length: len(destination)})
	return bytes.NewReader(reader.bytes).ReadAt(destination, offset)
}

type d1ForceSourceFault uint8

var errD1ForceTestFullReadNonEOF = errors.New("TEST ONLY full-read non-EOF D1 source failure")

const (
	d1ForceSourceNonEOF d1ForceSourceFault = iota + 1
	d1ForceSourceShortRead
	d1ForceSourceFullReadNonEOF
	d1ForceSourceCancellation
)

func (fault d1ForceSourceFault) String() string {
	switch fault {
	case d1ForceSourceShortRead:
		return "short source read"
	case d1ForceSourceFullReadNonEOF:
		return "full source read with non-EOF error"
	case d1ForceSourceCancellation:
		return "source cancellation"
	default:
		return "non-EOF source error"
	}
}

type d1ForceFaultReader struct {
	bytes    []byte
	fault    d1ForceSourceFault
	cancel   context.CancelFunc
	requests []d1ForceReadRequest
}

func (reader *d1ForceFaultReader) ReadAt(destination []byte, offset int64) (int, error) {
	reader.requests = append(reader.requests, d1ForceReadRequest{offset: offset, length: len(destination)})
	switch reader.fault {
	case d1ForceSourceNonEOF:
		return 0, errors.New("TEST ONLY non-EOF D1 source failure")
	case d1ForceSourceShortRead:
		if len(destination) == 0 {
			return 0, nil
		}
		count := len(destination) / 2
		if count == 0 {
			count = 1
		}
		read, _ := bytes.NewReader(reader.bytes).ReadAt(destination[:count], offset)
		return read, io.ErrUnexpectedEOF
	case d1ForceSourceFullReadNonEOF:
		read, err := bytes.NewReader(reader.bytes).ReadAt(destination, offset)
		if read != len(destination) {
			return read, err
		}
		return read, errD1ForceTestFullReadNonEOF
	case d1ForceSourceCancellation:
		if reader.cancel == nil {
			return 0, errors.New("TEST ONLY D1 cancellation source omitted its cancel function")
		}
		reader.cancel()
		return bytes.NewReader(reader.bytes).ReadAt(destination, offset)
	default:
		return bytes.NewReader(reader.bytes).ReadAt(destination, offset)
	}
}

func newD1ForceTestBodyCandidate(
	t *testing.T,
	role D1BootstrapRole,
	keyFill byte,
	inner []byte,
	evidence d1ForceTestBootstrapEvidence,
) (*d1ForceCandidate, []byte) {
	t.Helper()
	access, keyOwner := newD1TestOuterAccess(t, keyFill)
	body := encodeD1TestBody(t, access, inner)
	bootstrap := d1ForceTestBootstrap(role, keyFill)
	return &d1ForceCandidate{
		role:            role,
		bootstrap:       bootstrap,
		bootstrapKnown:  true,
		bodyLength:      uint64(len(body)),
		secret:          &d1OuterSecretOwner{bodyLength: uint64(len(body)), keys: keyOwner},
		wrapVerified:    evidence.wrapVerified,
		replicaVerified: evidence.replicaVerified,
	}, append([]byte(nil), body...)
}

func newD1ForceTestCandidate(
	t *testing.T,
	role D1BootstrapRole,
	keyFill byte,
	bodyLength uint64,
	evidence d1ForceTestBootstrapEvidence,
) *d1ForceCandidate {
	t.Helper()
	_, keyOwner := newD1TestOuterAccess(t, keyFill)
	bootstrap := d1ForceTestBootstrap(role, keyFill)
	return &d1ForceCandidate{
		role:            role,
		bootstrap:       bootstrap,
		bootstrapKnown:  true,
		bodyLength:      bodyLength,
		secret:          &d1OuterSecretOwner{bodyLength: bodyLength, keys: keyOwner},
		wrapVerified:    evidence.wrapVerified,
		replicaVerified: evidence.replicaVerified,
	}
}

func d1ForceTestBootstrap(role D1BootstrapRole, keyFill byte) d1BootstrapCandidate {
	roleFill := keyFill
	if role == D1BootstrapTail {
		roleFill ^= 0xff
	}
	bootstrap := d1BootstrapCandidate{role: role}
	for index := range bootstrap.argonSalt {
		bootstrap.argonSalt[index] = roleFill
	}
	for index := range bootstrap.wrapNonce {
		bootstrap.wrapNonce[index] = roleFill ^ 0x55
	}
	for index := range bootstrap.wrapSerpentIV {
		bootstrap.wrapSerpentIV[index] = roleFill ^ 0xaa
	}
	return bootstrap
}

func newMatchingD1ForceTestBodyCandidates(
	t *testing.T,
	keyFill byte,
	inner []byte,
	evidence d1ForceTestBootstrapEvidence,
) (*d1ForceCandidate, *d1ForceCandidate, []byte) {
	t.Helper()
	front, body := newD1ForceTestBodyCandidate(
		t,
		D1BootstrapFront,
		keyFill,
		inner,
		evidence,
	)
	tail := newD1ForceTestCandidate(
		t,
		D1BootstrapTail,
		keyFill,
		uint64(len(body)),
		evidence,
	)
	return front, tail, body
}

func d1ForceCanonicalPhysicalFile(body []byte) []byte {
	physical := make([]byte, 0, 2*d1BootstrapLength+len(body))
	physical = append(physical, make([]byte, d1BootstrapLength)...)
	physical = append(physical, body...)
	physical = append(physical, make([]byte, d1BootstrapLength)...)
	return physical
}

func corruptEveryD1ForceTestTag(t *testing.T, body []byte) {
	t.Helper()
	geometry, err := parseD1OuterGeometry(uint64(len(body)))
	if err != nil {
		t.Fatalf("parse D1 Force test geometry: %v", err)
	}
	for index := range geometry.recordCount {
		expected, err := expectedD1OuterRecord(geometry, index)
		if err != nil {
			t.Fatalf("expected D1 Force test record %d: %v", index, err)
		}
		tagOffset := expected.offset + uint64(expected.ciphertextLength)
		body[tagOffset] ^= byte(index + 1)
	}
}

var _ io.ReaderAt = (*d1ForceObservedReader)(nil)
