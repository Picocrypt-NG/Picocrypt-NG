package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
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

func TestD1ForceCandidatesClassifyEveryPhysicalWindowBeforeInnerKDF(t *testing.T) {
	inner := bytes.Repeat([]byte("TEST ONLY multi-record D1 candidate; "), 70_000)
	frontBody := encodeD1ForceTestBody(t, 0x32, inner)
	front := newD1ForceTestCandidate(
		t,
		D1BootstrapFront,
		0x31,
		uint64(len(frontBody)),
		d1ForceTestBootstrapEvidence{replicaVerified: true},
	)
	tail, tailBody := newD1ForceTestBodyCandidate(
		t,
		D1BootstrapTail,
		0x71,
		inner,
		d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
	)
	physical := d1ForceSplitPhysicalFile(frontBody, []byte("TEST ONLY insertion gap"), tailBody)
	source := &d1ForceObservedReader{bytes: physical}
	frontSecret, tailSecret := front.secret, tail.secret
	frontExpected := expectedD1ForceCandidate(front, false)
	tailExpected := expectedD1ForceCandidate(tail, true)

	seams := defaultD1ForceSeams()
	realAuthenticate := seams.authenticateRecord
	var events []d1ForceAuthEvent
	seams.authenticateRecord = func(
		candidate *d1ForceCandidate,
		codec *d1OuterCodec,
		ctx context.Context,
		index uint64,
		final bool,
		ciphertext, tag []byte,
	) error {
		err := realAuthenticate(candidate, codec, ctx, index, final, ciphertext, tag)
		events = append(events, d1ForceAuthEvent{
			role: candidate.role, index: index, final: final, authenticated: err == nil,
		})
		return err
	}
	decryptCalls := observeD1ForceDecrypts(&seams)

	request, err := newD1RecoveryRequest(RecoveryModeForce)
	if err != nil {
		t.Fatalf("create D1 Force request: %v", err)
	}
	innerCalls := 0
	result, err := resolveD1ForceCandidatesWithSeams(
		context.Background(),
		source,
		int64(len(physical)),
		request,
		[]*d1ForceCandidate{front, tail},
		seams,
		func(selected *d1ForceCandidateAnalysis) (*RecoveryResult, error) {
			innerCalls++
			assertExactD1ForceAuthEvents(t, events, frontExpected, tailExpected)
			assertExactD1ForcePhysicalReads(
				t,
				source.requests,
				int64(len(physical)),
				frontExpected,
				tailExpected,
			)
			if selected == nil || selected.candidate.role != D1BootstrapTail ||
				!selected.outerAnchored {
				t.Fatal("resolver did not select the only outer-tag-anchored identity")
			}
			return newRecoveryResult(
				OutcomeSuccess,
				ForceProvenanceNone,
				StageNone,
				0,
				nil,
				0,
			)
		},
	)
	if err != nil {
		t.Fatalf("resolve D1 Force candidates: %v", err)
	}
	defer result.Close()
	if innerCalls != 1 || *decryptCalls != 0 ||
		result.Outcome() != OutcomeAuthenticatedDegraded ||
		result.Stage() != StageD1Bootstrap || result.DetailStage() != StageNone ||
		result.D1BootstrapProvenance() != D1BootstrapProvenanceTail {
		t.Fatalf(
			"degraded bootstrap = inner %d, decrypt %d, %v/%v detail %v, provenance %v; want one post-classification inner success mapped to authenticated-degraded/d1-bootstrap/tail",
			innerCalls,
			*decryptCalls,
			result.Outcome(),
			result.Stage(),
			result.DetailStage(),
			result.D1BootstrapProvenance(),
		)
	}
	assertD1ForceCandidateClosed(t, front, frontSecret)
	assertD1ForceCandidateClosed(t, tail, tailSecret)
}

func TestD1ForceCandidatesCloseOwnersOnErrorAndCancellation(t *testing.T) {
	t.Run("inner error", func(t *testing.T) {
		candidate, body := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapFront,
			0x42,
			[]byte("TEST ONLY inner error"),
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		secret := candidate.secret
		physical := d1ForceCanonicalPhysicalFile(body)
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		innerErr := errors.New("TEST ONLY inner callback failure")
		result, err := resolveD1ForceCandidates(
			context.Background(),
			bytes.NewReader(physical),
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{candidate},
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				return nil, innerErr
			},
		)
		if result != nil {
			result.Close()
			t.Fatal("inner callback error returned a semantic result")
		}
		if !errors.Is(err, innerErr) {
			t.Fatalf("inner callback error = %v; want preserved sentinel", err)
		}
		assertD1ForceCandidateClosed(t, candidate, secret)
	})

	t.Run("mid-pass cancellation", func(t *testing.T) {
		front, body := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapFront,
			0x43,
			bytes.Repeat([]byte{0x43}, 2*d1OuterChunkSize),
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		tail := newD1ForceTestCandidate(
			t,
			D1BootstrapTail,
			0x43,
			uint64(len(body)),
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceCanonicalPhysicalFile(body)
		ctx, cancel := context.WithCancel(context.Background())
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		seams := defaultD1ForceSeams()
		realAuthenticate := seams.authenticateRecord
		authCalls := 0
		seams.authenticateRecord = func(
			candidate *d1ForceCandidate,
			codec *d1OuterCodec,
			ctx context.Context,
			index uint64,
			final bool,
			ciphertext, tag []byte,
		) error {
			authCalls++
			err := realAuthenticate(candidate, codec, ctx, index, final, ciphertext, tag)
			if authCalls == 1 {
				cancel()
			}
			return err
		}
		decryptCalls := observeD1ForceDecrypts(&seams)
		innerCalls := 0
		result, err := resolveD1ForceCandidatesWithSeams(
			ctx,
			bytes.NewReader(physical),
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{front, tail},
			seams,
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				innerCalls++
				return nil, nil
			},
		)
		if result != nil {
			result.Close()
		}
		if err == nil || authCalls != 1 || innerCalls != 0 || *decryptCalls != 0 {
			t.Fatalf(
				"mid-pass cancellation = result %#v, error %v, auth %d, inner %d, decrypt %d; want fail closed",
				result,
				err,
				authCalls,
				innerCalls,
				*decryptCalls,
			)
		}
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	for _, fault := range []d1ForceSourceFault{
		d1ForceSourceNonEOF,
		d1ForceSourceShortRead,
		d1ForceSourceFullReadNonEOF,
	} {
		t.Run(fault.String(), func(t *testing.T) {
			front, tail, body := newMatchingD1ForceTestBodyCandidates(
				t,
				0x44,
				[]byte("TEST ONLY source fault"),
				d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
			)
			frontSecret, tailSecret := front.secret, tail.secret
			physical := d1ForceCanonicalPhysicalFile(body)
			request, err := newD1RecoveryRequest(RecoveryModeForce)
			if err != nil {
				t.Fatalf("create D1 Force request: %v", err)
			}
			seams := defaultD1ForceSeams()
			decryptCalls := observeD1ForceDecrypts(&seams)
			innerCalls := 0
			result, err := resolveD1ForceCandidatesWithSeams(
				context.Background(),
				&d1ForceFaultReader{bytes: physical, fault: fault},
				int64(len(physical)),
				request,
				[]*d1ForceCandidate{front, tail},
				seams,
				func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
					innerCalls++
					return nil, nil
				},
			)
			if result != nil {
				result.Close()
			}
			if result != nil || err == nil || innerCalls != 0 || *decryptCalls != 0 {
				t.Fatalf("source fault %v = result %#v, error %v, inner %d, decrypt %d", fault, result, err, innerCalls, *decryptCalls)
			}
			if fault == d1ForceSourceFullReadNonEOF {
				var failure *d1OuterFailure
				if !errors.Is(err, errD1ForceTestFullReadNonEOF) ||
					!errors.As(err, &failure) || failure.Stage() != StageInputIO {
					t.Fatalf("full-read source error = %T %v; want preserved sentinel at input-io", err, err)
				}
			}
			assertD1ForceCandidateClosed(t, front, frontSecret)
			assertD1ForceCandidateClosed(t, tail, tailSecret)
		})
	}

	t.Run("authenticate seam error", func(t *testing.T) {
		front, tail, body := newMatchingD1ForceTestBodyCandidates(
			t,
			0x45,
			[]byte("TEST ONLY auth seam"),
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceCanonicalPhysicalFile(body)
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		seams := defaultD1ForceSeams()
		authErr := errors.New("TEST ONLY authenticate seam failure")
		seams.authenticateRecord = func(
			*d1ForceCandidate,
			*d1OuterCodec,
			context.Context,
			uint64,
			bool,
			[]byte,
			[]byte,
		) error {
			return authErr
		}
		decryptCalls := observeD1ForceDecrypts(&seams)
		innerCalls := 0
		result, err := resolveD1ForceCandidatesWithSeams(
			context.Background(),
			bytes.NewReader(physical),
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{front, tail},
			seams,
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				innerCalls++
				return nil, nil
			},
		)
		if result != nil {
			result.Close()
		}
		if !errors.Is(err, authErr) || innerCalls != 0 || *decryptCalls != 0 {
			t.Fatalf("auth seam failure = result %#v, error %v, inner %d, decrypt %d", result, err, innerCalls, *decryptCalls)
		}
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})
}

func TestD1ForceAnchorsRejectFalseAnchorsAndFirstCandidateChoice(t *testing.T) {
	t.Run("two unanchored identities refuse first slot and readable signatures", func(t *testing.T) {
		rawInner := []byte("PCV\x00TEST ONLY plausible normal bytes PK\x03\x04 archive signature")
		front, frontBody := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapFront,
			0x51,
			rawInner,
			d1ForceTestBootstrapEvidence{replicaVerified: true},
		)
		tail, tailBody := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapTail,
			0x91,
			rawInner,
			d1ForceTestBootstrapEvidence{replicaVerified: true},
		)
		corruptEveryD1ForceTestTag(t, frontBody)
		corruptEveryD1ForceTestTag(t, tailBody)
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceSplitPhysicalFile(frontBody, nil, tailBody)

		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		seams := defaultD1ForceSeams()
		decryptCalls := observeD1ForceDecrypts(&seams)
		innerCalls := 0
		result, err := resolveD1ForceCandidatesWithSeams(
			context.Background(),
			bytes.NewReader(physical),
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{front, tail},
			seams,
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				innerCalls++
				return nil, nil
			},
		)
		if err != nil {
			t.Fatalf("resolve false anchors: %v", err)
		}
		defer result.Close()
		if innerCalls != 0 || *decryptCalls != 0 || result.Outcome() != OutcomeCredentialsOrDamage ||
			result.Stage() != StageD1Bootstrap || result.DetailStage() != StageNone ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceNone || result.Ranges() != nil {
			t.Fatalf(
				"false-anchor result = inner %d, decrypt %d, %v/%v detail %v provenance %v, ranges %#v; want pre-inner credentials-or-damage/d1-bootstrap/none",
				innerCalls,
				*decryptCalls,
				result.Outcome(),
				result.Stage(),
				result.DetailStage(),
				result.D1BootstrapProvenance(),
				result.Ranges(),
			)
		}
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	t.Run("fully verified bootstrap splice is terminal before body reads", func(t *testing.T) {
		verified := d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true}
		front, frontBody := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapFront,
			0x61,
			bytes.Repeat([]byte{0x31}, 97),
			verified,
		)
		tail, tailBody := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapTail,
			0xa1,
			bytes.Repeat([]byte{0x71}, 97),
			verified,
		)
		if front.bodyLength != tail.bodyLength {
			t.Fatal("bootstrap-splice fixture produced unequal D1 body lengths")
		}
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceSplitPhysicalFile(frontBody, []byte("TEST ONLY inserted damage"), tailBody)
		source := &d1ForceObservedReader{bytes: physical}
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		seams := defaultD1ForceSeams()
		decryptCalls := observeD1ForceDecrypts(&seams)
		innerCalls := 0
		result, err := resolveD1ForceCandidatesWithSeams(
			context.Background(),
			source,
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{front, tail},
			seams,
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				innerCalls++
				return nil, errors.New("TEST ONLY bootstrap splice must not reach inner recovery")
			},
		)
		if err != nil {
			t.Fatalf("resolve bootstrap splice: %v", err)
		}
		defer result.Close()
		if len(source.requests) != 0 || innerCalls != 0 || *decryptCalls != 0 ||
			result.Outcome() != OutcomeAmbiguousVolume || result.Stage() != StageD1Bootstrap ||
			result.DetailStage() != StageNone ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceNone || result.Ranges() != nil {
			t.Fatalf(
				"bootstrap splice = reads %v, inner %d, decrypt %d, %v/%v detail %v provenance %v, ranges %#v; want pre-body ambiguous-volume/d1-bootstrap/none",
				source.requests,
				innerCalls,
				*decryptCalls,
				result.Outcome(),
				result.Stage(),
				result.DetailStage(),
				result.D1BootstrapProvenance(),
				result.Ranges(),
			)
		}
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	t.Run("distinct replica-only body anchors are terminal", func(t *testing.T) {
		replicaOnly := d1ForceTestBootstrapEvidence{replicaVerified: true}
		front, frontBody := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapFront,
			0x67,
			[]byte("TEST ONLY short inner"),
			replicaOnly,
		)
		tail, tailBody := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapTail,
			0x67,
			bytes.Repeat([]byte{0x75}, d1OuterChunkSize+31),
			replicaOnly,
		)
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceSplitPhysicalFile(frontBody, nil, tailBody)
		assertD1ForceBodyAnchoredAmbiguity(t, physical, front, tail)
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	t.Run("identical identity dedupes with matching provenance", func(t *testing.T) {
		front, tail, body := newMatchingD1ForceTestBodyCandidates(
			t,
			0x71,
			[]byte("TEST ONLY matching identity"),
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceCanonicalPhysicalFile(body)
		source := &d1ForceObservedReader{bytes: physical}
		frontExpected := expectedD1ForceCandidate(front, true)
		tailExpected := expectedD1ForceCandidate(tail, true)
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		seams := defaultD1ForceSeams()
		realAuthenticate := seams.authenticateRecord
		var events []d1ForceAuthEvent
		seams.authenticateRecord = func(
			candidate *d1ForceCandidate,
			codec *d1OuterCodec,
			ctx context.Context,
			index uint64,
			final bool,
			ciphertext, tag []byte,
		) error {
			err := realAuthenticate(candidate, codec, ctx, index, final, ciphertext, tag)
			events = append(events, d1ForceAuthEvent{
				role: candidate.role, index: index, final: final, authenticated: err == nil,
			})
			return err
		}
		innerCalls := 0
		result, err := resolveD1ForceCandidatesWithSeams(
			context.Background(),
			source,
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{front, tail},
			seams,
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				innerCalls++
				assertExactD1ForceAuthEvents(
					t,
					events,
					frontExpected,
					tailExpected,
				)
				assertExactD1ForcePhysicalReads(
					t,
					source.requests,
					int64(len(physical)),
					frontExpected,
					tailExpected,
				)
				return newRecoveryResult(OutcomeSuccess, ForceProvenanceNone, StageNone, 0, nil, 0)
			},
		)
		if err != nil {
			t.Fatalf("resolve matching identity: %v", err)
		}
		defer result.Close()
		if innerCalls != 1 || result.Outcome() != OutcomeSuccess || result.Stage() != StageNone ||
			result.DetailStage() != StageNone ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceMatching {
			t.Fatalf(
				"matching identity = calls %d, %v/%v detail %v provenance %v; want success/none/matching",
				innerCalls,
				result.Outcome(),
				result.Stage(),
				result.DetailStage(),
				result.D1BootstrapProvenance(),
			)
		}
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	t.Run("matching replica identity without a body tag is not an anchor", func(t *testing.T) {
		front, tail, body := newMatchingD1ForceTestBodyCandidates(
			t,
			0x77,
			[]byte("TEST ONLY matching but unanchored"),
			d1ForceTestBootstrapEvidence{replicaVerified: true},
		)
		corruptEveryD1ForceTestTag(t, body)
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceCanonicalPhysicalFile(body)
		source := &d1ForceObservedReader{bytes: physical}
		frontExpected := expectedD1ForceCandidate(front, false)
		tailExpected := expectedD1ForceCandidate(tail, false)
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		seams := defaultD1ForceSeams()
		realAuthenticate := seams.authenticateRecord
		var events []d1ForceAuthEvent
		seams.authenticateRecord = func(
			candidate *d1ForceCandidate,
			codec *d1OuterCodec,
			ctx context.Context,
			index uint64,
			final bool,
			ciphertext, tag []byte,
		) error {
			err := realAuthenticate(candidate, codec, ctx, index, final, ciphertext, tag)
			events = append(events, d1ForceAuthEvent{
				role: candidate.role, index: index, final: final, authenticated: err == nil,
			})
			return err
		}
		decryptCalls := observeD1ForceDecrypts(&seams)
		innerCalls := 0
		result, err := resolveD1ForceCandidatesWithSeams(
			context.Background(),
			source,
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{front, tail},
			seams,
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				innerCalls++
				return nil, nil
			},
		)
		if err != nil {
			t.Fatalf("resolve matching unanchored identities: %v", err)
		}
		defer result.Close()
		assertExactD1ForceAuthEvents(t, events, frontExpected, tailExpected)
		assertExactD1ForcePhysicalReads(
			t,
			source.requests,
			int64(len(physical)),
			frontExpected,
			tailExpected,
		)
		if innerCalls != 0 || *decryptCalls != 0 ||
			result.Outcome() != OutcomeCredentialsOrDamage || result.Stage() != StageD1Bootstrap ||
			result.DetailStage() != StageNone ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceNone {
			t.Fatalf(
				"matching unanchored = inner %d, decrypt %d, %v/%v detail %v provenance %v; want credentials-or-damage/d1-bootstrap/none",
				innerCalls,
				*decryptCalls,
				result.Outcome(),
				result.Stage(),
				result.DetailStage(),
				result.D1BootstrapProvenance(),
			)
		}
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	t.Run("live tail role authority selects degraded replica-only identity", func(t *testing.T) {
		replicaOnly := d1ForceTestBootstrapEvidence{replicaVerified: true}
		front, frontBody := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapFront,
			0x81,
			[]byte("TEST ONLY front"),
			replicaOnly,
		)
		tail, tailBody := newD1ForceTestBodyCandidate(
			t,
			D1BootstrapTail,
			0xb1,
			[]byte("TEST ONLY tail"),
			replicaOnly,
		)
		corruptEveryD1ForceTestTag(t, frontBody)
		corruptEveryD1ForceTestTag(t, tailBody)
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceSplitPhysicalFile(frontBody, nil, tailBody)
		source := &d1ForceObservedReader{bytes: physical}
		frontExpected := expectedD1ForceCandidate(front, false)
		tailExpected := expectedD1ForceCandidate(tail, false)
		seams := defaultD1ForceSeams()
		realAuthenticate := seams.authenticateRecord
		var events []d1ForceAuthEvent
		seams.authenticateRecord = func(
			candidate *d1ForceCandidate,
			codec *d1OuterCodec,
			ctx context.Context,
			index uint64,
			final bool,
			ciphertext, tag []byte,
		) error {
			err := realAuthenticate(candidate, codec, ctx, index, final, ciphertext, tag)
			events = append(events, d1ForceAuthEvent{
				role: candidate.role, index: index, final: final, authenticated: err == nil,
			})
			return err
		}
		decryptCalls := observeD1ForceDecrypts(&seams)
		var retained d1RecoveryRequest
		var result *RecoveryResult
		var resultErr error
		innerCalls := 0
		err := withUnverifiedD1RecoveryRequest(D1BootstrapTail, func(request d1RecoveryRequest) error {
			retained = request
			result, resultErr = resolveD1ForceCandidatesWithSeams(
				context.Background(),
				source,
				int64(len(physical)),
				request,
				[]*d1ForceCandidate{front, tail},
				seams,
				func(selected *d1ForceCandidateAnalysis) (*RecoveryResult, error) {
					innerCalls++
					assertExactD1ForceAuthEvents(t, events, frontExpected, tailExpected)
					assertExactD1ForcePhysicalReads(
						t,
						source.requests,
						int64(len(physical)),
						frontExpected,
						tailExpected,
					)
					if selected == nil || selected.candidate.role != D1BootstrapTail ||
						selected.outerAnchored {
						t.Fatal("live Tail authority did not select exactly the unanchored physical tail")
					}
					return newRecoveryResult(
						OutcomeSuccess,
						ForceProvenanceNone,
						StageNone,
						0,
						nil,
						0,
					)
				},
			)
			return resultErr
		})
		if err != nil {
			t.Fatalf("resolve tail role authority: %v", err)
		}
		defer result.Close()
		if innerCalls != 1 || *decryptCalls != 0 ||
			result.Outcome() != OutcomeAuthenticatedDegraded || result.Stage() != StageD1Bootstrap ||
			result.DetailStage() != StageNone ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceTail || result.Ranges() != nil {
			t.Fatalf(
				"tail role authority = inner %d, decrypt %d, %v/%v detail %v provenance %v, ranges %#v; want one inner success mapped to authenticated-degraded/d1-bootstrap/tail",
				innerCalls,
				*decryptCalls,
				result.Outcome(),
				result.Stage(),
				result.DetailStage(),
				result.D1BootstrapProvenance(),
				result.Ranges(),
			)
		}
		if retained.valid() || retained.authorizesRawOuter(D1BootstrapTail) {
			t.Fatal("captured D1 physical-role authority survived its callback")
		}
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	t.Run("invalid physical role cannot mint authority", func(t *testing.T) {
		called := false
		if err := withUnverifiedD1RecoveryRequest(D1BootstrapRole(0xff), func(d1RecoveryRequest) error {
			called = true
			return nil
		}); err == nil || called {
			t.Fatalf("invalid D1 role = called %v, error %v; want rejection before callback", called, err)
		}
	})
}

func TestD1ForceAnchorsRawOpenRequiresLiveExactPhysicalRole(t *testing.T) {
	rawInner := []byte("PCV\x00TEST ONLY raw inner PK\x03\x04")
	candidate, body := newD1ForceTestBodyCandidate(
		t,
		D1BootstrapFront,
		0xc1,
		rawInner,
		d1ForceTestBootstrapEvidence{replicaVerified: true},
	)
	defer candidate.Close()
	geometry, err := parseD1OuterGeometry(candidate.bodyLength)
	if err != nil {
		t.Fatalf("parse raw-open geometry: %v", err)
	}
	expected, err := expectedD1OuterRecord(geometry, 0)
	if err != nil {
		t.Fatalf("expected raw-open record: %v", err)
	}
	corruptEveryD1ForceTestTag(t, body)
	physical := d1ForceCanonicalPhysicalFile(body)

	seams := defaultD1ForceSeams()
	realDecrypt := seams.decryptRecord
	decryptCalls := 0
	seams.decryptRecord = func(
		candidate *d1ForceCandidate,
		codec *d1OuterCodec,
		ctx context.Context,
		index uint64,
		final bool,
		ciphertext, plaintext []byte,
	) error {
		decryptCalls++
		return realDecrypt(candidate, codec, ctx, index, final, ciphertext, plaintext)
	}

	assertRefused := func(t *testing.T, request d1RecoveryRequest) {
		t.Helper()
		destination := bytes.Repeat([]byte{0xa5}, expected.ciphertextLength)
		err := openD1ForceRawRecordWithSeams(
			context.Background(),
			bytes.NewReader(physical),
			int64(len(physical)),
			request,
			candidate,
			0,
			destination,
			seams,
		)
		if err == nil || !bytes.Equal(destination, make([]byte, len(destination))) {
			t.Fatalf("refused raw open = error %v, zeroed %v; want fail-closed zero output", err, bytes.Equal(destination, make([]byte, len(destination))))
		}
	}

	ordinary, err := newD1RecoveryRequest(RecoveryModeForce)
	if err != nil {
		t.Fatalf("create ordinary D1 request: %v", err)
	}
	assertRefused(t, ordinary)

	if err := withUnverifiedD1RecoveryRequest(D1BootstrapTail, func(request d1RecoveryRequest) error {
		assertRefused(t, request)
		return nil
	}); err != nil {
		t.Fatalf("wrong-role D1 consent: %v", err)
	}
	if decryptCalls != 0 {
		t.Fatalf("ordinary/wrong-role requests invoked raw decrypt %d times", decryptCalls)
	}

	var retained d1RecoveryRequest
	if err := withUnverifiedD1RecoveryRequest(D1BootstrapFront, func(request d1RecoveryRequest) error {
		retained = request
		destination := make([]byte, expected.ciphertextLength)
		if err := openD1ForceRawRecordWithSeams(
			context.Background(),
			bytes.NewReader(physical),
			int64(len(physical)),
			request,
			candidate,
			0,
			destination,
			seams,
		); err != nil {
			return err
		}
		want := append([]byte("PCVOUT3\x00"), make([]byte, 8)...)
		if !bytes.Equal(destination[:8], want[:8]) || !bytes.Contains(destination, rawInner) {
			return errors.New("raw open did not delegate the canonical codec transform")
		}
		return nil
	}); err != nil {
		t.Fatalf("live exact-role raw open: %v", err)
	}
	if decryptCalls != 1 {
		t.Fatalf("live exact-role raw decrypt calls = %d; want 1", decryptCalls)
	}
	assertRefused(t, retained)
	if decryptCalls != 1 {
		t.Fatalf("expired replay invoked raw decrypt; calls=%d", decryptCalls)
	}
}

func TestD1ForceNestedOutcomePreservesOuterInnerAndRangeTruth(t *testing.T) {
	t.Run("damaged outer plus authenticated inner is D1 degraded", func(t *testing.T) {
		front, tail, body := newMatchingD1ForceTestBodyCandidates(
			t,
			0xd1,
			bytes.Repeat([]byte{0x29}, d1OuterChunkSize+31),
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		frontSecret, tailSecret := front.secret, tail.secret
		geometry, err := parseD1OuterGeometry(uint64(len(body)))
		if err != nil {
			t.Fatalf("parse damaged outer geometry: %v", err)
		}
		final, err := expectedD1OuterRecord(geometry, geometry.recordCount-1)
		if err != nil {
			t.Fatalf("expected final outer record: %v", err)
		}
		body[final.offset+uint64(final.ciphertextLength)] ^= 0x01
		physical := d1ForceCanonicalPhysicalFile(body)
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		result, err := resolveD1ForceCandidates(
			context.Background(),
			bytes.NewReader(physical),
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{front, tail},
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				return newRecoveryResult(OutcomeSuccess, ForceProvenanceNone, StageNone, 0, nil, 0)
			},
		)
		if err != nil {
			t.Fatalf("resolve degraded outer: %v", err)
		}
		if result.Outcome() != OutcomeAuthenticatedDegraded || result.Stage() != StageD1Body ||
			result.DetailStage() != StageNone ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceMatching ||
			result.PlaintextLength() != 0 {
			t.Fatalf(
				"damaged outer mapping = %v/%v detail %v D1 %v length %d; want authenticated-degraded/d1-body/matching",
				result.Outcome(),
				result.Stage(),
				result.DetailStage(),
				result.D1BootstrapProvenance(),
				result.PlaintextLength(),
			)
		}
		result.Close()
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	t.Run("authenticated outer plus inner failure retains detail", func(t *testing.T) {
		front, tail, body := newMatchingD1ForceTestBodyCandidates(
			t,
			0xd2,
			[]byte("TEST ONLY inner failure"),
			d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
		)
		frontSecret, tailSecret := front.secret, tail.secret
		physical := d1ForceCanonicalPhysicalFile(body)
		request, err := newD1RecoveryRequest(RecoveryModeForce)
		if err != nil {
			t.Fatalf("create D1 Force request: %v", err)
		}
		result, err := resolveD1ForceCandidates(
			context.Background(),
			bytes.NewReader(physical),
			int64(len(physical)),
			request,
			[]*d1ForceCandidate{front, tail},
			func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
				return newRecoveryResult(
					OutcomeAuthenticationFailed,
					ForceProvenanceNone,
					StageRecordAuth,
					0,
					nil,
					0,
				)
			},
		)
		if err != nil {
			t.Fatalf("resolve nested inner failure: %v", err)
		}
		if result.Outcome() != OutcomeAuthenticationFailed || result.Stage() != StageInnerVolume ||
			result.DetailStage() != StageRecordAuth ||
			result.D1BootstrapProvenance() != D1BootstrapProvenanceMatching ||
			result.PlaintextLength() != 0 {
			t.Fatalf(
				"nested failure = %v/%v detail %v D1 %v length %d; want authentication-failed/inner-volume/record-auth",
				result.Outcome(),
				result.Stage(),
				result.DetailStage(),
				result.D1BootstrapProvenance(),
				result.PlaintextLength(),
			)
		}
		result.Close()
		assertD1ForceCandidateClosed(t, front, frontSecret)
		assertD1ForceCandidateClosed(t, tail, tailSecret)
	})

	t.Run("partial and verified inner ranges remain exact", func(t *testing.T) {
		const plaintextLength = uint64(recordPlaintextMax + 17)
		partialRanges := []RecoveryRange{
			{recordIndex: 0, start: 0, end: recordPlaintextMax, state: RecoveryRangeVerified},
			{recordIndex: 1, start: recordPlaintextMax, end: plaintextLength, state: RecoveryRangeMissing},
		}
		verifiedRanges := []RecoveryRange{
			{recordIndex: 0, start: 0, end: recordPlaintextMax, state: RecoveryRangeVerified},
			{recordIndex: 1, start: recordPlaintextMax, end: plaintextLength, state: RecoveryRangeVerified},
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
				name: "partial", outcome: OutcomeForcePartial, provenance: ForceProvenancePartial,
				stage: StageRecordAuth, ranges: partialRanges, final: RecoveryFinalVerified,
			},
			{
				name: "verified", outcome: OutcomeAuthenticatedDegraded, provenance: ForceProvenanceVerified,
				stage: StageWrapAuth, ranges: verifiedRanges, final: RecoveryFinalVerified,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				front, tail, body := newMatchingD1ForceTestBodyCandidates(
					t,
					0xd3,
					[]byte("TEST ONLY exact ranges"),
					d1ForceTestBootstrapEvidence{wrapVerified: true, replicaVerified: true},
				)
				frontSecret, tailSecret := front.secret, tail.secret
				physical := d1ForceCanonicalPhysicalFile(body)
				request, err := newD1RecoveryRequest(RecoveryModeForce)
				if err != nil {
					t.Fatalf("create D1 Force request: %v", err)
				}
				result, err := resolveD1ForceCandidates(
					context.Background(),
					bytes.NewReader(physical),
					int64(len(physical)),
					request,
					[]*d1ForceCandidate{front, tail},
					func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
						return newRecoveryResult(
							test.outcome,
							test.provenance,
							test.stage,
							plaintextLength,
							test.ranges,
							test.final,
						)
					},
				)
				if err != nil {
					t.Fatalf("resolve %s inner ranges: %v", test.name, err)
				}
				if result.Outcome() != test.outcome || result.Stage() != StageInnerVolume ||
					result.DetailStage() != test.stage || result.ForceProvenance() != test.provenance ||
					result.D1BootstrapProvenance() != D1BootstrapProvenanceMatching ||
					result.PlaintextLength() != plaintextLength ||
					!slices.Equal(result.Ranges(), test.ranges) || result.FinalRecordState() != test.final {
					t.Fatalf(
						"%s nested evidence = %v/%v detail %v force %v D1 %v length %d ranges %#v final %v",
						test.name,
						result.Outcome(),
						result.Stage(),
						result.DetailStage(),
						result.ForceProvenance(),
						result.D1BootstrapProvenance(),
						result.PlaintextLength(),
						result.Ranges(),
						result.FinalRecordState(),
					)
				}
				result.Close()
				assertD1ForceCandidateClosed(t, front, frontSecret)
				assertD1ForceCandidateClosed(t, tail, tailSecret)
			})
		}
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
		{name: "non-inner detail", stage: StageD1Body, detail: StageRecordAuth},
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

type d1ForceAuthEvent struct {
	role          D1BootstrapRole
	index         uint64
	final         bool
	authenticated bool
}

type d1ForceExpectedCandidate struct {
	role          D1BootstrapRole
	bodyLength    uint64
	authenticated bool
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
)

func (fault d1ForceSourceFault) String() string {
	switch fault {
	case d1ForceSourceShortRead:
		return "short source read"
	case d1ForceSourceFullReadNonEOF:
		return "full source read with non-EOF error"
	default:
		return "non-EOF source error"
	}
}

type d1ForceFaultReader struct {
	bytes []byte
	fault d1ForceSourceFault
}

func (reader *d1ForceFaultReader) ReadAt(destination []byte, offset int64) (int, error) {
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
	default:
		return bytes.NewReader(reader.bytes).ReadAt(destination, offset)
	}
}

func observeD1ForceDecrypts(seams *d1ForceSeams) *int {
	decryptCalls := new(int)
	realDecrypt := seams.decryptRecord
	seams.decryptRecord = func(
		candidate *d1ForceCandidate,
		codec *d1OuterCodec,
		ctx context.Context,
		index uint64,
		final bool,
		ciphertext, plaintext []byte,
	) error {
		*decryptCalls = *decryptCalls + 1
		return realDecrypt(candidate, codec, ctx, index, final, ciphertext, plaintext)
	}
	return decryptCalls
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
	return &d1ForceCandidate{
		role:            role,
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
	return &d1ForceCandidate{
		role:            role,
		bodyLength:      bodyLength,
		secret:          &d1OuterSecretOwner{bodyLength: bodyLength, keys: keyOwner},
		wrapVerified:    evidence.wrapVerified,
		replicaVerified: evidence.replicaVerified,
	}
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

func encodeD1ForceTestBody(t *testing.T, keyFill byte, inner []byte) []byte {
	t.Helper()
	access, keyOwner := newD1TestOuterAccess(t, keyFill)
	defer keyOwner.Close()
	return append([]byte(nil), encodeD1TestBody(t, access, inner)...)
}

func d1ForceCanonicalPhysicalFile(body []byte) []byte {
	physical := make([]byte, 0, 2*d1BootstrapLength+len(body))
	physical = append(physical, make([]byte, d1BootstrapLength)...)
	physical = append(physical, body...)
	physical = append(physical, make([]byte, d1BootstrapLength)...)
	return physical
}

func d1ForceSplitPhysicalFile(frontBody, insertion, tailBody []byte) []byte {
	physical := make([]byte, 0, 2*d1BootstrapLength+len(frontBody)+len(insertion)+len(tailBody))
	physical = append(physical, make([]byte, d1BootstrapLength)...)
	physical = append(physical, frontBody...)
	physical = append(physical, insertion...)
	physical = append(physical, tailBody...)
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

func expectedD1ForceCandidate(
	candidate *d1ForceCandidate,
	authenticated bool,
) d1ForceExpectedCandidate {
	return d1ForceExpectedCandidate{
		role:          candidate.role,
		bodyLength:    candidate.bodyLength,
		authenticated: authenticated,
	}
}

func assertExactD1ForceAuthEvents(
	t *testing.T,
	got []d1ForceAuthEvent,
	candidates ...d1ForceExpectedCandidate,
) {
	t.Helper()
	want := make(map[d1ForceAuthEvent]int)
	for _, candidate := range candidates {
		geometry, err := parseD1OuterGeometry(candidate.bodyLength)
		if err != nil {
			t.Fatalf("parse candidate event geometry: %v", err)
		}
		for index := range geometry.recordCount {
			expected, err := expectedD1OuterRecord(geometry, index)
			if err != nil {
				t.Fatalf("expected candidate event %d: %v", index, err)
			}
			want[d1ForceAuthEvent{
				role: candidate.role, index: index, final: expected.final, authenticated: candidate.authenticated,
			}]++
		}
	}
	gotCounts := make(map[d1ForceAuthEvent]int)
	for _, event := range got {
		gotCounts[event]++
	}
	if !mapsEqualD1ForceCounts(gotCounts, want) {
		t.Fatalf("tag-auth event multiset = %#v; want exactly %#v", gotCounts, want)
	}
}

func assertExactD1ForcePhysicalReads(
	t *testing.T,
	got []d1ForceReadRequest,
	physicalSize int64,
	candidates ...d1ForceExpectedCandidate,
) {
	t.Helper()
	want := make(map[d1ForceReadRequest]int)
	for _, candidate := range candidates {
		bodyOffset := int64(d1BootstrapLength)
		if candidate.role == D1BootstrapTail {
			bodyOffset = physicalSize - d1BootstrapLength - int64(candidate.bodyLength) //nolint:gosec // Test bodies are bounded below MaxInt64.
		}
		geometry, err := parseD1OuterGeometry(candidate.bodyLength)
		if err != nil {
			t.Fatalf("parse physical-read geometry: %v", err)
		}
		for index := range geometry.recordCount {
			expected, err := expectedD1OuterRecord(geometry, index)
			if err != nil {
				t.Fatalf("expected physical-read record %d: %v", index, err)
			}
			want[d1ForceReadRequest{
				offset: bodyOffset + int64(expected.offset), //nolint:gosec // Test geometry is bounded.
				length: expected.ciphertextLength,
			}]++
			want[d1ForceReadRequest{
				offset: bodyOffset + int64(expected.offset) + int64(expected.ciphertextLength), //nolint:gosec // Test geometry is bounded.
				length: d1OuterTagSize,
			}]++
		}
	}
	gotCounts := make(map[d1ForceReadRequest]int)
	for _, request := range got {
		gotCounts[request]++
	}
	if !mapsEqualD1ForceCounts(gotCounts, want) {
		t.Fatalf("physical read multiset = %#v; want exactly %#v", gotCounts, want)
	}
}

func mapsEqualD1ForceCounts[K comparable](left, right map[K]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, count := range left {
		if right[key] != count {
			return false
		}
	}
	return true
}

func assertD1ForceBodyAnchoredAmbiguity(
	t *testing.T,
	physical []byte,
	front, tail *d1ForceCandidate,
) {
	t.Helper()
	frontExpected := expectedD1ForceCandidate(front, true)
	tailExpected := expectedD1ForceCandidate(tail, true)
	source := &d1ForceObservedReader{bytes: physical}
	request, err := newD1RecoveryRequest(RecoveryModeForce)
	if err != nil {
		t.Fatalf("create D1 Force request: %v", err)
	}
	seams := defaultD1ForceSeams()
	realAuthenticate := seams.authenticateRecord
	var events []d1ForceAuthEvent
	seams.authenticateRecord = func(
		candidate *d1ForceCandidate,
		codec *d1OuterCodec,
		ctx context.Context,
		index uint64,
		final bool,
		ciphertext, tag []byte,
	) error {
		err := realAuthenticate(candidate, codec, ctx, index, final, ciphertext, tag)
		events = append(events, d1ForceAuthEvent{
			role: candidate.role, index: index, final: final, authenticated: err == nil,
		})
		return err
	}
	decryptCalls := observeD1ForceDecrypts(&seams)
	innerCalls := 0
	result, err := resolveD1ForceCandidatesWithSeams(
		context.Background(),
		source,
		int64(len(physical)),
		request,
		[]*d1ForceCandidate{front, tail},
		seams,
		func(*d1ForceCandidateAnalysis) (*RecoveryResult, error) {
			innerCalls++
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("resolve conflicting anchors: %v", err)
	}
	defer result.Close()
	assertExactD1ForceAuthEvents(t, events, frontExpected, tailExpected)
	assertExactD1ForcePhysicalReads(
		t,
		source.requests,
		int64(len(physical)),
		frontExpected,
		tailExpected,
	)
	if innerCalls != 0 || *decryptCalls != 0 || result.Outcome() != OutcomeAmbiguousVolume ||
		result.Stage() != StageD1Body || result.DetailStage() != StageNone ||
		result.D1BootstrapProvenance() != D1BootstrapProvenanceNone || result.Ranges() != nil {
		t.Fatalf(
			"body-anchor conflict = inner %d, decrypt %d, %v/%v detail %v provenance %v, ranges %#v; want ambiguous-volume/d1-body/none with no inner/output",
			innerCalls,
			*decryptCalls,
			result.Outcome(),
			result.Stage(),
			result.DetailStage(),
			result.D1BootstrapProvenance(),
			result.Ranges(),
		)
	}
}

func assertD1ForceCandidateClosed(
	t *testing.T,
	candidate *d1ForceCandidate,
	secret *d1OuterSecretOwner,
) {
	t.Helper()
	if candidate == nil || secret == nil {
		t.Fatal("missing candidate cleanup oracle")
	}
	if candidate.bodyLength != 0 || candidate.secret != nil ||
		candidate.wrapVerified || candidate.replicaVerified ||
		secret.bodyLength != 0 || secret.keys != nil {
		t.Fatalf("candidate owner survived resolution: candidate=%#v secret=%#v", candidate, secret)
	}
	if err := secret.withOuterKeys(context.Background(), func(*pcv3credential.BorrowedD1OuterKeys) error {
		return nil
	}); err == nil {
		t.Fatal("closed candidate retained borrowable OuterSecret keys")
	}
}

var _ io.ReaderAt = (*d1ForceObservedReader)(nil)
