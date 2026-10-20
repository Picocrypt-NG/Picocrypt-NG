package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"errors"
	"testing"
)

// Only the costly credential derivation is replaced. Bootstrap authentication,
// pair checks, outer records, inner capsules and the complete emitter are real.
func d1VerifyCodecSeams(front, tail *d1CProfileTestAccess) d1VerifySeams {
	return d1VerifySeams{candidate: func(ctx context.Context, _ *pcv3credential.CredentialInputOuter, bootstrap d1BootstrapCandidate, _ pcv3credential.Admitter, request d1RecoveryRequest, callback func(*d1ForceCandidate) error) error {
		access := front
		if bootstrap.role == D1BootstrapTail {
			access = tail
		}
		return withD1RecoveryCandidate(ctx, bootstrap, access, request, callback)
	}}
}

func TestVerifyD1AuthenticatesBothCopiesAndCompletePayload(t *testing.T) {
	for _, suite := range []Suite{SuiteStandard, SuiteParanoid} {
		t.Run(map[Suite]string{SuiteStandard: "standard", SuiteParanoid: "paranoid"}[suite], func(t *testing.T) {
			volume, front, tail, _ := newD1CCodecFixture(t, suite)
			before := bytes.Clone(volume)
			report := verifyD1WithSeams(context.Background(), bytes.NewReader(volume), int64(len(volume)), d1CCodecFactors(), d1CreationTestAdmitter{}, d1VerifyCodecSeams(front, tail))
			if report.Outcome() != OutcomeSuccess || report.Front() != D1CheckPassed || report.Tail() != D1CheckPassed || report.Pair() != D1CheckPassed || report.Payload() != D1CheckPassed {
				t.Fatalf("strict verification did not authenticate the full volume: %+v", report)
			}
			if !bytes.Equal(volume, before) {
				t.Fatal("verification changed the source")
			}
		})
	}
}

func TestVerifyD1CannotPromoteSingleCopyOrDamagedPayload(t *testing.T) {
	volume, front, tail, _ := newD1CCodecFixture(t, SuiteStandard)
	for _, tc := range []struct {
		name                       string
		mutate                     func([]byte) []byte
		front, tail, pair, payload D1CheckState
	}{
		{"front damaged", func(b []byte) []byte { b[d1BootstrapWrapTagOffset] ^= 1; return b }, D1CheckFailed, D1CheckPassed, D1CheckUnchecked, D1CheckUnchecked},
		{"tail damaged", func(b []byte) []byte { b[len(b)-d1BootstrapLength+d1BootstrapWrapTagOffset] ^= 1; return b }, D1CheckPassed, D1CheckFailed, D1CheckUnchecked, D1CheckUnchecked},
		{"front deleted", func(b []byte) []byte { return b[d1BootstrapLength:] }, D1CheckFailed, D1CheckPassed, D1CheckUnchecked, D1CheckUnchecked},
		{"tail deleted", func(b []byte) []byte { return b[:len(b)-d1BootstrapLength] }, D1CheckPassed, D1CheckFailed, D1CheckUnchecked, D1CheckUnchecked},
		{"outer payload damaged", func(b []byte) []byte { b[d1BootstrapLength+d1OuterPrefixLength+10] ^= 1; return b }, D1CheckPassed, D1CheckPassed, D1CheckPassed, D1CheckFailed},
		{"outer final damaged", func(b []byte) []byte { b[len(b)-d1BootstrapLength-1] ^= 1; return b }, D1CheckPassed, D1CheckPassed, D1CheckPassed, D1CheckFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			physical := tc.mutate(bytes.Clone(volume))
			report := verifyD1WithSeams(context.Background(), bytes.NewReader(physical), int64(len(physical)), d1CCodecFactors(), d1CreationTestAdmitter{}, d1VerifyCodecSeams(front, tail))
			if report.Outcome() == OutcomeSuccess || report.Front() != tc.front || report.Tail() != tc.tail || report.Pair() != tc.pair || report.Payload() != tc.payload {
				t.Fatalf("damage yielded incorrect verification evidence: outcome=%v front=%v tail=%v pair=%v payload=%v", report.Outcome(), report.Front(), report.Tail(), report.Pair(), report.Payload())
			}
		})
	}
}

func TestVerifyD1RejectsAuthenticatedInconsistentOrNonIndependentPair(t *testing.T) {
	for _, mutation := range []string{"outer root", "inner root", "profile", "length", "geometry", "salt", "nonce", "iv"} {
		t.Run(mutation, func(t *testing.T) {
			volume, front, tail, _ := newD1CCodecFixture(t, SuiteStandard)
			f, _ := parseD1Bootstrap(volume[:d1BootstrapLength], D1BootstrapFront)
			tc, _ := parseD1Bootstrap(volume[len(volume)-d1BootstrapLength:], D1BootstrapTail)
			outer, inner, profile := byte(0x31), byte(0x72), pcv3credential.D1ProfileStandard
			length := uint64(len(volume) - 2*d1BootstrapLength)
			switch mutation {
			case "outer root":
				outer++
			case "inner root":
				inner++
			case "profile":
				profile = pcv3credential.D1ProfileParanoid
			case "length", "geometry":
				length++
			case "salt":
				tc.argonSalt = f.argonSalt
			case "nonce":
				tc.wrapNonce = f.wrapNonce
			case "iv":
				tc.wrapSerpentIV = f.wrapSerpentIV
			}
			owner, err := pcv3credential.NewD1RootsOwner(bytes.Repeat([]byte{outer}, 32), bytes.Repeat([]byte{inner}, 32), profile)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			encode := func(role D1BootstrapRole, candidate d1BootstrapCandidate, access *d1CProfileTestAccess) [d1BootstrapLength]byte {
				b, err := encodeD1Bootstrap(context.Background(), role, length, d1BootstrapWriteParameters{argonSalt: candidate.argonSalt, wrapNonce: candidate.wrapNonce, wrapSerpentIV: candidate.wrapSerpentIV}, access, &d1OuterOwnerAccess{owner: owner})
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			encoded := encode(D1BootstrapTail, tc, tail)
			copy(volume[len(volume)-d1BootstrapLength:], encoded[:])
			if mutation == "geometry" {
				encoded = encode(D1BootstrapFront, f, front)
				copy(volume[:d1BootstrapLength], encoded[:])
			}
			report := verifyD1WithSeams(context.Background(), bytes.NewReader(volume), int64(len(volume)), d1CCodecFactors(), d1CreationTestAdmitter{}, d1VerifyCodecSeams(front, tail))
			if report.Front() != D1CheckPassed || report.Tail() != D1CheckPassed || report.Pair() != D1CheckFailed || report.Payload() != D1CheckUnchecked || report.Outcome() != OutcomeAuthenticationFailed {
				t.Fatalf("authenticated inconsistent pair accepted: outcome=%v front=%v tail=%v pair=%v payload=%v", report.Outcome(), report.Front(), report.Tail(), report.Pair(), report.Payload())
			}
		})
	}
}

type d1VerifyReadFault struct {
	*bytes.Reader
	cancel              context.CancelFunc
	bodyReads, failRead int
}

func (r *d1VerifyReadFault) ReadAt(p []byte, off int64) (int, error) {
	if off >= d1BootstrapLength && off < r.Size()-d1BootstrapLength {
		r.bodyReads++
		if r.cancel != nil {
			r.cancel()
		}
		if r.failRead > 0 && r.bodyReads == r.failRead {
			return 0, errors.New("TEST ONLY I/O failure")
		}
	}
	return r.Reader.ReadAt(p, off)
}

func TestVerifyD1OperationalFailuresDoNotClaimDamage(t *testing.T) {
	volume, front, tail, _ := newD1CCodecFixture(t, SuiteStandard)
	for _, phase := range []string{"between credentials", "reading payload", "late read failure"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &d1VerifyReadFault{Reader: bytes.NewReader(volume)}
			seams := d1VerifyCodecSeams(front, tail)
			wantStage := StageCancellation
			switch phase {
			case "between credentials":
				candidate := seams.candidate
				seams.candidate = func(ctx context.Context, input *pcv3credential.CredentialInputOuter, bootstrap d1BootstrapCandidate, admitter pcv3credential.Admitter, request d1RecoveryRequest, callback func(*d1ForceCandidate) error) error {
					return candidate(ctx, input, bootstrap, admitter, request, func(c *d1ForceCandidate) error { cancel(); return callback(c) })
				}
			case "reading payload":
				reader.cancel = cancel
			case "late read failure":
				baseline := verifyD1WithSeams(ctx, reader, int64(len(volume)), d1CCodecFactors(), d1CreationTestAdmitter{}, seams)
				if baseline.Outcome() != OutcomeSuccess || reader.bodyReads < 2 {
					t.Fatal("baseline did not exercise full payload reads")
				}
				reader.failRead, reader.bodyReads = reader.bodyReads, 0
				wantStage = StageInputIO
			}
			report := verifyD1WithSeams(ctx, reader, int64(len(volume)), d1CCodecFactors(), d1CreationTestAdmitter{}, seams)
			if report.Outcome() != OutcomeOperationFailed || report.Stage() != wantStage || report.Payload() != D1CheckUnchecked {
				t.Fatalf("operational failure classified as damage/success: outcome=%v stage=%v payload=%v", report.Outcome(), report.Stage(), report.Payload())
			}
		})
	}
}

func TestVerifyD1RejectsDamagedInnerPayloadAndFinalUnderAuthenticatedOuter(t *testing.T) {
	for _, final := range []bool{false, true} {
		t.Run(map[bool]string{false: "payload", true: "final"}[final], func(t *testing.T) {
			volume, front, tail, _ := newD1CCodecFixture(t, SuiteStandard)
			owner, err := pcv3credential.NewD1RootsOwner(bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x72}, 32), pcv3credential.D1ProfileStandard)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			codec, err := newD1OuterCodec(context.Background(), &d1OuterOwnerAccess{owner: owner})
			if err != nil {
				t.Fatal(err)
			}
			defer codec.Close()
			geometry, err := parseD1OuterGeometry(uint64(len(volume) - 2*d1BootstrapLength))
			if err != nil {
				t.Fatal(err)
			}
			var outerPlain []byte
			for i := range geometry.recordCount {
				record, err := expectedD1OuterRecord(geometry, i)
				if err != nil {
					t.Fatal(err)
				}
				off := d1BootstrapLength + int(record.offset)
				plaintext := make([]byte, record.ciphertextLength)
				if err := codec.openRecord(context.Background(), i, record.final, volume[off:off+record.ciphertextLength], volume[off+record.ciphertextLength:off+record.ciphertextLength+d1OuterTagSize], plaintext); err != nil {
					t.Fatal(err)
				}
				outerPlain = append(outerPlain, plaintext...)
			}
			inner := outerPlain[d1OuterPrefixLength:]
			structure, err := inspectRecovery(bytes.NewReader(inner), int64(len(inner)), true)
			if err != nil {
				t.Fatal(err)
			}
			candidate, ok := structure.CandidateAt(0)
			if !ok {
				t.Fatal("missing inner candidate")
			}
			innerGeometry, ok := structure.GeometryAt(0)
			if !ok {
				t.Fatal("missing inner geometry")
			}
			index := uint64(0)
			if final {
				index = candidate.core.recordCount
			}
			expected, err := expectedRecord(candidate.core, innerGeometry, index)
			if err != nil {
				t.Fatal(err)
			}
			// More damage than RS can repair; the untouched bootstrap MACs cannot
			// substitute for payload/final authentication inside the outer wrapper.
			clear(inner[expected.bodyOffset : expected.bodyOffset+int64(expected.encodedBodyLength)])
			consumed := 0
			for i := range geometry.recordCount {
				record, err := expectedD1OuterRecord(geometry, i)
				if err != nil {
					t.Fatal(err)
				}
				off := d1BootstrapLength + int(record.offset)
				tag, err := codec.sealRecord(context.Background(), i, record.final, outerPlain[consumed:consumed+record.ciphertextLength], volume[off:off+record.ciphertextLength])
				if err != nil {
					t.Fatal(err)
				}
				copy(volume[off+record.ciphertextLength:], tag[:])
				consumed += record.ciphertextLength
			}
			report := verifyD1WithSeams(context.Background(), bytes.NewReader(volume), int64(len(volume)), d1CCodecFactors(), d1CreationTestAdmitter{}, d1VerifyCodecSeams(front, tail))
			if report.Outcome() == OutcomeSuccess || report.Outcome() == OutcomeOperationFailed || report.Pair() != D1CheckPassed || report.Payload() != D1CheckFailed {
				t.Fatalf("inner damage promoted or misclassified: outcome=%v stage=%v pair=%v payload=%v", report.Outcome(), report.Stage(), report.Pair(), report.Payload())
			}
		})
	}
}
