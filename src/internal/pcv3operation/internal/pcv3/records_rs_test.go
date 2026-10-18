package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"fmt"
	"testing"
)

// Err becomes canceled after a fixed number of real decoder checkpoints. This
// makes cancellation during full correction deterministic, without a timer or
// replacing the RS operation under test.
type recordRSCancelContext struct {
	context.Context
	active    bool
	remaining int
	cancel    context.CancelFunc
}

func (ctx *recordRSCancelContext) Err() error {
	if err := ctx.Context.Err(); err != nil {
		return err
	}
	if !ctx.active {
		return nil
	}
	if ctx.remaining == 0 {
		ctx.cancel()
		return ctx.Context.Err()
	}
	ctx.remaining--
	return nil
}

func TestRecordRSFullCorrectionCancellation(t *testing.T) {
	fixture := recordFixtureByName(t, loadRecordFixtureManifest(t), "exact_one_paranoid_rs")
	payload := assembleRecordFixturePayload(t, fixture)
	payload[fixture.Records[0].BodyOffset] ^= 1
	auth, borrower := recordFixtureAuthority(t, fixture)
	defer auth.Close()
	defer borrower.close()
	realCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &recordRSCancelContext{Context: realCtx, cancel: cancel}
	seams := defaultRecordEngineSeams()
	realDecode := seams.decodeBody
	seams.decodeBody = func(decodeCtx context.Context, codecs *pcencoding.RSCodecs, encoded, decoded []byte, full bool) error {
		if full {
			ctx.active = true
			ctx.remaining = 16
		}
		return realDecode(decodeCtx, codecs, encoded, decoded, full)
	}
	evaluator, err := newRecordEvaluator(ctx, &recordTrackingReader{base: int64(fixture.FrontHeaderLength), data: payload}, auth.candidate.core, auth.geometry, recordTestCodecs(t), auth, seams)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluator.close()
	encoded, decoded, plaintext := evaluator.encodedBody, evaluator.decodedBody, evaluator.plaintext
	called := false
	err = evaluator.evaluateCanonicalRecord(0, recoveryRequest{}, 0, func(recordEvidence, []byte) error { called = true; return nil })
	if err == nil {
		t.Fatal("full RS correction ignored cancellation and returned success")
	}
	requireRecordFailureStage(t, err, StageCancellation)
	select {
	case <-ctx.Done():
	default:
		t.Fatal("canceled context did not close Done")
	}
	if called {
		t.Fatal("canceled record reached plaintext callback")
	}
	if !recordPaddingIsZero(decoded) {
		t.Fatal("canceled decoder retained partial corrected bytes")
	}
	evaluator.close()
	if !recordPaddingIsZero(encoded) || !recordPaddingIsZero(decoded) || !recordPaddingIsZero(plaintext) {
		t.Fatal("evaluator close retained owned buffers")
	}
}

func TestRecordRSFullRecordRecoveryAndRefusal(t *testing.T) {
	fixture := recordFixtureByName(t, loadRecordFixtureManifest(t), "exact_one_paranoid_rs")
	base := assembleRecordFixturePayload(t, fixture)
	want := recordFixturePlaintext(t, fixture)
	codecs := recordTestCodecs(t)
	type recordCase struct {
		name     string
		offsets  []int
		reencode bool
		stage    Stage
	}
	var cases []recordCase
	for count := 1; count <= 4; count++ {
		offsets := make([]int, count)
		for i := range offsets {
			offsets[i] = i * 23
		}
		cases = append(cases, recordCase{fmt.Sprintf("repair-%d-unknown-errors", count), offsets, false, StageNone})
	}
	many := make([]int, 256)
	for word := range many {
		many[word] = word * 136
	}
	tagWord := (1 << 20) / 128 * 136
	cases = append(cases,
		recordCase{"repair-256-damaged-words", many, false, StageNone},
		recordCase{"repair-tag", []int{tagWord}, false, StageNone},
		recordCase{"repair-padding", []int{tagWord + 64}, false, StageNone},
		recordCase{"refuse-authentic-rs-invalid-tag", []int{tagWord}, true, StageRecordAuth},
		recordCase{"refuse-authentic-rs-nonzero-padding", []int{tagWord + 64}, true, StageRecordBodyRS},
		recordCase{"refuse-overbudget-unauthentic", []int{0, 1, 2, 3, 4, 5, 6, 7, 8}, false, StageRecordBodyRS},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Clone(base)
			body := payload[fixture.Records[0].BodyOffset : fixture.Records[0].BodyOffset+fixture.Records[0].EncodedBodyLength]
			for _, offset := range tc.offsets {
				body[offset] ^= 0x5b
			}
			if tc.reencode {
				start := tc.offsets[0] / 136 * 136
				if err := pcencoding.EncodeInto(body[start:start+136], codecs.RS128, body[start:start+128]); err != nil {
					t.Fatal(err)
				}
			}
			auth, borrower := recordFixtureAuthority(t, fixture)
			defer auth.Close()
			defer borrower.close()
			seams := defaultRecordEngineSeams()
			decryptCalls := 0
			realDecrypt := seams.decryptParanoid
			seams.decryptParanoid = func(dst, src, key, nonce, serpent, iv []byte) error {
				decryptCalls++
				return realDecrypt(dst, src, key, nonce, serpent, iv)
			}
			evaluator, err := newRecordEvaluator(context.Background(), &recordTrackingReader{base: int64(fixture.FrontHeaderLength), data: payload}, auth.candidate.core, auth.geometry, codecs, auth, seams)
			if err != nil {
				t.Fatal(err)
			}
			defer evaluator.close()
			encoded, decoded, plaintext := evaluator.encodedBody, evaluator.decodedBody, evaluator.plaintext
			original := bytes.Clone(body)
			called := false
			err = evaluator.evaluateCanonicalRecord(0, recoveryRequest{}, 0, func(e recordEvidence, got []byte) error {
				called = true
				if e.authentication != recordAuthenticationVerified || !bytes.Equal(got, want) {
					t.Fatal("repaired plaintext differs from frozen oracle")
				}
				return nil
			})
			if tc.stage == StageNone {
				if err != nil || !called {
					t.Fatalf("correctable record not delivered: %v", err)
				}
			} else {
				requireRecordFailureStage(t, err, tc.stage)
				if called || decryptCalls != 0 {
					t.Fatal("unauthentic record reached decryption or callback")
				}
			}
			if !bytes.Equal(body, original) || !bytes.Equal(evaluator.encodedBody[:len(body)], original) {
				t.Fatal("decoder changed source input")
			}
			evaluator.close()
			if !recordPaddingIsZero(encoded) || !recordPaddingIsZero(decoded) || !recordPaddingIsZero(plaintext) {
				t.Fatal("evaluator close retained owned buffers")
			}
		})
	}
}
