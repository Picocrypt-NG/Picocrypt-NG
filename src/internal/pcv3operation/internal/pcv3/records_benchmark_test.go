package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"context"
	"errors"
	"testing"
)

// Full-record measurements use independent frozen ciphertext and literal keys,
// keeping KDF and fixture loading outside the measured record boundary.
func BenchmarkRecordRSFullCorrection(b *testing.B) {
	fixture := recordFixtureByName(b, loadRecordFixtureManifest(b), "exact_one_paranoid_rs")
	codecs := recordTestCodecs(b)
	for _, mode := range []string{"clean", "repair", "many-damaged", "cancel"} {
		b.Run(mode, func(b *testing.B) {
			payload := assembleRecordFixturePayload(b, fixture)
			if mode != "clean" {
				payload[fixture.Records[0].BodyOffset] ^= 1
			}
			if mode == "many-damaged" {
				for word := 1; word < 256; word++ {
					payload[int(fixture.Records[0].BodyOffset)+word*136] ^= 1
				}
			}
			auth, borrower := recordFixtureAuthority(b, fixture)
			defer auth.Close()
			defer borrower.close()
			ctx := &recordRSCancelContext{Context: context.Background()}
			seams := defaultRecordEngineSeams()
			realDecode := seams.decodeBody
			seams.decodeBody = func(decodeCtx context.Context, codecs *pcencoding.RSCodecs, encoded, decoded []byte, full bool) error {
				if mode == "cancel" && full {
					ctx.remaining = 16
					ctx.active = true
				}
				return realDecode(decodeCtx, codecs, encoded, decoded, full)
			}
			evaluator, err := newRecordEvaluator(ctx, &recordTrackingReader{base: int64(fixture.FrontHeaderLength), data: payload}, auth.candidate.core, auth.geometry, codecs, auth, seams)
			if err != nil {
				b.Fatal(err)
			}
			defer evaluator.close()
			defer func() {
				if ctx.cancel != nil {
					ctx.cancel()
				}
			}()
			b.SetBytes(1 << 20)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				ctx.active = false
				if mode == "cancel" {
					if ctx.cancel != nil {
						ctx.cancel()
					}
					ctx.Context, ctx.cancel = context.WithCancel(context.Background())
				}
				err := evaluator.evaluateCanonicalRecord(0, recoveryRequest{}, 0, func(recordEvidence, []byte) error { return nil })
				if mode != "cancel" && err != nil {
					b.Fatal(err)
				}
				if mode == "cancel" {
					var failure *recordFailure
					if !errors.Is(err, context.Canceled) || !errors.As(err, &failure) || failure.stage != StageCancellation {
						b.Fatalf("correction did not return cancellation: %v", err)
					}
				}
			}
		})
	}
}
