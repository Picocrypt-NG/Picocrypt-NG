//go:build pcv3_production_kdf

package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"io"
	"testing"
)

func TestVerifyD1IndependentProductionKDF(t *testing.T) {
	for _, fixture := range []string{"d1.pcv", "d1-standard.pcv", "d1-empty-standard.pcv", "d1-exact-mib-paranoid.pcv", "d1-multi-standard.pcv", "d1-multi-paranoid.pcv", "d1-multi-rs-standard.pcv", "d1-multi-rs-paranoid.pcv", "d1-outer-exact-standard.pcv"} {
		t.Run(fixture, func(t *testing.T) {
			volume := independentD1File(t, fixture)
			admitter := &independentD1Admitter{}
			report := VerifyD1(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, ""), admitter)
			if report.Outcome() != OutcomeSuccess || report.Front() != D1CheckPassed || report.Tail() != D1CheckPassed || report.Pair() != D1CheckPassed || report.Payload() != D1CheckPassed || admitter.calls != 2 {
				t.Fatalf("independent strict verify: outcome=%v stage=%v front=%v tail=%v pair=%v payload=%v KDFs=%d", report.Outcome(), report.Stage(), report.Front(), report.Tail(), report.Pair(), report.Payload(), admitter.calls)
			}
		})
	}
}

func TestVerifyD1WrongFactorsProductionKDF(t *testing.T) {
	volume := independentD1File(t, "d1-standard.pcv")
	for _, mutation := range []string{"password changed", "factor deleted", "factor changed", "factors reordered"} {
		t.Run(mutation, func(t *testing.T) {
			admitter := &independentD1Admitter{}
			report := VerifyD1(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, mutation), admitter)
			if report.Outcome() != OutcomeCredentialsOrDamage || report.Front() != D1CheckFailed || report.Tail() != D1CheckFailed || report.Pair() != D1CheckUnchecked || report.Payload() != D1CheckUnchecked || admitter.calls != 2 {
				t.Fatalf("changed factors gained verification evidence: outcome=%v front=%v tail=%v pair=%v payload=%v KDFs=%d", report.Outcome(), report.Front(), report.Tail(), report.Pair(), report.Payload(), admitter.calls)
			}
		})
	}
}

type d1VerifyCancellingAdmitter struct {
	independentD1Admitter
	cancel context.CancelFunc
}

func (a *d1VerifyCancellingAdmitter) AdmitKDF(ctx context.Context, p pcv3credential.KDFProfile) (pcv3credential.KDFAdmission, error) {
	decision, err := a.independentD1Admitter.AdmitKDF(ctx, p)
	if a.calls == 2 {
		a.cancel()
	}
	return decision, err
}

func TestVerifyD1CancellationBetweenProductionKDFs(t *testing.T) {
	volume := independentD1File(t, "d1-standard.pcv")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	admitter := &d1VerifyCancellingAdmitter{cancel: cancel}
	report := VerifyD1(ctx, bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, ""), admitter)
	if report.Outcome() != OutcomeOperationFailed || report.Stage() != StageCancellation || report.Front() != D1CheckPassed || report.Tail() != D1CheckUnchecked || report.Payload() != D1CheckUnchecked || admitter.calls != 2 {
		t.Fatalf("cancellation after the first completed KDF misclassified: outcome=%v stage=%v front=%v tail=%v KDF admissions=%d", report.Outcome(), report.Stage(), report.Front(), report.Tail(), admitter.calls)
	}
}

func TestVerifyD1LeavesOrdinaryHealthyOpenAtOneProductionKDF(t *testing.T) {
	volume := independentD1File(t, "d1-standard.pcv")
	admitter := &independentD1Admitter{}
	result, err := RecoverD1(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, ""), admitter, RecoveryModeNormalV3, func(_ *RecoveryResult, _ D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
		return emitter(func(_ RecoveryRange, data []byte) error { _, err := io.Discard.Write(data); return err })
	})
	if result != nil {
		defer result.Close()
	}
	if err != nil || result == nil || result.Outcome() != OutcomeSuccess || admitter.calls != 1 {
		t.Fatalf("ordinary D1 open changed: result=%v err=%v KDFs=%d", result, err, admitter.calls)
	}
}
