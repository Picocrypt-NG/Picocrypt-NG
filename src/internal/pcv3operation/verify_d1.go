package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3resource"
	"context"
	"fmt"
	"os"
)

// D1VerifyRequest transfers its opened source, mutable factors and reporter to
// VerifyD1 immediately, including on refusal. As with Request, the caller must
// establish the source descriptor's no-follow provenance before transfer.
// Verification has no destination, Force, suite hint or deletion authority.
type D1VerifyRequest struct {
	Source   *os.File
	Factors  *FactorRequest
	Reporter Reporter
}

func (D1VerifyRequest) String() string     { return "pcv3operation.D1VerifyRequest([REDACTED])" }
func (r D1VerifyRequest) GoString() string { return r.String() }

type D1CheckState = pcv3.D1CheckState

const (
	D1CheckUnchecked = pcv3.D1CheckUnchecked
	D1CheckPassed    = pcv3.D1CheckPassed
	D1CheckFailed    = pcv3.D1CheckFailed
)

// D1VerifyReport is a closed, authority-free verification snapshot. A failed
// bootstrap check does not distinguish wrong credentials from damaged bytes.
type D1VerifyReport struct {
	outcome                    Outcome
	stage                      Stage
	front, tail, pair, payload D1CheckState
	diagnostic                 Diagnostic
	cleanupIncomplete          bool
}

func (r D1VerifyReport) Outcome() Outcome        { return r.outcome }
func (r D1VerifyReport) Stage() Stage            { return r.stage }
func (r D1VerifyReport) Front() D1CheckState     { return r.front }
func (r D1VerifyReport) Tail() D1CheckState      { return r.tail }
func (r D1VerifyReport) Pair() D1CheckState      { return r.pair }
func (r D1VerifyReport) Payload() D1CheckState   { return r.payload }
func (r D1VerifyReport) Diagnostic() Diagnostic  { return r.diagnostic }
func (r D1VerifyReport) CleanupIncomplete() bool { return r.cleanupIncomplete }
func (r D1VerifyReport) Verified() bool {
	return r.outcome == pcv3.OutcomeSuccess && r.front == D1CheckPassed && r.tail == D1CheckPassed && r.pair == D1CheckPassed && r.payload == D1CheckPassed && !r.cleanupIncomplete
}
func (D1VerifyReport) String() string                      { return "pcv3operation.D1VerifyReport" }
func (r D1VerifyReport) GoString() string                  { return r.String() }
func (r D1VerifyReport) Format(state fmt.State, verb rune) { _, _ = fmt.Fprint(state, r.String()) }

// VerifyD1 authenticates both physical bootstraps and the complete outer/inner
// payload. A healthy verification uses exactly two fixed D1 KDFs, sequentially.
// Ordinary ModeReadD1 is unchanged and still uses one KDF on a healthy volume.
func VerifyD1(ctx context.Context, request *D1VerifyRequest) D1VerifyReport {
	return verifyD1WithAdmitter(ctx, request, pcv3resource.NewPlatformAdmitter())
}

func verifyD1WithAdmitter(ctx context.Context, request *D1VerifyRequest, admitter pcv3credential.Admitter) (report D1VerifyReport) {
	report = D1VerifyReport{outcome: OutcomeOperationFailed, stage: StageCredentialPolicy, diagnostic: DiagnosticInvalidRequest}
	owner := &operationOwner{}
	if request != nil {
		owner.source, owner.factors, owner.reporter = request.Source, request.Factors, request.Reporter
		*request = D1VerifyRequest{}
	}
	factorCleanup := owner.factors
	defer func() {
		if recovered := recover(); recovered != nil {
			report = D1VerifyReport{outcome: OutcomeOperationFailed, stage: StageCredentialPolicy, diagnostic: DiagnosticCallbackPanic, cleanupIncomplete: panicCleanupIncomplete(recovered)}
		}
		report.cleanupIncomplete = owner.close() || factorCleanup.CleanupIncomplete() || report.cleanupIncomplete
		if owner.reporterFailed || owner.reporterPanicked {
			report.outcome, report.stage = OutcomeOperationFailed, StageCredentialPolicy
			report.diagnostic = DiagnosticCallbackFailure
			if owner.reporterPanicked {
				report.diagnostic = DiagnosticCallbackPanic
			}
		}
	}()
	if ctx == nil || owner.source == nil || owner.factors == nil || admitter == nil {
		return report
	}
	if ctx.Err() != nil {
		report.stage, report.diagnostic = StageCancellation, DiagnosticCancellation
		return report
	}
	if !owner.report(StatusCheckingRequest) || !owner.report(StatusCheckingFactors) {
		return report
	}
	info, err := owner.source.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		report.stage, report.diagnostic = StageInputIO, DiagnosticCoreFailure
		return report
	}
	if !owner.report(StatusAuthenticating) {
		return report
	}
	core := pcv3.VerifyD1(ctx, owner.source, info.Size(), owner.takeFactors(), reportingAdmitter{owner: owner, next: admitter})
	report = D1VerifyReport{outcome: core.Outcome(), stage: core.Stage(), front: core.Front(), tail: core.Tail(), pair: core.Pair(), payload: core.Payload()}
	if report.outcome == OutcomeOperationFailed {
		report.diagnostic = DiagnosticCoreFailure
		switch report.stage {
		case StageCancellation:
			report.diagnostic = DiagnosticCancellation
		case StageCredentialPolicy:
			report.diagnostic = DiagnosticCredentialPolicy
		}
		if (report.stage == StageCredentialPolicy || report.stage == StageKDFRuntime) && owner.resourceDiagnostic != DiagnosticNone {
			report.diagnostic = owner.resourceDiagnostic
		}
	}
	return report
}
