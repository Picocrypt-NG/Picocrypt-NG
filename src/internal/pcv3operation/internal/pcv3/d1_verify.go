package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
	"fmt"
	"io"

	pcv3crypto "Picocrypt-NG/internal/crypto"
)

// D1CheckState records only completed verification evidence. Unchecked also
// covers a check interrupted by an operational failure.
type D1CheckState uint8

const (
	D1CheckUnchecked D1CheckState = iota
	D1CheckPassed
	D1CheckFailed
)

// D1VerifyReport carries no plaintext, publication or recovery authority.
type D1VerifyReport struct {
	front, tail, pair, payload D1CheckState
	outcome                    Outcome
	stage                      Stage
}

func (r D1VerifyReport) Front() D1CheckState               { return r.front }
func (r D1VerifyReport) Tail() D1CheckState                { return r.tail }
func (r D1VerifyReport) Pair() D1CheckState                { return r.pair }
func (r D1VerifyReport) Payload() D1CheckState             { return r.payload }
func (r D1VerifyReport) Outcome() Outcome                  { return r.outcome }
func (r D1VerifyReport) Stage() Stage                      { return r.stage }
func (D1VerifyReport) String() string                      { return "pcv3: D1 verification report" }
func (r D1VerifyReport) GoString() string                  { return r.String() }
func (r D1VerifyReport) Format(state fmt.State, verb rune) { writeFixedFormat(state, verb, r.String()) }

type d1VerifySeams struct {
	candidate func(context.Context, *pcv3credential.CredentialInputOuter, d1BootstrapCandidate, pcv3credential.Admitter, d1RecoveryRequest, func(*d1ForceCandidate) error) error
}

// VerifyD1 consumes factors and borrows source until the complete inner emitter
// has finished. Both ordinary bootstrap authentications are mandatory; this does
// not use the filesystem recovery wrapper or its plaintext staging.
func VerifyD1(ctx context.Context, source io.ReaderAt, sourceSize int64, factors *pcv3credential.FactorRequest, admitter pcv3credential.Admitter) D1VerifyReport {
	return verifyD1WithSeams(ctx, source, sourceSize, factors, admitter, d1VerifySeams{candidate: withD1RecoveryCredentialCandidate})
}

func verifyD1WithSeams(ctx context.Context, source io.ReaderAt, sourceSize int64, factors *pcv3credential.FactorRequest, admitter pcv3credential.Admitter, seams d1VerifySeams) D1VerifyReport {
	report := D1VerifyReport{outcome: OutcomeCredentialsOrDamage, stage: StageD1Bootstrap}
	defer closeRecoveryFactors(factors)
	operationFailure := func(stage Stage) D1VerifyReport {
		report.outcome, report.stage = OutcomeOperationFailed, stage
		report.payload = D1CheckUnchecked
		return report
	}
	if ctx == nil || source == nil || sourceSize < 0 || factors == nil || admitter == nil || seams.candidate == nil {
		return operationFailure(StageCredentialPolicy)
	}
	if ctx.Err() != nil {
		return operationFailure(StageCancellation)
	}
	if sourceSize < 2*d1BootstrapLength {
		return report
	}
	var raw [2][d1BootstrapLength]byte
	defer pcv3crypto.SecureZero(raw[0][:])
	defer pcv3crypto.SecureZero(raw[1][:])
	for index, offset := range []int64{0, sourceSize - d1BootstrapLength} {
		if _, err := readExactAt(source, offset, raw[index][:], StageD1Bootstrap); err != nil {
			if stage, operational := d1OperationalStage(ctx, err); operational {
				return operationFailure(stage)
			}
			return report
		}
		if ctx.Err() != nil {
			return operationFailure(StageCancellation)
		}
	}
	front, err := parseD1Bootstrap(raw[0][:], D1BootstrapFront)
	if err != nil {
		return report
	}
	tail, err := parseD1Bootstrap(raw[1][:], D1BootstrapTail)
	if err != nil {
		return report
	}
	defer clearD1BootstrapCandidate(&front)
	defer clearD1BootstrapCandidate(&tail)
	request, err := newD1RecoveryRequest(RecoveryModeNormalV3)
	if err != nil {
		return operationFailure(StageCredentialPolicy)
	}
	err = pcv3credential.WithValidatedFactors(ctx, factors, func(validated *pcv3credential.ValidatedFactors) error {
		transcript, err := pcv3credential.NewCanonicalTranscript(validated)
		if err != nil {
			return err
		}
		defer transcript.Close()
		outerInput, err := pcv3credential.NewD1CredentialInput(transcript)
		if err != nil {
			return err
		}
		defer outerInput.Close()
		return seams.candidate(ctx, outerInput, front, admitter, request, func(frontCandidate *d1ForceCandidate) error {
			report.front = D1CheckFailed
			if fullyAuthenticatedD1Candidate(frontCandidate) {
				report.front = D1CheckPassed
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return seams.candidate(ctx, outerInput, tail, admitter, request, func(tailCandidate *d1ForceCandidate) error {
				report.tail = D1CheckFailed
				if fullyAuthenticatedD1Candidate(tailCandidate) {
					report.tail = D1CheckPassed
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if report.front != D1CheckPassed || report.tail != D1CheckPassed {
					return nil
				}
				same, err := sameD1OuterSecretAccess(ctx, frontCandidate.bodyLength, frontCandidate, tailCandidate.bodyLength, tailCandidate)
				if err != nil {
					return err
				}
				report.pair = D1CheckFailed
				if !same || !independentD1BootstrapParameters(front, tail) || !canonicalD1Geometry(sourceSize, frontCandidate.bodyLength) {
					report.outcome, report.stage = OutcomeAuthenticationFailed, StageD1Bootstrap
					return nil
				}
				report.pair = D1CheckPassed
				analysis, selection, selected, err := selectNormalD1Front(ctx, source, sourceSize, frontCandidate)
				if err != nil {
					return err
				}
				report.payload = D1CheckFailed
				report.outcome, report.stage = OutcomeAuthenticationFailed, StageD1Body
				if analysis == nil || !selected {
					return nil
				}
				emitted := false
				result, err := recoverD1Selection(ctx, source, sourceSize, validated, request, selection, defaultD1ForceSeams(), func(_ *RecoveryResult, _ D1BootstrapRole, _ string, plan RecoveryOutputPlan, emitter RecoveryEmitter) error {
					var consumed uint64
					if err := emitter(func(r RecoveryRange, data []byte) error {
						if ctx.Err() != nil {
							return ctx.Err()
						}
						if r.State() != RecoveryRangeVerified || r.Start() != consumed || r.End()-r.Start() != uint64(len(data)) {
							return errInvalidD1Force
						}
						consumed = r.End()
						return nil
					}); err != nil {
						return err
					}
					if consumed != plan.PlaintextLength() {
						return errInvalidD1Force
					}
					emitted = true
					return nil
				})
				if result != nil {
					defer result.Close()
					report.outcome, report.stage = result.Outcome(), result.Stage()
				}
				if err != nil {
					if result != nil && result.Outcome() == OutcomeOperationFailed {
						return newD1OuterFailure(result.Stage(), err)
					}
					return err
				}
				if emitted && result != nil && (result.Outcome() == OutcomeSuccess || result.Outcome() == OutcomeAuthenticatedDegraded) {
					report.payload = D1CheckPassed
				}
				return nil
			})
		})
	})
	if err != nil {
		return operationFailure(d1CredentialFailureStage(ctx, err))
	}
	if ctx.Err() != nil {
		return operationFailure(StageCancellation)
	}
	return report
}
