// Package pcv3recovery composes PCV3 recovery semantics with the existing
// no-replace publication state machine. It owns no cryptographic primitives,
// archive authority, or source-deletion behavior.
package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
)

const recoveryRecordPlaintextMax = uint64(1 << 20)

// Request contains the operation-owned publication inputs. Credential and
// source fields are added by the production core adapter; tests exercise the
// exact filesystem composition through runWithCore.
type Request struct {
	Source       io.ReaderAt
	SourceSize   int64
	Factors      *pcv3credential.FactorRequest
	Admitter     pcv3credential.Admitter
	Mode         pcv3.RecoveryMode
	SelectedRole pcv3.CapsuleRole
	Target       string
	Protected    []string
	stageWriter  func(io.Writer) io.Writer
}

type operationRange struct {
	recordIndex uint64
	start       uint64
	end         uint64
	state       pcv3.RecoveryRangeState
}

type operationSemantic struct {
	outcome         pcv3.Outcome
	provenance      pcv3.ForceProvenance
	stage           pcv3.Stage
	code            pcv3.Code
	plaintextLength uint64
	ranges          []operationRange
	final           pcv3.RecoveryFinalState
}

func (semantic operationSemantic) outputCapable() bool {
	return semantic.outcome == pcv3.OutcomeSuccess ||
		semantic.outcome == pcv3.OutcomeAuthenticatedDegraded ||
		semantic.outcome == pcv3.OutcomeForcePartial ||
		semantic.outcome == pcv3.OutcomeForceUnverified
}

type (
	operationSegmentSink func(operationRange, []byte) error
	operationEmitter     func(operationSegmentSink) error
	operationOutput      func(operationSemantic, pcv3.CapsuleRole, operationEmitter) error
	recoveryCoreRunner   func(context.Context, *Request, operationOutput) (operationSemantic, error)
)

// Run executes the internal production recovery core and composes its output
// capability with one no-replace stage. No public app surface calls Run in
// Phase 6.
func Run(ctx context.Context, request *Request) *Result {
	if ctx == nil && request != nil && request.Factors != nil {
		_ = request.Factors.Close()
		request.Factors = nil
	}
	return runWithCore(ctx, request, runProductionCore)
}

// Result keeps semantic recovery and transport publication as orthogonal
// dimensions. Its formatting never contains a path or wrapped error.
type Result struct {
	semantic             operationSemantic
	publicationAttempted bool
	publicationState     pcv3publication.State
	publicationStage     pcv3.Stage
	publicationCode      pcv3publication.Code
}

func (result *Result) Outcome() pcv3.Outcome {
	if result == nil {
		return 0
	}
	return result.semantic.outcome
}

func (result *Result) ForceProvenance() pcv3.ForceProvenance {
	if result == nil {
		return 0
	}
	return result.semantic.provenance
}

func (result *Result) Stage() pcv3.Stage {
	if result == nil {
		return 0
	}
	return result.semantic.stage
}

func (result *Result) Code() pcv3.Code {
	if result == nil {
		return 0
	}
	return result.semantic.code
}

func (result *Result) PublicationAttempted() bool {
	return result != nil && result.publicationAttempted
}

func (result *Result) PublicationState() pcv3publication.State {
	if result == nil {
		return 0
	}
	return result.publicationState
}

func (result *Result) PublicationStage() pcv3.Stage {
	if result == nil {
		return 0
	}
	return result.publicationStage
}

func (result *Result) PublicationCode() pcv3publication.Code {
	if result == nil {
		return 0
	}
	return result.publicationCode
}

func (result *Result) Error() string {
	if result == nil {
		return "pcv3 recovery operation: unavailable"
	}
	return "pcv3 recovery operation: completed"
}

func (result *Result) String() string { return result.Error() }

func (result *Result) GoString() string { return result.Error() }

func (result *Result) Format(state fmt.State, verb rune) {
	value := result.Error()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	}
	_, _ = io.WriteString(state, value)
}

func runWithCore(
	ctx context.Context,
	request *Request,
	run recoveryCoreRunner,
) *Result {
	result := &Result{}
	if ctx == nil || request == nil || run == nil {
		result.semantic = operationSemantic{
			outcome: pcv3.OutcomeOperationFailed,
			stage:   pcv3.StageCredentialPolicy,
			code:    pcv3.CodeOperationFailed,
		}
		return result
	}

	outputCalls := 0
	output := func(
		semantic operationSemantic,
		role pcv3.CapsuleRole,
		emit operationEmitter,
	) error {
		outputCalls++
		if outputCalls != 1 || !semantic.outputCapable() || !validOperationSemantic(semantic) || emit == nil {
			return errors.New("pcv3 recovery operation: invalid core output")
		}
		result.semantic = cloneOperationSemantic(semantic)
		result.publicationAttempted = true

		stage, err := pcv3publication.Create(
			request.Target,
			append([]string(nil), request.Protected...),
			pcv3publication.PolicyNoReplace,
		)
		if err != nil {
			result.retainPublicationError(err)
			return err
		}
		defer func() {
			if cleanupErr := stage.Cleanup(); cleanupErr != nil &&
				result.publicationState == pcv3publication.StateNotPublished {
				result.publicationStage = pcv3.StageOutputPublication
				result.publicationCode = pcv3publication.CodeStageFailure
			}
		}()

		file := stage.File()
		if file == nil {
			result.retainNotPublished(pcv3.StageOutputPublication)
			return errors.New("pcv3 recovery operation: stage unavailable")
		}
		destination := io.Writer(file)
		if request.stageWriter != nil {
			destination = request.stageWriter(file)
			if destination == nil {
				result.retainNotPublished(pcv3.StageOutputWrite)
				return errors.New("pcv3 recovery operation: stage writer unavailable")
			}
		}
		if semantic.outcome == pcv3.OutcomeForcePartial ||
			semantic.outcome == pcv3.OutcomeForceUnverified {
			descriptor, descriptorErr := artifactDescriptor(semantic, role)
			if descriptorErr != nil {
				result.retainNotPublished(pcv3.StageOutputPublication)
				return descriptorErr
			}
			err = pcv3artifact.Encode(destination, descriptor, func(yield func(uint64, io.Reader) error) error {
				return emit(func(recoveryRange operationRange, plaintext []byte) error {
					return yield(recoveryRange.recordIndex, bytes.NewReader(plaintext))
				})
			})
		} else {
			err = emit(func(_ operationRange, plaintext []byte) error {
				return writeAll(destination, plaintext)
			})
		}
		if err != nil {
			result.retainNotPublished(pcv3.StageOutputWrite)
			return err
		}
		publication := stage.Publish(ctx)
		result.retainPublication(publication)
		if publication.State() != pcv3publication.StatePublishedDurable {
			return publication
		}
		return nil
	}

	semantic, _ := run(ctx, request, output)
	if result.publicationAttempted && semantic.outcome != 0 && !semantic.outputCapable() {
		result.semantic = cloneOperationSemantic(semantic)
		result.retainNotPublished(semantic.stage)
	}
	if result.semantic.outcome == 0 {
		if semantic.outcome == 0 {
			result.semantic = operationSemantic{
				outcome: pcv3.OutcomeOperationFailed,
				stage:   pcv3.StageCredentialPolicy,
				code:    pcv3.CodeOperationFailed,
			}
		} else {
			result.semantic = cloneOperationSemantic(semantic)
		}
	}
	return result
}

func (result *Result) retainPublication(publication pcv3publication.Result) {
	if result == nil || publication == nil {
		return
	}
	result.publicationState = publication.State()
	result.publicationStage = publication.Stage()
	result.publicationCode = publication.Code()
}

func (result *Result) retainPublicationError(err error) {
	var publication pcv3publication.Result
	if errors.As(err, &publication) {
		result.retainPublication(publication)
		return
	}
	result.retainNotPublished(pcv3.StageOutputPublication)
}

func (result *Result) retainNotPublished(stage pcv3.Stage) {
	result.publicationState = pcv3publication.StateNotPublished
	result.publicationStage = stage
	result.publicationCode = pcv3publication.CodeStageFailure
}

func cloneOperationSemantic(semantic operationSemantic) operationSemantic {
	semantic.ranges = append([]operationRange(nil), semantic.ranges...)
	return semantic
}

func validOperationSemantic(semantic operationSemantic) bool {
	if !semantic.outputCapable() {
		return false
	}
	if semantic.provenance == pcv3.ForceProvenanceNone {
		return (semantic.outcome == pcv3.OutcomeSuccess ||
			semantic.outcome == pcv3.OutcomeAuthenticatedDegraded) &&
			semantic.plaintextLength == 0 && len(semantic.ranges) == 0 && semantic.final == 0
	}
	wantCount := uint64(0)
	if semantic.plaintextLength != 0 {
		wantCount = (semantic.plaintextLength-1)/recoveryRecordPlaintextMax + 1
	}
	if uint64(len(semantic.ranges)) != wantCount {
		return false
	}
	for index, recoveryRange := range semantic.ranges {
		start := uint64(index) * recoveryRecordPlaintextMax
		end := start + recoveryRecordPlaintextMax
		if end > semantic.plaintextLength {
			end = semantic.plaintextLength
		}
		if recoveryRange.recordIndex != uint64(index) || recoveryRange.start != start ||
			recoveryRange.end != end || recoveryRange.start >= recoveryRange.end ||
			(recoveryRange.state != pcv3.RecoveryRangeVerified &&
				recoveryRange.state != pcv3.RecoveryRangeUnverified &&
				recoveryRange.state != pcv3.RecoveryRangeMissing) {
			return false
		}
	}
	return semantic.final == pcv3.RecoveryFinalVerified ||
		semantic.final == pcv3.RecoveryFinalUnverified ||
		semantic.final == pcv3.RecoveryFinalMissing
}

func runProductionCore(
	ctx context.Context,
	request *Request,
	output operationOutput,
) (operationSemantic, error) {
	if request == nil {
		return operationSemantic{
			outcome: pcv3.OutcomeOperationFailed,
			stage:   pcv3.StageCredentialPolicy,
			code:    pcv3.CodeOperationFailed,
		}, errors.New("pcv3 recovery operation: invalid request")
	}
	factors := request.Factors
	request.Factors = nil
	coreOutput := func(
		result *pcv3.RecoveryResult,
		role pcv3.CapsuleRole,
		emitter pcv3.RecoveryEmitter,
	) error {
		semantic := semanticFromCore(result)
		return output(semantic, role, func(sink operationSegmentSink) error {
			return emitter(func(recoveryRange pcv3.RecoveryRange, plaintext []byte) error {
				return sink(operationRange{
					recordIndex: recoveryRange.RecordIndex(),
					start:       recoveryRange.Start(),
					end:         recoveryRange.End(),
					state:       recoveryRange.State(),
				}, plaintext)
			})
		})
	}

	var result *pcv3.RecoveryResult
	var err error
	if request.Mode == pcv3.RecoveryModeForceUnverified {
		result, err = pcv3.RecoverUnverified(
			ctx,
			request.Source,
			request.SourceSize,
			factors,
			request.Admitter,
			request.SelectedRole,
			coreOutput,
		)
	} else {
		result, err = pcv3.Recover(
			ctx,
			request.Source,
			request.SourceSize,
			factors,
			request.Admitter,
			request.Mode,
			coreOutput,
		)
	}
	return semanticFromCore(result), err
}

func semanticFromCore(result *pcv3.RecoveryResult) operationSemantic {
	if result == nil {
		return operationSemantic{
			outcome: pcv3.OutcomeOperationFailed,
			stage:   pcv3.StageCredentialPolicy,
			code:    pcv3.CodeOperationFailed,
		}
	}
	semantic := operationSemantic{
		outcome:         result.Outcome(),
		provenance:      result.ForceProvenance(),
		stage:           result.Stage(),
		code:            result.Code(),
		plaintextLength: result.PlaintextLength(),
		final:           result.FinalRecordState(),
	}
	for _, recoveryRange := range result.Ranges() {
		semantic.ranges = append(semantic.ranges, operationRange{
			recordIndex: recoveryRange.RecordIndex(),
			start:       recoveryRange.Start(),
			end:         recoveryRange.End(),
			state:       recoveryRange.State(),
		})
	}
	return semantic
}

func artifactDescriptor(
	semantic operationSemantic,
	role pcv3.CapsuleRole,
) (pcv3artifact.Descriptor, error) {
	descriptor := pcv3artifact.Descriptor{
		PlaintextLength: semantic.plaintextLength,
	}
	switch semantic.outcome {
	case pcv3.OutcomeForcePartial:
		descriptor.State = pcv3artifact.StatePartial
	case pcv3.OutcomeForceUnverified:
		descriptor.State = pcv3artifact.StateUnverifiedForensic
	default:
		return pcv3artifact.Descriptor{}, errors.New("pcv3 recovery operation: artifact state unavailable")
	}
	hasUnverified := semantic.final == pcv3.RecoveryFinalUnverified
	for _, recoveryRange := range semantic.ranges {
		if recoveryRange.state == pcv3.RecoveryRangeUnverified {
			hasUnverified = true
		}
		descriptor.Ranges = append(descriptor.Ranges, pcv3artifact.Range{
			RecordIndex: recoveryRange.recordIndex,
			Start:       recoveryRange.start,
			End:         recoveryRange.end,
			Status:      artifactRangeState(recoveryRange.state),
		})
	}
	if hasUnverified {
		switch role {
		case pcv3.CapsuleRolePrimary:
			descriptor.Role = pcv3artifact.RolePrimary
		case pcv3.CapsuleRoleBackup:
			descriptor.Role = pcv3artifact.RoleBackup
		default:
			return pcv3artifact.Descriptor{}, errors.New("pcv3 recovery operation: unverified role unavailable")
		}
	}
	descriptor.Final = artifactFinalState(semantic.final)
	return descriptor, nil
}

func artifactRangeState(state pcv3.RecoveryRangeState) pcv3artifact.RangeStatus {
	switch state {
	case pcv3.RecoveryRangeVerified:
		return pcv3artifact.RangeVerified
	case pcv3.RecoveryRangeUnverified:
		return pcv3artifact.RangeUnverified
	case pcv3.RecoveryRangeMissing:
		return pcv3artifact.RangeMissing
	default:
		return 0
	}
}

func artifactFinalState(state pcv3.RecoveryFinalState) pcv3artifact.FinalStatus {
	switch state {
	case pcv3.RecoveryFinalVerified:
		return pcv3artifact.FinalVerified
	case pcv3.RecoveryFinalUnverified:
		return pcv3artifact.FinalUnverified
	case pcv3.RecoveryFinalMissing:
		return pcv3artifact.FinalMissing
	default:
		return 0
	}
}

func writeAll(destination io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := destination.Write(data)
		if written < 0 || written > len(data) {
			return errors.New("pcv3 recovery operation: invalid write progress")
		}
		data = data[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
