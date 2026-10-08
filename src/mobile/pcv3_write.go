package mobile

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/volume"
	"context"
	"errors"
	"math"
	"os"
)

var runPCV3WriteWithOptions = pcv3operation.RunWriteWithOptions

// pcv3WriteRequest owns the inputs transferred by StartPCV3. The shared writer
// borrows source and consumes factors and comment.
type pcv3WriteRequest struct {
	prepared   *volume.PreparedEncryptInput
	input      volume.EncryptInputRequest
	d1         bool
	suite      pcv3operation.Suite
	payloadRS  bool
	comment    []byte
	sourcePath string
	source     *os.File
	factors    *pcv3operation.FactorRequest
	target     string
	protected  []string
}

func executePCV3WriteOperation(operation *PCV3Operation, request *pcv3WriteRequest) {
	var result *pcv3operation.Result
	defer func() {
		recovered := recover()
		cleanupIncomplete := releasePCV3WriteRequest(request)
		if cleanupIncomplete && result != nil {
			result.WithCleanupWarning()
		}
		if recovered != nil {
			cleanupIncomplete = cleanupIncomplete || fileops.PanicCleanupIncomplete(recovered)
			if result != nil {
				for _, warning := range result.Warnings() {
					cleanupIncomplete = cleanupIncomplete || warning == pcv3operation.WarningCleanupIncomplete
				}
				if output := result.OutputFollowUp(); output != nil {
					discard := output.Discard()
					cleanupIncomplete = cleanupIncomplete || discard.CleanupIncomplete()
				}
			}
			completePCV3Panic(operation, cleanupIncomplete)
			return
		}
		completePCV3Result(operation, result)
	}()
	ctx, ok := getContext(operation.id)
	if !ok {
		return
	}
	var err error
	request.input.Reporter = &pcv3InputReporter{ctx: ctx, report: pcv3Reporter(operation)}
	request.prepared, err = volume.PrepareEncryptInput(ctx, request.input)
	if err != nil {
		result = runPCV3WriteWithOptions(ctx, &pcv3operation.WriteRequest{Factors: request.factors, Comment: request.comment}, pcv3operation.ExecutionOptions{})
		if errors.Is(err, volume.ErrEncryptInputCleanupIncomplete) {
			result.WithCleanupWarning()
		}
		return
	}
	result = runPCV3Write(ctx, request, pcv3Reporter(operation))
}

func releasePCV3WriteRequest(request *pcv3WriteRequest) (cleanupIncomplete bool) {
	if request == nil {
		return false
	}
	if request.factors != nil {
		cleanupIncomplete = request.factors.Close() != nil
	}
	if request.prepared != nil && request.prepared.Close() != nil {
		cleanupIncomplete = true
	}
	if request.source != nil && request.source.Close() != nil {
		cleanupIncomplete = true
	}
	clear(request.comment)
	clear(request.protected)
	*request = pcv3WriteRequest{}
	return cleanupIncomplete
}

func runPCV3Write(ctx context.Context, request *pcv3WriteRequest, reporter pcv3operation.Reporter) *pcv3operation.Result {
	mode := pcv3operation.WriteModeNormal
	if request.d1 {
		mode = pcv3operation.WriteModeD1
	}
	core := &pcv3operation.WriteRequest{
		Mode: mode, Suite: request.suite, PayloadKind: request.prepared.PayloadKind(),
		PayloadBodyRS: request.payloadRS, PlaintextLength: request.prepared.Length(),
		Comment: request.comment, Factors: request.factors, Source: request.prepared.Reader(),
		SourceFile: request.prepared.File(), SourcePath: request.prepared.Path(), Target: request.target,
		Protected: request.protected, Reporter: reporter,
	}
	return runPCV3WriteWithOptions(ctx, core, pcv3operation.ExecutionOptions{RetainDurableOutput: true, JournalPrivateStage: true})
}

// Input preparation reports numeric presentation only; it cannot mint a result.
type pcv3InputReporter struct {
	ctx    context.Context
	report pcv3operation.Reporter
}

func (r *pcv3InputReporter) SetStatus(string) {
	_ = r.report(pcv3operation.InputPreparationStatus(0, 0))
}

func (r *pcv3InputReporter) SetProgress(fraction float32, _ string) {
	if math.IsNaN(float64(fraction)) || math.IsInf(float64(fraction), 0) {
		return
	}
	fraction = max(float32(0), min(float32(1), fraction))
	_ = r.report(pcv3operation.InputPreparationStatus(uint64(fraction*10000), 10000))
}
func (*pcv3InputReporter) SetCanCancel(bool)   {}
func (*pcv3InputReporter) Update()             {}
func (r *pcv3InputReporter) IsCancelled() bool { return r.ctx.Err() != nil }
