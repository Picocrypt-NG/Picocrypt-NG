package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3resource"
	"context"
	"errors"
)

// AdmitZIPWorkingMemory checks fresh native headroom before a ZIP discovery,
// preparation or extraction phase. The ledger supplies the fixed platform
// envelope; metadata and frontends cannot enlarge it. Passing this advisory
// check does not reserve RAM or replace allocation accounting against budget.
func AdmitZIPWorkingMemory(ctx context.Context, budget *fileops.ZIPResourceBudget) error {
	return pcv3resource.AdmitZIPWorkingMemory(ctx, budget)
}

func archiveWorkingMemoryRefusal(ctx context.Context, cleanupIncomplete bool) *Result {
	result := newResult(resultData{
		outcome: OutcomeOperationFailed, stage: StageResourceBudget,
		code: CodeOperationFailed, diagnostic: DiagnosticResourceLimit,
	})
	if ctx != nil && ctx.Err() != nil {
		result.stage = StageCancellation
		result.diagnostic = DiagnosticCancellation
		result.cancellationDeadline = errors.Is(ctx.Err(), context.DeadlineExceeded)
	}
	if cleanupIncomplete {
		result.appendWarning(WarningCleanupIncomplete)
	}
	return result
}
