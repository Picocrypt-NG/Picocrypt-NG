package pcv3operation

import "Picocrypt-NG/internal/pcv3operation/internal/pcv3"

func desktopCleanupFailure() *Result {
	result := closedFailure(pcv3.OutcomeOperationFailed, pcv3.StageOutputPublication, pcv3.CodeOperationFailed, DiagnosticCoreFailure)
	result.appendWarning(WarningCleanupIncomplete)
	return result
}
