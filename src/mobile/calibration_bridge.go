//go:build pcv3_calibration

package mobile

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
)

// StartPCV3Calibration starts the default-excluded fixed-public-data
// calibration probe. It accepts no input and returns only the ordinary
// Go-owned operation object with bounded terminal presentation state.
func StartPCV3Calibration() *PCV3StartResult {
	operation := startPCV3Operation()
	if operation == nil {
		return newPCV3StartResult(pcv3BridgeOperationUnavailable, nil)
	}
	ctx, ok := getContext(operation.id)
	if !ok {
		completePCV3PresentationForOperation(
			operation,
			calibrationPresentation(pcv3credential.CalibrationProbeStatusFailed),
		)
		return newPCV3StartResult("", operation)
	}
	go runPCV3Calibration(ctx, operation)
	return newPCV3StartResult("", operation)
}

func runPCV3Calibration(ctx context.Context, operation *PCV3Operation) {
	status := pcv3credential.CalibrationProbeStatusFailed
	defer func() {
		if recover() != nil {
			status = pcv3credential.CalibrationProbeStatusFailed
		}
		completePCV3PresentationForOperation(operation, calibrationPresentation(status))
	}()
	status = pcv3credential.RunCalibrationProbe(ctx)
}

func calibrationPresentation(
	status pcv3credential.CalibrationProbeStatus,
) pcv3operation.Presentation {
	spec := pcv3operation.PresentationSpec{
		Outcome:    pcv3.OutcomeOperationFailed,
		Stage:      pcv3.StageCredentialPolicy,
		Code:       pcv3.CodeOperationFailed,
		Diagnostic: pcv3operation.DiagnosticCoreFailure,
	}
	switch status {
	case pcv3credential.CalibrationProbeStatusCompleted:
		spec.Outcome = pcv3.OutcomeSuccess
		spec.Stage = pcv3.StageNone
		spec.Code = pcv3.CodeSuccess
		spec.Diagnostic = pcv3operation.DiagnosticNone
	case pcv3credential.CalibrationProbeStatusCancelled:
		spec.Stage = pcv3.StageCancellation
		spec.Diagnostic = pcv3operation.DiagnosticCancellation
	case pcv3credential.CalibrationProbeStatusUnknown,
		pcv3credential.CalibrationProbeStatusFailed:
	}
	presentation, err := pcv3operation.NewPresentation(spec)
	if err != nil {
		return fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	return presentation
}
