package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"os"
)

// Consume retained output before rendering so cleanup warnings describe the
// complete transport. StreamTo keeps the plaintext/ciphertext one-shot policy.
func finishPCV3CLIStdout(ctx context.Context, result pcv3CLIResult, useStdout bool) error {
	if !useStdout || result == nil {
		return nil
	}
	followUp := result.OutputFollowUp()
	if followUp == nil {
		if result.CompletionClass() == pcv3operation.CompletionClean ||
			result.CompletionClass() == pcv3operation.CompletionStreamPending {
			return errors.New("PCV3 stdout output capability is unavailable")
		}
		return nil
	}
	action := followUp.StreamTo(ctx, os.Stdout)
	return finishPCV3CLIStdoutAction(result, action.Code(), action.CleanupIncomplete(), action.CleanupDurabilityUncertain())
}

func finishPCV3CLIStdoutAction(result pcv3CLIResult, code pcv3operation.OutputActionCode, incomplete, uncertain bool) error {
	if incomplete {
		result.WithCleanupWarning()
	}
	if uncertain {
		result.WithCleanupDurabilityWarning()
	}
	if code != pcv3operation.OutputActionSaved && code != pcv3operation.OutputActionSavedCleanupIncomplete &&
		code != pcv3operation.OutputActionSavedCleanupDurabilityUncertain {
		return errors.New("PCV3 stdout transport failed; source files were preserved")
	}
	return nil
}
