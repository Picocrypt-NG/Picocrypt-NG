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
		if result.CompletionClass() == pcv3operation.CompletionClean {
			return errors.New("PCV3 stdout output capability is unavailable")
		}
		return nil
	}
	action := followUp.StreamTo(ctx, os.Stdout)
	if action.CleanupIncomplete() {
		result.WithCleanupWarning()
	}
	if action.Code() != pcv3operation.OutputActionSaved && action.Code() != pcv3operation.OutputActionSavedCleanupIncomplete {
		return errors.New("PCV3 stdout transport failed; source files were preserved")
	}
	return nil
}
