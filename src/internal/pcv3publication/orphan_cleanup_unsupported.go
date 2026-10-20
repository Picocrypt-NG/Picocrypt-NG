//go:build !linux || android

package pcv3publication

import (
	"errors"
	"os"
)

// CleanupOrphanedStages requires a native desktop interprocess lease backend.
// Android retains its separate app-private legacy recovery contract.
func CleanupOrphanedStages(string, []*os.File) (CleanupJournalState, error) {
	return CleanupJournalIncomplete, errors.Join(ErrCleanupIncomplete, errors.ErrUnsupported)
}
