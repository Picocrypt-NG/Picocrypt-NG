//go:build !linux || android

package pcv3publication

import "os"

func leasedCleanupAvailable() bool { return false }

// Other platforms retain their existing staging contract until they have a
// native, verified interprocess lease backend.
func acquireStageLease(*os.File) (*os.File, error) { return nil, nil }
