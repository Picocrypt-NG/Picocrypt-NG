//go:build !linux

package pcv3publication

import "os"

func existingMoveIdentityMatches(os.FileInfo, uint64, uint64) bool { return false }
