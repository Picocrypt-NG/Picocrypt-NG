//go:build !windows

package pcv3operation

import "testing"

func nativeOperationDirectorySyncSupported(t testing.TB, _ string) bool {
	t.Helper()
	return true
}
