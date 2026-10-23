//go:build !windows

package pcv3recovery

import "testing"

func nativeRecoveryDirectorySyncSupported(t testing.TB, _ string) bool {
	t.Helper()
	return true
}
