//go:build !windows

package pcv3publication

import "testing"

func nativeDirectorySyncSupported(t testing.TB, _ string) bool {
	t.Helper()
	return true
}
