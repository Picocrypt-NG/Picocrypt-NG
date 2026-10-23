//go:build !windows

package pcv3

import "testing"

func nativeDirectorySyncSupported(t testing.TB, _ string) bool {
	t.Helper()
	return true
}
