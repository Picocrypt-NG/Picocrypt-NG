//go:build !windows

package cli

import "testing"

func nativeCLIDirectorySyncSupported(t testing.TB, _ string) bool {
	t.Helper()
	return true
}
