//go:build !windows

package ui

import "testing"

func nativeUIDirectorySyncSupported(t testing.TB, _ string) bool {
	t.Helper()
	return true
}
