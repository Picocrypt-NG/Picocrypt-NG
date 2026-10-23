//go:build !windows

package fileops

import "testing"

func nativeFileopsDirectorySyncSupported(t testing.TB, _ string) bool {
	t.Helper()
	return true
}
