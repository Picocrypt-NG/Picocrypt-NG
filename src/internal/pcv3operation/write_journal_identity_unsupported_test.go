//go:build !linux && !android

package pcv3operation

import "testing"

func requireWriteJournalBeforeKDF(t *testing.T, _ string) {
	t.Helper()
	t.Fatal("unsupported journal backend reached KDF")
}
