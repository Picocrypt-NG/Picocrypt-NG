//go:build !windows

package pcv3corpus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRefusesIntermediateSymlinkEscape(t *testing.T) {
	root := writeTestCorpus(t)
	outside := t.TempDir()
	writeTestFile(t, outside, "nfc.json", positiveFixture)

	if err := os.RemoveAll(filepath.Join(root, "positive")); err != nil {
		t.Fatalf("remove synthetic positive directory: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "positive")); err != nil {
		t.Fatalf("create required intermediate symlink fixture: %v", err)
	}

	_, err := Load(root, testCustodyID)
	assertRefusal(t, err, RefusalSymlink)
}
