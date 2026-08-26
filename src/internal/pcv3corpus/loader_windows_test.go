//go:build windows

package pcv3corpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLoadRefusesIntermediateJunctionEscape(t *testing.T) {
	root := writeTestCorpus(t)
	outside := t.TempDir()
	writeTestFile(t, outside, "nfc.json", positiveFixture)

	junction := filepath.Join(root, "positive")
	if err := os.RemoveAll(junction); err != nil {
		t.Fatalf("remove synthetic positive directory: %v", err)
	}
	if err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).Run(); err != nil {
		t.Fatal("create required directory-junction fixture")
	}

	_, err := Load(root, testCustodyID)
	assertRefusal(t, err, RefusalSymlink)
}
