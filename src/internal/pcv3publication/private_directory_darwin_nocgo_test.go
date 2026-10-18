//go:build darwin && !cgo

package pcv3publication

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinWithoutCGORefusesBeforeFilesystemEffects(t *testing.T) {
	parent := t.TempDir()
	stage, err := Create(filepath.Join(parent, "output"), nil, PolicyNoReplace)
	if stage != nil || err == nil {
		t.Fatal("Darwin without fd ACL backend accepted plaintext custody")
	}
	if result := requireResultError(t, err); result.Code() != CodePolicyUnsupported {
		t.Fatalf("backend refusal = %v", result)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unsupported backend left filesystem effects: %v %v", entries, err)
	}
}
