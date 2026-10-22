//go:build !arm && !386

package argon2

import "testing"

func TestContiguousWorkspacePreservesDirectBlockAddresses(t *testing.T) {
	workspace := newWorkspace(8196)
	defer wipeBlocks(workspace)
	if len(workspace) != 8196 || cap(workspace) != 8196 {
		t.Fatalf("workspace len/cap = %d/%d, want 8196/8196 blocks", len(workspace), cap(workspace))
	}
	for _, index := range []uint32{0, 4095, 4096, 8195} {
		if workspace.at(index) != &workspace[index] {
			t.Fatalf("logical block %d does not address its contiguous block", index)
		}
	}
}
