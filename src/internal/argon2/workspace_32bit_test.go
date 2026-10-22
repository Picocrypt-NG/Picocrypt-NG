//go:build arm || 386

package argon2

import (
	"bytes"
	"testing"

	upstream "golang.org/x/crypto/argon2"
)

func Test32BitWorkspaceBoundsAllocationsAtFourMiB(t *testing.T) {
	h0 := initHash([]byte("password"), []byte("somesalt"), nil, nil, 2, 8196, 3, 65, argon2id)
	workspace := initBlocks(&h0, 8196, 3)
	defer wipeBlocks(workspace)
	wantSizes := []int{4096, 4096, 4}
	if len(workspace) != len(wantSizes) {
		t.Fatalf("workspace allocations = %d, want %d to bound contiguous allocation size", len(workspace), len(wantSizes))
	}
	for i, want := range wantSizes {
		if len(workspace[i]) != want {
			t.Fatalf("allocation %d length = %d, want %d blocks", i, len(workspace[i]), want)
		}
		if cap(workspace[i]) != want {
			t.Fatalf("allocation %d capacity = %d, want %d blocks", i, cap(workspace[i]), want)
		}
	}
	if &workspace[0][0] == &workspace[1][0] || &workspace[1][0] == &workspace[2][0] {
		t.Fatal("workspace allocations alias")
	}
}

func Test32BitWorkspaceIndexesCrossChunkBoundaries(t *testing.T) {
	workspace := newWorkspace(8196)
	defer wipeBlocks(workspace)
	for _, tc := range []struct {
		index uint32
		chunk int
		block int
	}{
		{0, 0, 0},
		{4095, 0, 4095},
		{4096, 1, 0},
		{8191, 1, 4095},
		{8192, 2, 0},
		{8195, 2, 3},
	} {
		if workspace.at(tc.index) != &workspace[tc.chunk][tc.block] {
			t.Fatalf("logical block %d addresses the wrong allocation or offset", tc.index)
		}
		workspace.at(tc.index)[127] = uint64(tc.index) + 1
		if workspace[tc.chunk][tc.block][127] != uint64(tc.index)+1 {
			t.Fatalf("logical block %d did not update its owned block", tc.index)
		}
	}
}

func Test32BitCrossChunkDerivationClearsEveryAllocationAndOwnsOutput(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      int
		reference func([]byte, []byte, uint32, uint32, uint8, uint32) []byte
	}{
		{"argon2i", argon2i, upstream.Key},
		{"argon2id", argon2id, upstream.IDKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			password, salt := []byte("password"), []byte("somesalt")
			want := tc.reference(password, salt, 2, 8197, 3, 65)
			var original blockWorkspace
			defer func() { wipeBlocks(original) }()
			key := deriveKey(tc.mode, password, salt, nil, nil, 2, 8197, 3, 65, func(workspace blockWorkspace) {
				// Keep the inner allocations even if cleanup drops their descriptors.
				original = append(blockWorkspace(nil), workspace...)
				if len(original) != 3 {
					t.Fatalf("derivation allocations = %d, want 3", len(original))
				}
				for i, want := range []int{4096, 4096, 4} {
					if len(original[i]) != want || cap(original[i]) != want {
						t.Fatalf("derivation allocation %d len/cap = %d/%d, want %d/%d", i, len(original[i]), cap(original[i]), want, want)
					}
				}
				for _, index := range []uint32{0, 1, 2732, 2733, 5464, 5465} {
					if *workspace.at(index) == (block{}) {
						t.Fatalf("initialized lane block %d is empty", index)
					}
				}
			})
			if !bytes.Equal(key, want) {
				t.Fatalf("cross-chunk key = %x, want independent upstream %x", key, want)
			}
			for chunkIndex, chunk := range original {
				for blockIndex := range chunk {
					if chunk[blockIndex] != (block{}) {
						t.Fatalf("allocation %d block %d remains nonzero", chunkIndex, blockIndex)
					}
				}
			}
			for _, chunk := range original {
				for b := range chunk {
					for w := range chunk[b] {
						chunk[b][w] = ^uint64(0)
					}
				}
			}
			if !bytes.Equal(key, want) {
				t.Fatal("returned key aliases a workspace allocation")
			}
		})
	}
}
