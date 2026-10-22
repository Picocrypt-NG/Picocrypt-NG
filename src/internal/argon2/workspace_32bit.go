//go:build arm || 386

package argon2

const (
	workspaceChunkShift  = 12
	workspaceChunkBlocks = uint32(1 << workspaceChunkShift)
	workspaceChunkMask   = workspaceChunkBlocks - 1
)

// Separate 4 MiB allocations avoid a contiguous 1 GiB reservation on 32-bit.
type blockWorkspace [][]block

func newWorkspace(memory uint32) blockWorkspace {
	count := memory / workspaceChunkBlocks
	if memory%workspaceChunkBlocks != 0 {
		count++
	}
	workspace := make(blockWorkspace, count)
	for i := range workspace {
		size := min(memory, workspaceChunkBlocks)
		workspace[i] = make([]block, size)
		memory -= size
	}
	return workspace
}

func (workspace blockWorkspace) at(index uint32) *block {
	return &workspace[index>>workspaceChunkShift][index&workspaceChunkMask]
}

func (workspace blockWorkspace) clear() {
	for _, chunk := range workspace {
		clear(chunk)
	}
}
