//go:build !arm && !386

package argon2

type blockWorkspace []block

func newWorkspace(memory uint32) blockWorkspace {
	return make(blockWorkspace, memory)
}

func (workspace blockWorkspace) at(index uint32) *block {
	return &workspace[index]
}

func (workspace blockWorkspace) clear() {
	clear(workspace)
}
