// Package pcv3ranges owns immutable, compact canonical recovery evidence.
package pcv3ranges

import (
	"errors"
	"iter"
	"sort"
	"unsafe"
)

const (
	RecordSize         uint64 = 1 << 20
	pageBytes                 = 4096
	pageRecords               = pageBytes * 4
	DefaultBudgetBytes uint64 = 8 << 20
)

var (
	ErrBudget  = errors.New("pcv3: recovery map resource budget exhausted")
	ErrInvalid = errors.New("pcv3: invalid recovery map")
)

type State uint8

const (
	Verified State = iota + 1
	Unverified
	Missing
)

type Range struct {
	Index, Start, End uint64
	State             State
}
type Summary struct{ Verified, Unverified, Missing, RecoveredBytes uint64 }

// Budget accounts actual backing capacities, including simultaneous old and new
// index arrays during growth. It belongs to one sequential recovery operation.
type Budget struct{ limit, used uint64 }

func NewBudget(limit uint64) *Budget { return &Budget{limit: limit} }
func (b *Budget) Used() uint64       { return b.used }
func (b *Budget) acquire(n uint64) error {
	if n > b.limit-b.used {
		return ErrBudget
	}
	b.used += n
	return nil
}
func (b *Budget) release(n uint64) { b.used -= n }

type block struct {
	end    uint64
	state  State
	packed *[pageBytes]byte
}
type Map struct {
	length, count, prefix uint64
	blocks                []block
	summary               Summary
}
type Builder struct {
	m       Map
	budget  *Budget
	scratch *[pageBytes]byte
	filled  int
	uniform State
	sealed  bool
	charged uint64
}

func NewBuilder(length uint64, budget *Budget) (*Builder, error) {
	if budget == nil {
		budget = NewBudget(DefaultBudgetBytes)
	}
	if err := budget.acquire(pageBytes); err != nil {
		return nil, err
	}
	count := length / RecordSize
	if length%RecordSize != 0 {
		count++
	}
	return &Builder{m: Map{length: length, count: count}, budget: budget, scratch: new([pageBytes]byte), charged: pageBytes}, nil
}

func (b *Builder) Append(s State) error {
	if b == nil || b.sealed || b.scratch == nil || b.m.prefix >= b.m.count || s < Verified || s > Missing {
		return ErrInvalid
	}
	if b.filled == pageRecords {
		if err := b.flush(); err != nil {
			return err
		}
	}
	if b.filled == 0 {
		b.uniform = s
	} else if b.uniform != s {
		b.uniform = 0
	}
	shift := uint((b.filled % 4) * 2)
	b.scratch[b.filled/4] |= byte(s) << shift
	b.filled++
	b.m.prefix++
	start := (b.m.prefix - 1) * RecordSize
	size := RecordSize
	if b.m.length-start < size {
		size = b.m.length - start
	}
	switch s {
	case Verified:
		b.m.summary.Verified++
		b.m.summary.RecoveredBytes += size
	case Unverified:
		b.m.summary.Unverified++
		b.m.summary.RecoveredBytes += size
	case Missing:
		b.m.summary.Missing++
	}
	return nil
}

func (b *Builder) flush() error {
	if b.filled == 0 {
		return nil
	}
	if b.uniform != 0 && len(b.m.blocks) > 0 && b.m.blocks[len(b.m.blocks)-1].state == b.uniform {
		b.m.blocks[len(b.m.blocks)-1].end = b.m.prefix
	} else {
		if len(b.m.blocks) == cap(b.m.blocks) {
			capacity := cap(b.m.blocks) * 2
			if capacity == 0 {
				capacity = 4
			}
			size := uint64(capacity) * uint64(unsafe.Sizeof(block{}))
			if err := b.budget.acquire(size); err != nil {
				return err
			}
			replacement := make([]block, len(b.m.blocks), capacity)
			copy(replacement, b.m.blocks)
			old := uint64(cap(b.m.blocks)) * uint64(unsafe.Sizeof(block{}))
			b.budget.release(old)
			b.charged += size - old
			b.m.blocks = replacement
		}
		entry := block{end: b.m.prefix, state: b.uniform}
		if b.uniform == 0 {
			if err := b.budget.acquire(pageBytes); err != nil {
				return err
			}
			entry.packed = new([pageBytes]byte)
			*entry.packed = *b.scratch
			b.charged += pageBytes
		}
		b.m.blocks = append(b.m.blocks, entry)
	}
	clear(b.scratch[:])
	b.filled = 0
	b.uniform = 0
	return nil
}

func (b *Builder) FinishMissingTail() error {
	if b == nil || b.sealed || b.scratch == nil {
		return ErrInvalid
	}
	if err := b.flush(); err != nil {
		return err
	}
	b.m.summary.Missing += b.m.count - b.m.prefix
	b.sealed = true // prevents appending into the implicit tail
	return nil
}

func (b *Builder) Seal() (*Map, error) {
	if b == nil || b.scratch == nil {
		return nil, ErrInvalid
	}
	if !b.sealed && b.m.prefix != b.m.count {
		return nil, ErrInvalid
	}
	if err := b.flush(); err != nil {
		return nil, err
	}
	b.budget.release(pageBytes)
	b.charged -= pageBytes
	b.scratch = nil
	b.sealed = true
	m := b.m
	b.m = Map{}
	b.charged = 0
	return &m, nil
}

// Close abandons an unsealed builder; sealed maps retain their own immutable storage.
func (b *Builder) Close() {
	if b == nil {
		return
	}
	b.budget.release(b.charged)
	b.charged = 0
	b.scratch = nil
	b.m = Map{}
	b.sealed = true
}

func (m *Map) Count() uint64 {
	if m == nil {
		return 0
	}
	return m.count
}

func (m *Map) PlaintextLength() uint64 {
	if m == nil {
		return 0
	}
	return m.length
}

func (m *Map) Summary() Summary {
	if m == nil {
		return Summary{}
	}
	return m.summary
}

func (m *Map) StateAt(i uint64) (State, bool) {
	if m == nil || i >= m.count {
		return 0, false
	}
	if i >= m.prefix {
		return Missing, true
	}
	n := sort.Search(len(m.blocks), func(n int) bool { return m.blocks[n].end > i })
	entry := m.blocks[n]
	if entry.state != 0 {
		return entry.state, true
	}
	start := uint64(0)
	if n > 0 {
		start = m.blocks[n-1].end
	}
	offset := i - start
	return State((entry.packed[offset/4] >> uint((offset%4)*2)) & 3), true
}

func (m *Map) At(i uint64) (Range, bool) {
	s, ok := m.StateAt(i)
	if !ok {
		return Range{}, false
	}
	start := i * RecordSize
	end := m.length
	if m.length-start > RecordSize {
		end = start + RecordSize
	}
	return Range{Index: i, Start: start, End: end, State: s}, true
}

// All derives independent canonical descriptors with a forward-only cursor.
func (m *Map) All() iter.Seq[Range] { return m.walk(false) }

// Present skips missing runs, including the implicit missing tail.
func (m *Map) Present() iter.Seq[Range] { return m.walk(true) }

func (m *Map) walk(presentOnly bool) iter.Seq[Range] {
	return func(yield func(Range) bool) {
		if m == nil {
			return
		}
		limit := m.count
		if presentOnly {
			limit = m.prefix
		}
		blockIndex := 0
		blockStart := uint64(0)
		for i := uint64(0); i < limit; i++ {
			state := Missing
			if i < m.prefix {
				for i >= m.blocks[blockIndex].end {
					blockStart = m.blocks[blockIndex].end
					blockIndex++
				}
				entry := m.blocks[blockIndex]
				state = entry.state
				if state == 0 {
					offset := i - blockStart
					state = State((entry.packed[offset/4] >> uint((offset%4)*2)) & 3)
				}
				if presentOnly && state == Missing {
					if entry.state == Missing {
						i = entry.end - 1
					}
					continue
				}
			}
			start := i * RecordSize
			end := m.length
			if m.length-start > RecordSize {
				end = start + RecordSize
			}
			if !yield(Range{Index: i, Start: start, End: end, State: state}) {
				return
			}
		}
	}
}
