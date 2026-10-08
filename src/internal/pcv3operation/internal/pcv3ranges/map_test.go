package pcv3ranges

import (
	"errors"
	"testing"
)

func TestMapMissingTailAndPartialBounds(t *testing.T) {
	b, err := NewBuilder(68719476737, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Append(Verified); err != nil {
		t.Fatal(err)
	}
	if err = b.FinishMissingTail(); err != nil {
		t.Fatal(err)
	}
	m, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if m.Count() != 65537 || m.Summary().Verified != 1 || m.Summary().Missing != 65536 || m.Summary().RecoveredBytes != 1048576 {
		t.Fatalf("bad summary: %+v", m.Summary())
	}
	r, ok := m.At(65536)
	if !ok || r.Start != 68719476736 || r.End != 68719476737 || r.State != Missing {
		t.Fatalf("bad tail: %+v", r)
	}
	if b.Append(Unverified) == nil {
		t.Fatal("sealed builder mutated")
	}
	if _, err = b.Seal(); err == nil {
		t.Fatal("sealed twice")
	}
}

func TestMapUniformPagesCoalesceAndAlternatingStatesRemainPacked(t *testing.T) {
	for _, alternating := range []bool{false, true} {
		budget := NewBudget(32768)
		b, err := NewBuilder(65536*1048576, budget)
		if err != nil {
			t.Fatal(err)
		}
		for i := range 65536 {
			s := Verified
			if alternating && i%2 == 1 {
				s = Unverified
			}
			if err = b.Append(s); err != nil {
				t.Fatal(err)
			}
		}
		m, err := b.Seal()
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range []uint64{0, 1, 16383, 16384, 65535} {
			s, ok := m.StateAt(i)
			want := Verified
			if alternating && i%2 == 1 {
				want = Unverified
			}
			if !ok || s != want {
				t.Fatalf("state %d=%v", i, s)
			}
		}
		if !alternating && budget.Used() > 1024 {
			t.Fatalf("uniform retained %d bytes", budget.Used())
		}
	}
}

func TestMapBudgetChargesScratchAndGrowthBeforeAllocation(t *testing.T) {
	budget := NewBudget(4096)
	b, err := NewBuilder(2*1048576, budget)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Append(Verified); err != nil {
		t.Fatal(err)
	}
	if err = b.Append(Unverified); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Seal(); !errors.Is(err, ErrBudget) {
		t.Fatalf("capacity refusal: %v", err)
	}
	b.Close()
	if budget.Used() != 0 {
		t.Fatalf("leaked charge: %d", budget.Used())
	}
	if _, err = NewBuilder(1, NewBudget(4095)); !errors.Is(err, ErrBudget) {
		t.Fatalf("scratch not charged: %v", err)
	}
}

func TestMapMaximumLengthAndIncompleteSeal(t *testing.T) {
	b, err := NewBuilder(^uint64(0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Seal(); err == nil {
		t.Fatal("incomplete accepted")
	}
	if err = b.FinishMissingTail(); err != nil {
		t.Fatal(err)
	}
	m, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := m.At(17592186044415)
	if !ok || r.Start != 18446744073708503040 || r.End != 18446744073709551615 {
		t.Fatalf("overflow: %+v", r)
	}
}

func TestMapLateDamagePreservesCoalescedPrefixAndIndependentValues(t *testing.T) {
	b, err := NewBuilder(32771*1048576, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 32768 {
		if err = b.Append(Verified); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []State{Missing, Unverified, Verified} {
		if err = b.Append(s); err != nil {
			t.Fatal(err)
		}
	}
	m, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	want := []State{Verified, Missing, Unverified, Verified}
	for i, s := range want {
		r, ok := m.At(uint64(32767 + i))
		if !ok || r.State != s {
			t.Fatalf("late state %d: %+v", i, r)
		}
		r.State = Missing
	}
	summary := m.Summary()
	if summary.Verified != 32769 || summary.Unverified != 1 || summary.Missing != 1 || summary.RecoveredBytes != 34361835520 {
		t.Fatalf("incorrect summary %+v", summary)
	}
	visited := 0
	for r := range m.Present() {
		if r.State == Missing {
			t.Fatal("missing emitted")
		}
		visited++
	}
	if visited != 32770 {
		t.Fatalf("present visit count %d", visited)
	}
}

func TestMapBudgetSharesCandidateCapacityAndIncludesIndexReplacement(t *testing.T) {
	budget := NewBudget(4200)
	b, err := NewBuilder(5*16384*1048576, budget)
	if err != nil {
		t.Fatal(err)
	}
	for page := range 5 {
		s := Verified
		if page%2 == 1 {
			s = Missing
		}
		for range 16384 {
			if err = b.Append(s); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = b.Seal(); !errors.Is(err, ErrBudget) {
		t.Fatalf("index replacement escaped budget: %v", err)
	}
	b.Close()
	first, err := NewBuilder(1, budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewBuilder(1, budget); !errors.Is(err, ErrBudget) {
		t.Fatalf("candidate scratch not shared: %v", err)
	}
	first.Close()
}
