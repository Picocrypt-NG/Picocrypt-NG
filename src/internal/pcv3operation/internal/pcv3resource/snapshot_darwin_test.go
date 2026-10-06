//go:build darwin && cgo

package pcv3resource

import (
	"math"
	"testing"
)

const darwinTestMiB = uint64(1 << 20)

func validDarwinSnapshotFacts() darwinSnapshotFacts {
	return darwinSnapshotFacts{
		observed:          true,
		freePages:         1_048_576,
		pageSize:          4_096,
		physicalFootprint: 384 * darwinTestMiB,
		virtualSize:       1_024 * darwinTestMiB,
	}
}

func TestDarwinSnapshotNormalizationUsesMinimumApplicableHeadroom(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*darwinSnapshotFacts)
		want   uint64
	}{
		{
			name: "immediately free physical pages",
			want: 4_096 * darwinTestMiB,
		},
		{
			name: "finite process address-space headroom",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.addressLimited = true
				facts.addressLimit = 3_072 * darwinTestMiB
			},
			want: 2_048 * darwinTestMiB,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := validDarwinSnapshotFacts()
			if test.mutate != nil {
				test.mutate(&facts)
			}

			snapshot := snapshotFromDarwinFacts(facts)
			if snapshot.source != snapshotSourceDarwin || snapshot.state != snapshotStateReady {
				t.Fatalf("snapshot source/state = %v/%v; want Darwin/ready", snapshot.source, snapshot.state)
			}
			if snapshot.effectiveAvailable != test.want {
				t.Fatalf("effective available = %d; want checked minimum %d", snapshot.effectiveAvailable, test.want)
			}
			if snapshot.platformThreshold != 0 {
				t.Fatalf("platform threshold = %d; want zero for conservative desktop headroom", snapshot.platformThreshold)
			}
			if snapshot.codeOwnedReserve != 384*darwinTestMiB {
				t.Fatalf("code-owned reserve = %d; want same-snapshot physical footprint %d", snapshot.codeOwnedReserve, 384*darwinTestMiB)
			}
		})
	}
}

func TestDarwinSnapshotNormalizationFailsClosedOnUncertainFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*darwinSnapshotFacts)
	}{
		{
			name: "native API failure",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.observed = false
			},
		},
		{
			name: "zero free page count",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.freePages = 0
			},
		},
		{
			name: "zero native page size",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.pageSize = 0
			},
		},
		{
			name: "free-page multiplication overflow",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.freePages = math.MaxUint64
				facts.pageSize = 2
			},
		},
		{
			name: "zero current-process physical footprint",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.physicalFootprint = 0
			},
		},
		{
			name: "zero process virtual size",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.virtualSize = 0
			},
		},
		{
			name: "active address limit is zero",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.addressLimited = true
				facts.addressLimit = 0
			},
		},
		{
			name: "virtual size equals finite address limit",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.addressLimited = true
				facts.addressLimit = facts.virtualSize
			},
		},
		{
			name: "virtual size exceeds finite address limit",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.addressLimited = true
				facts.addressLimit = facts.virtualSize - 1
			},
		},
		{
			name: "address limit value without active limit",
			mutate: func(facts *darwinSnapshotFacts) {
				facts.addressLimit = 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := validDarwinSnapshotFacts()
			test.mutate(&facts)
			snapshot := snapshotFromDarwinFacts(facts)
			if snapshot.source != snapshotSourceDarwin || snapshot.state != snapshotStateUnknown {
				t.Fatalf("snapshot source/state = %v/%v; want Darwin/unknown", snapshot.source, snapshot.state)
			}
			if snapshot.effectiveAvailable != 0 || snapshot.platformThreshold != 0 || snapshot.codeOwnedReserve != 0 {
				t.Fatalf("failed snapshot exposed facts: available=%d threshold=%d reserve=%d", snapshot.effectiveAvailable, snapshot.platformThreshold, snapshot.codeOwnedReserve)
			}
		})
	}
}
