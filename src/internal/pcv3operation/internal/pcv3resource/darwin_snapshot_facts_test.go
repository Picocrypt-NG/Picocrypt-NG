package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"testing"
)

func TestDarwinKDFAdmissionCanReuseReleasedGoHeap(t *testing.T) {
	const (
		mib = uint64(1 << 20)
		gib = 1024 * mib
	)
	facts := darwinSnapshotFacts{
		observed:          true,
		freePages:         64 * mib / 4096,
		inactivePages:     512 * mib / 4096,
		internalPages:     256 * mib / 4096,
		pageSize:          4096,
		physicalFootprint: 64 * mib,
		residentBytes:     gib + 64*mib,
		reusableBytes:     gib,
		releasedHeapBytes: gib,
		virtualSize:       4 * gib,
	}
	tests := []struct {
		name      string
		mutate    func(*darwinSnapshotFacts)
		headroom  uint64
		admission pcv3credential.KDFAdmission
	}{
		{
			name:      "released workspace supports the next 1 GiB derivation",
			headroom:  gib + 64*mib,
			admission: pcv3credential.KDFAdmissionGranted,
		},
		{
			name:      "reusable memory is bounded by Go heap releases",
			mutate:    func(f *darwinSnapshotFacts) { f.releasedHeapBytes = 512 * mib },
			headroom:  576 * mib,
			admission: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:      "inconsistent reusable ledger supplies no credit",
			mutate:    func(f *darwinSnapshotFacts) { f.reusableBytes = f.residentBytes + f.pageSize },
			headroom:  320 * mib,
			admission: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name: "address space still bounds available memory",
			mutate: func(f *darwinSnapshotFacts) {
				f.addressLimited = true
				f.addressLimit = f.virtualSize + gib
			},
			headroom:  gib,
			admission: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sample := facts
			if test.mutate != nil {
				test.mutate(&sample)
			}
			snapshot := kdfSnapshotFromDarwinFacts(sample)
			if snapshot.state != snapshotStateReady || snapshot.effectiveAvailable != test.headroom {
				t.Fatalf("state/headroom = %v/%d; want ready/%d", snapshot.state, snapshot.effectiveAvailable, test.headroom)
			}
			if snapshot.codeOwnedReserve != 64*mib {
				t.Fatalf("reserve = %d; want unchanged 64 MiB", snapshot.codeOwnedReserve)
			}
			admitter := newAdmitter(&scriptedSnapshotProvider{snapshots: []Snapshot{snapshot}})
			got, err := admitter.AdmitKDF(t.Context(), pcv3credential.KDFProfile{MemoryKiB: 1_048_576})
			if err != nil || got != test.admission {
				t.Fatalf("production KDF admission = %v/%v; want %v/nil", got, err, test.admission)
			}
		})
	}

	if snapshot := snapshotFromDarwinFacts(facts); snapshot.effectiveAvailable != 64*mib {
		t.Fatalf("ordinary working-memory snapshot credited reusable heap: %d", snapshot.effectiveAvailable)
	}
}
