//go:build darwin && cgo

package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
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

func TestDarwinKDFAdmissionCountsOnlyInactiveFileHeadroom(t *testing.T) {
	tests := []struct {
		name          string
		freePages     uint64
		inactivePages uint64
		internalPages uint64
		addressLimit  uint64
		wantAvailable uint64
		wantAdmission pcv3credential.KDFAdmission
	}{
		{
			name:          "recorded cached state admits unchanged one GiB profile",
			freePages:     254_907,
			inactivePages: 576_715,
			internalPages: 446_587,
			wantAvailable: 1_577_103_360,
			wantAdmission: pcv3credential.KDFAdmissionGranted,
		},
		{
			name:          "inactive anonymous pages supply no headroom",
			freePages:     254_907,
			inactivePages: 576_715,
			internalPages: 576_715,
			wantAvailable: 1_044_099_072,
			wantAdmission: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:          "active anonymous pages cannot underflow cache estimate",
			freePages:     254_907,
			inactivePages: 576_715,
			internalPages: 600_000,
			wantAvailable: 1_044_099_072,
			wantAdmission: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:          "finite address space still refuses cached headroom",
			freePages:     254_907,
			inactivePages: 576_715,
			internalPages: 446_587,
			addressLimit:  2_147_483_648,
			wantAvailable: 1_073_741_824,
			wantAdmission: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:          "exact profile plus footprint boundary grants",
			freePages:     254_907,
			inactivePages: 470_208,
			internalPages: 446_587,
			wantAvailable: 1_140_850_688,
			wantAdmission: pcv3credential.KDFAdmissionGranted,
		},
		{
			name:          "one page below profile plus footprint refuses",
			freePages:     254_907,
			inactivePages: 470_207,
			internalPages: 446_587,
			wantAvailable: 1_140_846_592,
			wantAdmission: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:          "inactive file headroom does not require positive free pages",
			inactivePages: 600_000,
			internalPages: 300_000,
			wantAvailable: 1_228_800_000,
			wantAdmission: pcv3credential.KDFAdmissionGranted,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := darwinSnapshotFacts{
				observed:          true,
				freePages:         test.freePages,
				inactivePages:     test.inactivePages,
				internalPages:     test.internalPages,
				pageSize:          4_096,
				physicalFootprint: 64 * darwinTestMiB,
				virtualSize:       1_024 * darwinTestMiB,
				addressLimit:      test.addressLimit,
				addressLimited:    test.addressLimit != 0,
			}
			snapshot := kdfSnapshotFromDarwinFacts(facts)
			if snapshot.state != snapshotStateReady || snapshot.effectiveAvailable != test.wantAvailable {
				t.Fatalf("KDF snapshot state/headroom = %v/%d; want ready/%d", snapshot.state, snapshot.effectiveAvailable, test.wantAvailable)
			}
			if snapshot.platformThreshold != 0 || snapshot.codeOwnedReserve != 64*darwinTestMiB {
				t.Fatalf("KDF threshold/reserve = %d/%d; want unchanged zero/64 MiB", snapshot.platformThreshold, snapshot.codeOwnedReserve)
			}
			admitter := newAdmitter(&scriptedSnapshotProvider{snapshots: []Snapshot{snapshot}})
			decision, err := admitter.AdmitKDF(context.Background(), pcv3credential.KDFProfile{MemoryKiB: 1_048_576})
			if err != nil || decision != test.wantAdmission {
				t.Fatalf("fixed one GiB admission = %v/%v; want %v/nil", decision, err, test.wantAdmission)
			}
		})
	}
}

func TestDarwinKDFHeadroomDoesNotBroadenZIPWorkingMemorySnapshot(t *testing.T) {
	facts := darwinSnapshotFacts{
		observed:          true,
		freePages:         32_768,
		inactivePages:     576_715,
		internalPages:     446_587,
		pageSize:          4_096,
		physicalFootprint: 64 * darwinTestMiB,
		virtualSize:       1_024 * darwinTestMiB,
	}
	snapshot := snapshotFromDarwinFacts(facts)
	if snapshot.state != snapshotStateReady || snapshot.effectiveAvailable != 134_217_728 {
		t.Fatalf("ZIP snapshot state/headroom = %v/%d; want unchanged ready/134217728", snapshot.state, snapshot.effectiveAvailable)
	}
	admitter := newAdmitter(&scriptedSnapshotProvider{snapshots: []Snapshot{snapshot}})
	if err := admitter.admitWorkingMemory(context.Background(), 256*darwinTestMiB); err != errWorkingMemoryInsufficient {
		t.Fatalf("ZIP working-memory admission = %v; want unchanged insufficient-headroom refusal", err)
	}
}

func TestDarwinKDFSnapshotFailsClosedOnOverflow(t *testing.T) {
	tests := []struct {
		name          string
		freePages     uint64
		inactivePages uint64
	}{
		{name: "free plus inactive file page addition", freePages: math.MaxUint64, inactivePages: 1},
		{name: "combined page multiplication", freePages: 1, inactivePages: math.MaxUint64 / 4_096},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := validDarwinSnapshotFacts()
			facts.freePages = test.freePages
			facts.inactivePages = test.inactivePages
			snapshot := kdfSnapshotFromDarwinFacts(facts)
			if snapshot.state != snapshotStateUnknown || snapshot.effectiveAvailable != 0 || snapshot.codeOwnedReserve != 0 {
				t.Fatalf("overflow snapshot state/headroom/reserve = %v/%d/%d; want unknown/0/0", snapshot.state, snapshot.effectiveAvailable, snapshot.codeOwnedReserve)
			}
		})
	}
}

func TestDarwinKDFSnapshotRejectsCancelledObservation(t *testing.T) {
	var provider kdfSnapshotProvider = darwinSnapshotProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		snapshot := provider.snapshotForKDF(ctx, pcv3credential.KDFProfile{MemoryKiB: 1_048_576})
		if snapshot.state != snapshotStateUnknown || snapshot.effectiveAvailable != 0 || snapshot.codeOwnedReserve != 0 {
			t.Fatalf("cancelled snapshot state/headroom/reserve = %v/%d/%d; want unknown/0/0", snapshot.state, snapshot.effectiveAvailable, snapshot.codeOwnedReserve)
		}
	}
}
