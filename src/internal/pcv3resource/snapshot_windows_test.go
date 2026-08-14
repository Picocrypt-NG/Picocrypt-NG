//go:build windows

package pcv3resource

import (
	"math"
	"testing"
)

const windowsTestMiB = uint64(1 << 20)

func validWindowsSnapshotFacts() windowsSnapshotFacts {
	return windowsSnapshotFacts{
		observed: true,
		status: memoryStatusEx{
			memoryLoad:        50,
			totalPhysical:     16_384 * windowsTestMiB,
			availablePhysical: 4_096 * windowsTestMiB,
			totalCommit:       24_576 * windowsTestMiB,
			availableCommit:   6_144 * windowsTestMiB,
			totalVirtual:      131_072 * windowsTestMiB,
			availableVirtual:  8_192 * windowsTestMiB,
		},
		privateCommit: 256 * windowsTestMiB,
	}
}

func TestWindowsSnapshotNormalizationUsesMinimumApplicableHeadroom(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*windowsSnapshotFacts)
		want   uint64
	}{
		{
			name: "immediately available physical memory",
			want: 4_096 * windowsTestMiB,
		},
		{
			name: "available commit",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.status.availableCommit = 3_072 * windowsTestMiB
			},
			want: 3_072 * windowsTestMiB,
		},
		{
			name: "calling process virtual address headroom",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.status.availableVirtual = 2_048 * windowsTestMiB
			},
			want: 2_048 * windowsTestMiB,
		},
		{
			name: "active job memory headroom",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.jobLimited = true
				facts.jobHeadroom = 1_536 * windowsTestMiB
			},
			want: 1_536 * windowsTestMiB,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := validWindowsSnapshotFacts()
			if test.mutate != nil {
				test.mutate(&facts)
			}

			snapshot := snapshotFromWindowsFacts(facts)
			if snapshot.source != snapshotSourceWindows || snapshot.state != snapshotStateReady {
				t.Fatalf("snapshot source/state = %v/%v; want Windows/ready", snapshot.source, snapshot.state)
			}
			if snapshot.effectiveAvailable != test.want {
				t.Fatalf("effective available = %d; want checked minimum %d", snapshot.effectiveAvailable, test.want)
			}
			if snapshot.platformThreshold != 0 {
				t.Fatalf("platform threshold = %d; want zero for conservative desktop headroom", snapshot.platformThreshold)
			}
			if snapshot.codeOwnedReserve != 256*windowsTestMiB {
				t.Fatalf("code-owned reserve = %d; want same-snapshot private commit %d", snapshot.codeOwnedReserve, 256*windowsTestMiB)
			}
		})
	}
}

func TestWindowsJobHeadroomUsesEveryActiveFiniteLimit(t *testing.T) {
	tests := []struct {
		name    string
		facts   windowsJobMemoryFacts
		want    uint64
		limited bool
	}{
		{
			name:    "no memory limit",
			limited: false,
		},
		{
			name: "per-process commit limit",
			facts: windowsJobMemoryFacts{
				processLimited: true,
				processLimit:   2_048 * windowsTestMiB,
			},
			want:    1_792 * windowsTestMiB,
			limited: true,
		},
		{
			name: "job-wide commit limit",
			facts: windowsJobMemoryFacts{
				jobLimited:       true,
				jobLimit:         3_072 * windowsTestMiB,
				peakJobMemoryUse: 1_024 * windowsTestMiB,
			},
			want:    2_048 * windowsTestMiB,
			limited: true,
		},
		{
			name: "minimum of independent process and job limits",
			facts: windowsJobMemoryFacts{
				processLimited:   true,
				processLimit:     2_048 * windowsTestMiB,
				jobLimited:       true,
				jobLimit:         1_536 * windowsTestMiB,
				peakJobMemoryUse: 512 * windowsTestMiB,
			},
			want:    1_024 * windowsTestMiB,
			limited: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headroom, limited, ok := normalizeWindowsJobHeadroom(256*windowsTestMiB, test.facts)
			if !ok {
				t.Fatal("valid finite job facts were rejected")
			}
			if headroom != test.want || limited != test.limited {
				t.Fatalf("job headroom/limited = %d/%v; want %d/%v", headroom, limited, test.want, test.limited)
			}
		})
	}
}

func TestWindowsSnapshotNormalizationFailsClosedOnUncertainFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*windowsSnapshotFacts)
	}{
		{
			name: "native API failure",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.observed = false
			},
		},
		{
			name: "invalid memory load",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.status.memoryLoad = 101
			},
		},
		{
			name: "physical availability exceeds total",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.status.availablePhysical = facts.status.totalPhysical + 1
			},
		},
		{
			name: "commit availability exceeds total",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.status.availableCommit = facts.status.totalCommit + 1
			},
		},
		{
			name: "virtual availability exceeds address space",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.status.availableVirtual = facts.status.totalVirtual + 1
			},
		},
		{
			name: "zero current-process footprint",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.privateCommit = 0
			},
		},
		{
			name: "overflow-sized footprint exceeds finite commit limit",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.privateCommit = math.MaxUint64
			},
		},
		{
			name: "active job limit has no headroom",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.jobLimited = true
				facts.jobHeadroom = 0
			},
		},
		{
			name: "job headroom without active limit",
			mutate: func(facts *windowsSnapshotFacts) {
				facts.jobHeadroom = 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := validWindowsSnapshotFacts()
			test.mutate(&facts)
			snapshot := snapshotFromWindowsFacts(facts)
			if snapshot.source != snapshotSourceWindows || snapshot.state != snapshotStateUnknown {
				t.Fatalf("snapshot source/state = %v/%v; want Windows/unknown", snapshot.source, snapshot.state)
			}
			if snapshot.effectiveAvailable != 0 || snapshot.platformThreshold != 0 || snapshot.codeOwnedReserve != 0 {
				t.Fatalf("failed snapshot exposed facts: available=%d threshold=%d reserve=%d", snapshot.effectiveAvailable, snapshot.platformThreshold, snapshot.codeOwnedReserve)
			}
		})
	}
}

func TestWindowsJobHeadroomRejectsUnderflowOrAmbiguity(t *testing.T) {
	tests := []struct {
		name  string
		facts windowsJobMemoryFacts
	}{
		{
			name: "process limit equals private commit",
			facts: windowsJobMemoryFacts{
				processLimited: true,
				processLimit:   256 * windowsTestMiB,
			},
		},
		{
			name: "process limit below private commit",
			facts: windowsJobMemoryFacts{
				processLimited: true,
				processLimit:   255 * windowsTestMiB,
			},
		},
		{
			name: "job limit has missing usage",
			facts: windowsJobMemoryFacts{
				jobLimited: true,
				jobLimit:   2_048 * windowsTestMiB,
			},
		},
		{
			name: "job usage equals limit",
			facts: windowsJobMemoryFacts{
				jobLimited:       true,
				jobLimit:         2_048 * windowsTestMiB,
				peakJobMemoryUse: 2_048 * windowsTestMiB,
			},
		},
		{
			name: "overflow-sized usage exceeds finite job limit",
			facts: windowsJobMemoryFacts{
				jobLimited:       true,
				jobLimit:         2_048 * windowsTestMiB,
				peakJobMemoryUse: math.MaxUint64,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headroom, limited, ok := normalizeWindowsJobHeadroom(256*windowsTestMiB, test.facts)
			if ok || headroom != 0 || limited {
				t.Fatalf("ambiguous job facts returned headroom/limited/ok = %d/%v/%v; want 0/false/false", headroom, limited, ok)
			}
		})
	}
}
