package pcv3resource

import "math"

type darwinSnapshotFacts struct {
	observed          bool
	freePages         uint64
	inactivePages     uint64
	internalPages     uint64
	pageSize          uint64
	physicalFootprint uint64
	residentBytes     uint64
	reusableBytes     uint64
	releasedHeapBytes uint64
	virtualSize       uint64
	addressLimit      uint64
	addressLimited    bool
}

func kdfSnapshotFromDarwinFacts(facts darwinSnapshotFacts) Snapshot {
	// Internal pages include active and inactive anonymous memory. Subtract
	// them to get a lower bound on inactive file-backed pages.
	// Raw free pages already include speculative pages; do not add them again.
	var reclaimablePages uint64
	if facts.inactivePages > facts.internalPages {
		reclaimablePages = facts.inactivePages - facts.internalPages
	}
	pages, ok := checkedAdd(facts.freePages, reclaimablePages)
	if !ok {
		return snapshotFromDarwinFacts(darwinSnapshotFacts{})
	}
	// Go uses MADV_FREE_REUSABLE on Darwin. A page can move between free
	// and reusable while the host and task are sampled. Use the larger
	// independent estimate so that a moved page supplies at most one credit.
	if facts.pageSize != 0 && facts.reusableBytes <= facts.residentBytes {
		reusablePages := min(facts.reusableBytes, facts.releasedHeapBytes) / facts.pageSize
		pages = max(pages, reusablePages)
	}
	facts.freePages = pages
	return snapshotFromDarwinFacts(facts)
}

func snapshotFromDarwinFacts(facts darwinSnapshotFacts) Snapshot {
	effective, reserve, ok := normalizeDarwinSnapshotFacts(facts)
	if !ok {
		return newSnapshot(snapshotSourceDarwin, snapshotStateUnknown, 0, 0, 0)
	}
	return newSnapshot(snapshotSourceDarwin, snapshotStateReady, effective, 0, reserve)
}

func normalizeDarwinSnapshotFacts(facts darwinSnapshotFacts) (uint64, uint64, bool) {
	if !facts.observed || facts.freePages == 0 || facts.pageSize == 0 ||
		facts.freePages > math.MaxUint64/facts.pageSize ||
		facts.physicalFootprint == 0 || facts.virtualSize == 0 ||
		(!facts.addressLimited && facts.addressLimit != 0) {
		return 0, 0, false
	}

	effective := facts.freePages * facts.pageSize
	if facts.addressLimited {
		if facts.addressLimit == 0 || facts.virtualSize >= facts.addressLimit {
			return 0, 0, false
		}
		effective = min(effective, facts.addressLimit-facts.virtualSize)
	}
	if effective == 0 {
		return 0, 0, false
	}
	return effective, facts.physicalFootprint, true
}
