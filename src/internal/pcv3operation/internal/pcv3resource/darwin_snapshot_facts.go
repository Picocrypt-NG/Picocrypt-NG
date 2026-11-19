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
	liveFreePages     uint64
	pageGrabs         uint64
	liveFreeObserved  bool
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
	// Go marks released heap pages MADV_FREE_REUSABLE. Keep a count of
	// reusable pages independently from the potentially cached Mach estimate.
	if facts.pageSize != 0 && facts.reusableBytes <= facts.residentBytes {
		reusablePages := min(facts.reusableBytes, facts.releasedHeapBytes) / facts.pageSize
		pages = max(pages, reusablePages)

		// XNU counts each page grab before handing it to the caller. Deduct
		// all grabs around the uncached free-page and task ledger reads.
		// A page that moved from that free count into the ledger supplies
		// at most one credit. Mach's cached estimates stay separate.
		if facts.liveFreeObserved && reusablePages != 0 && facts.liveFreePages > facts.pageGrabs {
			stillFree := facts.liveFreePages - facts.pageGrabs
			if combined, ok := checkedAdd(stillFree, reusablePages); ok {
				pages = max(pages, combined)
			}
		}
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
