//go:build darwin && cgo

package pcv3resource

/*
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/task_info.h>
#include <stdint.h>
#include <sys/resource.h>

typedef struct {
	uint64_t free_pages;
	uint64_t inactive_pages;
	uint64_t internal_pages;
	uint64_t page_size;
	uint64_t physical_footprint;
	uint64_t virtual_size;
	uint64_t address_limit;
	int address_limited;
} pcv3_darwin_snapshot;

static int pcv3_read_darwin_snapshot(pcv3_darwin_snapshot *out) {
	if (out == NULL) {
		return 0;
	}

	host_t host = mach_host_self();
	vm_size_t page_size = 0;
	vm_statistics64_data_t memory;
	mach_msg_type_number_t memory_count = HOST_VM_INFO64_COUNT;
	kern_return_t status = host_page_size(host, &page_size);
	if (status == KERN_SUCCESS) {
		status = host_statistics64(
			host,
			HOST_VM_INFO64,
			(host_info64_t)&memory,
			&memory_count
		);
	}
	mach_port_deallocate(mach_task_self(), host);
	if (status != KERN_SUCCESS || memory_count < HOST_VM_INFO64_REV1_COUNT ||
		page_size == 0 ||
		(uint64_t)memory.free_count > UINT64_MAX / (uint64_t)page_size) {
		return 0;
	}

	task_vm_info_data_t task_memory;
	mach_msg_type_number_t task_count = TASK_VM_INFO_COUNT;
	status = task_info(
		mach_task_self(),
		TASK_VM_INFO,
		(task_info_t)&task_memory,
		&task_count
	);
	if (status != KERN_SUCCESS || task_count < TASK_VM_INFO_REV1_COUNT ||
		task_memory.phys_footprint == 0 || task_memory.virtual_size == 0) {
		return 0;
	}

	struct rlimit address_space;
	if (getrlimit(RLIMIT_AS, &address_space) != 0) {
		return 0;
	}

	out->free_pages = (uint64_t)memory.free_count;
	out->inactive_pages = (uint64_t)memory.inactive_count;
	out->internal_pages = (uint64_t)memory.internal_page_count;
	out->page_size = (uint64_t)page_size;
	out->physical_footprint = (uint64_t)task_memory.phys_footprint;
	out->virtual_size = (uint64_t)task_memory.virtual_size;
	out->address_limited = address_space.rlim_cur != RLIM_INFINITY;
	out->address_limit = out->address_limited ? (uint64_t)address_space.rlim_cur : 0;
	return 1;
}
*/
import "C"

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
	"math"
)

type darwinSnapshotProvider struct{}

type darwinSnapshotFacts struct {
	observed          bool
	freePages         uint64
	inactivePages     uint64
	internalPages     uint64
	pageSize          uint64
	physicalFootprint uint64
	virtualSize       uint64
	addressLimit      uint64
	addressLimited    bool
}

func newPlatformSnapshotProvider() snapshotProvider {
	return darwinSnapshotProvider{}
}

func (darwinSnapshotProvider) Snapshot(ctx context.Context) Snapshot {
	return snapshotFromDarwinFacts(readDarwinSnapshotFacts(ctx))
}

func (darwinSnapshotProvider) snapshotForKDF(
	ctx context.Context,
	_ pcv3credential.KDFProfile,
) Snapshot {
	return kdfSnapshotFromDarwinFacts(readDarwinSnapshotFacts(ctx))
}

func readDarwinSnapshotFacts(ctx context.Context) darwinSnapshotFacts {
	if ctx == nil || ctx.Err() != nil {
		return darwinSnapshotFacts{}
	}

	var facts C.pcv3_darwin_snapshot
	if C.pcv3_read_darwin_snapshot(&facts) == 0 {
		return darwinSnapshotFacts{}
	}

	return darwinSnapshotFacts{
		observed:          ctx.Err() == nil,
		freePages:         uint64(facts.free_pages),
		inactivePages:     uint64(facts.inactive_pages),
		internalPages:     uint64(facts.internal_pages),
		pageSize:          uint64(facts.page_size),
		physicalFootprint: uint64(facts.physical_footprint),
		virtualSize:       uint64(facts.virtual_size),
		addressLimit:      uint64(facts.address_limit),
		addressLimited:    facts.address_limited != 0,
	}
}

func kdfSnapshotFromDarwinFacts(facts darwinSnapshotFacts) Snapshot {
	// Credit only a lower bound on inactive file-backed pages. Internal pages
	// include active and inactive anonymous memory, so subtract all of them.
	// Raw free pages already include speculative pages; do not add them again.
	// This is advisory reclaimable headroom, not a memory reservation.
	if facts.inactivePages > facts.internalPages {
		inactiveFilePages := facts.inactivePages - facts.internalPages
		pages, ok := checkedAdd(facts.freePages, inactiveFilePages)
		if !ok {
			return snapshotFromDarwinFacts(darwinSnapshotFacts{})
		}
		facts.freePages = pages
	}
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
