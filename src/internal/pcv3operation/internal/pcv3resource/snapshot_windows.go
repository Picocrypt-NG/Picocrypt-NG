//go:build windows

package pcv3resource

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	psapi                       = windows.NewLazySystemDLL("psapi.dll")
	globalMemoryStatusEx        = kernel32.NewProc("GlobalMemoryStatusEx")
	isProcessInJob              = kernel32.NewProc("IsProcessInJob")
	getProcessMemoryInformation = psapi.NewProc("GetProcessMemoryInfo")
)

type windowsSnapshotProvider struct{}

type windowsSnapshotFacts struct {
	observed      bool
	status        memoryStatusEx
	privateCommit uint64
	outsideJob    bool
}

type memoryStatusEx struct {
	length                uint32
	memoryLoad            uint32
	totalPhysical         uint64
	availablePhysical     uint64
	totalCommit           uint64
	availableCommit       uint64
	totalVirtual          uint64
	availableVirtual      uint64
	availableExtendedVirt uint64
}

type processMemoryCountersEx struct {
	size                       uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
	privateUsage               uintptr
}

func newPlatformSnapshotProvider() snapshotProvider {
	return windowsSnapshotProvider{}
}

func (windowsSnapshotProvider) Snapshot(ctx context.Context) Snapshot {
	if ctx == nil || ctx.Err() != nil {
		return snapshotFromWindowsFacts(windowsSnapshotFacts{})
	}

	status, ok := readWindowsMemoryStatus()
	if !ok {
		return snapshotFromWindowsFacts(windowsSnapshotFacts{})
	}
	footprint, ok := readWindowsPrivateCommit()
	if !ok || footprint > status.totalCommit {
		return snapshotFromWindowsFacts(windowsSnapshotFacts{})
	}

	outsideJob := windowsProcessOutsideJob()
	if !outsideJob {
		return snapshotFromWindowsFacts(windowsSnapshotFacts{})
	}

	return snapshotFromWindowsFacts(windowsSnapshotFacts{
		observed:      ctx.Err() == nil,
		status:        status,
		privateCommit: footprint,
		outsideJob:    outsideJob,
	})
}

func snapshotFromWindowsFacts(facts windowsSnapshotFacts) Snapshot {
	effective, reserve, ok := normalizeWindowsSnapshotFacts(facts)
	if !ok {
		return newSnapshot(snapshotSourceWindows, snapshotStateUnknown, 0, 0, 0)
	}
	return newSnapshot(snapshotSourceWindows, snapshotStateReady, effective, 0, reserve)
}

func normalizeWindowsSnapshotFacts(facts windowsSnapshotFacts) (uint64, uint64, bool) {
	if !facts.observed || !validWindowsMemoryStatus(facts.status) ||
		facts.privateCommit == 0 || facts.privateCommit > facts.status.totalCommit ||
		!facts.outsideJob {
		return 0, 0, false
	}

	effective := min(
		facts.status.availablePhysical,
		facts.status.availableCommit,
		facts.status.availableVirtual,
	)
	if effective == 0 {
		return 0, 0, false
	}
	return effective, facts.privateCommit, true
}

func readWindowsMemoryStatus() (memoryStatusEx, bool) {
	var status memoryStatusEx
	status.length = uint32(unsafe.Sizeof(status))
	result, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if result == 0 || !validWindowsMemoryStatus(status) {
		return memoryStatusEx{}, false
	}
	return status, true
}

func validWindowsMemoryStatus(status memoryStatusEx) bool {
	if status.memoryLoad > 100 ||
		status.totalPhysical == 0 || status.availablePhysical == 0 ||
		status.availablePhysical > status.totalPhysical ||
		status.totalCommit == 0 || status.availableCommit == 0 ||
		status.availableCommit > status.totalCommit ||
		status.totalVirtual == 0 || status.availableVirtual == 0 ||
		status.availableVirtual > status.totalVirtual {
		return false
	}
	return true
}

func readWindowsPrivateCommit() (uint64, bool) {
	var counters processMemoryCountersEx
	counters.size = uint32(unsafe.Sizeof(counters))
	result, _, _ := getProcessMemoryInformation.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.size),
	)
	if result == 0 || counters.privateUsage == 0 {
		return 0, false
	}
	return uint64(counters.privateUsage), true
}

// QueryInformationJobObject(NULL) observes only the immediate job, while
// ancestor commit limits and sibling usage also constrain this process. Until
// complete chain headroom can be proven, job membership denies admission.
func windowsProcessOutsideJob() bool {
	var inJob int32
	result, _, _ := isProcessInJob.Call(
		uintptr(windows.CurrentProcess()),
		0,
		uintptr(unsafe.Pointer(&inJob)),
	)
	return result != 0 && inJob == 0
}
