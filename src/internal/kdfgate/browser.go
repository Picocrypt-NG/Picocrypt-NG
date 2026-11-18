package kdfgate

import (
	"runtime"
	"runtime/debug"
)

const (
	BrowserGoBudget       = (2 << 30) - (128 << 20)
	browserWorkingReserve = 96 << 20
	browserJSBudget       = 768 << 20
	browserJSUsable       = browserJSBudget - (64 << 20)
	// Legacy reads may need a JS input buffer and an equally large output.
	BrowserMaxLegacyInputBytes = browserJSUsable / 2
)

// BrowserKDFWithinBudget bounds the Go address space, not physical RAM.
// The fixed Argon2id workspace and pending allocations must both fit.
func BrowserKDFWithinBudget(heap, pending uint64) bool {
	const usable = BrowserGoBudget - (1 << 30) - browserWorkingReserve
	return heap <= usable && pending <= usable-heap
}

func BrowserHasKDFRoom(pending uint64) bool {
	debug.FreeOSMemory()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return BrowserKDFWithinBudget(stats.HeapAlloc, pending)
}

func BrowserJSWithinBudget(input, output, factors uint64) bool {
	return input <= browserJSUsable && output <= browserJSUsable-input && factors <= browserJSUsable-input-output
}
