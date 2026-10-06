package pcv3resource

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"errors"
	"runtime/debug"
)

var (
	errWorkingMemoryUnknown      = errors.New("working memory observation unavailable")
	errWorkingMemoryInsufficient = errors.New("insufficient working memory headroom")
)

type workingMemorySnapshotProvider interface {
	snapshotForWorkingMemory(context.Context) Snapshot
}

// AdmitZIPWorkingMemory observes fresh native headroom for the complete trusted
// ZIP envelope. This is an advisory phase-boundary check, not a RAM reservation
// or an RSS limit. Callers must still account allocations against the ledger.
func AdmitZIPWorkingMemory(ctx context.Context, budget *fileops.ZIPResourceBudget) error {
	if budget == nil {
		return fileops.ErrZIPMetadataLimit
	}
	if err := newAdmitter(newPlatformSnapshotProvider()).admitWorkingMemory(ctx, budget.LimitBytes()); err != nil {
		return errors.Join(fileops.ErrZIPMetadataLimit, err)
	}
	return nil
}

func (admitter *resourceAdmitter) admitWorkingMemory(ctx context.Context, bytes uint64) error {
	if admitter == nil || admitter.provider == nil || ctx == nil || bytes == 0 {
		return errWorkingMemoryUnknown
	}
	admitter.mu.Lock()
	defer admitter.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Retired parse/KDF workspaces may still occupy the Go heap. Collect before
	// observing rather than discounting live allocations or tuning GC globally.
	debug.FreeOSMemory()
	var snapshot Snapshot
	if provider, ok := admitter.provider.(workingMemorySnapshotProvider); ok {
		snapshot = provider.snapshotForWorkingMemory(ctx)
	} else {
		snapshot = admitter.provider.Snapshot(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !admitter.acceptFreshSnapshot(snapshot) || snapshot.state != snapshotStateReady || snapshot.codeOwnedReserve == 0 {
		return errWorkingMemoryUnknown
	}
	if snapshot.platformLowMemory {
		return errWorkingMemoryInsufficient
	}
	required, ok := checkedAdd(bytes, snapshot.platformThreshold)
	if !ok {
		return errWorkingMemoryUnknown
	}
	required, ok = checkedAdd(required, snapshot.codeOwnedReserve)
	if !ok {
		return errWorkingMemoryUnknown
	}
	if snapshot.effectiveAvailable < required {
		return errWorkingMemoryInsufficient
	}
	return nil
}
