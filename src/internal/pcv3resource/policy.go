// Package pcv3resource owns PCV3 fixed-profile resource admission.
package pcv3resource

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"Picocrypt-NG/internal/pcv3credential"
)

const (
	currentSnapshotVersion uint8 = 1
	maximumSnapshotAge           = 5 * time.Second
)

type snapshotSource uint8

const (
	snapshotSourceUnknown snapshotSource = iota
	snapshotSourceLinux
	snapshotSourceDarwin
	snapshotSourceWindows
	snapshotSourceAndroid
)

type snapshotState uint8

const (
	snapshotStateUnknown snapshotState = iota
	snapshotStateReady
	snapshotStateUnsupported
	snapshotStateUnconfigured
)

// Snapshot is one bounded, immutable resource observation. Its fields are
// private so platform providers can supply facts but external callers cannot
// alter policy terms or attach filesystem/frontend authority.
type Snapshot struct {
	version            uint8
	source             snapshotSource
	state              snapshotState
	sequence           uint64
	observedAt         time.Time
	effectiveAvailable uint64
	platformThreshold  uint64
	codeOwnedReserve   uint64
	platformLowMemory  bool
}

type snapshotProvider interface {
	Snapshot(context.Context) Snapshot
}

// kdfSnapshotProvider is implemented only when a platform's frozen policy is
// profile-specific. It keeps profile selection in Go while retaining the same
// resourceAdmitter decision and arithmetic path for every platform.
type kdfSnapshotProvider interface {
	snapshotForKDF(context.Context, pcv3credential.KDFProfile) Snapshot
}

type resourceAdmitter struct {
	mu           sync.Mutex
	provider     snapshotProvider
	lastSequence uint64
}

var snapshotSequence atomic.Uint64

var _ pcv3credential.Admitter = (*resourceAdmitter)(nil)

func newSnapshot(
	source snapshotSource,
	state snapshotState,
	effectiveAvailable uint64,
	platformThreshold uint64,
	codeOwnedReserve uint64,
	platformLowMemory bool,
) Snapshot {
	return newSnapshotAt(
		source,
		state,
		effectiveAvailable,
		platformThreshold,
		codeOwnedReserve,
		platformLowMemory,
		time.Now(),
	)
}

func newSnapshotAt(
	source snapshotSource,
	state snapshotState,
	effectiveAvailable uint64,
	platformThreshold uint64,
	codeOwnedReserve uint64,
	platformLowMemory bool,
	observedAt time.Time,
) Snapshot {
	return Snapshot{
		version:            currentSnapshotVersion,
		source:             source,
		state:              state,
		sequence:           snapshotSequence.Add(1),
		observedAt:         observedAt,
		effectiveAvailable: effectiveAvailable,
		platformThreshold:  platformThreshold,
		codeOwnedReserve:   codeOwnedReserve,
		platformLowMemory:  platformLowMemory,
	}
}

func newAdmitter(provider snapshotProvider) *resourceAdmitter {
	return &resourceAdmitter{provider: provider}
}

// NewPlatformAdmitter binds the package-owned native resource provider to the
// fixed-profile admission policy. Callers receive only the decision interface;
// platform observations and policy terms remain private to this package.
func NewPlatformAdmitter() pcv3credential.Admitter {
	return newAdmitter(newPlatformSnapshotProvider())
}

// AdmitKDF obtains one new provider observation and returns only a resource
// decision. It never changes, retries, or substitutes the selected profile.
func (admitter *resourceAdmitter) AdmitKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	if admitter == nil || admitter.provider == nil || ctx == nil {
		return pcv3credential.KDFAdmissionDeniedUnknown, nil
	}

	admitter.mu.Lock()
	defer admitter.mu.Unlock()

	var snapshot Snapshot
	if provider, ok := admitter.provider.(kdfSnapshotProvider); ok {
		snapshot = provider.snapshotForKDF(ctx, profile)
	} else {
		snapshot = admitter.provider.Snapshot(ctx)
	}
	if ctx.Err() != nil || !admitter.acceptFreshSnapshot(snapshot) {
		return pcv3credential.KDFAdmissionDeniedUnknown, nil
	}
	if snapshot.state != snapshotStateReady || snapshot.codeOwnedReserve == 0 ||
		profile.MemoryKiB == 0 {
		return pcv3credential.KDFAdmissionDeniedUnknown, nil
	}
	if snapshot.platformLowMemory {
		return pcv3credential.KDFAdmissionDeniedInsufficient, nil
	}

	kdfKiB := uint64(profile.MemoryKiB)
	if kdfKiB > math.MaxUint64/1024 {
		return pcv3credential.KDFAdmissionDeniedUnknown, nil
	}
	kdfBytes := kdfKiB * 1024
	required, ok := checkedAdd(kdfBytes, snapshot.platformThreshold)
	if !ok {
		return pcv3credential.KDFAdmissionDeniedUnknown, nil
	}
	required, ok = checkedAdd(required, snapshot.codeOwnedReserve)
	if !ok {
		return pcv3credential.KDFAdmissionDeniedUnknown, nil
	}
	if snapshot.effectiveAvailable < required {
		return pcv3credential.KDFAdmissionDeniedInsufficient, nil
	}
	return pcv3credential.KDFAdmissionGranted, nil
}

func (admitter *resourceAdmitter) acceptFreshSnapshot(snapshot Snapshot) bool {
	if snapshot.version != currentSnapshotVersion ||
		snapshot.source <= snapshotSourceUnknown ||
		snapshot.source > snapshotSourceAndroid ||
		snapshot.sequence == 0 || snapshot.sequence <= admitter.lastSequence ||
		snapshot.observedAt.IsZero() {
		return false
	}

	now := time.Now()
	if now.Before(snapshot.observedAt) || now.Sub(snapshot.observedAt) > maximumSnapshotAge {
		return false
	}
	admitter.lastSequence = snapshot.sequence
	return true
}

func checkedAdd(left, right uint64) (uint64, bool) {
	if left > math.MaxUint64-right {
		return 0, false
	}
	return left + right, true
}
