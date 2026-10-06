package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
	"math"
	"sync"
	"time"
)

type androidResourceObservation struct {
	effectiveAvailable uint64
	platformThreshold  uint64
	processFootprint   uint64
	processIs64Bit     bool
	lowMemory          bool
	observedAt         time.Time
}

type androidPendingChallenge struct {
	generation uint64
	expiresAt  time.Time
	responded  bool
	response   chan androidResourceObservation
}

// AndroidResourceSession binds one fresh Android memory observation to one
// Go-owned operation. Android supplies facts; the shared Go policy decides.
type AndroidResourceSession struct {
	mu             sync.Mutex
	timeout        time.Duration
	nextGeneration uint64
	pending        *androidPendingChallenge
}

// AndroidResourceChallenge is an opaque one-shot response capability.
type AndroidResourceChallenge struct {
	session    *AndroidResourceSession
	pending    *androidPendingChallenge
	generation uint64
}

type androidResourceSessionContextKey struct{}

func NewAndroidResourceSession() *AndroidResourceSession {
	return newAndroidResourceSession(maximumSnapshotAge)
}

func newAndroidResourceSession(timeout time.Duration) *AndroidResourceSession {
	return &AndroidResourceSession{timeout: timeout}
}

func WithAndroidResourceSession(
	ctx context.Context,
	session *AndroidResourceSession,
) context.Context {
	if ctx == nil || session == nil {
		return ctx
	}
	return context.WithValue(ctx, androidResourceSessionContextKey{}, session)
}

// Snapshot cannot obtain Android facts without the matching host challenge.
func (*AndroidResourceSession) Snapshot(context.Context) Snapshot {
	return newUnknownAndroidSnapshot()
}

func (session *AndroidResourceSession) snapshotForKDF(
	ctx context.Context,
	_ pcv3credential.KDFProfile,
) Snapshot {
	return session.requestSnapshot(ctx, true)
}

func (session *AndroidResourceSession) snapshotForWorkingMemory(ctx context.Context) Snapshot {
	return session.requestSnapshot(ctx, false)
}

// The transport supplies facts only. KDF keeps its independent 64-bit policy;
// a bounded ZIP workspace also has a trusted 32-bit envelope.
func (session *AndroidResourceSession) requestSnapshot(ctx context.Context, require64Bit bool) Snapshot {
	if session == nil || ctx == nil || ctx.Err() != nil || session.timeout <= 0 {
		return newUnknownAndroidSnapshot()
	}

	session.mu.Lock()
	if session.pending != nil || session.nextGeneration == math.MaxUint64 {
		session.mu.Unlock()
		return newUnknownAndroidSnapshot()
	}
	session.nextGeneration++
	pending := &androidPendingChallenge{
		generation: session.nextGeneration,
		expiresAt:  time.Now().Add(session.timeout),
		response:   make(chan androidResourceObservation, 1),
	}
	session.pending = pending
	session.mu.Unlock()

	defer session.retireChallenge(pending)
	timer := time.NewTimer(time.Until(pending.expiresAt))
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return newUnknownAndroidSnapshot()
	case <-timer.C:
		return newUnknownAndroidSnapshot()
	case observation := <-pending.response:
		if ctx.Err() != nil || observation.observedAt.After(pending.expiresAt) ||
			(require64Bit && !observation.processIs64Bit) {
			return newUnknownAndroidSnapshot()
		}
		return newSnapshotAt(
			snapshotSourceAndroid,
			snapshotStateReady,
			observation.effectiveAvailable,
			observation.platformThreshold,
			observation.processFootprint,
			observation.lowMemory,
			observation.observedAt,
		)
	}
}

// Challenge returns the current operation-scoped response capability.
func (session *AndroidResourceSession) Challenge() *AndroidResourceChallenge {
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.pending == nil || session.pending.responded ||
		!time.Now().Before(session.pending.expiresAt) {
		return nil
	}
	return &AndroidResourceChallenge{
		session:    session,
		pending:    session.pending,
		generation: session.pending.generation,
	}
}

// Submit transfers bounded, non-secret runtime facts. Its result reports only
// whether this one-shot capability was consumed, never the admission decision.
func (challenge *AndroidResourceChallenge) Submit(
	totalRAMBytes int64,
	effectiveAvailable int64,
	platformThreshold int64,
	processFootprint int64,
	processIs64Bit bool,
	lowMemory bool,
) bool {
	observation, valid := newAndroidResourceObservation(
		totalRAMBytes,
		effectiveAvailable,
		platformThreshold,
		processFootprint,
		processIs64Bit,
		lowMemory,
	)
	if challenge == nil || challenge.session == nil || challenge.pending == nil || !valid {
		return false
	}

	session := challenge.session
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.pending != challenge.pending ||
		session.pending.generation != challenge.generation ||
		session.pending.responded {
		return false
	}
	observedAt := time.Now()
	if !observedAt.Before(session.pending.expiresAt) {
		return false
	}
	observation.observedAt = observedAt
	session.pending.responded = true
	session.pending.response <- observation
	return true
}

func newAndroidResourceObservation(
	totalRAMBytes int64,
	effectiveAvailable int64,
	platformThreshold int64,
	processFootprint int64,
	processIs64Bit bool,
	lowMemory bool,
) (androidResourceObservation, bool) {
	if totalRAMBytes <= 0 ||
		effectiveAvailable <= 0 || effectiveAvailable > totalRAMBytes ||
		platformThreshold <= 0 || platformThreshold > totalRAMBytes ||
		processFootprint <= 0 || processFootprint > totalRAMBytes {
		return androidResourceObservation{}, false
	}
	return androidResourceObservation{
		effectiveAvailable: uint64(effectiveAvailable),
		platformThreshold:  uint64(platformThreshold),
		processFootprint:   uint64(processFootprint),
		processIs64Bit:     processIs64Bit,
		lowMemory:          lowMemory,
	}, true
}

func (session *AndroidResourceSession) retireChallenge(pending *androidPendingChallenge) {
	session.mu.Lock()
	if session.pending == pending {
		session.pending = nil
	}
	session.mu.Unlock()
}

func newUnknownAndroidSnapshot() Snapshot {
	return newSnapshot(
		snapshotSourceAndroid,
		snapshotStateUnknown,
		0,
		0,
		0,
	)
}
