package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
	"math"
	"testing"
	"time"
)

// These boundary fixtures protect against omitting runtime/platform reserves,
// admitting stale facts, and wrapping arithmetic into a false approval.
func TestWorkingMemoryAdmissionRequiresFreshHeadroomAndReserves(t *testing.T) {
	for _, test := range []struct {
		name   string
		bytes  uint64
		change func(*Snapshot)
		denied bool
	}{
		{name: "exact remaining headroom", bytes: 256 << 20},
		{name: "one byte short", bytes: 256 << 20, change: func(s *Snapshot) { s.effectiveAvailable-- }, denied: true},
		{name: "low memory signal", bytes: 256 << 20, change: func(s *Snapshot) { s.platformLowMemory = true }, denied: true},
		{name: "unknown facts", bytes: 256 << 20, change: func(s *Snapshot) { s.state = snapshotStateUnknown }, denied: true},
		{name: "missing runtime reserve", bytes: 256 << 20, change: func(s *Snapshot) { s.codeOwnedReserve = 0 }, denied: true},
		{name: "stale facts", bytes: 256 << 20, change: func(s *Snapshot) { s.observedAt = time.Now().Add(-6 * time.Second) }, denied: true},
		{name: "future facts", bytes: 256 << 20, change: func(s *Snapshot) { s.observedAt = time.Now().Add(time.Minute) }, denied: true},
		{name: "unknown source", bytes: 256 << 20, change: func(s *Snapshot) { s.source = snapshotSourceUnknown }, denied: true},
		{name: "zero workspace", denied: true},
		{name: "workspace threshold overflow", bytes: math.MaxUint64, denied: true},
		{name: "reserve overflow", bytes: 256 << 20, change: func(s *Snapshot) { s.codeOwnedReserve = math.MaxUint64 }, denied: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := newSnapshot(snapshotSourceLinux, snapshotStateReady, 304<<20, 16<<20, 32<<20)
			if test.change != nil {
				test.change(&snapshot)
			}
			admitter := newAdmitter(&scriptedSnapshotProvider{snapshots: []Snapshot{snapshot}})
			if err := admitter.admitWorkingMemory(context.Background(), test.bytes); (err != nil) != test.denied {
				t.Fatalf("denied=%v, want %v (err=%v)", err != nil, test.denied, err)
			}
		})
	}
}

func TestWorkingMemoryAdmissionRefusesReplayedObservation(t *testing.T) {
	snapshot := newSnapshot(snapshotSourceLinux, snapshotStateReady, 304<<20, 16<<20, 32<<20)
	admitter := newAdmitter(&scriptedSnapshotProvider{snapshots: []Snapshot{snapshot, snapshot}})
	if err := admitter.admitWorkingMemory(context.Background(), 256<<20); err != nil {
		t.Fatal(err)
	}
	if err := admitter.admitWorkingMemory(context.Background(), 256<<20); err == nil {
		t.Fatal("replayed snapshot admitted a second workspace")
	}
}

func TestWorkingMemoryAdmissionCancellationDoesNotCollectFacts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := &scriptedSnapshotProvider{}
	if err := newAdmitter(provider).admitWorkingMemory(ctx, 256<<20); err == nil {
		t.Fatal("cancelled workspace admitted")
	}
	if provider.calls != 0 {
		t.Fatal("cancelled request collected facts")
	}
}

func TestAndroidWorkingMemoryUsesFreshChallengeOn32BitWithoutWeakeningKDF(t *testing.T) {
	session := newAndroidResourceSession(time.Second)
	done := make(chan error, 1)
	go func() { done <- newAdmitter(session).admitWorkingMemory(context.Background(), 64<<20) }()
	challenge := awaitAndroidChallenge(t, session)
	if !challenge.Submit(2<<30, 192<<20, 64<<20, 64<<20, false, false) {
		t.Fatal("32-bit facts rejected")
	}
	if err := <-done; err != nil {
		t.Fatalf("fitting 32-bit workspace denied: %v", err)
	}
	// KDF has an independent 64-bit contract despite sharing the fact broker.
	kdf := startAndroidAdmission(session)
	challenge = awaitAndroidChallenge(t, session)
	if !challenge.Submit(4<<30, 2<<30, 64<<20, 64<<20, false, false) {
		t.Fatal("KDF facts rejected")
	}
	result := awaitAndroidAdmission(t, kdf)
	if result.err != nil || result.decision != pcv3credential.KDFAdmissionDeniedUnknown {
		t.Fatalf("32-bit KDF must remain denied: %+v", result)
	}
}
