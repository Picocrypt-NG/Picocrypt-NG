package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"math"
	"sync"
	"time"
)

const (
	maximumAndroidDeviceTextBytes    = 128
	maximumAndroidObservationInteger = int64(1<<53 - 1)
)

type androidFrozenDeviceClass struct {
	manufacturer      string
	model             string
	abi               string
	osArch            string
	totalRAMBytes     uint64
	platformThreshold uint64
}

// androidFrozenPolicy is deliberately private. A future production value may
// contain only separately reviewed, Go-owned calibration results; Android
// observations cannot create or alter it.
type androidFrozenPolicy struct {
	deviceClasses    []androidFrozenDeviceClass
	profiles         []pcv3credential.KDFProfile
	codeOwnedReserve uint64
}

type androidResourceObservation struct {
	manufacturer        string
	model               string
	abi                 string
	osArch              string
	totalRAMBytes       uint64
	effectiveAvailable  uint64
	processIs64Bit      bool
	emulatorTraitsClear bool
	lowMemory           bool
	observedAt          time.Time
}

type androidChallengeResponse struct {
	observation androidResourceObservation
	valid       bool
}

type androidPendingChallenge struct {
	generation uint64
	expiresAt  time.Time
	responded  bool
	response   chan androidChallengeResponse
}

// AndroidResourceSession binds resource observations to one Go-owned mobile
// operation context. Its production constructor remains unconfigured until a
// separately reviewed calibration policy is frozen in Go.
type AndroidResourceSession struct {
	mu             sync.Mutex
	policy         *androidFrozenPolicy
	timeout        time.Duration
	nextGeneration uint64
	pending        *androidPendingChallenge
}

// AndroidResourceChallenge is an opaque, one-shot response capability. It is
// tied to one session and generation; callers cannot reconstruct it from an
// operation ID or scalar generation.
type AndroidResourceChallenge struct {
	session    *AndroidResourceSession
	pending    *androidPendingChallenge
	generation uint64
}

type androidResourceSessionContextKey struct{}

// NewAndroidResourceSession returns the production Android operation session.
// The current production policy is intentionally unconfigured, so it exposes
// no challenge and every admission fails closed before the KDF.
func NewAndroidResourceSession() *AndroidResourceSession {
	return newAndroidResourceSession(androidFrozenPolicy{}, maximumSnapshotAge)
}

// WithAndroidResourceSession binds an already Go-owned session to the matching
// operation context. It adds no caller-supplied policy or decision authority.
func WithAndroidResourceSession(
	ctx context.Context,
	session *AndroidResourceSession,
) context.Context {
	if ctx == nil || session == nil {
		return ctx
	}
	return context.WithValue(ctx, androidResourceSessionContextKey{}, session)
}

func newAndroidResourceSession(
	policy androidFrozenPolicy,
	timeout time.Duration,
) *AndroidResourceSession {
	session := &AndroidResourceSession{timeout: timeout}
	if !validAndroidFrozenPolicy(policy) {
		return session
	}
	frozen := androidFrozenPolicy{
		deviceClasses:    append([]androidFrozenDeviceClass(nil), policy.deviceClasses...),
		profiles:         append([]pcv3credential.KDFProfile(nil), policy.profiles...),
		codeOwnedReserve: policy.codeOwnedReserve,
	}
	session.policy = &frozen
	return session
}

// Snapshot cannot initiate Android resource admission without a fixed profile.
func (*AndroidResourceSession) Snapshot(context.Context) Snapshot {
	return newAndroidBrokerSnapshot(snapshotStateUnknown)
}

func (session *AndroidResourceSession) snapshotForKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) Snapshot {
	if session == nil || session.policy == nil {
		return newAndroidBrokerSnapshot(snapshotStateUnconfigured)
	}
	if ctx == nil || ctx.Err() != nil || session.timeout <= 0 ||
		!session.supportsProfile(profile) {
		return newAndroidBrokerSnapshot(snapshotStateUnknown)
	}

	session.mu.Lock()
	if session.pending != nil || session.nextGeneration == math.MaxUint64 {
		session.mu.Unlock()
		return newAndroidBrokerSnapshot(snapshotStateUnknown)
	}
	session.nextGeneration++
	issuedAt := time.Now()
	pending := &androidPendingChallenge{
		generation: session.nextGeneration,
		expiresAt:  issuedAt.Add(session.timeout),
		response:   make(chan androidChallengeResponse, 1),
	}
	session.pending = pending
	session.mu.Unlock()

	defer session.retireChallenge(pending)
	timer := time.NewTimer(time.Until(pending.expiresAt))
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return newAndroidBrokerSnapshot(snapshotStateUnknown)
	case <-timer.C:
		return newAndroidBrokerSnapshot(snapshotStateUnknown)
	case response := <-pending.response:
		deviceClass, ok := session.matchDeviceClass(response.observation)
		if !response.valid || !ok || ctx.Err() != nil ||
			response.observation.observedAt.After(pending.expiresAt) {
			return newAndroidBrokerSnapshot(snapshotStateUnknown)
		}
		return newAndroidBrokerSnapshotAt(
			snapshotStateReady,
			response.observation.effectiveAvailable,
			deviceClass.platformThreshold,
			session.policy.codeOwnedReserve,
			response.observation.lowMemory,
			response.observation.observedAt,
		)
	}
}

// Challenge returns the current operation-scoped response capability, or nil
// when no configured KDF admission is waiting for a fresh observation.
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

// Submit records only bounded, non-secret Android observations. Its boolean
// reports one-shot transport consumption, never resource sufficiency or a KDF
// admission decision.
func (challenge *AndroidResourceChallenge) Submit(
	manufacturer string,
	model string,
	abi string,
	osArch string,
	totalRAMBytes int64,
	effectiveAvailable int64,
	processIs64Bit bool,
	emulatorTraitsClear bool,
	lowMemory bool,
) bool {
	if challenge == nil || challenge.session == nil || challenge.pending == nil ||
		!validAndroidObservationText(manufacturer) ||
		!validAndroidObservationText(model) ||
		!validAndroidObservationText(abi) ||
		!validAndroidObservationText(osArch) ||
		totalRAMBytes <= 0 || totalRAMBytes > maximumAndroidObservationInteger ||
		effectiveAvailable <= 0 || effectiveAvailable > maximumAndroidObservationInteger ||
		effectiveAvailable > totalRAMBytes {
		return false
	}

	observation := androidResourceObservation{
		manufacturer:        manufacturer,
		model:               model,
		abi:                 abi,
		osArch:              osArch,
		totalRAMBytes:       uint64(totalRAMBytes),
		effectiveAvailable:  uint64(effectiveAvailable),
		processIs64Bit:      processIs64Bit,
		emulatorTraitsClear: emulatorTraitsClear,
		lowMemory:           lowMemory,
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
	session.pending.response <- androidChallengeResponse{
		observation: observation,
		valid:       true,
	}
	return true
}

func (session *AndroidResourceSession) supportsProfile(
	profile pcv3credential.KDFProfile,
) bool {
	for _, supported := range session.policy.profiles {
		if profile == supported {
			return true
		}
	}
	return false
}

func (session *AndroidResourceSession) matchDeviceClass(
	observation androidResourceObservation,
) (androidFrozenDeviceClass, bool) {
	if !observation.processIs64Bit || !observation.emulatorTraitsClear {
		return androidFrozenDeviceClass{}, false
	}
	for _, supported := range session.policy.deviceClasses {
		if observation.manufacturer == supported.manufacturer &&
			observation.model == supported.model &&
			observation.abi == supported.abi &&
			observation.osArch == supported.osArch &&
			observation.totalRAMBytes == supported.totalRAMBytes {
			return supported, true
		}
	}
	return androidFrozenDeviceClass{}, false
}

func (session *AndroidResourceSession) retireChallenge(pending *androidPendingChallenge) {
	session.mu.Lock()
	if session.pending == pending {
		session.pending = nil
	}
	session.mu.Unlock()
}

func validAndroidFrozenPolicy(policy androidFrozenPolicy) bool {
	if len(policy.deviceClasses) == 0 || len(policy.profiles) == 0 ||
		policy.codeOwnedReserve == 0 ||
		policy.codeOwnedReserve > uint64(maximumAndroidObservationInteger) {
		return false
	}
	for index, deviceClass := range policy.deviceClasses {
		if !validAndroidObservationText(deviceClass.manufacturer) ||
			!validAndroidObservationText(deviceClass.model) ||
			!validAndroidObservationText(deviceClass.abi) ||
			!validAndroidObservationText(deviceClass.osArch) ||
			deviceClass.totalRAMBytes == 0 ||
			deviceClass.totalRAMBytes > uint64(maximumAndroidObservationInteger) ||
			deviceClass.platformThreshold > uint64(maximumAndroidObservationInteger) {
			return false
		}
		for prior := range index {
			if sameAndroidFrozenDeviceClass(deviceClass, policy.deviceClasses[prior]) {
				return false
			}
		}
	}
	for index, profile := range policy.profiles {
		if profile.ID == 0 || profile.Argon2Version == 0 || profile.Time == 0 ||
			profile.MemoryKiB == 0 || profile.Parallelism == 0 ||
			profile.SaltBytes == 0 || profile.OutputBytes == 0 {
			return false
		}
		for prior := range index {
			if profile == policy.profiles[prior] {
				return false
			}
		}
	}
	return true
}

func sameAndroidFrozenDeviceClass(left, right androidFrozenDeviceClass) bool {
	return left.manufacturer == right.manufacturer &&
		left.model == right.model &&
		left.abi == right.abi &&
		left.osArch == right.osArch &&
		left.totalRAMBytes == right.totalRAMBytes
}

func validAndroidObservationText(value string) bool {
	if len(value) == 0 || len(value) > maximumAndroidDeviceTextBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			(index > 0 && (character == ' ' || character == '.' || character == '_' ||
				character == '(' || character == ')' || character == '+' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func newAndroidBrokerSnapshot(state snapshotState) Snapshot {
	return newAndroidBrokerSnapshotAt(
		state,
		0,
		0,
		0,
		false,
		time.Now(),
	)
}

func newAndroidBrokerSnapshotAt(
	state snapshotState,
	effectiveAvailable uint64,
	platformThreshold uint64,
	codeOwnedReserve uint64,
	lowMemory bool,
	observedAt time.Time,
) Snapshot {
	return newSnapshotAt(
		snapshotSourceAndroid,
		state,
		effectiveAvailable,
		platformThreshold,
		codeOwnedReserve,
		lowMemory,
		observedAt,
	)
}
