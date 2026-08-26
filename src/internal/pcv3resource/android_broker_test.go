package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"math"
	"strings"
	"testing"
	"time"
)

const androidBrokerTestMiB = uint64(1 << 20)

type androidAdmissionResult struct {
	admission pcv3credential.KDFAdmission
	err       error
}

func TestAndroidBrokerRequiresOneFreshChallengePerAdmission(t *testing.T) {
	session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
	admitter := newAdmitter(session)

	var previousGeneration uint64
	for attempt := range 2 {
		result := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(context.Background(), admitter, androidBrokerTestProfile(), result)

		challenge := awaitAndroidBrokerTestChallenge(t, session)
		if challenge.generation == 0 || challenge.generation <= previousGeneration {
			t.Fatalf("challenge generation = %d after %d; want a distinct increasing capability", challenge.generation, previousGeneration)
		}
		previousGeneration = challenge.generation
		if !submitAndroidBrokerTestObservation(challenge) {
			t.Fatal("fresh challenge rejected one bounded observation")
		}
		got := awaitAndroidBrokerTestAdmission(t, result)
		if got.err != nil || got.admission != pcv3credential.KDFAdmissionGranted {
			t.Fatalf("admission %d = %v, %v; want granted, nil", attempt, got.admission, got.err)
		}
		if session.Challenge() != nil {
			t.Fatal("consumed challenge remained observable")
		}
	}
}

func TestAndroidBrokerCapabilitiesCannotCrossOperations(t *testing.T) {
	firstSession := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
	secondSession := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
	firstResult := make(chan androidAdmissionResult, 1)
	secondResult := make(chan androidAdmissionResult, 1)
	go admitAndroidBrokerTestKDF(
		context.Background(),
		newAdmitter(firstSession),
		androidBrokerTestProfile(),
		firstResult,
	)
	go admitAndroidBrokerTestKDF(
		context.Background(),
		newAdmitter(secondSession),
		androidBrokerTestProfile(),
		secondResult,
	)

	firstChallenge := awaitAndroidBrokerTestChallenge(t, firstSession)
	secondChallenge := awaitAndroidBrokerTestChallenge(t, secondSession)
	if !submitAndroidBrokerTestObservation(firstChallenge) {
		t.Fatal("first operation challenge rejected its own observation")
	}
	first := awaitAndroidBrokerTestAdmission(t, firstResult)
	if first.err != nil || first.admission != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("first operation admission = %v, %v; want granted, nil", first.admission, first.err)
	}
	select {
	case unexpected := <-secondResult:
		t.Fatalf("first operation capability completed the second operation: %v, %v", unexpected.admission, unexpected.err)
	default:
	}
	if submitAndroidBrokerTestObservation(firstChallenge) {
		t.Fatal("consumed first-operation capability was reusable")
	}
	if !submitAndroidBrokerTestObservation(secondChallenge) {
		t.Fatal("second operation challenge rejected its own observation")
	}
	second := awaitAndroidBrokerTestAdmission(t, secondResult)
	if second.err != nil || second.admission != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("second operation admission = %v, %v; want granted, nil", second.admission, second.err)
	}
}

func TestAndroidBrokerStaleDuplicateAndMismatchedResponsesFailClosed(t *testing.T) {
	t.Run("duplicate cannot authorize another KDF", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		result := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(
			context.Background(),
			newAdmitter(session),
			androidBrokerTestProfile(),
			result,
		)
		challenge := awaitAndroidBrokerTestChallenge(t, session)
		if !submitAndroidBrokerTestObservation(challenge) {
			t.Fatal("first response was not accepted")
		}
		if submitAndroidBrokerTestObservation(challenge) {
			t.Fatal("duplicate response was accepted")
		}
		got := awaitAndroidBrokerTestAdmission(t, result)
		if got.err != nil || got.admission != pcv3credential.KDFAdmissionGranted {
			t.Fatalf("first one-shot admission = %v, %v; want granted, nil", got.admission, got.err)
		}
	})

	t.Run("stale handle cannot satisfy next generation", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		admitter := newAdmitter(session)
		firstResult := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(context.Background(), admitter, androidBrokerTestProfile(), firstResult)
		stale := awaitAndroidBrokerTestChallenge(t, session)
		if !submitAndroidBrokerTestObservation(stale) {
			t.Fatal("first response was not accepted")
		}
		if got := awaitAndroidBrokerTestAdmission(t, firstResult); got.err != nil || got.admission != pcv3credential.KDFAdmissionGranted {
			t.Fatalf("first admission = %v, %v; want granted, nil", got.admission, got.err)
		}

		secondResult := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(context.Background(), admitter, androidBrokerTestProfile(), secondResult)
		fresh := awaitAndroidBrokerTestChallenge(t, session)
		if submitAndroidBrokerTestObservation(stale) {
			t.Fatal("stale capability was accepted for a later generation")
		}
		select {
		case unexpected := <-secondResult:
			t.Fatalf("stale capability completed a later admission: %v, %v", unexpected.admission, unexpected.err)
		default:
		}
		if !submitAndroidBrokerTestObservation(fresh) {
			t.Fatal("fresh later-generation response was rejected")
		}
		if got := awaitAndroidBrokerTestAdmission(t, secondResult); got.err != nil || got.admission != pcv3credential.KDFAdmissionGranted {
			t.Fatalf("second admission = %v, %v; want granted, nil", got.admission, got.err)
		}
	})

	t.Run("mismatched device observation never grants", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		result := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(
			context.Background(),
			newAdmitter(session),
			androidBrokerTestProfile(),
			result,
		)
		challenge := awaitAndroidBrokerTestChallenge(t, session)
		if !challenge.Submit(
			"OtherVendor",
			"TestModel",
			"arm64-v8a",
			"aarch64",
			8<<30,
			4<<30,
			true,
			true,
			false,
		) {
			t.Fatal("bounded mismatched observation was not consumed")
		}
		got := awaitAndroidBrokerTestAdmission(t, result)
		if got.err != nil || got.admission != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf("mismatched-device admission = %v, %v; want denied unknown, nil", got.admission, got.err)
		}
	})
}

func TestAndroidBrokerTimeoutCancellationBusyAndOverflowFailClosed(t *testing.T) {
	t.Run("expired capability cannot consume a response", func(t *testing.T) {
		pending := &androidPendingChallenge{
			generation: 1,
			expiresAt:  time.Now().Add(-time.Nanosecond),
			response:   make(chan androidChallengeResponse, 1),
		}
		session := &AndroidResourceSession{pending: pending}
		challenge := &AndroidResourceChallenge{
			session:    session,
			pending:    pending,
			generation: pending.generation,
		}
		if submitAndroidBrokerTestObservation(challenge) {
			t.Fatal("expired capability consumed an observation")
		}
		if pending.responded {
			t.Fatal("expired capability marked the challenge responded")
		}
		select {
		case <-pending.response:
			t.Fatal("expired capability sent a response")
		default:
		}
	})

	t.Run("missing response times out", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), 0)
		admission, err := newAdmitter(session).AdmitKDF(context.Background(), androidBrokerTestProfile())
		if err != nil || admission != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf("timeout admission = %v, %v; want denied unknown, nil", admission, err)
		}
		if session.Challenge() != nil {
			t.Fatal("timed-out challenge remained live")
		}
	})

	t.Run("cancellation retires challenge", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(ctx, newAdmitter(session), androidBrokerTestProfile(), result)
		challenge := awaitAndroidBrokerTestChallenge(t, session)
		cancel()
		got := awaitAndroidBrokerTestAdmission(t, result)
		if got.err != nil || got.admission != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf("cancelled admission = %v, %v; want denied unknown, nil", got.admission, got.err)
		}
		if submitAndroidBrokerTestObservation(challenge) || session.Challenge() != nil {
			t.Fatal("cancelled challenge remained usable")
		}
	})

	t.Run("busy session never replaces pending challenge", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		firstResult := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(
			context.Background(),
			newAdmitter(session),
			androidBrokerTestProfile(),
			firstResult,
		)
		firstChallenge := awaitAndroidBrokerTestChallenge(t, session)
		second, err := newAdmitter(session).AdmitKDF(context.Background(), androidBrokerTestProfile())
		if err != nil || second != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf("busy admission = %v, %v; want denied unknown, nil", second, err)
		}
		current := session.Challenge()
		if current == nil || current.generation != firstChallenge.generation {
			t.Fatal("busy admission replaced the first live challenge")
		}
		if !submitAndroidBrokerTestObservation(firstChallenge) {
			t.Fatal("busy probe invalidated the original challenge")
		}
		first := awaitAndroidBrokerTestAdmission(t, firstResult)
		if first.err != nil || first.admission != pcv3credential.KDFAdmissionGranted {
			t.Fatalf("original admission = %v, %v; want granted, nil", first.admission, first.err)
		}
	})

	t.Run("generation exhaustion issues no challenge", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		session.nextGeneration = math.MaxUint64
		admission, err := newAdmitter(session).AdmitKDF(context.Background(), androidBrokerTestProfile())
		if err != nil || admission != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf("generation-overflow admission = %v, %v; want denied unknown, nil", admission, err)
		}
		if session.Challenge() != nil {
			t.Fatal("generation exhaustion exposed a challenge")
		}
	})

	t.Run("oversized observation cannot satisfy challenge", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(ctx, newAdmitter(session), androidBrokerTestProfile(), result)
		challenge := awaitAndroidBrokerTestChallenge(t, session)
		if challenge.Submit(
			strings.Repeat("x", maximumAndroidDeviceTextBytes+1),
			"TestModel",
			"arm64-v8a",
			"aarch64",
			8<<30,
			4<<30,
			true,
			true,
			false,
		) {
			t.Fatal("oversized observation was accepted")
		}
		if challenge.Submit(
			"TestVendor",
			"TestModel",
			"arm64-v8a",
			"aarch64",
			maximumAndroidObservationInteger+1,
			4<<30,
			true,
			true,
			false,
		) {
			t.Fatal("overflowing observation integer was accepted")
		}
		cancel()
		got := awaitAndroidBrokerTestAdmission(t, result)
		if got.err != nil || got.admission != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf("invalid-observation admission = %v, %v; want denied unknown, nil", got.admission, got.err)
		}
	})
}

func TestAndroidBrokerPolicyAndObservationRemainGoOwned(t *testing.T) {
	t.Run("wrong fixed profile has no challenge", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		profile := androidBrokerTestProfile()
		profile.Time++
		admission, err := newAdmitter(session).AdmitKDF(context.Background(), profile)
		if err != nil || admission != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf("wrong-profile admission = %v, %v; want denied unknown, nil", admission, err)
		}
		if session.Challenge() != nil {
			t.Fatal("unsupported profile caused an Android observation request")
		}
	})

	t.Run("unconfigured production session has zero challenge", func(t *testing.T) {
		session := NewAndroidResourceSession()
		admission, err := newAdmitter(session).AdmitKDF(context.Background(), androidBrokerTestProfile())
		if err != nil || admission != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf("unconfigured admission = %v, %v; want denied unknown, nil", admission, err)
		}
		if session.Challenge() != nil {
			t.Fatal("unconfigured Android policy exposed a challenge")
		}
	})

	t.Run("low-memory observation uses shared admission path", func(t *testing.T) {
		session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
		result := make(chan androidAdmissionResult, 1)
		go admitAndroidBrokerTestKDF(
			context.Background(),
			newAdmitter(session),
			androidBrokerTestProfile(),
			result,
		)
		challenge := awaitAndroidBrokerTestChallenge(t, session)
		if !challenge.Submit(
			"TestVendor",
			"TestModel",
			"arm64-v8a",
			"aarch64",
			8<<30,
			4<<30,
			true,
			true,
			true,
		) {
			t.Fatal("bounded low-memory observation was rejected")
		}
		got := awaitAndroidBrokerTestAdmission(t, result)
		if got.err != nil || got.admission != pcv3credential.KDFAdmissionDeniedInsufficient {
			t.Fatalf("low-memory admission = %v, %v; want denied insufficient, nil", got.admission, got.err)
		}
	})
}

func androidBrokerTestPolicy() androidFrozenPolicy {
	return androidFrozenPolicy{
		deviceClasses: []androidFrozenDeviceClass{{
			manufacturer:      "TestVendor",
			model:             "TestModel",
			abi:               "arm64-v8a",
			osArch:            "aarch64",
			totalRAMBytes:     8 << 30,
			platformThreshold: androidBrokerTestMiB,
		}},
		profiles:         []pcv3credential.KDFProfile{androidBrokerTestProfile()},
		codeOwnedReserve: 2 * androidBrokerTestMiB,
	}
}

func androidBrokerTestProfile() pcv3credential.KDFProfile {
	return pcv3credential.KDFProfile{
		ID:            0x01,
		Argon2Version: 0x13,
		Time:          4,
		MemoryKiB:     uint32(androidBrokerTestMiB / 1024),
		Parallelism:   4,
		SaltBytes:     16,
		OutputBytes:   32,
	}
}

func submitAndroidBrokerTestObservation(challenge *AndroidResourceChallenge) bool {
	return challenge.Submit(
		"TestVendor",
		"TestModel",
		"arm64-v8a",
		"aarch64",
		8<<30,
		4<<30,
		true,
		true,
		false,
	)
}

func admitAndroidBrokerTestKDF(
	ctx context.Context,
	admitter pcv3credential.Admitter,
	profile pcv3credential.KDFProfile,
	result chan<- androidAdmissionResult,
) {
	admission, err := admitter.AdmitKDF(ctx, profile)
	result <- androidAdmissionResult{admission: admission, err: err}
}

func awaitAndroidBrokerTestChallenge(
	t *testing.T,
	session *AndroidResourceSession,
) *AndroidResourceChallenge {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if challenge := session.Challenge(); challenge != nil {
			return challenge
		}
		select {
		case <-deadline.C:
			t.Fatal("Android admission did not expose its operation-scoped challenge")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func awaitAndroidBrokerTestAdmission(
	t *testing.T,
	result <-chan androidAdmissionResult,
) androidAdmissionResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("Android admission did not complete")
		return androidAdmissionResult{}
	}
}
