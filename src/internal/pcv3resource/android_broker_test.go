package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"testing"
	"time"
)

const androidTestMiB = uint64(1 << 20)

type androidAdmissionResult struct {
	decision pcv3credential.KDFAdmission
	err      error
}

func TestAndroidRuntimeAdmissionUsesFreshMemoryHeadroom(t *testing.T) {
	tests := []struct {
		name      string
		available uint64
		is64Bit   bool
		lowMemory bool
		want      pcv3credential.KDFAdmission
	}{
		{
			name:      "sufficient headroom",
			available: 1408 * androidTestMiB,
			is64Bit:   true,
			want:      pcv3credential.KDFAdmissionGranted,
		},
		{
			name:      "one byte below required headroom",
			available: 1408*androidTestMiB - 1,
			is64Bit:   true,
			want:      pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:      "platform reports low memory",
			available: 4 * 1024 * androidTestMiB,
			is64Bit:   true,
			lowMemory: true,
			want:      pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:      "32 bit process cannot safely admit one GiB KDF",
			available: 4 * 1024 * androidTestMiB,
			want:      pcv3credential.KDFAdmissionDeniedUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newAndroidResourceSession(time.Second)
			result := startAndroidAdmission(session)
			challenge := awaitAndroidChallenge(t, session)
			if !challenge.Submit(
				8*1024*int64(androidTestMiB),
				int64(test.available),
				256*int64(androidTestMiB),
				128*int64(androidTestMiB),
				test.is64Bit,
				test.lowMemory,
			) {
				t.Fatal("fresh bounded Android observation was rejected")
			}
			got := awaitAndroidAdmission(t, result)
			if got.err != nil || got.decision != test.want {
				t.Fatalf("admission = %v, %v; want %v, nil", got.decision, got.err, test.want)
			}
		})
	}
}

func TestAndroidResourceChallengeIsBoundedAndOneShot(t *testing.T) {
	session := newAndroidResourceSession(time.Second)
	result := startAndroidAdmission(session)
	challenge := awaitAndroidChallenge(t, session)

	if challenge.Submit(8<<30, 2<<30, 0, 128<<20, true, false) {
		t.Fatal("observation without the platform low-memory threshold was accepted")
	}
	if !challenge.Submit(8<<30, 2<<30, 256<<20, 128<<20, true, false) {
		t.Fatal("valid observation was rejected after a malformed transport attempt")
	}
	if challenge.Submit(8<<30, 2<<30, 256<<20, 128<<20, true, false) {
		t.Fatal("one-shot challenge accepted a second observation")
	}

	got := awaitAndroidAdmission(t, result)
	if got.err != nil || got.decision != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("admission = %v, %v; want granted, nil", got.decision, got.err)
	}
	if session.Challenge() != nil {
		t.Fatal("completed admission retained a resource challenge")
	}
}

func TestAndroidResourceAdmissionCancellationRetiresChallenge(t *testing.T) {
	session := newAndroidResourceSession(time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan androidAdmissionResult, 1)
	go func() {
		decision, err := newAdmitter(session).AdmitKDF(ctx, androidTestProfile())
		result <- androidAdmissionResult{decision: decision, err: err}
	}()
	_ = awaitAndroidChallenge(t, session)
	cancel()

	got := awaitAndroidAdmission(t, result)
	if got.err != nil || got.decision != pcv3credential.KDFAdmissionDeniedUnknown {
		t.Fatalf("cancelled admission = %v, %v; want denied unknown, nil", got.decision, got.err)
	}
	if session.Challenge() != nil {
		t.Fatal("cancelled admission retained a resource challenge")
	}
}

func startAndroidAdmission(session *AndroidResourceSession) <-chan androidAdmissionResult {
	result := make(chan androidAdmissionResult, 1)
	go func() {
		decision, err := newAdmitter(session).AdmitKDF(
			context.Background(),
			androidTestProfile(),
		)
		result <- androidAdmissionResult{decision: decision, err: err}
	}()
	return result
}

func androidTestProfile() pcv3credential.KDFProfile {
	return pcv3credential.KDFProfile{
		ID:            1,
		Argon2Version: 0x13,
		Time:          4,
		MemoryKiB:     1 << 20,
		Parallelism:   4,
		SaltBytes:     16,
		OutputBytes:   32,
	}
}

func awaitAndroidChallenge(t *testing.T, session *AndroidResourceSession) *AndroidResourceChallenge {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if challenge := session.Challenge(); challenge != nil {
			return challenge
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Android admission did not expose its operation-scoped challenge")
	return nil
}

func awaitAndroidAdmission(t *testing.T, result <-chan androidAdmissionResult) androidAdmissionResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("Android resource admission did not finish")
		return androidAdmissionResult{}
	}
}
