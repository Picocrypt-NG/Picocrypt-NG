//go:build android

package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"testing"
	"time"
)

type configuredAndroidPolicyProvider struct {
	configured bool
}

func (configuredAndroidPolicyProvider) Snapshot(context.Context) Snapshot {
	panic("presentation policy must not observe volatile resource facts")
}

func (provider configuredAndroidPolicyProvider) AndroidReadPolicyConfigured() bool {
	return provider.configured
}

type snapshotOnlyAndroidProvider struct{}

func (snapshotOnlyAndroidProvider) Snapshot(context.Context) Snapshot {
	panic("presentation policy must not observe volatile resource facts")
}

func TestAndroidReadPolicyConfiguredRequiresExplicitStaticPredicate(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider snapshotProvider
		want     bool
	}{
		{name: "configured Android policy", provider: configuredAndroidPolicyProvider{configured: true}, want: true},
		{name: "unconfigured Android policy", provider: configuredAndroidPolicyProvider{}, want: false},
		{name: "provider without Android policy", provider: snapshotOnlyAndroidProvider{}, want: false},
		{name: "nil provider", provider: nil, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := androidReadPolicyConfigured(test.provider); got != test.want {
				t.Fatalf("androidReadPolicyConfigured() = %v; want %v", got, test.want)
			}
		})
	}
}

func TestAndroidPolicyUnconfigured(t *testing.T) {
	provider := newPlatformSnapshotProvider()
	if androidReadPolicyConfigured(provider) || AndroidReadPolicyConfigured() {
		t.Fatal("ordinary Android provider advertised configured read policy before calibration freeze")
	}
	snapshot := provider.Snapshot(context.Background())
	if snapshot.source != snapshotSourceAndroid ||
		snapshot.state != snapshotStateUnconfigured ||
		snapshot.effectiveAvailable != 0 ||
		snapshot.platformThreshold != 0 ||
		snapshot.codeOwnedReserve != 0 ||
		snapshot.platformLowMemory {
		t.Fatalf("ordinary Android snapshot was not fail-closed: %#v", snapshot)
	}

	admission, err := newAdmitter(provider).AdmitKDF(
		context.Background(),
		pcv3credential.KDFProfile{MemoryKiB: 1048576},
	)
	if err != nil {
		t.Fatalf("ordinary Android admission returned an unexpected error: %v", err)
	}
	if admission != pcv3credential.KDFAdmissionDeniedUnknown {
		t.Fatalf("ordinary Android admission = %v; want denied unknown before KDF", admission)
	}
	if sequenceAfterAdmission := snapshotSequence.Load(); sequenceAfterAdmission != snapshot.sequence+1 {
		t.Fatalf(
			"ordinary Android admission observations = %d after the direct snapshot; want exactly one fresh provider observation",
			sequenceAfterAdmission-snapshot.sequence,
		)
	}
}

func TestAndroidProviderUsesOnlyItsBoundOperationSession(t *testing.T) {
	session := newAndroidResourceSession(androidBrokerTestPolicy(), time.Hour)
	ctx := WithAndroidResourceSession(context.Background(), session)
	result := make(chan androidAdmissionResult, 1)
	go admitAndroidBrokerTestKDF(
		ctx,
		newAdmitter(newPlatformSnapshotProvider()),
		androidBrokerTestProfile(),
		result,
	)
	challenge := awaitAndroidBrokerTestChallenge(t, session)
	if !submitAndroidBrokerTestObservation(challenge) {
		t.Fatal("bound operation challenge rejected its own observation")
	}
	got := awaitAndroidBrokerTestAdmission(t, result)
	if got.err != nil || got.admission != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("bound Android admission = %v, %v; want granted, nil", got.admission, got.err)
	}
}
