//go:build android

package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
	"testing"
	"time"
)

type androidPolicyPresentationProvider struct {
	configured bool
}

func (androidPolicyPresentationProvider) Snapshot(context.Context) Snapshot {
	panic("presentation state must not collect resource facts")
}

func (provider androidPolicyPresentationProvider) AndroidReadPolicyConfigured() bool {
	return provider.configured
}

type androidSnapshotOnlyProvider struct{}

func (androidSnapshotOnlyProvider) Snapshot(context.Context) Snapshot {
	panic("presentation state must not collect resource facts")
}

func TestAndroidReadPolicyConfiguredRequiresExplicitProviderSupport(t *testing.T) {
	tests := []struct {
		provider snapshotProvider
		want     bool
	}{
		{provider: androidPolicyPresentationProvider{configured: true}, want: true},
		{provider: androidPolicyPresentationProvider{}, want: false},
		{provider: androidSnapshotOnlyProvider{}, want: false},
		{provider: nil, want: false},
	}
	for _, test := range tests {
		if got := androidReadPolicyConfigured(test.provider); got != test.want {
			t.Fatalf("androidReadPolicyConfigured() = %v; want %v", got, test.want)
		}
	}
}

func TestAndroidProviderIsConfiguredButRequiresBoundFreshObservation(t *testing.T) {
	provider := newPlatformSnapshotProvider()
	if !androidReadPolicyConfigured(provider) || !AndroidReadPolicyConfigured() {
		t.Fatal("Android runtime admission was not advertised by the Android build")
	}

	decision, err := newAdmitter(provider).AdmitKDF(context.Background(), androidTestProfile())
	if err != nil || decision != pcv3credential.KDFAdmissionDeniedUnknown {
		t.Fatalf("unbound admission = %v, %v; want denied unknown, nil", decision, err)
	}

	session := newAndroidResourceSession(time.Second)
	ctx := WithAndroidResourceSession(context.Background(), session)
	result := make(chan androidAdmissionResult, 1)
	go func() {
		decision, err := newAdmitter(provider).AdmitKDF(ctx, androidTestProfile())
		result <- androidAdmissionResult{decision: decision, err: err}
	}()
	challenge := awaitAndroidChallenge(t, session)
	if !challenge.Submit(8<<30, 2<<30, 256<<20, 128<<20, true, false) {
		t.Fatal("bound operation rejected its fresh observation")
	}
	got := awaitAndroidAdmission(t, result)
	if got.err != nil || got.decision != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("bound admission = %v, %v; want granted, nil", got.decision, got.err)
	}
}
