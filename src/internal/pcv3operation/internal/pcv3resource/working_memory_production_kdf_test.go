//go:build pcv3_production_kdf && ((linux && !android) || (darwin && cgo))

package pcv3resource

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"io"
	"testing"
)

// The provisioned native lane must admit a small ZIP after the fixed 1 GiB
// KDF retires. Record the actual decision snapshots to distinguish unavailable
// observations from insufficient headroom; neither is a successful extraction.
func TestNativeWorkingMemoryAdmissionAfterProductionKDF(t *testing.T) {
	ctx := context.Background()
	provider := &nativeWorkingMemoryRecordingProvider{
		t: t, phase: "KDF admission", delegate: newPlatformSnapshotProvider(),
	}
	admitter := newAdmitter(provider)
	owner, err := pcv3credential.WithReaderCredential(ctx, &pcv3credential.ReaderCredentialRequest{
		Suite: pcv3credential.SuiteStandard1, ProfileID: 1,
		ClaimedPolicy: pcv3credential.FactorPolicyKeyfilesOnly,
		ArgonSalt:     bytes.Repeat([]byte{0x31}, 16),
		VolumeID:      bytes.Repeat([]byte{0x42}, 32),
		Factors: &pcv3credential.FactorRequest{
			Mode: pcv3credential.CredentialModeKeyfilesOnly, ExpectedPolicy: pcv3credential.FactorPolicyKeyfilesOnly,
			KeyfileMode: pcv3credential.KeyfileModeUnordered,
			Keyfiles: []*pcv3credential.KeyfileReader{pcv3credential.OwnKeyfileReader(
				io.NopCloser(bytes.NewReader([]byte("public native working-memory factor"))),
			)},
		},
	}, admitter, func(reader *pcv3credential.ReaderCredential) error {
		return reader.AdoptVolumeKey(bytes.Repeat([]byte{0x5a}, 32))
	})
	if err != nil || owner == nil {
		t.Fatalf("native production KDF failed before ZIP admission: %v", err)
	}
	t.Cleanup(owner.Close)
	owner.Close()

	budget := fileops.NewZIPResourceBudget()
	t.Logf("native ZIP working-memory envelope bytes=%d", budget.LimitBytes())
	for _, phase := range []string{"post-KDF ZIP check 1", "post-KDF ZIP check 2"} {
		provider.phase = phase
		if err := newAdmitter(provider).admitWorkingMemory(ctx, budget.LimitBytes()); err != nil {
			t.Fatalf("%s failed: %v", phase, err)
		}
	}
}

type nativeWorkingMemoryRecordingProvider struct {
	t        *testing.T
	phase    string
	delegate snapshotProvider
}

func (provider *nativeWorkingMemoryRecordingProvider) Snapshot(ctx context.Context) Snapshot {
	snapshot := provider.delegate.Snapshot(ctx)
	provider.t.Logf("native %s: source=%d state=%d effectiveAvailable=%d platformThreshold=%d codeOwnedReserve=%d",
		provider.phase, snapshot.source, snapshot.state, snapshot.effectiveAvailable,
		snapshot.platformThreshold, snapshot.codeOwnedReserve)
	return snapshot
}
