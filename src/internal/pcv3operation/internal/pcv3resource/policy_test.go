package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
	"testing"
	"time"
)

type scriptedSnapshotProvider struct {
	snapshots []Snapshot
	calls     int
}

func (provider *scriptedSnapshotProvider) Snapshot(context.Context) Snapshot {
	provider.calls++
	if provider.calls > len(provider.snapshots) {
		return Snapshot{}
	}
	return provider.snapshots[provider.calls-1]
}

func TestFixedProfileAdmissionCheckedArithmetic(t *testing.T) {
	profile := pcv3credential.KDFProfile{
		ID:            0x01,
		Argon2Version: 0x13,
		Time:          4,
		MemoryKiB:     1048576,
		Parallelism:   4,
		SaltBytes:     16,
		OutputBytes:   32,
	}
	now := time.Now()
	ready := Snapshot{
		version:            currentSnapshotVersion,
		source:             snapshotSourceLinux,
		state:              snapshotStateReady,
		sequence:           1,
		observedAt:         now,
		effectiveAvailable: 1124073472,
		platformThreshold:  16777216,
		codeOwnedReserve:   33554432,
		platformLowMemory:  false,
	}

	tests := []struct {
		name     string
		profile  pcv3credential.KDFProfile
		snapshot Snapshot
		want     pcv3credential.KDFAdmission
	}{
		{
			name:     "equality admits",
			profile:  profile,
			snapshot: ready,
			want:     pcv3credential.KDFAdmissionGranted,
		},
		{
			name:    "desktop zero threshold equality admits",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.effectiveAvailable = 1107296256
				value.platformThreshold = 0
				return value
			}(),
			want: pcv3credential.KDFAdmissionGranted,
		},
		{
			name:    "one byte short denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.effectiveAvailable = 1124073471
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:    "KDF plus threshold overflow denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.effectiveAvailable = 18446744073709551615
				value.platformThreshold = 18446744072635809792
				value.codeOwnedReserve = 1
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "reserve addition overflow denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.effectiveAvailable = 18446744073709551615
				value.platformThreshold = 0
				value.codeOwnedReserve = 18446744073709551615
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "zero reserve denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.codeOwnedReserve = 0
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "unknown state denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.state = snapshotStateUnknown
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "unsupported state denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.state = snapshotStateUnsupported
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "unconfigured state denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.state = snapshotStateUnconfigured
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "platform low memory denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.platformLowMemory = true
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedInsufficient,
		},
		{
			name:    "stale observation denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.observedAt = now.Add(-maximumSnapshotAge - time.Second)
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "future observation denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.observedAt = now.Add(time.Second)
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "unknown source denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.source = snapshotSourceUnknown
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "unknown snapshot version denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.version++
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "zero sequence denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.sequence = 0
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name:    "zero observation time denies",
			profile: profile,
			snapshot: func() Snapshot {
				value := ready
				value.observedAt = time.Time{}
				return value
			}(),
			want: pcv3credential.KDFAdmissionDeniedUnknown,
		},
		{
			name: "zero KDF memory denies",
			profile: func() pcv3credential.KDFProfile {
				value := profile
				value.MemoryKiB = 0
				return value
			}(),
			snapshot: ready,
			want:     pcv3credential.KDFAdmissionDeniedUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &scriptedSnapshotProvider{snapshots: []Snapshot{test.snapshot}}
			admission, err := newAdmitter(provider).AdmitKDF(context.Background(), test.profile)
			if err != nil {
				t.Fatalf("AdmitKDF returned unexpected error: %v", err)
			}
			if admission != test.want {
				t.Fatalf("AdmitKDF = %v; want %v", admission, test.want)
			}
			if provider.calls != 1 {
				t.Fatalf("snapshot provider calls = %d; want 1", provider.calls)
			}
		})
	}
}

func TestResourceAdmitterObtainsFreshSnapshot(t *testing.T) {
	profile := pcv3credential.KDFProfile{MemoryKiB: 1048576}
	now := time.Now()
	fresh := Snapshot{
		version:            currentSnapshotVersion,
		source:             snapshotSourceLinux,
		state:              snapshotStateReady,
		sequence:           100,
		observedAt:         now,
		effectiveAvailable: 1107296256,
		codeOwnedReserve:   33554432,
	}
	insufficient := fresh
	insufficient.sequence = 101
	insufficient.effectiveAvailable = 1107296255

	provider := &scriptedSnapshotProvider{snapshots: []Snapshot{fresh, insufficient}}
	admitter := newAdmitter(provider)
	first, err := admitter.AdmitKDF(context.Background(), profile)
	if err != nil || first != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("first AdmitKDF = %v, %v; want granted, nil", first, err)
	}
	second, err := admitter.AdmitKDF(context.Background(), profile)
	if err != nil || second != pcv3credential.KDFAdmissionDeniedInsufficient {
		t.Fatalf("second AdmitKDF = %v, %v; want denied, nil", second, err)
	}
	if provider.calls != 2 {
		t.Fatalf("snapshot provider calls = %d; want one fresh call per admission", provider.calls)
	}

	reusedProvider := &scriptedSnapshotProvider{snapshots: []Snapshot{fresh, fresh}}
	reusedAdmitter := newAdmitter(reusedProvider)
	first, err = reusedAdmitter.AdmitKDF(context.Background(), profile)
	if err != nil || first != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("first reuse probe = %v, %v; want granted, nil", first, err)
	}
	second, err = reusedAdmitter.AdmitKDF(context.Background(), profile)
	if err != nil || second != pcv3credential.KDFAdmissionDeniedUnknown {
		t.Fatalf("reused observation = %v, %v; want denied, nil", second, err)
	}
	if reusedProvider.calls != 2 {
		t.Fatalf("reused provider calls = %d; want 2", reusedProvider.calls)
	}
}
