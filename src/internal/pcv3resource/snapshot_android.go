//go:build android

package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
)

// androidSnapshotProvider deliberately supplies no guessed resource facts.
// A calibrated provider is frozen only after the representative-device gate.
type androidSnapshotProvider struct{}

func newPlatformSnapshotProvider() snapshotProvider {
	return androidSnapshotProvider{}
}

func (androidSnapshotProvider) AndroidReadPolicyConfigured() bool {
	return false
}

func (androidSnapshotProvider) Snapshot(context.Context) Snapshot {
	return newAndroidBrokerSnapshot(snapshotStateUnconfigured)
}

func (androidSnapshotProvider) snapshotForKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) Snapshot {
	if ctx == nil {
		return newAndroidBrokerSnapshot(snapshotStateUnconfigured)
	}
	session, _ := ctx.Value(androidResourceSessionContextKey{}).(*AndroidResourceSession)
	if session == nil {
		return newAndroidBrokerSnapshot(snapshotStateUnconfigured)
	}
	return session.snapshotForKDF(ctx, profile)
}
