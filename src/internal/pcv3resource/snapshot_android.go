//go:build android

package pcv3resource

import (
	"context"

	"Picocrypt-NG/internal/pcv3credential"
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
	return newAndroidBrokerSnapshot(snapshotStateUnconfigured, 0, 0, 0, false)
}

func (androidSnapshotProvider) snapshotForKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) Snapshot {
	session := androidResourceSessionFromContext(ctx)
	if session == nil {
		return newAndroidBrokerSnapshot(snapshotStateUnconfigured, 0, 0, 0, false)
	}
	return session.snapshotForKDF(ctx, profile)
}
