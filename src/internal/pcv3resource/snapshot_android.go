//go:build android

package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3credential"
	"context"
)

// androidSnapshotProvider obtains fresh facts through the operation-scoped
// Kotlin challenge. It has no device or firmware allowlist.
type androidSnapshotProvider struct{}

func newPlatformSnapshotProvider() snapshotProvider {
	return androidSnapshotProvider{}
}

func (androidSnapshotProvider) AndroidReadPolicyConfigured() bool {
	return true
}

func (androidSnapshotProvider) Snapshot(context.Context) Snapshot {
	return newUnknownAndroidSnapshot()
}

func (androidSnapshotProvider) snapshotForKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) Snapshot {
	if ctx == nil {
		return newUnknownAndroidSnapshot()
	}
	session, _ := ctx.Value(androidResourceSessionContextKey{}).(*AndroidResourceSession)
	if session == nil {
		return newUnknownAndroidSnapshot()
	}
	return session.snapshotForKDF(ctx, profile)
}
