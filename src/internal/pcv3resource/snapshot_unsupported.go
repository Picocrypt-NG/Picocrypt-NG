//go:build (darwin && !cgo) || (!linux && !darwin && !windows && !android)

package pcv3resource

import (
	"context"
	"runtime"
)

type unsupportedSnapshotProvider struct{}

func newPlatformSnapshotProvider() snapshotProvider {
	return unsupportedSnapshotProvider{}
}

func (unsupportedSnapshotProvider) Snapshot(context.Context) Snapshot {
	if runtime.GOOS == "darwin" {
		return newSnapshot(snapshotSourceDarwin, snapshotStateUnsupported, 0, 0, 0, false)
	}
	return newSnapshot(snapshotSourceUnknown, snapshotStateUnsupported, 0, 0, 0, false)
}
