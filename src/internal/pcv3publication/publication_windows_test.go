//go:build windows

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"testing"
)

func TestWindowsNativeNoReplacePublishesWithUncertainDurability(t *testing.T) {
	testNativeNoReplacePublication(
		t,
		StatePublishedDurabilityUncertain,
		pcv3result.OutcomeCommittedDurabilityUncertain,
		pcv3result.StageDirectorySync,
		CodeDurabilityUncertain,
	)
}

func TestWindowsSetFileInformationRejectsLateCollision(t *testing.T) {
	testNativeLateCollision(t)
}

func TestWindowsSafeReplaceFailsBeforeStage(t *testing.T) {
	testNativeSafeReplaceFailsBeforeStage(t)
}
