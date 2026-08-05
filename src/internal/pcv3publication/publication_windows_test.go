//go:build windows

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3"
	"testing"
)

func TestWindowsNativeNoReplacePublishesWithUncertainDurability(t *testing.T) {
	testNativeNoReplacePublication(
		t,
		StatePublishedDurabilityUncertain,
		pcv3.OutcomeCommittedDurabilityUncertain,
		pcv3.StageDirectorySync,
		CodeDurabilityUncertain,
	)
}

func TestWindowsSetFileInformationRejectsLateCollision(t *testing.T) {
	testNativeLateCollision(t)
}

func TestWindowsSafeReplaceFailsBeforeStage(t *testing.T) {
	testNativeSafeReplaceFailsBeforeStage(t)
}
