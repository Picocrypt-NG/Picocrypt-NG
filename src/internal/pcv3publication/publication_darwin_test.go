//go:build darwin

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3"
	"testing"
)

func TestDarwinNativeNoReplacePublishesDurably(t *testing.T) {
	testNativeNoReplacePublication(
		t,
		StatePublishedDurable,
		pcv3.OutcomeSuccess,
		pcv3.StageNone,
		CodePublishedDurable,
	)
}

func TestDarwinRenameatxNpRejectsLateCollision(t *testing.T) {
	testNativeLateCollision(t)
}

func TestDarwinSafeReplaceFailsBeforeStage(t *testing.T) {
	testNativeSafeReplaceFailsBeforeStage(t)
}
