//go:build darwin

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"testing"
)

func TestDarwinNativeNoReplacePublishesDurably(t *testing.T) {
	testNativeNoReplacePublication(
		t,
		StatePublishedDurable,
		pcv3result.OutcomeSuccess,
		pcv3result.StageNone,
		CodePublishedDurable,
	)
}

func TestDarwinRenameatxNpRejectsLateCollision(t *testing.T) {
	testNativeLateCollision(t)
}

func TestDarwinSafeReplaceFailsBeforeStage(t *testing.T) {
	testNativeSafeReplaceFailsBeforeStage(t)
}
