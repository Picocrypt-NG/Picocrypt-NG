//go:build linux

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"testing"
)

func TestLinuxNativeNoReplacePublishesDurably(t *testing.T) {
	testNativeNoReplacePublication(
		t,
		StatePublishedDurable,
		pcv3result.OutcomeSuccess,
		pcv3result.StageNone,
		CodePublishedDurable,
	)
}

func TestLinuxRenameat2RejectsLateCollision(t *testing.T) {
	testNativeLateCollision(t)
}

func TestLinuxSafeReplaceFailsBeforeStage(t *testing.T) {
	testNativeSafeReplaceFailsBeforeStage(t)
}
