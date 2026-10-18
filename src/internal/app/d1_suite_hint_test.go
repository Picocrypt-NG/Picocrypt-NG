package app

import (
	"Picocrypt-NG/internal/pcv3operation"
	"os"
	"path/filepath"
	"testing"
)

func TestD1RecoverySuiteHintTransfersAndClearsWithSelection(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "input.pcv")
	if err := os.WriteFile(path, []byte("public recovery selection"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if !s.SetPCV3Ready(source, PCV3FormatD1, path, path+".out", 0) {
		t.Fatal("set D1 selection")
	}
	s.Password = "test password"
	s.SetPCV3Intent(PCV3ActionForceUnverified, PCV3FactorPolicyPassword, PCV3KeyfileOrderUnset)
	s.PCV3D1SuiteHint = pcv3operation.SuiteStandard
	intent, ok := s.TakePCV3OperationIntent()
	if !ok || intent.D1SuiteHint != pcv3operation.SuiteStandard {
		t.Fatalf("captured D1 recovery profile = %v, accepted=%v", intent.D1SuiteHint, ok)
	}
	s.Reset()
	if s.UISnapshot().PCV3D1SuiteHint != 0 {
		t.Fatal("cleared selection retained a recovery-only profile")
	}
}

func TestD1RecoverySuiteHintDoesNotFollowOtherActions(t *testing.T) {
	for _, action := range []PCV3Action{PCV3ActionDecrypt, PCV3ActionRecovery, PCV3ActionForce} {
		s, err := NewState()
		if err != nil {
			t.Fatal(err)
		}
		s.PCV3Format = PCV3FormatD1
		s.PCV3D1SuiteHint = pcv3operation.SuiteParanoid
		s.SetPCV3Intent(action, PCV3FactorPolicyPassword, PCV3KeyfileOrderUnset)
		if s.PCV3D1SuiteHint != 0 {
			t.Fatalf("action %v retained an unverified-recovery profile", action)
		}
	}
}
