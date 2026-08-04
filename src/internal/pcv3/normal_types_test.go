package pcv3

import (
	"fmt"
	"strings"
	"testing"
)

func TestNormalAuthResultRegistryAndRedaction(t *testing.T) {
	tests := []struct {
		outcome normalAuthOutcome
		stage   normalAuthStage
		wantOut string
		wantStg string
	}{
		{normalOutcomeSuccess, normalStageNone, "success", "none"},
		{normalOutcomeInvalidStructurePreKDF, normalStageCapsuleStructure, "invalid-structure-pre-kdf", "capsule-structure"},
		{normalOutcomeCredentialsOrDamage, normalStageWrapAuth, "credentials-or-damage", "wrap-auth"},
		{normalOutcomeAuthenticatedDegraded, normalStageReplicaAuth, "authenticated-degraded", "replica-auth"},
		{normalOutcomeAmbiguousVolume, normalStageCapsuleStructure, "ambiguous-volume", "capsule-structure"},
	}
	for _, test := range tests {
		if got := test.outcome.String(); got != test.wantOut {
			t.Errorf("outcome string = %q; want %q", got, test.wantOut)
		}
		if got := test.stage.String(); got != test.wantStg {
			t.Errorf("stage string = %q; want %q", got, test.wantStg)
		}
	}

	result := newNormalAuthResult(
		normalOutcomeCredentialsOrDamage,
		normalStageWrapAuth,
		0,
	)
	canary := "credential-root=00112233445566778899aabbccddeeff"
	for _, rendered := range []string{
		result.Error(),
		result.String(),
		result.GoString(),
		fmt.Sprintf("%v", result),
		fmt.Sprintf("%+v", result),
		fmt.Sprintf("%#v", result),
	} {
		if strings.Contains(rendered, canary) ||
			rendered != "pcv3: credentials incorrect or volume damaged" {
			t.Fatalf("normal auth result rendered %q", rendered)
		}
	}
	result.Close()
}
