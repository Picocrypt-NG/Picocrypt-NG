package pcv3

import (
	"fmt"
	"strings"
	"testing"
)

func TestNormalAuthResultRegistryAndRedaction(t *testing.T) {
	tests := []struct {
		outcome Outcome
		stage   Stage
		code    Code
		wantOut string
		wantStg string
	}{
		{OutcomeSuccess, StageNone, CodeSuccess, "success", "none"},
		{OutcomeInvalidStructurePreKDF, StageCapsuleStructure, CodeInvalidStructure, "invalid-structure-pre-kdf", "capsule-structure"},
		{OutcomeCredentialsOrDamage, StageWrapAuth, CodeCredentialsOrDamage, "credentials-or-damage", "wrap-auth"},
		{OutcomeAuthenticatedDegraded, StageReplicaAuth, CodeAuthenticatedDegraded, "authenticated-degraded", "replica-auth"},
		{OutcomeAmbiguousVolume, StageCapsuleStructure, CodeAmbiguousVolume, "ambiguous-volume", "capsule-structure"},
	}
	for _, test := range tests {
		if got := test.outcome.String(); got != test.wantOut {
			t.Errorf("outcome string = %q; want %q", got, test.wantOut)
		}
		if got := test.stage.String(); got != test.wantStg {
			t.Errorf("stage string = %q; want %q", got, test.wantStg)
		}
		if got := newNormalAuthResult(test.outcome, test.stage, 0).Code(); got != test.code {
			t.Errorf("code = %v; want %v", got, test.code)
		}
	}

	result := newNormalAuthResult(
		OutcomeCredentialsOrDamage,
		StageWrapAuth,
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
