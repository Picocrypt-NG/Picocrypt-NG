package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
)

func TestPCV3MobileD1SuiteHintTransfersOnlyExplicitRawIntent(t *testing.T) {
	for _, test := range []struct {
		wire  string
		suite pcv3operation.Suite
	}{
		{"standard", pcv3operation.SuiteStandard}, {"paranoid", pcv3operation.SuiteParanoid},
	} {
		t.Run(test.wire, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				directory := t.TempDir()
				source := writePCV3MobileFile(t, directory, "input", "damaged D1")
				wire := pcv3TestEnvelope("force-unverified-d1", "password", "none", source, filepath.Join(directory, "output"), nil)
				wire = strings.TrimSuffix(wire, "}") + `,"d1SuiteHint":"` + test.wire + `"}`
				oldRun := runPCV3Operation
				reached := false
				runPCV3Operation = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
					reached = true
					if request.Mode != pcv3operation.ModeForceUnverifiedD1 || request.D1SuiteHint != test.suite || request.Consent == nil {
						t.Errorf("raw-D1 suite intent changed: mode=%v hint=%v consent=%v", request.Mode, request.D1SuiteHint, request.Consent != nil)
					}
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return pcv3operation.Run(ctx, request)
				}
				t.Cleanup(func() { runPCV3Operation = oldRun })
				password := []byte("password")
				start := StartPCV3(wire, password)
				if start == nil || start.Code() != "" || start.Operation() == nil {
					t.Fatalf("valid raw-D1 suite hint refused: %#v", start)
				}
				t.Cleanup(func() { cleanupOperation(start.Operation().ID()) })
				synctest.Wait()
				if !reached || !allZero(password) {
					t.Fatal("suite transfer lost native route or password cleanup")
				}
			})
		})
	}
}

func TestPCV3MobileD1SuiteHintRejectsWrongRoutesAndValues(t *testing.T) {
	for _, mode := range []string{"read-normal", "read-d1", "recover-d1", "force-d1", "force-unverified-normal"} {
		wire := pcv3TestEnvelope(mode, "password", "none", "/input", "/output", nil)
		if _, err := decodePCV3Envelope(strings.TrimSuffix(wire, "}") + `,"d1SuiteHint":"standard"}`); err == nil {
			t.Fatalf("suite hint admitted for %s", mode)
		}
	}
	for _, value := range []string{`null`, `""`, `"future"`, `1`} {
		wire := pcv3TestEnvelope("force-unverified-d1", "password", "none", "/input", "/output", nil)
		if _, err := decodePCV3Envelope(strings.TrimSuffix(wire, "}") + `,"d1SuiteHint":` + value + `}`); err == nil {
			t.Fatalf("invalid suite hint admitted: %s", value)
		}
	}
}
