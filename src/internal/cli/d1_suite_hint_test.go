package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestPCV3CLID1SuiteHintRemainsExplicitAndRawOnly(t *testing.T) {
	for _, test := range []struct {
		name, action, role, hint string
		want                     pcv3operation.Suite
	}{
		{"standard raw", "force", "front", "standard", pcv3operation.SuiteStandard},
		{"paranoid raw", "force", "tail", "paranoid", pcv3operation.SuiteParanoid},
		{"ordinary read", "", "", "standard", 0},
		{"verified force", "force", "", "paranoid", 0},
		{"unknown suite", "force", "front", "future", 0},
		{"empty suite", "force", "front", "", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			input := writePCV3CLIFixture(t, directory, "input", []byte("random-looking D1 input"))
			args := []string{
				"decrypt", input, "-o", filepath.Join(directory, "output"), "--pcv3-format=d1",
				"--pcv3-factors=password", "-p", "password", "--pcv3-d1-suite=" + test.hint,
			}
			if test.action != "" {
				args = append(args, "--pcv3-action="+test.action)
			}
			if test.role != "" {
				args = append(args, "--pcv3-role="+test.role)
			}
			result, observation := runPCV3CLIHelper(t, directory, pcv3CLIHelperConfig{
				Args:        args,
				Observation: filepath.Join(directory, "observation"),
			}, nil)
			if test.want == 0 {
				if observation.Called || result.exitCode == 0 {
					t.Fatalf("invalid suite hint reached operation: %#v %s", observation, result.stderr)
				}
			} else if !observation.Called || observation.Mode != uint8(pcv3operation.ModeForceUnverifiedD1) ||
				observation.D1SuiteHint != uint16(test.want) || !observation.ConsentPresent {
				t.Fatalf("explicit suite intent was lost: %#v %s", observation, result.stderr)
			}
		})
	}
}

func TestPCV3CLID1SuiteHintDoesNotSelectNormalOrLegacyRecovery(t *testing.T) {
	for _, test := range []struct {
		name     string
		contents []byte
		message  string
	}{
		{"normal", loadPCV3CLIFixture(t), "--pcv3-d1-suite requires"},
		{"legacy", []byte("legacy-shaped input"), "normal PCV3 must be selected by content"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			input := writePCV3CLIFixture(t, directory, "input", test.contents)
			result, observation := runPCV3CLIHelper(t, directory, pcv3CLIHelperConfig{
				Args: []string{
					"decrypt", input, "-o", filepath.Join(directory, "output"),
					"--pcv3-factors=password", "-p", "password", "--pcv3-action=force", "--pcv3-role=primary", "--pcv3-d1-suite=standard",
				},
				Observation: filepath.Join(directory, "observation"),
			}, nil)
			if observation.Called || result.exitCode == 0 || !strings.Contains(result.stderr, test.message) {
				t.Fatalf("D1 suite hint escaped its explicit format route: %#v %s", observation, result.stderr)
			}
		})
	}
}

func TestPCV3CLIUnknownD1ProfileExplainsExplicitUnverifiedChoice(t *testing.T) {
	var output bytes.Buffer
	exit := renderPCV3CLIResult(&output, &pcv3CLIFixedResult{
		outcome: pcv3operation.OutcomeOperationFailed, stage: pcv3operation.StageD1Bootstrap,
		code: pcv3operation.CodeOperationFailed, class: pcv3operation.CompletionNoOutput,
		diagnosticCode: pcv3operation.DiagnosticD1ProfileRequired,
	})
	if exit != ExitGeneralError || !strings.Contains(output.String(), "--pcv3-d1-suite") || !strings.Contains(output.String(), "--pcv3-role") {
		t.Fatalf("unknown hidden profile lost its safe next action: exit=%d output=%q", exit, output.String())
	}
}
