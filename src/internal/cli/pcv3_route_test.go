package cli

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const pcv3CLIHelperConfigEnv = "PICOCRYPT_TEST_PCV3_CLI_HELPER_CONFIG"

type pcv3CLIHelperConfig struct {
	Args           []string `json:"args"`
	Observation    string   `json:"observation"`
	OpenLog        string   `json:"open_log,omitempty"`
	Interactive    bool     `json:"interactive,omitempty"`
	ConsentLine    string   `json:"consent_line,omitempty"`
	RealOperation  bool     `json:"real_operation,omitempty"`
	AttackerText   string   `json:"attacker_text,omitempty"`
	ResultScenario string   `json:"result_scenario,omitempty"`
}

type pcv3CLIObservation struct {
	Called         bool     `json:"called"`
	Mode           uint8    `json:"mode"`
	FactorMode     uint8    `json:"factor_mode"`
	KeyfileMode    uint8    `json:"keyfile_mode"`
	ExpectedPolicy uint8    `json:"expected_policy"`
	Password       string   `json:"password"`
	KeyfileCount   int      `json:"keyfile_count"`
	SourcePrefix   string   `json:"source_prefix"`
	Target         string   `json:"target"`
	Protected      []string `json:"protected"`
	ConsentPresent bool     `json:"consent_present"`
}

type pcv3CLIFixedResult struct {
	outcome              pcv3operation.Outcome
	stage                pcv3operation.Stage
	code                 pcv3operation.Code
	publicationAttempted bool
	publicationState     pcv3publication.State
	publicationStage     pcv3operation.Stage
	publicationCode      pcv3publication.Code
	warnings             []pcv3operation.Warning
	class                pcv3operation.CompletionClass
	archive              pcv3CLIArchiveFollowUp
	output               pcv3CLIOutputFollowUp
	diagnostic           string
}

func (result *pcv3CLIFixedResult) Outcome() pcv3operation.Outcome { return result.outcome }

func (result *pcv3CLIFixedResult) Stage() pcv3operation.Stage { return result.stage }

func (result *pcv3CLIFixedResult) Code() pcv3operation.Code { return result.code }

func (result *pcv3CLIFixedResult) PublicationAttempted() bool {
	return result.publicationAttempted
}

func (result *pcv3CLIFixedResult) PublicationState() pcv3publication.State {
	return result.publicationState
}

func (result *pcv3CLIFixedResult) PublicationStage() pcv3operation.Stage {
	return result.publicationStage
}

func (result *pcv3CLIFixedResult) PublicationCode() pcv3publication.Code {
	return result.publicationCode
}

func (result *pcv3CLIFixedResult) Warnings() []pcv3operation.Warning {
	return append([]pcv3operation.Warning(nil), result.warnings...)
}

func (result *pcv3CLIFixedResult) CompletionClass() pcv3operation.CompletionClass {
	return result.class
}

func (result *pcv3CLIFixedResult) ArchiveFollowUp() pcv3CLIArchiveFollowUp {
	return result.archive
}

func (result *pcv3CLIFixedResult) OutputFollowUp() pcv3CLIOutputFollowUp {
	return result.output
}

func (result *pcv3CLIFixedResult) Error() string { return result.diagnostic }

func (result *pcv3CLIFixedResult) String() string { return result.diagnostic }

func pcv3CLIRefusalResult() pcv3CLIResult {
	return &pcv3CLIFixedResult{
		outcome: pcv3operation.OutcomeOperationFailed,
		stage:   pcv3operation.StageCredentialPolicy,
		code:    pcv3operation.CodeOperationFailed,
		class:   pcv3operation.CompletionRefused,
	}
}

// TestPCV3CLIProcessHelper runs the real Cobra command path in a child process.
// The substitution is at the already independently tested operation boundary;
// request capture therefore exercises CLI routing, descriptor ownership, and
// terminal mapping without invoking the fixed 1 GiB Argon2id profile.
func TestPCV3CLIProcessHelper(t *testing.T) {
	configPath := os.Getenv(pcv3CLIHelperConfigEnv)
	if configPath == "" {
		return
	}
	encoded, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper configuration unavailable")
		os.Exit(97)
	}
	var config pcv3CLIHelperConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		fmt.Fprintln(os.Stderr, "helper configuration invalid")
		os.Exit(97)
	}

	pcv3CLIIsInteractive = func() bool { return config.Interactive }
	pcv3CLIReadConsent = func() (string, error) { return config.ConsentLine, nil }
	if config.OpenLog != "" {
		pcv3CLIOpenKeyfile = func(path string) (*os.File, error) {
			file, openErr := fileops.OpenExistingNoSymlink(path, os.O_RDONLY)
			if openErr != nil {
				return nil, openErr
			}
			log, logErr := os.OpenFile(config.OpenLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if logErr != nil {
				_ = file.Close()
				return nil, logErr
			}
			_, writeErr := fmt.Fprintln(log, filepath.Base(path))
			closeErr := log.Close()
			if writeErr != nil || closeErr != nil {
				_ = file.Close()
				return nil, errors.Join(writeErr, closeErr)
			}
			return file, nil
		}
	}

	pcv3CLIRunOperation = func(
		_ context.Context,
		request *pcv3operation.Request,
		retainOutput bool,
	) pcv3CLIResult {
		observation := observePCV3CLIRequest(request)
		if config.RealOperation {
			result := pcv3CLIResultAdapter{result: pcv3operation.RunWithOptions(
				context.Background(),
				request,
				pcv3operation.ExecutionOptions{RetainDurableOutput: retainOutput},
			)}
			writePCV3CLIObservation(config.Observation, observation)
			return result
		}
		consumePCV3CLIRequest(request)
		writePCV3CLIObservation(config.Observation, observation)
		return pcv3CLIFixedResultForScenario(config.ResultScenario, config.AttackerText)
	}

	rootCmd.SetArgs(config.Args)
	err = rootCmd.Execute()
	if err != nil && !isExitCodeError(err) {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
	os.Exit(exitCodeForError(err))
}

func observePCV3CLIRequest(request *pcv3operation.Request) pcv3CLIObservation {
	observation := pcv3CLIObservation{Called: true}
	if request == nil {
		return observation
	}
	observation.Mode = uint8(request.Mode)
	observation.Target = request.Target
	observation.Protected = append([]string(nil), request.Protected...)
	observation.ConsentPresent = request.Consent != nil
	if request.Factors != nil {
		observation.FactorMode = uint8(request.Factors.Mode)
		observation.KeyfileMode = uint8(request.Factors.KeyfileMode)
		observation.ExpectedPolicy = uint8(request.Factors.ExpectedPolicy)
		observation.Password = string(request.Factors.Password)
		observation.KeyfileCount = len(request.Factors.Keyfiles)
	}
	if request.Source != nil {
		var prefix [4]byte
		count, _ := request.Source.ReadAt(prefix[:], 0)
		observation.SourcePrefix = string(prefix[:count])
	}
	return observation
}

func consumePCV3CLIRequest(request *pcv3operation.Request) {
	if request == nil {
		return
	}
	if request.Factors != nil {
		_ = request.Factors.Close()
		request.Factors = nil
	}
	if request.Source != nil {
		_ = request.Source.Close()
		request.Source = nil
	}
	request.Consent = nil
	request.Reporter = nil
}

func writePCV3CLIObservation(path string, observation pcv3CLIObservation) {
	if path == "" {
		return
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, encoded, 0o600)
}

func pcv3CLIFixedResultForScenario(scenario, attacker string) pcv3CLIResult {
	switch scenario {
	case "", "refusal":
		return pcv3CLIRefusalResult()
	case "clean":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeSuccess, stage: pcv3operation.StageNone, code: pcv3operation.CodeSuccess,
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublishedDurable,
			publicationCode:      pcv3publication.CodePublishedDurable,
			class:                pcv3operation.CompletionClean,
			diagnostic:           attacker,
		}
	case "warning":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeForceUnverified, stage: pcv3operation.StageRecordAuth, code: pcv3operation.CodeForceUnverified,
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublishedDurable,
			publicationCode:      pcv3publication.CodePublishedDurable,
			warnings:             []pcv3operation.Warning{pcv3operation.WarningForceUnverified},
			class:                pcv3operation.CompletionWarning,
			diagnostic:           attacker,
		}
	case "degraded":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeAuthenticatedDegraded, stage: pcv3operation.StageMetadata, code: pcv3operation.CodeAuthenticatedDegraded,
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublishedDurable,
			publicationCode:      pcv3publication.CodePublishedDurable,
			warnings:             []pcv3operation.Warning{pcv3operation.WarningAuthenticatedDegraded},
			class:                pcv3operation.CompletionWarning,
			diagnostic:           attacker,
		}
	case "partial":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeForcePartial, stage: pcv3operation.StageRecordAuth, code: pcv3operation.CodeForcePartial,
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublishedDurable,
			publicationCode:      pcv3publication.CodePublishedDurable,
			warnings:             []pcv3operation.Warning{pcv3operation.WarningForcePartial},
			class:                pcv3operation.CompletionWarning,
			diagnostic:           attacker,
		}
	case "cleanup-warning":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeSuccess, stage: pcv3operation.StageNone, code: pcv3operation.CodeSuccess,
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublishedDurable,
			publicationCode:      pcv3publication.CodePublishedDurable,
			warnings:             []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete},
			class:                pcv3operation.CompletionWarning,
			diagnostic:           attacker,
		}
	case "uncertain":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeSuccess, stage: pcv3operation.StageNone, code: pcv3operation.CodeSuccess,
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublishedDurabilityUncertain,
			publicationStage:     pcv3operation.StageDirectorySync,
			publicationCode:      pcv3publication.CodeDurabilityUncertain,
			warnings:             []pcv3operation.Warning{pcv3operation.WarningDurabilityUncertain},
			class:                pcv3operation.CompletionDurabilityUncertain,
			diagnostic:           attacker,
		}
	case "indeterminate":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeForcePartial, stage: pcv3operation.StageRecordAuth, code: pcv3operation.CodeForcePartial,
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublicationIndeterminate,
			publicationStage:     pcv3operation.StageOutputPublication,
			publicationCode:      pcv3publication.CodePublicationIndeterminate,
			warnings: []pcv3operation.Warning{
				pcv3operation.WarningForcePartial,
				pcv3operation.WarningPublicationIndeterminate,
			},
			class:      pcv3operation.CompletionPublicationIndeterminate,
			diagnostic: attacker,
		}
	case "unknown":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.Outcome(255), stage: pcv3operation.Stage(255), code: pcv3operation.Code(255),
			publicationAttempted: true,
			publicationState:     pcv3publication.State(255),
			publicationStage:     pcv3operation.Stage(255),
			publicationCode:      pcv3publication.Code(255),
			warnings:             []pcv3operation.Warning{pcv3operation.Warning(255)},
			class:                pcv3operation.CompletionUnknown,
			diagnostic:           attacker,
		}
	case "not-published":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeOperationFailed, stage: pcv3operation.StageOutputPublication, code: pcv3operation.CodeOperationFailed,
			publicationAttempted: true,
			publicationState:     pcv3publication.StateNotPublished,
			publicationStage:     pcv3operation.StageOutputPublication,
			publicationCode:      pcv3publication.CodeAtomicFailed,
			class:                pcv3operation.CompletionNoOutput,
			diagnostic:           attacker,
		}
	case "archive-signal":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeSuccess, stage: pcv3operation.StageNone, code: pcv3operation.CodeSuccess,
			class: pcv3operation.CompletionArchivePending,
			archive: &pcv3CLIFakeArchive{extract: func(ctx context.Context, root *os.Root) pcv3CLIResult {
				if root != nil {
					defer func() { _ = root.Close() }()
				}
				handleSignal()
				if ctx.Err() == nil {
					return pcv3CLIFixedResultForScenario("unknown", "")
				}
				return pcv3CLIFixedResultForScenario("not-published", "")
			}},
		}
	case "archive-close":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeSuccess, stage: pcv3operation.StageNone, code: pcv3operation.CodeSuccess,
			class: pcv3operation.CompletionArchivePending,
			archive: &pcv3CLIFakeArchive{close: func() pcv3CLIResult {
				return &pcv3CLIFixedResult{
					outcome: pcv3operation.OutcomeOperationFailed,
					stage:   pcv3operation.StageOutputPublication,
					code:    pcv3operation.CodeOperationFailed,
					class:   pcv3operation.CompletionNoOutput,
				}
			}},
		}
	case "archive-extract":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeSuccess, stage: pcv3operation.StageNone, code: pcv3operation.CodeSuccess,
			class: pcv3operation.CompletionArchivePending,
			archive: &pcv3CLIFakeArchive{extract: func(_ context.Context, root *os.Root) pcv3CLIResult {
				if root == nil {
					return pcv3CLIRefusalResult()
				}
				file, err := root.OpenFile("extracted.txt", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if err == nil {
					_, err = file.Write([]byte("authenticated archive contents"))
					err = errors.Join(err, file.Close())
				}
				_ = root.Close()
				if err != nil {
					return pcv3CLIRefusalResult()
				}
				return pcv3CLIFixedResultForScenario("clean", "")
			}},
		}
	case "archive-expired":
		return &pcv3CLIFixedResult{
			outcome: pcv3operation.OutcomeSuccess, stage: pcv3operation.StageNone, code: pcv3operation.CodeSuccess,
			class: pcv3operation.CompletionArchivePending,
		}
	}
	return pcv3CLIRefusalResult()
}

func runPCV3CLIHelper(
	t *testing.T,
	dir string,
	config pcv3CLIHelperConfig,
	stdin []byte,
	extraEnv ...string,
) (cliTestResult, pcv3CLIObservation) {
	t.Helper()
	if config.Observation == "" {
		config.Observation = filepath.Join(dir, "observation.json")
	}
	configPath := filepath.Join(dir, "helper.json")
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal helper configuration: %v", err)
	}
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatalf("write helper configuration: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestPCV3CLIProcessHelper$")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), append([]string{pcv3CLIHelperConfigEnv + "=" + configPath}, extraEnv...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	var observation pcv3CLIObservation
	if observed, readErr := os.ReadFile(config.Observation); readErr == nil {
		if err := json.Unmarshal(observed, &observation); err != nil {
			t.Fatalf("decode helper observation: %v", err)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		t.Fatalf("read helper observation: %v", readErr)
	}
	return cliTestResult{exitCode: exitCode, stdout: stdout.Bytes(), stderr: stderr.String()}, observation
}

func loadPCV3CLIFixture(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "schema1-minimal.pcv"))
	if err != nil {
		t.Fatalf("read literal PCV3 fixture: %v", err)
	}
	return fixture
}

func writePCV3CLIFixture(t *testing.T, dir, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write PCV3 CLI fixture: %v", err)
	}
	return path
}

func TestPCV3CLIPreservesFactorIntent(t *testing.T) {
	fixture := loadPCV3CLIFixture(t)
	tests := []struct {
		name          string
		args          func(input, output, first, second string) []string
		wantMode      pcv3operation.Mode
		wantFactor    pcv3operation.CredentialMode
		wantOrder     pcv3operation.KeyfileMode
		wantPolicy    pcv3operation.FactorPolicy
		wantPassword  string
		wantOpenOrder []string
	}{
		{
			name: "password only normal content route",
			args: func(input, output, _, _ string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-factors=password", "-p", "raw-password"}
			},
			wantMode:     pcv3operation.ModeReadNormal,
			wantFactor:   pcv3operation.CredentialModePasswordOnly,
			wantOrder:    pcv3operation.KeyfileModeNone,
			wantPolicy:   pcv3operation.FactorPolicyPasswordOnly,
			wantPassword: "raw-password",
		},
		{
			name: "keyfiles only preserves duplicate selected order",
			args: func(input, output, first, second string) []string {
				return []string{
					"decrypt", input, "-o", output,
					"--pcv3-factors=keyfiles", "--pcv3-keyfile-order=ordered", "-p", "",
					"-k", second, "-k", first, "-k", second,
				}
			},
			wantMode:      pcv3operation.ModeReadNormal,
			wantFactor:    pcv3operation.CredentialModeKeyfilesOnly,
			wantOrder:     pcv3operation.KeyfileModeOrdered,
			wantPolicy:    pcv3operation.FactorPolicyKeyfilesOnly,
			wantOpenOrder: []string{"second.key", "first.key", "second.key"},
		},
		{
			name: "combined unordered preserves caller order",
			args: func(input, output, first, second string) []string {
				return []string{
					"decrypt", input, "-o", output,
					"--pcv3-factors=combined", "--pcv3-keyfile-order=unordered", "-p", "combined-password",
					"-k", first, "-k", second,
				}
			},
			wantMode:      pcv3operation.ModeReadNormal,
			wantFactor:    pcv3operation.CredentialModePasswordAndKeyfiles,
			wantOrder:     pcv3operation.KeyfileModeUnordered,
			wantPolicy:    pcv3operation.FactorPolicyPasswordAndKeyfiles,
			wantPassword:  "combined-password",
			wantOpenOrder: []string{"first.key", "second.key"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			input := writePCV3CLIFixture(t, dir, "misleading.bin", fixture)
			output := filepath.Join(dir, "plaintext")
			first := writePCV3CLIFixture(t, dir, "first.key", []byte("first-keyfile"))
			second := writePCV3CLIFixture(t, dir, "second.key", []byte("second-keyfile"))
			openLog := filepath.Join(dir, "opens.log")
			result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
				Args:        test.args(input, output, first, second),
				Observation: filepath.Join(dir, "observation.json"),
				OpenLog:     openLog,
			}, nil)
			if result.exitCode != ExitGeneralError || len(result.stdout) != 0 {
				t.Fatalf("result = exit %d stdout %q stderr %q; want closed refusal", result.exitCode, result.stdout, result.stderr)
			}
			if !observation.Called {
				t.Fatal("PCV3 content route did not reach operation boundary")
			}
			if got := pcv3operation.Mode(observation.Mode); got != test.wantMode {
				t.Fatalf("mode = %v; want %v", got, test.wantMode)
			}
			if got := pcv3operation.CredentialMode(observation.FactorMode); got != test.wantFactor {
				t.Fatalf("factor mode = %v; want %v", got, test.wantFactor)
			}
			if got := pcv3operation.KeyfileMode(observation.KeyfileMode); got != test.wantOrder {
				t.Fatalf("keyfile order = %v; want %v", got, test.wantOrder)
			}
			if got := pcv3operation.FactorPolicy(observation.ExpectedPolicy); got != test.wantPolicy {
				t.Fatalf("factor policy = %v; want %v", got, test.wantPolicy)
			}
			if observation.Password != test.wantPassword {
				t.Fatalf("password bytes changed: got %q want %q", observation.Password, test.wantPassword)
			}
			if observation.KeyfileCount != len(test.wantOpenOrder) {
				t.Fatalf("keyfile count = %d; want %d", observation.KeyfileCount, len(test.wantOpenOrder))
			}
			var opened []string
			if data, err := os.ReadFile(openLog); err == nil {
				opened = strings.Fields(string(data))
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("read keyfile open log: %v", err)
			}
			if !reflect.DeepEqual(opened, test.wantOpenOrder) {
				t.Fatalf("keyfile open order = %v; want exact %v", opened, test.wantOpenOrder)
			}
			if observation.SourcePrefix != "PCV\x00" {
				t.Fatalf("operation source prefix = %q; want retained claimed descriptor", observation.SourcePrefix)
			}
			if observation.Target != output {
				t.Fatalf("target = %q; want %q", observation.Target, output)
			}
		})
	}
}

// TestPCV3CLIPasswordStdinKeepsSecretOutOfArguments protects the scripting
// credential boundary. A PCV3 password supplied on stdin must reach the owned
// factor request without requiring the secret in argv, diagnostics, or output.
func TestPCV3CLIPasswordStdinKeepsSecretOutOfArguments(t *testing.T) {
	dir := t.TempDir()
	input := writePCV3CLIFixture(t, dir, "claimed.pcv", loadPCV3CLIFixture(t))
	output := filepath.Join(dir, "plaintext")
	secret := "pcv3-stdin-secret"
	args := []string{
		"decrypt", input, "-o", output,
		"--pcv3-factors=password", "--password-stdin",
	}
	if strings.Contains(strings.Join(args, "\x00"), secret) {
		t.Fatal("test placed the stdin secret in process arguments")
	}

	result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
		Args:        args,
		Observation: filepath.Join(dir, "observation.json"),
	}, []byte(secret+"\n"))

	if result.exitCode != ExitGeneralError || !observation.Called {
		t.Fatalf(
			"stdin password route = exit %d called=%v stdout=%q stderr=%q; want operation-boundary refusal",
			result.exitCode, observation.Called, result.stdout, result.stderr,
		)
	}
	if observation.Password != secret {
		t.Fatalf("operation password = %q; want exact stdin bytes", observation.Password)
	}
	if bytes.Contains(result.stdout, []byte(secret)) || strings.Contains(result.stderr, secret) {
		t.Fatal("stdin password was exposed in command output")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused stdin-password route changed output: %v", err)
	}
}

func TestPCV3CLIRequiresExplicitModeAndLiveConsent(t *testing.T) {
	fixture := loadPCV3CLIFixture(t)
	for _, mapping := range []struct {
		normal bool
		name   string
		want   pcv3operation.PhysicalRole
	}{
		{normal: true, name: "primary", want: pcv3operation.RolePrimary},
		{normal: true, name: "backup", want: pcv3operation.RoleBackup},
		{normal: false, name: "front", want: pcv3operation.RoleD1Front},
		{normal: false, name: "tail", want: pcv3operation.RoleD1Tail},
	} {
		got, ok := pcv3CLIPhysicalRole(mapping.normal, mapping.name)
		if !ok || got != mapping.want {
			t.Fatalf("physical role %q normal=%v = %v, %v; want %v, true", mapping.name, mapping.normal, got, ok, mapping.want)
		}
	}
	tests := []struct {
		name          string
		input         []byte
		args          func(input, output string) []string
		interactive   bool
		consentLine   string
		realOperation bool
		extraEnv      []string
		wantCalled    bool
		wantMode      pcv3operation.Mode
		wantConsent   bool
		wantOutcome   string
		wantProgress  bool
		quietProgress bool
	}{
		{
			name: "normal recovery is explicit", input: fixture,
			args: func(input, output string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-factors=password", "--pcv3-action=recovery", "-p", "pw"}
			},
			wantCalled: true, wantMode: pcv3operation.ModeRecoverNormal,
		},
		{
			name: "D1 force is explicit and not content detected", input: []byte("random-looking D1 candidate"),
			args: func(input, output string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-format=d1", "--pcv3-action=force", "--pcv3-factors=password", "-p", "pw"}
			},
			wantCalled: true, wantMode: pcv3operation.ModeForceD1,
		},
		{
			name: "normal unverified force binds backup role and live literal", input: []byte{'P', 'C', 'V', 0},
			interactive: true, consentLine: "RECOVER UNVERIFIED", realOperation: true,
			args: func(input, output string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-action=force", "--pcv3-role=backup", "--pcv3-factors=password", "-p", "pw"}
			},
			wantCalled: true, wantMode: pcv3operation.ModeForceUnverifiedNormal,
			wantConsent: true, wantOutcome: "Outcome: invalid-structure-pre-kdf", wantProgress: true,
		},
		{
			name: "D1 unverified force binds tail role", input: []byte("D1!!"),
			interactive: true, consentLine: "RECOVER UNVERIFIED", realOperation: true,
			args: func(input, output string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-format=d1", "--pcv3-action=force", "--pcv3-role=tail", "--pcv3-factors=password", "-p", "pw", "--quiet"}
			},
			wantCalled: true, wantMode: pcv3operation.ModeForceUnverifiedD1,
			wantConsent: true, wantOutcome: "Outcome: credentials-or-damage", quietProgress: true,
		},
		{
			name: "near match does not grant consent", input: []byte{'P', 'C', 'V', 0},
			interactive: true, consentLine: "recover unverified", realOperation: true,
			args: func(input, output string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-action=force", "--pcv3-role=primary", "--pcv3-factors=password", "-p", "pw", "--yes"}
			},
			wantCalled: true, wantMode: pcv3operation.ModeForceUnverifiedNormal, wantConsent: true,
			wantOutcome: "Outcome: operation-failed",
		},
		{
			name: "non terminal refuses flags env and stdin literal", input: []byte{'P', 'C', 'V', 0},
			consentLine: "RECOVER UNVERIFIED", realOperation: true,
			extraEnv: []string{"PICOCRYPT_PCV3_CONSENT=RECOVER UNVERIFIED"},
			args: func(input, output string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-action=force", "--pcv3-role=primary", "--pcv3-factors=password", "-p", "pw", "--yes"}
			},
			wantCalled: true, wantMode: pcv3operation.ModeForceUnverifiedNormal, wantConsent: true,
			wantOutcome: "Outcome: operation-failed",
		},
		{
			name: "legacy force flag cannot select PCV3 force", input: fixture,
			args: func(input, output string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-factors=password", "-p", "pw", "--force"}
			},
		},
		{
			name: "incompatible D1 physical role is rejected", input: []byte("explicit D1 candidate"),
			args: func(input, output string) []string {
				return []string{"decrypt", input, "-o", output, "--pcv3-format=d1", "--pcv3-action=force", "--pcv3-role=backup", "--pcv3-factors=password", "-p", "pw"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			input := writePCV3CLIFixture(t, dir, "candidate.pcv", test.input)
			output := filepath.Join(dir, "output")
			result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
				Args: test.args(input, output), Observation: filepath.Join(dir, "observation.json"),
				Interactive: test.interactive, ConsentLine: test.consentLine, RealOperation: test.realOperation,
			}, []byte("RECOVER UNVERIFIED\n"), test.extraEnv...)
			if result.exitCode != ExitGeneralError || len(result.stdout) != 0 {
				t.Fatalf("result = exit %d stdout %q stderr %q; want closed refusal", result.exitCode, result.stdout, result.stderr)
			}
			if observation.Called != test.wantCalled {
				t.Fatalf("operation called = %v; want %v; stderr %q", observation.Called, test.wantCalled, result.stderr)
			}
			if !test.wantCalled {
				if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected route created output: %v", err)
				}
				return
			}
			if got := pcv3operation.Mode(observation.Mode); got != test.wantMode {
				t.Fatalf("mode = %v; want %v", got, test.wantMode)
			}
			if observation.ConsentPresent != test.wantConsent {
				t.Fatalf("consent callback present = %v; want %v", observation.ConsentPresent, test.wantConsent)
			}
			if test.wantOutcome != "" && !strings.Contains(result.stderr, test.wantOutcome) {
				t.Fatalf("stderr = %q; want real-core terminal %q", result.stderr, test.wantOutcome)
			}
			hasProgress := strings.Contains(result.stderr, "Checking operation…") &&
				strings.Contains(result.stderr, "Checking credential policy…")
			if test.wantProgress && !hasProgress {
				t.Fatalf("real core progress was not rendered: %q", result.stderr)
			}
			if test.quietProgress && strings.Contains(result.stderr, "Checking ") {
				t.Fatalf("quiet mode rendered progress: %q", result.stderr)
			}
		})
	}
}

// TestPCV3CLISplitRoutingUsesChunkZeroAuthority protects the split-volume
// discriminator contract: chunk zero classifies the entire recombined input.
// A selected later chunk may contain arbitrary PCV3-looking bytes and must not
// divert a legacy split into the PCV3 route.
func TestPCV3CLISplitRoutingUsesChunkZeroAuthority(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "legacy.pcv")
	legacy, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatalf("read frozen legacy chunk zero: %v", err)
	}
	if err := os.WriteFile(base+".0", legacy, 0o600); err != nil {
		t.Fatalf("write legacy chunk zero: %v", err)
	}
	if err := os.WriteFile(base+".1", loadPCV3CLIFixture(t), 0o600); err != nil {
		t.Fatalf("write PCV3-looking later chunk: %v", err)
	}
	result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
		Args: []string{
			"decrypt", base + ".1", "-o", filepath.Join(dir, "output"),
			"-p", "test",
		},
		Observation: filepath.Join(dir, "observation.json"),
	}, nil)
	if observation.Called {
		t.Fatal("nonzero split chunk diverted the legacy volume into PCV3 operation")
	}
	if !strings.Contains(result.stderr, "Detected split volume") {
		t.Fatalf("split route did not reach chunk-zero legacy path: exit %d stderr %q", result.exitCode, result.stderr)
	}
	if strings.Contains(result.stderr, "PCV3 does not support") {
		t.Fatalf("nonzero split chunk controlled the PCV3 discriminator: %q", result.stderr)
	}
}

// TestPCV3CLIRecombineBaseUsesChunkZeroAuthority protects the base-operand
// form of --recombine: a stale base file is not part of the split and must not
// override the format discriminator held by base.0. The stale file remains a
// no-replace collision when recombination later tries to claim that pathname.
func TestPCV3CLIRecombineBaseUsesChunkZeroAuthority(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "legacy.pcv")
	if err := os.WriteFile(base, loadPCV3CLIFixture(t), 0o600); err != nil {
		t.Fatalf("write stale PCV3-looking base file: %v", err)
	}
	legacy, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatalf("read frozen legacy volume: %v", err)
	}
	splitAt := len(legacy) / 2
	for index, chunk := range [][]byte{legacy[:splitAt], legacy[splitAt:]} {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", base, index), chunk, 0o600); err != nil {
			t.Fatalf("write legacy chunk %d: %v", index, err)
		}
	}
	output := filepath.Join(dir, "recovered.txt")
	result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
		Args: []string{
			"decrypt", base, "-o", output, "--recombine",
			"-p", "test", "-q", "-y",
		},
		Observation: filepath.Join(dir, "observation.json"),
	}, nil)
	if result.exitCode != ExitGeneralError || observation.Called || len(result.stdout) != 0 ||
		!strings.Contains(result.stderr, "output file already exists") ||
		strings.Contains(result.stderr, "PCV3 does not support") {
		t.Fatalf(
			"base-operand split route = exit %d called=%v stdout=%q stderr=%q; want legacy no-replace collision",
			result.exitCode, observation.Called, result.stdout, result.stderr,
		)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("base-operand collision created plaintext output: %v", err)
	}
}

func TestPCV3CLISplitChunkZeroSymlinkPreservesLegacyFallback(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "legacy.pcv")
	legacy, err := filepath.Abs(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatalf("resolve frozen legacy volume: %v", err)
	}
	if err := os.Symlink(legacy, base+".0"); err != nil {
		t.Skipf("chunk-zero symlink unavailable: %v", err)
	}
	if err := os.WriteFile(base+".1", []byte("legacy-looking later chunk"), 0o600); err != nil {
		t.Fatalf("write later chunk: %v", err)
	}
	result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
		Args: []string{
			"decrypt", base + ".1", "-o", filepath.Join(dir, "output"),
			"-p", "test",
		},
		Observation: filepath.Join(dir, "observation.json"),
	}, nil)
	if observation.Called || !strings.Contains(result.stderr, "Detected split volume") {
		t.Fatalf("chunk-zero symlink lost legacy fallback: called=%v exit=%d stderr=%q", observation.Called, result.exitCode, result.stderr)
	}
}

func TestPCV3RouteBeforeLegacyPrompts(t *testing.T) {
	fixture := loadPCV3CLIFixture(t)

	t.Run("missing PCV3 factor policy refuses before overwrite and password prompts", func(t *testing.T) {
		dir := t.TempDir()
		input := writePCV3CLIFixture(t, dir, "claimed.data", fixture)
		output := writePCV3CLIFixture(t, dir, "existing", []byte("unchanged"))
		result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
			Args:        []string{"decrypt", input, "-o", output},
			Observation: filepath.Join(dir, "observation.json"),
		}, nil)
		if result.exitCode != ExitGeneralError || observation.Called {
			t.Fatalf("result = exit %d called %v stderr %q; want pre-operation refusal", result.exitCode, observation.Called, result.stderr)
		}
		if strings.Contains(result.stderr, "Overwrite?") || strings.Contains(result.stderr, "Password:") {
			t.Fatalf("PCV3 route reached legacy prompt: %q", result.stderr)
		}
		got, err := os.ReadFile(output)
		if err != nil || string(got) != "unchanged" {
			t.Fatalf("existing output changed: %q, %v", got, err)
		}
	})

	t.Run("PCV3 legacy transforms fail closed", func(t *testing.T) {
		for _, flags := range [][]string{
			{"--deniability"},
			{"--auto-unzip"},
			{"--verify-first"},
		} {
			dir := t.TempDir()
			input := writePCV3CLIFixture(t, dir, "claimed", fixture)
			output := filepath.Join(dir, "output")
			args := []string{"decrypt", input, "-o", output, "--pcv3-factors=password", "-p", "pw"}
			args = append(args, flags...)
			result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
				Args:        args,
				Observation: filepath.Join(dir, "observation.json"),
			}, nil)
			if result.exitCode != ExitGeneralError || observation.Called || len(result.stdout) != 0 {
				t.Fatalf("flags %v = exit %d called %v stdout %q stderr %q", flags, result.exitCode, observation.Called, result.stdout, result.stderr)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("flags %v created output: %v", flags, err)
			}
		}
	})

	t.Run("normal route rejects unsafe source and keyfile objects", func(t *testing.T) {
		for _, test := range []struct {
			name             string
			symlinkSource    bool
			symlinkKeyfile   bool
			directoryKeyfile bool
		}{
			{name: "source symlink", symlinkSource: true},
			{name: "keyfile symlink", symlinkKeyfile: true},
			{name: "keyfile directory", directoryKeyfile: true},
		} {
			t.Run(test.name, func(t *testing.T) {
				dir := t.TempDir()
				realInput := writePCV3CLIFixture(t, dir, "real.pcv", fixture)
				input := realInput
				keyfile := writePCV3CLIFixture(t, dir, "real.key", []byte("key"))
				if test.symlinkSource {
					input = filepath.Join(dir, "source-link")
					if err := os.Symlink(realInput, input); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
				}
				if test.symlinkKeyfile {
					link := filepath.Join(dir, "key-link")
					if err := os.Symlink(keyfile, link); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
					keyfile = link
				}
				if test.directoryKeyfile {
					keyfile = filepath.Join(dir, "key-directory")
					if err := os.Mkdir(keyfile, 0o700); err != nil {
						t.Fatalf("create keyfile directory: %v", err)
					}
				}
				result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
					Args: []string{
						"decrypt", input, "-o", filepath.Join(dir, "output"),
						"--pcv3-factors=keyfiles", "--pcv3-keyfile-order=ordered", "-p", "", "-k", keyfile,
					},
					Observation: filepath.Join(dir, "observation.json"),
				}, nil)
				if result.exitCode != ExitGeneralError || observation.Called {
					t.Fatalf("unsafe object = exit %d called %v stderr %q", result.exitCode, observation.Called, result.stderr)
				}
			})
		}
	})

	t.Run("explicit D1 rejects a non-regular source before operation and credential input", func(t *testing.T) {
		dir := t.TempDir()
		input := os.DevNull
		info, err := os.Stat(input)
		if err != nil || info.Mode().IsRegular() {
			t.Skipf("platform has no openable non-regular null device: %v", err)
		}
		result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
			Args: []string{
				"decrypt", input, "-o", filepath.Join(dir, "output"),
				"--pcv3-format=d1", "--pcv3-factors=password", "-p", "must-not-transfer",
			},
			Observation: filepath.Join(dir, "observation.json"),
		}, nil)
		if result.exitCode != ExitGeneralError || observation.Called {
			t.Fatalf(
				"non-regular D1 source = exit %d called %v stderr %q",
				result.exitCode, observation.Called, result.stderr,
			)
		}
		if !strings.Contains(result.stderr, "input source is not a regular file") {
			t.Fatalf("non-regular D1 diagnostic = %q", result.stderr)
		}
	})

	t.Run("partial and mismatched prefixes remain legacy eligible", func(t *testing.T) {
		for _, data := range [][]byte{{'P', 'C', 'V'}, {'P', 'C', 'X', 0}} {
			dir := t.TempDir()
			input := writePCV3CLIFixture(t, dir, "legacy.pcv", data)
			output := filepath.Join(dir, "output")
			result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
				Args:        []string{"decrypt", input, "-o", output, "-p", "unused", "-q", "-y"},
				Observation: filepath.Join(dir, "observation.json"),
			}, nil)
			if result.exitCode == 0 || observation.Called {
				t.Fatalf("legacy prefix = exit %d called %v stderr %q", result.exitCode, observation.Called, result.stderr)
			}
		}
	})
}
