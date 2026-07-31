package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

const (
	gateSchemaVersion       = 1
	executionIdentityMode   = 0o444
	evidenceMode            = 0o400
	maxCommandOutputBytes   = 4 << 20
	maxGoTestFailureIDs     = 32
	maxGoTestFailureIDBytes = 256
	processWaitDelay        = 2 * time.Second
	reviewedGateConfigSHA   = "e9186d3ff2546a62c2badd8117b0fffda3ab91cbc1005ad818bd940e1eff6809"
	picocryptModulePath     = "Picocrypt-NG"
	pcv3PackagePath         = "Picocrypt-NG/internal/pcv3credential"
)

var (
	errOutputLimit             = errors.New("child output exceeded the configured limit")
	phase2Baseline             string
	phase2Base                 string
	phase2SourceManifestSHA256 string
)

type gateConfig struct {
	SchemaVersion          int                      `json:"schema_version"`
	GoVersion              string                   `json:"go_version"`
	Module                 string                   `json:"module"`
	BuildAttestation       buildAttestationContract `json:"build_attestation"`
	RuntimeBindings        runtimeBindings          `json:"runtime_bindings"`
	DependencyContract     vendorDependencyContract `json:"dependency_contract"`
	CPUContract            cpuContract              `json:"cpu_contract"`
	ChildEnvironment       childEnvironment         `json:"child_environment"`
	RequiredThreatIDs      []string                 `json:"required_threat_ids"`
	ThreatClosure          []threatClosure          `json:"threat_closure"`
	RequiredMutationIDs    []string                 `json:"required_mutation_ids"`
	RequiredExecutionUnits []string                 `json:"required_execution_units"`
	SkipAllowlist          []skipRule               `json:"skip_allowlist"`
	SkipRuntimeCardinality skipCardinality          `json:"skip_runtime_cardinality"`
	LintRuns               []lintRun                `json:"lint_runs"`
	Stages                 map[string]stageConfig   `json:"stages"`
	EvidenceContract       evidenceContract         `json:"evidence_contract"`
}

type runtimeBindings struct {
	Baseline             string            `json:"baseline"`
	Base                 string            `json:"base"`
	SourceTree           string            `json:"source_tree"`
	SourceManifestSHA256 string            `json:"source_manifest_sha256"`
	DiffSHA256           string            `json:"diff_sha256"`
	ConfigSHA256         string            `json:"config_sha256"`
	SpecSHA256           string            `json:"spec_sha256"`
	VectorsSHA256        string            `json:"vectors_sha256"`
	VectorInputSHA256    string            `json:"vector_input_sha256"`
	MutationsSHA256      string            `json:"mutations_sha256"`
	Runner               executableBinding `json:"runner"`
	Inspector            executableBinding `json:"inspector"`
}

type buildAttestationContract struct {
	Classification             string `json:"classification"`
	BaselineLDFlag             string `json:"baseline_ldflag"`
	BaseLDFlag                 string `json:"base_ldflag"`
	SourceManifestSHA256LDFlag string `json:"source_manifest_sha256_ldflag"`
}

type executableBinding struct {
	AbsolutePath   string `json:"absolute_path"`
	SHA256         string `json:"sha256"`
	GoBuildVersion string `json:"go_build_version"`
}

type vendorDependencyContract struct {
	Mode                   string `json:"mode"`
	VendorModulesPath      string `json:"vendor_modules_path"`
	SourceManifestCoverage string `json:"source_manifest_coverage"`
	GOFlags                string `json:"goflags"`
	ModuleCacheFallback    string `json:"module_cache_fallback"`
	StageBuildCache        string `json:"stage_build_cache"`
}

type cpuContract struct {
	OnlineSource                      string `json:"online_source"`
	MinimumOnline                     int    `json:"minimum_online"`
	ExactProfileMinimumOnline         int    `json:"exact_profile_minimum_online"`
	PhaseJobsFormula                  string `json:"phase_jobs_formula"`
	GOMAXPROCS                        string `json:"gomaxprocs"`
	MaximumConcurrency                string `json:"maximum_concurrency"`
	MemoryHardPackageParallelism      int    `json:"memory_hard_package_parallelism"`
	RequireForAllGoAndGoBasedChildren bool   `json:"require_for_all_go_and_go_based_children"`
}

type childEnvironment struct {
	Allowlist           []string          `json:"allowlist"`
	Required            map[string]string `json:"required"`
	RejectNameFragments []string          `json:"reject_name_fragments"`
}

type skipRule struct {
	Test                       string `json:"test"`
	Reason                     string `json:"reason"`
	Match                      string `json:"match"`
	SourcePath                 string `json:"source_path"`
	RequiredGoTestDeclarations int    `json:"required_go_test_declarations"`
}

type skipCardinality struct {
	Minimum int `json:"minimum"`
	Maximum int `json:"maximum"`
}

type threatClosure struct {
	ID                  string   `json:"id"`
	Stage               string   `json:"stage"`
	CommandID           string   `json:"command_id"`
	RequiredObservedIDs []string `json:"required_observed_ids"`
}

type lintRun struct {
	ID               string   `json:"id"`
	Tags             []string `json:"tags"`
	Argv             []string `json:"argv"`
	JSONPath         string   `json:"json_path"`
	JSONRequired     bool     `json:"json_required"`
	IssuesRequired   int      `json:"issues_required"`
	ExitCodeRequired int      `json:"exit_code_required"`
	TextOutput       string   `json:"text_output"`
}

type stageConfig struct {
	MinimumOnline       int             `json:"minimum_online"`
	OwnedExecutionUnits []string        `json:"owned_execution_units"`
	Commands            []commandConfig `json:"commands"`
}

type commandConfig struct {
	ID                    string                  `json:"id"`
	Kind                  string                  `json:"kind"`
	ExecutionSurface      executionSurface        `json:"execution_surface"`
	Argv                  []string                `json:"argv,omitempty"`
	CWD                   string                  `json:"cwd,omitempty"`
	TimeoutSeconds        int                     `json:"timeout_seconds,omitempty"`
	GoBased               bool                    `json:"go_based,omitempty"`
	MemoryHard            bool                    `json:"memory_hard,omitempty"`
	PackageParallelism    any                     `json:"package_parallelism,omitempty"`
	RequiredIDsSource     string                  `json:"required_ids_source,omitempty"`
	RequiredExitCode      int                     `json:"required_exit_code,omitempty"`
	RequiredTestIDs       []string                `json:"required_test_ids,omitempty"`
	RequiredTestPackages  map[string]string       `json:"required_test_packages,omitempty"`
	LintRun               string                  `json:"lint_run,omitempty"`
	RequiredCount         int                     `json:"required_count,omitempty"`
	RequiredOutputMarker  string                  `json:"required_output_marker,omitempty"`
	ForbiddenOutputMarker string                  `json:"forbidden_output_marker,omitempty"`
	ExpectedGoTestEvent   *goTestEventAttestation `json:"-"`
}

type executionSurface struct {
	PackagePaths []string `json:"package_paths"`
	BuildTags    []string `json:"build_tags"`
	TestSelector string   `json:"test_selector"`
	EvidenceKind string   `json:"evidence_kind"`
}

type evidenceContract struct {
	SchemaVersion          int               `json:"schema_version"`
	TerminalStatuses       []string          `json:"terminal_statuses"`
	RequiredStageNames     []string          `json:"required_stage_names"`
	StageFilenames         map[string]string `json:"stage_filenames"`
	CreateExclusive        bool              `json:"create_exclusive"`
	ReplaceForbidden       bool              `json:"replace_forbidden"`
	PublicationProofSuffix string            `json:"publication_proof_suffix"`
	RequiredFields         []string          `json:"required_fields"`
}

type evidencePublicationProof struct {
	SchemaVersion  int    `json:"schema_version"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type fileIdentity struct {
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	Mode            uint32 `json:"mode"`
	Size            int64  `json:"size"`
	ModTimeUnixNano int64  `json:"mod_time_unix_nano"`
}

type executableIdentity struct {
	File            fileIdentity `json:"file"`
	GoBuildVersion  string       `json:"go_build_version"`
	ModulePath      string       `json:"module_path"`
	MainPackagePath string       `json:"main_package_path"`
	BuildInfoSHA256 string       `json:"go_build_info_sha256"`
}

type buildAttestation struct {
	Baseline             string `json:"baseline"`
	Base                 string `json:"base"`
	SourceManifestSHA256 string `json:"source_manifest_sha256"`
}

type directoryIdentity struct {
	Path            string `json:"path"`
	Mode            uint32 `json:"mode"`
	ModTimeUnixNano int64  `json:"mod_time_unix_nano"`
}

type treeIdentity struct {
	SHA256     string `json:"sha256"`
	EntryCount int    `json:"entry_count"`
}

type treeEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type sourceManifest struct {
	SchemaVersion int          `json:"schema_version"`
	Baseline      string       `json:"baseline"`
	Base          string       `json:"base"`
	DiffSHA256    string       `json:"diff_sha256"`
	SourceTree    treeIdentity `json:"source_tree"`
	Entries       []treeEntry  `json:"entries"`
}

type executionIdentity struct {
	SchemaVersion  int                           `json:"schema_version"`
	Baseline       string                        `json:"baseline"`
	Base           string                        `json:"base"`
	Source         directoryIdentity             `json:"source"`
	SourceTree     treeIdentity                  `json:"source_tree"`
	EvidenceRoot   directoryIdentity             `json:"evidence_root"`
	SourceManifest fileIdentity                  `json:"source_manifest"`
	Diff           fileIdentity                  `json:"diff"`
	Config         fileIdentity                  `json:"config"`
	Spec           fileIdentity                  `json:"spec"`
	Vectors        fileIdentity                  `json:"vectors"`
	VectorInput    fileIdentity                  `json:"vector_input"`
	Mutations      fileIdentity                  `json:"mutations"`
	Runner         executableIdentity            `json:"runner"`
	Inspector      executableIdentity            `json:"inspector"`
	Executables    map[string]executableIdentity `json:"executables"`
	GoVersion      string                        `json:"go_version"`
	Module         string                        `json:"module"`
	GOOS           string                        `json:"goos"`
	GOARCH         string                        `json:"goarch"`
	CPUModel       string                        `json:"cpu_model"`
	CPUModelSource string                        `json:"cpu_model_source"`
	OnlineSource   string                        `json:"online_source"`
	Online         int                           `json:"online"`
	PhaseJobs      int                           `json:"phase_jobs"`
	WorkingDirs    []string                      `json:"working_directories"`
	Environment    map[string][]string           `json:"stage_child_environments"`
}

type freezeOptions struct {
	Config         string
	Baseline       string
	Base           string
	SourceManifest string
	Diff           string
	Spec           string
	Vectors        string
	VectorInput    string
	Mutations      string
	Runner         string
	Inspector      string
	Output         string
}

type stageOptions struct {
	Stage                   string
	Config                  string
	Baseline                string
	Base                    string
	Source                  string
	SourceManifest          string
	Diff                    string
	ExecutionIdentity       string
	ExecutionIdentitySHA256 string
	Evidence                string
}

type hostFacts struct {
	GOOS           string
	GOARCH         string
	CPUModel       string
	CPUModelSource string
	OnlineSource   string
	Online         int
}

type runtimeDeps struct {
	hostFacts           func() (hostFacts, error)
	lookPath            func(string) (string, error)
	executable          func() (string, error)
	executableID        func(string) (executableIdentity, error)
	compiledAttestation func() buildAttestation
	validateConfig      func(*gateConfig) error
	gateConfigSHA       string
	now                 func() time.Time
	beforePostCheck     func()
	beforePublish       func(string, string)
	removeStageTemp     func(*os.Root, string) error
	syncDirectory       func(*os.File) error
	commandContext      func(context.Context, string, ...string) *exec.Cmd
}

func defaultDeps() runtimeDeps {
	return runtimeDeps{
		hostFacts:    currentHostFacts,
		lookPath:     exec.LookPath,
		executable:   os.Executable,
		executableID: executableFileIdentity,
		compiledAttestation: func() buildAttestation {
			return buildAttestation{
				Baseline:             phase2Baseline,
				Base:                 phase2Base,
				SourceManifestSHA256: phase2SourceManifestSHA256,
			}
		},
		validateConfig:  validateGateConfig,
		gateConfigSHA:   reviewedGateConfigSHA,
		now:             time.Now,
		removeStageTemp: (*os.Root).RemoveAll,
		syncDirectory:   (*os.File).Sync,
		commandContext:  exec.CommandContext,
	}
}

type stageEvidence struct {
	SchemaVersion           int             `json:"schema_version"`
	Stage                   string          `json:"stage"`
	Status                  string          `json:"status"`
	Baseline                string          `json:"baseline"`
	Base                    string          `json:"base"`
	ExecutionIdentitySHA256 string          `json:"execution_identity_sha256"`
	ConfigSHA256            string          `json:"config_sha256"`
	StartedAt               string          `json:"started_at"`
	FinishedAt              string          `json:"finished_at"`
	Commands                []commandResult `json:"commands"`
	RequiredIDs             []string        `json:"required_ids"`
	ObservedIDs             []string        `json:"observed_ids"`
	SkipEvents              []skipEvent     `json:"skip_events"`
	ClosedThreatIDs         []string        `json:"closed_threat_ids"`
	Failure                 string          `json:"failure,omitempty"`
}

type commandResult struct {
	ID              string                  `json:"id"`
	Argv            []string                `json:"argv,omitempty"`
	CWD             string                  `json:"cwd,omitempty"`
	Contract        commandEvidence         `json:"contract"`
	ExitCode        int                     `json:"exit_code"`
	StdoutSHA256    string                  `json:"stdout_sha256,omitempty"`
	StderrSHA256    string                  `json:"stderr_sha256,omitempty"`
	ObservedIDs     []string                `json:"observed_ids,omitempty"`
	SkipEvents      []skipEvent             `json:"skip_events,omitempty"`
	GoTestEvent     *goTestEventAttestation `json:"go_test_event,omitempty"`
	GoTestFailure   *goTestFailureSummary   `json:"go_test_failure_summary,omitempty"`
	TimedOut        bool                    `json:"timed_out"`
	TerminationErr  string                  `json:"termination_error,omitempty"`
	WaitErr         string                  `json:"wait_error,omitempty"`
	Mutations       []mutationExecution     `json:"mutations,omitempty"`
	ClosedThreatIDs []string                `json:"closed_threat_ids,omitempty"`
	LintResult      *lintEvidenceResult     `json:"lint_result,omitempty"`
	ScanResult      *scanEvidenceResult     `json:"scan_result,omitempty"`
}

type goTestEventAttestation struct {
	Package        string `json:"package"`
	TestID         string `json:"test_id"`
	TerminalAction string `json:"terminal_action"`
}

type goTestFailureSummary struct {
	TopLevelTestIDs []string `json:"top_level_test_ids"`
	Classification  string   `json:"classification"`
	Truncated       bool     `json:"truncated"`
}

type commandEvidence struct {
	Kind                 string            `json:"kind"`
	ExecutionSurface     executionSurface  `json:"execution_surface"`
	TimeoutSeconds       int               `json:"timeout_seconds"`
	GoBased              bool              `json:"go_based"`
	MemoryHard           bool              `json:"memory_hard"`
	PackageParallelism   int               `json:"package_parallelism"`
	RequiredExitCode     int               `json:"required_exit_code"`
	RequiredTestIDs      []string          `json:"required_test_ids"`
	RequiredTestPackages map[string]string `json:"required_test_packages"`
}

type lintEvidenceResult struct {
	RunID          string     `json:"run_id"`
	JSONSHA256     string     `json:"json_sha256"`
	Issues         []struct{} `json:"issues"`
	EnabledLinters []string   `json:"enabled_linters"`
}

type scanEvidenceResult struct {
	Scanner  string `json:"scanner"`
	Target   string `json:"target"`
	Findings int    `json:"findings"`
}

type mutationExecution struct {
	ID                 string                    `json:"id"`
	KillingTestID      string                    `json:"killing_test_id"`
	ViolationMarker    string                    `json:"violation_marker"`
	Pristine           commandResult             `json:"pristine"`
	Application        commandResult             `json:"application"`
	ApplicationReceipt campaignApplicationRecord `json:"application_receipt"`
	Mutant             commandResult             `json:"mutant"`
}

type campaignManifest struct {
	SchemaVersion   int                `json:"schema_version"`
	SpecSHA256      string             `json:"spec_sha256"`
	SourceSetSHA256 string             `json:"source_set_sha256"`
	ArgvTemplate    []string           `json:"argv_template"`
	Mutations       []campaignMutation `json:"mutations"`
}

var campaignArgvTemplate = []string{
	"phase2-mutator",
	"--source-copy", "${SOURCE_COPY}",
	"--manifest", "${MUTATION_MANIFEST}",
	"--mutation-id", "${MUTATION_ID}",
	"--source-set-sha256", "${SOURCE_SET_SHA256}",
	"--baseline", "${BASELINE}",
	"--spec-sha256", "${SPEC_SHA256}",
	"--result", "${RESULT}",
}

type campaignMutation struct {
	ID              string          `json:"id"`
	Requirement     string          `json:"requirement"`
	Invariant       string          `json:"invariant"`
	SourcePath      string          `json:"source_path"`
	SourceSHA256    string          `json:"source_sha256"`
	Anchor          string          `json:"anchor"`
	Replacement     string          `json:"replacement"`
	KillingTestID   string          `json:"killing_test_id"`
	ViolationMarker string          `json:"expected_violation_marker"`
	Pristine        campaignOutcome `json:"pristine"`
	Mutant          campaignOutcome `json:"mutant"`
}

type campaignOutcome struct {
	Status          string   `json:"status"`
	Execution       string   `json:"execution"`
	SemanticCommand []string `json:"semantic_command"`
	TestID          string   `json:"test_id"`
	ViolationMarker string   `json:"violation_marker"`
	Stage           string   `json:"stage"`
	Reason          string   `json:"reason"`
	Skipped         bool     `json:"skipped"`
	CompileOnly     bool     `json:"compile_only"`
}

type campaignApplicationRecord struct {
	SchemaVersion      int             `json:"schema_version"`
	MutationID         string          `json:"mutation_id"`
	BaselineCommit     string          `json:"baseline_commit"`
	SpecSHA256         string          `json:"spec_sha256"`
	SourceSetSHA256    string          `json:"source_set_sha256"`
	SourcePath         string          `json:"source_path"`
	SourceBeforeSHA256 string          `json:"source_before_sha256"`
	SourceAfterSHA256  string          `json:"source_after_sha256"`
	AnchorMatches      int             `json:"anchor_matches"`
	ApplicationCount   int             `json:"application_count"`
	KillingTestID      string          `json:"killing_test_id"`
	ViolationMarker    string          `json:"expected_violation_marker"`
	ExpectedPristine   campaignOutcome `json:"expected_pristine"`
	ExpectedMutant     campaignOutcome `json:"expected_mutant"`
}

type cpuFacts struct {
	Online       int    `json:"online"`
	PhaseJobs    int    `json:"phase_jobs"`
	OnlineSource string `json:"online_source"`
}

type skipEvent struct {
	Test   string `json:"test"`
	Reason string `json:"reason"`
}

type processTree interface {
	Start() error
	Terminate() error
	Wait() error
	Active() (bool, error)
	Close() error
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		_, err := io.WriteString(
			stdout,
			"phasegates cpu-facts\nphasegates freeze-identity\nphasegates stage\n",
		)
		return err
	}
	if len(args) == 2 && args[1] == "--help" {
		switch args[0] {
		case "cpu-facts":
			_, err := io.WriteString(stdout, "cpu-facts\n")
			return err
		case "freeze-identity":
			_, err := io.WriteString(
				stdout,
				"freeze-identity --config --baseline --base --source-manifest --diff --spec --vectors --vector-input --mutations --runner --inspector --output\n",
			)
			return err
		case "stage":
			_, err := io.WriteString(
				stdout,
				"stage --stage --config --baseline --base --source --source-manifest --diff --execution-identity --execution-identity-sha256 --evidence\n",
			)
			return err
		default:
			return errors.New("unknown phasegates command")
		}
	}
	if len(args) == 0 {
		return errors.New("phasegates requires cpu-facts, freeze-identity, or stage")
	}

	deps := defaultDeps()
	switch args[0] {
	case "cpu-facts":
		if len(args) != 1 {
			return errors.New("cpu-facts accepts no arguments")
		}
		facts, err := cpuFactsForOnline(runtime.NumCPU())
		if err != nil {
			return err
		}
		data, err := canonicalJSON(facts)
		if err != nil {
			return fmt.Errorf("encode CPU facts: %w", err)
		}
		_, err = stdout.Write(data)
		return err
	case "freeze-identity":
		options, err := parseFreezeOptions(args[1:])
		if err != nil {
			return err
		}
		hash, err := freezeIdentity(options, deps)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, hash)
		return err
	case "stage":
		options, err := parseStageOptions(args[1:])
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(
			context.Background(),
			os.Interrupt,
			syscall.SIGTERM,
		)
		defer stop()
		return runStage(ctx, options, deps)
	default:
		return errors.New("unknown phasegates command")
	}
}

func parseFreezeOptions(args []string) (freezeOptions, error) {
	names := []string{
		"--config", "--baseline", "--base", "--source-manifest", "--diff",
		"--spec", "--vectors", "--vector-input", "--mutations", "--runner",
		"--inspector", "--output",
	}
	values, err := parseExactPairs(args, names)
	if err != nil {
		return freezeOptions{}, err
	}
	return freezeOptions{
		Config:         values["--config"],
		Baseline:       values["--baseline"],
		Base:           values["--base"],
		SourceManifest: values["--source-manifest"],
		Diff:           values["--diff"],
		Spec:           values["--spec"],
		Vectors:        values["--vectors"],
		VectorInput:    values["--vector-input"],
		Mutations:      values["--mutations"],
		Runner:         values["--runner"],
		Inspector:      values["--inspector"],
		Output:         values["--output"],
	}, nil
}

func parseStageOptions(args []string) (stageOptions, error) {
	names := []string{
		"--stage", "--config", "--baseline", "--base", "--source",
		"--source-manifest", "--diff", "--execution-identity",
		"--execution-identity-sha256", "--evidence",
	}
	values, err := parseExactPairs(args, names)
	if err != nil {
		return stageOptions{}, err
	}
	return stageOptions{
		Stage:                   values["--stage"],
		Config:                  values["--config"],
		Baseline:                values["--baseline"],
		Base:                    values["--base"],
		Source:                  values["--source"],
		SourceManifest:          values["--source-manifest"],
		Diff:                    values["--diff"],
		ExecutionIdentity:       values["--execution-identity"],
		ExecutionIdentitySHA256: values["--execution-identity-sha256"],
		Evidence:                values["--evidence"],
	}, nil
}

func parseExactPairs(args, names []string) (map[string]string, error) {
	if len(args) != len(names)*2 {
		return nil, errors.New("phasegates command has missing or extra arguments")
	}
	values := make(map[string]string, len(names))
	for index, name := range names {
		if args[index*2] != name || args[index*2+1] == "" {
			return nil, fmt.Errorf("phasegates requires exact argument %s", name)
		}
		values[name] = args[index*2+1]
	}
	return values, nil
}

func freezeIdentity(options freezeOptions, deps runtimeDeps) (string, error) {
	if err := processTreeSupported(); err != nil {
		return "", err
	}
	if !validOID(options.Baseline) || !validOID(options.Base) {
		return "", errors.New("baseline and base must be full hexadecimal object IDs")
	}
	config, configIdentity, err := loadGateConfig(options.Config, deps.gateConfigSHA)
	if err != nil {
		return "", err
	}
	if err := validateRuntimeGateConfig(deps, config); err != nil {
		return "", err
	}
	facts, err := deps.hostFacts()
	if err != nil {
		return "", fmt.Errorf("read host facts: %w", err)
	}
	if facts.Online < config.CPUContract.MinimumOnline {
		return "", errors.New("online CPU count is below the gate minimum")
	}
	phaseJobs := derivedPhaseJobs(facts.Online)
	if phaseJobs < 1 {
		return "", errors.New("derived phase jobs must be positive")
	}
	if os.Getenv("GOMAXPROCS") != strconv.Itoa(phaseJobs) {
		return "", errors.New("GOMAXPROCS does not equal the frozen half-core value")
	}

	source, err := commonSourceDirectory(
		options.Config,
		options.SourceManifest,
		options.Diff,
		options.Spec,
		options.Vectors,
		options.VectorInput,
		options.Mutations,
	)
	if err != nil {
		return "", err
	}
	identity := executionIdentity{
		SchemaVersion:  gateSchemaVersion,
		Baseline:       strings.ToLower(options.Baseline),
		Base:           strings.ToLower(options.Base),
		Source:         source,
		Config:         configIdentity,
		GoVersion:      config.GoVersion,
		Module:         config.Module,
		GOOS:           facts.GOOS,
		GOARCH:         facts.GOARCH,
		CPUModel:       facts.CPUModel,
		CPUModelSource: facts.CPUModelSource,
		OnlineSource:   facts.OnlineSource,
		Online:         facts.Online,
		PhaseJobs:      phaseJobs,
		Executables:    map[string]executableIdentity{},
		Environment:    map[string][]string{},
	}
	if identity.SourceManifest, err = regularFileIdentity(
		options.SourceManifest,
	); err != nil {
		return "", err
	}
	expectedAttestation := buildAttestation{
		Baseline:             identity.Baseline,
		Base:                 identity.Base,
		SourceManifestSHA256: identity.SourceManifest.SHA256,
	}
	// Go deliberately omits -ldflags from BuildInfo when -trimpath is set.
	// The running binary therefore checks its linker-injected values directly;
	// exact executable bytes and the remaining BuildInfo stay independently bound.
	if deps.compiledAttestation() != expectedAttestation {
		return "", errors.New("running phasegates build attestation mismatch")
	}
	if identity.EvidenceRoot, err = directoryIdentityFor(
		filepath.Dir(options.Output),
	); err != nil {
		return "", fmt.Errorf("bind evidence root: %w", err)
	}
	if os.FileMode(identity.EvidenceRoot.Mode).Perm() != 0o700 {
		return "", errors.New("evidence root must have mode 0700")
	}
	// Evidence publication itself changes the parent directory timestamp.
	// Path and mode remain frozen; individual identity/evidence files carry
	// their own complete content and metadata identities.
	identity.EvidenceRoot.ModTimeUnixNano = 0
	var sourceEntries []treeEntry
	identity.SourceTree, sourceEntries, err = stableDirectoryTreeSnapshot(identity.Source.Path)
	if err != nil {
		return "", fmt.Errorf("bind complete source tree: %w", err)
	}
	if err := validateVendoredSource(identity.Source.Path, sourceEntries); err != nil {
		return "", err
	}
	if identity.Diff, err = regularFileIdentity(options.Diff); err != nil {
		return "", err
	}
	if err := validateSourceManifest(
		options.SourceManifest,
		identity.Baseline,
		identity.Base,
		identity.Diff.SHA256,
		identity.SourceTree,
		sourceEntries,
	); err != nil {
		return "", err
	}
	if identity.Spec, err = regularFileIdentity(options.Spec); err != nil {
		return "", err
	}
	if identity.Vectors, err = regularFileIdentity(options.Vectors); err != nil {
		return "", err
	}
	if identity.VectorInput, err = regularFileIdentity(options.VectorInput); err != nil {
		return "", err
	}
	if identity.Mutations, err = regularFileIdentity(options.Mutations); err != nil {
		return "", err
	}
	if identity.Runner, err = deps.executableID(options.Runner); err != nil {
		return "", fmt.Errorf("bind runner: %w", err)
	}
	if identity.Inspector, err = deps.executableID(options.Inspector); err != nil {
		return "", fmt.Errorf("bind inspector: %w", err)
	}
	if identity.Runner.File.Path == identity.Inspector.File.Path {
		return "", errors.New("runner and inspector must be distinct executable paths")
	}
	if identity.Runner.File.SHA256 == identity.Inspector.File.SHA256 {
		return "", errors.New("runner and inspector must be distinct executable binaries")
	}
	if !strings.HasSuffix(identity.Runner.MainPackagePath, "/phasegates") ||
		!strings.HasSuffix(identity.Inspector.MainPackagePath, "/phaseinspect") ||
		identity.Runner.MainPackagePath == identity.Inspector.MainPackagePath {
		return "", errors.New("runner and inspector main package identities are invalid")
	}
	selfPath, err := deps.executable()
	if err != nil {
		return "", fmt.Errorf("resolve running phasegates executable: %w", err)
	}
	selfIdentity, err := deps.executableID(selfPath)
	if err != nil || !sameExecutableIdentity(identity.Runner, selfIdentity) {
		return "", errors.New("running phasegates executable does not match --runner")
	}
	if identity.Runner.GoBuildVersion != config.GoVersion ||
		identity.Inspector.GoBuildVersion != config.GoVersion {
		return "", errors.New("runner or inspector Go build version mismatch")
	}
	if !executableBelongsToModule(identity.Runner, config.Module) ||
		!executableBelongsToModule(identity.Inspector, config.Module) {
		return "", errors.New("runner or inspector module mismatch")
	}

	identity.WorkingDirs, err = frozenWorkingDirectories(config, source.Path)
	if err != nil {
		return "", err
	}
	identity.Executables, err = frozenExecutables(
		config,
		identity.Runner,
		deps.lookPath,
	)
	if err != nil {
		return "", err
	}
	var finalizePrivateRoots func(bool) error
	if len(config.ThreatClosure) != 0 {
		finalizePrivateRoots, err = preparePrivateEnvironmentRoots(
			identity.EvidenceRoot.Path,
			config,
		)
		if err != nil {
			return "", err
		}
		defer func() {
			if finalizePrivateRoots != nil {
				_ = finalizePrivateRoots(false)
			}
		}()
	}
	goExecutable := identity.Executables["${GO}"]
	for stageName := range config.Stages {
		identity.Environment[stageName], err = frozenEnvironment(
			config,
			phaseJobs,
			stageName,
			stageTempDirectory(identity.EvidenceRoot.Path, stageName),
			filepath.Dir(goExecutable.File.Path),
		)
		if err != nil {
			return "", err
		}
	}
	if len(config.ThreatClosure) != 0 {
		if err := validateDistinctStageCaches(identity.Environment); err != nil {
			return "", err
		}
	}

	hash, err := writeExclusiveCanonical(
		options.Output,
		identity,
		deps.syncDirectory,
	)
	if err != nil {
		return "", err
	}
	if finalizePrivateRoots != nil {
		// The identity and its workspace directories are committed at this point.
		// A directory-handle close error cannot safely turn that success into retry.
		_ = finalizePrivateRoots(true)
		finalizePrivateRoots = nil
	}
	return hash, nil
}

func runStage(
	ctx context.Context,
	options stageOptions,
	deps runtimeDeps,
) (returnErr error) {
	if err := processTreeSupported(); err != nil {
		return err
	}
	identity, config, err := validateStageInputs(options, deps)
	if err != nil {
		return err
	}
	stage, ok := config.Stages[options.Stage]
	if !ok {
		return errors.New("unknown stage")
	}
	if identity.Online < stage.MinimumOnline {
		return errors.New("stage online CPU minimum is not satisfied")
	}
	if len(config.ThreatClosure) != 0 {
		if err := validateStagePrivateWorkspace(identity, options.Stage, true); err != nil {
			return err
		}
	}
	evidenceRoot, err := openEvidenceRootHandle(identity.EvidenceRoot.Path)
	if err != nil {
		return fmt.Errorf("open authenticated evidence root: %w", err)
	}
	published := false
	defer func() {
		closeErr := evidenceRoot.Close()
		if !published {
			returnErr = errors.Join(returnErr, closeErr)
		}
	}()
	if err := sameOpenDirectory(evidenceRoot, identity.EvidenceRoot.Path); err != nil {
		return err
	}
	releaseLease, err := acquireStageLease(evidenceRoot)
	if err != nil {
		return err
	}
	defer func() {
		if releaseLease != nil {
			returnErr = errors.Join(returnErr, releaseLease())
		}
	}()

	evidenceName := filepath.Base(options.Evidence)
	if err := requirePublicationProofAbsentAt(
		evidenceRoot,
		evidenceName,
		config.EvidenceContract.PublicationProofSuffix,
	); err != nil {
		return err
	}
	evidenceFile, err := createEvidenceFileAt(evidenceRoot, evidenceName)
	if err != nil {
		return err
	}
	if err := sameOpenRegularFileAt(evidenceFile, evidenceRoot, evidenceName); err != nil {
		_ = evidenceFile.Close()
		return err
	}
	started := deps.now().UTC()
	evidence := stageEvidence{
		SchemaVersion:           gateSchemaVersion,
		Stage:                   options.Stage,
		Status:                  "FAIL",
		Baseline:                options.Baseline,
		Base:                    options.Base,
		ExecutionIdentitySHA256: strings.ToLower(options.ExecutionIdentitySHA256),
		ConfigSHA256:            identity.Config.SHA256,
		StartedAt:               started.Format(time.RFC3339Nano),
		RequiredIDs:             requiredIDsForStage(options.Stage, config),
	}
	defer func() {
		if evidenceFile == nil {
			return
		}
		if returnErr != nil {
			evidence.Failure = safeFailure(returnErr)
		}
		evidence.FinishedAt = deps.now().UTC().Format(time.RFC3339Nano)
		_, finishErr := finishEvidence(
			evidenceFile,
			evidenceRoot,
			evidenceName,
			evidence,
			deps.syncDirectory,
		)
		returnErr = errors.Join(returnErr, finishErr)
	}()
	cleanupRoot, err := os.OpenRoot(identity.EvidenceRoot.Path)
	if err != nil {
		return fmt.Errorf("open rooted stage cleanup handle: %w", err)
	}
	evidenceRootInfo, evidenceRootInfoErr := evidenceRoot.Stat()
	cleanupRootInfo, cleanupRootInfoErr := cleanupRoot.Stat(".")
	if evidenceRootInfoErr != nil ||
		cleanupRootInfoErr != nil ||
		!evidenceRootInfo.IsDir() ||
		!cleanupRootInfo.IsDir() ||
		!os.SameFile(evidenceRootInfo, cleanupRootInfo) {
		closeErr := cleanupRoot.Close()
		return errors.Join(
			evidenceRootInfoErr,
			cleanupRootInfoErr,
			closeErr,
			errors.New("rooted stage cleanup handle identity mismatch"),
		)
	}
	defer func() {
		closeErr := cleanupRoot.Close()
		if !published {
			returnErr = errors.Join(returnErr, closeErr)
		}
	}()
	stageTemp := stageTempDirectory(identity.EvidenceRoot.Path, options.Stage)
	stageTempName := filepath.Base(stageTemp)
	if err := makeDirectoryAt(evidenceRoot, stageTempName, 0o700); err != nil {
		return fmt.Errorf("create exclusive stage temp directory: %w", err)
	}
	stageTempPending := true
	cleanupStageTemp := func() error {
		if !stageTempPending {
			return nil
		}
		if err := deps.removeStageTemp(cleanupRoot, stageTempName); err != nil {
			return fmt.Errorf("remove stage temp directory: %w", err)
		}
		if _, err := cleanupRoot.Lstat(stageTempName); err == nil {
			return errors.New("stage temp directory still exists after cleanup")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("verify stage temp directory removal: %w", err)
		}
		stageTempPending = false
		return nil
	}
	defer func() {
		returnErr = errors.Join(returnErr, cleanupStageTemp())
	}()

	replacements := stageReplacements(options, identity)
	for _, command := range stage.Commands {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		result, commandErr := runConfiguredCommand(
			ctx,
			command,
			config,
			identity,
			replacements,
			deps,
		)
		evidence.Commands = append(evidence.Commands, result)
		evidence.ObservedIDs = append(evidence.ObservedIDs, result.ObservedIDs...)
		evidence.SkipEvents = append(evidence.SkipEvents, result.SkipEvents...)
		if commandErr != nil {
			return commandErr
		}
		closedThreats, closureErr := closedThreatsForCommand(
			config,
			options.Stage,
			command.ID,
			result.ObservedIDs,
		)
		if closureErr != nil {
			return closureErr
		}
		evidence.Commands[len(evidence.Commands)-1].ClosedThreatIDs = closedThreats
		evidence.ClosedThreatIDs = append(evidence.ClosedThreatIDs, closedThreats...)
	}
	if err := sameOpenRegularFileAt(evidenceFile, evidenceRoot, evidenceName); err != nil {
		return err
	}
	if err := sameOpenDirectory(evidenceRoot, identity.EvidenceRoot.Path); err != nil {
		return err
	}
	if err := validateObservedStage(config, evidence); err != nil {
		return err
	}
	if deps.beforePostCheck != nil {
		deps.beforePostCheck()
	}
	if _, _, err := validateStageInputs(options, deps); err != nil {
		return fmt.Errorf("post-execution identity validation: %w", err)
	}
	if len(config.ThreatClosure) != 0 {
		if err := validateStagePrivateWorkspace(identity, options.Stage, false); err != nil {
			return err
		}
	}
	if err := cleanupStageTemp(); err != nil {
		return err
	}
	evidence.Status = "PASS"
	evidence.FinishedAt = deps.now().UTC().Format(time.RFC3339Nano)
	evidenceSHA256, finishErr := finishEvidence(
		evidenceFile,
		evidenceRoot,
		evidenceName,
		evidence,
		deps.syncDirectory,
	)
	evidenceFile = nil
	if finishErr != nil {
		return finishErr
	}
	if err := releaseLease(); err != nil {
		return err
	}
	releaseLease = nil
	if deps.beforePublish != nil {
		deps.beforePublish(identity.EvidenceRoot.Path, evidenceName)
	}
	if err := publishEvidenceProofAt(
		evidenceRoot,
		evidenceName,
		config.EvidenceContract.PublicationProofSuffix,
		evidenceSHA256,
		deps.syncDirectory,
	); err != nil {
		return err
	}
	published = true
	return nil
}

func requirePublicationProofAbsentAt(
	root *os.File,
	evidenceName string,
	suffix string,
) error {
	if suffix == "" || strings.ContainsAny(suffix, `/\\`) {
		return errors.New("invalid evidence publication proof suffix")
	}
	for _, name := range []string{
		evidenceName + suffix,
		"." + evidenceName + suffix + ".pending",
	} {
		file, err := openReadFileAt(root, name)
		if err == nil {
			_ = file.Close()
			return errors.New("evidence publication proof path already exists")
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect evidence publication proof path: %w", err)
		}
	}
	return nil
}

func acquireStageLease(evidenceRoot *os.File) (func() error, error) {
	const name = ".phasegates-execution-lease"
	if err := makeDirectoryAt(evidenceRoot, name, 0o700); err != nil {
		return nil, fmt.Errorf("acquire exclusive cross-stage execution lease: %w", err)
	}
	return func() error {
		info, err := os.Lstat(filepath.Join(evidenceRoot.Name(), name))
		if err != nil {
			return fmt.Errorf("validate cross-stage execution lease: %w", err)
		}
		if !info.IsDir() {
			return errors.New("cross-stage execution lease path was replaced")
		}
		if err := removeDirectoryAt(evidenceRoot, name); err != nil {
			return fmt.Errorf("release cross-stage execution lease: %w", err)
		}
		return nil
	}, nil
}

func validateStageInputs(
	options stageOptions,
	deps runtimeDeps,
) (executionIdentity, *gateConfig, error) {
	if !validOID(options.Baseline) || !validOID(options.Base) ||
		!validSHA256(options.ExecutionIdentitySHA256) {
		return executionIdentity{}, nil, errors.New("invalid stage identity arguments")
	}
	identityFile, err := regularFileIdentity(options.ExecutionIdentity)
	if err != nil {
		return executionIdentity{}, nil, err
	}
	if identityFile.Mode&0o777 != executionIdentityMode ||
		identityFile.SHA256 != strings.ToLower(options.ExecutionIdentitySHA256) {
		return executionIdentity{}, nil, errors.New("execution identity file mismatch")
	}
	var identity executionIdentity
	if err := decodeStrictFile(options.ExecutionIdentity, &identity); err != nil {
		return executionIdentity{}, nil, fmt.Errorf("decode execution identity: %w", err)
	}
	if identity.SchemaVersion != gateSchemaVersion ||
		identity.Baseline != strings.ToLower(options.Baseline) ||
		identity.Base != strings.ToLower(options.Base) {
		return executionIdentity{}, nil, errors.New("execution identity baseline mismatch")
	}
	expectedAttestation := buildAttestation{
		Baseline:             identity.Baseline,
		Base:                 identity.Base,
		SourceManifestSHA256: identity.SourceManifest.SHA256,
	}
	if deps.compiledAttestation() != expectedAttestation {
		return executionIdentity{}, nil, errors.New("running phasegates build attestation mismatch")
	}
	config, configIdentity, err := loadGateConfig(options.Config, deps.gateConfigSHA)
	if err != nil {
		return executionIdentity{}, nil, err
	}
	if err := validateRuntimeGateConfig(deps, config); err != nil {
		return executionIdentity{}, nil, err
	}
	evidenceName, ok := config.EvidenceContract.StageFilenames[options.Stage]
	if !ok || filepath.Base(options.Evidence) != evidenceName {
		return executionIdentity{}, nil, errors.New(
			"stage evidence basename does not match the reviewed contract",
		)
	}
	if !sameFileIdentity(identity.Config, configIdentity) {
		return executionIdentity{}, nil, errors.New("gate config identity mismatch")
	}
	source, err := directoryIdentityFor(options.Source)
	if err != nil {
		return executionIdentity{}, nil, err
	}
	if source != identity.Source {
		return executionIdentity{}, nil, errors.New("source directory identity mismatch")
	}
	sourceTree, err := stableDirectoryTreeIdentity(source.Path)
	if err != nil || sourceTree != identity.SourceTree {
		return executionIdentity{}, nil, errors.New("complete source-tree identity mismatch")
	}
	sourceManifest, err := regularFileIdentity(options.SourceManifest)
	if err != nil || !sameFileIdentity(identity.SourceManifest, sourceManifest) {
		return executionIdentity{}, nil, errors.New("source manifest identity mismatch")
	}
	diff, err := regularFileIdentity(options.Diff)
	if err != nil || !sameFileIdentity(identity.Diff, diff) {
		return executionIdentity{}, nil, errors.New("diff identity mismatch")
	}
	for _, pair := range [][2]fileIdentity{
		{identity.Spec, mustFileIdentity(identity.Spec.Path)},
		{identity.Vectors, mustFileIdentity(identity.Vectors.Path)},
		{identity.VectorInput, mustFileIdentity(identity.VectorInput.Path)},
		{identity.Mutations, mustFileIdentity(identity.Mutations.Path)},
	} {
		if !sameFileIdentity(pair[0], pair[1]) {
			return executionIdentity{}, nil, errors.New("frozen file identity mismatch")
		}
	}
	runner, err := deps.executableID(identity.Runner.File.Path)
	if err != nil || !sameExecutableIdentity(identity.Runner, runner) {
		return executionIdentity{}, nil, errors.New("runner executable identity mismatch")
	}
	selfPath, err := deps.executable()
	if err != nil {
		return executionIdentity{}, nil, errors.New("resolve running phasegates executable")
	}
	selfIdentity, err := deps.executableID(selfPath)
	if err != nil || !sameExecutableIdentity(identity.Runner, selfIdentity) {
		return executionIdentity{}, nil, errors.New("running phasegates executable identity mismatch")
	}
	inspector, err := deps.executableID(identity.Inspector.File.Path)
	if err != nil || !sameExecutableIdentity(identity.Inspector, inspector) {
		return executionIdentity{}, nil, errors.New("inspector executable identity mismatch")
	}
	for name, want := range identity.Executables {
		got, err := executableFileIdentity(want.File.Path)
		if err != nil || !sameExecutableIdentity(want, got) {
			return executionIdentity{}, nil, fmt.Errorf("executable identity mismatch: %s", name)
		}
	}
	facts, err := deps.hostFacts()
	if err != nil || facts.GOOS != identity.GOOS ||
		facts.GOARCH != identity.GOARCH ||
		facts.CPUModel != identity.CPUModel ||
		facts.CPUModelSource != identity.CPUModelSource ||
		facts.OnlineSource != identity.OnlineSource ||
		facts.Online != identity.Online ||
		identity.PhaseJobs != derivedPhaseJobs(identity.Online) ||
		os.Getenv("GOMAXPROCS") != strconv.Itoa(identity.PhaseJobs) {
		return executionIdentity{}, nil, errors.New("frozen host or CPU identity mismatch")
	}
	for stageName := range config.Stages {
		expected, environmentErr := frozenEnvironment(
			config,
			identity.PhaseJobs,
			stageName,
			stageTempDirectory(identity.EvidenceRoot.Path, stageName),
			filepath.Dir(identity.Executables["${GO}"].File.Path),
		)
		if environmentErr != nil ||
			!equalStrings(identity.Environment[stageName], expected) {
			return executionIdentity{}, nil, errors.New("child environment identity mismatch")
		}
	}
	if len(config.ThreatClosure) != 0 {
		if err := validateDistinctStageCaches(identity.Environment); err != nil {
			return executionIdentity{}, nil, err
		}
	}
	for _, path := range identity.WorkingDirs {
		workingDirectory, directoryErr := directoryIdentityFor(path)
		if directoryErr != nil ||
			!pathWithin(identity.Source.Path, workingDirectory.Path) {
			return executionIdentity{}, nil, errors.New("working-directory identity mismatch")
		}
	}
	evidenceParent, err := directoryIdentityFor(filepath.Dir(options.Evidence))
	evidenceParent.ModTimeUnixNano = 0
	if err != nil || evidenceParent != identity.EvidenceRoot {
		return executionIdentity{}, nil, errors.New("evidence path is outside the frozen evidence root")
	}
	return identity, config, nil
}

func loadGateConfig(
	path string,
	expectedSHA256 string,
) (*gateConfig, fileIdentity, error) {
	identity, err := regularFileIdentity(path)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if !validSHA256(expectedSHA256) || identity.SHA256 != expectedSHA256 {
		return nil, fileIdentity{}, errors.New("gate config is not the exact reviewed manifest")
	}
	var config gateConfig
	if err := decodeStrictFile(path, &config); err != nil {
		return nil, fileIdentity{}, fmt.Errorf("decode gate config: %w", err)
	}
	return &config, identity, nil
}

func validateRuntimeGateConfig(deps runtimeDeps, config *gateConfig) error {
	if deps.validateConfig == nil {
		return errors.New("gate config validator is unavailable")
	}
	return deps.validateConfig(config)
}

func validateGateConfig(config *gateConfig) error {
	if config == nil || len(config.ThreatClosure) == 0 {
		return errors.New("reviewed gate config requires a complete threat closure")
	}
	return validateGateConfigStructure(config)
}

func validateGateConfigStructure(config *gateConfig) error {
	if config == nil || config.SchemaVersion != gateSchemaVersion ||
		config.GoVersion != "go1.26.5" || config.Module == "" {
		return errors.New("invalid gate config header")
	}
	stageNames := make([]string, 0, len(config.Stages))
	var owned []string
	var surfaces []executionSurface
	for name, stage := range config.Stages {
		stageNames = append(stageNames, name)
		owned = append(owned, stage.OwnedExecutionUnits...)
		var commandIDs []string
		for _, command := range stage.Commands {
			if command.ID == "" || command.Kind == "" {
				return errors.New("stage command is missing identity")
			}
			commandIDs = append(commandIDs, command.ID)
			if command.Kind == "go-test" && !command.GoBased {
				return errors.New("go-test command must be Go-based")
			}
			if command.GoBased {
				raceEnabled, err := exactGoRaceFlag(command.Argv)
				if err != nil {
					return err
				}
				if raceEnabled &&
					config.ChildEnvironment.Required["CGO_ENABLED"] != "1" {
					return errors.New("go -race command requires CGO_ENABLED=1")
				}
				value, err := parallelismValue(command.PackageParallelism)
				if err != nil || value != 1 {
					return errors.New("invalid Go package parallelism")
				}
				if command.Kind == "go-test" &&
					!argvHasExactFlag(command.Argv, "-p", "1") {
					return errors.New("go test argv does not enforce serial package execution")
				}
			}
			if len(config.ThreatClosure) != 0 {
				if err := validateExecutionSurface(
					command,
					config.ChildEnvironment.Required["CGO_ENABLED"],
				); err != nil {
					return fmt.Errorf("command %s execution surface: %w", command.ID, err)
				}
				if command.Kind == "golangci-lint" {
					lint, ok := lintByID(config.LintRuns, command.LintRun)
					if !ok {
						return fmt.Errorf("command %s references an unknown lint run", command.ID)
					}
					if err := validateLintExecutionSurface(command, lint); err != nil {
						return fmt.Errorf("command %s execution surface: %w", command.ID, err)
					}
				}
				surfaces = append(surfaces, command.ExecutionSurface)
			}
		}
		if len(config.ThreatClosure) != 0 &&
			(hasDuplicates(commandIDs) ||
				!sameStringSet(commandIDs, stage.OwnedExecutionUnits)) {
			return errors.New("stage commands do not exactly own their execution units")
		}
	}
	sort.Strings(stageNames)
	if !equalStrings(stageNames, []string{"host", "mutation", "normal1", "paranoid1"}) {
		return errors.New("gate config must contain exactly four stages")
	}
	if hasDuplicates(owned) || !sameStringSet(owned, config.RequiredExecutionUnits) {
		return errors.New("stage execution-unit partition is not disjoint and exhaustive")
	}
	if len(config.RequiredThreatIDs) != 21 || hasDuplicates(config.RequiredThreatIDs) {
		return errors.New("gate config must contain 21 unique threat IDs")
	}
	if len(config.LintRuns) != 3 {
		return errors.New("gate config must contain three lint runs")
	}
	if err := validateArtifactNamespace(
		config.EvidenceContract,
		stageNames,
	); err != nil {
		return err
	}
	if len(config.ThreatClosure) != 0 {
		if config.BuildAttestation != (buildAttestationContract{
			Classification:             "controlled-build self-attestation; not proof against a malicious builder",
			BaselineLDFlag:             "-X=main.phase2Baseline=${BASELINE}",
			BaseLDFlag:                 "-X=main.phase2Base=${BASE}",
			SourceManifestSHA256LDFlag: "-X=main.phase2SourceManifestSHA256=${SOURCE_MANIFEST_SHA256}",
		}) {
			return errors.New("controlled-build attestation contract mismatch")
		}
		if config.DependencyContract != (vendorDependencyContract{
			Mode:                   "archive-local-vendor",
			VendorModulesPath:      "src/vendor/modules.txt",
			SourceManifestCoverage: "complete-tree",
			GOFlags:                "-mod=vendor -trimpath",
			ModuleCacheFallback:    "forbidden-empty-sentinel",
			StageBuildCache:        "distinct-empty-per-stage",
		}) {
			return errors.New("vendored dependency contract mismatch")
		}
		for left := range surfaces {
			for right := left + 1; right < len(surfaces); right++ {
				if executionSurfacesOverlap(surfaces[left], surfaces[right]) {
					return errors.New("execution surfaces overlap")
				}
			}
		}
		if config.ChildEnvironment.Required["GOFLAGS"] != "-mod=vendor -trimpath" ||
			config.ChildEnvironment.Required["GOCACHE"] != "${STAGE_GOCACHE}" ||
			config.ChildEnvironment.Required["GOMODCACHE"] != "${WORKSPACE_GOMODCACHE}" ||
			config.ChildEnvironment.Required["GOPROXY"] != "off" ||
			config.ChildEnvironment.Required["GOTOOLCHAIN"] != "local" {
			return errors.New("vendored child environment contract mismatch")
		}
		if err := validateHostTestScopes(config); err != nil {
			return err
		}
	}
	if err := validateSkipContract(config); err != nil {
		return err
	}
	if err := validateThreatClosure(config); err != nil {
		return err
	}
	return nil
}

func validateHostTestScopes(config *gateConfig) error {
	host, ok := config.Stages["host"]
	if !ok {
		return errors.New("host stage is missing")
	}
	phase2, phase2OK := commandByID(host.Commands, "host-phase2-tests")
	controller, controllerOK := commandByID(host.Commands, "host-controller-tests")
	reproduction, reproductionOK := commandByID(
		host.Commands,
		"host-fixture-reproduction",
	)
	schema, schemaOK := commandByID(host.Commands, "host-fixture-schema")
	var goTestIDs []string
	for _, command := range host.Commands {
		if command.Kind == "go-test" {
			goTestIDs = append(goTestIDs, command.ID)
		}
	}
	if !phase2OK || !controllerOK || !reproductionOK || !schemaOK ||
		!sameStringSet(goTestIDs, []string{
			"host-phase2-tests",
			"host-controller-tests",
			"host-fixture-reproduction",
			"host-fixture-schema",
		}) ||
		!equalStrings(
			phase2.ExecutionSurface.PackagePaths,
			[]string{"./internal/pcv3credential"},
		) ||
		!equalStrings(
			phase2.ExecutionSurface.BuildTags,
			[]string{"migrated_fynedo"},
		) ||
		phase2.ExecutionSurface.TestSelector != "all" ||
		!equalStrings(
			controller.ExecutionSurface.PackagePaths,
			[]string{
				"./internal/pcv3credential/testdata/phasegates",
				"./internal/pcv3credential/testdata/phaseinspect",
			},
		) ||
		!equalStrings(
			controller.ExecutionSurface.BuildTags,
			[]string{"migrated_fynedo"},
		) ||
		controller.ExecutionSurface.TestSelector == "all" ||
		!equalStrings(
			reproduction.ExecutionSurface.PackagePaths,
			[]string{"./internal/pcv3credential"},
		) ||
		!equalStrings(
			reproduction.ExecutionSurface.BuildTags,
			[]string{"migrated_fynedo", "pcv3_fixture_reproduction"},
		) ||
		reproduction.ExecutionSurface.TestSelector !=
			"^TestKDFLiteralFixtureReproduction$" ||
		!equalStrings(
			schema.ExecutionSurface.PackagePaths,
			[]string{
				"./internal/pcv3credential/testdata/vectorfixture",
				"./internal/pcv3credential/testdata/mutator",
			},
		) ||
		!equalStrings(
			schema.ExecutionSurface.BuildTags,
			[]string{"migrated_fynedo"},
		) ||
		schema.ExecutionSurface.TestSelector != "all" {
		return errors.New("host Phase-2 or controller test scope is not exact")
	}
	return nil
}

func validateArtifactNamespace(
	contract evidenceContract,
	stageNames []string,
) error {
	if contract.SchemaVersion != gateSchemaVersion ||
		!equalStrings(contract.TerminalStatuses, []string{"PASS", "FAIL"}) ||
		!contract.CreateExclusive ||
		!contract.ReplaceForbidden ||
		hasDuplicates(contract.RequiredStageNames) ||
		!sameStringSet(contract.RequiredStageNames, stageNames) ||
		len(contract.StageFilenames) != len(stageNames) ||
		!safeArtifactSuffix(contract.PublicationProofSuffix) {
		return errors.New("evidence artifact namespace mismatch")
	}
	seen := make(map[string]bool, len(stageNames)*2)
	for _, stageName := range stageNames {
		filename, ok := contract.StageFilenames[stageName]
		if !ok || !safeArtifactBasename(filename) ||
			seen[filename] ||
			!safeArtifactBasename(filename+contract.PublicationProofSuffix) ||
			seen[filename+contract.PublicationProofSuffix] {
			return errors.New("evidence artifact namespace mismatch")
		}
		seen[filename] = true
		seen[filename+contract.PublicationProofSuffix] = true
	}
	return nil
}

func safeArtifactBasename(value string) bool {
	return value != "" &&
		value != "." &&
		value != ".." &&
		!strings.ContainsRune(value, '\x00') &&
		!strings.ContainsAny(value, `/\`) &&
		filepath.Base(value) == value
}

func safeArtifactSuffix(value string) bool {
	return value != "" &&
		value != "." &&
		value != ".." &&
		!strings.ContainsRune(value, '\x00') &&
		!strings.ContainsAny(value, `/\`) &&
		filepath.Base(value) == value
}

func validateExecutionSurface(
	command commandConfig,
	cgoEnabled string,
) error {
	surface := command.ExecutionSurface
	if surface.EvidenceKind == "" || surface.TestSelector == "" ||
		hasDuplicates(surface.PackagePaths) || hasDuplicates(surface.BuildTags) {
		return errors.New("surface fields are incomplete or duplicated")
	}
	for _, packagePath := range surface.PackagePaths {
		if !strings.HasPrefix(packagePath, "./") ||
			strings.Contains(packagePath, "...") {
			return errors.New("surface package path is not explicit")
		}
	}
	if command.Kind != "go-test" {
		return nil
	}
	if !command.GoBased {
		return errors.New("go-test command must be Go-based")
	}
	if len(command.Argv) < 2 ||
		command.Argv[0] != "${GO}" ||
		command.Argv[1] != "test" {
		return errors.New("go-test argv must start with exact ${GO} test")
	}
	var packages []string
	var tags []string
	selector := "all"
	tagCount := 0
	selectorCount := 0
	parallelismCount := 0
	jsonCount := 0
	raceCount := 0
	countCount := 0
	timeoutCount := 0
	for index := 2; index < len(command.Argv); index++ {
		argument := command.Argv[index]
		switch {
		case argument == "-tags":
			tagCount++
			if tagCount != 1 || index+1 >= len(command.Argv) {
				return errors.New(
					"go-test argv contains duplicate or incomplete -tags",
				)
			}
			index++
			if command.Argv[index] == "" {
				return errors.New("go-test argv contains empty build tags")
			}
			tags = strings.Split(command.Argv[index], ",")
			if hasDuplicates(tags) || contains(tags, "") {
				return errors.New(
					"go-test argv contains empty or duplicate build tags",
				)
			}
		case argument == "-run":
			selectorCount++
			if selectorCount != 1 || index+1 >= len(command.Argv) {
				return errors.New(
					"go-test argv contains duplicate or incomplete -run",
				)
			}
			index++
			selector = command.Argv[index]
			if selector == "" {
				return errors.New("go-test argv contains an empty selector")
			}
		case argument == "-p":
			parallelismCount++
			if index+1 >= len(command.Argv) ||
				command.Argv[index+1] != "1" {
				return errors.New(
					"go-test argv requires exactly one canonical -p 1",
				)
			}
			index++
		case argument == "-json":
			jsonCount++
		case argument == "-race":
			raceCount++
			if raceCount > 1 {
				return errors.New("go-test argv contains duplicate -race")
			}
		case argument == "-count=1":
			countCount++
			if countCount > 1 {
				return errors.New(
					"go-test argv requires exactly one canonical -count=1",
				)
			}
		case strings.HasPrefix(argument, "-timeout="):
			timeoutCount++
			duration, err := time.ParseDuration(
				strings.TrimPrefix(argument, "-timeout="),
			)
			if err != nil ||
				timeoutCount > 1 ||
				duration <= 0 ||
				duration >= time.Duration(command.TimeoutSeconds)*time.Second {
				return errors.New(
					"go-test argv requires exactly one canonical positive -timeout shorter than outer timeout",
				)
			}
		case strings.HasPrefix(argument, "-count"),
			strings.HasPrefix(argument, "--count"):
			return errors.New(
				"go-test argv requires exactly one canonical -count=1",
			)
		case strings.HasPrefix(argument, "-timeout"),
			strings.HasPrefix(argument, "--timeout"):
			return errors.New(
				"go-test argv requires exactly one canonical positive -timeout shorter than outer timeout",
			)
		case argument == "--race",
			strings.HasPrefix(argument, "-race="),
			strings.HasPrefix(argument, "--race="):
			return errors.New("go race flag must use exact -race form")
		case strings.HasPrefix(argument, "-p="),
			strings.HasPrefix(argument, "--p"),
			strings.HasPrefix(argument, "-json="),
			strings.HasPrefix(argument, "--json"),
			strings.HasPrefix(argument, "-tags="),
			strings.HasPrefix(argument, "--tags"),
			strings.HasPrefix(argument, "-run="),
			strings.HasPrefix(argument, "--run"):
			return errors.New(
				"go-test argv contains a noncanonical execution flag",
			)
		case strings.HasPrefix(argument, "./"):
			if !exactGoPackagePath(argument) {
				return errors.New("go-test argv package is not exact")
			}
			packages = append(packages, argument)
		default:
			return errors.New(
				"go-test argv contains an unsupported or ambiguous argument",
			)
		}
	}
	if parallelismCount != 1 {
		return errors.New("go-test argv requires exactly one canonical -p 1")
	}
	if jsonCount != 1 {
		return errors.New("go-test argv requires exactly one canonical -json")
	}
	if countCount != 1 {
		return errors.New(
			"go-test argv requires exactly one canonical -count=1",
		)
	}
	if timeoutCount != 1 {
		return errors.New(
			"go-test argv requires exactly one canonical positive -timeout shorter than outer timeout",
		)
	}
	if len(packages) == 0 || hasDuplicates(packages) {
		return errors.New(
			"go-test argv requires unique explicit package paths",
		)
	}
	wantEvidenceKind := "go-test-json"
	if raceCount == 1 {
		if cgoEnabled != "1" {
			return errors.New("go -race command requires CGO_ENABLED=1")
		}
		wantEvidenceKind = "go-test-race-json"
	}
	if !equalStrings(surface.PackagePaths, packages) ||
		!equalStrings(surface.BuildTags, tags) ||
		surface.TestSelector != selector ||
		surface.EvidenceKind != wantEvidenceKind {
		return errors.New("surface does not match exact go-test argv")
	}
	if selector != "all" {
		paths, ok := exactTestSelector(selector)
		if !ok {
			return errors.New("go-test surface selector is not an exact test path")
		}
		selected := selectorTestIDs(paths)
		if hasDuplicates(command.RequiredTestIDs) ||
			!sameStringSet(selected, command.RequiredTestIDs) {
			return errors.New(
				"go-test selector does not match the required evidence inventory",
			)
		}
	}
	return validateRequiredTestPackages(command)
}

func validateLintExecutionSurface(command commandConfig, lint lintRun) error {
	const packageStart = 12
	buildTagFlags := 0
	for _, argument := range lint.Argv {
		if argument == "--build-tags" {
			buildTagFlags++
		}
	}
	if buildTagFlags != 1 {
		return errors.New("lint argv requires exactly one canonical --build-tags")
	}
	if len(lint.Argv) <= packageStart || lint.JSONPath == "" ||
		lint.Argv[0] != "${GOLANGCI_LINT}" ||
		lint.Argv[1] != "run" ||
		lint.Argv[2] != "-c" ||
		lint.Argv[3] != ".golangci.phase2.yml" ||
		lint.Argv[4] != "--build-tags" ||
		lint.Argv[6] != "--concurrency" ||
		lint.Argv[7] != "1" ||
		lint.Argv[8] != "--output.text.path" ||
		lint.Argv[9] != "/dev/null" ||
		lint.Argv[10] != "--output.json.path" ||
		lint.Argv[11] != lint.JSONPath {
		return errors.New("lint argv is not canonical")
	}
	tags := strings.Split(lint.Argv[5], ",")
	if contains(tags, "") || hasDuplicates(tags) {
		return errors.New("lint argv contains empty or duplicate build tags")
	}
	for _, tag := range tags {
		for _, character := range tag {
			if !unicode.IsLetter(character) && !unicode.IsDigit(character) &&
				character != '_' && character != '.' {
				return errors.New("lint argv contains a noncanonical build tag")
			}
		}
	}
	packages := append([]string(nil), lint.Argv[packageStart:]...)
	for _, packagePath := range packages {
		if !exactGoPackagePath(packagePath) {
			return errors.New("lint argv package is not exact")
		}
	}
	if hasDuplicates(packages) {
		return errors.New("lint argv contains duplicate packages")
	}
	if !equalStrings(command.ExecutionSurface.PackagePaths, packages) ||
		!equalStrings(command.ExecutionSurface.BuildTags, tags) ||
		command.ExecutionSurface.TestSelector != "all" ||
		command.ExecutionSurface.EvidenceKind != "lint-json" {
		return errors.New("lint execution surface does not match argv")
	}
	if !equalStrings(lint.Tags, tags) {
		return errors.New("lint run tags do not match argv")
	}
	return nil
}

func exactGoPackagePath(path string) bool {
	if !strings.HasPrefix(path, "./") ||
		len(path) == 2 ||
		strings.Contains(path, "...") ||
		strings.ContainsAny(path, `\*?[]`) {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "./"), "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func validateRequiredTestPackages(command commandConfig) error {
	if len(command.RequiredTestIDs) == 0 ||
		hasDuplicates(command.RequiredTestIDs) ||
		len(command.RequiredTestPackages) != len(command.RequiredTestIDs) {
		return errors.New("go-test required evidence inventory is incomplete")
	}
	allowedPackages := make(map[string]bool, len(command.ExecutionSurface.PackagePaths))
	for _, packagePath := range command.ExecutionSurface.PackagePaths {
		allowedPackages[picocryptModulePath+"/"+strings.TrimPrefix(packagePath, "./")] = true
	}
	for _, testID := range command.RequiredTestIDs {
		packagePath, ok := command.RequiredTestPackages[testID]
		if !ok || !allowedPackages[packagePath] {
			return errors.New("go-test required package binding is outside its surface")
		}
	}
	return nil
}

func executionSurfacesOverlap(left, right executionSurface) bool {
	if left.EvidenceKind != right.EvidenceKind ||
		!sameStringSet(left.BuildTags, right.BuildTags) {
		return false
	}
	sharesPackage := false
	for _, packagePath := range left.PackagePaths {
		if contains(right.PackagePaths, packagePath) {
			sharesPackage = true
			break
		}
	}
	if !sharesPackage {
		return false
	}
	if left.TestSelector == "all" || right.TestSelector == "all" {
		return true
	}
	leftTests, leftExact := exactTestSelector(left.TestSelector)
	rightTests, rightExact := exactTestSelector(right.TestSelector)
	if !leftExact || !rightExact {
		return true
	}
	for _, leftPath := range leftTests {
		for _, rightPath := range rightTests {
			if selectorPrefix(leftPath, rightPath) ||
				selectorPrefix(rightPath, leftPath) {
				return true
			}
		}
	}
	return false
}

func exactTestSelector(selector string) ([][]string, bool) {
	parts := strings.Split(selector, "/")
	if len(parts) == 1 {
		tests, ok := exactSelectorPart(parts[0], true)
		if !ok {
			return nil, false
		}
		paths := make([][]string, len(tests))
		for index, test := range tests {
			paths[index] = []string{test}
		}
		return paths, true
	}

	path := make([]string, 0, len(parts))
	for _, part := range parts {
		tests, ok := exactSelectorPart(part, false)
		if !ok || len(tests) != 1 {
			return nil, false
		}
		path = append(path, tests[0])
	}
	return [][]string{path}, true
}

func exactSelectorPart(part string, allowAlternatives bool) ([]string, bool) {
	if len(part) < 3 || part[0] != '^' || part[len(part)-1] != '$' {
		return nil, false
	}
	body := part[1 : len(part)-1]
	if allowAlternatives &&
		strings.HasPrefix(body, "(") &&
		strings.HasSuffix(body, ")") {
		tests := strings.Split(body[1:len(body)-1], "|")
		if len(tests) < 2 || hasDuplicates(tests) {
			return nil, false
		}
		for _, test := range tests {
			if !exactSelectorLiteral(test) {
				return nil, false
			}
		}
		return tests, true
	}
	if !exactSelectorLiteral(body) {
		return nil, false
	}
	return []string{body}, true
}

func exactSelectorLiteral(literal string) bool {
	if literal == "" {
		return false
	}
	for _, character := range literal {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func selectorTestIDs(paths [][]string) []string {
	tests := make([]string, len(paths))
	for index, path := range paths {
		tests[index] = strings.Join(path, "/")
	}
	return tests
}

func selectorPrefix(prefix, selector []string) bool {
	if len(prefix) > len(selector) {
		return false
	}
	for index := range prefix {
		if prefix[index] != selector[index] {
			return false
		}
	}
	return true
}

func argvHasExactFlag(argv []string, flagName, value string) bool {
	count := 0
	for index := 0; index+1 < len(argv); index++ {
		if argv[index] == flagName {
			count++
			if argv[index+1] != value {
				return false
			}
		}
	}
	return count == 1
}

func exactGoRaceFlag(argv []string) (bool, error) {
	enabled := false
	for _, argument := range argv {
		switch {
		case argument == "-race":
			enabled = true
		case argument == "--race",
			strings.HasPrefix(argument, "-race="),
			strings.HasPrefix(argument, "--race="):
			return false, errors.New("go race flag must use exact -race form")
		}
	}
	return enabled, nil
}

func validateThreatClosure(config *gateConfig) error {
	if len(config.ThreatClosure) == 0 {
		return nil
	}
	if len(config.ThreatClosure) != len(config.RequiredThreatIDs) {
		return errors.New("threat closure must map every required threat exactly once")
	}
	var mapped []string
	observedByCommand := map[string]map[string]bool{}
	for _, closure := range config.ThreatClosure {
		mapped = append(mapped, closure.ID)
		stage, ok := config.Stages[closure.Stage]
		if !ok || len(closure.RequiredObservedIDs) == 0 ||
			hasDuplicates(closure.RequiredObservedIDs) {
			return errors.New("threat closure contains an invalid stage or observed-ID set")
		}
		command, ok := commandByID(stage.Commands, closure.CommandID)
		if !ok {
			return errors.New("threat closure names an unknown command")
		}
		switch command.Kind {
		case "mutation-campaign":
			if !subsetOf(closure.RequiredObservedIDs, config.RequiredMutationIDs) {
				return errors.New("mutation threat closure names an unknown mutation")
			}
		case "go-test":
			if !subsetOf(closure.RequiredObservedIDs, command.RequiredTestIDs) {
				return errors.New("test threat closure is outside the command inventory")
			}
			if observedByCommand[command.ID] == nil {
				observedByCommand[command.ID] = map[string]bool{}
			}
			for _, observedID := range closure.RequiredObservedIDs {
				observedByCommand[command.ID][observedID] = true
			}
		default:
			return errors.New("threat closure must be backed by mutation or structured test evidence")
		}
	}
	if hasDuplicates(mapped) || !sameStringSet(mapped, config.RequiredThreatIDs) {
		return errors.New("threat closure IDs do not match the required threat set")
	}
	host, ok := config.Stages["host"]
	if !ok {
		return errors.New("threat closure names an unknown command")
	}
	for commandID, observedIDs := range observedByCommand {
		command, ok := commandByID(host.Commands, commandID)
		if !ok || command.Kind != "go-test" {
			return errors.New("threat closure names an unknown command")
		}
		var observed []string
		for testID := range observedIDs {
			observed = append(observed, testID)
		}
		if !sameStringSet(observed, command.RequiredTestIDs) {
			return errors.New(
				"test command evidence inventory exceeds its threat closure",
			)
		}
	}
	return nil
}

func commandByID(commands []commandConfig, id string) (commandConfig, bool) {
	for _, command := range commands {
		if command.ID == id {
			return command, true
		}
	}
	return commandConfig{}, false
}

func subsetOf(values, allowed []string) bool {
	for _, value := range values {
		if !contains(allowed, value) {
			return false
		}
	}
	return true
}

func validateSkipContract(config *gateConfig) error {
	if len(config.SkipAllowlist) != 0 ||
		config.SkipRuntimeCardinality != (skipCardinality{}) {
		return errors.New("controlled Phase-2 gates must forbid every runtime skip")
	}
	return nil
}

func runConfiguredCommand(
	ctx context.Context,
	command commandConfig,
	config *gateConfig,
	identity executionIdentity,
	replacements map[string]string,
	deps runtimeDeps,
) (commandResult, error) {
	effective := command
	var result commandResult
	var runErr error
	switch command.Kind {
	case "internal":
		result, runErr = runInternalCheck(command, config, replacements)
	case "mutation-campaign":
		if command.TimeoutSeconds <= 0 {
			return commandResult{ID: command.ID}, errors.New("mutation campaign has invalid timeout")
		}
		campaignContext, cancel := context.WithTimeout(
			ctx,
			time.Duration(command.TimeoutSeconds)*time.Second,
		)
		defer cancel()
		var err error
		result, err = runMutationCampaign(
			campaignContext,
			command,
			config,
			identity,
			replacements,
			deps,
		)
		result.TimedOut = errors.Is(campaignContext.Err(), context.DeadlineExceeded)
		runErr = err
	case "golangci-lint":
		lint, ok := lintByID(config.LintRuns, command.LintRun)
		if !ok {
			return commandResult{ID: command.ID}, errors.New("unknown lint run")
		}
		effective.Argv = lint.Argv
		effective.CWD = "${SOURCE}/src"
		effective.TimeoutSeconds = 600
		effective.GoBased = true
		effective.PackageParallelism = float64(1)
		effective.RequiredExitCode = lint.ExitCodeRequired
		result, runErr = executeCommand(ctx, effective, identity, replacements, deps)
		if runErr == nil {
			jsonPath := replaceAll(lint.JSONPath, replacements)
			lintResult, lintErr := readLintEvidence(
				jsonPath,
				lint.ID,
				lint.IssuesRequired,
			)
			if lintErr != nil {
				runErr = lintErr
			} else {
				result.LintResult = &lintResult
			}
		}
	case "go-test", "gitleaks", "structured":
		result, runErr = executeCommand(ctx, command, identity, replacements, deps)
		if runErr == nil && command.Kind == "gitleaks" {
			scan, scanErr := scanEvidenceFor(result.Argv)
			if scanErr != nil {
				runErr = scanErr
			} else {
				result.ScanResult = &scan
			}
		}
	default:
		return commandResult{ID: command.ID}, errors.New("unsupported gate command kind")
	}
	result.Contract = commandEvidenceFor(effective)
	if result.Argv == nil {
		result.Argv = []string{}
	}
	if result.CWD == "" {
		result.CWD = replaceAll(effective.CWD, replacements)
	}
	if runErr == nil {
		if err := validateProducedCommandResult(
			effective,
			result,
			replacements,
		); err != nil {
			runErr = err
		}
	}
	return result, runErr
}

func validateProducedCommandResult(
	command commandConfig,
	result commandResult,
	replacements map[string]string,
) error {
	if !reflect.DeepEqual(result.Contract, commandEvidenceFor(command)) {
		return errors.New("produced command contract mismatch")
	}
	expectedCWD := replaceAll(command.CWD, replacements)
	if result.CWD != expectedCWD {
		return errors.New("produced command working directory mismatch")
	}
	switch command.Kind {
	case "go-test", "golangci-lint", "gitleaks", "structured":
		if !equalStrings(result.Argv, replaceSlice(command.Argv, replacements)) {
			return errors.New("produced command argv mismatch")
		}
	case "internal", "mutation-campaign":
		if len(result.Argv) != 0 {
			return errors.New("non-process command recorded an argv")
		}
	default:
		return errors.New("produced command has an unsupported kind")
	}
	switch command.Kind {
	case "golangci-lint":
		if result.LintResult == nil ||
			result.LintResult.RunID != command.LintRun ||
			!validSHA256(result.LintResult.JSONSHA256) ||
			len(result.LintResult.Issues) != 0 ||
			len(result.LintResult.EnabledLinters) == 0 ||
			hasDuplicates(result.LintResult.EnabledLinters) ||
			result.ScanResult != nil {
			return errors.New("produced lint result mismatch")
		}
	case "gitleaks":
		expected, err := scanEvidenceFor(result.Argv)
		if err != nil || result.ScanResult == nil ||
			*result.ScanResult != expected ||
			result.LintResult != nil {
			return errors.Join(err, errors.New("produced scan result mismatch"))
		}
	default:
		if result.LintResult != nil || result.ScanResult != nil {
			return errors.New("unexpected lint or scan result")
		}
	}
	if command.Kind == "mutation-campaign" {
		for _, mutation := range result.Mutations {
			if mutation.ApplicationReceipt.SchemaVersion != gateSchemaVersion ||
				mutation.ApplicationReceipt.MutationID != mutation.ID ||
				mutation.ApplicationReceipt.KillingTestID != mutation.KillingTestID ||
				mutation.ApplicationReceipt.ViolationMarker != mutation.ViolationMarker {
				return errors.New("produced mutation receipt mismatch")
			}
		}
	}
	if result.GoTestFailure != nil {
		return errors.New("successful command retained Go test failure diagnostics")
	}
	return nil
}

type lintJSONOutput struct {
	Issues []json.RawMessage `json:"Issues"`
	Report lintJSONReport    `json:"Report"`
}

type lintJSONReport struct {
	Linters []lintJSONLinter `json:"Linters"`
}

type lintJSONLinter struct {
	Name    string `json:"Name"`
	Enabled bool   `json:"Enabled,omitempty"`
}

func validateLintJSON(path string, requiredIssues int) error {
	_, err := readLintEvidence(path, "", requiredIssues)
	return err
}

func readLintEvidence(
	path string,
	runID string,
	requiredIssues int,
) (lintEvidenceResult, error) {
	var output lintJSONOutput
	if err := decodeStrictFile(path, &output); err != nil {
		return lintEvidenceResult{}, fmt.Errorf("decode lint JSON: %w", err)
	}
	if len(output.Issues) != requiredIssues || len(output.Report.Linters) == 0 {
		return lintEvidenceResult{},
			errors.New("lint JSON contains unexpected issues or an empty report")
	}
	var enabled []string
	for _, linter := range output.Report.Linters {
		if linter.Name == "" {
			return lintEvidenceResult{},
				errors.New("lint JSON report contains an unnamed linter")
		}
		if linter.Enabled {
			enabled = append(enabled, linter.Name)
		}
	}
	if len(enabled) == 0 {
		return lintEvidenceResult{},
			errors.New("lint JSON report contains no enabled linter")
	}
	sort.Strings(enabled)
	identity, err := regularFileIdentity(path)
	if err != nil {
		return lintEvidenceResult{}, fmt.Errorf("bind lint JSON result: %w", err)
	}
	return lintEvidenceResult{
		RunID:          runID,
		JSONSHA256:     identity.SHA256,
		Issues:         []struct{}{},
		EnabledLinters: enabled,
	}, nil
}

func scanEvidenceFor(argv []string) (scanEvidenceResult, error) {
	if len(argv) == 0 || filepath.Base(argv[0]) != "gitleaks" {
		return scanEvidenceResult{}, errors.New("scan executable is not gitleaks")
	}
	target := ""
	for index := 1; index+1 < len(argv); index++ {
		if argv[index] == "--source" {
			if target != "" || argv[index+1] == "" {
				return scanEvidenceResult{}, errors.New("scan target is ambiguous")
			}
			target = argv[index+1]
		}
	}
	if target == "" {
		return scanEvidenceResult{}, errors.New("scan target is absent")
	}
	return scanEvidenceResult{
		Scanner:  "gitleaks",
		Target:   target,
		Findings: 0,
	}, nil
}

func executeCommand(
	parent context.Context,
	command commandConfig,
	identity executionIdentity,
	replacements map[string]string,
	deps runtimeDeps,
) (commandResult, error) {
	if len(command.Argv) == 0 {
		return commandResult{ID: command.ID}, errors.New("command has no argv")
	}
	argv := replaceSlice(command.Argv, replacements)
	cwd := replaceAll(command.CWD, replacements)
	if cwd == "" {
		return commandResult{ID: command.ID}, errors.New("command has no working directory")
	}
	timeout := time.Duration(command.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		return commandResult{ID: command.ID}, errors.New("command has invalid timeout")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := deps.commandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = cwd
	cmd.Env = append([]string(nil), identity.Environment[replacements["${STAGE}"]]...)
	if actualEnvironment := cmd.Environ(); hasDuplicates(actualEnvironment) ||
		!sameStringSet(actualEnvironment, cmd.Env) {
		return commandResult{ID: command.ID, Argv: argv, CWD: cwd},
			errors.New("child process environment differs from the frozen environment")
	}
	cmd.WaitDelay = processWaitDelay
	stdout := &limitedBuffer{limit: maxCommandOutputBytes}
	stderr := &limitedBuffer{limit: maxCommandOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	tree, err := newProcessTree(cmd)
	if err != nil {
		return commandResult{ID: command.ID, Argv: argv, CWD: cwd}, err
	}
	var terminationErr error
	var terminationMu sync.Mutex
	cmd.Cancel = func() error {
		terminationMu.Lock()
		defer terminationMu.Unlock()
		if terminationErr == nil {
			terminationErr = tree.Terminate()
		}
		return terminationErr
	}
	if err := tree.Start(); err != nil {
		_ = tree.Close()
		return commandResult{ID: command.ID, Argv: argv, CWD: cwd}, err
	}
	waitErr := tree.Wait()
	active, activeErr := tree.Active()
	if activeErr != nil || active {
		if terminateErr := tree.Terminate(); terminateErr != nil {
			terminationErr = errors.Join(terminationErr, terminateErr)
		}
		if activeErr == nil {
			active, activeErr = waitForProcessTreeInactive(tree, processWaitDelay)
		}
	}
	closeErr := tree.Close()
	terminationMu.Lock()
	capturedTerminationErr := terminationErr
	terminationMu.Unlock()
	result := commandResult{
		ID:           command.ID,
		Argv:         argv,
		CWD:          cwd,
		Contract:     commandEvidenceFor(command),
		ExitCode:     exitCode(waitErr),
		StdoutSHA256: sha256Hex(stdout.Bytes()),
		StderrSHA256: sha256Hex(stderr.Bytes()),
		TimedOut:     errors.Is(ctx.Err(), context.DeadlineExceeded),
	}
	if capturedTerminationErr != nil {
		result.TerminationErr = safeFailure(capturedTerminationErr)
	}
	var exitError *exec.ExitError
	expectedExitError := waitErr != nil &&
		errors.As(waitErr, &exitError) &&
		result.ExitCode == command.RequiredExitCode
	if waitErr != nil && !expectedExitError {
		result.WaitErr = safeFailure(waitErr)
	}
	if stdout.err != nil || stderr.err != nil {
		return result, errors.Join(stdout.err, stderr.err)
	}
	if activeErr != nil || active {
		return result, errors.Join(activeErr, errors.New("child process group remains active"))
	}
	if closeErr != nil {
		return result, closeErr
	}
	if ctx.Err() != nil {
		return result, errors.Join(ctx.Err(), capturedTerminationErr, waitErr)
	}
	if result.ExitCode != command.RequiredExitCode {
		if command.Kind == "go-test" {
			summary := summarizeGoTestFailure(stdout.Bytes())
			result.GoTestFailure = &summary
		}
		return result, errors.Join(waitErr, errors.New("child process exit code mismatch"))
	}
	if waitErr != nil && !expectedExitError {
		return result, waitErr
	}
	combinedOutput := append(append([]byte(nil), stdout.Bytes()...), stderr.Bytes()...)
	if command.RequiredOutputMarker != "" &&
		!bytes.Contains(combinedOutput, []byte(command.RequiredOutputMarker)) {
		return result, errors.New("child output is missing the required violation marker")
	}
	if command.ForbiddenOutputMarker != "" &&
		bytes.Contains(combinedOutput, []byte(command.ForbiddenOutputMarker)) {
		return result, errors.New("child output contains a forbidden violation marker")
	}
	if command.ExpectedGoTestEvent != nil {
		attestation, err := parseNestedGoTestJSON(
			stdout.Bytes(),
			*command.ExpectedGoTestEvent,
			command.RequiredOutputMarker,
		)
		if err != nil {
			return result, err
		}
		result.GoTestEvent = &attestation
	}
	if command.Kind == "go-test" {
		ids, skips, parseErr := parseGoTestJSON(
			stdout.Bytes(),
			command.RequiredTestIDs,
			command.RequiredTestPackages,
		)
		result.ObservedIDs = ids
		result.SkipEvents = skips
		if parseErr != nil {
			return result, parseErr
		}
	}
	return result, nil
}

func waitForProcessTreeInactive(
	tree processTree,
	timeout time.Duration,
) (bool, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		active, err := tree.Active()
		if err != nil || !active {
			return active, err
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			active, err := tree.Active()
			return active, err
		}
	}
}

func runMutationCampaign(
	ctx context.Context,
	command commandConfig,
	config *gateConfig,
	identity executionIdentity,
	replacements map[string]string,
	deps runtimeDeps,
) (commandResult, error) {
	result := commandResult{ID: command.ID, ExitCode: 0}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	var manifest campaignManifest
	if err := decodeStrictFile(identity.Mutations.Path, &manifest); err != nil {
		return result, fmt.Errorf("decode mutation campaign manifest: %w", err)
	}
	if err := validateCampaignManifest(&manifest, config, identity); err != nil {
		return result, err
	}
	goExecutable, ok := identity.Executables["${GO}"]
	if !ok {
		return result, errors.New("mutation campaign has no frozen Go executable")
	}
	stageTemp := replacements["${STAGE_TMPDIR}"]
	mutationsByID := make(map[string]*campaignMutation, len(manifest.Mutations))
	for index := range manifest.Mutations {
		mutation := &manifest.Mutations[index]
		mutationsByID[mutation.ID] = mutation
	}
	for _, mutationID := range config.RequiredMutationIDs {
		mutation, ok := mutationsByID[mutationID]
		if !ok {
			return result, errors.New("required mutation is absent from campaign manifest")
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if mutation.ID == "" || mutation.KillingTestID == "" ||
			mutation.ViolationMarker == "" {
			return result, errors.New("mutation campaign entry is incomplete")
		}
		mutationRoot := filepath.Join(stageTemp, mutation.ID)
		sourceCopy := filepath.Join(mutationRoot, "source")
		if err := os.Mkdir(mutationRoot, 0o700); err != nil {
			return result, fmt.Errorf("create mutation work directory: %w", err)
		}
		if err := os.CopyFS(sourceCopy, os.DirFS(identity.Source.Path)); err != nil {
			return result, fmt.Errorf("copy frozen source for mutation %s: %w", mutation.ID, err)
		}
		copiedTarget := filepath.Join(sourceCopy, "src", mutation.SourcePath)
		beforeMutation, err := regularFileIdentity(copiedTarget)
		if err != nil || beforeMutation.SHA256 != mutation.SourceSHA256 {
			return result, errors.New("copied mutation source identity mismatch")
		}
		execution := mutationExecution{
			ID:              mutation.ID,
			KillingTestID:   mutation.KillingTestID,
			ViolationMarker: mutation.ViolationMarker,
		}
		pristineConfig := nestedMutationCommand(
			goExecutable.File.Path,
			mutation,
			sourceCopy,
			"pristine",
		)
		pristine, err := executeCommand(
			ctx,
			pristineConfig,
			identity,
			replacements,
			deps,
		)
		execution.Pristine = pristine
		if err != nil {
			result.ExitCode = 1
			result.Mutations = append(result.Mutations, execution)
			return result, fmt.Errorf("mutation %s pristine test: %w", mutation.ID, err)
		}
		mutationResultPath := filepath.Join(mutationRoot, "application.json")
		applicationConfig := mutationApplicationCommand(
			goExecutable.File.Path,
			identity,
			&manifest,
			mutation,
			sourceCopy,
			mutationResultPath,
		)
		application, err := executeCommand(
			ctx,
			applicationConfig,
			identity,
			replacements,
			deps,
		)
		execution.Application = application
		if err != nil {
			result.ExitCode = 1
			result.Mutations = append(result.Mutations, execution)
			return result, fmt.Errorf("apply mutation %s: %w", mutation.ID, err)
		}
		var applicationRecord campaignApplicationRecord
		if err := decodeStrictFile(mutationResultPath, &applicationRecord); err != nil ||
			!validCampaignApplication(
				&applicationRecord,
				&manifest,
				mutation,
				identity.Baseline,
			) {
			result.ExitCode = 1
			result.Mutations = append(result.Mutations, execution)
			return result, errors.New("mutation application result is malformed")
		}
		execution.ApplicationReceipt = applicationRecord
		afterMutation, err := regularFileIdentity(copiedTarget)
		if err != nil ||
			afterMutation.SHA256 != applicationRecord.SourceAfterSHA256 {
			result.ExitCode = 1
			result.Mutations = append(result.Mutations, execution)
			return result, errors.New("mutated source bytes do not match the application result")
		}
		mutantConfig := nestedMutationCommand(
			goExecutable.File.Path,
			mutation,
			sourceCopy,
			"mutant",
		)
		mutant, err := executeCommand(
			ctx,
			mutantConfig,
			identity,
			replacements,
			deps,
		)
		execution.Mutant = mutant
		if err != nil {
			result.ExitCode = 1
			result.Mutations = append(result.Mutations, execution)
			return result, fmt.Errorf("mutation %s killing test: %w", mutation.ID, err)
		}
		result.Mutations = append(result.Mutations, execution)
		result.ObservedIDs = append(result.ObservedIDs, mutation.ID)
	}
	return result, nil
}

func nestedMutationCommand(
	goExecutable string,
	mutation *campaignMutation,
	sourceCopy string,
	kind string,
) commandConfig {
	exitCode := 0
	terminalAction := "pass"
	if kind == "mutant" {
		exitCode = 1
		terminalAction = "fail"
	}
	command := commandConfig{
		ID:                 mutation.ID + "/" + kind,
		Kind:               "structured",
		Argv:               semanticTestArgv(goExecutable, mutation.KillingTestID),
		CWD:                filepath.Join(sourceCopy, "src"),
		TimeoutSeconds:     120,
		GoBased:            true,
		PackageParallelism: float64(1),
		RequiredExitCode:   exitCode,
		ExpectedGoTestEvent: &goTestEventAttestation{
			Package:        pcv3PackagePath,
			TestID:         mutation.KillingTestID,
			TerminalAction: terminalAction,
		},
	}
	if kind == "mutant" {
		command.RequiredOutputMarker = mutation.ViolationMarker
	} else {
		command.ForbiddenOutputMarker = mutation.ViolationMarker
	}
	return command
}

func mutationApplicationCommand(
	goExecutable string,
	identity executionIdentity,
	manifest *campaignManifest,
	mutation *campaignMutation,
	sourceCopy string,
	resultPath string,
) commandConfig {
	return commandConfig{
		ID:   mutation.ID + "/application",
		Kind: "structured",
		Argv: []string{
			goExecutable,
			"run",
			"-tags",
			"migrated_fynedo",
			"./internal/pcv3credential/testdata/mutator",
			"--source-copy", filepath.Join(sourceCopy, "src"),
			"--manifest", identity.Mutations.Path,
			"--mutation-id", mutation.ID,
			"--source-set-sha256", manifest.SourceSetSHA256,
			"--baseline", identity.Baseline,
			"--spec-sha256", manifest.SpecSHA256,
			"--result", resultPath,
		},
		CWD:                filepath.Join(identity.Source.Path, "src"),
		TimeoutSeconds:     120,
		GoBased:            true,
		PackageParallelism: float64(1),
		RequiredExitCode:   0,
	}
}

func validateCampaignManifest(
	manifest *campaignManifest,
	config *gateConfig,
	identity executionIdentity,
) error {
	if manifest == nil ||
		manifest.SchemaVersion != gateSchemaVersion ||
		manifest.SpecSHA256 != identity.Spec.SHA256 ||
		!equalStrings(manifest.ArgvTemplate, campaignArgvTemplate) ||
		!sameStringSet(mutationIDs(manifest.Mutations), config.RequiredMutationIDs) ||
		hasDuplicates(mutationIDs(manifest.Mutations)) {
		return errors.New("mutation campaign manifest identity mismatch")
	}
	for index := range manifest.Mutations {
		mutation := &manifest.Mutations[index]
		if !validCampaignMutation(manifest, mutation) {
			return fmt.Errorf("mutation campaign entry %q is invalid", mutation.ID)
		}
	}
	if campaignSourceSetHash(manifest.Mutations) != manifest.SourceSetSHA256 {
		return errors.New("mutation campaign source-set hash mismatch")
	}
	return nil
}

func validCampaignMutation(
	manifest *campaignManifest,
	mutation *campaignMutation,
) bool {
	if manifest == nil || mutation == nil ||
		!validCampaignMutationID(mutation.ID) ||
		mutation.Requirement == "" ||
		mutation.Invariant == "" ||
		mutation.SourcePath == "" ||
		filepath.IsAbs(mutation.SourcePath) ||
		filepath.ToSlash(filepath.Clean(mutation.SourcePath)) != mutation.SourcePath ||
		strings.HasPrefix(mutation.SourcePath, "../") ||
		!validSHA256(mutation.SourceSHA256) ||
		mutation.Anchor == "" ||
		mutation.Replacement == "" ||
		mutation.Anchor == mutation.Replacement ||
		!validGoTestID(mutation.KillingTestID) ||
		mutation.ViolationMarker == "" {
		return false
	}
	return validCampaignOutcome(
		&mutation.Pristine,
		mutation.KillingTestID,
		"PASS",
		"",
	) && validCampaignOutcome(
		&mutation.Mutant,
		mutation.KillingTestID,
		"FAIL",
		mutation.ViolationMarker,
	)
}

func validCampaignMutationID(value string) bool {
	if !strings.HasPrefix(value, "M-CRD") {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' {
			return false
		}
	}
	return true
}

func validGoTestID(value string) bool {
	if !strings.HasPrefix(value, "Test") || len(value) == len("Test") {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' {
			return false
		}
	}
	return true
}

func validCampaignOutcome(
	outcome *campaignOutcome,
	testID string,
	status string,
	marker string,
) bool {
	if outcome == nil ||
		outcome.Status != status ||
		outcome.Execution != "semantic" ||
		outcome.TestID != testID ||
		outcome.ViolationMarker != marker ||
		outcome.Stage == "" ||
		outcome.Reason == "" ||
		outcome.Skipped ||
		outcome.CompileOnly ||
		!equalStrings(outcome.SemanticCommand, []string{
			"go",
			"test",
			"./internal/pcv3credential",
			"-run",
			"^" + testID + "$",
			"-count=1",
		}) {
		return false
	}
	return true
}

func validCampaignApplication(
	record *campaignApplicationRecord,
	manifest *campaignManifest,
	mutation *campaignMutation,
	baseline string,
) bool {
	return record != nil &&
		manifest != nil &&
		mutation != nil &&
		record.SchemaVersion == gateSchemaVersion &&
		record.MutationID == mutation.ID &&
		record.BaselineCommit == baseline &&
		record.SpecSHA256 == manifest.SpecSHA256 &&
		record.SourceSetSHA256 == manifest.SourceSetSHA256 &&
		record.SourcePath == mutation.SourcePath &&
		validSHA256(record.SourceBeforeSHA256) &&
		record.SourceBeforeSHA256 == mutation.SourceSHA256 &&
		validSHA256(record.SourceAfterSHA256) &&
		record.SourceBeforeSHA256 != record.SourceAfterSHA256 &&
		record.AnchorMatches == 1 &&
		record.ApplicationCount == 1 &&
		record.KillingTestID == mutation.KillingTestID &&
		record.ViolationMarker == mutation.ViolationMarker &&
		reflect.DeepEqual(record.ExpectedPristine, mutation.Pristine) &&
		reflect.DeepEqual(record.ExpectedMutant, mutation.Mutant)
}

func semanticTestArgv(goExecutable, testID string) []string {
	return []string{
		goExecutable,
		"test",
		"-tags",
		"migrated_fynedo",
		"-p",
		"1",
		"./internal/pcv3credential",
		"-run",
		"^" + testID + "$",
		"-count=1",
		"-timeout=60s",
		"-json",
	}
}

func mutationIDs(mutations []campaignMutation) []string {
	ids := make([]string, len(mutations))
	for index, mutation := range mutations {
		ids[index] = mutation.ID
	}
	return ids
}

func campaignSourceSetHash(mutations []campaignMutation) string {
	sources := map[string]string{}
	for _, mutation := range mutations {
		if previous, exists := sources[mutation.SourcePath]; exists &&
			previous != mutation.SourceSHA256 {
			return ""
		}
		sources[mutation.SourcePath] = mutation.SourceSHA256
	}
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	hasher := sha256.New()
	for _, path := range paths {
		_, _ = hasher.Write([]byte(path))
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(sources[path]))
		_, _ = hasher.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func runInternalCheck(
	command commandConfig,
	config *gateConfig,
	replacements map[string]string,
) (commandResult, error) {
	result := commandResult{ID: command.ID, ExitCode: 0}
	switch command.ID {
	case "host-threat-closure":
		if command.RequiredIDsSource != "required_threat_ids" ||
			command.RequiredCount != len(config.RequiredThreatIDs) ||
			validateThreatClosure(config) != nil {
			return result, errors.New("threat closure mismatch")
		}
	default:
		return result, fmt.Errorf("unsupported internal gate %s", command.ID)
	}
	_ = replacements
	return result, nil
}

func validateObservedStage(config *gateConfig, evidence stageEvidence) error {
	if err := validateRuntimeSkips(config, evidence.SkipEvents); err != nil {
		return err
	}
	expectedThreats := expectedThreatsForStage(config, evidence.Stage)
	if !sameStringSet(evidence.ClosedThreatIDs, expectedThreats) ||
		hasDuplicates(evidence.ClosedThreatIDs) {
		return errors.New("stage threat closure is incomplete or duplicated")
	}
	if evidence.Stage == "mutation" {
		for _, id := range config.RequiredMutationIDs {
			if !contains(evidence.ObservedIDs, id) {
				return errors.New("mutation closure is incomplete")
			}
		}
	}
	return nil
}

func closedThreatsForCommand(
	config *gateConfig,
	stage string,
	commandID string,
	observedIDs []string,
) ([]string, error) {
	var closed []string
	for _, closure := range config.ThreatClosure {
		if closure.Stage != stage || closure.CommandID != commandID {
			continue
		}
		if !subsetOf(closure.RequiredObservedIDs, observedIDs) {
			return nil, fmt.Errorf(
				"threat %s lacks required structured evidence",
				closure.ID,
			)
		}
		closed = append(closed, closure.ID)
	}
	sort.Strings(closed)
	return closed, nil
}

func expectedThreatsForStage(config *gateConfig, stage string) []string {
	var expected []string
	for _, closure := range config.ThreatClosure {
		if closure.Stage == stage {
			expected = append(expected, closure.ID)
		}
	}
	sort.Strings(expected)
	return expected
}

func validateRuntimeSkips(config *gateConfig, events []skipEvent) error {
	if validateSkipContract(config) != nil || len(events) != 0 {
		return errors.New("runtime skip events are forbidden")
	}
	return nil
}

func parseGoTestJSON(
	data []byte,
	required []string,
	requiredPackages map[string]string,
) ([]string, []skipEvent, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxCommandOutputBytes)
	passed := map[string]int{}
	var skips []skipEvent
	for scanner.Scan() {
		var event struct {
			Action  string `json:"Action"`
			Package string `json:"Package"`
			Test    string `json:"Test"`
			Output  string `json:"Output"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, nil, errors.New("go test emitted malformed JSON")
		}
		if event.Action == "pass" && event.Test != "" {
			if requiredPackage, required := requiredPackages[event.Test]; required && requiredPackage != "" &&
				event.Package != requiredPackage {
				return nil, nil, errors.New(
					"selected test passed in an unexpected package",
				)
			}
			passed[event.Package+"\x00"+event.Test]++
		}
		if event.Action == "skip" {
			skips = append(skips, skipEvent{
				Test:   event.Test,
				Reason: strings.TrimSpace(event.Output),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	var observed []string
	for _, id := range required {
		requiredPackage := requiredPackages[id]
		if requiredPackage == "" && len(requiredPackages) != 0 {
			return nil, nil, fmt.Errorf("required test package is missing: %s", id)
		}
		key := requiredPackage + "\x00" + id
		if requiredPackage == "" {
			for observedKey := range passed {
				if strings.HasSuffix(observedKey, "\x00"+id) {
					key = observedKey
					break
				}
			}
		}
		if passed[key] != 1 {
			return observed, skips,
				fmt.Errorf("required test did not produce exactly one PASS event: %s", id)
		}
		observed = append(observed, id)
	}
	if len(skips) != 0 {
		return observed, skips, errors.New("go test reported forbidden skip events")
	}
	return observed, skips, nil
}

func summarizeGoTestFailure(data []byte) goTestFailureSummary {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxCommandOutputBytes)
	testIDs := map[string]struct{}{}
	packageFailed := false
	valid := true
	for scanner.Scan() {
		var event struct {
			Action string `json:"Action"`
			Test   string `json:"Test"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			valid = false
			continue
		}
		if event.Action != "fail" {
			continue
		}
		if event.Test == "" {
			packageFailed = true
			continue
		}
		if strings.Contains(event.Test, "/") {
			continue
		}
		if len(event.Test) > maxGoTestFailureIDBytes || !validGoTestID(event.Test) {
			valid = false
			continue
		}
		testIDs[event.Test] = struct{}{}
	}
	if scanner.Err() != nil {
		valid = false
	}

	ids := make([]string, 0, len(testIDs))
	for id := range testIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	truncated := len(ids) > maxGoTestFailureIDs
	if truncated {
		ids = ids[:maxGoTestFailureIDs]
	}
	classification := "unclassified"
	if valid && len(ids) != 0 {
		classification = "test"
	} else if valid && packageFailed {
		classification = "package"
	}
	if !valid {
		ids = []string{}
	}
	return goTestFailureSummary{
		TopLevelTestIDs: ids,
		Classification:  classification,
		Truncated:       truncated,
	}
}

func parseNestedGoTestJSON(
	data []byte,
	expected goTestEventAttestation,
	marker string,
) (goTestEventAttestation, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxCommandOutputBytes)
	counts := map[string]int{
		"run":  0,
		"pass": 0,
		"fail": 0,
		"skip": 0,
	}
	sawMarker := false
	for scanner.Scan() {
		var event struct {
			Action  string `json:"Action"`
			Package string `json:"Package"`
			Test    string `json:"Test"`
			Output  string `json:"Output"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return goTestEventAttestation{},
				errors.New("nested go test emitted malformed JSON")
		}
		if event.Package != expected.Package || event.Test != expected.TestID {
			continue
		}
		if _, tracked := counts[event.Action]; tracked {
			counts[event.Action]++
		}
		if marker != "" && strings.Contains(event.Output, marker) {
			sawMarker = true
		}
	}
	if err := scanner.Err(); err != nil {
		return goTestEventAttestation{}, err
	}
	if counts["run"] != 1 ||
		counts[expected.TerminalAction] != 1 {
		return goTestEventAttestation{},
			errors.New("nested go test event cardinality mismatch")
	}
	for _, action := range []string{"pass", "fail", "skip"} {
		if action != expected.TerminalAction && counts[action] != 0 {
			return goTestEventAttestation{},
				errors.New("nested go test terminal action mismatch")
		}
	}
	if marker != "" && !sawMarker {
		return goTestEventAttestation{},
			errors.New("mutant output lacks the exact failing test and violation marker")
	}
	return expected, nil
}

func frozenEnvironment(
	config *gateConfig,
	phaseJobs int,
	stage string,
	stageTemp string,
	goDirectory string,
) ([]string, error) {
	allowed := make(map[string]bool, len(config.ChildEnvironment.Allowlist))
	for _, name := range config.ChildEnvironment.Allowlist {
		if name == "" || allowed[name] || secretBearingName(name, config.ChildEnvironment.RejectNameFragments) {
			return nil, errors.New("invalid or secret-bearing child environment allowlist")
		}
		allowed[name] = true
	}
	replacements := map[string]string{
		"${PHASE_JOBS}":           strconv.Itoa(phaseJobs),
		"${FROZEN_SYSTEMROOT}":    os.Getenv("SYSTEMROOT"),
		"${GO_DIR}":               goDirectory,
		"${STAGE_TMPDIR}":         stageTemp,
		"${WORKSPACE_HOME}":       filepath.Join(filepath.Dir(stageTemp), ".phasegates-home"),
		"${STAGE_GOCACHE}":        stageCacheDirectory(filepath.Dir(stageTemp), stage),
		"${WORKSPACE_GOMODCACHE}": filepath.Join(filepath.Dir(stageTemp), ".phasegates-go-mod-cache"),
		"${WORKSPACE_GOPATH}":     filepath.Join(filepath.Dir(stageTemp), ".phasegates-go-path"),
		"${WORKSPACE_XDG_CACHE}":  filepath.Join(filepath.Dir(stageTemp), ".phasegates-xdg-cache"),
		"${WORKSPACE_XDG_CONFIG}": filepath.Join(filepath.Dir(stageTemp), ".phasegates-xdg-config"),
	}
	var environment []string
	for name, value := range config.ChildEnvironment.Required {
		if !allowed[name] || secretBearingName(name, config.ChildEnvironment.RejectNameFragments) {
			return nil, errors.New("unrecognized or secret-bearing child environment key")
		}
		resolved := replaceAll(value, replacements)
		if strings.Contains(resolved, "${") || strings.ContainsRune(resolved, '\x00') {
			return nil, errors.New("unresolved child environment value")
		}
		if privateEnvironmentRoot(name) {
			identity, err := directoryIdentityFor(resolved)
			if err != nil || !pathWithin(filepath.Dir(stageTemp), identity.Path) {
				return nil, errors.New("private child environment root is unavailable or outside the workspace")
			}
		}
		environment = append(environment, name+"="+resolved)
	}
	sort.Strings(environment)
	return environment, nil
}

func privateEnvironmentRoot(name string) bool {
	switch name {
	case "HOME", "GOCACHE", "GOMODCACHE", "GOPATH",
		"XDG_CACHE_HOME", "XDG_CONFIG_HOME":
		return true
	default:
		return false
	}
}

func preparePrivateEnvironmentRoots(
	root string,
	config *gateConfig,
) (func(bool) error, error) {
	names := []string{
		".phasegates-home",
		".phasegates-go-mod-cache",
		".phasegates-go-path",
		".phasegates-xdg-cache",
		".phasegates-xdg-config",
	}
	for stage := range config.Stages {
		names = append(names, filepath.Base(stageCacheDirectory(root, stage)))
	}
	sort.Strings(names)
	rootHandle, err := openEvidenceRootHandle(root)
	if err != nil {
		return nil, fmt.Errorf("open authenticated private workspace root: %w", err)
	}
	created := make([]string, 0, len(names))
	finalize := func(keep bool) error {
		var finalizeErr error
		if !keep {
			for index := len(created) - 1; index >= 0; index-- {
				finalizeErr = errors.Join(
					finalizeErr,
					removeDirectoryAt(rootHandle, created[index]),
				)
			}
		}
		closeErr := rootHandle.Close()
		created = nil
		if keep {
			return nil
		}
		finalizeErr = errors.Join(finalizeErr, closeErr)
		return finalizeErr
	}
	for _, name := range names {
		if err := makeDirectoryAt(rootHandle, name, 0o700); err != nil {
			return nil, errors.Join(
				fmt.Errorf("create private execution workspace %s: %w", name, err),
				finalize(false),
			)
		}
		created = append(created, name)
	}
	return finalize, nil
}

func validateStagePrivateWorkspace(
	identity executionIdentity,
	stage string,
	requireStageCacheEmpty bool,
) error {
	environment, ok := identity.Environment[stage]
	if !ok {
		return errors.New("stage child environment is absent")
	}
	moduleCache, ok := environmentValue(environment, "GOMODCACHE")
	if !ok || !pathWithin(identity.EvidenceRoot.Path, moduleCache) {
		return errors.New("module-cache sentinel is outside the private workspace")
	}
	empty, err := directoryEmpty(moduleCache)
	if err != nil || !empty {
		return errors.Join(err, errors.New("module-cache fallback sentinel is not empty"))
	}
	stageCache, ok := environmentValue(environment, "GOCACHE")
	if !ok || stageCache != stageCacheDirectory(identity.EvidenceRoot.Path, stage) {
		return errors.New("stage build cache is not the exact private cache")
	}
	if requireStageCacheEmpty {
		empty, err := directoryEmpty(stageCache)
		if err != nil || !empty {
			return errors.Join(err, errors.New("stage build cache is not empty before execution"))
		}
	}
	return nil
}

func directoryEmpty(path string) (bool, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	directory, openErr := root.Open(filepath.Base(path))
	closeErr := root.Close()
	if openErr != nil || closeErr != nil {
		if directory != nil {
			_ = directory.Close()
		}
		return false, errors.Join(openErr, closeErr)
	}
	_, readErr := directory.Readdirnames(1)
	directoryCloseErr := directory.Close()
	switch {
	case errors.Is(readErr, io.EOF):
		return true, directoryCloseErr
	case readErr != nil:
		return false, errors.Join(readErr, directoryCloseErr)
	default:
		return false, directoryCloseErr
	}
}

func environmentValue(environment []string, name string) (string, bool) {
	prefix := name + "="
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix), true
		}
	}
	return "", false
}

func validateDistinctStageCaches(environments map[string][]string) error {
	seen := map[string]bool{}
	for stage, environment := range environments {
		cache, ok := environmentValue(environment, "GOCACHE")
		if !ok || cache == "" || seen[cache] ||
			filepath.Base(cache) != ".phasegates-"+stage+"-go-cache" {
			return errors.New("stage build-cache paths are not distinct and canonical")
		}
		seen[cache] = true
	}
	return nil
}

func stageCacheDirectory(evidenceRoot, stage string) string {
	return filepath.Join(evidenceRoot, ".phasegates-"+stage+"-go-cache")
}

func frozenWorkingDirectories(
	config *gateConfig,
	source string,
) ([]string, error) {
	set := map[string]bool{}
	replacements := map[string]string{"${SOURCE}": source}
	for _, stage := range config.Stages {
		for _, command := range stage.Commands {
			if command.CWD == "" {
				continue
			}
			path := replaceAll(command.CWD, replacements)
			identity, err := directoryIdentityFor(path)
			if err != nil {
				return nil, err
			}
			set[identity.Path] = true
		}
	}
	workdirs := make([]string, 0, len(set))
	for path := range set {
		workdirs = append(workdirs, path)
	}
	sort.Strings(workdirs)
	return workdirs, nil
}

func frozenExecutables(
	config *gateConfig,
	runner executableIdentity,
	lookPath func(string) (string, error),
) (map[string]executableIdentity, error) {
	names := map[string]bool{}
	for _, stage := range config.Stages {
		for _, command := range stage.Commands {
			if len(command.Argv) > 0 {
				names[command.Argv[0]] = true
			}
			if command.Kind == "mutation-campaign" {
				names["${GO}"] = true
			}
		}
	}
	for _, lint := range config.LintRuns {
		if len(lint.Argv) > 0 {
			names[lint.Argv[0]] = true
		}
	}
	identities := make(map[string]executableIdentity, len(names))
	for name := range names {
		if name == "${RUNNER}" {
			identities[name] = runner
			continue
		}
		binaryName := executableName(name)
		path, err := lookPath(binaryName)
		if err != nil {
			return nil, fmt.Errorf("resolve executable %s: %w", name, err)
		}
		identity, err := executableFileIdentity(path)
		if err != nil {
			return nil, fmt.Errorf("bind executable %s: %w", name, err)
		}
		if name == "${GO}" {
			if identity.GoBuildVersion != config.GoVersion {
				return nil, errors.New(
					"go executable build version does not match gate config",
				)
			}
			if identity.MainPackagePath != "cmd/go" {
				return nil, errors.New(
					"go executable main package is not cmd/go",
				)
			}
		}
		identities[name] = identity
	}
	return identities, nil
}

func executableName(value string) string {
	switch value {
	case "${GO}":
		return "go"
	case "${GOLANGCI_LINT}":
		return "golangci-lint"
	case "${GITLEAKS}":
		return "gitleaks"
	default:
		return value
	}
}

func commonSourceDirectory(paths ...string) (directoryIdentity, error) {
	var source directoryIdentity
	for _, path := range paths {
		absolute, err := cleanAbsolute(path)
		if err != nil {
			return directoryIdentity{}, err
		}
		candidate := filepath.Dir(absolute)
		for filepath.Base(candidate) != "src" && filepath.Dir(candidate) != candidate {
			candidate = filepath.Dir(candidate)
		}
		if filepath.Base(candidate) != "src" {
			continue
		}
		root := filepath.Dir(candidate)
		identity, err := directoryIdentityFor(root)
		if err != nil {
			return directoryIdentity{}, err
		}
		if source.Path == "" {
			source = identity
		} else if source != identity {
			return directoryIdentity{}, errors.New("identity inputs do not share one source tree")
		}
	}
	if source.Path == "" {
		return directoryIdentity{}, errors.New("cannot derive source tree from identity inputs")
	}
	return source, nil
}

func regularFileIdentity(path string) (fileIdentity, error) {
	absolute, err := cleanAbsolute(path)
	if err != nil {
		return fileIdentity{}, err
	}
	if err := rejectResolvedAlias(absolute); err != nil {
		return fileIdentity{}, err
	}
	before, err := os.Lstat(absolute)
	if err != nil {
		return fileIdentity{}, err
	}
	if !before.Mode().IsRegular() {
		return fileIdentity{}, errors.New("identity path is not a regular file")
	}
	file, err := openParentFile(absolute, os.O_RDONLY, 0)
	if err != nil {
		return fileIdentity{}, err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	after, statErr := file.Stat()
	pathAfter, pathStatErr := os.Lstat(absolute)
	closeErr := file.Close()
	if copyErr != nil || statErr != nil || pathStatErr != nil || closeErr != nil {
		return fileIdentity{}, errors.Join(copyErr, statErr, pathStatErr, closeErr)
	}
	if !pathAfter.Mode().IsRegular() ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathAfter) ||
		before.Size() != after.Size() ||
		before.Mode() != after.Mode() ||
		before.ModTime() != after.ModTime() ||
		after.Size() != pathAfter.Size() ||
		after.Mode() != pathAfter.Mode() ||
		after.ModTime() != pathAfter.ModTime() {
		return fileIdentity{}, errors.New("file identity changed while hashing")
	}
	return fileIdentity{
		Path:            absolute,
		SHA256:          hex.EncodeToString(hash.Sum(nil)),
		Mode:            uint32(after.Mode()),
		Size:            after.Size(),
		ModTimeUnixNano: after.ModTime().UnixNano(),
	}, nil
}

func executableFileIdentity(path string) (executableIdentity, error) {
	file, err := regularFileIdentity(path)
	if err != nil {
		return executableIdentity{}, err
	}
	if file.Mode&0o111 == 0 {
		return executableIdentity{}, errors.New("executable identity has no execute bit")
	}
	info, err := buildinfo.ReadFile(file.Path)
	if err != nil {
		// Non-Go executables are still hash-bound and intentionally have no build metadata.
		//nolint:nilerr
		return executableIdentity{File: file}, nil
	}
	encodedBuildInfo, err := canonicalJSON(info)
	if err != nil {
		return executableIdentity{}, err
	}
	return executableIdentity{
		File:            file,
		GoBuildVersion:  info.GoVersion,
		ModulePath:      info.Main.Path,
		MainPackagePath: info.Path,
		BuildInfoSHA256: sha256Hex(encodedBuildInfo),
	}, nil
}

func directoryIdentityFor(path string) (directoryIdentity, error) {
	absolute, err := cleanAbsolute(path)
	if err != nil {
		return directoryIdentity{}, err
	}
	if err := rejectResolvedAlias(absolute); err != nil {
		return directoryIdentity{}, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return directoryIdentity{}, err
	}
	if !info.IsDir() {
		return directoryIdentity{}, errors.New("identity source is not a directory")
	}
	return directoryIdentity{
		Path:            absolute,
		Mode:            uint32(info.Mode()),
		ModTimeUnixNano: info.ModTime().UnixNano(),
	}, nil
}

func stableDirectoryTreeIdentity(root string) (treeIdentity, error) {
	identity, _, err := stableDirectoryTreeSnapshot(root)
	return identity, err
}

func stableDirectoryTreeSnapshot(
	root string,
) (treeIdentity, []treeEntry, error) {
	before, err := directoryIdentityFor(root)
	if err != nil {
		return treeIdentity{}, nil, err
	}
	first, firstEntries, err := directoryTreeSnapshot(before.Path)
	if err != nil {
		return treeIdentity{}, nil, err
	}
	second, secondEntries, err := directoryTreeSnapshot(before.Path)
	if err != nil {
		return treeIdentity{}, nil, err
	}
	after, err := directoryIdentityFor(before.Path)
	if err != nil {
		return treeIdentity{}, nil, err
	}
	if before != after || first != second || !reflect.DeepEqual(firstEntries, secondEntries) {
		return treeIdentity{}, nil, errors.New("source tree changed while hashing")
	}
	return first, firstEntries, nil
}

func directoryTreeSnapshot(root string) (treeIdentity, []treeEntry, error) {
	hasher := sha256.New()
	var entries []treeEntry
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		record := treeEntry{
			Path: relative,
			Mode: uint32(info.Mode()),
			Size: info.Size(),
		}
		switch {
		case info.IsDir():
			record.Type = "directory"
		case info.Mode().IsRegular():
			record.Type = "regular"
			identity, err := regularFileIdentity(path)
			if err != nil {
				return err
			}
			record.SHA256 = identity.SHA256
		default:
			return fmt.Errorf("unsupported source-tree entry %q", relative)
		}
		encoded, err := canonicalJSON(record)
		if err != nil {
			return err
		}
		if _, err := hasher.Write(encoded); err != nil {
			return err
		}
		entries = append(entries, record)
		return nil
	})
	if err != nil {
		return treeIdentity{}, nil, err
	}
	return treeIdentity{
		SHA256:     hex.EncodeToString(hasher.Sum(nil)),
		EntryCount: len(entries),
	}, entries, nil
}

func validateSourceManifest(
	path string,
	baseline string,
	base string,
	diffSHA256 string,
	sourceTree treeIdentity,
	entries []treeEntry,
) error {
	var manifest sourceManifest
	if err := decodeStrictFile(path, &manifest); err != nil {
		return fmt.Errorf("decode complete source manifest: %w", err)
	}
	if manifest.SchemaVersion != gateSchemaVersion ||
		manifest.Baseline != baseline ||
		manifest.Base != base ||
		manifest.DiffSHA256 != diffSHA256 ||
		manifest.SourceTree != sourceTree ||
		!reflect.DeepEqual(manifest.Entries, entries) {
		return errors.New("complete source manifest does not match baseline, diff, or live tree")
	}
	return nil
}

func validateVendoredSource(source string, entries []treeEntry) error {
	const (
		goModRelative   = "src/go.mod"
		modulesRelative = "src/vendor/modules.txt"
	)
	entryByPath := make(map[string]treeEntry, len(entries))
	for _, entry := range entries {
		entryByPath[entry.Path] = entry
	}
	for _, required := range []string{goModRelative, modulesRelative} {
		entry, ok := entryByPath[required]
		if !ok || entry.Type != "regular" || !validSHA256(entry.SHA256) {
			return errors.New("vendored source is absent from the complete source manifest")
		}
	}
	goMod, err := readBoundedFile(
		filepath.Join(source, filepath.FromSlash(goModRelative)),
	)
	if err != nil {
		return fmt.Errorf("read vendored source go.mod: %w", err)
	}
	requirements, err := parseGoModRequirements(goMod)
	if err != nil {
		return fmt.Errorf("parse vendored source go.mod: %w", err)
	}
	modules, err := readBoundedFile(
		filepath.Join(source, filepath.FromSlash(modulesRelative)),
	)
	if err != nil {
		return fmt.Errorf("read vendor/modules.txt: %w", err)
	}
	type vendoredModule struct {
		version  string
		explicit bool
	}
	vendored := map[string]vendoredModule{}
	current := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(modules), "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# "):
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[0] != "#" ||
				fields[1] == "" || fields[2] == "" ||
				strings.Contains(line, "=>") {
				return errors.New("vendor/modules.txt contains an invalid module header")
			}
			current = fields[1]
			if _, exists := vendored[current]; exists {
				return errors.New("vendor/modules.txt contains a duplicate module")
			}
			vendored[current] = vendoredModule{version: fields[2]}
		case strings.HasPrefix(line, "## explicit"):
			module, ok := vendored[current]
			if !ok || module.explicit {
				return errors.New("vendor/modules.txt contains an invalid explicit marker")
			}
			module.explicit = true
			vendored[current] = module
		case line == "" || strings.HasPrefix(line, "## "):
			continue
		default:
			if current == "" ||
				(line != current && !strings.HasPrefix(line, current+"/")) {
				return errors.New("vendor/modules.txt contains an unbound package path")
			}
			packageEntry := "src/vendor/" + line
			if entry, ok := entryByPath[packageEntry]; !ok || entry.Type != "directory" {
				return errors.New("vendored package is absent from the complete source manifest")
			}
		}
	}
	for path, version := range requirements {
		module, ok := vendored[path]
		if !ok || !module.explicit || module.version != version {
			return errors.New("vendor/modules.txt does not match an explicit go.mod requirement")
		}
	}
	if len(requirements) == 0 || len(vendored) == 0 {
		return errors.New("vendored source contains no dependency inventory")
	}
	return nil
}

func parseGoModRequirements(data []byte) (map[string]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxCommandOutputBytes)
	requirements := map[string]string{}
	inRequireBlock := false
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "//")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			if err := addGoModRequirement(requirements, strings.Fields(line)); err != nil {
				return nil, err
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "require" && fields[1] == "(" {
			inRequireBlock = true
			continue
		}
		if len(fields) > 0 && fields[0] == "require" {
			if err := addGoModRequirement(requirements, fields[1:]); err != nil {
				return nil, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if inRequireBlock {
		return nil, errors.New("unterminated go.mod require block")
	}
	return requirements, nil
}

func addGoModRequirement(requirements map[string]string, fields []string) error {
	if len(fields) != 2 || fields[0] == "" || fields[1] == "" ||
		strings.ContainsAny(fields[0], `"'`) ||
		!strings.HasPrefix(fields[1], "v") {
		return errors.New("invalid go.mod requirement")
	}
	if _, exists := requirements[fields[0]]; exists {
		return errors.New("duplicate go.mod requirement")
	}
	requirements[fields[0]] = fields[1]
	return nil
}

func pathWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil &&
		relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func rejectResolvedAlias(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return err
	}
	if filepath.Clean(resolved) != filepath.Clean(path) {
		return errors.New("identity path contains a symlink or alias")
	}
	return nil
}

func cleanAbsolute(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

func writeExclusiveCanonical(
	path string,
	value any,
	syncDirectory func(*os.File) error,
) (string, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	absolute, err := cleanAbsolute(path)
	if err != nil {
		return "", err
	}
	parentPath := filepath.Dir(absolute)
	parent, err := openEvidenceRootHandle(parentPath)
	if err != nil {
		return "", fmt.Errorf("open authenticated identity directory: %w", err)
	}
	if err := sameOpenDirectory(parent, parentPath); err != nil {
		return "", errors.Join(err, parent.Close())
	}
	file, err := createEvidenceFileAt(parent, filepath.Base(absolute))
	if err != nil {
		return "", errors.Join(err, parent.Close())
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	chmodErr := file.Chmod(executionIdentityMode)
	secondSyncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || chmodErr != nil ||
		secondSyncErr != nil || closeErr != nil {
		return "", errors.Join(
			writeErr,
			syncErr,
			chmodErr,
			secondSyncErr,
			closeErr,
			parent.Close(),
		)
	}
	if err := syncDirectory(parent); err != nil {
		return "", errors.Join(
			fmt.Errorf("sync execution identity directory: %w", err),
			parent.Close(),
		)
	}
	if err := parent.Close(); err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

func finishEvidence(
	file *os.File,
	root *os.File,
	name string,
	evidence stageEvidence,
	syncDirectory func(*os.File) error,
) (string, error) {
	if file == nil {
		return "", nil
	}
	data, err := canonicalJSON(evidence)
	if err != nil {
		return "", err
	}
	expectedSHA256 := sha256Hex(data)
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	chmodErr := file.Chmod(evidenceMode)
	secondSyncErr := file.Sync()
	pathErr := sameOpenRegularFileAt(file, root, name)
	openInfo, statErr := file.Stat()
	closeErr := file.Close()
	reopenErr := verifyClosedEvidenceAt(root, name, openInfo, expectedSHA256)
	err = errors.Join(
		writeErr,
		syncErr,
		chmodErr,
		secondSyncErr,
		pathErr,
		statErr,
		closeErr,
		reopenErr,
	)
	if err != nil {
		return "", err
	}
	if err := syncDirectory(root); err != nil {
		return "", fmt.Errorf("sync terminal evidence directory: %w", err)
	}
	return expectedSHA256, nil
}

func publishEvidenceProofAt(
	root *os.File,
	evidenceName string,
	suffix string,
	evidenceSHA256 string,
	syncDirectory func(*os.File) error,
) error {
	if suffix == "" || strings.ContainsAny(suffix, `/\\`) ||
		!validSHA256(evidenceSHA256) {
		return errors.New("invalid evidence publication proof contract")
	}
	finalName := evidenceName + suffix
	pendingName := "." + finalName + ".pending"
	proof := evidencePublicationProof{
		SchemaVersion:  gateSchemaVersion,
		EvidenceSHA256: evidenceSHA256,
	}
	data, err := canonicalJSON(proof)
	if err != nil {
		return err
	}
	file, err := createEvidenceFileAt(root, pendingName)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	chmodErr := file.Chmod(evidenceMode)
	secondSyncErr := file.Sync()
	info, statErr := file.Stat()
	closeErr := file.Close()
	verifyErr := verifyClosedEvidenceAt(
		root,
		pendingName,
		info,
		sha256Hex(data),
	)
	if err := errors.Join(
		writeErr,
		syncErr,
		chmodErr,
		secondSyncErr,
		statErr,
		closeErr,
		verifyErr,
	); err != nil {
		return err
	}
	if err := linkPublicationProofAt(root, pendingName, finalName); err != nil {
		return err
	}
	if err := syncDirectory(root); err != nil {
		return fmt.Errorf("sync publication proof directory: %w", err)
	}
	return nil
}

func verifyEvidencePublicationProofAt(
	root *os.File,
	evidenceName string,
	suffix string,
) error {
	evidence, err := openReadFileAt(root, evidenceName)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, hashErr := io.Copy(hash, evidence)
	evidenceCloseErr := evidence.Close()
	if hashErr != nil || evidenceCloseErr != nil {
		return errors.Join(hashErr, evidenceCloseErr)
	}
	proofFile, err := openReadFileAt(root, evidenceName+suffix)
	if err != nil {
		return err
	}
	proofInfo, statErr := proofFile.Stat()
	proofData, readErr := io.ReadAll(io.LimitReader(proofFile, maxCommandOutputBytes+1))
	proofCloseErr := proofFile.Close()
	if statErr != nil || !proofInfo.Mode().IsRegular() ||
		proofInfo.Mode().Perm() != evidenceMode ||
		readErr != nil || proofCloseErr != nil ||
		len(proofData) > maxCommandOutputBytes {
		return errors.Join(
			statErr,
			readErr,
			proofCloseErr,
			errors.New("invalid publication proof file"),
		)
	}
	var proof evidencePublicationProof
	decoder := json.NewDecoder(bytes.NewReader(proofData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("publication proof contains trailing JSON values")
	}
	if proof.SchemaVersion != gateSchemaVersion ||
		proof.EvidenceSHA256 != hex.EncodeToString(hash.Sum(nil)) {
		return errors.New("publication proof does not bind the evidence bytes")
	}
	canonical, err := canonicalJSON(proof)
	if err != nil || !bytes.Equal(proofData, canonical) {
		return errors.New("publication proof is not canonical")
	}
	return nil
}

func sameOpenRegularFileAt(
	file *os.File,
	root *os.File,
	name string,
) error {
	openInfo, err := file.Stat()
	if err != nil {
		return err
	}
	pathFile, err := openReadFileAt(root, name)
	if err != nil {
		return err
	}
	pathInfo, statErr := pathFile.Stat()
	closeErr := pathFile.Close()
	if statErr != nil || closeErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if !openInfo.Mode().IsRegular() ||
		!pathInfo.Mode().IsRegular() ||
		!os.SameFile(openInfo, pathInfo) {
		return errors.New("evidence path no longer names the reserved file")
	}
	if links, supported := fileLinkCount(openInfo); supported && links != 1 {
		return errors.New("reserved evidence file link count is not one")
	}
	return nil
}

func verifyClosedEvidenceAt(
	root *os.File,
	name string,
	reservedInfo os.FileInfo,
	expectedSHA256 string,
) error {
	if reservedInfo == nil {
		return errors.New("reserved evidence identity is unavailable")
	}
	pathFile, err := openReadFileAt(root, name)
	if err != nil {
		return err
	}
	defer pathFile.Close()
	pathInfo, err := pathFile.Stat()
	if err != nil {
		return err
	}
	if !pathInfo.Mode().IsRegular() || !os.SameFile(reservedInfo, pathInfo) {
		return errors.New("closed evidence path identity mismatch")
	}
	if links, supported := fileLinkCount(pathInfo); supported && links != 1 {
		return errors.New("closed evidence file link count is not one")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, pathFile); err != nil ||
		hex.EncodeToString(hash.Sum(nil)) != expectedSHA256 ||
		pathInfo.Mode().Perm() != evidenceMode {
		return errors.New("closed evidence content or mode mismatch")
	}
	return nil
}

func sameOpenDirectory(root *os.File, path string) error {
	openInfo, err := root.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !openInfo.IsDir() || !pathInfo.IsDir() || !os.SameFile(openInfo, pathInfo) {
		return errors.New("evidence root path no longer names the authenticated directory")
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func decodeStrictFile(path string, value any) error {
	data, err := readBoundedFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("json contains trailing values")
	}
	return nil
}

func readBoundedFile(path string) ([]byte, error) {
	file, err := openParentFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxCommandOutputBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > maxCommandOutputBytes {
		return nil, errors.Join(
			readErr,
			closeErr,
			errors.New("file exceeds the input limit"),
		)
	}
	return data, nil
}

func openParentFile(
	path string,
	flag int,
	perm os.FileMode,
) (*os.File, error) {
	absolute, err := cleanAbsolute(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	file, openErr := root.OpenFile(filepath.Base(absolute), flag, perm)
	closeErr := root.Close()
	if openErr != nil || closeErr != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, errors.Join(openErr, closeErr)
	}
	return file, nil
}

func currentHostFacts() (hostFacts, error) {
	online := runtime.NumCPU()
	if online < 1 {
		return hostFacts{}, errors.New("runtime reported an invalid online CPU count")
	}
	model := runtime.GOARCH
	source := "runtime.GOARCH"
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if name, value, ok := strings.Cut(line, ":"); ok &&
					strings.TrimSpace(name) == "model name" &&
					strings.TrimSpace(value) != "" {
					model = strings.TrimSpace(value)
					source = "/proc/cpuinfo:model name"
					break
				}
			}
		}
	}
	return hostFacts{
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		CPUModel:       model,
		CPUModelSource: source,
		OnlineSource:   "runtime.NumCPU",
		Online:         online,
	}, nil
}

func derivedPhaseJobs(online int) int {
	jobs := online / 2
	if jobs > 10 {
		return 10
	}
	return jobs
}

func cpuFactsForOnline(online int) (cpuFacts, error) {
	if online < 2 {
		return cpuFacts{}, errors.New("online CPU count is below the gate minimum")
	}
	return cpuFacts{
		Online:       online,
		PhaseJobs:    derivedPhaseJobs(online),
		OnlineSource: "runtime.NumCPU",
	}, nil
}

func stageReplacements(
	options stageOptions,
	identity executionIdentity,
) map[string]string {
	replacements := map[string]string{
		"${SOURCE}":          identity.Source.Path,
		"${SOURCE_MANIFEST}": identity.SourceManifest.Path,
		"${MUTATIONS}":       identity.Mutations.Path,
		"${PHASE_JOBS}":      strconv.Itoa(identity.PhaseJobs),
		"${STAGE_TMPDIR}":    stageTempDirectory(identity.EvidenceRoot.Path, options.Stage),
		"${STAGE}":           options.Stage,
	}
	for name, executable := range identity.Executables {
		replacements[name] = executable.File.Path
	}
	return replacements
}

func stageTempDirectory(evidenceRoot, stage string) string {
	return filepath.Join(evidenceRoot, ".phasegates-"+stage+"-tmp")
}

func requiredIDsForStage(stage string, config *gateConfig) []string {
	switch stage {
	case "mutation":
		return append([]string(nil), config.RequiredMutationIDs...)
	case "host":
		return expectedThreatsForStage(config, stage)
	default:
		return nil
	}
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
	err    error
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	if buffer.err != nil {
		return 0, buffer.err
	}
	remaining := buffer.limit - buffer.buffer.Len()
	if len(value) > remaining {
		if remaining > 0 {
			_, _ = buffer.buffer.Write(value[:remaining])
		}
		buffer.err = errOutputLimit
		return len(value), nil
	}
	return buffer.buffer.Write(value)
}

func (buffer *limitedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func validOID(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func safeFailure(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded"
	case errors.Is(err, context.Canceled):
		return "execution canceled"
	case errors.Is(err, errOutputLimit):
		return errOutputLimit.Error()
	default:
		return err.Error()
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func replaceSlice(values []string, replacements map[string]string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = replaceAll(value, replacements)
	}
	return result
}

func replaceAll(value string, replacements map[string]string) string {
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value = strings.ReplaceAll(value, key, replacements[key])
	}
	return value
}

func secretBearingName(name string, fragments []string) bool {
	upper := strings.ToUpper(name)
	for _, fragment := range fragments {
		if strings.Contains(upper, strings.ToUpper(fragment)) {
			return true
		}
	}
	return false
}

func executableSettingsHash(value executableIdentity) string {
	return value.BuildInfoSHA256
}

func sameFileIdentity(left, right fileIdentity) bool {
	return left == right
}

func sameExecutableIdentity(left, right executableIdentity) bool {
	return sameFileIdentity(left.File, right.File) &&
		left.GoBuildVersion == right.GoBuildVersion &&
		left.ModulePath == right.ModulePath &&
		left.MainPackagePath == right.MainPackagePath &&
		executableSettingsHash(left) == executableSettingsHash(right)
}

func executableBelongsToModule(executable executableIdentity, module string) bool {
	return executable.ModulePath == module ||
		strings.HasPrefix(executable.ModulePath, module+"/")
}

func mustFileIdentity(path string) fileIdentity {
	identity, _ := regularFileIdentity(path)
	return identity
}

func equalStrings(left, right []string) bool {
	return slicesEqual(left, right)
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameStringSet(left, right []string) bool {
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return equalStrings(leftCopy, rightCopy)
}

func hasDuplicates(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func lintByID(values []lintRun, id string) (lintRun, bool) {
	for _, value := range values {
		if value.ID == id {
			return value, true
		}
	}
	return lintRun{}, false
}

func parallelismValue(value any) (int, error) {
	switch typed := value.(type) {
	case float64:
		return int(typed), nil
	case string:
		if typed == "${PHASE_JOBS}" {
			return 1, nil
		}
		return strconv.Atoi(typed)
	default:
		return 0, errors.New("unsupported package parallelism")
	}
}

func commandEvidenceFor(command commandConfig) commandEvidence {
	parallelism, err := parallelismValue(command.PackageParallelism)
	if err != nil {
		parallelism = 0
	}
	surface := command.ExecutionSurface
	surface.PackagePaths = nonNilStrings(surface.PackagePaths)
	surface.BuildTags = nonNilStrings(surface.BuildTags)
	packages := make(map[string]string, len(command.RequiredTestPackages))
	for testID, packagePath := range command.RequiredTestPackages {
		packages[testID] = packagePath
	}
	return commandEvidence{
		Kind:                 command.Kind,
		ExecutionSurface:     surface,
		TimeoutSeconds:       command.TimeoutSeconds,
		GoBased:              command.GoBased,
		MemoryHard:           command.MemoryHard,
		PackageParallelism:   parallelism,
		RequiredExitCode:     command.RequiredExitCode,
		RequiredTestIDs:      nonNilStrings(command.RequiredTestIDs),
		RequiredTestPackages: packages,
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string(nil), values...)
}
