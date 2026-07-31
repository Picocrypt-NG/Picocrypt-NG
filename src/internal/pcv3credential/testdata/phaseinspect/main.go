package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	inspectorSchemaVersion = 1
	maxInspectorInputBytes = 64 << 20
	maxExecutableBytes     = 256 << 20
	executionIdentityMode  = 0o444
	evidenceMode           = 0o400
	picocryptModulePath    = "Picocrypt-NG"
	pcv3PackagePath        = "Picocrypt-NG/internal/pcv3credential"
)

var (
	phase2Baseline             string
	phase2Base                 string
	phase2SourceManifestSHA256 string
)

type inspectorOptions struct {
	config                  string
	baseline                string
	base                    string
	sourceManifest          string
	spec                    string
	executionIdentity       string
	executionIdentitySHA256 string
	diff                    string
	evidenceDir             string
}

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

type threatClosure struct {
	ID                  string   `json:"id"`
	Stage               string   `json:"stage"`
	CommandID           string   `json:"command_id"`
	RequiredObservedIDs []string `json:"required_observed_ids"`
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
	ID                    string            `json:"id"`
	Kind                  string            `json:"kind"`
	ExecutionSurface      executionSurface  `json:"execution_surface"`
	Argv                  []string          `json:"argv,omitempty"`
	CWD                   string            `json:"cwd,omitempty"`
	TimeoutSeconds        int               `json:"timeout_seconds,omitempty"`
	GoBased               bool              `json:"go_based,omitempty"`
	MemoryHard            bool              `json:"memory_hard,omitempty"`
	PackageParallelism    any               `json:"package_parallelism,omitempty"`
	RequiredIDsSource     string            `json:"required_ids_source,omitempty"`
	RequiredExitCode      int               `json:"required_exit_code,omitempty"`
	RequiredTestIDs       []string          `json:"required_test_ids,omitempty"`
	RequiredTestPackages  map[string]string `json:"required_test_packages,omitempty"`
	LintRun               string            `json:"lint_run,omitempty"`
	RequiredCount         int               `json:"required_count,omitempty"`
	RequiredOutputMarker  string            `json:"required_output_marker,omitempty"`
	ForbiddenOutputMarker string            `json:"forbidden_output_marker,omitempty"`
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
	trimpath        bool
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

type skipEvent struct {
	Test   string `json:"test"`
	Reason string `json:"reason"`
}

type mutationManifest struct {
	SchemaVersion   int                `json:"schema_version"`
	SpecSHA256      string             `json:"spec_sha256"`
	SourceSetSHA256 string             `json:"source_set_sha256"`
	ArgvTemplate    []string           `json:"argv_template"`
	Mutations       []campaignMutation `json:"mutations"`
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

type evidencePublicationProof struct {
	SchemaVersion  int    `json:"schema_version"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type inspectorVerdict struct {
	SchemaVersion             int                `json:"schema_version"`
	Status                    string             `json:"status"`
	Baseline                  string             `json:"baseline"`
	Base                      string             `json:"base"`
	ConfigSHA256              string             `json:"config_sha256"`
	SourceManifestSHA256      string             `json:"source_manifest_sha256"`
	SpecSHA256                string             `json:"spec_sha256"`
	ExecutionIdentitySHA256   string             `json:"execution_identity_sha256"`
	DiffSHA256                string             `json:"diff_sha256"`
	Inspector                 verdictExecutable  `json:"inspector"`
	Stages                    []verdictStage     `json:"stages"`
	RequiredExecutionSurfaces []executionSurface `json:"required_execution_surfaces"`
	ObservedExecutionSurfaces []executionSurface `json:"observed_execution_surfaces"`
	Skip                      verdictSkip        `json:"skip"`
	ThreatClosure             []string           `json:"threat_closure"`
}

type verdictExecutable struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	GoBuildVersion string `json:"go_build_version"`
}

type verdictStage struct {
	Stage          string `json:"stage"`
	EvidenceName   string `json:"evidence_name"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	ProofName      string `json:"proof_name"`
	ProofSHA256    string `json:"proof_sha256"`
}

type verdictSkip struct {
	ObservedCardinality int `json:"observed_cardinality"`
}

type inspectedStage struct {
	verdict  verdictStage
	evidence stageEvidence
}

type sessionFileState struct {
	identity fileIdentity
	info     os.FileInfo
	links    uint64
	limit    int64
}

type sessionDirectoryState struct {
	path  string
	info  os.FileInfo
	links uint64
}

type sessionRoot struct {
	path string
	root *os.Root
	info os.FileInfo
}

type inspectionSession struct {
	roots       map[string]*sessionRoot
	files       map[string]sessionFileState
	directories map[string]sessionDirectoryState
	namespaces  map[string][]string
	components  map[string]os.FileInfo
	closed      bool
}

func newInspectionSession() *inspectionSession {
	return &inspectionSession{
		roots:       map[string]*sessionRoot{},
		files:       map[string]sessionFileState{},
		directories: map[string]sessionDirectoryState{},
		namespaces:  map[string][]string{},
		components:  map[string]os.FileInfo{},
	}
}

func (session *inspectionSession) close() error {
	if session == nil || session.closed {
		return nil
	}
	session.closed = true
	paths := make([]string, 0, len(session.roots))
	for path := range session.roots {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var closeErrors []error
	for _, path := range paths {
		root := session.roots[path]
		if root != nil && root.root != nil {
			if err := root.root.Close(); err != nil {
				closeErrors = append(
					closeErrors,
					fmt.Errorf("close inspection root %s: %w", path, err),
				)
			}
		}
	}
	return errors.Join(closeErrors...)
}

func (session *inspectionSession) readBoundedFile(
	path string,
	limit int64,
) ([]byte, fileIdentity, error) {
	data, state, err := session.captureFile(path, limit, true, nil)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if err := session.rememberFile(state); err != nil {
		return nil, fileIdentity{}, err
	}
	return data, state.identity, nil
}

func (session *inspectionSession) executableIdentity(
	path string,
) (executableIdentity, error) {
	var info *buildinfo.BuildInfo
	var buildInfoErr error
	_, state, err := session.captureFile(
		path,
		maxExecutableBytes,
		true,
		func(file *os.File) {
			info, buildInfoErr = buildinfo.Read(file)
		},
	)
	if err != nil {
		return executableIdentity{}, err
	}
	if err := session.rememberFile(state); err != nil {
		return executableIdentity{}, err
	}
	if state.identity.Mode&0o111 == 0 {
		return executableIdentity{}, errors.New(
			"executable identity has no execute bit",
		)
	}
	if buildInfoErr != nil {
		// Non-Go executables are still hash-bound and intentionally have no build metadata.
		//nolint:nilerr
		return executableIdentity{File: state.identity}, nil
	}
	encoded, err := canonicalJSON(info)
	if err != nil {
		return executableIdentity{}, err
	}
	return executableIdentity{
		File:            state.identity,
		GoBuildVersion:  info.GoVersion,
		ModulePath:      info.Main.Path,
		MainPackagePath: info.Path,
		BuildInfoSHA256: sha256Hex(encoded),
		trimpath:        hasExactBuildSetting(info, "-trimpath", "true"),
	}, nil
}

func hasExactBuildSetting(
	info *buildinfo.BuildInfo,
	key string,
	value string,
) bool {
	matches := 0
	for _, setting := range info.Settings {
		if setting.Key != key {
			continue
		}
		matches++
		if setting.Value != value {
			return false
		}
	}
	return matches == 1
}

func (session *inspectionSession) rememberFile(
	state sessionFileState,
) error {
	if previous, exists := session.files[state.identity.Path]; exists {
		if !sameSessionFileState(previous, state) {
			return errors.New(
				"inspection input changed between authenticated reads",
			)
		}
	} else {
		session.files[state.identity.Path] = state
	}
	return nil
}

func (session *inspectionSession) fileHasSingleLink(
	identity fileIdentity,
) bool {
	state, ok := session.files[identity.Path]
	return ok &&
		sameFileIdentity(state.identity, identity) &&
		state.links == 1
}

func (session *inspectionSession) readDirectoryNames(
	path string,
) ([]string, error) {
	state, names, err := session.captureDirectory(path, true, true)
	if err != nil {
		return nil, err
	}
	if previous, exists := session.directories[state.path]; exists {
		if !sameSessionDirectoryState(previous, state) {
			return nil, errors.New(
				"inspection directory changed between authenticated reads",
			)
		}
	} else {
		session.directories[state.path] = state
	}
	if previous, exists := session.namespaces[state.path]; exists {
		if !equalStrings(previous, names) {
			return nil, errors.New(
				"inspection namespace changed between authenticated reads",
			)
		}
	} else {
		session.namespaces[state.path] = append([]string{}, names...)
	}
	return names, nil
}

func (session *inspectionSession) directoryIdentity(
	path string,
) (directoryIdentity, error) {
	state, _, err := session.captureDirectory(path, false, true)
	if err != nil {
		return directoryIdentity{}, err
	}
	if previous, exists := session.directories[state.path]; exists {
		if !sameSessionDirectoryState(previous, state) {
			return directoryIdentity{}, errors.New(
				"inspection directory changed between authenticated reads",
			)
		}
	} else {
		session.directories[state.path] = state
	}
	return directoryIdentity{
		Path:            state.path,
		Mode:            uint32(state.info.Mode()),
		ModTimeUnixNano: state.info.ModTime().UnixNano(),
	}, nil
}

func (session *inspectionSession) verify() error {
	if session == nil || session.closed {
		return errors.New("inspection session is not open")
	}
	for path, before := range session.components {
		after, err := os.Lstat(path)
		if err != nil ||
			!after.IsDir() ||
			after.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(before, after) {
			return fmt.Errorf("inspection path component changed: %s", path)
		}
	}
	for path, before := range session.files {
		_, after, err := session.captureFile(
			path,
			before.limit,
			false,
			nil,
		)
		if err != nil || !sameSessionFileState(before, after) {
			return fmt.Errorf("inspection input changed: %s", path)
		}
	}
	for path, before := range session.directories {
		_, trackNamespace := session.namespaces[path]
		after, names, err := session.captureDirectory(
			path,
			trackNamespace,
			false,
		)
		if err != nil || !sameSessionDirectoryState(before, after) {
			if trackNamespace &&
				!equalStrings(session.namespaces[path], names) {
				return fmt.Errorf("inspection namespace changed: %s", path)
			}
			return fmt.Errorf("inspection directory changed: %s", path)
		}
		if trackNamespace && !equalStrings(session.namespaces[path], names) {
			return fmt.Errorf("inspection namespace changed: %s", path)
		}
	}
	for path, before := range session.roots {
		external, externalErr := os.Lstat(path)
		rooted, rootedErr := before.root.Stat(".")
		if externalErr != nil ||
			rootedErr != nil ||
			!external.IsDir() ||
			external.Mode()&os.ModeSymlink != 0 ||
			!rooted.IsDir() ||
			!sameStableInputInfo(before.info, external) ||
			!sameStableInputInfo(before.info, rooted) {
			return fmt.Errorf("inspection root changed: %s", path)
		}
	}
	return nil
}

func (session *inspectionSession) captureFile(
	path string,
	limit int64,
	trackComponents bool,
	inspectOpenFile func(*os.File),
) ([]byte, sessionFileState, error) {
	cleaned, err := session.cleanPath(path, trackComponents)
	if err != nil {
		return nil, sessionFileState{}, err
	}
	parent, err := session.rootForDirectory(
		filepath.Dir(cleaned),
		trackComponents,
	)
	if err != nil {
		return nil, sessionFileState{}, err
	}
	name := filepath.Base(cleaned)
	before, err := parent.root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 {
		return nil, sessionFileState{}, errors.New(
			"input is not a regular non-symlink file",
		)
	}
	file, err := parent.root.Open(name)
	if err != nil {
		return nil, sessionFileState{}, err
	}
	openInfo, statErr := file.Stat()
	if statErr != nil ||
		!openInfo.Mode().IsRegular() ||
		!sameStableInputInfo(before, openInfo) {
		_ = file.Close()
		return nil, sessionFileState{}, errors.New(
			"input file identity changed while opening",
		)
	}
	if limit >= 0 && openInfo.Size() > limit {
		closeErr := file.Close()
		return nil, sessionFileState{}, errors.Join(
			errors.New("input exceeds the bounded reader limit"),
			closeErr,
		)
	}
	if inspectOpenFile != nil {
		inspectOpenFile(file)
	}
	reader := io.Reader(file)
	if limit >= 0 {
		reader = io.LimitReader(file, limit+1)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := file.Close()
	after, afterErr := parent.root.Lstat(name)
	external, externalErr := os.Lstat(cleaned)
	if readErr != nil || closeErr != nil ||
		afterErr != nil || externalErr != nil {
		return nil, sessionFileState{}, errors.Join(
			readErr,
			closeErr,
			afterErr,
			externalErr,
		)
	}
	if limit >= 0 && int64(len(data)) > limit {
		return nil, sessionFileState{}, errors.New(
			"input exceeds the bounded reader limit",
		)
	}
	if !after.Mode().IsRegular() ||
		after.Mode()&os.ModeSymlink != 0 ||
		!sameStableInputInfo(openInfo, after) ||
		!sameStableInputInfo(after, external) {
		return nil, sessionFileState{}, errors.New(
			"input file identity changed while reading",
		)
	}
	links, ok := stableLinkCount(after)
	if !ok {
		return nil, sessionFileState{}, errors.New(
			"input file link count is unavailable",
		)
	}
	return data, sessionFileState{
		identity: fileIdentity{
			Path:            cleaned,
			SHA256:          sha256Hex(data),
			Mode:            uint32(after.Mode()),
			Size:            after.Size(),
			ModTimeUnixNano: after.ModTime().UnixNano(),
		},
		info:  after,
		links: links,
		limit: limit,
	}, nil
}

func (session *inspectionSession) captureDirectory(
	path string,
	readNames bool,
	trackComponents bool,
) (sessionDirectoryState, []string, error) {
	cleaned, err := session.cleanPath(path, trackComponents)
	if err != nil {
		return sessionDirectoryState{}, nil, err
	}
	bound, err := session.rootForDirectory(cleaned, trackComponents)
	if err != nil {
		return sessionDirectoryState{}, nil, err
	}
	before, err := bound.root.Stat(".")
	if err != nil {
		return sessionDirectoryState{}, nil, err
	}
	directory, err := bound.root.Open(".")
	if err != nil {
		return sessionDirectoryState{}, nil, err
	}
	openInfo, statErr := directory.Stat()
	var entries []os.DirEntry
	var readErr error
	if statErr == nil && readNames {
		entries, readErr = directory.ReadDir(-1)
	}
	closeErr := directory.Close()
	after, afterErr := bound.root.Stat(".")
	external, externalErr := os.Lstat(cleaned)
	if statErr != nil || readErr != nil || closeErr != nil ||
		afterErr != nil || externalErr != nil {
		return sessionDirectoryState{}, nil, errors.Join(
			statErr,
			readErr,
			closeErr,
			afterErr,
			externalErr,
		)
	}
	if !openInfo.IsDir() ||
		!after.IsDir() ||
		after.Mode()&os.ModeSymlink != 0 ||
		!sameStableInputInfo(before, openInfo) ||
		!sameStableInputInfo(openInfo, after) ||
		!sameStableInputInfo(after, external) {
		return sessionDirectoryState{}, nil, errors.New(
			"directory identity changed while reading",
		)
	}
	links, ok := stableLinkCount(after)
	if !ok {
		return sessionDirectoryState{}, nil, errors.New(
			"directory link count is unavailable",
		)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	return sessionDirectoryState{
		path:  cleaned,
		info:  after,
		links: links,
	}, names, nil
}

func (session *inspectionSession) rootForDirectory(
	path string,
	trackComponents bool,
) (*sessionRoot, error) {
	if session == nil || session.closed {
		return nil, errors.New("inspection session is not open")
	}
	cleaned, err := session.cleanPath(path, trackComponents)
	if err != nil {
		return nil, err
	}
	if previous, exists := session.roots[cleaned]; exists {
		if !trackComponents {
			return previous, nil
		}
		external, externalErr := os.Lstat(cleaned)
		rooted, rootedErr := previous.root.Stat(".")
		if externalErr != nil ||
			rootedErr != nil ||
			!external.IsDir() ||
			external.Mode()&os.ModeSymlink != 0 ||
			!rooted.IsDir() ||
			!sameStableInputInfo(previous.info, external) ||
			!sameStableInputInfo(previous.info, rooted) {
			return nil, errors.New(
				"inspection root changed between authenticated reads",
			)
		}
		return previous, nil
	}
	before, err := os.Lstat(cleaned)
	if err != nil || !before.IsDir() ||
		before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New(
			"input is not a non-symlink directory",
		)
	}
	root, err := os.OpenRoot(cleaned)
	if err != nil {
		return nil, err
	}
	rooted, rootedErr := root.Stat(".")
	after, afterErr := os.Lstat(cleaned)
	if rootedErr != nil ||
		afterErr != nil ||
		!rooted.IsDir() ||
		!after.IsDir() ||
		after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, rooted) ||
		!os.SameFile(rooted, after) {
		_ = root.Close()
		return nil, errors.New(
			"input directory changed while opening inspection root",
		)
	}
	bound := &sessionRoot{
		path: cleaned,
		root: root,
		info: after,
	}
	session.roots[cleaned] = bound
	return bound, nil
}

func (session *inspectionSession) cleanPath(
	path string,
	trackComponents bool,
) (string, error) {
	cleaned, err := cleanAbsoluteNoSymlink(path)
	if err != nil {
		return "", err
	}
	if !trackComponents {
		return cleaned, nil
	}
	parent := filepath.Dir(cleaned)
	current := string(os.PathSeparator)
	for _, component := range strings.Split(
		strings.TrimPrefix(parent, string(os.PathSeparator)),
		string(os.PathSeparator),
	) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New(
				"input path ancestor is not a non-symlink directory",
			)
		}
		if previous, exists := session.components[current]; exists {
			if !os.SameFile(previous, info) {
				return "", errors.New(
					"inspection path component changed while opening",
				)
			}
		} else {
			session.components[current] = info
		}
	}
	return cleaned, nil
}

func sameSessionFileState(
	left sessionFileState,
	right sessionFileState,
) bool {
	return sameFileIdentity(left.identity, right.identity) &&
		left.links == right.links &&
		os.SameFile(left.info, right.info)
}

func sameSessionDirectoryState(
	left sessionDirectoryState,
	right sessionDirectoryState,
) bool {
	return left.path == right.path &&
		uint32(left.info.Mode()) == uint32(right.info.Mode()) &&
		left.info.Size() == right.info.Size() &&
		left.info.ModTime().UnixNano() == right.info.ModTime().UnixNano() &&
		left.links == right.links &&
		os.SameFile(left.info, right.info)
}

func sameStableInputInfo(left os.FileInfo, right os.FileInfo) bool {
	leftLinks, leftOK := stableLinkCount(left)
	rightLinks, rightOK := stableLinkCount(right)
	return leftOK &&
		rightOK &&
		leftLinks == rightLinks &&
		uint32(left.Mode()) == uint32(right.Mode()) &&
		left.Size() == right.Size() &&
		left.ModTime().UnixNano() == right.ModTime().UnixNano() &&
		os.SameFile(left, right)
}

func stableLinkCount(info os.FileInfo) (uint64, bool) {
	if info == nil || info.Sys() == nil {
		return 0, false
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, false
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		return field.Uint(), true
	default:
		return 0, false
	}
}

func observedExecutionSurfaces(
	inspected []inspectedStage,
) []executionSurface {
	var surfaces []executionSurface
	for _, stage := range inspected {
		for _, command := range stage.evidence.Commands {
			surface := command.Contract.ExecutionSurface
			surface.PackagePaths = append([]string{}, surface.PackagePaths...)
			surface.BuildTags = append([]string{}, surface.BuildTags...)
			surfaces = append(surfaces, surface)
		}
	}
	return surfaces
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	options, err := parseOptions(args)
	if err != nil {
		return err
	}
	verdict, err := inspect(options)
	if err != nil {
		return err
	}
	data, err := canonicalJSON(verdict)
	if err != nil {
		return fmt.Errorf("encode inspector verdict: %w", err)
	}
	_, err = stdout.Write(data)
	return err
}

func parseOptions(args []string) (inspectorOptions, error) {
	names := []string{
		"--config",
		"--baseline",
		"--base",
		"--source-manifest",
		"--spec",
		"--execution-identity",
		"--execution-identity-sha256",
		"--diff",
		"--evidence-dir",
	}
	if len(args) != len(names)*2 {
		return inspectorOptions{}, errors.New(
			"phaseinspect requires exactly nine flag/value pairs",
		)
	}
	values := make(map[string]string, len(names))
	for index, name := range names {
		if args[index*2] != name || args[index*2+1] == "" {
			return inspectorOptions{}, fmt.Errorf(
				"phaseinspect requires exact argument %s",
				name,
			)
		}
		values[name] = args[index*2+1]
	}
	return inspectorOptions{
		config:                  values["--config"],
		baseline:                values["--baseline"],
		base:                    values["--base"],
		sourceManifest:          values["--source-manifest"],
		spec:                    values["--spec"],
		executionIdentity:       values["--execution-identity"],
		executionIdentitySHA256: values["--execution-identity-sha256"],
		diff:                    values["--diff"],
		evidenceDir:             values["--evidence-dir"],
	}, nil
}

func inspect(options inspectorOptions) (inspectorVerdict, error) {
	session := newInspectionSession()
	verdict, inspectErr := inspectWithSession(session, options)
	if inspectErr == nil {
		inspectErr = session.verify()
	}
	closeErr := session.close()
	if inspectErr != nil || closeErr != nil {
		return inspectorVerdict{}, errors.Join(inspectErr, closeErr)
	}
	return verdict, nil
}

func inspectWithSession(
	session *inspectionSession,
	options inspectorOptions,
) (inspectorVerdict, error) {
	if !validOID(options.baseline) || !validOID(options.base) ||
		!validSHA256(options.executionIdentitySHA256) {
		return inspectorVerdict{}, errors.New("invalid inspector identity arguments")
	}

	configData, configIdentity, err := session.readBoundedFile(
		options.config,
		maxInspectorInputBytes,
	)
	if err != nil {
		return inspectorVerdict{}, fmt.Errorf("read gate config: %w", err)
	}
	var config gateConfig
	if err := decodeStrictJSON(configData, &config, false); err != nil {
		return inspectorVerdict{}, fmt.Errorf("decode gate config: %w", err)
	}
	surfaces, err := validateGateConfig(&config)
	if err != nil {
		return inspectorVerdict{}, err
	}

	identityData, identityFile, err := session.readBoundedFile(
		options.executionIdentity,
		maxInspectorInputBytes,
	)
	if err != nil {
		return inspectorVerdict{}, fmt.Errorf("read execution identity: %w", err)
	}
	if identityFile.Mode&0o777 != executionIdentityMode ||
		identityFile.SHA256 != strings.ToLower(options.executionIdentitySHA256) {
		return inspectorVerdict{}, errors.New("execution identity file mismatch")
	}
	var identity executionIdentity
	if err := decodeStrictJSON(identityData, &identity, true); err != nil {
		return inspectorVerdict{}, fmt.Errorf("decode execution identity: %w", err)
	}
	if err := validateExecutionIdentity(
		session,
		options,
		&config,
		configIdentity,
		identityFile,
		&identity,
	); err != nil {
		return inspectorVerdict{}, err
	}

	selfPath, err := os.Executable()
	if err != nil {
		return inspectorVerdict{}, fmt.Errorf("resolve inspector executable: %w", err)
	}
	self, err := session.executableIdentity(selfPath)
	if err != nil {
		return inspectorVerdict{}, fmt.Errorf("authenticate inspector executable: %w", err)
	}
	if !sameExecutableIdentity(identity.Inspector, self) {
		return inspectorVerdict{}, errors.New("running inspector executable identity mismatch")
	}

	mutationData, mutationIdentity, err := session.readBoundedFile(
		identity.Mutations.Path,
		maxInspectorInputBytes,
	)
	if err != nil || !sameFileIdentity(identity.Mutations, mutationIdentity) {
		return inspectorVerdict{}, errors.New("mutation manifest identity mismatch")
	}
	var mutations mutationManifest
	if err := decodeStrictJSON(mutationData, &mutations, false); err != nil {
		return inspectorVerdict{}, fmt.Errorf("decode mutation manifest: %w", err)
	}
	if err := validateMutationManifest(
		session,
		&mutations,
		&config,
		identity.Spec.SHA256,
		identity.Source.Path,
	); err != nil {
		return inspectorVerdict{}, err
	}

	sourceManifestData, sourceManifestIdentity, err := session.readBoundedFile(
		options.sourceManifest,
		maxInspectorInputBytes,
	)
	if err != nil {
		return inspectorVerdict{}, fmt.Errorf("read source manifest: %w", err)
	}
	var manifest sourceManifest
	if err := decodeStrictJSON(sourceManifestData, &manifest, true); err != nil {
		return inspectorVerdict{}, fmt.Errorf("decode source manifest: %w", err)
	}
	if !sameFileIdentity(identity.SourceManifest, sourceManifestIdentity) ||
		manifest.SchemaVersion != inspectorSchemaVersion ||
		manifest.Baseline != identity.Baseline ||
		manifest.Base != identity.Base ||
		manifest.DiffSHA256 != identity.Diff.SHA256 ||
		manifest.SourceTree != identity.SourceTree {
		return inspectorVerdict{}, errors.New("source manifest identity mismatch")
	}
	liveTree, liveEntries, err := stableDirectoryTreeSnapshot(
		session,
		identity.Source.Path,
	)
	if err != nil ||
		liveTree != identity.SourceTree ||
		!reflect.DeepEqual(liveEntries, manifest.Entries) {
		return inspectorVerdict{}, errors.New(
			"complete source manifest does not match the live source tree",
		)
	}
	inspected, observedSkipCount, err := inspectEvidence(
		session,
		options.evidenceDir,
		&config,
		&identity,
		identityFile.SHA256,
		configIdentity.SHA256,
		&mutations,
	)
	if err != nil {
		return inspectorVerdict{}, err
	}
	if err := validateCompleteClosure(&config, inspected); err != nil {
		return inspectorVerdict{}, err
	}
	observedSurfaces := observedExecutionSurfaces(inspected)

	stages := make([]verdictStage, len(inspected))
	for index := range inspected {
		stages[index] = inspected[index].verdict
	}
	return inspectorVerdict{
		SchemaVersion:           inspectorSchemaVersion,
		Status:                  "PASS",
		Baseline:                identity.Baseline,
		Base:                    identity.Base,
		ConfigSHA256:            configIdentity.SHA256,
		SourceManifestSHA256:    sourceManifestIdentity.SHA256,
		SpecSHA256:              identity.Spec.SHA256,
		ExecutionIdentitySHA256: identityFile.SHA256,
		DiffSHA256:              identity.Diff.SHA256,
		Inspector: verdictExecutable{
			Path:           self.File.Path,
			SHA256:         self.File.SHA256,
			GoBuildVersion: self.GoBuildVersion,
		},
		Stages:                    stages,
		RequiredExecutionSurfaces: append([]executionSurface(nil), surfaces...),
		ObservedExecutionSurfaces: observedSurfaces,
		Skip: verdictSkip{
			ObservedCardinality: observedSkipCount,
		},
		ThreatClosure: append([]string(nil), config.RequiredThreatIDs...),
	}, nil
}

func validateGateConfig(config *gateConfig) ([]executionSurface, error) {
	if config == nil ||
		config.SchemaVersion != inspectorSchemaVersion {
		return nil, errors.New("invalid gate config header")
	}
	if config.GoVersion != "go1.26.5" ||
		config.Module != "Picocrypt-NG" {
		return nil, errors.New("gate config module/version mismatch")
	}
	if config.BuildAttestation != (buildAttestationContract{
		Classification:             "controlled-build self-attestation; not proof against a malicious builder",
		BaselineLDFlag:             "-X=main.phase2Baseline=${BASELINE}",
		BaseLDFlag:                 "-X=main.phase2Base=${BASE}",
		SourceManifestSHA256LDFlag: "-X=main.phase2SourceManifestSHA256=${SOURCE_MANIFEST_SHA256}",
	}) {
		return nil, errors.New("build attestation contract mismatch")
	}
	requiredBinding := executableBinding{
		AbsolutePath:   "required",
		SHA256:         "required",
		GoBuildVersion: "go1.26.5",
	}
	if config.RuntimeBindings != (runtimeBindings{
		Baseline:             "required",
		Base:                 "required",
		SourceTree:           "required",
		SourceManifestSHA256: "required",
		DiffSHA256:           "required",
		ConfigSHA256:         "required",
		SpecSHA256:           "required",
		VectorsSHA256:        "required",
		VectorInputSHA256:    "required",
		MutationsSHA256:      "required",
		Runner:               requiredBinding,
		Inspector:            requiredBinding,
	}) {
		return nil, errors.New("runtime binding contract mismatch")
	}
	if config.DependencyContract != (vendorDependencyContract{
		Mode:                   "archive-local-vendor",
		VendorModulesPath:      "src/vendor/modules.txt",
		SourceManifestCoverage: "complete-tree",
		GOFlags:                "-mod=vendor -trimpath",
		ModuleCacheFallback:    "forbidden-empty-sentinel",
		StageBuildCache:        "distinct-empty-per-stage",
	}) {
		return nil, errors.New("dependency contract mismatch")
	}
	if config.CPUContract != (cpuContract{
		OnlineSource:                      "runtime.NumCPU",
		MinimumOnline:                     2,
		ExactProfileMinimumOnline:         8,
		PhaseJobsFormula:                  "min(floor(online/2),10)",
		GOMAXPROCS:                        "${PHASE_JOBS}",
		MaximumConcurrency:                "10",
		MemoryHardPackageParallelism:      1,
		RequireForAllGoAndGoBasedChildren: true,
	}) {
		return nil, errors.New("CPU contract mismatch")
	}
	if !equalStrings(config.ChildEnvironment.Allowlist, []string{
		"CGO_ENABLED",
		"GOCACHE",
		"GOENV",
		"GOFLAGS",
		"GOMAXPROCS",
		"GOMODCACHE",
		"GOPATH",
		"GOPROXY",
		"GOSUMDB",
		"GOTOOLCHAIN",
		"GOWORK",
		"HOME",
		"PATH",
		"SYSTEMROOT",
		"TMPDIR",
		"XDG_CACHE_HOME",
		"XDG_CONFIG_HOME",
	}) || !reflect.DeepEqual(config.ChildEnvironment.Required, map[string]string{
		"CGO_ENABLED":     "0",
		"GOCACHE":         "${STAGE_GOCACHE}",
		"GOENV":           "off",
		"GOFLAGS":         "-mod=vendor -trimpath",
		"GOMAXPROCS":      "${PHASE_JOBS}",
		"GOMODCACHE":      "${WORKSPACE_GOMODCACHE}",
		"GOPATH":          "${WORKSPACE_GOPATH}",
		"GOPROXY":         "off",
		"GOSUMDB":         "off",
		"GOTOOLCHAIN":     "local",
		"GOWORK":          "off",
		"HOME":            "${WORKSPACE_HOME}",
		"PATH":            "${GO_DIR}",
		"SYSTEMROOT":      "${FROZEN_SYSTEMROOT}",
		"TMPDIR":          "${STAGE_TMPDIR}",
		"XDG_CACHE_HOME":  "${WORKSPACE_XDG_CACHE}",
		"XDG_CONFIG_HOME": "${WORKSPACE_XDG_CONFIG}",
	}) || !equalStrings(config.ChildEnvironment.RejectNameFragments, []string{
		"AUTH",
		"CREDENTIAL",
		"KEY",
		"PASSWORD",
		"SECRET",
		"TOKEN",
	}) {
		return nil, errors.New("child environment contract mismatch")
	}
	stageNames := []string{"mutation", "normal1", "paranoid1", "host"}
	if !equalStrings(config.EvidenceContract.RequiredStageNames, stageNames) ||
		config.EvidenceContract.SchemaVersion != inspectorSchemaVersion ||
		!equalStrings(
			config.EvidenceContract.TerminalStatuses,
			[]string{"PASS", "FAIL"},
		) ||
		!config.EvidenceContract.CreateExclusive ||
		!config.EvidenceContract.ReplaceForbidden ||
		config.EvidenceContract.PublicationProofSuffix != ".verified" ||
		len(config.EvidenceContract.StageFilenames) != len(stageNames) {
		return nil, errors.New("invalid evidence artifact contract")
	}
	seenFilenames := map[string]bool{}
	for _, stage := range stageNames {
		name, exists := config.EvidenceContract.StageFilenames[stage]
		if !exists || name == "" || filepath.Base(name) != name ||
			!strings.HasSuffix(name, ".evidence.json") ||
			seenFilenames[name] {
			return nil, errors.New("invalid evidence stage filename mapping")
		}
		seenFilenames[name] = true
	}
	if len(config.Stages) != len(stageNames) {
		return nil, errors.New("gate config stage set mismatch")
	}
	if err := validateSkipContract(config); err != nil {
		return nil, err
	}
	if len(config.RequiredMutationIDs) != 20 ||
		hasDuplicates(config.RequiredMutationIDs) {
		return nil, errors.New("mutation requirement set mismatch")
	}
	if len(config.RequiredThreatIDs) != 21 ||
		hasDuplicates(config.RequiredThreatIDs) {
		return nil, errors.New("threat requirement set mismatch")
	}
	for index, id := range config.RequiredThreatIDs {
		if id != fmt.Sprintf("T-02-%02d", index+1) {
			return nil, errors.New("threat requirement order mismatch")
		}
	}
	if len(config.LintRuns) != 3 {
		return nil, errors.New("lint closure must contain three runs")
	}
	lintIDs := map[string]bool{}
	for _, lint := range config.LintRuns {
		if lint.ID == "" || lintIDs[lint.ID] || !lint.JSONRequired ||
			lint.IssuesRequired != 0 || lint.ExitCodeRequired != 0 ||
			len(lint.Tags) == 0 || len(lint.Argv) == 0 ||
			lint.TextOutput != "discard" {
			return nil, errors.New("lint run contract mismatch")
		}
		lintIDs[lint.ID] = true
	}

	var surfaces []executionSurface
	var owned []string
	var commandIDs []string
	exactProfiles := map[string]bool{}
	lintCommands := map[string]bool{}
	gitleaks := 0
	threatCheck := 0
	for _, stageName := range stageNames {
		stage, exists := config.Stages[stageName]
		if !exists || len(stage.Commands) == 0 {
			return nil, errors.New("gate config stage is incomplete")
		}
		owned = append(owned, stage.OwnedExecutionUnits...)
		if !sameStringSet(stage.OwnedExecutionUnits, commandConfigIDs(stage.Commands)) {
			return nil, errors.New("stage command ownership mismatch")
		}
		for _, command := range stage.Commands {
			if command.ID == "" || command.Kind == "" ||
				hasDuplicates(command.ExecutionSurface.PackagePaths) ||
				hasDuplicates(command.ExecutionSurface.BuildTags) ||
				command.ExecutionSurface.TestSelector == "" ||
				command.ExecutionSurface.EvidenceKind == "" {
				return nil, errors.New("execution surface is incomplete")
			}
			commandIDs = append(commandIDs, command.ID)
			for _, packagePath := range command.ExecutionSurface.PackagePaths {
				if !strings.HasPrefix(packagePath, "./") ||
					strings.Contains(packagePath, "...") {
					return nil, errors.New("execution surface package is not exact")
				}
			}
			if command.GoBased {
				parallelism, ok := command.PackageParallelism.(float64)
				if !ok || parallelism != 1 {
					return nil, errors.New("go command package parallelism mismatch")
				}
			}
			switch command.Kind {
			case "go-test":
				if command.TimeoutSeconds <= 0 || command.RequiredExitCode != 0 {
					return nil, errors.New("go-test command resource contract mismatch")
				}
				if err := validateGoTestExecutionSurface(
					command,
					config.ChildEnvironment.Required["CGO_ENABLED"],
				); err != nil {
					return nil, err
				}
			case "mutation-campaign":
				if stageName != "mutation" || command.TimeoutSeconds <= 0 ||
					command.RequiredIDsSource != "required_mutation_ids" {
					return nil, errors.New("mutation command contract mismatch")
				}
			case "golangci-lint":
				if !lintIDs[command.LintRun] {
					return nil, errors.New("lint command references an unknown run")
				}
				lintCommands[command.LintRun] = true
			case "gitleaks":
				if command.TimeoutSeconds <= 0 || command.RequiredExitCode != 0 {
					return nil, errors.New("scan command resource contract mismatch")
				}
				gitleaks++
			case "internal":
				switch command.ID {
				case "host-threat-closure":
					if command.RequiredIDsSource != "required_threat_ids" ||
						command.RequiredCount != len(config.RequiredThreatIDs) {
						return nil, errors.New("threat accounting command mismatch")
					}
					threatCheck++
				default:
					return nil, errors.New("unknown internal inspector surface")
				}
			default:
				return nil, errors.New("unsupported command kind")
			}
			if stageName == "normal1" || stageName == "paranoid1" {
				if len(command.RequiredTestIDs) != 1 {
					return nil, errors.New("exact profile test binding mismatch")
				}
				exactProfiles[command.RequiredTestIDs[0]] = true
			}
			surfaces = append(surfaces, command.ExecutionSurface)
		}
	}
	if hasDuplicates(owned) || hasDuplicates(commandIDs) ||
		!sameStringSet(owned, config.RequiredExecutionUnits) ||
		len(lintCommands) != 3 || gitleaks != 1 ||
		threatCheck != 1 ||
		!exactProfiles["TestProductionKDFExactProfiles/normal-1"] ||
		!exactProfiles["TestProductionKDFExactProfiles/paranoid-1"] {
		return nil, errors.New("gate execution-unit closure mismatch")
	}
	if err := validateHostTestScopes(config); err != nil {
		return nil, err
	}
	for left := range surfaces {
		for right := left + 1; right < len(surfaces); right++ {
			if executionSurfacesOverlap(surfaces[left], surfaces[right]) {
				return nil, errors.New("execution surfaces overlap")
			}
		}
	}
	if err := validateThreatConfig(config); err != nil {
		return nil, err
	}
	return surfaces, nil
}

func validateHostTestScopes(config *gateConfig) error {
	host, ok := config.Stages["host"]
	if !ok {
		return errors.New("host stage is missing")
	}
	phase2, phase2OK := commandByID(host.Commands, "host-phase2-tests")
	controller, controllerOK := commandByID(
		host.Commands,
		"host-controller-tests",
	)
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

func validateGoTestExecutionSurface(
	command commandConfig,
	cgoEnabled string,
) error {
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
	evidenceKind := "go-test-json"
	if raceCount == 1 {
		if cgoEnabled != "1" {
			return errors.New("go -race command requires CGO_ENABLED=1")
		}
		evidenceKind = "go-test-race-json"
	}
	derived := executionSurface{
		PackagePaths: packages,
		BuildTags:    tags,
		TestSelector: selector,
		EvidenceKind: evidenceKind,
	}
	if !reflect.DeepEqual(command.ExecutionSurface, derived) {
		return errors.New("go-test execution surface does not match argv")
	}
	if selector != "all" {
		paths, ok := exactSelectorTests(selector)
		if !ok {
			return errors.New("go-test selector is not an exact test path")
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

func validateSkipContract(config *gateConfig) error {
	if config == nil ||
		len(config.SkipAllowlist) != 0 ||
		config.SkipRuntimeCardinality != (skipCardinality{}) {
		return errors.New("controlled Phase-2 gates must forbid every runtime skip")
	}
	return nil
}

func validateMutationManifest(
	session *inspectionSession,
	manifest *mutationManifest,
	config *gateConfig,
	specSHA256 string,
	sourceRoot string,
) error {
	expectedArgv := []string{
		"phase2-mutator",
		"--source-copy", "${SOURCE_COPY}",
		"--manifest", "${MUTATION_MANIFEST}",
		"--mutation-id", "${MUTATION_ID}",
		"--source-set-sha256", "${SOURCE_SET_SHA256}",
		"--baseline", "${BASELINE}",
		"--spec-sha256", "${SPEC_SHA256}",
		"--result", "${RESULT}",
	}
	if manifest == nil ||
		manifest.SchemaVersion != inspectorSchemaVersion ||
		manifest.SpecSHA256 != specSHA256 ||
		!validSHA256(manifest.SourceSetSHA256) ||
		!equalStrings(manifest.ArgvTemplate, expectedArgv) ||
		len(manifest.Mutations) != len(config.RequiredMutationIDs) {
		return errors.New("mutation manifest header mismatch")
	}
	ids := make([]string, len(manifest.Mutations))
	sources := map[string]string{}
	for index := range manifest.Mutations {
		mutation := &manifest.Mutations[index]
		ids[index] = mutation.ID
		if mutation.ID == "" ||
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
			mutation.KillingTestID == "" ||
			mutation.ViolationMarker == "" ||
			!validCampaignOutcome(
				mutation.Pristine,
				mutation.KillingTestID,
				"PASS",
				"",
			) ||
			!validCampaignOutcome(
				mutation.Mutant,
				mutation.KillingTestID,
				"FAIL",
				mutation.ViolationMarker,
			) {
			return fmt.Errorf("mutation manifest entry %q is invalid", mutation.ID)
		}
		if previous, exists := sources[mutation.SourcePath]; exists &&
			previous != mutation.SourceSHA256 {
			return errors.New("mutation source hashes conflict")
		}
		sources[mutation.SourcePath] = mutation.SourceSHA256
		sourceData, sourceIdentity, err := session.readBoundedFile(
			filepath.Join(sourceRoot, "src", filepath.FromSlash(mutation.SourcePath)),
			maxInspectorInputBytes,
		)
		if err != nil ||
			sourceIdentity.SHA256 != mutation.SourceSHA256 ||
			bytes.Count(sourceData, []byte(mutation.Anchor)) != 1 {
			return errors.New("mutation source or anchor identity mismatch")
		}
	}
	if !sameStringSet(ids, config.RequiredMutationIDs) ||
		hasDuplicates(ids) ||
		sourceSetHash(sources) != manifest.SourceSetSHA256 {
		return errors.New("mutation manifest closure mismatch")
	}
	return nil
}

func validCampaignOutcome(
	outcome campaignOutcome,
	testID string,
	status string,
	marker string,
) bool {
	if outcome.Status != status ||
		outcome.Execution != "semantic" ||
		outcome.TestID != testID ||
		outcome.ViolationMarker != marker ||
		outcome.Stage == "" ||
		outcome.Reason == "" ||
		outcome.Skipped ||
		outcome.CompileOnly ||
		!semanticCommandKills(outcome.SemanticCommand, testID) {
		return false
	}
	return true
}

func semanticCommandKills(command []string, testID string) bool {
	return len(command) == 6 &&
		command[0] == "go" &&
		command[1] == "test" &&
		command[2] == "./internal/pcv3credential" &&
		command[3] == "-run" &&
		command[4] == "^"+testID+"$" &&
		command[5] == "-count=1"
}

func sourceSetHash(sources map[string]string) string {
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

func mutationByID(
	manifest *mutationManifest,
	id string,
) (*campaignMutation, bool) {
	if manifest == nil {
		return nil, false
	}
	for index := range manifest.Mutations {
		if manifest.Mutations[index].ID == id {
			return &manifest.Mutations[index], true
		}
	}
	return nil, false
}

func validateThreatConfig(config *gateConfig) error {
	if len(config.ThreatClosure) != len(config.RequiredThreatIDs) {
		return errors.New("threat closure count mismatch")
	}
	seen := map[string]bool{}
	observedByCommand := map[string]map[string]bool{}
	for _, closure := range config.ThreatClosure {
		stage, exists := config.Stages[closure.Stage]
		command, commandExists := commandByID(stage.Commands, closure.CommandID)
		if !exists || seen[closure.ID] ||
			!contains(config.RequiredThreatIDs, closure.ID) ||
			!commandExists ||
			len(closure.RequiredObservedIDs) == 0 ||
			hasDuplicates(closure.RequiredObservedIDs) {
			return errors.New("threat closure mapping mismatch")
		}
		switch command.Kind {
		case "go-test":
			if !subsetOf(
				closure.RequiredObservedIDs,
				command.RequiredTestIDs,
			) {
				return errors.New("test threat closure is outside the command inventory")
			}
			if observedByCommand[command.ID] == nil {
				observedByCommand[command.ID] = map[string]bool{}
			}
			for _, observedID := range closure.RequiredObservedIDs {
				observedByCommand[command.ID][observedID] = true
			}
		case "mutation-campaign":
			if !subsetOf(
				closure.RequiredObservedIDs,
				config.RequiredMutationIDs,
			) {
				return errors.New("mutation threat closure is outside the campaign")
			}
		default:
			return errors.New(
				"threat closure must use structured test or mutation evidence",
			)
		}
		seen[closure.ID] = true
	}
	host, exists := config.Stages["host"]
	if !exists {
		return errors.New("threat closure mapping mismatch")
	}
	for commandID, observedIDs := range observedByCommand {
		command, exists := commandByID(host.Commands, commandID)
		if !exists || command.Kind != "go-test" {
			return errors.New("threat closure mapping mismatch")
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

func validateExecutionIdentity(
	session *inspectionSession,
	options inspectorOptions,
	config *gateConfig,
	configIdentity fileIdentity,
	identityFile fileIdentity,
	identity *executionIdentity,
) error {
	if identity == nil ||
		identity.SchemaVersion != inspectorSchemaVersion ||
		identity.Baseline != strings.ToLower(options.baseline) ||
		identity.Base != strings.ToLower(options.base) ||
		identity.GoVersion != config.GoVersion ||
		identity.Module != config.Module ||
		identity.OnlineSource != "runtime.NumCPU" ||
		identity.Online < 2 ||
		identity.PhaseJobs != derivedPhaseJobs(identity.Online) ||
		identity.CPUModel == "" ||
		identity.CPUModelSource == "" ||
		identity.GOOS != "linux" ||
		identity.GOARCH == "" ||
		identity.Executables == nil ||
		identity.Environment == nil ||
		identity.WorkingDirs == nil {
		return errors.New("execution identity header mismatch")
	}
	if identityFile.SHA256 != strings.ToLower(options.executionIdentitySHA256) ||
		!sameFileIdentity(identity.Config, configIdentity) {
		return errors.New("execution identity binding mismatch")
	}
	if phase2Baseline != identity.Baseline ||
		phase2Baseline != strings.ToLower(options.baseline) ||
		phase2Base != identity.Base ||
		phase2Base != strings.ToLower(options.base) ||
		phase2SourceManifestSHA256 != identity.SourceManifest.SHA256 {
		return errors.New("running inspector build binding mismatch")
	}
	if identity.GOOS != runtime.GOOS ||
		identity.GOARCH != runtime.GOARCH ||
		identity.Online != runtime.NumCPU() ||
		identity.PhaseJobs != derivedPhaseJobs(runtime.NumCPU()) {
		return errors.New("execution identity host facts mismatch")
	}
	if !equalStrings(
		sortedExecutableNames(identity.Executables),
		requiredExecutableNames(config),
	) {
		return errors.New("execution identity executable set mismatch")
	}
	goExecutable, ok := identity.Executables["${GO}"]
	if !ok || goExecutable.GoBuildVersion != config.GoVersion {
		return errors.New(
			"execution identity Go executable build version mismatch",
		)
	}
	if goExecutable.MainPackagePath != "cmd/go" {
		return errors.New(
			"execution identity Go executable main package mismatch",
		)
	}
	if identity.Runner.File.Path == identity.Inspector.File.Path ||
		identity.Runner.File.SHA256 == identity.Inspector.File.SHA256 {
		return errors.New("runner and inspector executable identities are not distinct")
	}
	if identity.Runner.GoBuildVersion != config.GoVersion ||
		identity.Inspector.GoBuildVersion != config.GoVersion ||
		identity.Runner.ModulePath != config.Module ||
		identity.Inspector.ModulePath != config.Module ||
		identity.Runner.MainPackagePath !=
			"Picocrypt-NG/internal/pcv3credential/testdata/phasegates" ||
		identity.Inspector.MainPackagePath !=
			"Picocrypt-NG/internal/pcv3credential/testdata/phaseinspect" ||
		!validSHA256(identity.Runner.BuildInfoSHA256) ||
		!validSHA256(identity.Inspector.BuildInfoSHA256) {
		return errors.New("runner or inspector build identity mismatch")
	}
	for _, binding := range []struct {
		name string
		path string
		want fileIdentity
	}{
		{name: "source manifest", path: options.sourceManifest, want: identity.SourceManifest},
		{name: "specification", path: options.spec, want: identity.Spec},
		{name: "diff", path: options.diff, want: identity.Diff},
		{name: "vectors", path: identity.Vectors.Path, want: identity.Vectors},
		{name: "vector input", path: identity.VectorInput.Path, want: identity.VectorInput},
		{name: "mutations", path: identity.Mutations.Path, want: identity.Mutations},
	} {
		_, got, err := session.readBoundedFile(
			binding.path,
			maxInspectorInputBytes,
		)
		if err != nil || !sameFileIdentity(binding.want, got) {
			return fmt.Errorf("%s identity mismatch", binding.name)
		}
	}
	source, err := session.directoryIdentity(identity.Source.Path)
	if err != nil || source != identity.Source {
		return errors.New("source directory identity mismatch")
	}
	evidenceRoot, err := session.directoryIdentity(options.evidenceDir)
	evidenceRootMode := os.FileMode(evidenceRoot.Mode)
	if err != nil ||
		filepath.Clean(evidenceRoot.Path) != filepath.Clean(identity.EvidenceRoot.Path) ||
		evidenceRoot.Mode != identity.EvidenceRoot.Mode ||
		identity.EvidenceRoot.ModTimeUnixNano != 0 ||
		!evidenceRootMode.IsDir() ||
		evidenceRootMode.Perm() != 0o700 {
		return errors.New("evidence root contract mismatch")
	}
	if err := validatePrivateWorkspace(session, config, identity); err != nil {
		return err
	}
	if err := validateWorkingDirectories(session, config, identity); err != nil {
		return err
	}
	if err := validateChildEnvironments(config, identity); err != nil {
		return err
	}
	runner, err := session.executableIdentity(identity.Runner.File.Path)
	if err != nil || !sameExecutableIdentity(identity.Runner, runner) {
		return errors.New("runner executable identity mismatch")
	}
	inspector, err := session.executableIdentity(identity.Inspector.File.Path)
	if err != nil || !sameExecutableIdentity(identity.Inspector, inspector) ||
		inspector.GoBuildVersion == "" {
		return errors.New("inspector executable identity mismatch")
	}
	if !runner.trimpath || !inspector.trimpath {
		return errors.New(
			"runner or inspector trimpath build policy mismatch",
		)
	}
	for name, want := range identity.Executables {
		got, err := session.executableIdentity(want.File.Path)
		if err != nil || !sameExecutableIdentity(want, got) {
			return fmt.Errorf("executable identity mismatch: %s", name)
		}
	}
	return nil
}

func requiredExecutableNames(config *gateConfig) []string {
	set := map[string]bool{}
	if config != nil {
		for _, stage := range config.Stages {
			for _, command := range stage.Commands {
				if len(command.Argv) != 0 {
					set[command.Argv[0]] = true
				}
				if command.Kind == "mutation-campaign" {
					set["${GO}"] = true
				}
			}
		}
		for _, lint := range config.LintRuns {
			if len(lint.Argv) != 0 {
				set[lint.Argv[0]] = true
			}
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedExecutableNames(
	executables map[string]executableIdentity,
) []string {
	names := make([]string, 0, len(executables))
	for name := range executables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func validateWorkingDirectories(
	session *inspectionSession,
	config *gateConfig,
	identity *executionIdentity,
) error {
	if session == nil || config == nil || identity == nil {
		return errors.New("execution identity working directories mismatch")
	}
	set := map[string]bool{}
	for _, stage := range config.Stages {
		for _, command := range stage.Commands {
			if command.CWD == "" {
				continue
			}
			path := replaceEvidenceValue(
				command.CWD,
				map[string]string{"${SOURCE}": identity.Source.Path},
			)
			if strings.Contains(path, "${") ||
				!pathWithinDirectory(identity.Source.Path, path) {
				return errors.New(
					"execution identity working directories mismatch",
				)
			}
			directory, err := session.directoryIdentity(path)
			if err != nil {
				return errors.New(
					"execution identity working directories mismatch",
				)
			}
			set[directory.Path] = true
		}
	}
	expected := make([]string, 0, len(set))
	for path := range set {
		expected = append(expected, path)
	}
	sort.Strings(expected)
	if !equalStrings(identity.WorkingDirs, expected) {
		return errors.New("execution identity working directories mismatch")
	}
	return nil
}

func pathWithinDirectory(root string, path string) bool {
	cleanRoot, rootErr := filepath.Abs(filepath.Clean(root))
	cleanPath, pathErr := filepath.Abs(filepath.Clean(path))
	if rootErr != nil || pathErr != nil {
		return false
	}
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	return err == nil &&
		relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func validateChildEnvironments(
	config *gateConfig,
	identity *executionIdentity,
) error {
	if config == nil || identity == nil ||
		len(identity.Environment) != len(config.Stages) {
		return errors.New("execution identity child environment mismatch")
	}
	goExecutable, ok := identity.Executables["${GO}"]
	if !ok {
		return errors.New("execution identity child environment mismatch")
	}
	for stage := range config.Stages {
		replacements := map[string]string{
			"${PHASE_JOBS}":        strconv.Itoa(identity.PhaseJobs),
			"${FROZEN_SYSTEMROOT}": os.Getenv("SYSTEMROOT"),
			"${GO_DIR}":            filepath.Dir(goExecutable.File.Path),
			"${STAGE_TMPDIR}": filepath.Join(
				identity.EvidenceRoot.Path,
				".phasegates-"+stage+"-tmp",
			),
			"${WORKSPACE_HOME}": filepath.Join(
				identity.EvidenceRoot.Path,
				".phasegates-home",
			),
			"${STAGE_GOCACHE}": filepath.Join(
				identity.EvidenceRoot.Path,
				".phasegates-"+stage+"-go-cache",
			),
			"${WORKSPACE_GOMODCACHE}": filepath.Join(
				identity.EvidenceRoot.Path,
				".phasegates-go-mod-cache",
			),
			"${WORKSPACE_GOPATH}": filepath.Join(
				identity.EvidenceRoot.Path,
				".phasegates-go-path",
			),
			"${WORKSPACE_XDG_CACHE}": filepath.Join(
				identity.EvidenceRoot.Path,
				".phasegates-xdg-cache",
			),
			"${WORKSPACE_XDG_CONFIG}": filepath.Join(
				identity.EvidenceRoot.Path,
				".phasegates-xdg-config",
			),
		}
		expected := make([]string, 0, len(
			config.ChildEnvironment.Required,
		))
		for name, value := range config.ChildEnvironment.Required {
			resolved := replaceEvidenceValue(value, replacements)
			if strings.Contains(resolved, "${") ||
				strings.ContainsRune(resolved, '\x00') {
				return errors.New(
					"execution identity child environment mismatch",
				)
			}
			expected = append(expected, name+"="+resolved)
		}
		sort.Strings(expected)
		if !equalStrings(identity.Environment[stage], expected) {
			return errors.New(
				"execution identity child environment mismatch",
			)
		}
	}
	return nil
}

func validatePrivateWorkspace(
	session *inspectionSession,
	config *gateConfig,
	identity *executionIdentity,
) error {
	if session == nil || config == nil || identity == nil {
		return errors.New("private workspace lifecycle mismatch")
	}
	required := map[string]bool{
		".phasegates-home":         true,
		".phasegates-go-mod-cache": true,
		".phasegates-go-path":      true,
		".phasegates-xdg-cache":    true,
		".phasegates-xdg-config":   true,
	}
	for stage := range config.Stages {
		required[".phasegates-"+stage+"-go-cache"] = true
	}
	names, err := session.readDirectoryNames(identity.EvidenceRoot.Path)
	if err != nil {
		return errors.New("private workspace lifecycle mismatch")
	}
	present := make(map[string]bool, len(names))
	for _, name := range names {
		present[name] = true
		if strings.HasPrefix(name, ".phasegates-") && !required[name] {
			return errors.New("private workspace lifecycle mismatch")
		}
	}
	for name := range required {
		if !present[name] {
			return errors.New("private workspace lifecycle mismatch")
		}
		path := filepath.Join(
			identity.EvidenceRoot.Path,
			name,
		)
		directory, err := session.directoryIdentity(path)
		mode := os.FileMode(directory.Mode)
		if err != nil || !mode.IsDir() || mode.Perm() != 0o700 {
			return errors.New("private workspace lifecycle mismatch")
		}
		if name == ".phasegates-go-mod-cache" {
			names, err := session.readDirectoryNames(path)
			if err != nil {
				return errors.New(
					"module-cache sentinel namespace is unavailable",
				)
			}
			if len(names) != 0 {
				return errors.New("module-cache sentinel is not empty")
			}
		}
	}
	return nil
}

func inspectEvidence(
	session *inspectionSession,
	evidenceDir string,
	config *gateConfig,
	identity *executionIdentity,
	identitySHA string,
	configSHA string,
	mutations *mutationManifest,
) ([]inspectedStage, int, error) {
	names, err := session.readDirectoryNames(evidenceDir)
	if err != nil {
		return nil, 0, fmt.Errorf("read evidence directory: %w", err)
	}
	requiredNames := make([]string, 0, len(
		config.EvidenceContract.RequiredStageNames,
	)*2)
	for _, stage := range config.EvidenceContract.RequiredStageNames {
		evidenceName := config.EvidenceContract.StageFilenames[stage]
		requiredNames = append(
			requiredNames,
			evidenceName,
			evidenceName+config.EvidenceContract.PublicationProofSuffix,
		)
	}
	sort.Strings(requiredNames)
	pendingProofNames := make(map[string]bool, len(
		config.EvidenceContract.RequiredStageNames,
	))
	for _, stage := range config.EvidenceContract.RequiredStageNames {
		evidenceName := config.EvidenceContract.StageFilenames[stage]
		pendingProofNames["."+evidenceName+
			config.EvidenceContract.PublicationProofSuffix+
			".pending"] = true
	}
	var terminalNames []string
	for _, name := range names {
		if pendingProofNames[name] {
			return nil, 0, errors.New("pending evidence proof exists")
		}
		if strings.HasSuffix(name, ".evidence.json") ||
			strings.HasSuffix(name, ".evidence.json.verified") {
			terminalNames = append(terminalNames, name)
		}
	}
	if !equalStrings(terminalNames, requiredNames) {
		return nil, 0, errors.New("required evidence stage set mismatch")
	}

	var inspected []inspectedStage
	observedSkips := 0
	for _, stage := range config.EvidenceContract.RequiredStageNames {
		evidenceName := config.EvidenceContract.StageFilenames[stage]
		evidencePath := filepath.Join(evidenceDir, evidenceName)
		evidenceData, evidenceIdentity, err := session.readBoundedFile(
			evidencePath,
			maxInspectorInputBytes,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("read %s evidence: %w", stage, err)
		}
		if evidenceIdentity.Mode&0o777 != evidenceMode {
			return nil, 0, errors.New("evidence file mode mismatch")
		}
		if !session.fileHasSingleLink(evidenceIdentity) {
			return nil, 0, errors.New(
				"evidence file link count mismatch",
			)
		}
		var evidence stageEvidence
		if err := decodeStrictJSON(evidenceData, &evidence, true); err != nil {
			return nil, 0, fmt.Errorf("decode %s evidence: %w", stage, err)
		}
		proofName := evidenceName + config.EvidenceContract.PublicationProofSuffix
		proofPath := filepath.Join(evidenceDir, proofName)
		proofData, proofIdentity, err := session.readBoundedFile(
			proofPath,
			maxInspectorInputBytes,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("read %s proof: %w", stage, err)
		}
		if proofIdentity.Mode&0o777 != evidenceMode {
			return nil, 0, errors.New("evidence proof mode mismatch")
		}
		if !session.fileHasSingleLink(proofIdentity) {
			return nil, 0, errors.New(
				"evidence proof link count mismatch",
			)
		}
		var proof evidencePublicationProof
		if err := decodeStrictJSON(proofData, &proof, true); err != nil {
			return nil, 0, fmt.Errorf("decode %s proof: %w", stage, err)
		}
		if proof.SchemaVersion != inspectorSchemaVersion ||
			proof.EvidenceSHA256 != evidenceIdentity.SHA256 {
			return nil, 0, errors.New("evidence publication proof mismatch")
		}
		if err := validateStageEvidence(
			session,
			stage,
			config,
			identity,
			identitySHA,
			configSHA,
			&evidence,
			mutations,
		); err != nil {
			return nil, 0, err
		}
		observedSkips += len(evidence.SkipEvents)
		inspected = append(inspected, inspectedStage{
			verdict: verdictStage{
				Stage:          stage,
				EvidenceName:   evidenceName,
				EvidenceSHA256: evidenceIdentity.SHA256,
				ProofName:      proofName,
				ProofSHA256:    proofIdentity.SHA256,
			},
			evidence: evidence,
		})
	}
	if observedSkips < config.SkipRuntimeCardinality.Minimum ||
		observedSkips > config.SkipRuntimeCardinality.Maximum {
		return nil, 0, errors.New("runtime skip cardinality mismatch")
	}
	return inspected, observedSkips, nil
}

func validateStageEvidence(
	session *inspectionSession,
	stageName string,
	config *gateConfig,
	identity *executionIdentity,
	identitySHA string,
	configSHA string,
	evidence *stageEvidence,
	mutations *mutationManifest,
) error {
	if evidence == nil ||
		evidence.SchemaVersion != inspectorSchemaVersion ||
		evidence.Stage != stageName ||
		evidence.Status != "PASS" ||
		evidence.Baseline != identity.Baseline ||
		evidence.Base != identity.Base ||
		evidence.ExecutionIdentitySHA256 != identitySHA ||
		evidence.ConfigSHA256 != configSHA ||
		evidence.StartedAt == "" ||
		evidence.FinishedAt == "" ||
		len(evidence.Commands) == 0 ||
		evidence.Failure != "" {
		return fmt.Errorf("%s evidence header mismatch", stageName)
	}
	started, startErr := time.Parse(time.RFC3339Nano, evidence.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, evidence.FinishedAt)
	if startErr != nil || finishErr != nil || finished.Before(started) {
		return errors.New("evidence timestamps are invalid")
	}
	stage := config.Stages[stageName]
	if len(evidence.Commands) != len(stage.Commands) {
		return fmt.Errorf("%s evidence command count mismatch", stageName)
	}
	var observed []string
	var skips []skipEvent
	var closed []string
	for index, command := range stage.Commands {
		result := &evidence.Commands[index]
		if err := validateCommandResult(
			session,
			stageName,
			&command,
			result,
			config,
			identity,
			mutations,
		); err != nil {
			return err
		}
		observed = append(observed, result.ObservedIDs...)
		skips = append(skips, result.SkipEvents...)
		closed = append(closed, result.ClosedThreatIDs...)
	}
	if !equalStrings(evidence.ObservedIDs, observed) ||
		!equalSkipEvents(evidence.SkipEvents, skips) ||
		!sameStringSet(evidence.ClosedThreatIDs, closed) ||
		hasDuplicates(evidence.ClosedThreatIDs) {
		return fmt.Errorf("%s stage aggregate evidence mismatch", stageName)
	}
	expectedRequired := []string{}
	switch stageName {
	case "mutation":
		expectedRequired = config.RequiredMutationIDs
	case "host":
		expectedRequired = threatsForStage(config, stageName)
	}
	if !equalStrings(evidence.RequiredIDs, expectedRequired) {
		return errors.New("stage required ID set mismatch")
	}
	if err := validateSkipEvents(evidence.SkipEvents); err != nil {
		return err
	}
	return nil
}

func validateCommandResult(
	session *inspectionSession,
	stageName string,
	command *commandConfig,
	result *commandResult,
	config *gateConfig,
	identity *executionIdentity,
	mutations *mutationManifest,
) error {
	if command == nil || result == nil || identity == nil {
		return errors.New("command result is not terminal PASS evidence")
	}
	effective := effectiveCommandForEvidence(config, *command)
	if result.ID != command.ID ||
		!reflect.DeepEqual(
			result.Contract,
			commandEvidenceForConfig(effective),
		) ||
		result.ExitCode != command.RequiredExitCode ||
		result.TimedOut ||
		result.TerminationErr != "" ||
		result.WaitErr != "" ||
		result.GoTestEvent != nil ||
		(result.StdoutSHA256 != "" && !validSHA256(result.StdoutSHA256)) ||
		(result.StderrSHA256 != "" && !validSHA256(result.StderrSHA256)) {
		return errors.New("command result is not terminal PASS evidence")
	}
	replacements := evidenceReplacements(identity, stageName)
	expectedCWD := replaceEvidenceValue(effective.CWD, replacements)
	if result.CWD != expectedCWD {
		return errors.New("command argv or working directory mismatch")
	}
	switch effective.Kind {
	case "go-test", "golangci-lint", "gitleaks":
		if !equalStrings(
			result.Argv,
			replaceEvidenceSlice(effective.Argv, replacements),
		) {
			return errors.New("command argv or working directory mismatch")
		}
		if !validSHA256(result.StdoutSHA256) ||
			!validSHA256(result.StderrSHA256) {
			return errors.New("external command output hash mismatch")
		}
	case "internal", "mutation-campaign":
		if len(result.Argv) != 0 ||
			result.StdoutSHA256 != "" ||
			result.StderrSHA256 != "" {
			return errors.New("non-process command receipt mismatch")
		}
	default:
		return errors.New("unsupported command receipt kind")
	}
	if err := validateToolResult(effective, result); err != nil {
		return err
	}
	var expectedObservedIDs []string
	switch command.Kind {
	case "go-test":
		expectedObservedIDs = command.RequiredTestIDs
	case "mutation-campaign":
		expectedObservedIDs = config.RequiredMutationIDs
	}
	if !equalStrings(result.ObservedIDs, expectedObservedIDs) {
		return errors.New("command observed IDs mismatch")
	}
	expectedThreats := threatsForCommand(config, stageName, command.ID)
	if !equalStrings(result.ClosedThreatIDs, expectedThreats) {
		return errors.New("command threat closure mismatch")
	}
	for _, closure := range config.ThreatClosure {
		if closure.Stage == stageName && closure.CommandID == command.ID &&
			!subsetOf(closure.RequiredObservedIDs, result.ObservedIDs) {
			return errors.New("command lacks required threat observations")
		}
	}
	if command.Kind == "mutation-campaign" {
		if !equalStrings(result.ObservedIDs, config.RequiredMutationIDs) ||
			len(result.Mutations) != len(config.RequiredMutationIDs) {
			return errors.New("mutation campaign result set mismatch")
		}
		for index, mutation := range result.Mutations {
			specification, ok := mutationByID(mutations, mutation.ID)
			if mutation.ID != config.RequiredMutationIDs[index] ||
				!ok ||
				mutation.KillingTestID == "" ||
				mutation.KillingTestID != specification.KillingTestID ||
				mutation.ViolationMarker == "" ||
				mutation.ViolationMarker != specification.ViolationMarker {
				return errors.New("mutation semantic outcome mismatch")
			}
			if !successfulNestedResult(
				mutation.Pristine,
				nestedMutationCommand(
					identity,
					stageName,
					specification,
					"pristine",
				),
				&goTestEventAttestation{
					Package:        pcv3PackagePath,
					TestID:         specification.KillingTestID,
					TerminalAction: "pass",
				},
			) ||
				!successfulNestedResult(
					mutation.Application,
					mutationApplicationCommand(
						identity,
						stageName,
						mutations,
						specification,
					),
					nil,
				) ||
				!successfulNestedResult(
					mutation.Mutant,
					nestedMutationCommand(
						identity,
						stageName,
						specification,
						"mutant",
					),
					&goTestEventAttestation{
						Package:        pcv3PackagePath,
						TestID:         specification.KillingTestID,
						TerminalAction: "fail",
					},
				) {
				return errors.New("nested mutation command receipt mismatch")
			}
			if !validMutationApplicationReceipt(
				session,
				identity,
				mutations,
				specification,
				mutation.ApplicationReceipt,
			) {
				return errors.New("mutation application receipt mismatch")
			}
		}
	} else if len(result.Mutations) != 0 {
		return errors.New("non-mutation command contains mutation outcomes")
	}
	return validateSkipEvents(result.SkipEvents)
}

func effectiveCommandForEvidence(
	config *gateConfig,
	command commandConfig,
) commandConfig {
	if command.Kind == "golangci-lint" && config != nil {
		for _, lint := range config.LintRuns {
			if lint.ID != command.LintRun {
				continue
			}
			command.Argv = append([]string(nil), lint.Argv...)
			command.CWD = "${SOURCE}/src"
			command.TimeoutSeconds = 600
			command.GoBased = true
			command.PackageParallelism = float64(1)
			command.RequiredExitCode = lint.ExitCodeRequired
			break
		}
	}
	return command
}

func commandEvidenceForConfig(command commandConfig) commandEvidence {
	parallelism := 0
	switch value := command.PackageParallelism.(type) {
	case float64:
		parallelism = int(value)
	case string:
		if value == "${PHASE_JOBS}" {
			parallelism = 1
		}
	}
	surface := command.ExecutionSurface
	if surface.PackagePaths == nil {
		surface.PackagePaths = []string{}
	}
	if surface.BuildTags == nil {
		surface.BuildTags = []string{}
	}
	requiredTestIDs := append([]string(nil), command.RequiredTestIDs...)
	if requiredTestIDs == nil {
		requiredTestIDs = []string{}
	}
	requiredTestPackages := make(map[string]string, len(command.RequiredTestPackages))
	for testID, packagePath := range command.RequiredTestPackages {
		requiredTestPackages[testID] = packagePath
	}
	return commandEvidence{
		Kind:                 command.Kind,
		ExecutionSurface:     surface,
		TimeoutSeconds:       command.TimeoutSeconds,
		GoBased:              command.GoBased,
		MemoryHard:           command.MemoryHard,
		PackageParallelism:   parallelism,
		RequiredExitCode:     command.RequiredExitCode,
		RequiredTestIDs:      requiredTestIDs,
		RequiredTestPackages: requiredTestPackages,
	}
}

func validateToolResult(
	command commandConfig,
	result *commandResult,
) error {
	switch command.Kind {
	case "golangci-lint":
		if result.LintResult == nil ||
			result.LintResult.RunID != command.LintRun ||
			!validSHA256(result.LintResult.JSONSHA256) ||
			result.LintResult.Issues == nil ||
			len(result.LintResult.Issues) != 0 ||
			len(result.LintResult.EnabledLinters) == 0 ||
			!sort.StringsAreSorted(result.LintResult.EnabledLinters) ||
			hasDuplicates(result.LintResult.EnabledLinters) ||
			result.ScanResult != nil {
			return errors.New("lint result mismatch")
		}
		for _, name := range result.LintResult.EnabledLinters {
			if name == "" {
				return errors.New("lint result mismatch")
			}
		}
	case "gitleaks":
		target, ok := scanTargetFromArgv(result.Argv)
		if !ok ||
			result.ScanResult == nil ||
			*result.ScanResult != (scanEvidenceResult{
				Scanner:  "gitleaks",
				Target:   target,
				Findings: 0,
			}) ||
			result.LintResult != nil {
			return errors.New("scan result mismatch")
		}
	default:
		if result.LintResult != nil || result.ScanResult != nil {
			return errors.New("unexpected lint or scan result")
		}
	}
	return nil
}

func scanTargetFromArgv(argv []string) (string, bool) {
	if len(argv) == 0 || filepath.Base(argv[0]) != "gitleaks" {
		return "", false
	}
	target := ""
	for index := 1; index+1 < len(argv); index++ {
		if argv[index] != "--source" {
			continue
		}
		if target != "" || argv[index+1] == "" {
			return "", false
		}
		target = argv[index+1]
	}
	return target, target != ""
}

func evidenceReplacements(
	identity *executionIdentity,
	stage string,
) map[string]string {
	replacements := map[string]string{
		"${SOURCE}":          identity.Source.Path,
		"${SOURCE_MANIFEST}": identity.SourceManifest.Path,
		"${MUTATIONS}":       identity.Mutations.Path,
		"${PHASE_JOBS}":      strconv.Itoa(identity.PhaseJobs),
		"${STAGE_TMPDIR}": filepath.Join(
			identity.EvidenceRoot.Path,
			".phasegates-"+stage+"-tmp",
		),
		"${STAGE}": stage,
	}
	for name, executable := range identity.Executables {
		replacements[name] = executable.File.Path
	}
	return replacements
}

func replaceEvidenceSlice(
	values []string,
	replacements map[string]string,
) []string {
	replaced := make([]string, len(values))
	for index, value := range values {
		replaced[index] = replaceEvidenceValue(value, replacements)
	}
	return replaced
}

func replaceEvidenceValue(
	value string,
	replacements map[string]string,
) string {
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

func nestedMutationCommand(
	identity *executionIdentity,
	stage string,
	mutation *campaignMutation,
	kind string,
) commandConfig {
	exitCode := 0
	if kind == "mutant" {
		exitCode = 1
	}
	sourceCopy := filepath.Join(
		identity.EvidenceRoot.Path,
		".phasegates-"+stage+"-tmp",
		mutation.ID,
		"source",
	)
	return commandConfig{
		ID:   mutation.ID + "/" + kind,
		Kind: "structured",
		Argv: semanticTestArgvEvidence(
			identity.Executables["${GO}"].File.Path,
			mutation.KillingTestID,
		),
		CWD:                filepath.Join(sourceCopy, "src"),
		TimeoutSeconds:     120,
		GoBased:            true,
		PackageParallelism: float64(1),
		RequiredExitCode:   exitCode,
	}
}

func mutationApplicationCommand(
	identity *executionIdentity,
	stage string,
	manifest *mutationManifest,
	mutation *campaignMutation,
) commandConfig {
	mutationRoot := filepath.Join(
		identity.EvidenceRoot.Path,
		".phasegates-"+stage+"-tmp",
		mutation.ID,
	)
	moduleRoot := filepath.Join(mutationRoot, "source", "src")
	return commandConfig{
		ID:   mutation.ID + "/application",
		Kind: "structured",
		Argv: []string{
			identity.Executables["${GO}"].File.Path,
			"run",
			"-tags",
			"migrated_fynedo",
			"./internal/pcv3credential/testdata/mutator",
			"--source-copy", moduleRoot,
			"--manifest", identity.Mutations.Path,
			"--mutation-id", mutation.ID,
			"--source-set-sha256", manifest.SourceSetSHA256,
			"--baseline", identity.Baseline,
			"--spec-sha256", manifest.SpecSHA256,
			"--result", filepath.Join(mutationRoot, "application.json"),
		},
		CWD:                filepath.Join(identity.Source.Path, "src"),
		TimeoutSeconds:     120,
		GoBased:            true,
		PackageParallelism: float64(1),
		RequiredExitCode:   0,
	}
}

func semanticTestArgvEvidence(
	goExecutable string,
	testID string,
) []string {
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

func validMutationApplicationReceipt(
	session *inspectionSession,
	identity *executionIdentity,
	manifest *mutationManifest,
	mutation *campaignMutation,
	receipt campaignApplicationRecord,
) bool {
	source, sourceIdentity, err := session.readBoundedFile(
		filepath.Join(
			identity.Source.Path,
			"src",
			filepath.FromSlash(mutation.SourcePath),
		),
		maxInspectorInputBytes,
	)
	if err != nil ||
		sourceIdentity.SHA256 != mutation.SourceSHA256 ||
		bytes.Count(source, []byte(mutation.Anchor)) != 1 {
		return false
	}
	mutated := bytes.Replace(
		source,
		[]byte(mutation.Anchor),
		[]byte(mutation.Replacement),
		1,
	)
	expectedAfter := sha256Hex(mutated)
	return receipt.SchemaVersion == inspectorSchemaVersion &&
		receipt.MutationID == mutation.ID &&
		receipt.BaselineCommit == identity.Baseline &&
		receipt.SpecSHA256 == manifest.SpecSHA256 &&
		receipt.SourceSetSHA256 == manifest.SourceSetSHA256 &&
		receipt.SourcePath == mutation.SourcePath &&
		receipt.SourceBeforeSHA256 == mutation.SourceSHA256 &&
		receipt.SourceAfterSHA256 == expectedAfter &&
		receipt.SourceAfterSHA256 != receipt.SourceBeforeSHA256 &&
		receipt.AnchorMatches == 1 &&
		receipt.ApplicationCount == 1 &&
		receipt.KillingTestID == mutation.KillingTestID &&
		receipt.ViolationMarker == mutation.ViolationMarker &&
		reflect.DeepEqual(receipt.ExpectedPristine, mutation.Pristine) &&
		reflect.DeepEqual(receipt.ExpectedMutant, mutation.Mutant)
}

func successfulNestedResult(
	result commandResult,
	command commandConfig,
	expectedEvent *goTestEventAttestation,
) bool {
	return result.ID == command.ID &&
		reflect.DeepEqual(result.Contract, commandEvidenceForConfig(command)) &&
		equalStrings(result.Argv, command.Argv) &&
		result.CWD == command.CWD &&
		result.ExitCode == command.RequiredExitCode &&
		validSHA256(result.StdoutSHA256) &&
		validSHA256(result.StderrSHA256) &&
		!result.TimedOut &&
		result.TerminationErr == "" &&
		result.WaitErr == "" &&
		reflect.DeepEqual(result.GoTestEvent, expectedEvent) &&
		len(result.ObservedIDs) == 0 &&
		len(result.SkipEvents) == 0 &&
		len(result.Mutations) == 0 &&
		len(result.ClosedThreatIDs) == 0 &&
		result.LintResult == nil &&
		result.ScanResult == nil
}

func validateSkipEvents(skips []skipEvent) error {
	if len(skips) != 0 {
		return errors.New("runtime skip events are forbidden")
	}
	return nil
}

func validateCompleteClosure(
	config *gateConfig,
	inspected []inspectedStage,
) error {
	if len(inspected) != len(config.EvidenceContract.RequiredStageNames) {
		return errors.New("incomplete stage closure")
	}
	var closed []string
	for index := range inspected {
		if inspected[index].evidence.Stage !=
			config.EvidenceContract.RequiredStageNames[index] {
			return errors.New("stage closure order mismatch")
		}
		closed = append(closed, inspected[index].evidence.ClosedThreatIDs...)
	}
	if !sameStringSet(closed, config.RequiredThreatIDs) ||
		hasDuplicates(closed) {
		return errors.New("exact threat closure mismatch")
	}
	return nil
}

func cleanAbsoluteNoSymlink(path string) (string, error) {
	cleaned, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	volume := filepath.VolumeName(cleaned)
	root := volume + string(os.PathSeparator)
	relative := strings.TrimPrefix(cleaned, root)
	current := root
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("path contains symlink component %q", current)
		}
	}
	return cleaned, nil
}

func stableDirectoryTreeSnapshot(
	session *inspectionSession,
	root string,
) (treeIdentity, []treeEntry, error) {
	before, err := session.directoryIdentity(root)
	if err != nil {
		return treeIdentity{}, nil, err
	}
	first, firstEntries, err := directoryTreeSnapshot(session, before.Path)
	if err != nil {
		return treeIdentity{}, nil, err
	}
	second, secondEntries, err := directoryTreeSnapshot(session, before.Path)
	if err != nil {
		return treeIdentity{}, nil, err
	}
	after, err := session.directoryIdentity(before.Path)
	if err != nil {
		return treeIdentity{}, nil, err
	}
	if before != after ||
		first != second ||
		!reflect.DeepEqual(firstEntries, secondEntries) {
		return treeIdentity{}, nil, errors.New(
			"source tree changed while the inspector hashed it",
		)
	}
	return first, firstEntries, nil
}

func directoryTreeSnapshot(
	session *inspectionSession,
	root string,
) (treeIdentity, []treeEntry, error) {
	hasher := sha256.New()
	var entries []treeEntry
	var walk func(string, string) error
	walk = func(path string, relative string) error {
		names, err := session.readDirectoryNames(path)
		if err != nil {
			return err
		}
		state := session.directories[path]
		record := treeEntry{
			Path: filepath.ToSlash(relative),
			Type: "directory",
			Mode: uint32(state.info.Mode()),
			Size: state.info.Size(),
		}
		encoded, err := canonicalJSON(record)
		if err != nil {
			return err
		}
		if _, err := hasher.Write(encoded); err != nil {
			return err
		}
		entries = append(entries, record)

		bound, err := session.rootForDirectory(path, false)
		if err != nil {
			return err
		}
		for _, name := range names {
			childPath := filepath.Join(path, name)
			childRelative := filepath.Join(relative, name)
			info, err := bound.root.Lstat(name)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf(
					"unsupported source-tree entry %q",
					filepath.ToSlash(childRelative),
				)
			}
			if info.IsDir() {
				if err := walk(childPath, childRelative); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf(
					"unsupported source-tree entry %q",
					filepath.ToSlash(childRelative),
				)
			}
			_, identity, err := session.readBoundedFile(
				childPath,
				maxInspectorInputBytes,
			)
			if err != nil {
				return err
			}
			fileRecord := treeEntry{
				Path:   filepath.ToSlash(childRelative),
				Type:   "regular",
				Mode:   identity.Mode,
				Size:   identity.Size,
				SHA256: identity.SHA256,
			}
			encoded, err := canonicalJSON(fileRecord)
			if err != nil {
				return err
			}
			if _, err := hasher.Write(encoded); err != nil {
				return err
			}
			entries = append(entries, fileRecord)
		}
		return nil
	}
	if err := walk(root, "."); err != nil {
		return treeIdentity{}, nil, err
	}
	return treeIdentity{
		SHA256:     hex.EncodeToString(hasher.Sum(nil)),
		EntryCount: len(entries),
	}, entries, nil
}

func decodeStrictJSON(data []byte, value any, canonical bool) error {
	if value == nil {
		return errors.New("nil JSON destination")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing values")
	}
	if canonical {
		encoded, err := canonicalJSON(value)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, encoded) {
			return errors.New("JSON is not canonical")
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing tokens")
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("JSON contains a duplicate object field")
			}
			seen[key] = true
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array is not terminated")
		}
	default:
		return errors.New("JSON contains an unexpected delimiter")
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

func executionSurfacesOverlap(
	left executionSurface,
	right executionSurface,
) bool {
	if left.EvidenceKind != right.EvidenceKind ||
		!sameStringSet(left.BuildTags, right.BuildTags) ||
		!setsIntersect(left.PackagePaths, right.PackagePaths) {
		return false
	}
	return selectorsOverlap(left.TestSelector, right.TestSelector)
}

func selectorsOverlap(left string, right string) bool {
	if left == "all" || right == "all" {
		return true
	}
	leftTests, leftExact := exactSelectorTests(left)
	rightTests, rightExact := exactSelectorTests(right)
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

func exactSelectorTests(selector string) ([][]string, bool) {
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

func threatsForCommand(
	config *gateConfig,
	stage string,
	command string,
) []string {
	var threats []string
	for _, closure := range config.ThreatClosure {
		if closure.Stage == stage && closure.CommandID == command {
			threats = append(threats, closure.ID)
		}
	}
	sort.Strings(threats)
	return threats
}

func threatsForStage(config *gateConfig, stage string) []string {
	var threats []string
	for _, closure := range config.ThreatClosure {
		if closure.Stage == stage {
			threats = append(threats, closure.ID)
		}
	}
	sort.Strings(threats)
	return threats
}

func commandConfigIDs(commands []commandConfig) []string {
	ids := make([]string, len(commands))
	for index := range commands {
		ids[index] = commands[index].ID
	}
	return ids
}

func commandByID(commands []commandConfig, id string) (commandConfig, bool) {
	for _, command := range commands {
		if command.ID == id {
			return command, true
		}
	}
	return commandConfig{}, false
}

func derivedPhaseJobs(online int) int {
	jobs := online / 2
	if jobs > 10 {
		return 10
	}
	return jobs
}

func sameFileIdentity(left fileIdentity, right fileIdentity) bool {
	return left == right
}

func sameExecutableIdentity(
	left executableIdentity,
	right executableIdentity,
) bool {
	return sameFileIdentity(left.File, right.File) &&
		left.GoBuildVersion == right.GoBuildVersion &&
		left.ModulePath == right.ModulePath &&
		left.MainPackagePath == right.MainPackagePath &&
		left.BuildInfoSHA256 == right.BuildInfoSHA256
}

func validOID(value string) bool {
	return len(value) == 40 &&
		strings.ToLower(value) == value &&
		validHex(value)
}

func validSHA256(value string) bool {
	return len(value) == sha256.Size*2 &&
		strings.ToLower(value) == value &&
		validHex(value)
}

func validHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func equalStrings(left []string, right []string) bool {
	return slices.Equal(left, right)
}

func equalSkipEvents(left []skipEvent, right []skipEvent) bool {
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

func sameStringSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return equalStrings(leftCopy, rightCopy)
}

func setsIntersect(left []string, right []string) bool {
	for _, value := range left {
		if contains(right, value) {
			return true
		}
	}
	return false
}

func subsetOf(values []string, allowed []string) bool {
	for _, value := range values {
		if !contains(allowed, value) {
			return false
		}
	}
	return true
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func hasDuplicates(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}
