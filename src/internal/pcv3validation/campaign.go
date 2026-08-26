package pcv3validation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Classification is the closed per-mutation terminal vocabulary. Only
// ClassKilled counts; every other state fails the campaign.
type Classification string

const (
	ClassKilled            Classification = "killed"
	ClassSurvived          Classification = "survived"
	ClassPristineFailed    Classification = "pristine-failed"
	ClassPristineMissing   Classification = "pristine-missing"
	ClassSelectorMissing   Classification = "selector-missing"
	ClassRequiredSkip      Classification = "required-skip"
	ClassUnexpectedTest    Classification = "unexpected-test"
	ClassUnrelatedFailure  Classification = "unrelated-failure"
	ClassMarkerMissing     Classification = "marker-missing"
	ClassCompileFailed     Classification = "compile-failed"
	ClassSourceDrift       Classification = "source-drift"
	ClassTransformInvalid  Classification = "transform-invalid"
	ClassConfinementFailed Classification = "confinement-failed"
	ClassEventInvalid      Classification = "event-invalid"
	ClassTimeout           Classification = "timeout"
	ClassSetupFailed       Classification = "setup-failed"
	ClassCleanupFailed     Classification = "cleanup-failed"
)

// classificationDiagnostics maps each closed classification to one stable
// closed diagnostic string.
var classificationDiagnostics = map[Classification]string{
	ClassKilled:            "named-oracle-failed-with-frozen-marker",
	ClassSurvived:          "named-oracle-passed",
	ClassPristineFailed:    "pristine-oracle-did-not-pass",
	ClassPristineMissing:   "pristine-event-missing",
	ClassSelectorMissing:   "named-selector-missing",
	ClassRequiredSkip:      "required-skip-observed",
	ClassUnexpectedTest:    "unexpected-test-in-stream",
	ClassUnrelatedFailure:  "failure-unrelated-to-named-oracle",
	ClassMarkerMissing:     "frozen-behavioral-marker-absent",
	ClassCompileFailed:     "mutated-package-did-not-compile",
	ClassSourceDrift:       "source-or-preimage-drift",
	ClassTransformInvalid:  "anchor-not-exactly-one-or-no-op",
	ClassConfinementFailed: "target-outside-ancestor-live-tree-or-symlink",
	ClassEventInvalid:      "event-stream-invalid",
	ClassTimeout:           "command-deadline-exceeded",
	ClassSetupFailed:       "campaign-setup-failed",
	ClassCleanupFailed:     "owned-copy-cleanup-failed",
}

const (
	copyDirPrefix      = "pcv3validation-campaign-"
	reportSchemaVer    = 1
	maxGoModBytes      = 1 << 20
	mutationTempSuffix = ".pcv3validation-mutant.tmp"
)

// CommandResult is the raw, transient outcome of one spawned command. Output
// is cleared as soon as it has been parsed; it never enters retained evidence.
type CommandResult struct {
	Output      []byte
	Err         error
	TimedOut    bool
	StartFailed bool
}

// CommandRunner executes argv inside dir with a per-command timeout.
type CommandRunner func(dir string, argv []string, timeout time.Duration) CommandResult

// ExecCommandRunner is the production runner: one process per command,
// deadline-bound, with GOWORK pinned off.
func ExecCommandRunner(dir string, argv []string, timeout time.Duration) CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	output, err := cmd.CombinedOutput()
	result := CommandResult{Output: output, Err: err, TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)}
	var exitErr *exec.ExitError
	result.StartFailed = err != nil && !result.TimedOut && !errors.As(err, &exitErr)
	return result
}

// CampaignConfig binds one campaign execution. SourceRoot is read-only (it
// may be a live checkout; it is never mutated). WorkParent must be outside
// any live checkout and outside SourceRoot; the campaign creates one private
// copy beneath it and removes exactly that copy on every exit. All paths must
// be absolute and clean.
type CampaignConfig struct {
	SourceRoot     string
	WorkParent     string
	Manifest       *Manifest
	ManifestSHA256 string
	Runner         CommandRunner
	Timeout        time.Duration
}

// MutationReport is the closed retained record of one mutation. It carries
// only stable IDs, hashes, counts, and closed states: never raw output,
// absolute paths, anchors, or replacements.
type MutationReport struct {
	ID              string         `json:"id"`
	Family          string         `json:"family"`
	SourcePath      string         `json:"source_path"`
	SourceSHA256    string         `json:"source_sha256"`
	PostimageSHA256 string         `json:"postimage_sha256"`
	Package         string         `json:"package"`
	Test            string         `json:"test"`
	Subtest         string         `json:"subtest"`
	Marker          string         `json:"marker"`
	Observations    Observations   `json:"observations"`
	Classification  Classification `json:"classification"`
	Diagnostic      string         `json:"diagnostic"`
	PristineRuns    int            `json:"pristine_runs"`
	PristinePasses  int            `json:"pristine_passes"`
	MutantRuns      int            `json:"mutant_runs"`
	MutantFails     int            `json:"mutant_fails"`
}

// CampaignReport is the closed campaign record.
type CampaignReport struct {
	SchemaVersion  int              `json:"schema_version"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	Mutations      []MutationReport `json:"mutations"`
	Killed         int              `json:"killed"`
	Total          int              `json:"total"`
}

// CampaignError reports a non-terminal campaign with closed data only.
type CampaignError struct {
	MutationID     string
	Classification Classification
}

func (err *CampaignError) Error() string {
	return fmt.Sprintf("mutation %s: %s", err.MutationID, classificationDiagnostics[err.Classification])
}

// RunCampaign executes the isolated source-copy campaign over the frozen
// manifest. It returns the closed report; the error is non-nil unless every
// mutation was killed. The pristine oracle runs first, the transform must
// compile in the isolated copy, and only the exact frozen behavioral failure
// of the same oracle counts as a kill.
func RunCampaign(config CampaignConfig) (report CampaignReport, retErr error) {
	report = CampaignReport{
		SchemaVersion:  reportSchemaVer,
		ManifestSHA256: config.ManifestSHA256,
	}
	if config.Manifest == nil || config.Runner == nil || config.Timeout <= 0 ||
		!validSHA256Hex(config.ManifestSHA256) {
		return report, &CampaignError{Classification: ClassSetupFailed}
	}
	if err := config.Manifest.Validate(); err != nil {
		return report, &CampaignError{Classification: ClassSetupFailed}
	}
	report.Total = len(config.Manifest.Mutations)
	sourceRoot, modulePath, rejection := validateSourceRoot(config.SourceRoot)
	if rejection != nil {
		return report, &CampaignError{Classification: rejection.Kind}
	}
	copyDir, rejection := prepareWorkParent(config.WorkParent, sourceRoot)
	if rejection != nil {
		return report, &CampaignError{Classification: rejection.Kind}
	}
	defer func() {
		if cleanup := removeOwnedCopy(config.WorkParent, copyDir); cleanup != nil && retErr == nil {
			retErr = &CampaignError{Classification: ClassCleanupFailed}
		}
	}()

	copyRoot, rejection := materializePrivateCopy(sourceRoot, copyDir)
	if rejection != nil {
		return report, &CampaignError{Classification: rejection.Kind}
	}
	defer func() { _ = copyRoot.Close() }()

	liveRoot, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return report, &CampaignError{Classification: ClassSetupFailed}
	}
	defer func() { _ = liveRoot.Close() }()

	for i := range config.Manifest.Mutations {
		mutation := &config.Manifest.Mutations[i]
		mutationReport := executeMutation(liveRoot, copyRoot, copyDir, modulePath, config, mutation)
		report.Mutations = append(report.Mutations, mutationReport)
		if mutationReport.Classification != ClassKilled {
			return report, &CampaignError{MutationID: mutation.ID, Classification: mutationReport.Classification}
		}
		report.Killed++
	}
	return report, nil
}

// executeMutation runs one pristine-transform-compile-mutant cycle and always
// restores the mutated file in the private copy.
func executeMutation(
	liveRoot *os.Root,
	copyRoot *os.Root,
	copyDir string,
	modulePath string,
	config CampaignConfig,
	mutation *Mutation,
) MutationReport {
	report := MutationReport{
		ID:             mutation.ID,
		Family:         mutation.Family,
		SourcePath:     mutation.SourcePath,
		SourceSHA256:   mutation.SourceSHA256,
		Package:        mutation.Package,
		Test:           mutation.Test,
		Subtest:        mutation.RequiredSubtest(),
		Marker:         mutation.Marker,
		Observations:   mutation.Observations,
		Classification: ClassSetupFailed,
	}
	setTerminal := func(kind Classification) MutationReport {
		report.Classification = kind
		report.Diagnostic = classificationDiagnostics[kind]
		return report
	}
	selector := OracleSelector{
		EventPackage: modulePath + "/" + strings.TrimPrefix(mutation.Package, "./"),
		Test:         mutation.Test,
		Subtest:      mutation.RequiredSubtest(),
	}

	live, kind := readConfinedSource(liveRoot, mutation.SourcePath)
	if kind != "" {
		return setTerminal(kind)
	}
	if sha256Hex(live) != mutation.SourceSHA256 {
		clear(live)
		return setTerminal(ClassSourceDrift)
	}
	clear(live)

	pristine := config.Runner(copyDir, oracleCommand(mutation), config.Timeout)
	kind = classifyCommand(pristine, func(events []TestEvent) *Rejection {
		inventory, rejection := AcceptPristine(events, selector)
		report.PristineRuns = inventory.Runs
		report.PristinePasses = inventory.Passes
		return rejection
	})
	clear(pristine.Output)
	if kind != "" {
		return setTerminal(kind)
	}

	original, kind := readConfinedSource(copyRoot, mutation.SourcePath)
	if kind != "" {
		return setTerminal(kind)
	}
	mutated, kind := applyTransform(original, mutation)
	if kind != "" {
		clear(original)
		return setTerminal(kind)
	}
	report.PostimageSHA256 = sha256Hex(mutated)
	mode, kind := confinedMode(copyRoot, mutation.SourcePath)
	if kind != "" {
		clear(original)
		clear(mutated)
		return setTerminal(kind)
	}
	if replaceKind := replaceConfinedSource(copyRoot, mutation.SourcePath, mutated, mode); replaceKind != "" {
		clear(original)
		clear(mutated)
		return setTerminal(replaceKind)
	}
	clear(mutated)
	restored := false
	defer func() {
		if !restored {
			_ = replaceConfinedSource(copyRoot, mutation.SourcePath, original, mode)
		}
		clear(original)
	}()

	compile := config.Runner(copyDir, compileCommand(mutation), config.Timeout)
	kind = classifyCompile(compile)
	clear(compile.Output)
	if kind != "" {
		return setTerminal(kind)
	}

	mutant := config.Runner(copyDir, oracleCommand(mutation), config.Timeout)
	killed := false
	kind = classifyCommand(mutant, func(events []TestEvent) *Rejection {
		inventory, rejection := AcceptMutant(events, selector, mutation.Marker, mutant.Err != nil)
		report.MutantRuns = inventory.Runs
		report.MutantFails = inventory.Fails
		killed = rejection == nil
		return rejection
	})
	clear(mutant.Output)
	if !killed && kind == "" {
		kind = ClassEventInvalid
	}

	if replaceKind := replaceConfinedSource(copyRoot, mutation.SourcePath, original, mode); replaceKind != "" {
		return setTerminal(ClassCleanupFailed)
	}
	restored = true
	if !confinedHashMatches(copyRoot, mutation.SourcePath, mutation.SourceSHA256) {
		return setTerminal(ClassCleanupFailed)
	}
	if kind != "" {
		return setTerminal(kind)
	}
	return setTerminal(ClassKilled)
}

// classifyCommand parses one event stream and applies the acceptance
// function, mapping runner and parser failures onto closed classifications.
func classifyCommand(result CommandResult, accept func([]TestEvent) *Rejection) Classification {
	if result.TimedOut {
		return ClassTimeout
	}
	if result.StartFailed {
		return ClassSetupFailed
	}
	events, err := ParseTestEvents(result.Output)
	if err != nil {
		return ClassEventInvalid
	}
	if rejection := accept(events); rejection != nil {
		return rejection.Kind
	}
	return ""
}

func classifyCompile(result CommandResult) Classification {
	if result.TimedOut {
		return ClassTimeout
	}
	if result.StartFailed {
		return ClassSetupFailed
	}
	if result.Err != nil {
		return ClassCompileFailed
	}
	return ""
}

// applyTransform verifies the preimage and the exactly-one anchor and returns
// the postimage, refusing no-op outcomes.
func applyTransform(original []byte, mutation *Mutation) ([]byte, Classification) {
	if sha256Hex(original) != mutation.SourceSHA256 {
		return nil, ClassSourceDrift
	}
	anchor := []byte(mutation.Anchor)
	if bytes.Count(original, anchor) != 1 {
		return nil, ClassTransformInvalid
	}
	mutated := bytes.Replace(original, anchor, []byte(mutation.ReplacementText()), 1)
	if bytes.Equal(mutated, original) || sha256Hex(mutated) == mutation.SourceSHA256 {
		return nil, ClassTransformInvalid
	}
	return mutated, ""
}

func oracleCommand(mutation *Mutation) []string {
	return []string{
		"go", "test", "-json", "-p", "1", "-count=1",
		"-run", "^" + mutation.Test + "$", mutation.Package,
	}
}

// compileCommand compiles the package that owns the transformed file (which
// may differ from the oracle's package).
func compileCommand(mutation *Mutation) []string {
	return []string{
		"go", "test", "-json", "-p", "1", "-count=1",
		"-run", "^$", "./" + path.Dir(mutation.SourcePath),
	}
}

// validateSourceRoot verifies the read-only source root and returns its
// absolute path and module path.
func validateSourceRoot(root string) (string, string, *Rejection) {
	absolute, rejection := confinedDirectory(root)
	if rejection != nil {
		return "", "", rejection
	}
	osRoot, err := os.OpenRoot(absolute)
	if err != nil {
		return "", "", &Rejection{Kind: ClassSetupFailed, Detail: "open source root"}
	}
	defer func() { _ = osRoot.Close() }()
	goMod, err := osRoot.ReadFile("go.mod")
	if err != nil || len(goMod) > maxGoModBytes {
		return "", "", &Rejection{Kind: ClassSetupFailed, Detail: "source root has no readable go.mod"}
	}
	for line := range strings.Lines(string(goMod)) {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "module" && !strings.ContainsAny(fields[1], "\"'") {
			return absolute, fields[1], nil
		}
	}
	return "", "", &Rejection{Kind: ClassSetupFailed, Detail: "go.mod has no module directive"}
}

// prepareWorkParent validates the work parent (outside the source root and
// outside any live checkout) and creates the fresh private copy directory.
func prepareWorkParent(workParent, sourceRoot string) (string, *Rejection) {
	parent, rejection := confinedDirectory(workParent)
	if rejection != nil {
		return "", rejection
	}
	if within, err := pathWithin(sourceRoot, parent); err != nil || within {
		return "", &Rejection{Kind: ClassConfinementFailed, Detail: "work parent is the source root or inside it"}
	}
	if insideLiveCheckout(parent) {
		return "", &Rejection{Kind: ClassConfinementFailed, Detail: "work parent is inside a live checkout"}
	}
	copyDir, err := os.MkdirTemp(parent, copyDirPrefix)
	if err != nil {
		return "", &Rejection{Kind: ClassSetupFailed, Detail: "create private copy directory"}
	}
	return copyDir, nil
}

// materializePrivateCopy copies the source tree into the fresh copy
// directory, rejecting symlinks and non-regular entries so no escape is
// possible. VCS metadata is never copied.
func materializePrivateCopy(sourceRoot, copyDir string) (*os.Root, *Rejection) {
	srcFS := os.DirFS(sourceRoot)
	copyRoot, err := os.OpenRoot(copyDir)
	if err != nil {
		return nil, &Rejection{Kind: ClassSetupFailed, Detail: "open private copy root"}
	}
	keep := false
	defer func() {
		if !keep {
			_ = copyRoot.Close()
		}
	}()
	walkErr := fs.WalkDir(srcFS, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return errors.New("loose .git entry")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink escape in source tree")
		}
		if entry.IsDir() {
			if path == "." {
				return nil
			}
			return copyRoot.MkdirAll(filepath.FromSlash(path), 0o700)
		}
		if !entry.Type().IsRegular() {
			return errors.New("non-regular entry in source tree")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := fs.ReadFile(srcFS, path)
		if err != nil {
			return err
		}
		if err := copyRoot.WriteFile(filepath.FromSlash(path), data, info.Mode().Perm()|0o600); err != nil {
			return err
		}
		clear(data)
		return nil
	})
	if walkErr != nil {
		return nil, &Rejection{Kind: ClassConfinementFailed, Detail: "source tree copy failed confinement"}
	}
	keep = true
	return copyRoot, nil
}

// removeOwnedCopy removes exactly the copy directory the campaign created and
// verifies it is gone.
func removeOwnedCopy(workParent, copyDir string) *Rejection {
	parent, rejection := confinedDirectory(workParent)
	if rejection != nil {
		return rejection
	}
	if filepath.Dir(copyDir) != parent || !strings.HasPrefix(filepath.Base(copyDir), copyDirPrefix) {
		return &Rejection{Kind: ClassCleanupFailed, Detail: "refusing to remove an unowned directory"}
	}
	info, err := os.Lstat(copyDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return &Rejection{Kind: ClassCleanupFailed, Detail: "inspect owned copy"}
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &Rejection{Kind: ClassCleanupFailed, Detail: "owned copy is not a real directory"}
	}
	if err := os.RemoveAll(copyDir); err != nil {
		return &Rejection{Kind: ClassCleanupFailed, Detail: "remove owned copy"}
	}
	if _, err := os.Lstat(copyDir); !errors.Is(err, os.ErrNotExist) {
		return &Rejection{Kind: ClassCleanupFailed, Detail: "owned copy residue remains"}
	}
	return nil
}

// confinedDirectory validates an absolute, clean, non-symlink, fully resolved
// existing directory.
func confinedDirectory(path string) (string, *Rejection) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", &Rejection{Kind: ClassConfinementFailed, Detail: "path is not absolute and clean"}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", &Rejection{Kind: ClassConfinementFailed, Detail: "path is not a non-symlink directory"}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", &Rejection{Kind: ClassConfinementFailed, Detail: "path resolves through a symlink"}
	}
	return path, nil
}

// pathWithin reports whether child is equal to or beneath parent.
func pathWithin(parent, child string) (bool, error) {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false, err
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}

// insideLiveCheckout walks upward looking for a .git marker.
func insideLiveCheckout(root string) bool {
	for current := root; ; current = filepath.Dir(current) {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
	}
}

// readConfinedSource reads one allowlisted regular non-symlink file through
// rooted operations.
func readConfinedSource(root *os.Root, path string) ([]byte, Classification) {
	if !validSourcePath(path) {
		return nil, ClassConfinementFailed
	}
	info, err := root.Lstat(filepath.FromSlash(path))
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ClassSourceDrift
	}
	data, err := root.ReadFile(filepath.FromSlash(path))
	if err != nil {
		return nil, ClassSourceDrift
	}
	return data, ""
}

func confinedMode(root *os.Root, path string) (os.FileMode, Classification) {
	info, err := root.Lstat(filepath.FromSlash(path))
	if err != nil || !info.Mode().IsRegular() {
		return 0, ClassSourceDrift
	}
	return info.Mode().Perm(), ""
}

func confinedHashMatches(root *os.Root, path, expected string) bool {
	data, kind := readConfinedSource(root, path)
	if kind != "" {
		return false
	}
	defer clear(data)
	return sha256Hex(data) == expected
}

// replaceConfinedSource atomically replaces one file inside the rooted tree
// via an exclusive temporary plus rename.
func replaceConfinedSource(root *os.Root, path string, data []byte, mode os.FileMode) Classification {
	target := filepath.FromSlash(path)
	temporary := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+mutationTempSuffix)
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return ClassCleanupFailed
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = root.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return ClassCleanupFailed
	}
	if err := file.Sync(); err != nil {
		return ClassCleanupFailed
	}
	if err := file.Close(); err != nil {
		return ClassCleanupFailed
	}
	if err := root.Rename(temporary, target); err != nil {
		return ClassCleanupFailed
	}
	keep = true
	return ""
}
