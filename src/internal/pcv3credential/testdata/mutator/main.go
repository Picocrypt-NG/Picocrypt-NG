package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const manifestSchemaVersion = 1

var exactArgvTemplate = []string{
	"phase2-mutator",
	"--source-copy", "${SOURCE_COPY}",
	"--manifest", "${MUTATION_MANIFEST}",
	"--mutation-id", "${MUTATION_ID}",
	"--source-set-sha256", "${SOURCE_SET_SHA256}",
	"--baseline", "${BASELINE}",
	"--spec-sha256", "${SPEC_SHA256}",
	"--result", "${RESULT}",
}

type mutationManifest struct {
	SchemaVersion   int            `json:"schema_version"`
	SpecSHA256      string         `json:"spec_sha256"`
	SourceSetSHA256 string         `json:"source_set_sha256"`
	ArgvTemplate    []string       `json:"argv_template"`
	Mutations       []mutationSpec `json:"mutations"`
}

type mutationSpec struct {
	ID              string          `json:"id"`
	Requirement     string          `json:"requirement"`
	Invariant       string          `json:"invariant"`
	SourcePath      string          `json:"source_path"`
	SourceSHA256    string          `json:"source_sha256"`
	Anchor          string          `json:"anchor"`
	Replacement     string          `json:"replacement"`
	KillingTestID   string          `json:"killing_test_id"`
	ViolationMarker string          `json:"expected_violation_marker"`
	Pristine        mutationOutcome `json:"pristine"`
	Mutant          mutationOutcome `json:"mutant"`
}

type mutationOutcome struct {
	Status          string          `json:"status"`
	Execution       string          `json:"execution"`
	SemanticCommand []string        `json:"semantic_command"`
	TestID          string          `json:"test_id"`
	ViolationMarker string          `json:"violation_marker"`
	Stage           string          `json:"stage"`
	Reason          string          `json:"reason"`
	Skipped         bool            `json:"skipped"`
	CompileOnly     bool            `json:"compile_only"`
	Counts          *mutationCounts `json:"counts"`
}

type mutationCounts struct {
	EntropyCalls         *int `json:"entropy_calls"`
	KDFCalls             *int `json:"kdf_calls"`
	ExpandCalls          *int `json:"expand_calls"`
	OwnerPublications    *int `json:"owner_publications"`
	ActiveBorrows        *int `json:"active_borrows"`
	UnclearedOwnedBuffer *int `json:"uncleared_owned_buffers"`
}

type mutationResult struct {
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
	ExpectedPristine   mutationOutcome `json:"expected_pristine"`
	ExpectedMutant     mutationOutcome `json:"expected_mutant"`
}

type commandOptions struct {
	sourceCopy   string
	manifest     string
	mutationID   string
	sourceSetSHA string
	baseline     string
	specSHA      string
	result       string
}

type sourceIdentity struct {
	path string
	hash string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if runtime.GOOS == "js" || runtime.GOOS == "plan9" {
		return errors.New("source-copy mutation is unsupported on this platform")
	}
	options, err := parseOptions(args)
	if err != nil {
		return err
	}
	manifest, err := loadManifest(options.manifest)
	if err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	if !validCommitID(options.baseline) {
		return errors.New("runtime baseline must be a lowercase full object ID")
	}
	if manifest.SpecSHA256 != options.specSHA {
		return errors.New("specification identity mismatch")
	}
	if manifest.SourceSetSHA256 != options.sourceSetSHA {
		return errors.New("source-set identity mismatch")
	}

	mutation, err := selectMutation(manifest, options.mutationID)
	if err != nil {
		return err
	}
	rootPath, target, err := confinedTarget(
		options.sourceCopy,
		mutation.SourcePath,
	)
	if err != nil {
		return err
	}
	if err := rejectLiveCheckout(rootPath); err != nil {
		return err
	}
	if err := ensureResultAvailable(options.result); err != nil {
		return err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open source-copy root: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()
	original, mode, err := readRegularNoSymlink(root, target)
	if err != nil {
		return err
	}
	beforeHash := sha256Hex(original)
	if beforeHash != mutation.SourceSHA256 {
		return errors.New("mutation source hash drift")
	}
	matches := bytes.Count(original, []byte(mutation.Anchor))
	if matches != 1 {
		return fmt.Errorf("mutation anchor matches = %d; want exactly 1", matches)
	}
	if mutation.Anchor == mutation.Replacement {
		return errors.New("mutation replacement is a no-op")
	}
	mutated := bytes.Replace(
		original,
		[]byte(mutation.Anchor),
		[]byte(mutation.Replacement),
		1,
	)
	if bytes.Equal(mutated, original) {
		return errors.New("mutation did not change source bytes")
	}
	if err := atomicReplace(root, target, mutated, mode); err != nil {
		return err
	}

	result := mutationResult{
		SchemaVersion:      manifestSchemaVersion,
		MutationID:         mutation.ID,
		BaselineCommit:     options.baseline,
		SpecSHA256:         manifest.SpecSHA256,
		SourceSetSHA256:    manifest.SourceSetSHA256,
		SourcePath:         mutation.SourcePath,
		SourceBeforeSHA256: beforeHash,
		SourceAfterSHA256:  sha256Hex(mutated),
		AnchorMatches:      matches,
		ApplicationCount:   1,
		KillingTestID:      mutation.KillingTestID,
		ViolationMarker:    mutation.ViolationMarker,
		ExpectedPristine:   mutation.Pristine,
		ExpectedMutant:     mutation.Mutant,
	}
	if err := validateMutationResult(
		manifest,
		mutation,
		options.baseline,
		&result,
	); err != nil {
		return err
	}
	if err := writeCanonicalResult(options.result, result); err != nil {
		if rollbackErr := atomicReplace(root, target, original, mode); rollbackErr != nil {
			return fmt.Errorf(
				"%w; source-copy rollback also failed: %w",
				err,
				rollbackErr,
			)
		}
		return fmt.Errorf("%w; source copy rolled back", err)
	}
	return nil
}

func validateMutationResult(
	manifest *mutationManifest,
	mutation *mutationSpec,
	baseline string,
	result *mutationResult,
) error {
	if manifest == nil || mutation == nil || result == nil ||
		result.SchemaVersion != manifestSchemaVersion ||
		result.MutationID != mutation.ID ||
		result.BaselineCommit != baseline ||
		result.SpecSHA256 != manifest.SpecSHA256 ||
		result.SourceSetSHA256 != manifest.SourceSetSHA256 ||
		result.SourcePath != mutation.SourcePath ||
		!validSHA256(result.SourceBeforeSHA256) ||
		!validSHA256(result.SourceAfterSHA256) ||
		result.SourceBeforeSHA256 == result.SourceAfterSHA256 ||
		result.AnchorMatches != 1 ||
		result.ApplicationCount != 1 ||
		result.KillingTestID != mutation.KillingTestID ||
		result.ViolationMarker != mutation.ViolationMarker ||
		!equalOutcome(result.ExpectedPristine, mutation.Pristine) ||
		!equalOutcome(result.ExpectedMutant, mutation.Mutant) {
		return errors.New("mutation result does not match frozen manifest contract")
	}
	return nil
}

func parseOptions(args []string) (commandOptions, error) {
	var options commandOptions
	allowed := map[string]bool{
		"--source-copy":       true,
		"--manifest":          true,
		"--mutation-id":       true,
		"--source-set-sha256": true,
		"--baseline":          true,
		"--spec-sha256":       true,
		"--result":            true,
	}
	seen := make(map[string]bool, len(allowed))
	if len(args) != len(allowed)*2 {
		return options, errors.New("exactly seven flag/value pairs are required")
	}
	for i := 0; i < len(args); i += 2 {
		name := args[i]
		expectedName := exactArgvTemplate[i+1]
		if name != expectedName {
			return options, fmt.Errorf(
				"mutator flag %d = %q; want exact argv flag %q",
				i/2,
				name,
				expectedName,
			)
		}
		if !allowed[name] {
			return options, fmt.Errorf("unknown mutator flag %q", name)
		}
		if seen[name] {
			return options, fmt.Errorf("duplicate mutator flag %q", name)
		}
		if args[i+1] == "" {
			return options, fmt.Errorf("empty mutator flag value for %q", name)
		}
		seen[name] = true
	}

	flags := flag.NewFlagSet("phase2-mutator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.sourceCopy, "source-copy", "", "")
	flags.StringVar(&options.manifest, "manifest", "", "")
	flags.StringVar(&options.mutationID, "mutation-id", "", "")
	flags.StringVar(
		&options.sourceSetSHA,
		"source-set-sha256",
		"",
		"",
	)
	flags.StringVar(&options.baseline, "baseline", "", "")
	flags.StringVar(&options.specSHA, "spec-sha256", "", "")
	flags.StringVar(&options.result, "result", "", "")
	if err := flags.Parse(args); err != nil {
		return options, fmt.Errorf("parse mutator flags: %w", err)
	}
	if flags.NArg() != 0 {
		return options, errors.New("positional mutator arguments are forbidden")
	}
	return options, nil
}

func loadManifest(path string) (*mutationManifest, error) {
	root, name, err := openParentRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open mutation manifest parent: %w", err)
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open mutation manifest: %w", err)
	}
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf(
			"read mutation manifest: %w",
			errors.Join(readErr, closeErr),
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest mutationManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode mutation manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("mutation manifest has trailing JSON")
	}
	return &manifest, nil
}

func validateManifest(manifest *mutationManifest) error {
	if manifest == nil ||
		manifest.SchemaVersion != manifestSchemaVersion ||
		!validSHA256(manifest.SpecSHA256) ||
		!validSHA256(manifest.SourceSetSHA256) ||
		!equalStrings(manifest.ArgvTemplate, exactArgvTemplate) ||
		len(manifest.Mutations) == 0 {
		return errors.New("invalid mutation manifest header")
	}

	ids := make(map[string]bool, len(manifest.Mutations))
	sources := make(map[string]string)
	for i := range manifest.Mutations {
		mutation := &manifest.Mutations[i]
		if ids[mutation.ID] {
			return fmt.Errorf("duplicate mutation ID %q", mutation.ID)
		}
		ids[mutation.ID] = true
		if err := validateMutation(mutation); err != nil {
			return fmt.Errorf("mutation %q: %w", mutation.ID, err)
		}
		if hash, exists := sources[mutation.SourcePath]; exists &&
			hash != mutation.SourceSHA256 {
			return fmt.Errorf(
				"mutation source %q has conflicting hashes",
				mutation.SourcePath,
			)
		}
		sources[mutation.SourcePath] = mutation.SourceSHA256
	}
	if sourceSetHash(sources) != manifest.SourceSetSHA256 {
		return errors.New("source-set hash does not match mutation sources")
	}
	return nil
}

func validateMutation(mutation *mutationSpec) error {
	if !validMutationID(mutation.ID) ||
		!validRequirement(mutation.Requirement) ||
		mutation.Invariant == "" ||
		!validRelativePath(mutation.SourcePath) ||
		!validSHA256(mutation.SourceSHA256) ||
		mutation.Anchor == "" ||
		mutation.Replacement == "" ||
		mutation.Anchor == mutation.Replacement ||
		!strings.HasPrefix(mutation.KillingTestID, "Test") ||
		mutation.ViolationMarker == "" {
		return errors.New("missing or invalid required mutation field")
	}
	if err := validateOutcome(
		mutation.KillingTestID,
		mutation.ViolationMarker,
		"PASS",
		"",
		&mutation.Pristine,
	); err != nil {
		return fmt.Errorf("pristine outcome: %w", err)
	}
	if err := validateOutcome(
		mutation.KillingTestID,
		mutation.ViolationMarker,
		"FAIL",
		mutation.ViolationMarker,
		&mutation.Mutant,
	); err != nil {
		return fmt.Errorf("mutant outcome: %w", err)
	}
	return nil
}

func validateOutcome(
	killingTestID string,
	violationMarker string,
	status string,
	marker string,
	outcome *mutationOutcome,
) error {
	if outcome == nil ||
		outcome.Status != status ||
		outcome.Execution != "semantic" ||
		outcome.TestID != killingTestID ||
		outcome.ViolationMarker != marker ||
		outcome.Stage == "" ||
		outcome.Reason == "" ||
		outcome.Skipped ||
		outcome.CompileOnly ||
		outcome.Counts == nil ||
		len(outcome.SemanticCommand) == 0 {
		return errors.New("incomplete semantic outcome")
	}
	if status == "FAIL" && outcome.ViolationMarker != violationMarker {
		return errors.New("mutant violation marker mismatch")
	}
	if !semanticCommandKills(outcome.SemanticCommand, killingTestID) {
		return errors.New("outcome command is not the named semantic test")
	}
	if !completeNonnegativeCounts(outcome.Counts) {
		return errors.New("outcome does not contain six nonnegative counts")
	}
	return nil
}

func semanticCommandKills(command []string, killingTestID string) bool {
	expected := []string{
		"go",
		"test",
		"./internal/pcv3credential",
		"-run",
		"^" + killingTestID + "$",
		"-count=1",
	}
	return equalStrings(command, expected)
}

func completeNonnegativeCounts(counts *mutationCounts) bool {
	values := []*int{
		counts.EntropyCalls,
		counts.KDFCalls,
		counts.ExpandCalls,
		counts.OwnerPublications,
		counts.ActiveBorrows,
		counts.UnclearedOwnedBuffer,
	}
	for _, value := range values {
		if value == nil || *value < 0 {
			return false
		}
	}
	return true
}

func selectMutation(
	manifest *mutationManifest,
	id string,
) (*mutationSpec, error) {
	var selected *mutationSpec
	for i := range manifest.Mutations {
		if manifest.Mutations[i].ID == id {
			if selected != nil {
				return nil, errors.New("mutation ID is ambiguous")
			}
			selected = &manifest.Mutations[i]
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("unknown mutation ID %q", id)
	}
	return selected, nil
}

func confinedTarget(
	sourceCopy string,
	sourcePath string,
) (root string, target string, err error) {
	root, err = filepath.Abs(sourceCopy)
	if err != nil {
		return "", "", fmt.Errorf("resolve source-copy root: %w", err)
	}
	root = filepath.Clean(root)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", "", fmt.Errorf("inspect source-copy root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("source-copy root must be a non-symlink directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || resolvedRoot != root {
		return "", "", errors.New("source-copy root contains a symlink")
	}
	if !validRelativePath(sourcePath) {
		return "", "", errors.New("mutation source path is not confined")
	}
	return root, filepath.FromSlash(sourcePath), nil
}

func rejectLiveCheckout(root string) error {
	for current := root; ; current = filepath.Dir(current) {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return errors.New("refusing to mutate inside a live Git checkout")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect source-copy Git marker: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func readRegularNoSymlink(
	root *os.Root,
	path string,
) ([]byte, os.FileMode, error) {
	info, err := root.Lstat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("inspect mutation source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("mutation source must be a regular non-symlink file")
	}
	data, err := root.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read mutation source: %w", err)
	}
	return data, info.Mode().Perm(), nil
}

func ensureResultAvailable(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve mutation result: %w", err)
	}
	parent := filepath.Dir(absolute)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect mutation result directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("mutation result directory must be a non-symlink directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errors.New("mutation result directory contains a symlink")
	}
	if _, err := os.Lstat(absolute); err == nil {
		return errors.New("mutation result already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect mutation result: %w", err)
	}
	return nil
}

func atomicReplace(
	root *os.Root,
	path string,
	data []byte,
	mode os.FileMode,
) error {
	directory := filepath.Dir(path)
	temporary := filepath.Join(directory, ".phase2-mutator.tmp")
	file, err := root.OpenFile(
		temporary,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		mode,
	)
	if err != nil {
		return fmt.Errorf("create mutation temporary: %w", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = root.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write mutation temporary: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync mutation temporary: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close mutation temporary: %w", err)
	}
	if err := root.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace mutation source: %w", err)
	}
	keep = true
	return nil
}

func writeCanonicalResult(path string, result mutationResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode mutation result: %w", err)
	}
	data = append(data, '\n')
	root, name, err := openParentRoot(path)
	if err != nil {
		return fmt.Errorf("open mutation result parent: %w", err)
	}
	defer root.Close()
	file, err := root.OpenFile(
		name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create mutation result: %w", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = root.Remove(name)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write mutation result: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync mutation result: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close mutation result: %w", err)
	}
	keep = true
	return nil
}

func openParentRoot(path string) (*os.Root, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, "", err
	}
	return root, filepath.Base(absolute), nil
}

func sourceSetHash(sources map[string]string) string {
	identities := make([]sourceIdentity, 0, len(sources))
	for path, hash := range sources {
		identities = append(identities, sourceIdentity{path: path, hash: hash})
	}
	sort.Slice(identities, func(i, j int) bool {
		return identities[i].path < identities[j].path
	})
	hasher := sha256.New()
	for _, identity := range identities {
		_, _ = hasher.Write([]byte(identity.path))
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(identity.hash))
		_, _ = hasher.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func validMutationID(id string) bool {
	prefixes := []string{
		"M-CRD06-",
		"M-CRD07-",
		"M-CRD08-",
		"M-CRD09-",
		"M-CRD10-",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(id, prefix) && len(id) > len(prefix) {
			return true
		}
	}
	return false
}

func validRequirement(requirement string) bool {
	switch requirement {
	case "CRD-06", "CRD-07", "CRD-08", "CRD-09", "CRD-10":
		return true
	default:
		return false
	}
}

func validRelativePath(path string) bool {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return false
	}
	cleaned := filepath.Clean(filepath.FromSlash(path))
	return cleaned != "." &&
		cleaned != ".." &&
		!strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) &&
		filepath.ToSlash(cleaned) == path
}

func validCommitID(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalOutcome(left, right mutationOutcome) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
