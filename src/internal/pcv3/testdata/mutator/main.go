package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	manifestSchemaVersion = 1
	expectedSpecRevision  = "0.3"
	commandTimeout        = 10 * time.Minute
)

var canonicalCampaignCommand = []string{
	"go", "run", "./internal/pcv3/testdata/mutator",
	"-source-root", ".",
	"-manifest", "internal/pcv3/testdata/mutations.json",
	"-spec", "../docs/PCV3_FORMAT_SPEC.md",
	"-result", "../.planning/phases/03-isolated-routing-and-bounded-reader/03-MUTATION-REPORT.json",
}

type campaignOptions struct {
	sourceRoot string
	manifest   string
	spec       string
	result     string
}

type mutationManifest struct {
	SchemaVersion int            `json:"schema_version"`
	SpecRevision  string         `json:"spec_revision"`
	SpecSHA256    string         `json:"spec_sha256"`
	Mutations     []mutationSpec `json:"mutations"`
}

type mutationSpec struct {
	ID                      string `json:"id"`
	SpecRevision            string `json:"spec_revision"`
	SpecSHA256              string `json:"spec_sha256"`
	SourcePath              string `json:"source_path"`
	SourceSHA256            string `json:"source_sha256"`
	Anchor                  string `json:"anchor"`
	AnchorSHA256            string `json:"anchor_sha256"`
	Replacement             string `json:"replacement"`
	Package                 string `json:"package"`
	Test                    string `json:"test"`
	ExpectedAssertionMarker string `json:"expected_assertion_marker"`
}

type mutationResult struct {
	ID                      string   `json:"id"`
	SourcePath              string   `json:"source_path"`
	SourceSHA256            string   `json:"source_sha256"`
	AnchorSHA256            string   `json:"anchor_sha256"`
	Package                 string   `json:"package"`
	Test                    string   `json:"test"`
	ExpectedAssertionMarker string   `json:"expected_assertion_marker"`
	BaselineCommand         []string `json:"baseline_command"`
	CompileCommand          []string `json:"compile_command"`
	MutantCommand           []string `json:"mutant_command"`
	BaselineGreen           bool     `json:"baselineGreen"`
	Applied                 bool     `json:"applied"`
	Compiled                bool     `json:"compiled"`
	NamedAssertionFailed    bool     `json:"namedAssertionFailed"`
	Restored                bool     `json:"restored"`
	Killed                  bool     `json:"killed"`
}

type campaignReport struct {
	SchemaVersion  int              `json:"schema_version"`
	BaselineCommit string           `json:"baseline_commit"`
	BaselineTree   string           `json:"baseline_tree"`
	SpecRevision   string           `json:"spec_revision"`
	SpecSHA256     string           `json:"spec_sha256"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	Command        []string         `json:"command"`
	Mutations      []mutationResult `json:"mutations"`
}

type expectedMutation struct {
	sourcePath string
	pkg        string
	test       string
	marker     string
}

var expectedMutations = map[string]expectedMutation{
	"P3-ROUTE-ORDER-001": {
		sourcePath: "internal/volume/deniability.go",
		pkg:        "./internal/volume",
		test:       "TestRemoveDeniabilityRejectsBorrowedPCV3BeforeEffects",
		marker:     "want ErrReaderUnavailable",
	},
	"P3-NO-FALLBACK-001": {
		sourcePath: "internal/volume/pcv3_dispatch.go",
		pkg:        "./internal/volume",
		test:       "TestPCV3TerminalNoFallback",
		marker:     "want terminal typed PCV3 result",
	},
	"P3-LENGTH-GUARD-001": {
		sourcePath: "internal/pcv3/preamble.go",
		pkg:        "./internal/pcv3",
		test:       "TestParsePreamble",
		marker:     "want pcv3.Failure",
	},
}

type testEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	options, err := parseOptions(args)
	if err != nil {
		return err
	}
	if err := ensureResultAbsent(options.result); err != nil {
		return err
	}

	manifestBytes, manifest, err := loadManifest(options.manifest)
	if err != nil {
		return err
	}
	specBytes, err := os.ReadFile(options.spec)
	if err != nil {
		return fmt.Errorf("read specification: %w", err)
	}
	if sha256Hex(specBytes) != manifest.SpecSHA256 {
		return errors.New("specification hash drift")
	}

	sourceRoot, err := filepath.Abs(options.sourceRoot)
	if err != nil {
		return fmt.Errorf("resolve source root: %w", err)
	}
	repoRoot, err := gitValue(sourceRoot, "rev-parse", "--show-toplevel")
	if err != nil {
		return err
	}
	modulePath, err := filepath.Rel(repoRoot, sourceRoot)
	if err != nil || !validRelativePath(filepath.ToSlash(modulePath)) {
		return errors.New("source root is not a confined repository subdirectory")
	}
	baselineCommit, err := gitValue(sourceRoot, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	baselineTree, err := gitValue(sourceRoot, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	if !validObjectID(baselineCommit) || !validObjectID(baselineTree) {
		return errors.New("invalid baseline commit or tree identity")
	}

	results := make([]mutationResult, 0, len(manifest.Mutations))
	for _, mutation := range manifest.Mutations {
		result, err := executeMutation(repoRoot, filepath.ToSlash(modulePath), sourceRoot, baselineCommit, mutation)
		if err != nil {
			return fmt.Errorf("mutation %s: %w", mutation.ID, err)
		}
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })

	reportBytes, err := marshalReport(campaignReport{
		SchemaVersion:  manifestSchemaVersion,
		BaselineCommit: baselineCommit,
		BaselineTree:   baselineTree,
		SpecRevision:   manifest.SpecRevision,
		SpecSHA256:     manifest.SpecSHA256,
		ManifestSHA256: sha256Hex(manifestBytes),
		Command:        append([]string(nil), canonicalCampaignCommand...),
		Mutations:      results,
	})
	if err != nil {
		return err
	}
	return writeAtomicReport(options.result, reportBytes)
}

func parseOptions(args []string) (campaignOptions, error) {
	var options campaignOptions
	flags := flag.NewFlagSet("phase3-mutator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.sourceRoot, "source-root", "", "")
	flags.StringVar(&options.manifest, "manifest", "", "")
	flags.StringVar(&options.spec, "spec", "", "")
	flags.StringVar(&options.result, "result", "", "")
	if err := flags.Parse(args); err != nil {
		return options, fmt.Errorf("parse arguments: %w", err)
	}
	if flags.NArg() != 0 || options.sourceRoot == "" || options.manifest == "" || options.spec == "" || options.result == "" {
		return options, errors.New("source-root, manifest, spec, and result are required")
	}
	return options, nil
}

func loadManifest(path string) ([]byte, mutationManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, mutationManifest{}, fmt.Errorf("read manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest mutationManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, mutationManifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, mutationManifest{}, errors.New("manifest has trailing JSON")
	}
	if err := validateManifest(manifest); err != nil {
		return nil, mutationManifest{}, err
	}
	return data, manifest, nil
}

func validateManifest(manifest mutationManifest) error {
	if manifest.SchemaVersion != manifestSchemaVersion || manifest.SpecRevision != expectedSpecRevision || !validSHA256(manifest.SpecSHA256) {
		return errors.New("invalid manifest header")
	}
	if len(manifest.Mutations) != len(expectedMutations) {
		return fmt.Errorf("manifest mutations = %d; want exactly %d", len(manifest.Mutations), len(expectedMutations))
	}
	seen := make(map[string]bool, len(manifest.Mutations))
	for _, mutation := range manifest.Mutations {
		expected, ok := expectedMutations[mutation.ID]
		if !ok || seen[mutation.ID] {
			return fmt.Errorf("unexpected or duplicate mutation ID %q", mutation.ID)
		}
		seen[mutation.ID] = true
		if mutation.SpecRevision != manifest.SpecRevision || mutation.SpecSHA256 != manifest.SpecSHA256 ||
			mutation.SourcePath != expected.sourcePath || mutation.Package != expected.pkg ||
			mutation.Test != expected.test || mutation.ExpectedAssertionMarker != expected.marker ||
			!validRelativePath(mutation.SourcePath) || !validSHA256(mutation.SourceSHA256) ||
			mutation.Anchor == "" || mutation.Replacement == "" || mutation.Anchor == mutation.Replacement ||
			!validSHA256(mutation.AnchorSHA256) || sha256Hex([]byte(mutation.Anchor)) != mutation.AnchorSHA256 {
			return fmt.Errorf("mutation %q does not match the fixed campaign contract", mutation.ID)
		}
	}
	return nil
}

func executeMutation(repoRoot, modulePath, liveSourceRoot, baselineCommit string, mutation mutationSpec) (result mutationResult, retErr error) {
	result = mutationResult{
		ID:                      mutation.ID,
		SourcePath:              mutation.SourcePath,
		SourceSHA256:            mutation.SourceSHA256,
		AnchorSHA256:            mutation.AnchorSHA256,
		Package:                 mutation.Package,
		Test:                    mutation.Test,
		ExpectedAssertionMarker: mutation.ExpectedAssertionMarker,
		BaselineCommand:         namedTestCommand(mutation.Package, mutation.Test),
		CompileCommand:          compileCommand(mutation.Package),
		MutantCommand:           namedTestCommand(mutation.Package, mutation.Test),
	}

	liveSource := filepath.Join(liveSourceRoot, filepath.FromSlash(mutation.SourcePath))
	if err := verifyFileHash(liveSource, mutation.SourceSHA256); err != nil {
		return result, fmt.Errorf("live source drift: %w", err)
	}
	temporaryRoot, err := os.MkdirTemp("", "pcv3-phase3-mutator-")
	if err != nil {
		return result, fmt.Errorf("create temporary tree: %w", err)
	}
	defer func() {
		removeErr := os.RemoveAll(temporaryRoot)
		hashErr := verifyFileHash(liveSource, mutation.SourceSHA256)
		result.Restored = removeErr == nil && hashErr == nil
		if removeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("dispose temporary tree: %w", removeErr))
		}
		if hashErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("original source changed: %w", hashErr))
		}
	}()

	if err := materializeCommittedTree(repoRoot, baselineCommit, temporaryRoot); err != nil {
		return result, err
	}
	temporaryModule := filepath.Join(temporaryRoot, filepath.FromSlash(modulePath))
	temporarySource := filepath.Join(temporaryModule, filepath.FromSlash(mutation.SourcePath))
	original, err := os.ReadFile(temporarySource)
	if err != nil {
		return result, fmt.Errorf("read copied source: %w", err)
	}
	if sha256Hex(original) != mutation.SourceSHA256 {
		return result, errors.New("committed source hash drift")
	}

	baselineOutput, baselineErr := runGoTest(temporaryModule, result.BaselineCommand)
	if err := requireBaselinePass(baselineOutput, baselineErr, mutation.Test); err != nil {
		return result, fmt.Errorf("baseline is not green: %w", err)
	}
	result.BaselineGreen = true

	mutated, err := applyMutation(original, mutation)
	if err != nil {
		return result, err
	}
	info, err := os.Stat(temporarySource)
	if err != nil {
		return result, fmt.Errorf("stat copied source: %w", err)
	}
	if err := os.WriteFile(temporarySource, mutated, info.Mode().Perm()); err != nil {
		return result, fmt.Errorf("write copied mutation: %w", err)
	}
	result.Applied = true

	compileOutput, compileErr := runGoTest(temporaryModule, result.CompileCommand)
	if compileErr != nil {
		return result, fmt.Errorf("mutated package did not compile: %w: %s", compileErr, lastOutputLine(compileOutput))
	}
	result.Compiled = true

	mutantOutput, mutantErr := runGoTest(temporaryModule, result.MutantCommand)
	if err := requireNamedAssertionFailure(mutantOutput, mutantErr, mutation.Test, mutation.ExpectedAssertionMarker); err != nil {
		return result, err
	}
	result.NamedAssertionFailed = true
	result.Killed = true
	return result, nil
}

func applyMutation(source []byte, mutation mutationSpec) ([]byte, error) {
	if sha256Hex(source) != mutation.SourceSHA256 {
		return nil, errors.New("mutation source hash drift")
	}
	if sha256Hex([]byte(mutation.Anchor)) != mutation.AnchorSHA256 {
		return nil, errors.New("mutation anchor hash drift")
	}
	matches := bytes.Count(source, []byte(mutation.Anchor))
	if matches != 1 {
		return nil, fmt.Errorf("mutation anchor occurs %d times; want exactly once", matches)
	}
	mutated := bytes.Replace(source, []byte(mutation.Anchor), []byte(mutation.Replacement), 1)
	if bytes.Equal(mutated, source) {
		return nil, errors.New("mutation replacement is a no-op")
	}
	return mutated, nil
}

func namedTestCommand(pkg, test string) []string {
	return []string{"go", "test", "-json", "-p", "1", "-count=1", "-run", "^" + test + "$", pkg}
}

func compileCommand(pkg string) []string {
	return []string{"go", "test", "-json", "-p", "1", "-count=1", "-run", "^$", pkg}
}

func runGoTest(directory string, command []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = directory
	cmd.Env = append(os.Environ(), "GOWORK=off")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, fmt.Errorf("test command timed out: %w", ctx.Err())
	}
	return output, err
}

func requireBaselinePass(output []byte, runErr error, test string) error {
	if runErr != nil {
		return fmt.Errorf("test command failed: %w: %s", runErr, lastOutputLine(output))
	}
	events, err := parseTestEvents(output)
	if err != nil {
		return err
	}
	seenRun, seenPass := false, false
	for _, event := range events {
		if event.Test == test && event.Action == "run" {
			seenRun = true
		}
		if event.Test == test && event.Action == "pass" {
			seenPass = true
		}
		if (event.Test == test || strings.HasPrefix(event.Test, test+"/")) && event.Action == "skip" {
			return errors.New("named baseline test skipped")
		}
	}
	if !seenRun || !seenPass {
		return errors.New("named baseline test did not run and pass")
	}
	return nil
}

func requireNamedAssertionFailure(output []byte, runErr error, test, marker string) error {
	if runErr == nil {
		return errors.New("mutant survived its named behavioral test")
	}
	events, err := parseTestEvents(output)
	if err != nil {
		return err
	}
	seenRun, seenFail, seenMarker := false, false, false
	for _, event := range events {
		inNamedTest := event.Test == test || strings.HasPrefix(event.Test, test+"/")
		if event.Test == test && event.Action == "run" {
			seenRun = true
		}
		if event.Test == test && event.Action == "fail" {
			seenFail = true
		}
		if inNamedTest && strings.Contains(event.Output, marker) {
			seenMarker = true
		}
		if inNamedTest && event.Action == "skip" {
			return errors.New("named mutant test skipped")
		}
	}
	if !seenRun || !seenFail || !seenMarker {
		return fmt.Errorf("failure was not the named assertion: run=%t fail=%t marker=%t", seenRun, seenFail, seenMarker)
	}
	return nil
}

func parseTestEvents(output []byte) ([]testEvent, error) {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var events []testEvent
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event testEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("decode go test event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go test events: %w", err)
	}
	return events, nil
}

func materializeCommittedTree(repoRoot, commit, destination string) error {
	archive, err := os.CreateTemp("", "pcv3-phase3-tree-*.tar")
	if err != nil {
		return fmt.Errorf("create committed-tree archive: %w", err)
	}
	archivePath := archive.Name()
	defer func() {
		_ = archive.Close()
		_ = os.Remove(archivePath)
	}()

	cmd := exec.Command("git", "-C", repoRoot, "archive", "--format=tar", commit)
	var stderr bytes.Buffer
	cmd.Stdout = archive
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git archive failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind committed-tree archive: %w", err)
	}
	return extractTar(archive, destination)
}

func extractTar(source io.Reader, destination string) error {
	reader := tar.NewReader(source)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read committed tree archive: %w", err)
		}
		name := filepath.ToSlash(filepath.Clean(header.Name))
		if !validRelativePath(name) {
			return fmt.Errorf("unsafe committed-tree path %q", header.Name)
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)&0o777); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(file, reader)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				return errors.Join(copyErr, closeErr)
			}
		case tar.TypeSymlink:
			linkTarget := filepath.Clean(filepath.Join(filepath.Dir(target), filepath.FromSlash(header.Linkname)))
			relative, err := filepath.Rel(destination, linkTarget)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return fmt.Errorf("unsafe committed-tree symlink %q", header.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(header.Linkname, target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported committed-tree entry %q", header.Name)
		}
	}
}

func gitValue(directory string, args ...string) (string, error) {
	command := append([]string{"-C", directory}, args...)
	output, err := exec.Command("git", command...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func marshalReport(report campaignReport) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode mutation report: %w", err)
	}
	return append(data, '\n'), nil
}

func ensureResultAbsent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("mutation report already exists; reconcile it instead of rerunning")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect mutation report: %w", err)
	}
	return nil
}

func writeAtomicReport(path string, data []byte) error {
	if err := ensureResultAbsent(path); err != nil {
		return err
	}
	parent, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errors.New("mutation report parent is missing or contains a symlink")
	}
	temporary, err := os.CreateTemp(parent, ".pcv3-mutation-report-*")
	if err != nil {
		return fmt.Errorf("create mutation report temporary: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("publish mutation report: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return fmt.Errorf("remove mutation report temporary: %w", err)
	}
	keep = true
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func verifyFileHash(path, expected string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	actual := sha256Hex(data)
	if actual != expected {
		return fmt.Errorf("hash = %s; want %s", actual, expected)
	}
	return nil
}

func lastOutputLine(output []byte) string {
	lines := bytes.Split(bytes.TrimSpace(output), []byte{'\n'})
	if len(lines) == 0 {
		return "no output"
	}
	return string(lines[len(lines)-1])
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validObjectID(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validRelativePath(path string) bool {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return cleaned == path && cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}
