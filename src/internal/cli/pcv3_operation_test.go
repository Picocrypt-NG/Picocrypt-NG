package cli

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestPCV3CLIPreservesResultAxes(t *testing.T) {
	tests := []struct {
		name       string
		result     *pcv3CLIFixedResult
		wantExit   int
		wantOutput string
	}{
		{
			name: "clean durable",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeSuccess, stage: pcv3.StageNone, code: pcv3.CodeSuccess,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				publicationCode:      pcv3publication.CodePublishedDurable,
				class:                pcv3operation.CompletionClean,
			},
			wantExit:   0,
			wantOutput: "Outcome: success\nPublication: published-durable\n",
		},
		{
			name: "authenticated degraded durable",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeAuthenticatedDegraded, stage: pcv3.StageMetadata, code: pcv3.CodeAuthenticatedDegraded,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				publicationCode:      pcv3publication.CodePublishedDurable,
				warnings:             []pcv3operation.Warning{pcv3operation.WarningAuthenticatedDegraded},
				class:                pcv3operation.CompletionWarning,
			},
			wantExit: 2,
			wantOutput: "Outcome: authenticated-degraded\nPublication: published-durable\n" +
				"Warning: output is authenticated but recovery redundancy is damaged\n",
		},
		{
			name: "force partial durable",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeForcePartial, stage: pcv3.StageRecordAuth, code: pcv3.CodeForcePartial,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				publicationCode:      pcv3publication.CodePublishedDurable,
				warnings:             []pcv3operation.Warning{pcv3operation.WarningForcePartial},
				class:                pcv3operation.CompletionWarning,
			},
			wantExit: 2,
			wantOutput: "Outcome: force-partial\nPublication: published-durable\n" +
				"Warning: partial recovery output is not a complete plaintext file\n",
		},
		{
			name: "force unverified durable",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeForceUnverified, stage: pcv3.StageRecordAuth, code: pcv3.CodeForceUnverified,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				publicationCode:      pcv3publication.CodePublishedDurable,
				warnings:             []pcv3operation.Warning{pcv3operation.WarningForceUnverified},
				class:                pcv3operation.CompletionWarning,
			},
			wantExit: 2,
			wantOutput: "Outcome: force-unverified\nPublication: published-durable\n" +
				"Warning: recovered bytes are unverified and may be unsafe\n",
		},
		{
			name: "clean durable with cleanup warning",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeSuccess, stage: pcv3.StageNone, code: pcv3.CodeSuccess,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurable,
				publicationCode:      pcv3publication.CodePublishedDurable,
				warnings:             []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete},
				class:                pcv3operation.CompletionWarning,
			},
			wantExit: 2,
			wantOutput: "Outcome: success\nPublication: published-durable\n" +
				"Warning: cleanup of operation-owned temporary plaintext could not be confirmed\n",
		},
		{
			name: "durability uncertain overrides clean",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeSuccess, stage: pcv3.StageNone, code: pcv3.CodeSuccess,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublishedDurabilityUncertain,
				publicationStage:     pcv3.StageDirectorySync,
				publicationCode:      pcv3publication.CodeDurabilityUncertain,
				warnings:             []pcv3operation.Warning{pcv3operation.WarningDurabilityUncertain},
				class:                pcv3operation.CompletionDurabilityUncertain,
			},
			wantExit: 3,
			wantOutput: "Outcome: success\nPublication: published-durability-uncertain\n" +
				"Warning: output durability was not confirmed; keep source and destination unchanged\n",
		},
		{
			name: "publication indeterminate overrides force",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeForcePartial, stage: pcv3.StageRecordAuth, code: pcv3.CodeForcePartial,
				publicationAttempted: true,
				publicationState:     pcv3publication.StatePublicationIndeterminate,
				publicationStage:     pcv3.StageOutputPublication,
				publicationCode:      pcv3publication.CodePublicationIndeterminate,
				warnings: []pcv3operation.Warning{
					pcv3operation.WarningForcePartial,
					pcv3operation.WarningPublicationIndeterminate,
				},
				class: pcv3operation.CompletionPublicationIndeterminate,
			},
			wantExit: 4,
			wantOutput: "Outcome: force-partial\nPublication: publication-indeterminate\n" +
				"Warning: partial recovery output is not a complete plaintext file\n" +
				"Warning: output state is unknown; keep source and destination unchanged\n",
		},
		{
			name: "refused without publication",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeUnsupportedRoutingPreKDF, stage: pcv3.StageRouting, code: pcv3.CodeUnsupported,
				class: pcv3operation.CompletionRefused,
			},
			wantExit:   1,
			wantOutput: "Outcome: unsupported-routing-pre-kdf\nPublication: not-attempted\n",
		},
		{
			name: "not published",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageOutputPublication, code: pcv3.CodeOperationFailed,
				publicationAttempted: true,
				publicationState:     pcv3publication.StateNotPublished,
				publicationStage:     pcv3.StageOutputPublication,
				publicationCode:      pcv3publication.CodeAtomicFailed,
				class:                pcv3operation.CompletionNoOutput,
			},
			wantExit:   1,
			wantOutput: "Outcome: operation-failed\nPublication: not-published\n",
		},
		{
			name: "unknown tuple remains neutral",
			result: &pcv3CLIFixedResult{
				outcome: pcv3.Outcome(255), stage: pcv3.Stage(255), code: pcv3.Code(255),
				publicationAttempted: true,
				publicationState:     pcv3publication.State(255),
				publicationStage:     pcv3.Stage(255),
				publicationCode:      pcv3publication.Code(255),
				warnings:             []pcv3operation.Warning{pcv3operation.Warning(255)},
				class:                pcv3operation.CompletionUnknown,
			},
			wantExit:   1,
			wantOutput: "Outcome: unknown-outcome\nPublication: unknown-state\nWarning: operation completed with a caution\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output strings.Builder
			exit := renderPCV3CLIResult(&output, test.result)
			if exit != test.wantExit {
				t.Fatalf("exit = %d; want %d", exit, test.wantExit)
			}
			if output.String() != test.wantOutput {
				t.Fatalf("stderr = %q; want %q", output.String(), test.wantOutput)
			}
		})
	}
}

type pcv3CLIFakeArchive struct {
	extract func(context.Context, *os.Root) pcv3CLIResult
	close   func() pcv3CLIResult
}

func (archive *pcv3CLIFakeArchive) Extract(ctx context.Context, root *os.Root) pcv3CLIResult {
	if archive == nil || archive.extract == nil {
		if root != nil {
			_ = root.Close()
		}
		return pcv3CLIRefusalResult()
	}
	return archive.extract(ctx, root)
}

func (archive *pcv3CLIFakeArchive) Close() pcv3CLIResult {
	if archive == nil || archive.close == nil {
		return pcv3CLIRefusalResult()
	}
	return archive.close()
}

func TestPCV3CLIArchiveUnavailableRootIsAttemptedNotPublished(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "missing")
	notPublished := &pcv3CLIFixedResult{
		outcome:              pcv3.OutcomeOperationFailed,
		stage:                pcv3.StageOutputPublication,
		code:                 pcv3.CodeOperationFailed,
		publicationAttempted: true,
		publicationState:     pcv3publication.StateNotPublished,
		publicationStage:     pcv3.StageOutputPublication,
		publicationCode:      pcv3publication.CodeAtomicFailed,
		class:                pcv3operation.CompletionNoOutput,
	}
	closedWithoutExtraction := &pcv3CLIFixedResult{
		outcome: pcv3.OutcomeOperationFailed,
		stage:   pcv3.StageOutputPublication,
		code:    pcv3.CodeOperationFailed,
		class:   pcv3operation.CompletionNoOutput,
	}
	pending := &pcv3CLIFixedResult{
		outcome: pcv3.OutcomeSuccess,
		stage:   pcv3.StageNone,
		code:    pcv3.CodeSuccess,
		class:   pcv3operation.CompletionArchivePending,
		archive: &pcv3CLIFakeArchive{
			extract: func(_ context.Context, root *os.Root) pcv3CLIResult {
				if root != nil {
					_ = root.Close()
					t.Fatal("unavailable extraction destination produced an open root")
				}
				return notPublished
			},
			close: func() pcv3CLIResult { return closedWithoutExtraction },
		},
	}

	result := finishPCV3CLIArchive(context.Background(), pending, "extract", destination)
	if result == nil {
		t.Fatal("unavailable-root terminal is nil; want attempted not-published result")
	}
	if !result.PublicationAttempted() ||
		result.PublicationState() != pcv3publication.StateNotPublished ||
		result.PublicationStage() != pcv3.StageOutputPublication ||
		result.PublicationCode() != pcv3publication.CodeAtomicFailed ||
		result.CompletionClass() != pcv3operation.CompletionNoOutput {
		t.Fatalf(
			"unavailable-root terminal = %#v attempted=%v state=%v stage=%v code=%v class=%v; want attempted not-published output-publication/atomic-failed no-output",
			result, result.PublicationAttempted(), result.PublicationState(),
			result.PublicationStage(), result.PublicationCode(), result.CompletionClass(),
		)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unavailable extraction destination changed filesystem: %v", err)
	}
}

// TestPCV3CLIArchiveExtractionObservesSignalCancellation protects the live
// signal path after the authenticated read has returned an archive follow-up.
// SIGINT must cancel the same context observed by extraction rather than only
// the already-finished read operation.
func TestPCV3CLIArchiveExtractionObservesSignalCancellation(t *testing.T) {
	destination := t.TempDir()
	terminal := &pcv3CLIFixedResult{
		outcome:              pcv3.OutcomeOperationFailed,
		stage:                pcv3.StageOutputPublication,
		code:                 pcv3.CodeOperationFailed,
		publicationAttempted: true,
		publicationState:     pcv3publication.StateNotPublished,
		publicationStage:     pcv3.StageOutputPublication,
		publicationCode:      pcv3publication.CodeAtomicFailed,
		class:                pcv3operation.CompletionNoOutput,
	}
	entered := make(chan struct{})
	pending := &pcv3CLIFixedResult{
		outcome: pcv3.OutcomeSuccess,
		stage:   pcv3.StageNone,
		code:    pcv3.CodeSuccess,
		class:   pcv3operation.CompletionArchivePending,
		archive: &pcv3CLIFakeArchive{
			extract: func(ctx context.Context, root *os.Root) pcv3CLIResult {
				close(entered)
				<-ctx.Done()
				if root != nil {
					_ = root.Close()
				}
				return terminal
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	reporter := NewReporter(true)
	reporter.setPCV3Cancel(cancel)
	previousReporter := globalReporter.Swap(reporter)
	t.Cleanup(func() {
		reporter.setPCV3Cancel(nil)
		cancel()
		globalReporter.Store(previousReporter)
	})

	resultReady := make(chan pcv3CLIResult, 1)
	go func() {
		resultReady <- finishPCV3CLIArchive(ctx, pending, "extract", destination)
	}()
	<-entered
	handleSignal()
	result := <-resultReady

	if result != terminal || !reporter.IsCancelled() || ctx.Err() == nil {
		t.Fatalf("signal cancellation = result %#v reporter=%v context=%v; want exact no-output terminal and cancelled context", result, reporter.IsCancelled(), ctx.Err())
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled archive extraction changed destination: entries=%v err=%v", entries, err)
	}
}

// TestPCV3CLIArchiveExtractionKeepsOperationSignalContext protects the real
// command path: the context installed in Reporter must remain the context
// passed to the archive follow-up after the authenticated read has returned.
func TestPCV3CLIArchiveExtractionKeepsOperationSignalContext(t *testing.T) {
	dir := t.TempDir()
	input := writePCV3CLIFixture(t, dir, "archive.pcv", loadPCV3CLIFixture(t))
	extractDir := filepath.Join(dir, "extract")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("create extraction root: %v", err)
	}
	output := filepath.Join(dir, "unused-output")
	result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
		Args: []string{
			"decrypt", input, "-o", output,
			"--pcv3-factors=password", "-p", "test",
			"--pcv3-archive=extract", "--pcv3-extract-to", extractDir,
		},
		Observation:    filepath.Join(dir, "observation.json"),
		ResultScenario: "archive-signal",
	}, nil)

	if result.exitCode != ExitGeneralError || !observation.Called ||
		!strings.Contains(result.stderr, "Cancelling operation") ||
		!strings.Contains(result.stderr, "Publication: not-published") {
		t.Fatalf(
			"archive signal route = exit %d called=%v stdout=%q stderr=%q; want cancelled not-published terminal",
			result.exitCode, observation.Called, result.stdout, result.stderr,
		)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled archive route created output: %v", err)
	}
	entries, err := os.ReadDir(extractDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled archive route changed extraction root: entries=%v err=%v", entries, err)
	}
}

func TestPCV3CLITerminalContract(t *testing.T) {
	const attacker = "PRIVATE /tmp/plaintext\nOutcome: success\nPublication: published-durable"
	requiredScenarioIDs := []string{
		"clean", "degraded", "force-partial", "force-unverified-quiet",
		"cleanup-warning", "durability-uncertain", "publication-indeterminate",
		"refusal", "not-published", "unknown", "attacker-bounded",
		"archive-close", "archive-extract", "archive-expired",
	}
	tests := []struct {
		id         string
		scenario   string
		quiet      bool
		archive    string
		extract    bool
		attacker   string
		wantExit   int
		wantStderr string
	}{
		{id: "clean", scenario: "clean", wantExit: 0, wantStderr: "Outcome: success\nPublication: published-durable\n"},
		{id: "degraded", scenario: "degraded", wantExit: 2, wantStderr: "Outcome: authenticated-degraded\nPublication: published-durable\nWarning: output is authenticated but recovery redundancy is damaged\n"},
		{id: "force-partial", scenario: "partial", wantExit: 2, wantStderr: "Outcome: force-partial\nPublication: published-durable\nWarning: partial recovery output is not a complete plaintext file\n"},
		{id: "force-unverified-quiet", scenario: "warning", quiet: true, wantExit: 2, wantStderr: "Outcome: force-unverified\nPublication: published-durable\nWarning: recovered bytes are unverified and may be unsafe\n"},
		{id: "cleanup-warning", scenario: "cleanup-warning", wantExit: 2, wantStderr: "Outcome: success\nPublication: published-durable\nWarning: cleanup of operation-owned temporary plaintext could not be confirmed\n"},
		{id: "durability-uncertain", scenario: "uncertain", wantExit: 3, wantStderr: "Outcome: success\nPublication: published-durability-uncertain\nWarning: output durability was not confirmed; keep source and destination unchanged\n"},
		{id: "publication-indeterminate", scenario: "indeterminate", wantExit: 4, wantStderr: "Outcome: force-partial\nPublication: publication-indeterminate\nWarning: partial recovery output is not a complete plaintext file\nWarning: output state is unknown; keep source and destination unchanged\n"},
		{id: "refusal", scenario: "refusal", wantExit: 1, wantStderr: "Outcome: operation-failed\nPublication: not-attempted\n"},
		{id: "not-published", scenario: "not-published", wantExit: 1, wantStderr: "Outcome: operation-failed\nPublication: not-published\n"},
		{id: "unknown", scenario: "unknown", wantExit: 1, wantStderr: "Outcome: unknown-outcome\nPublication: unknown-state\nWarning: operation completed with a caution\n"},
		{id: "attacker-bounded", scenario: "unknown", attacker: attacker, wantExit: 1, wantStderr: "Outcome: unknown-outcome\nPublication: unknown-state\nWarning: operation completed with a caution\n"},
		{id: "archive-close", scenario: "archive-close", archive: "close", wantExit: 1, wantStderr: "Outcome: operation-failed\nPublication: not-attempted\n"},
		{id: "archive-extract", scenario: "archive-extract", archive: "extract", extract: true, wantExit: 0, wantStderr: "Outcome: success\nPublication: published-durable\n"},
		{id: "archive-expired", scenario: "archive-expired", archive: "extract", extract: true, wantExit: 1, wantStderr: "Outcome: unknown-outcome\nPublication: not-attempted\n"},
	}

	executed := make(map[string]int, len(tests))
	fixture := loadPCV3CLIFixture(t)
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			executed[test.id]++
			dir := t.TempDir()
			input := writePCV3CLIFixture(t, dir, "claimed.pcv", fixture)
			output := filepath.Join(dir, "output")
			args := []string{"decrypt", input, "-o", output, "--pcv3-factors=password", "-p", "pw"}
			if test.quiet {
				args = append(args, "--quiet")
			}
			extractRoot := ""
			if test.extract {
				if test.id == "archive-expired" {
					extractRoot = filepath.Join(dir, "must-not-exist")
				} else {
					extractRoot = filepath.Join(dir, "extract")
					if err := os.Mkdir(extractRoot, 0o700); err != nil {
						t.Fatalf("create extraction root: %v", err)
					}
				}
				args = append(args, "--pcv3-archive=extract", "--pcv3-extract-to="+extractRoot)
			} else if test.archive != "" {
				args = append(args, "--pcv3-archive="+test.archive)
			}
			result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
				Args: args, Observation: filepath.Join(dir, "observation.json"),
				ResultScenario: test.scenario, AttackerText: test.attacker,
			}, nil)
			if result.exitCode != test.wantExit || len(result.stdout) != 0 || result.stderr != test.wantStderr {
				t.Fatalf("terminal = exit %d stdout %q stderr %q; want exit %d empty stdout stderr %q", result.exitCode, result.stdout, result.stderr, test.wantExit, test.wantStderr)
			}
			if !observation.Called {
				t.Fatal("real CLI route did not reach the operation boundary")
			}
			if strings.Contains(result.stderr, attacker) || len(result.stderr) > 512 {
				t.Fatalf("terminal exposed or amplified attacker text: %q", result.stderr)
			}
			if test.id == "archive-extract" {
				contents, err := os.ReadFile(filepath.Join(extractRoot, "extracted.txt"))
				if err != nil || string(contents) != "authenticated archive contents" {
					t.Fatalf("archive extraction = %q, %v", contents, err)
				}
			}
			if test.id == "archive-expired" {
				if _, err := os.Stat(extractRoot); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expired follow-up changed filesystem: %v", err)
				}
			}
		})
	}

	for _, id := range requiredScenarioIDs {
		if executed[id] != 1 {
			t.Fatalf("scenario %q executed %d times; want exactly once", id, executed[id])
		}
		delete(executed, id)
	}
	if len(executed) != 0 {
		t.Fatalf("unexpected scenario IDs executed: %v", executed)
	}
}

func TestPCV3CLIKeepsWriterAndMigrationAbsent(t *testing.T) {
	wantCommands := map[string]string{
		"decrypt": "decrypt VOLUME",
		"encrypt": "encrypt [PATH...]",
	}
	for _, command := range rootCmd.Commands() {
		if command.Name() == "help" {
			continue
		}
		wantUse, ok := wantCommands[command.Name()]
		if !ok {
			t.Fatalf("unexpected public CLI action %q (%q)", command.Name(), command.Use)
		}
		if command.Use != wantUse || len(command.Aliases) != 0 {
			t.Fatalf("public CLI action %q = use %q aliases %q; want use %q and no aliases", command.Name(), command.Use, command.Aliases, wantUse)
		}
		delete(wantCommands, command.Name())
	}
	if len(wantCommands) != 0 {
		t.Fatalf("public CLI actions missing from the real command tree: %v", wantCommands)
	}

	wantFlags := map[string]map[string]struct{}{
		"Picocrypt-NG": {
			"temp-dir": {},
		},
		"encrypt": {
			"comments": {}, "compress": {}, "deniability": {}, "follow-symlinks": {},
			"glob": {}, "input": {}, "keyfile": {}, "keyfile-ordered": {}, "output": {},
			"paranoid": {}, "password": {}, "password-stdin": {}, "quiet": {},
			"reed-solomon": {}, "split": {}, "split-size": {}, "split-unit": {}, "yes": {},
		},
		"decrypt": {
			"auto-unzip": {}, "deniability": {}, "force": {}, "input": {}, "keyfile": {},
			"output": {}, "password": {}, "password-stdin": {}, "pcv3-action": {},
			"pcv3-archive": {}, "pcv3-extract-to": {}, "pcv3-factors": {}, "pcv3-format": {},
			"pcv3-keyfile-order": {}, "pcv3-role": {}, "quiet": {}, "recombine": {},
			"same-level": {}, "verify-first": {}, "yes": {},
		},
	}
	checkFlags := func(name string, commandFlags *pflag.FlagSet) {
		t.Helper()
		remaining := wantFlags[name]
		commandFlags.VisitAll(func(flag *pflag.Flag) {
			if flag.Name == "help" || flag.Name == "version" {
				return
			}
			if _, ok := remaining[flag.Name]; !ok {
				t.Errorf("unexpected %s CLI request field --%s", name, flag.Name)
				return
			}
			delete(remaining, flag.Name)
		})
		if len(remaining) != 0 {
			t.Errorf("%s CLI request fields missing from the real flag set: %v", name, remaining)
		}
	}
	checkFlags("Picocrypt-NG", rootCmd.PersistentFlags())
	checkFlags("encrypt", encryptCmd.Flags())
	checkFlags("decrypt", decryptCmd.Flags())

	var help strings.Builder
	rootCmd.SetOut(&help)
	t.Cleanup(func() { rootCmd.SetOut(nil) })
	if err := rootCmd.Help(); err != nil {
		t.Fatalf("render root help: %v", err)
	}
	rootCmd.SetOut(nil)
	if !strings.Contains(help.String(), "encrypt") || !strings.Contains(help.String(), "decrypt") {
		t.Fatalf("root help did not render the real command tree: %q", help.String())
	}

	var completion strings.Builder
	if err := rootCmd.GenBashCompletion(&completion); err != nil {
		t.Fatalf("render Bash completion: %v", err)
	}
	if !strings.Contains(completion.String(), "encrypt") || !strings.Contains(completion.String(), "decrypt") {
		t.Fatal("Bash completion did not enumerate the real CLI actions")
	}
}
