package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// pcv3Sentinel is one unique non-zero secret or path token with a stable
// public ID. Failure output names only the ID, never the value.
type pcv3Sentinel struct {
	id    string
	value []byte
}

// pcv3LifecycleAdmitter records every admission request with its exact
// profile snapshot so the oracle can prove one-flight, fixed-profile scope.
type pcv3LifecycleAdmitter struct {
	calls     int
	profiles  []pcv3credential.KDFProfile
	admission pcv3credential.KDFAdmission
}

func (admitter *pcv3LifecycleAdmitter) AdmitKDF(
	_ context.Context,
	profile pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	admitter.calls++
	admitter.profiles = append(admitter.profiles, profile)
	if admitter.admission != pcv3credential.KDFAdmissionUnknown {
		return admitter.admission, nil
	}
	return pcv3credential.KDFAdmissionDenied, nil
}

// pcv3LifecycleRun carries one operation run plus every retained alias and
// channel the oracle inspects after the terminal result.
type pcv3LifecycleRun struct {
	ctx       context.Context
	request   *Request
	admitter  *pcv3LifecycleAdmitter
	outputDir string
	statuses  []StatusCode
	statusDbg []string
	statusArg []uint64

	passwords      []pcv3Sentinel // aliases: exact value before Run, zero after
	keyfiles       []*operationObservedReadCloser
	source         *os.File
	consentCalls   int
	retainedAction ConsentAction
	sentinels      []pcv3Sentinel // tokens that must never reach a channel
}

type pcv3LifecycleCase struct {
	name             string
	build            func(t *testing.T) *pcv3LifecycleRun
	wantOutcome      pcv3.Outcome
	wantStage        pcv3.Stage
	wantCode         pcv3.Code
	wantDiagnostic   Diagnostic
	wantClass        CompletionClass
	wantWarnings     []Warning
	wantStatuses     []StatusCode
	wantAdmissions   int
	wantConsentCalls int
}

// pcv3Standard1Profile is the frozen fixed Argon2id profile for suite
// 0x0001 (spec §6.4: Normal-1, version 0x13, t=4, m=1048576 KiB, p=4, 16-byte
// salt, 32-byte output). It is an independent literal, not a re-derivation.
var pcv3Standard1Profile = pcv3credential.KDFProfile{
	ID:            0x01,
	Argon2Version: 0x13,
	Time:          4,
	MemoryKiB:     1048576,
	Parallelism:   4,
	SaltBytes:     16,
	OutputBytes:   32,
}

func pcv3SentinelBytes(id string) []byte {
	return []byte("pcv3-life-" + id + "-7d21c94af0")
}

func pcv3PathSentinel(t *testing.T, id string) (directory, token string) {
	t.Helper()
	directory = t.TempDir()
	token = "pcv3-life-path-" + id + "-51b0e2"
	return directory, token
}

func pcv3BaseRun(t *testing.T, id string) *pcv3LifecycleRun {
	t.Helper()
	admitter := &pcv3LifecycleAdmitter{}
	run := &pcv3LifecycleRun{
		ctx:      context.Background(),
		admitter: admitter,
	}
	targetDir, targetToken := pcv3PathSentinel(t, id+"-target")
	protectedDir, protectedToken := pcv3PathSentinel(t, id+"-protected")
	run.outputDir = targetDir
	run.request = &Request{
		Target:    filepath.Join(targetDir, targetToken+".bin"),
		Protected: []string{filepath.Join(protectedDir, protectedToken+".bin")},
	}
	run.sentinels = append(run.sentinels,
		pcv3Sentinel{id: id + "-target-path", value: []byte(targetToken)},
		pcv3Sentinel{id: id + "-protected-path", value: []byte(protectedToken)},
	)
	return run
}

func pcv3WireReporter(run *pcv3LifecycleRun) {
	run.request.Reporter = func(status Status) error {
		run.statuses = append(run.statuses, status.Code())
		run.statusDbg = append(run.statusDbg, fmt.Sprintf("%#v", status))
		run.statusArg = append(run.statusArg, status.Args()...)
		return nil
	}
}

func pcv3PasswordFactors(run *pcv3LifecycleRun, id string) *pcv3credential.FactorRequest {
	password := pcv3SentinelBytes(id)
	run.passwords = append(run.passwords, pcv3Sentinel{id: id, value: password})
	run.sentinels = append(run.sentinels, pcv3Sentinel{id: id, value: password})
	return operationPasswordFactors(password)
}

func pcv3CaptureProcess(t *testing.T, run func()) (stdout, stderr []byte) {
	t.Helper()
	originalStdout, originalStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout capture pipe: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr capture pipe: %v", err)
	}
	done := make(chan struct{}, 2)
	go func() { stdout, _ = io.ReadAll(stdoutReader); done <- struct{}{} }()
	go func() { stderr, _ = io.ReadAll(stderrReader); done <- struct{}{} }()
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	defer func() { os.Stdout, os.Stderr = originalStdout, originalStderr }()

	run()

	os.Stdout, os.Stderr = originalStdout, originalStderr
	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("close stdout capture writer: %v", err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("close stderr capture writer: %v", err)
	}
	<-done
	<-done
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	return stdout, stderr
}

func pcv3ScanChannels(
	t *testing.T,
	run *pcv3LifecycleRun,
	result *Result,
	stdout, stderr, logBytes []byte,
) {
	t.Helper()
	channels := map[string][]byte{
		"result-error": []byte(
			result.Error() + "|" + result.String() + "|" + result.GoString() + "|" +
				fmt.Sprintf("%v|%q|%+v|%#v|%x|%d", result, result, result, result, result, result),
		),
		"result-presentation": []byte(fmt.Sprintf("%#v", result.Presentation())),
		"progress":            []byte(strings.Join(run.statusDbg, "|")),
		"request-debug":       []byte(fmt.Sprintf("%#v|%v", run.request, run.request)),
		"stdout":              stdout,
		"stderr":              stderr,
		"log":                 logBytes,
	}
	var argBytes []byte
	for _, arg := range run.statusArg {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], arg)
		argBytes = append(argBytes, encoded[:]...)
	}
	channels["progress-args"] = argBytes

	for _, sentinel := range run.sentinels {
		if len(sentinel.value) == 0 {
			t.Fatalf("sentinel %s is empty", sentinel.id)
		}
		for channel, content := range channels {
			if bytes.Contains(content, sentinel.value) {
				t.Fatalf("sentinel %s observed in channel %s", sentinel.id, channel)
			}
		}
	}
}

func pcv3AssertZeroed(t *testing.T, run *pcv3LifecycleRun) {
	t.Helper()
	for _, sentinel := range run.passwords {
		for index, value := range sentinel.value {
			if value != 0 {
				t.Fatalf("sentinel %s byte %d survived owner close", sentinel.id, index)
			}
		}
	}
	if run.source != nil {
		assertOperationFileClosed(t, run.source)
	}
	assertOperationKeyfilesClosedOnce(t, run.keyfiles)
}

func TestPCV3LifecycleMutationOracle(t *testing.T) {
	cases := []pcv3LifecycleCase{
		{
			name: "routing refusal closes every transferred owner before effects",
			build: func(t *testing.T) *pcv3LifecycleRun {
				run := pcv3BaseRun(t, "routing")
				run.source = newOperationEmptySource(t)
				run.request.Mode = 0
				run.request.Source = run.source
				run.request.Factors = pcv3PasswordFactors(run, "password-routing")
				pcv3WireReporter(run)
				run.request.Consent = func(ConsentRequest, ConsentAction) error {
					run.consentCalls++
					return nil
				}
				return run
			},
			wantOutcome:    pcv3.OutcomeUnsupportedRoutingPreKDF,
			wantStage:      pcv3.StageRouting,
			wantCode:       pcv3.CodeUnsupported,
			wantDiagnostic: DiagnosticRoutingRefusal,
			wantClass:      CompletionRefused,
		},
		{
			name: "credential policy refusal closes owners before admission",
			build: func(t *testing.T) *pcv3LifecycleRun {
				run := pcv3BaseRun(t, "credential")
				run.source = openOperationNormalFixture(t, "normal-standard-keyfiles-only-small.pcv")
				keyfileContent := pcv3SentinelBytes("keyfile-content-credential")
				run.sentinels = append(run.sentinels, pcv3Sentinel{
					id:    "keyfile-content-credential",
					value: keyfileContent,
				})
				run.keyfiles = []*operationObservedReadCloser{
					newOperationObservedKeyfile(t, keyfileContent),
					newOperationObservedKeyfile(t, keyfileContent),
				}
				run.request.Mode = ModeReadNormal
				run.request.Source = run.source
				run.request.Factors = &pcv3credential.FactorRequest{
					Mode:           pcv3credential.CredentialModeKeyfilesOnly,
					KeyfileMode:    pcv3credential.KeyfileModeOrdered,
					ExpectedPolicy: pcv3credential.FactorPolicyKeyfilesOnly,
					Keyfiles:       operationKeyfileHandles(run.keyfiles),
				}
				pcv3WireReporter(run)
				return run
			},
			wantOutcome:    pcv3.OutcomeOperationFailed,
			wantStage:      pcv3.StageCredentialPolicy,
			wantCode:       pcv3.CodeOperationFailed,
			wantDiagnostic: DiagnosticNone,
			wantClass:      CompletionRefused,
			wantStatuses: []StatusCode{
				StatusCheckingRequest,
				StatusCheckingFactors,
				StatusAuthenticating,
			},
		},
		{
			name: "resource refusal admits exactly one fixed profile and derives nothing",
			build: func(t *testing.T) *pcv3LifecycleRun {
				run := pcv3BaseRun(t, "resource")
				run.admitter.admission = pcv3credential.KDFAdmissionDeniedInsufficient
				run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-archive-small.pcv")
				keyfileOne := pcv3SentinelBytes("keyfile-one-resource")
				keyfileTwo := pcv3SentinelBytes("keyfile-two-resource")
				run.keyfiles = []*operationObservedReadCloser{
					newOperationObservedKeyfile(t, keyfileOne),
					newOperationObservedKeyfile(t, keyfileTwo),
				}
				run.sentinels = append(run.sentinels,
					pcv3Sentinel{id: "keyfile-one-resource", value: keyfileOne},
					pcv3Sentinel{id: "keyfile-two-resource", value: keyfileTwo},
				)
				run.request.Mode = ModeReadNormal
				run.request.Source = run.source
				run.request.Factors = &pcv3credential.FactorRequest{
					Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
					KeyfileMode:    pcv3credential.KeyfileModeOrdered,
					ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
					Password:       pcv3SentinelBytes("password-resource"),
					Keyfiles:       operationKeyfileHandles(run.keyfiles),
				}
				run.passwords = append(run.passwords, pcv3Sentinel{
					id:    "password-resource",
					value: run.request.Factors.Password,
				})
				run.sentinels = append(run.sentinels, pcv3Sentinel{
					id:    "password-resource",
					value: run.request.Factors.Password,
				})
				pcv3WireReporter(run)
				return run
			},
			wantOutcome:    pcv3.OutcomeOperationFailed,
			wantStage:      pcv3.StageCredentialPolicy,
			wantCode:       pcv3.CodeOperationFailed,
			wantDiagnostic: DiagnosticResourceInsufficient,
			wantClass:      CompletionRefused,
			wantStatuses: []StatusCode{
				StatusCheckingRequest,
				StatusCheckingFactors,
				StatusAuthenticating,
				StatusCheckingResources,
			},
			wantAdmissions: 1,
		},
		{
			name: "cancellation closes owners before any status or admission",
			build: func(t *testing.T) *pcv3LifecycleRun {
				run := pcv3BaseRun(t, "cancel")
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				run.ctx = ctx
				run.source = newOperationEmptySource(t)
				run.request.Mode = ModeReadNormal
				run.request.Source = run.source
				run.request.Factors = pcv3PasswordFactors(run, "password-cancel")
				pcv3WireReporter(run)
				return run
			},
			wantOutcome:    pcv3.OutcomeOperationFailed,
			wantStage:      pcv3.StageCancellation,
			wantCode:       pcv3.CodeOperationFailed,
			wantDiagnostic: DiagnosticCancellation,
			wantClass:      CompletionRefused,
		},
		{
			name: "consent refusal keeps one-shot authority expired and closes owners",
			build: func(t *testing.T) *pcv3LifecycleRun {
				run := pcv3BaseRun(t, "consent-refusal")
				run.source = newOperationEmptySource(t)
				run.request.Mode = ModeForceUnverifiedD1
				run.request.Source = run.source
				run.request.Factors = pcv3PasswordFactors(run, "password-consent-refusal")
				pcv3WireReporter(run)
				run.request.Consent = func(request ConsentRequest, action ConsentAction) error {
					run.consentCalls++
					if request.Mode() != ModeForceUnverifiedD1 {
						return errors.New("wrong consent mode")
					}
					run.retainedAction = action
					return nil
				}
				return run
			},
			wantOutcome:      pcv3.OutcomeOperationFailed,
			wantStage:        pcv3.StageCredentialPolicy,
			wantCode:         pcv3.CodeOperationFailed,
			wantDiagnostic:   DiagnosticCredentialPolicy,
			wantClass:        CompletionRefused,
			wantStatuses:     []StatusCode{StatusCheckingRequest, StatusCheckingFactors},
			wantConsentCalls: 1,
		},
		{
			name: "consent callback failure closes owners without leaking the callback error",
			build: func(t *testing.T) *pcv3LifecycleRun {
				run := pcv3BaseRun(t, "consent-failure")
				run.source = newOperationEmptySource(t)
				run.request.Mode = ModeForceUnverifiedD1
				run.request.Source = run.source
				run.request.Factors = pcv3PasswordFactors(run, "password-consent-failure")
				pcv3WireReporter(run)
				callbackSentinel := pcv3SentinelBytes("consent-error")
				run.sentinels = append(run.sentinels, pcv3Sentinel{
					id:    "consent-error",
					value: callbackSentinel,
				})
				run.request.Consent = func(_ ConsentRequest, action ConsentAction) error {
					run.consentCalls++
					run.retainedAction = action
					return errors.New(string(callbackSentinel))
				}
				return run
			},
			wantOutcome:      pcv3.OutcomeOperationFailed,
			wantStage:        pcv3.StageCredentialPolicy,
			wantCode:         pcv3.CodeOperationFailed,
			wantDiagnostic:   DiagnosticCallbackFailure,
			wantClass:        CompletionRefused,
			wantStatuses:     []StatusCode{StatusCheckingRequest, StatusCheckingFactors},
			wantConsentCalls: 1,
		},
		{
			name: "consent callback panic is contained and closes owners without leaking the payload",
			build: func(t *testing.T) *pcv3LifecycleRun {
				run := pcv3BaseRun(t, "consent-panic")
				run.source = newOperationEmptySource(t)
				run.request.Mode = ModeForceUnverifiedD1
				run.request.Source = run.source
				run.request.Factors = pcv3PasswordFactors(run, "password-consent-panic")
				pcv3WireReporter(run)
				panicSentinel := pcv3SentinelBytes("panic-payload")
				run.sentinels = append(run.sentinels, pcv3Sentinel{
					id:    "panic-payload",
					value: panicSentinel,
				})
				run.request.Consent = func(_ ConsentRequest, action ConsentAction) error {
					run.consentCalls++
					run.retainedAction = action
					panic(string(panicSentinel))
				}
				return run
			},
			wantOutcome:      pcv3.OutcomeOperationFailed,
			wantStage:        pcv3.StageCredentialPolicy,
			wantCode:         pcv3.CodeOperationFailed,
			wantDiagnostic:   DiagnosticCallbackPanic,
			wantClass:        CompletionRefused,
			wantStatuses:     []StatusCode{StatusCheckingRequest, StatusCheckingFactors},
			wantConsentCalls: 1,
		},
		{
			name: "D1 bootstrap failure closes owners with no admission and no output",
			build: func(t *testing.T) *pcv3LifecycleRun {
				run := pcv3BaseRun(t, "d1-bootstrap")
				run.source = newOperationEmptySource(t)
				run.request.Mode = ModeReadD1
				run.request.Source = run.source
				run.request.Factors = pcv3PasswordFactors(run, "password-d1-bootstrap")
				pcv3WireReporter(run)
				return run
			},
			wantOutcome:    pcv3.OutcomeCredentialsOrDamage,
			wantStage:      pcv3.StageD1Bootstrap,
			wantCode:       pcv3.CodeCredentialsOrDamage,
			wantDiagnostic: DiagnosticNone,
			wantClass:      CompletionNoOutput,
			wantStatuses: []StatusCode{
				StatusCheckingRequest,
				StatusCheckingFactors,
				StatusRecovering,
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			run := test.build(t)

			// Anti-vacuity: every retained alias holds its exact sentinel value
			// before ownership transfers.
			for _, sentinel := range run.passwords {
				if !bytes.Equal(sentinel.value, pcv3SentinelBytes(sentinel.id)) {
					t.Fatalf("sentinel %s was not live before transfer", sentinel.id)
				}
			}
			var logBytes bytes.Buffer
			originalLogOutput := log.Writer()
			originalLogFlags := log.Flags()
			log.SetOutput(&logBytes)
			defer func() {
				log.SetOutput(originalLogOutput)
				log.SetFlags(originalLogFlags)
			}()

			var result *Result
			stdout, stderr := pcv3CaptureProcess(t, func() {
				result = runWithSeams(run.ctx, run.request, operationSeams{admitter: run.admitter})
			})

			if result == nil {
				t.Fatal("operation returned no closed result")
			}
			if result.Outcome() != test.wantOutcome || result.Stage() != test.wantStage ||
				result.Code() != test.wantCode || result.Diagnostic() != test.wantDiagnostic ||
				result.CompletionClass() != test.wantClass {
				t.Fatalf(
					"terminal tuple = %v/%v/%v diagnostic=%v class=%v; want %v/%v/%v diagnostic=%v class=%v",
					result.Outcome(), result.Stage(), result.Code(), result.Diagnostic(), result.CompletionClass(),
					test.wantOutcome, test.wantStage, test.wantCode, test.wantDiagnostic, test.wantClass,
				)
			}
			if !slices.Equal(result.Warnings(), test.wantWarnings) {
				t.Fatalf("warnings = %v; want %v", result.Warnings(), test.wantWarnings)
			}
			if result.PublicationAttempted() || result.ArchiveFollowUp() != nil ||
				result.OutputFollowUp() != nil || result.ArtifactInspection() != nil {
				t.Fatal("refused operation retained output authority or attempted publication")
			}
			if !slices.Equal(run.statuses, test.wantStatuses) {
				t.Fatalf("status sequence = %v; want %v", run.statuses, test.wantStatuses)
			}
			if run.admitter.calls != test.wantAdmissions {
				t.Fatalf("admissions = %d; want %d", run.admitter.calls, test.wantAdmissions)
			}
			if test.wantAdmissions > 0 {
				if len(run.admitter.profiles) != 1 ||
					run.admitter.profiles[0] != pcv3Standard1Profile {
					t.Fatalf("admitted profiles = %+v; want exactly the frozen fixed profile", run.admitter.profiles)
				}
			}
			if run.consentCalls != test.wantConsentCalls {
				t.Fatalf("consent calls = %d; want %d", run.consentCalls, test.wantConsentCalls)
			}
			if run.retainedAction != nil &&
				!errors.Is(run.retainedAction(RoleD1Front), ErrConsentExpired) {
				t.Fatal("consent action survived its callback")
			}

			assertOperationRequestTransferred(t, run.request)
			pcv3AssertZeroed(t, run)
			pcv3ScanChannels(t, run, result, stdout, stderr, logBytes.Bytes())

			// The refused operation created no output or stage residue.
			entries, err := os.ReadDir(run.outputDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("refused operation output entries = %v, error %v; want none", entries, err)
			}
		})
	}
}

func pcv3BuildZipArchive(t *testing.T, path, entryName string, content []byte) {
	t.Helper()
	file, err := os.Create(path) // #nosec G304 -- test-owned archive path
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create(entryName)
	if err != nil {
		t.Fatalf("create archive entry: %v", err)
	}
	if _, err := entry.Write(content); err != nil {
		t.Fatalf("write archive entry: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
}

func TestPCV3TypedExtractionMissingRoot(t *testing.T) {
	frozenPayload := []byte("typed extraction oracle payload\n")
	directory := t.TempDir()
	zipPath := filepath.Join(directory, "archive.zip")
	pcv3BuildZipArchive(t, zipPath, "payload.txt", frozenPayload)

	t.Run("missing pinned root is not published before output", func(t *testing.T) {
		missingRoot := filepath.Join(directory, "missing-root")
		result := fileops.UnpackWithResult(fileops.UnpackOptions{
			ZipPath:    zipPath,
			ExtractDir: missingRoot,
		})
		if result == nil {
			t.Fatal("typed extraction returned no result")
		}
		if result.State() != fileops.UnpackStateNotPublished {
			t.Fatalf("missing-root state = %v; want not-published", result.State())
		}
		if errors.Unwrap(result) == nil {
			t.Fatal("missing-root extraction reported no failure cause")
		}
		if errors.Is(result, fileops.ErrUnpackCleanupIncomplete) {
			t.Fatal("missing-root extraction reported cleanup uncertainty")
		}
		if _, err := os.Lstat(missingRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("typed extraction created the missing pinned root: %v", err)
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 1 || entries[0].Name() != "archive.zip" {
			t.Fatalf("missing-root extraction left entries = %v, error %v; want only the archive", entries, err)
		}
	})

	t.Run("typed result exposes only the closed not-published surface", func(t *testing.T) {
		result := fileops.UnpackWithResult(fileops.UnpackOptions{
			ZipPath:    zipPath,
			ExtractDir: filepath.Join(directory, "missing-root"),
		})
		if result == nil {
			t.Fatal("typed extraction returned no result")
		}
		for _, rendered := range []string{
			result.Error(),
			fmt.Sprintf("%v", result),
			fmt.Sprintf("%s", result),
		} {
			if rendered != "fileops: unpack not-published" {
				t.Fatalf("typed not-published rendering = %q; want the fixed closed message", rendered)
			}
		}
		if quoted := fmt.Sprintf("%q", result); quoted != `"fileops: unpack not-published"` {
			t.Fatalf("typed not-published quoted rendering = %q; want the quoted fixed closed message", quoted)
		}
		// The closed not-published truth maps to no output at the operation
		// boundary; the exact operation tuple is pinned by the existing
		// TestArchiveFollowUpReturnsCommonTerminalResult rollback case.
	})

	t.Run("existing pinned root extracts durably with exact bytes", func(t *testing.T) {
		extractDir := t.TempDir()
		result := fileops.UnpackWithResult(fileops.UnpackOptions{
			ZipPath:    zipPath,
			ExtractDir: extractDir,
		})
		if result == nil {
			t.Fatal("typed extraction returned no result")
		}
		if result.State() != fileops.UnpackStatePublishedDurable || errors.Unwrap(result) != nil {
			t.Fatalf("existing-root extraction = %v, %v; want durable publication", result.State(), errors.Unwrap(result))
		}
		contents, err := os.ReadFile(filepath.Join(extractDir, "payload.txt")) // #nosec G304 -- test-owned extraction root
		if err != nil || !bytes.Equal(contents, frozenPayload) {
			t.Fatalf("extracted bytes = %q, %v; want the frozen payload", contents, err)
		}
		entries, err := os.ReadDir(extractDir)
		if err != nil || len(entries) != 1 || entries[0].Name() != "payload.txt" {
			t.Fatalf("existing-root entries = %v, error %v; want exactly the payload", entries, err)
		}
	})

	t.Run("extraction options expose no caller durability switch", func(t *testing.T) {
		// Policy/API guard only: product behavior is asserted by the real
		// extraction subtests above.
		optionsType := reflect.TypeOf(fileops.UnpackOptions{})
		for index := range optionsType.NumField() {
			field := optionsType.Field(index)
			lower := strings.ToLower(field.Name)
			if field.Type.Kind() == reflect.Bool && field.Name != "SameLevel" {
				t.Fatalf("UnpackOptions exposes unexpected boolean field %s", field.Name)
			}
			if strings.Contains(lower, "durab") || strings.Contains(lower, "persist") ||
				strings.Contains(lower, "flush") || strings.Contains(lower, "sync") {
				t.Fatalf("UnpackOptions exposes caller durability authority %s", field.Name)
			}
		}
	})

	t.Run("unarmed follow-up cannot extract into a real root", func(t *testing.T) {
		rootDir := t.TempDir()
		sentinelPath := filepath.Join(rootDir, "foreign.txt")
		if err := os.WriteFile(sentinelPath, []byte("foreign\n"), 0o600); err != nil {
			t.Fatalf("seed foreign sentinel: %v", err)
		}
		root, err := os.OpenRoot(rootDir)
		if err != nil {
			t.Fatalf("open extraction root: %v", err)
		}
		var followUp ArchiveFollowUp
		denied := followUp.Extract(context.Background(), root)
		if denied == nil {
			t.Fatal("unarmed extraction returned no closed result")
		}
		if denied.Outcome() != pcv3.OutcomeOperationFailed ||
			denied.Stage() != pcv3.StageOutputPublication ||
			denied.Code() != pcv3.CodeOperationFailed ||
			denied.Diagnostic() != DiagnosticInvalidRequest ||
			denied.PublicationAttempted() ||
			denied.CompletionClass() != CompletionNoOutput ||
			len(denied.Warnings()) != 0 {
			t.Fatalf(
				"unarmed extraction = %v/%v/%v diagnostic=%v attempted=%v class=%v warnings=%v; want closed no-output denial",
				denied.Outcome(), denied.Stage(), denied.Code(), denied.Diagnostic(),
				denied.PublicationAttempted(), denied.CompletionClass(), denied.Warnings(),
			)
		}
		if _, err := root.Stat("."); err == nil {
			t.Fatal("unarmed extraction left the caller root open")
		}
		contents, err := os.ReadFile(sentinelPath) // #nosec G304 -- test-owned sentinel path
		if err != nil || string(contents) != "foreign\n" {
			t.Fatalf("foreign sentinel after unarmed extraction = %q, %v", contents, err)
		}
		entries, err := os.ReadDir(rootDir)
		if err != nil || len(entries) != 1 || entries[0].Name() != "foreign.txt" {
			t.Fatalf("unarmed extraction entries = %v, error %v; want only the sentinel", entries, err)
		}
	})
}
