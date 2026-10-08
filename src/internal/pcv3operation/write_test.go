package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWriteCancellationConsumesSecretsWithoutClosingBorrowedSource(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	password := []byte("private-password")
	comment := []byte("private-comment")
	factors := &pcv3credential.FactorRequest{Password: password}
	req := &WriteRequest{Mode: WriteModeNormal, Suite: pcv3.SuiteStandard, PayloadKind: pcv3.PayloadKindRaw, Source: source, Factors: factors, Comment: comment, Target: filepath.Join(t.TempDir(), "output")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := RunWrite(ctx, req)
	if result.Diagnostic() != DiagnosticCancellation || result.SourceDeletionAllowed() {
		t.Fatalf("cancelled result=%v", result)
	}
	if req.Source != nil || req.Factors != nil || req.Comment != nil {
		t.Fatal("request retains transferred fields")
	}
	if strings.Trim(string(password), "\x00") != "" || strings.Trim(string(comment), "\x00") != "" {
		t.Fatal("secrets not cleared")
	}
	if _, err := source.Stat(); err != nil {
		t.Fatalf("borrowed source closed: %v", err)
	}
}

func TestWriteReporterPanicIsClosedBeforeSourceRead(t *testing.T) {
	req := &WriteRequest{Mode: WriteModeNormal, Suite: pcv3.SuiteStandard, PayloadKind: pcv3.PayloadKindRaw, Source: strings.NewReader("secret"), Factors: &pcv3credential.FactorRequest{Password: []byte("secret")}, Target: filepath.Join(t.TempDir(), "output"), Reporter: func(Status) error { panic("sensitive callback") }}
	result := RunWrite(context.Background(), req)
	if result.Diagnostic() != DiagnosticCallbackPanic || result.SourceDeletionAllowed() {
		t.Fatalf("panic result=%v", result)
	}
}

func TestWriteOutputFailedSaveRetainsExactCiphertextForRetry(t *testing.T) {
	directory := t.TempDir()
	payload := []byte("ciphertext must survive failed provider transport")
	retained, path := newOperationRetainedFile(t, directory, payload)
	followUp := newWriteOutputFollowUp(retained)
	readonlyPath := filepath.Join(directory, "readonly")
	if err := os.WriteFile(readonlyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	readonly, err := os.Open(readonlyPath)
	if err != nil {
		t.Fatal(err)
	}
	failed := followUp.SaveTo(readonly)
	if failed.Code() != OutputActionSaveFailed || !followUp.live() {
		t.Fatalf("failed copy lost retry authority: %v", failed)
	}
	requireOperationFileBytes(t, path, payload)
	target := filepath.Join(directory, "saved")
	output, err := os.Create(target)
	if err != nil {
		t.Fatal(err)
	}
	saved := followUp.SaveTo(output)
	wantCode := OutputActionSaved
	if runtime.GOOS == "windows" {
		wantCode = OutputActionSavedCleanupIncomplete
	}
	if saved.Code() != wantCode || saved.CleanupIncomplete() != (runtime.GOOS == "windows") || followUp.live() {
		t.Fatalf("retry = %v", saved)
	}
	requireOperationFileBytes(t, target, payload)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("saved internal ciphertext retained: %v", err)
	}
}

func TestWritePreflightPreservesExistingTargetBeforeKDF(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "existing")
	if err := os.WriteFile(target, []byte("existing user file"), 0o600); err != nil {
		t.Fatal(err)
	}
	admitter := &operationTestAdmitter{}
	request := &WriteRequest{Mode: WriteModeNormal, Suite: pcv3.SuiteStandard, PayloadKind: pcv3.PayloadKindRaw, Source: strings.NewReader("plaintext"), Factors: &pcv3credential.FactorRequest{Password: []byte("password")}, Target: target}
	result := runWriteWithSeams(context.Background(), request, ExecutionOptions{}, operationSeams{admitter: admitter})
	if admitter.calls != 0 || result.SourceDeletionAllowed() || result.CompletionClass() == CompletionClean {
		t.Fatalf("collision admitted KDF or success: %v calls=%d", result, admitter.calls)
	}
	requireOperationFileBytes(t, target, []byte("existing user file"))
}

type writeJournalAdmitter struct {
	t         *testing.T
	directory string
	calls     int
}

func (admitter *writeJournalAdmitter) AdmitKDF(context.Context, pcv3credential.KDFProfile) (pcv3credential.KDFAdmission, error) {
	admitter.calls++
	if _, err := os.Stat(filepath.Join(admitter.directory, ".picocrypt-pcv3-stage.journal")); err != nil {
		admitter.t.Fatalf("KDF reached before durable cleanup journal: %v", err)
	}
	return pcv3credential.KDFAdmissionDeniedInsufficient, nil
}

func TestWriteJournalRequiresPlatformSupportBeforeKDFAndCleansBothModes(t *testing.T) {
	for _, mode := range []WriteMode{WriteModeNormal, WriteModeD1} {
		t.Run(map[WriteMode]string{WriteModeNormal: "normal", WriteModeD1: "d1"}[mode], func(t *testing.T) {
			directory := t.TempDir()
			sourcePath := filepath.Join(directory, "source")
			if err := os.WriteFile(sourcePath, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			suite := pcv3.SuiteStandard
			if mode == WriteModeD1 {
				suite = pcv3.SuiteParanoid
			}
			factors := &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone, ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: []byte("password")}
			admitter := &writeJournalAdmitter{t: t, directory: directory}
			request := &WriteRequest{Mode: mode, Suite: suite, PayloadKind: pcv3.PayloadKindRaw, PlaintextLength: 4, Source: source, SourceFile: source, SourcePath: sourcePath, Target: filepath.Join(directory, "output"), Factors: factors}
			result := runWriteWithSeams(context.Background(), request, ExecutionOptions{JournalPrivateStage: true}, operationSeams{admitter: admitter})
			journalSupported := runtime.GOOS == "linux" || runtime.GOOS == "android"
			if !journalSupported {
				if admitter.calls != 0 || result.Diagnostic() != DiagnosticCoreFailure ||
					result.Stage() != pcv3.StageOutputPublication || result.CompletionClass() != CompletionNoOutput ||
					result.PublicationAttempted() || result.OutputFollowUp() != nil || result.ArchiveFollowUp() != nil {
					t.Fatalf("unsupported cleanup journal granted work/output authority: %v stage=%v diagnostic=%v calls=%d", result, result.Stage(), result.Diagnostic(), admitter.calls)
				}
			} else if admitter.calls != 1 || result.Diagnostic() != DiagnosticResourceInsufficient {
				t.Fatalf("resource refusal: %v diagnostic=%v calls=%d", result, result.Diagnostic(), admitter.calls)
			}
			if result.SourceDeletionAllowed() {
				t.Fatal("journal/admission refusal granted source deletion")
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "source" {
				t.Fatalf("refusal retained stage or journal: %v", entries)
			}
			requireOperationFileBytes(t, sourcePath, []byte("data"))
		})
	}
}

func TestWriteEmptyKeyfileRefusedBeforeKDFBothModes(t *testing.T) {
	for _, mode := range []WriteMode{WriteModeNormal, WriteModeD1} {
		t.Run(map[WriteMode]string{WriteModeNormal: "normal", WriteModeD1: "d1"}[mode], func(t *testing.T) {
			directory := t.TempDir()
			sourcePath := filepath.Join(directory, "source")
			if err := os.WriteFile(sourcePath, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			suite := pcv3.SuiteStandard
			if mode == WriteModeD1 {
				suite = pcv3.SuiteParanoid
			}
			factors := &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModeKeyfilesOnly, KeyfileMode: pcv3credential.KeyfileModeUnordered, ExpectedPolicy: pcv3credential.FactorPolicyKeyfilesOnly, Keyfiles: []*pcv3credential.KeyfileReader{pcv3credential.OwnKeyfileReader(io.NopCloser(strings.NewReader("")))}}
			admitter := &operationTestAdmitter{}
			request := &WriteRequest{Mode: mode, Suite: suite, PayloadKind: pcv3.PayloadKindRaw, PlaintextLength: 4, Source: source, SourceFile: source, SourcePath: sourcePath, Target: filepath.Join(directory, "output"), Factors: factors}
			result := runWriteWithSeams(context.Background(), request, ExecutionOptions{}, operationSeams{admitter: admitter})
			if admitter.calls != 0 || result.SourceDeletionAllowed() || result.CompletionClass() != CompletionRefused {
				t.Fatalf("empty keyfile reached admission: %v calls=%d", result, admitter.calls)
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "source" {
				t.Fatalf("empty keyfile refusal left output/stage: %v", entries)
			}
		})
	}
}

func TestWriteDeadlinePreservesContextSentinel(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result := RunWrite(ctx, &WriteRequest{Factors: &pcv3credential.FactorRequest{Password: []byte("password")}})
	if !errors.Is(result, context.DeadlineExceeded) || errors.Is(result, context.Canceled) {
		t.Fatalf("deadline sentinel lost: %v", result)
	}
}

// Exercises the real postpublication lifecycle without re-running an unrelated KDF.
func TestWritePublishedUncertainStillCreatesRequestedSplit(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "native publication", true: "uncertain"}[uncertain], func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ciphertext")
			payload := []byte(strings.Repeat("complete encrypted volume", 100))
			stage, err := pcv3publication.Create(target, nil, pcv3publication.PolicyNoReplace)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Cleanup()
			if _, err := stage.File().Write(payload); err != nil {
				t.Fatal(err)
			}
			publication, retained := stage.PublishWriteRetained(context.Background())
			if retained == nil {
				t.Fatalf("publication did not retain file: %v", publication)
			}
			result := writePublicationResult(publication)
			if uncertain {
				// Model the platform's already-proven uncertain full-file publication;
				// retained file and all split filesystem effects remain real.
				result.publicationState = pcv3publication.StatePublishedDurabilityUncertain
				result.publicationStage = pcv3.StageDirectorySync
				result.publicationCode = pcv3publication.CodeDurabilityUncertain
				result.appendWarning(WarningDurabilityUncertain)
			}
			owner := &operationOwner{}
			result = owner.finishWriteOutput(context.Background(), result, retained, &WriteSplitOptions{ChunkSize: 1, Unit: fileops.SplitUnitKiB}, false)
			if result.Outcome() != pcv3.OutcomeSuccess {
				t.Fatalf("split failed: %v", result)
			}
			recombined := filepath.Join(directory, "recombined")
			if err := fileops.Recombine(fileops.RecombineOptions{InputBase: target, OutputPath: recombined}); err != nil {
				t.Fatalf("requested split omitted: %v", err)
			}
			requireOperationFileBytes(t, recombined, payload)
			wantUncertain := uncertain || runtime.GOOS == "windows"
			if result.SourceDeletionAllowed() == wantUncertain {
				t.Fatalf("source deletion authority = %v for uncertain=%v", result.SourceDeletionAllowed(), uncertain)
			}
			if result.SplitOutputUncertain() != (runtime.GOOS == "windows") {
				t.Fatalf("split durability differs from native barrier: uncertain=%v", result.SplitOutputUncertain())
			}
			if runtime.GOOS == "windows" {
				requireOperationFileBytes(t, target, payload)
			} else if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("durable chunks did not consume the complete ciphertext: %v", err)
			}
			if wantUncertain && result.CompletionClass() != CompletionDurabilityUncertain {
				t.Fatalf("uncertainty lost: %v", result)
			}
			if !wantUncertain && result.CompletionClass() != CompletionClean {
				t.Fatalf("durable completion: %v", result)
			}
			if retained.Live() {
				t.Fatal("split retained consumed authority")
			}
		})
	}
}

func TestWriteSplitUncertaintyDowngradesPresentationAndRevokesDeletion(t *testing.T) {
	result := newResult(resultData{outcome: pcv3.OutcomeSuccess, code: pcv3.CodeSuccess, publicationAttempted: true, publicationState: pcv3publication.StatePublishedDurable, publicationCode: pcv3publication.CodePublishedDurable})
	result.writeOutput = true
	result.writeLifecycleComplete = true
	if !result.SourceDeletionAllowed() {
		t.Fatal("durable positive control has no deletion authority")
	}
	result.recordWriteSplitCompletion(fileops.SplitCompleteDurabilityUncertain)
	if !result.SplitOutputUncertain() || result.SourceDeletionAllowed() || result.CompletionClass() != CompletionDurabilityUncertain || result.Presentation().CompletionClass() != CompletionDurabilityUncertain {
		t.Fatalf("uncertain chunks incorrectly presented or allow deletion: %v", result)
	}
	if !result.hasWarning(WarningDurabilityUncertain) {
		t.Fatal("common durability warning absent")
	}
}
