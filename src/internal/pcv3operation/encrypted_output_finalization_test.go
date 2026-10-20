package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedOutputFinalizationRevokesOnInputCleanupOrCancellation(t *testing.T) {
	for _, failure := range []string{
		"source-close", "consumed-factor-close", "archive-preflight-close", "desktop-protected-close",
		"earlier-cleanup-warning", "canceled", "deadline", "clean",
	} {
		t.Run(failure, func(t *testing.T) {
			spool, path := encryptedOutputFixture(t, []byte("must remain private until cleanup settles"))
			result := newResult(resultData{outcome: OutcomeSuccess, code: CodeSuccess})
			adoptEncryptedOutput(context.Background(), result, spool)
			output := result.StreamFollowUp()
			if output == nil {
				t.Fatal("fixture did not mint the real stream owner")
			}
			copiedResult, copiedOutput := *result, *output
			owner := &operationOwner{}
			var factorCleanup *pcv3credential.FactorRequest
			var plan *archiveReadPlan
			var desktopProtected []*os.File
			ctx := context.Background()
			cleanupFailure := true
			switch failure {
			case "source-close":
				owner.source = closedFinalizationFixture(t)
			case "consumed-factor-close":
				file, err := os.CreateTemp(t.TempDir(), "keyfile")
				if err != nil {
					t.Fatal(err)
				}
				keyfile := pcv3credential.OwnKeyfileReader(file)
				factorCleanup = &pcv3credential.FactorRequest{Keyfiles: []*pcv3credential.KeyfileReader{keyfile}}
				// A closed real borrow reproduces an OS keyfile close failure;
				// ownership has already been consumed before final observation.
				if err := keyfile.BorrowFile().Close(); err != nil {
					t.Fatal(err)
				}
				if err := factorCleanup.Close(); err == nil || !factorCleanup.CleanupIncomplete() {
					t.Fatal("real consumed factor owner did not retain its cleanup failure")
				}
			case "archive-preflight-close":
				var err error
				plan, err = newArchiveReadPlan(ArchiveExtract, filepath.Join(t.TempDir(), "output.zip"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = plan.close() })
				if err := plan.parentDirectory.Close(); err != nil {
					t.Fatal(err)
				}
			case "desktop-protected-close":
				desktopProtected = []*os.File{closedFinalizationFixture(t)}
			case "earlier-cleanup-warning":
				result.appendWarning(WarningCleanupIncomplete)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				cleanupFailure = false
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Unix(0, 1))
				defer cancel()
				cleanupFailure = false
			case "clean":
				cleanupFailure = false
			}
			result = finalizeOperationResult(ctx, result, owner, factorCleanup, plan, desktopProtected)
			if failure == "clean" {
				if result.StreamFollowUp() == nil || result.CompletionClass() != CompletionStreamPending ||
					result.hasWarning(WarningCleanupIncomplete) {
					t.Fatal("confirmed cleanup revoked a valid pending stream")
				}
				if action := output.Discard(); action.Code() != OutputActionDiscarded {
					t.Fatalf("clean pending stream could not be discarded: %v", action)
				}
				return
			}
			if result.Outcome() != OutcomeOperationFailed || result.StreamFollowUp() != nil ||
				copiedResult.StreamFollowUp() != nil || output.State() != StreamFailed ||
				copiedResult.CompletionClass() != CompletionNoOutput ||
				result.CompletionClass() == CompletionUnknown || result.SourceDeletionAllowed() {
				t.Errorf("finalization left a live or malformed stream failure: outcome=%v state=%v completion=%v", result.Outcome(), output.State(), result.CompletionClass())
			}
			if result.hasWarning(WarningCleanupIncomplete) != cleanupFailure {
				t.Error("finalization lost or invented a real input cleanup failure")
			}
			if ctx.Err() != nil && (result.Stage() != StageCancellation ||
				result.Diagnostic() != DiagnosticCancellation || !errors.Is(result, ctx.Err())) {
				t.Error("final cancellation check lost the caller's cancellation cause")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Error("failed finalization retained its encrypted spool")
			}
			if action := copiedOutput.Discard(); action.Code() != OutputActionExpired {
				t.Errorf("copied stream owner retained authority after finalization: %v", action)
			}
		})
	}
}

func TestEncryptedOutputFinalizationPreservesPublishedFilesystemOutput(t *testing.T) {
	payload := []byte("an already published filesystem result must survive final cleanup failure")
	retained, path := newOperationRetainedFile(t, t.TempDir(), payload)
	result := newResult(resultData{
		outcome: OutcomeSuccess, code: CodeSuccess, publicationAttempted: true,
		publicationState: pcv3publication.StatePublishedDurable,
		publicationCode:  pcv3publication.CodePublishedDurable,
	})
	result.outputFollowUp = newOutputFollowUp(retained)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = finalizeOperationResult(ctx, result, &operationOwner{source: closedFinalizationFixture(t)}, nil, nil, nil)
	if result.Outcome() != OutcomeSuccess || result.Stage() != StageNone ||
		result.Diagnostic() != DiagnosticNone || result.PublicationState() != pcv3publication.StatePublishedDurable ||
		result.CompletionClass() != CompletionWarning || !result.hasWarning(WarningCleanupIncomplete) ||
		result.OutputFollowUp() == nil || errors.Is(result, context.Canceled) {
		t.Fatalf("late finalization changed existing filesystem publication semantics: %v", result)
	}
	requireOperationFileBytes(t, path, payload)
}

func closedFinalizationFixture(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "owned-input")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file
}
