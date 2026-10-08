package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestArchiveExtractionPreservesCancellationCause(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancelled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "output.zip")
			read := archiveActionFixture(t, target, archiveActionPayload(t))
			rootPath := t.TempDir()
			root, err := os.OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 1))
				want = context.DeadlineExceeded
			}
			cancel()
			result := read.ArchiveFollowUp().Extract(ctx, root)
			if result.Diagnostic() != DiagnosticCancellation || !errors.Is(result, want) ||
				result.PublicationState() != pcv3publication.StateNotPublished {
				t.Fatalf("extraction lost cancellation cause: %v", result)
			}
			entries, err := os.ReadDir(rootPath)
			if err != nil || len(entries) != 0 {
				t.Fatalf("cancelled extraction left output: %v", err)
			}
		})
	}
}

func TestLateArchiveCancellationPreservesPublishedState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, state := range []fileops.UnpackState{
		fileops.UnpackStatePublishedDurable,
		fileops.UnpackStatePublishedDurabilityUncertain,
		fileops.UnpackStatePublicationIndeterminate,
	} {
		fixture := archiveExtractionFixture{state: state}
		before := resultFromArchiveExtraction(context.Background(), fixture)
		after := resultFromArchiveExtraction(ctx, fixture)
		if before.CompletionClass() != after.CompletionClass() || before.PublicationState() != after.PublicationState() ||
			errors.Is(after, context.Canceled) {
			t.Errorf("late cancellation changed publication truth for state %v", state)
		}
	}
}

type archiveExtractionFixture struct {
	state             fileops.UnpackState
	cleanupIncomplete bool
	resourceLimited   bool
}

func (fixture archiveExtractionFixture) State() fileops.UnpackState {
	return fixture.state
}

func (fixture archiveExtractionFixture) CleanupIncomplete() bool {
	return fixture.cleanupIncomplete
}

func (fixture archiveExtractionFixture) ResourceLimited() bool {
	return fixture.resourceLimited
}

func TestArchiveFollowUpReturnsCommonTerminalResult(t *testing.T) {
	tests := []struct {
		name           string
		extraction     archiveExtractionFixture
		wantOutcome    pcv3.Outcome
		wantState      pcv3publication.State
		wantStage      pcv3.Stage
		wantCode       pcv3publication.Code
		wantCompletion CompletionClass
		wantWarnings   []Warning
	}{
		{
			name:           "proven rollback is closed no-output",
			extraction:     archiveExtractionFixture{state: fileops.UnpackStateNotPublished},
			wantOutcome:    pcv3.OutcomeOperationFailed,
			wantState:      pcv3publication.StateNotPublished,
			wantStage:      pcv3.StageOutputPublication,
			wantCode:       pcv3publication.CodeAtomicFailed,
			wantCompletion: CompletionNoOutput,
		},
		{
			name:           "directory-synced tree is clean",
			extraction:     archiveExtractionFixture{state: fileops.UnpackStatePublishedDurable},
			wantOutcome:    pcv3.OutcomeSuccess,
			wantState:      pcv3publication.StatePublishedDurable,
			wantStage:      pcv3.StageNone,
			wantCode:       pcv3publication.CodePublishedDurable,
			wantCompletion: CompletionClean,
		},
		{
			name:           "post-commit sync uncertainty stays separate",
			extraction:     archiveExtractionFixture{state: fileops.UnpackStatePublishedDurabilityUncertain},
			wantOutcome:    pcv3.OutcomeSuccess,
			wantState:      pcv3publication.StatePublishedDurabilityUncertain,
			wantStage:      pcv3.StageDirectorySync,
			wantCode:       pcv3publication.CodeDurabilityUncertain,
			wantCompletion: CompletionDurabilityUncertain,
			wantWarnings:   []Warning{WarningDurabilityUncertain},
		},
		{
			name: "unproven rollback stays indeterminate with cleanup warning",
			extraction: archiveExtractionFixture{
				state:             fileops.UnpackStatePublicationIndeterminate,
				cleanupIncomplete: true,
			},
			wantOutcome:    pcv3.OutcomeSuccess,
			wantState:      pcv3publication.StatePublicationIndeterminate,
			wantStage:      pcv3.StageOutputPublication,
			wantCode:       pcv3publication.CodePublicationIndeterminate,
			wantCompletion: CompletionPublicationIndeterminate,
			wantWarnings:   []Warning{WarningPublicationIndeterminate, WarningCleanupIncomplete},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resultFromArchiveExtraction(context.Background(), test.extraction)
			if result.Outcome() != test.wantOutcome ||
				result.PublicationState() != test.wantState ||
				result.PublicationStage() != test.wantStage ||
				result.PublicationCode() != test.wantCode ||
				result.CompletionClass() != test.wantCompletion ||
				!slices.Equal(result.Warnings(), test.wantWarnings) ||
				result.ArchiveFollowUp() != nil {
				t.Fatalf(
					"terminal archive tuple = %v/%v/%v/%v class=%v warnings=%v follow-up=%v; want %v/%v/%v/%v class=%v warnings=%v and no authority",
					result.Outcome(), result.PublicationState(), result.PublicationStage(),
					result.PublicationCode(), result.CompletionClass(), result.Warnings(),
					result.ArchiveFollowUp(), test.wantOutcome, test.wantState,
					test.wantStage, test.wantCode, test.wantCompletion, test.wantWarnings,
				)
			}
		})
	}

	state := &operationTestArchiveState{active: true, cleanupIncomplete: true}
	followUp := &ArchiveFollowUp{state: state}
	closed := followUp.Close()
	if closed.CompletionClass() != CompletionNoOutput || state.active ||
		followUp.state.live() || !slices.Equal(closed.Warnings(), []Warning{WarningCleanupIncomplete}) ||
		!errors.Is(closed, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf("close tuple = class %v active=%v warnings=%v cleanup=%v; want consumed no-output with cleanup warning", closed.CompletionClass(), state.active, closed.Warnings(), errors.Is(closed, pcv3publication.ErrCleanupIncomplete))
	}
	if expired := followUp.Close(); expired == nil || expired.Diagnostic() != DiagnosticInvalidRequest {
		t.Fatalf("second close = %#v; want one-shot expired invalid-request result", expired)
	}
}

func TestArchivePublicationPreservesTransportAndCleanupResult(t *testing.T) {
	for _, name := range []string{"durable", "occupied", "cancelled", "deadline", "cleanup warning"} {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "archive.zip")
			stage, err := pcv3publication.Create(target, nil, pcv3publication.PolicyNoReplace)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Cleanup()
			if _, err := stage.File().Write([]byte("publication projection payload")); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			wantCompletion, wantDiagnostic := CompletionClean, DiagnosticNone
			if runtime.GOOS == "windows" {
				wantCompletion = CompletionDurabilityUncertain
			}
			switch name {
			case "occupied":
				if err := os.WriteFile(target, []byte("foreign output"), 0o600); err != nil {
					t.Fatal(err)
				}
				wantCompletion = CompletionNoOutput
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantCompletion, wantDiagnostic = CompletionRefused, DiagnosticCancellation
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				wantCompletion, wantDiagnostic = CompletionRefused, DiagnosticCancellation
			case "cleanup warning":
				if runtime.GOOS != "windows" {
					wantCompletion = CompletionWarning
				}
			}
			publication := stage.Publish(ctx)
			// Cleanup is a separate axis from the publisher's durable result.
			result := resultFromArchivePublication(ctx, publication, name == "cleanup warning")
			if result.CompletionClass() != wantCompletion || result.Diagnostic() != wantDiagnostic ||
				!result.PublicationAttempted() || result.PublicationState() != publication.State() ||
				result.PublicationStage() != publication.Stage() || result.PublicationCode() != publication.Code() ||
				result.ArchiveFollowUp() != nil || result.SourceDeletionAllowed() {
				t.Fatalf("archive publication lost its transport/cleanup tuple: %v", result)
			}
			if (name == "cleanup warning") != errors.Is(result, pcv3publication.ErrCleanupIncomplete) {
				t.Fatalf("archive cleanup warning was lost or invented: %v", result.Warnings())
			}
			if wantDiagnostic == DiagnosticCancellation {
				if !errors.Is(result, ctx.Err()) || result.Stage() != pcv3.StageCancellation || result.PublicationState() != pcv3publication.StateNotPublished {
					t.Fatalf("archive publication lost cancellation cause or no-output state: %v", result)
				}
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("cancelled archive publication created an output: %v", err)
				}
			}
		})
	}
}

func TestArchivePublishWithoutAuthorityIsClosedFailure(t *testing.T) {
	for _, followUp := range []*ArchiveFollowUp{nil, {}, {state: &nativeArchiveFollowUpState{}}} {
		result := followUp.Publish(context.Background())
		if result.Diagnostic() != DiagnosticInvalidRequest || result.CompletionClass() != CompletionNoOutput || result.PublicationAttempted() {
			t.Fatalf("absent archive authority did not fail closed: %v", result)
		}
	}
}

func TestArchivePublishSavesAuthenticatedZIPAndComment(t *testing.T) {
	plaintext, err := os.ReadFile(filepath.Join("internal", "pcv3", "testdata", "normal", "plaintext", "normal-standard-combined-ordered-archive-small.zip"))
	if err != nil {
		t.Fatal(err)
	}
	factors := func() *FactorRequest {
		return &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, ExpectedPolicy: FactorPolicyKeyfilesOnly, KeyfileMode: KeyfileModeUnordered,
			Keyfiles: []*KeyfileReader{OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("public archive publication factor"))))},
		}
	}
	dir := t.TempDir()
	ciphertext := filepath.Join(dir, "archive.pcv")
	const comment = "public archive publication comment"
	write := RunWrite(context.Background(), &WriteRequest{
		Mode: WriteModeNormal, Suite: SuiteStandard, PayloadKind: PayloadKindArchive,
		Source: bytes.NewReader(plaintext), PlaintextLength: uint64(len(plaintext)),
		Target: ciphertext, Factors: factors(), Comment: []byte(comment),
	})
	requireNativeOperationPublication(t, write)
	source, err := os.Open(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "saved.zip")
	read := Run(context.Background(), &Request{Mode: ModeReadNormal, Source: source, Target: target, Factors: factors()})
	followUp := read.ArchiveFollowUp()
	if followUp == nil || read.CompletionClass() != CompletionArchivePending {
		t.Fatalf("authenticated archive did not grant publication authority: %v", read)
	}
	defer followUp.Close()
	copyOfFollowUp := *followUp
	result := followUp.Publish(context.Background())
	requireNativeOperationPublication(t, result)
	if result.AuthenticatedComment() != comment || result.ArchiveFollowUp() != nil {
		t.Fatalf("archive publication lost authentication or metadata: %v", result)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("published ZIP differs from the frozen payload: %v", err)
	}
	if copyOfFollowUp.Close().Diagnostic() != DiagnosticInvalidRequest {
		t.Fatal("copied follow-up retained authority after ZIP publication")
	}
	if _, err := os.Stat(ciphertext); err != nil {
		t.Fatalf("archive publication removed the encrypted source: %v", err)
	}
}

func TestArchiveResourceClassificationPreservesCleanupAndPublicationTruth(t *testing.T) {
	for _, state := range []fileops.UnpackState{fileops.UnpackStateNotPublished, fileops.UnpackStatePublishedDurable, fileops.UnpackStatePublishedDurabilityUncertain, fileops.UnpackStatePublicationIndeterminate} {
		for _, cancelled := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			if cancelled {
				cancel()
			}
			fixture := archiveExtractionFixture{state: state, cleanupIncomplete: true, resourceLimited: true}
			result := resultFromArchiveExtraction(ctx, fixture)
			cancel()
			if !result.Presentation().valid() || !slices.Contains(result.Warnings(), WarningCleanupIncomplete) {
				t.Fatalf("resource cause corrupted valid publication/cleanup axes: state=%v cancel=%v class=%v warnings=%v", state, cancelled, result.CompletionClass(), result.Warnings())
			}
			if state == fileops.UnpackStateNotPublished {
				if cancelled {
					if result.Diagnostic() != DiagnosticCancellation || !errors.Is(result, context.Canceled) {
						t.Fatal("resource cause hid cancellation")
					}
				} else if result.Diagnostic() != DiagnosticResourceLimit || result.Stage() != StageResourceBudget || result.CompletionClass() != CompletionNoOutput || result.PublicationAttempted() || result.PublicationState() != 0 || result.PublicationStage() != StageNone || result.PublicationCode() != 0 {
					t.Fatal("resource refusal lost canonical no-publication tuple")
				}
			} else {
				plain := resultFromArchiveExtraction(context.Background(), archiveExtractionFixture{state: state, cleanupIncomplete: true})
				if result.CompletionClass() != plain.CompletionClass() || result.PublicationState() != plain.PublicationState() || !result.PublicationAttempted() || !slices.Equal(result.Warnings(), plain.Warnings()) {
					t.Fatalf("resource cause erased actual publication/uncertainty: state=%v", state)
				}
			}
		}
	}
}
