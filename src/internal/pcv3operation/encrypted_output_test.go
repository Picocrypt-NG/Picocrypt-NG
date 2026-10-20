package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func encryptedOutputFixture(t *testing.T, body []byte) (*fileops.EncryptedSpool, string) {
	t.Helper()
	return encryptedOutputFixtureWithContext(t, context.Background(), body)
}

func encryptedOutputFixtureWithContext(t *testing.T, ctx context.Context, body []byte) (*fileops.EncryptedSpool, string) {
	t.Helper()
	spool, err := fileops.CreateEncryptedSpool(ctx, fileops.EncryptedSpoolOptions{
		NearPath: filepath.Join(t.TempDir(), "output"), MaxPhysicalBytes: uint64(len(body)) + (64 << 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	if _, err := spool.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := spool.Seal(); err != nil {
		t.Fatal(err)
	}
	return spool, spool.Path()
}

func TestEncryptedOutputRejectsReadOnlyPipeWithoutGrantingWriteAccess(t *testing.T) {
	spool, path := encryptedOutputFixture(t, []byte("authenticated stdout fixture"))
	output, err := OwnEncryptedOutput(spool)
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	result := output.StreamTo(context.Background(), reader)
	if result.Code() != OutputActionSaveFailed || result.CleanupIncomplete() || output.State() != StreamFailed {
		t.Errorf("read-only pipe gained output authority: result=%v state=%v", result, output.State())
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || len(got) != 0 {
		t.Errorf("read-only destination received plaintext: bytes=%d err=%v", len(got), err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("rejected destination retained the encrypted spool")
	}
}

func TestEncryptedOutputCancellationAfterSealRetainsCause(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				defer cancel()
				spool, path := encryptedOutputFixtureWithContext(t, ctx, []byte("sealed before cancellation"))
				want := context.Canceled
				other := context.DeadlineExceeded
				if deadline {
					time.Sleep(2 * time.Hour)
					want, other = other, want
				} else {
					cancel()
				}
				result := newResult(resultData{outcome: OutcomeSuccess, code: CodeSuccess})
				adoptEncryptedOutput(ctx, result, spool)
				if result.Stage() != StageCancellation || result.Diagnostic() != DiagnosticCancellation ||
					!errors.Is(result, want) || errors.Is(result, other) || result.CompletionClass() != CompletionRefused {
					t.Errorf("late cancellation lost its sanitized cause: stage=%v diagnostic=%v result=%v", result.Stage(), result.Diagnostic(), result)
				}
				if result.StreamFollowUp() != nil || result.hasWarning(WarningCleanupIncomplete) ||
					strings.Contains(fmt.Sprintf("%#v", result), path) {
					t.Error("late cancellation retained authority, invented cleanup failure, or exposed a path")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("late cancellation retained its sealed encrypted spool")
				}
			})
		})
	}
}

func TestEncryptedOutputConsumesOnlyAuthenticatedPlaintext(t *testing.T) {
	body := bytes.Repeat([]byte("public encrypted stdout fixture\n"), 5000)
	spool, path := encryptedOutputFixture(t, body)
	output, err := OwnEncryptedOutput(spool)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if output.State() != StreamPending {
		t.Fatal("new output did not remain pending transport")
	}
	result := output.StreamTo(context.Background(), destination)
	if result.Code() != OutputActionSaved || result.CleanupIncomplete() || output.State() != StreamComplete {
		t.Fatalf("transport=%v state=%v", result, output.State())
	}
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		t.Fatal("successful transport closed the caller destination")
	}
	got, err := io.ReadAll(destination)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("stdout did not contain the complete authenticated plaintext")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("consumed encrypted temporary file remained")
	}
	copyOfOutput := *output
	if result := copyOfOutput.StreamTo(context.Background(), destination); result.Code() != OutputActionExpired {
		t.Fatal("copy of consumed output regained transport authority")
	}
}

func TestEncryptedOutputChecksLastTagBeforeFirstStdoutByte(t *testing.T) {
	body := bytes.Repeat([]byte("authenticated prefix must not escape\n"), 5000)
	spool, path := encryptedOutputFixture(t, body)
	info, err := spool.File().Stat()
	if err != nil {
		t.Fatal(err)
	}
	var last [1]byte
	if _, err := spool.File().ReadAt(last[:], info.Size()-1); err != nil {
		t.Fatal(err)
	}
	last[0] ^= 1
	if _, err := spool.File().WriteAt(last[:], info.Size()-1); err != nil {
		t.Fatal(err)
	}
	output, err := OwnEncryptedOutput(spool)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if result := output.StreamTo(context.Background(), destination); result.Code() != OutputActionSaveFailed {
		t.Fatalf("corrupted final tag accepted: %v", result)
	}
	info, err = destination.Stat()
	if err != nil || info.Size() != 0 || output.State() != StreamFailed {
		t.Fatal("a valid prefix escaped before the corrupted final tag was checked")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed transport retained its temporary owner")
	}
}

func TestEncryptedOutputCancellationUnblocksPipeAndRevokesOwner(t *testing.T) {
	body := bytes.Repeat([]byte("bounded pipe cancellation\n"), 100000)
	spool, path := encryptedOutputFixture(t, body)
	output, err := OwnEncryptedOutput(spool)
	if err != nil {
		t.Fatal(err)
	}
	operation := newResult(resultData{outcome: OutcomeSuccess, code: CodeSuccess})
	operation.encryptedOutput = output
	copyOfOperation := *operation
	copyOfOutput := *output
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan OutputActionResult, 1)
	go func() { done <- output.StreamTo(ctx, writer) }()
	var first [1]byte
	if _, err := io.ReadFull(reader, first[:]); err != nil {
		t.Fatal(err)
	}
	if output.State() != StreamPending || operation.CompletionClass() != CompletionStreamPending ||
		copyOfOperation.CompletionClass() != CompletionStreamPending {
		t.Errorf("active transport prematurely became terminal: state=%v completion=%v", output.State(), operation.CompletionClass())
	}
	if operation.StreamFollowUp() != nil || copyOfOperation.StreamFollowUp() != nil ||
		copyOfOutput.StreamTo(ctx, writer).Code() != OutputActionExpired {
		t.Error("a consumed stream regained authority while stdout was blocked")
	}
	cancel()
	select {
	case result := <-done:
		if result.Code() != OutputActionSaveFailed || output.State() != StreamFailed {
			t.Fatalf("canceled transport=%v state=%v", result, output.State())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not release the blocked stdout writer")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("canceled stream retained its encrypted temporary file")
	}
}

func TestEncryptedOutputInvalidExtentPreservesCleanupFailure(t *testing.T) {
	for _, viaResult := range []bool{false, true} {
		for _, replacement := range []bool{false, true} {
			t.Run(fmt.Sprintf("result=%t/replacement=%t", viaResult, replacement), func(t *testing.T) {
				spool, path := encryptedOutputFixture(t, []byte("private staging fixture"))
				if err := spool.File().Truncate(0); err != nil {
					t.Fatal(err)
				}
				if replacement {
					if err := os.Rename(path, path+".moved"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte("foreign replacement"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if viaResult {
					result := newResult(resultData{outcome: OutcomeSuccess, code: CodeSuccess})
					adoptEncryptedOutput(context.Background(), result, spool)
					if result.StreamFollowUp() != nil || result.Outcome() != OutcomeOperationFailed ||
						result.Stage() != StageOutputWrite || result.Diagnostic() != DiagnosticCoreFailure ||
						result.CompletionClass() != CompletionNoOutput {
						t.Fatalf("invalid spool did not become a closed output failure: %v", result)
					}
					if result.hasWarning(WarningCleanupIncomplete) != replacement {
						t.Error("adoption lost or invented the actual spool cleanup failure")
					}
					if strings.Contains(fmt.Sprintf("%#v", result), path) {
						t.Error("closed failure retained a private staging path")
					}
				} else {
					output, err := OwnEncryptedOutput(spool)
					if output != nil || err == nil {
						t.Fatal("invalid spool gained transport authority")
					}
					if errors.Is(err, fileops.ErrEncryptedSpoolCleanupIncomplete) != replacement {
						t.Error("ownership failure lost or invented its spool cleanup sentinel")
					}
				}
				if spool.File() != nil || spool.Path() != "" {
					t.Error("failed adoption did not revoke the original owner")
				}
				if replacement {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != "foreign replacement" {
						t.Fatal("cleanup removed or modified a foreign replacement")
					}
				} else if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("cleanly failed adoption retained its owned spool")
				}
			})
		}
	}
}

func TestEncryptedOutputAdoptionFailureClearsOutputTrust(t *testing.T) {
	for _, outcome := range []pcv3.Outcome{OutcomeAuthenticatedDegraded, OutcomeForcePartial, OutcomeForceUnverified} {
		for _, cleanupWarning := range []bool{false, true} {
			t.Run(fmt.Sprintf("outcome=%d/cleanup=%t", outcome, cleanupWarning), func(t *testing.T) {
				code := CodeAuthenticatedDegraded
				if outcome == OutcomeForcePartial {
					code = CodeForcePartial
				} else if outcome == OutcomeForceUnverified {
					code = CodeForceUnverified
				}
				result := newResult(resultData{
					outcome: outcome, stage: StageRecordAuth, code: code,
					forceProvenance:       pcv3.ForceProvenanceUnverified,
					d1BootstrapProvenance: pcv3.D1BootstrapProvenanceMatching,
					detailStage:           StageRecordAuth, args: []uint64{1, 2},
				})
				result.authenticatedComment = "old authenticated metadata"
				if cleanupWarning {
					result.appendWarning(WarningCleanupIncomplete)
				}
				spool, _ := encryptedOutputFixture(t, []byte("invalid extent"))
				if err := spool.File().Truncate(0); err != nil {
					t.Fatal(err)
				}
				adoptEncryptedOutput(context.Background(), result, spool)
				if result.CompletionClass() != CompletionNoOutput || result.StreamFollowUp() != nil ||
					result.Outcome() != OutcomeOperationFailed || result.Stage() != StageOutputWrite ||
					result.Diagnostic() != DiagnosticCoreFailure {
					t.Errorf("closed failure retained contradictory output semantics: completion=%v result=%v", result.CompletionClass(), result)
				}
				if result.ForceProvenance() != 0 || result.D1BootstrapProvenance() != 0 ||
					result.DetailStage() != 0 || len(result.Args()) != 0 || result.AuthenticatedComment() != "" {
					t.Error("failed stream adoption retained output trust or metadata")
				}
				warnings := result.Warnings()
				if (cleanupWarning && (len(warnings) != 1 || warnings[0] != WarningCleanupIncomplete)) ||
					(!cleanupWarning && len(warnings) != 0) {
					t.Errorf("closed failure did not preserve only real cleanup warning: %v", warnings)
				}
			})
		}
	}
}

func TestStreamPresentationCannotClaimFilePublication(t *testing.T) {
	spec := PresentationSpec{Outcome: OutcomeSuccess, Code: CodeSuccess, StreamState: StreamPending}
	presentation, err := NewPresentation(spec)
	if err != nil || presentation.CompletionClass() != CompletionStreamPending || presentation.PublicationAttempted() {
		t.Fatalf("pending stream falsely became published: %v %v", presentation.CompletionClass(), err)
	}
	spec.StreamState = StreamComplete
	presentation, err = NewPresentation(spec)
	if err != nil || presentation.CompletionClass() != CompletionClean || presentation.PublicationState() != 0 {
		t.Fatal("completed stdout acquired filesystem publication truth")
	}
	spec.PublicationAttempted = true
	if _, err := NewPresentation(spec); err == nil {
		t.Fatal("contradictory stream/file-publication presentation accepted")
	}
}
