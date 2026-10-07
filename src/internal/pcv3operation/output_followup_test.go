package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOutputFollowUpSaveCopiesThenRemovesExactInternalOwner(t *testing.T) {
	directory := t.TempDir()
	payload := []byte("authenticated PCV3 output exported through an owned descriptor")
	retained, retainedPath := newOperationRetainedFile(t, directory, payload)
	followUp := newOutputFollowUp(retained)
	if followUp == nil || !followUp.live() {
		t.Fatal("retained transport fixture did not create a live output follow-up")
	}
	copiedFollowUp := *followUp
	destinationPath := filepath.Join(directory, "saved.bin")
	destination, err := os.OpenFile(
		destinationPath,
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		0o600,
	)
	if err != nil {
		t.Fatalf("create owned save destination: %v", err)
	}

	action := followUp.SaveTo(destination)
	wantCode := OutputActionSaved
	if runtime.GOOS == "windows" {
		wantCode = OutputActionSavedCleanupIncomplete
	}
	if action.Code() != wantCode || action.CleanupIncomplete() != (runtime.GOOS == "windows") {
		t.Fatalf(
			"save action = %v cleanup=%v; want %v with native removal durability",
			action.Code(), action.CleanupIncomplete(), wantCode,
		)
	}
	if _, err := destination.Stat(); err == nil {
		t.Fatal("SaveTo returned with the transferred destination open")
	}
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful save retained internal plaintext: %v", err)
	}
	requireOperationFileBytes(t, destinationPath, payload)
	if followUp.live() {
		t.Fatal("successful save left output authority live")
	}

	reusePath := filepath.Join(directory, "reuse.bin")
	reuse, err := os.OpenFile(reusePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create copied-capability destination: %v", err)
	}
	reused := copiedFollowUp.SaveTo(reuse)
	if reused.Code() != OutputActionExpired || reused.CleanupIncomplete() {
		t.Fatalf("copied capability reuse = %#v; want closed expired action", reused)
	}
	if _, err := reuse.Stat(); err == nil {
		t.Fatal("expired SaveTo returned with the transferred destination open")
	}
	requireOperationFileBytes(t, reusePath, nil)
}

func TestOutputFollowUpFailedSaveConsumesAuthorityAndRemovesInternalSource(t *testing.T) {
	directory := t.TempDir()
	payload := []byte("failed external transport must not orphan the internal owner")
	retained, retainedPath := newOperationRetainedFile(t, directory, payload)
	followUp := newOutputFollowUp(retained)
	destinationPath := filepath.Join(directory, "read-only.bin")
	if err := os.WriteFile(destinationPath, nil, 0o600); err != nil {
		t.Fatalf("seed read-only destination: %v", err)
	}
	destination, err := os.Open(destinationPath)
	if err != nil {
		t.Fatalf("open read-only destination: %v", err)
	}

	action := followUp.SaveTo(destination)
	wantCode := OutputActionSaveFailed
	if runtime.GOOS == "windows" {
		wantCode = OutputActionSaveFailedCleanupIncomplete
	}
	if action.Code() != wantCode || action.CleanupIncomplete() != (runtime.GOOS == "windows") {
		t.Fatalf(
			"failed save action = %v cleanup=%v; want %v with native removal durability",
			action.Code(), action.CleanupIncomplete(), wantCode,
		)
	}
	if followUp.live() {
		t.Fatal("failed one-shot save left action authority live")
	}
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed save left internal plaintext: %v", err)
	}
	requireOperationFileBytes(t, destinationPath, nil)
}

func TestOutputFollowUpStreamsTheRetainedFileAcrossPathReplacement(t *testing.T) {
	directory := t.TempDir()
	payload := []byte("authenticated plaintext from the retained descriptor")
	foreign := []byte("foreign pathname replacement")
	retained, retainedPath := newOperationRetainedFile(t, directory, payload)
	moved := filepath.Join(directory, "moved-private-output.bin")
	if err := os.Rename(retainedPath, moved); err != nil {
		t.Fatalf("move retained output: %v", err)
	}
	if err := os.WriteFile(retainedPath, foreign, 0o600); err != nil {
		t.Fatalf("write foreign replacement: %v", err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create output pipe: %v", err)
	}

	action := newOutputFollowUp(retained).StreamTo(context.Background(), writer)
	if err := writer.Close(); err != nil {
		t.Fatalf("close output pipe writer: %v", err)
	}
	streamed, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read streamed output: read=%v close=%v", readErr, closeErr)
	}
	if action.Code() != OutputActionSavedCleanupIncomplete || !action.CleanupIncomplete() {
		t.Fatalf("replacement stream action = %v cleanup=%v; want streamed with cleanup warning", action.Code(), action.CleanupIncomplete())
	}
	if string(streamed) != string(payload) {
		t.Fatalf("streamed replacement bytes = %q; want retained plaintext", streamed)
	}
	requireOperationFileBytes(t, retainedPath, foreign)
	requireOperationFileBytes(t, moved, payload)
}

func TestOutputFollowUpRejectsMutatedRetainedBytesBeforeStreaming(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "same size",
			mutate: func(payload []byte) []byte {
				mutated := append([]byte(nil), payload...)
				mutated[len(mutated)/2] ^= 0xff
				return mutated
			},
		},
		{
			name: "resized",
			mutate: func(payload []byte) []byte {
				return append([]byte(nil), payload[:len(payload)/2]...)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			payload := []byte("authenticated plaintext must be unchanged before stdout")
			retained, retainedPath := newOperationRetainedFile(t, directory, payload)
			if err := os.WriteFile(retainedPath, test.mutate(payload), 0o600); err != nil {
				t.Fatalf("mutate retained output: %v", err)
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatalf("create output pipe: %v", err)
			}
			action := newOutputFollowUp(retained).StreamTo(context.Background(), writer)
			if err := writer.Close(); err != nil {
				t.Fatalf("close output writer: %v", err)
			}
			streamed, readErr := io.ReadAll(reader)
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read rejected stream: read=%v close=%v", readErr, closeErr)
			}
			wantCode := OutputActionSaveFailed
			if runtime.GOOS == "windows" {
				wantCode = OutputActionSaveFailedCleanupIncomplete
			}
			if action.Code() != wantCode || action.CleanupIncomplete() != (runtime.GOOS == "windows") || len(streamed) != 0 {
				t.Fatalf("mutated stream action=%v cleanup=%v bytes=%d", action.Code(), action.CleanupIncomplete(), len(streamed))
			}
			if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mutated retained plaintext survived rejection: %v", err)
			}
		})
	}
}

func TestOutputFollowUpNilStreamDestinationStillRemovesPlaintext(t *testing.T) {
	directory := t.TempDir()
	retained, retainedPath := newOperationRetainedFile(t, directory, []byte("must be removed"))
	action := newOutputFollowUp(retained).StreamTo(context.Background(), nil)
	wantCode := OutputActionSaveFailed
	if runtime.GOOS == "windows" {
		wantCode = OutputActionSaveFailedCleanupIncomplete
	}
	if action.Code() != wantCode || action.CleanupIncomplete() != (runtime.GOOS == "windows") {
		t.Fatalf("nil stream action=%v cleanup=%v", action.Code(), action.CleanupIncomplete())
	}
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nil stream destination orphaned retained plaintext: %v", err)
	}
}

func TestOutputFollowUpDiscardIsExactIdentityOnly(t *testing.T) {
	t.Run("exact owner removed", func(t *testing.T) {
		directory := t.TempDir()
		retained, retainedPath := newOperationRetainedFile(t, directory, []byte("discard me"))
		action := newOutputFollowUp(retained).Discard()
		wantCode := OutputActionDiscarded
		if runtime.GOOS == "windows" {
			wantCode = OutputActionDiscardCleanupIncomplete
		}
		if action.Code() != wantCode || action.CleanupIncomplete() != (runtime.GOOS == "windows") {
			t.Fatalf("exact discard = %#v; want %v with native removal durability", action, wantCode)
		}
		if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("discarded internal output still exists: %v", err)
		}
	})

	t.Run("foreign replacement preserved", func(t *testing.T) {
		directory := t.TempDir()
		payload := []byte("owned output moved before discard")
		foreign := []byte("foreign replacement")
		retained, retainedPath := newOperationRetainedFile(t, directory, payload)
		moved := filepath.Join(directory, "moved-owner.bin")
		if err := os.Rename(retainedPath, moved); err != nil {
			t.Fatalf("move retained owner: %v", err)
		}
		if err := os.WriteFile(retainedPath, foreign, 0o600); err != nil {
			t.Fatalf("write foreign replacement: %v", err)
		}
		followUp := newOutputFollowUp(retained)

		action := followUp.Discard()
		if action.Code() != OutputActionDiscardCleanupIncomplete ||
			!action.CleanupIncomplete() {
			t.Fatalf(
				"replacement discard = %v cleanup=%v; want cleanup uncertainty",
				action.Code(), action.CleanupIncomplete(),
			)
		}
		if followUp.live() {
			t.Fatal("identity-loss discard left deletion authority live")
		}
		requireOperationFileBytes(t, retainedPath, foreign)
		requireOperationFileBytes(t, moved, payload)
	})
}

func TestResultGrantsOutputFollowUpOnlyForDurableOutputTuple(t *testing.T) {
	tests := []struct {
		name        string
		outcome     pcv3.Outcome
		stage       pcv3.Stage
		code        pcv3.Code
		publication pcv3publication.State
		want        bool
	}{
		{
			name: "durable success", outcome: pcv3.OutcomeSuccess,
			stage: pcv3.StageNone, code: pcv3.CodeSuccess,
			publication: pcv3publication.StatePublishedDurable, want: true,
		},
		{
			name: "durable authenticated degraded", outcome: pcv3.OutcomeAuthenticatedDegraded,
			stage: pcv3.StageMetadata, code: pcv3.CodeAuthenticatedDegraded,
			publication: pcv3publication.StatePublishedDurable, want: true,
		},
		{
			name: "durability uncertain", outcome: pcv3.OutcomeSuccess,
			stage: pcv3.StageNone, code: pcv3.CodeSuccess,
			publication: pcv3publication.StatePublishedDurabilityUncertain,
		},
		{
			name: "publication indeterminate", outcome: pcv3.OutcomeSuccess,
			stage: pcv3.StageNone, code: pcv3.CodeSuccess,
			publication: pcv3publication.StatePublicationIndeterminate,
		},
		{
			name: "operation failure", outcome: pcv3.OutcomeOperationFailed,
			stage: pcv3.StageOutputWrite, code: pcv3.CodeOperationFailed,
			publication: pcv3publication.StatePublishedDurable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			retained, _ := newOperationRetainedFile(t, directory, []byte("tuple owner"))
			followUp := newOutputFollowUp(retained)
			result := newResult(resultData{
				outcome: test.outcome, stage: test.stage, code: test.code,
				publicationAttempted: true,
				publicationState:     test.publication,
				publicationStage:     outputPublicationStage(test.publication),
				publicationCode:      outputPublicationCode(test.publication),
			})
			result.outputFollowUp = followUp

			got := result.OutputFollowUp()
			if (got != nil) != test.want {
				t.Fatalf("OutputFollowUp() present = %v; want %v", got != nil, test.want)
			}
			if got != nil {
				_ = got.Discard()
			} else {
				_ = followUp.Discard()
			}
		})
	}
}

func TestOutputFollowUpFormattingNeverDisclosesPath(t *testing.T) {
	directory := t.TempDir()
	retained, _ := newOperationRetainedFile(t, directory, []byte("private"))
	followUp := newOutputFollowUp(retained)
	formatted := fmt.Sprintf("%v|%+v|%#v", followUp, followUp, followUp)
	if strings.Contains(formatted, directory) {
		t.Fatalf("output follow-up formatting disclosed a path: %q", formatted)
	}
	_ = followUp.Discard()
}

func TestReporterFailureRemovesExactOutputBeforeDroppingCapability(t *testing.T) {
	directory := t.TempDir()
	retained, retainedPath := newOperationRetainedFile(
		t,
		directory,
		[]byte("no frontend received authority for this plaintext"),
	)
	result := newResult(resultData{
		outcome:              pcv3.OutcomeSuccess,
		stage:                pcv3.StageNone,
		code:                 pcv3.CodeSuccess,
		publicationAttempted: true,
		publicationState:     pcv3publication.StatePublishedDurable,
		publicationCode:      pcv3publication.CodePublishedDurable,
	})
	result.outputFollowUp = newOutputFollowUp(retained)
	owner := &operationOwner{reporterFailed: true}

	failure := owner.finishReportedResult(result)
	if failure.Diagnostic() != DiagnosticCallbackFailure ||
		failure.OutputFollowUp() != nil ||
		failure.hasWarning(WarningCleanupIncomplete) != (runtime.GOOS == "windows") {
		t.Fatalf(
			"reporter failure = diagnostic %v output=%v warnings=%v; want no follow-up and native cleanup truth",
			failure.Diagnostic(), failure.OutputFollowUp(), failure.Warnings(),
		)
	}
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reporter failure orphaned internal plaintext: %v", err)
	}
}

func newOperationRetainedFile(
	t *testing.T,
	directory string,
	payload []byte,
) (*pcv3publication.RetainedFile, string) {
	t.Helper()
	target := filepath.Join(directory, "private-output.bin")
	stage, err := pcv3publication.Create(target, nil, pcv3publication.PolicyNoReplace)
	if err != nil {
		t.Fatalf("create retained operation stage: %v", err)
	}
	t.Cleanup(func() { _ = stage.Cleanup() })
	if _, err := stage.File().Write(payload); err != nil {
		_ = stage.Cleanup()
		t.Fatalf("write retained operation stage: %v", err)
	}
	// These private-constructor tests exercise transport and exact cleanup,
	// independent of plaintext authority minting. Ciphertext custody preserves
	// Windows' genuine directory-durability uncertainty; native plaintext
	// publication refusal is tested separately in pcv3publication.
	publication, retained := stage.PublishWriteRetained(context.Background())
	if retained != nil {
		t.Cleanup(func() { _ = retained.Close() })
	}
	wantState := pcv3publication.StatePublishedDurable
	if runtime.GOOS == "windows" {
		wantState = pcv3publication.StatePublishedDurabilityUncertain
	}
	if publication == nil || publication.State() != wantState ||
		retained == nil {
		_ = stage.Cleanup()
		t.Fatalf("publish retained transport fixture = %v/%v; want %v custody", publication, retained, wantState)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup transferred publication stage: %v", err)
	}
	return retained, target
}

func outputPublicationStage(state pcv3publication.State) pcv3.Stage {
	switch state {
	case pcv3publication.StatePublishedDurabilityUncertain:
		return pcv3.StageDirectorySync
	case pcv3publication.StatePublicationIndeterminate:
		return pcv3.StageOutputPublication
	default:
		return pcv3.StageNone
	}
}

func outputPublicationCode(state pcv3publication.State) pcv3publication.Code {
	switch state {
	case pcv3publication.StatePublishedDurable:
		return pcv3publication.CodePublishedDurable
	case pcv3publication.StatePublishedDurabilityUncertain:
		return pcv3publication.CodeDurabilityUncertain
	case pcv3publication.StatePublicationIndeterminate:
		return pcv3publication.CodePublicationIndeterminate
	default:
		return 0
	}
}

func requireOperationFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read operation test file: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("operation file bytes = %q; want %q", got, want)
	}
}

// The failed plaintext save consumes its only follow-up. Even when the caller's
// destination cannot be cleaned, the independently owned internal plaintext
// must still be removed. No KDF or fixture is involved in this filesystem test.
func TestOutputFollowUpCleanupUncertainSaveRemovesInternalPlaintext(t *testing.T) {
	directory := t.TempDir()
	payload := []byte("owned plaintext must not be orphaned")
	retained, retainedPath := newOperationRetainedFile(t, directory, payload)
	// Retain a test-only cleanup reference so the test itself
	// cannot strand a descriptor or file beyond t.TempDir's lifetime.
	t.Cleanup(func() { _ = retained.Close() })
	followUp := newOutputFollowUp(retained)
	destination, err := os.OpenFile(retainedPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	action := followUp.SaveTo(destination)
	if action.Code() != OutputActionSaveFailedCleanupIncomplete || !action.CleanupIncomplete() {
		t.Fatalf("action = %v cleanup=%v, want failed save with alias uncertainty", action.Code(), action.CleanupIncomplete())
	}
	if followUp.live() {
		t.Fatal("failed one-shot plaintext save retained follow-up authority")
	}
	if _, err := destination.Stat(); err == nil {
		t.Fatal("SaveTo left its destination descriptor open")
	}
	bytes, readErr := os.ReadFile(retainedPath)
	if !errors.Is(readErr, os.ErrNotExist) {
		t.Fatalf("consumed plaintext follow-up left private source: readErr=%v payloadIntact=%v rawRetainedLive=%v", readErr, string(bytes) == string(payload), retained.Live())
	}
}
