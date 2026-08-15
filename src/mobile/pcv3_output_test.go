package mobile

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// retainedMobileOutputAction keeps the production publication owner real while
// making the action boundary deterministic enough to prove mobile registry
// ownership and in-flight release denial.
type retainedMobileOutputAction struct {
	retained *pcv3publication.RetainedFile
	started  chan struct{}
	release  chan struct{}
	calls    atomic.Int64
}

func (action *retainedMobileOutputAction) Discard() pcv3OutputActionResult {
	action.calls.Add(1)
	if action.started != nil {
		close(action.started)
	}
	if action.release != nil {
		<-action.release
	}
	if err := action.retained.RemoveExact(); err != nil {
		return pcv3OutputActionResult{code: "discard-cleanup-incomplete", cleanupIncomplete: true}
	}
	return pcv3OutputActionResult{code: "discarded"}
}

func (action *retainedMobileOutputAction) SaveTo(destination *os.File) pcv3OutputActionResult {
	action.calls.Add(1)
	if action.started != nil {
		close(action.started)
	}
	if action.release != nil {
		<-action.release
	}
	copyResult := action.retained.CopyTo(destination)
	if !copyResult.Copied() {
		cleanupIncomplete := copyResult.CleanupIncomplete() || action.retained.RemoveExact() != nil
		code := "save-failed"
		if cleanupIncomplete {
			code = "save-failed-cleanup-incomplete"
		}
		return pcv3OutputActionResult{code: code, cleanupIncomplete: cleanupIncomplete}
	}
	if err := action.retained.RemoveExact(); err != nil {
		return pcv3OutputActionResult{code: "saved-cleanup-incomplete", cleanupIncomplete: true}
	}
	return pcv3OutputActionResult{code: "saved"}
}

func TestPCV3MobileRetainedOutputOwnsExactDurableFile(t *testing.T) {
	directory := t.TempDir()
	retained, retainedPath := publishPCV3MobileRetainedFile(t, directory, "retained.bin", []byte("real retained plaintext"))
	action := &retainedMobileOutputAction{
		retained: retained,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	operation := startPCV3Operation()
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), action)

	output := operation.Output()
	if output == nil {
		t.Fatal("durably retained plaintext did not produce one operation-bound output handle")
	}
	formatted := fmt.Sprintf("%v|%+v|%#v", output, output, output)
	if strings.Contains(formatted, directory) || strings.Contains(formatted, "real retained plaintext") {
		t.Fatalf("live mobile output formatting disclosed private data: %q", formatted)
	}
	if code := operation.Release(); code != pcv3OperationReleaseDenied {
		t.Fatalf("release before discard = %q; want denial", code)
	}
	copy := *output
	result := make(chan *PCV3OutputResult, 1)
	go func() { result <- output.Discard() }()
	<-action.started
	if code := operation.Release(); code != pcv3OperationReleaseDenied {
		t.Fatalf("release during discard = %q; want denial", code)
	}
	close(action.release)
	discarded := <-result
	if discarded == nil || discarded.Code() != "discarded" || discarded.CleanupIncomplete() {
		t.Fatalf("discard result = %#v; want proven exact removal", discarded)
	}
	formatted = fmt.Sprintf("%v|%+v|%#v", discarded, discarded, discarded)
	if strings.Contains(formatted, directory) || strings.Contains(formatted, "real retained plaintext") {
		t.Fatalf("mobile output result formatting disclosed private data: %q", formatted)
	}
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discard did not remove exact retained plaintext: %v", err)
	}
	if again := copy.Discard(); again == nil || again.Code() != "expired" || again.CleanupIncomplete() {
		t.Fatalf("copied output reuse = %#v; want fixed expired result", again)
	}
	if calls := action.calls.Load(); calls != 1 {
		t.Fatalf("discard action calls = %d; want exactly one", calls)
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release after terminal discard = %q", code)
	}
	if code := operation.Release(); code != pcv3OperationReleaseDenied {
		t.Fatalf("released operation acted twice = %q", code)
	}
}

func TestPCV3MobileRetainedOutputPreservesForeignReplacement(t *testing.T) {
	directory := t.TempDir()
	payload := []byte("owned retained plaintext")
	foreign := []byte("foreign replacement")
	retained, retainedPath := publishPCV3MobileRetainedFile(t, directory, "retained.bin", payload)
	moved := filepath.Join(directory, "moved-owner.bin")
	if err := os.Rename(retainedPath, moved); err != nil {
		t.Fatalf("move exact owner: %v", err)
	}
	if err := os.WriteFile(retainedPath, foreign, 0o600); err != nil {
		t.Fatalf("write foreign replacement: %v", err)
	}
	operation := startPCV3Operation()
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), &retainedMobileOutputAction{retained: retained})

	result := operation.Output().Discard()
	if result == nil || result.Code() != "discard-cleanup-incomplete" || !result.CleanupIncomplete() {
		t.Fatalf("foreign replacement discard = %#v; want cleanup uncertainty", result)
	}
	requirePCV3MobileFileBytes(t, retainedPath, foreign)
	requirePCV3MobileFileBytes(t, moved, payload)
	if code := operation.Release(); code != "" {
		t.Fatalf("release after uncertain discard = %q", code)
	}
}

func TestPCV3MobileRetainedOutputRejectsStaleCompletionAndRedactsExports(t *testing.T) {
	directory := t.TempDir()
	retained, retainedPath := publishPCV3MobileRetainedFile(t, directory, "retained.bin", []byte("stale exact owner"))
	action := &retainedMobileOutputAction{retained: retained}
	operation := startPCV3Operation()
	completePCV3PresentationForOperation(operation, fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure))
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), action)
	if calls := action.calls.Load(); calls != 1 {
		t.Fatalf("stale completion discard calls = %d; want exactly one", calls)
	}
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale completion orphaned retained plaintext: %v", err)
	}
	if operation.Output() != nil {
		t.Fatal("stale completion exposed output authority")
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release stale terminal operation = %q", code)
	}

	retained, retainedPath = publishPCV3MobileRetainedFile(t, directory, "invalid.bin", []byte("invalid projection owner"))
	action = &retainedMobileOutputAction{retained: retained}
	operation = startPCV3Operation()
	invalid := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome: pcv3.OutcomeSuccess,
		Stage:   pcv3.StageNone,
		Code:    pcv3.CodeSuccess,
	})
	completePCV3PresentationWithOutput(operation, invalid, action)
	if snapshot := operation.Snapshot(); snapshot.Diagnostic() != "core-failure" || operation.Output() != nil {
		t.Fatalf("invalid output projection = %s output=%v; want fixed fail-closed result", snapshot.Diagnostic(), operation.Output())
	}
	if calls := action.calls.Load(); calls != 1 {
		t.Fatalf("invalid projection discard calls = %d; want exactly one", calls)
	}
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid projection orphaned retained plaintext: %v", err)
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release invalid projection = %q", code)
	}

}

func TestPCV3MobileRetainedOutputContainsDiscardPanic(t *testing.T) {
	operation := startPCV3Operation()
	action := &panicMobileOutputAction{}
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), action)

	output := operation.Output()
	if output == nil {
		t.Fatal("live output was not exposed before its panic-safe discard")
	}
	result := output.Discard()
	if result == nil || result.Code() != "discard-cleanup-incomplete" || !result.CleanupIncomplete() {
		t.Fatalf("contained public discard panic = %#v; want fixed cleanup-incomplete result", result)
	}
	if again := output.Discard(); again == nil || again.Code() != "expired" || again.CleanupIncomplete() {
		t.Fatalf("panic-consumed output reuse = %#v; want fixed expired result", again)
	}
	if calls := action.calls.Load(); calls != 1 {
		t.Fatalf("panic action calls = %d; want exactly one", calls)
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release after contained public panic = %q", code)
	}

	operation = startPCV3Operation()
	action = &panicMobileOutputAction{}
	completePCV3PresentationForOperation(operation, fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure))
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), action)
	if snapshot := operation.Snapshot(); snapshot.Diagnostic() != "core-failure" || operation.Output() != nil {
		t.Fatalf("contained stale cleanup panic = %s output=%v; want fail-closed terminal", snapshot.Diagnostic(), operation.Output())
	}
	if calls := action.calls.Load(); calls != 1 {
		t.Fatalf("stale panic action calls = %d; want exactly one", calls)
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release after contained stale panic = %q", code)
	}
}

func TestPCV3MobileRetainedOutputSaveFDTransfersExactOwner(t *testing.T) {
	directory := t.TempDir()
	payload := []byte("save through one Android-owned descriptor")
	retained, retainedPath := publishPCV3MobileRetainedFile(t, directory, "retained.bin", payload)
	action := &retainedMobileOutputAction{
		retained: retained,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	operation := startPCV3Operation()
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), action)
	output := operation.Output()
	if output == nil {
		t.Fatal("durable retained output did not expose a SaveFD capability")
	}

	destinationPath := filepath.Join(directory, "saved.bin")
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create transferred destination: %v", err)
	}
	destinationFD := int64(destination.Fd())
	copy := *output
	result := make(chan *PCV3OutputResult, 1)
	go func() { result <- output.SaveFD(destinationFD) }()
	<-action.started
	if code := operation.Release(); code != pcv3OperationReleaseDenied {
		t.Fatalf("release while SaveFD is in flight = %q; want denial", code)
	}
	if reused := copy.Discard(); reused == nil || reused.Code() != "expired" || reused.CleanupIncomplete() {
		t.Fatalf("Discard raced with SaveFD = %#v; want fixed expired result", reused)
	}
	close(action.release)
	saved := <-result
	if saved == nil || saved.Code() != "saved" || saved.CleanupIncomplete() {
		t.Fatalf("SaveFD result = %#v; want saved exact owner", saved)
	}
	if _, err := destination.Stat(); err == nil {
		t.Fatal("SaveFD returned with the transferred descriptor still usable")
	}
	requirePCV3MobileFileBytes(t, destinationPath, payload)
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SaveFD retained internal plaintext: %v", err)
	}
	if calls := action.calls.Load(); calls != 1 {
		t.Fatalf("SaveFD action calls = %d; want exactly one", calls)
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release after SaveFD settlement = %q", code)
	}
}

func TestPCV3MobileRetainedOutputSaveFDContainsInvalidAndPanic(t *testing.T) {
	directory := t.TempDir()
	guard, err := os.CreateTemp(directory, "unrelated-fd")
	if err != nil {
		t.Fatalf("create unrelated descriptor: %v", err)
	}
	defer func() { _ = guard.Close() }()
	guardPayload := []byte("unrelated descriptor must remain untouched")
	if _, err := guard.Write(guardPayload); err != nil {
		t.Fatalf("seed unrelated descriptor: %v", err)
	}
	if err := guard.Sync(); err != nil {
		t.Fatalf("sync unrelated descriptor: %v", err)
	}

	retained, retainedPath := publishPCV3MobileRetainedFile(t, directory, "invalid.bin", []byte("invalid FD cleanup"))
	operation := startPCV3Operation()
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), &retainedMobileOutputAction{retained: retained})
	truncatedFD := int64(guard.Fd()) + (int64(1) << 32)
	invalid := operation.Output().SaveFD(truncatedFD)
	if invalid == nil || invalid.Code() != "save-failed" || invalid.CleanupIncomplete() {
		t.Fatalf("invalid SaveFD result = %#v; want fixed clean save failure", invalid)
	}
	if _, err := guard.Stat(); err != nil {
		t.Fatalf("invalid SaveFD acted on unrelated descriptor: %v", err)
	}
	requirePCV3MobileFileBytes(t, guard.Name(), guardPayload)
	if _, err := os.Lstat(retainedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid SaveFD orphaned retained plaintext: %v", err)
	}
	if again := operation.Output(); again != nil {
		t.Fatal("invalid SaveFD left output authority live")
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release after invalid SaveFD = %q", code)
	}

	operation = startPCV3Operation()
	action := &panicMobileOutputAction{}
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), action)
	output := operation.Output()
	destination, err := os.CreateTemp(directory, "panic-fd")
	if err != nil {
		t.Fatalf("create panic destination: %v", err)
	}
	panicResult := output.SaveFD(int64(destination.Fd()))
	if panicResult == nil || panicResult.Code() != "save-failed-cleanup-incomplete" || !panicResult.CleanupIncomplete() {
		t.Fatalf("contained SaveFD panic = %#v; want fixed cleanup-incomplete failure", panicResult)
	}
	if _, err := destination.Stat(); err == nil {
		t.Fatal("panicking SaveFD returned with its transferred descriptor still usable")
	}
	if again := output.SaveFD(-1); again == nil || again.Code() != "expired" || again.CleanupIncomplete() {
		t.Fatalf("panic-consumed SaveFD reuse = %#v; want fixed expired result", again)
	}
	if calls := action.calls.Load(); calls != 1 {
		t.Fatalf("panicking SaveFD action calls = %d; want exactly one", calls)
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release after contained SaveFD panic = %q", code)
	}
}

func TestPCV3MobileRetainedOutputSaveFDClosesExpiredTransferredDescriptor(t *testing.T) {
	directory := t.TempDir()
	retained, _ := publishPCV3MobileRetainedFile(t, directory, "expired.bin", []byte("consume before reused SaveFD"))
	operation := startPCV3Operation()
	completePCV3PresentationWithOutput(operation, durablePCV3MobilePresentation(t), &retainedMobileOutputAction{retained: retained})
	output := operation.Output()
	if output == nil {
		t.Fatal("live output was not exposed before expiration")
	}
	expired := *output
	if discarded := output.Discard(); discarded == nil || discarded.Code() != "discarded" || discarded.CleanupIncomplete() {
		t.Fatalf("initial discard = %#v; want exact cleanup before expired SaveFD", discarded)
	}

	destination, err := os.CreateTemp(directory, "expired-fd")
	if err != nil {
		t.Fatalf("create expired transferred descriptor: %v", err)
	}
	result := expired.SaveFD(int64(destination.Fd()))
	if result == nil || result.Code() != "expired" || result.CleanupIncomplete() {
		t.Fatalf("expired SaveFD result = %#v; want fixed expired result", result)
	}
	if _, err := destination.Stat(); err == nil {
		t.Fatal("expired SaveFD leaked the transferred descriptor")
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("release after expired SaveFD = %q", code)
	}
}

type panicMobileOutputAction struct{ calls atomic.Int64 }

func (action *panicMobileOutputAction) Discard() pcv3OutputActionResult {
	action.calls.Add(1)
	panic("test-only output cleanup panic")
}

func (action *panicMobileOutputAction) SaveTo(*os.File) pcv3OutputActionResult {
	action.calls.Add(1)
	panic("test-only output save panic")
}

func publishPCV3MobileRetainedFile(
	t *testing.T,
	directory, name string,
	payload []byte,
) (*pcv3publication.RetainedFile, string) {
	t.Helper()
	path := filepath.Join(directory, name)
	stage, err := pcv3publication.Create(path, nil, pcv3publication.PolicyNoReplace)
	if err != nil {
		t.Fatalf("create real publication stage: %v", err)
	}
	t.Cleanup(func() {
		if err := stage.Cleanup(); err != nil {
			t.Errorf("cleanup real publication stage: %v", err)
		}
	})
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatalf("write real publication stage: %v", err)
	}
	publication, retained := stage.PublishRetained(context.Background())
	if publication == nil || publication.State() != pcv3publication.StatePublishedDurable || retained == nil || !retained.Live() {
		t.Fatalf("publish real retained file = %#v retained=%v", publication, retained)
	}
	return retained, path
}

func durablePCV3MobilePresentation(t *testing.T) pcv3operation.Presentation {
	t.Helper()
	return mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome:              pcv3.OutcomeSuccess,
		Stage:                pcv3.StageNone,
		Code:                 pcv3.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublishedDurable,
		PublicationStage:     pcv3.StageNone,
		PublicationCode:      pcv3publication.CodePublishedDurable,
	})
}

func requirePCV3MobileFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file %q = %q; want %q", path, got, want)
	}
}
