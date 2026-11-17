package mobile

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
)

func TestResourceBudgetRefusalKeepsDiagnosticAcrossMobileBoundary(t *testing.T) {
	presentation := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome: pcv3operation.OutcomeOperationFailed,
		Stage:   pcv3operation.StageResourceBudget, Code: pcv3operation.CodeOperationFailed,
		Diagnostic: pcv3operation.DiagnosticResourceLimit,
	})
	operation := startPCV3Operation()
	completePCV3PresentationForOperation(operation, presentation)
	if got := operation.Snapshot().Diagnostic(); got != "resource-limit" {
		t.Fatalf("resource diagnostic = %q", got)
	}
	if operation.Output() != nil || operation.Archive() != nil || operation.Consent() != nil {
		t.Fatal("resource refusal exposed a follow-up capability")
	}
	if code := operation.Release(); code != "" {
		t.Fatal(code)
	}
}

func TestWritePanicKeepsCleanupWarningWithoutDisclosingPanic(t *testing.T) {
	for _, test := range []struct {
		name    string
		carrier bool
	}{
		{name: "cleanup-carrier", carrier: true},
		{name: "request-cleanup"},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dir := t.TempDir()
				source := writePCV3MobileFile(t, dir, "source.bin", "unchanged source")
				target := filepath.Join(dir, "output.pcv")
				const sensitive, cleanupDetail = "private panic value", "private cleanup detail"
				previous := runPCV3WriteWithOptions
				runPCV3WriteWithOptions = func(_ context.Context, request *pcv3operation.WriteRequest, _ pcv3operation.ExecutionOptions) *pcv3operation.Result {
					if test.carrier {
						fileops.RepanicWithCleanup(sensitive, errors.New(cleanupDetail))
					}
					if err := request.SourceFile.Close(); err != nil {
						t.Errorf("close borrowed source before worker cleanup: %v", err)
					}
					panic(sensitive)
				}
				t.Cleanup(func() { runPCV3WriteWithOptions = previous })
				start := StartPCV3(pcv3WriteTestEnvelope("write-normal", "password", "none", "standard", false, "", source, target, nil), []byte("public fixture password"))
				operation := start.Operation()
				if operation == nil {
					t.Fatal("valid write request refused before the tested boundary")
				}
				t.Cleanup(func() { cleanupOperation(operation.ID()) })
				synctest.Wait()
				snapshot := operation.Snapshot()
				visible := pcv3MobileSnapshotText(snapshot)
				if snapshot.Diagnostic() != "callback-panic" || snapshot.Outcome() != "operation-failed" || snapshot.CompletionClass() != "refused" ||
					snapshot.WarningCount() != 1 || snapshot.WarningAt(0) != "cleanup-incomplete" {
					t.Fatalf("write panic snapshot = %s", visible)
				}
				if strings.Contains(visible, sensitive) || strings.Contains(visible, cleanupDetail) {
					t.Fatal("snapshot disclosed panic or cleanup details")
				}
				if snapshot.PublicationAttempted() || snapshot.ArchivePending() || operation.Output() != nil || operation.Archive() != nil || operation.ArtifactInspection() != nil {
					t.Fatal("write panic granted publication or follow-up authority")
				}
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("panic published output: %v", err)
				}
				if body, err := os.ReadFile(source); err != nil || string(body) != "unchanged source" {
					t.Fatal("original changed")
				}
				if code := operation.Release(); code != "" {
					t.Fatal(code)
				}
			})
		})
	}
}
