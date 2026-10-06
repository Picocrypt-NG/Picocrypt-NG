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
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		source := writePCV3MobileFile(t, dir, "source.bin", "unchanged source")
		target := filepath.Join(dir, "output.pcv")
		const sensitive = "private panic value"
		previous := runPCV3WriteWithOptions
		runPCV3WriteWithOptions = func(context.Context, *pcv3operation.WriteRequest, pcv3operation.ExecutionOptions) *pcv3operation.Result {
			fileops.RepanicWithCleanup(sensitive, errors.New("private cleanup detail"))
			return nil
		}
		t.Cleanup(func() { runPCV3WriteWithOptions = previous })
		start := StartPCV3(pcv3WriteTestEnvelope("write-normal", "password", "none", "standard", false, "", source, target, nil), []byte("public fixture password"))
		if start.Operation() == nil {
			t.Fatal("valid write request refused before the tested boundary")
		}
		synctest.Wait()
		snapshot := start.Operation().Snapshot()
		if snapshot.Diagnostic() != "callback-panic" {
			t.Fatalf("panic diagnostic = %q", snapshot.Diagnostic())
		}
		found := false
		for index := range snapshot.WarningCount() {
			if snapshot.WarningAt(index) == "cleanup-incomplete" {
				found = true
			}
		}
		if !found {
			t.Fatal("panic suppressed the incomplete-cleanup warning")
		}
		if strings.Contains(snapshot.Diagnostic(), sensitive) {
			t.Fatal("panic text disclosed")
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("panic published output: %v", err)
		}
		if body, err := os.ReadFile(source); err != nil || string(body) != "unchanged source" {
			t.Fatal("original changed")
		}
		if code := start.Operation().Release(); code != "" {
			t.Fatal(code)
		}
	})
}
