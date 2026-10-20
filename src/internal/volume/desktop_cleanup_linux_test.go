//go:build linux && !android

package volume

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type desktopCleanupReporter struct{ compressionStarted bool }

func (reporter *desktopCleanupReporter) SetStatus(status string) {
	reporter.compressionStarted = reporter.compressionStarted || status == "Compressing files..."
}
func (*desktopCleanupReporter) SetProgress(float32, string) {}
func (*desktopCleanupReporter) SetCanCancel(bool)           {}
func (*desktopCleanupReporter) Update()                     {}
func (*desktopCleanupReporter) IsCancelled() bool           { return false }

func TestDesktopUnprovenCleanupRefusesBeforeArchivePreparation(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("selected plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreignJournal := filepath.Join(parent, ".picocrypt-pcv3-stage.journal")
	if err := os.WriteFile(foreignJournal, []byte("unproven record"), 0o600); err != nil {
		t.Fatal(err)
	}
	reporter := &desktopCleanupReporter{}
	result, err := EncryptWithResult(context.Background(), &EncryptRequest{
		InputFiles: []string{source}, OutputFile: filepath.Join(parent, "output"),
		Password: []byte("password"), PCV3: true, Compress: true, Reporter: reporter,
	}, pcv3operation.ExecutionOptions{LinuxDesktopCleanup: true})
	if !errors.Is(err, pcv3publication.ErrCleanupIncomplete) || reporter.compressionStarted {
		t.Fatalf("unproven cleanup reached archive preparation: compression=%v result=%v err=%v", reporter.compressionStarted, result, err)
	}
	data, readErr := os.ReadFile(source)
	if readErr != nil || string(data) != "selected plaintext" {
		t.Fatalf("selected source changed: %q %v", data, readErr)
	}
}
