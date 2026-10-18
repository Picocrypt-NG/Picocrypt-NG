//go:build linux && !android

package pcv3operation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopCleanupProtectsActualNormalFileSourceWithoutMatchingSourceFile(t *testing.T) {
	for _, distinctSourceFile := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil SourceFile", true: "different SourceFile"}[distinctSourceFile], func(t *testing.T) {
			parent := t.TempDir()
			orphan := seedDesktopCleanupCrash(t, parent)
			entries, err := os.ReadDir(orphan)
			if err != nil {
				t.Fatal(err)
			}
			var selected string
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") && entry.Name() != ".picocrypt-pcv3-stage.journal" {
					selected = filepath.Join(orphan, entry.Name())
				}
			}
			source, err := os.Open(selected)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			var sourceFile *os.File
			if distinctSourceFile {
				sourceFile, err = os.CreateTemp(t.TempDir(), "different-pinned-source")
				if err != nil {
					t.Fatal(err)
				}
				defer sourceFile.Close()
			}
			payload := []byte("abandoned private plaintext")
			admitter := &operationTestAdmitter{}
			request := &WriteRequest{
				Mode: WriteModeNormal, Suite: SuiteStandard, PayloadKind: PayloadKindRaw,
				Source: source, SourceFile: sourceFile, PlaintextLength: uint64(len(payload)),
				Target: filepath.Join(parent, "output"), Factors: operationPasswordFactors([]byte("password")),
			}
			result := runWriteWithSeams(context.Background(), request, ExecutionOptions{LinuxDesktopCleanup: true}, operationSeams{admitter: admitter})
			if admitter.calls != 0 || result.PublicationAttempted() || result.SourceDeletionAllowed() {
				t.Errorf("actual file source did not block orphan cleanup: calls=%d result=%v", admitter.calls, result)
			}
			data, readErr := os.ReadFile(selected)
			if readErr != nil || string(data) != string(payload) {
				t.Errorf("cleanup deleted or changed the actual source: %q %v", data, readErr)
			}
			if _, err := source.Stat(); err != nil {
				t.Errorf("borrowed source descriptor was closed: %v", err)
			}
			if sourceFile != nil {
				if _, err := sourceFile.Stat(); err != nil {
					t.Errorf("distinct borrowed SourceFile descriptor was closed: %v", err)
				}
			}
		})
	}
}
