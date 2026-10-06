//go:build darwin

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinDirectoryBarrierFailurePreservesCommittedOutput(t *testing.T) {
	for _, failure := range []error{unix.ENOTSUP, unix.EINVAL, unix.EIO} {
		t.Run(failure.Error(), func(t *testing.T) {
			operations := nativeOperations()
			operations.syncDirectory = func(*os.File) error { return failure }
			directory := t.TempDir()
			target := filepath.Join(directory, "output.pcv")
			stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stage.Cleanup() })
			payload := []byte("complete ciphertext survives unavailable durability")
			if _, err := stage.File().Write(payload); err != nil {
				t.Fatal(err)
			}
			result := stage.PublishWrite(context.Background())
			requireResult(t, result, StatePublishedDurabilityUncertain,
				pcv3result.OutcomeCommittedDurabilityUncertain,
				pcv3result.StageDirectorySync, CodeDurabilityUncertain)
			if err := stage.Cleanup(); err != nil {
				t.Fatal(err)
			}
			requireFileBytes(t, target, payload)
			requireNoStageEntries(t, directory)
		})
	}
}
