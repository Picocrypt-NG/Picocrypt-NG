package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRecoveryCleanupDurabilityKeepsCauseAndWithholdsCapabilities(t *testing.T) {
	for _, both := range []bool{false, true} {
		archive, _ := prepareRecoveryArchive(t, nil)
		handoff := archive.archiveHandoff
		if handoff == nil {
			t.Fatal("archive fixture has no held capability")
		}
		defer handoff.Close()
		stream := runWithCoreOptions(context.Background(), &Request{
			Target: filepath.Join(t.TempDir(), "output"), Mode: pcv3.RecoveryModeNormalV3,
		}, recoveryArchiveCore([]byte("authenticated stream"), nil), ExecutionOptions{EncryptedStream: true})
		owner := stream.encryptedStream
		if owner == nil {
			t.Fatal("stream fixture has no held encrypted owner")
		}
		defer owner.Close()
		cleanupErr := pcv3publication.ErrCleanupDurabilityUncertain
		if both {
			cleanupErr = errors.Join(cleanupErr, pcv3publication.ErrCleanupIncomplete)
		}
		for _, result := range []*Result{archive, stream} {
			result.retainCleanupError(cleanupErr)
			if !result.CleanupDurabilityUncertain() || !errors.Is(result, pcv3publication.ErrCleanupDurabilityUncertain) || errors.Is(result, pcv3publication.ErrCleanupIncomplete) != both {
				t.Fatalf("cleanup result lost an independent fixed cause: %v", result.Unwrap())
			}
		}
		if archive.TakeArchiveHandoff() != nil || stream.TakeEncryptedStream() != nil {
			t.Fatal("reclassified cleanup uncertainty granted a previously withheld capability")
		}
		if archive.archiveHandoff != handoff || stream.encryptedStream != owner {
			t.Fatal("refused transfer dropped internal cleanup custody")
		}
	}
}
