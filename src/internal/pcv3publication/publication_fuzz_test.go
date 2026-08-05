package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const publicationFuzzPayloadLimit = 4 << 10

func FuzzPublicationStateMachine(f *testing.F) {
	for mode := range uint8(8) {
		f.Add(mode, []byte{mode, 0x50, 0x43, 0x56, 0x33})
	}

	f.Fuzz(func(t *testing.T, mode uint8, payload []byte) {
		if len(payload) > publicationFuzzPayloadLimit {
			payload = payload[:publicationFuzzPayloadLimit]
		}
		mode %= 8
		directory := t.TempDir()
		target := filepath.Join(directory, "output.pcv")
		protected := filepath.Join(directory, "protected-input.pcv")
		protectedBytes := []byte("protected source bytes")
		foreignTarget := []byte("foreign target bytes")
		foreignStage := []byte("foreign stage bytes")
		if err := os.WriteFile(protected, protectedBytes, 0o640); err != nil {
			t.Fatalf("write protected source: %v", err)
		}

		operations := nativeOperations()
		nativeAtomic := operations.atomicPublish
		nativeSync := operations.syncDirectory
		if nativeAtomic == nil || nativeSync == nil {
			t.Skip("native publication primitive unavailable on this platform")
		}
		policy := PolicyNoReplace
		ctx := context.Background()
		recovery := filepath.Join(directory, "recovery.pcv")

		wantState := StateNotPublished
		wantOutcome := pcv3.OutcomeOperationFailed
		wantStage := pcv3.StageOutputPublication
		wantCode := CodeAtomicFailed
		switch mode {
		case 0:
			wantState = StatePublishedDurable
			wantOutcome = pcv3.OutcomeSuccess
			wantStage = pcv3.StageNone
			wantCode = CodePublishedDurable
			if runtime.GOOS == "windows" {
				wantState = StatePublishedDurabilityUncertain
				wantOutcome = pcv3.OutcomeCommittedDurabilityUncertain
				wantStage = pcv3.StageDirectorySync
				wantCode = CodeDurabilityUncertain
			}
		case 1:
			operations.atomicPublish = func(*os.File, string, string, Policy) error {
				return errors.New("TEST ONLY definite non-commit")
			}
		case 2:
			operations.atomicPublish = func(parent *os.File, stageName, targetName string, policy Policy) error {
				if err := nativeAtomic(parent, stageName, targetName, policy); err != nil {
					return err
				}
				return errors.New("TEST ONLY error after real commit")
			}
			wantState = StatePublishedDurable
			wantOutcome = pcv3.OutcomeSuccess
			wantStage = pcv3.StageNone
			wantCode = CodePublishedDurable
			if runtime.GOOS == "windows" {
				wantState = StatePublishedDurabilityUncertain
				wantOutcome = pcv3.OutcomeCommittedDurabilityUncertain
				wantStage = pcv3.StageDirectorySync
				wantCode = CodeDurabilityUncertain
			}
		case 3:
			operations.atomicPublish = func(_ *os.File, stageName, targetName string, _ Policy) error {
				stagePath := filepath.Join(directory, stageName)
				if err := os.Rename(stagePath, recovery); err != nil {
					return err
				}
				if err := os.WriteFile(stagePath, foreignStage, 0o640); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(directory, targetName), foreignTarget, 0o640); err != nil {
					return err
				}
				return errors.New("TEST ONLY indeterminate commit")
			}
			wantState = StatePublicationIndeterminate
			wantOutcome = pcv3.OutcomePublicationIndeterminate
			wantCode = CodePublicationIndeterminate
		case 4:
			operations.atomicPublish = func(parent *os.File, stageName, targetName string, policy Policy) error {
				if err := os.WriteFile(filepath.Join(directory, targetName), foreignTarget, 0o640); err != nil {
					return err
				}
				return nativeAtomic(parent, stageName, targetName, policy)
			}
		case 5:
			policy = PolicySafeReplace
			if err := os.WriteFile(target, foreignTarget, 0o640); err != nil {
				t.Fatalf("write safe-replace target: %v", err)
			}
			wantCode = CodePolicyUnsupported
		case 6:
			operations.syncDirectory = func(*os.File) error {
				return errors.ErrUnsupported
			}
			wantState = StatePublishedDurabilityUncertain
			wantOutcome = pcv3.OutcomeCommittedDurabilityUncertain
			wantStage = pcv3.StageDirectorySync
			wantCode = CodeDurabilityUncertain
		case 7:
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			ctx = cancelled
			wantStage = pcv3.StageCancellation
			wantCode = CodeCancelled
		}

		stage, err := createWithOperations(target, []string{protected}, policy, operations)
		if mode == 5 {
			if stage != nil {
				stage.Cleanup()
				t.Fatal("unsupported safe-replace created a stage")
			}
			result := requireResultError(t, err)
			requireResult(t, result, wantState, wantOutcome, wantStage, wantCode)
			requireFileBytes(t, target, foreignTarget)
			requireFileBytes(t, protected, protectedBytes)
			requireNoStageEntries(t, directory)
			return
		}
		if err != nil {
			t.Fatalf("create fuzz stage: %v", err)
		}
		stagePath := stage.stagePath
		if count, writeErr := stage.File().Write(payload); writeErr != nil || count != len(payload) {
			stage.Cleanup()
			t.Fatalf("write fuzz stage = %d/%v; want %d/nil", count, writeErr, len(payload))
		}
		if info, statErr := os.Lstat(stagePath); statErr != nil || !info.Mode().IsRegular() {
			stage.Cleanup()
			t.Fatalf("fuzz stage is not a real regular file: %v/%v", info, statErr)
		}

		result := stage.Publish(ctx)
		requireResult(t, result, wantState, wantOutcome, wantStage, wantCode)
		if again := stage.Publish(context.Background()); again != result {
			stage.Cleanup()
			t.Fatal("terminal publication repeated or changed its result")
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup fuzz publication: %v", err)
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("repeat fuzz cleanup changed result: %v", err)
		}
		requireFileBytes(t, protected, protectedBytes)

		switch mode {
		case 0, 2, 6:
			requireFileBytes(t, target, payload)
			if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("committed stage path remains: %v", err)
			}
		case 1, 7:
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("uncommitted scenario created target: %v", err)
			}
			if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("owned uncommitted stage remains: %v", err)
			}
		case 3:
			requireFileBytes(t, target, foreignTarget)
			requireFileBytes(t, stagePath, foreignStage)
			requireFileBytes(t, recovery, payload)
		case 4:
			requireFileBytes(t, target, foreignTarget)
			if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("collision-rejected owned stage remains: %v", err)
			}
		}
	})
}
