package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type operationCounts struct {
	atomic int
	sync   int
}

func realRenameOperations(t *testing.T, directory string) (platformOperations, *operationCounts) {
	t.Helper()
	counts := &operationCounts{}
	return platformOperations{
		atomicPublish: func(parent *os.File, stageName, targetName string, policy Policy) error {
			counts.atomic++
			if policy != PolicyNoReplace {
				return errors.New("test operation received replacing policy")
			}
			if !sameDirectoryHandle(parent, directory) {
				return errors.New("test operation received wrong directory handle")
			}
			return os.Rename(
				filepath.Join(directory, stageName),
				filepath.Join(directory, targetName),
			)
		},
		syncDirectory: func(parent *os.File) error {
			counts.sync++
			if !sameDirectoryHandle(parent, directory) {
				return errors.New("test sync received wrong directory handle")
			}
			return parent.Sync()
		},
	}, counts
}

func sameDirectoryHandle(parent *os.File, directory string) bool {
	if parent == nil {
		return false
	}
	pinned, err := parent.Stat()
	if err != nil {
		return false
	}
	current, err := os.Stat(directory)
	return err == nil && os.SameFile(pinned, current)
}

func requireResultError(t *testing.T, err error) Result {
	t.Helper()
	if err == nil {
		t.Fatal("operation unexpectedly succeeded")
	}
	var result Result
	if !errors.As(err, &result) {
		t.Fatalf("error type = %T; want sealed publication Result", err)
	}
	return result
}

func requireResult(
	t *testing.T,
	result Result,
	wantState State,
	wantOutcome pcv3.Outcome,
	wantStage pcv3.Stage,
	wantCode Code,
) {
	t.Helper()
	if result == nil {
		t.Fatal("publication returned a nil result")
	}
	if got := result.State(); got != wantState {
		t.Errorf("state = %s; want %s", got, wantState)
	}
	if got := result.Outcome(); got != wantOutcome {
		t.Errorf("outcome = %s; want %s", got, wantOutcome)
	}
	if got := result.Stage(); got != wantStage {
		t.Errorf("stage = %s; want %s", got, wantStage)
	}
	if got := result.Code(); got != wantCode {
		t.Errorf("code = %s; want %s", got, wantCode)
	}
}

func requireFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("test file bytes = %q; want %q", got, want)
	}
}

func requireNoStageEntries(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read test directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), stageNamePrefix) {
			t.Fatalf("unexpected publication stage remains: %q", entry.Name())
		}
	}
}

func TestCreateStageOwnsExclusivePrivateSibling(t *testing.T) {
	directory := t.TempDir()
	operations, counts := realRenameOperations(t, directory)
	first, err := createWithOperations(
		filepath.Join(directory, "first.pcv"),
		nil,
		PolicyNoReplace,
		operations,
	)
	if err != nil {
		t.Fatalf("create first stage: %v", err)
	}
	defer first.Cleanup()
	second, err := createWithOperations(
		filepath.Join(directory, "second.pcv"),
		nil,
		PolicyNoReplace,
		operations,
	)
	if err != nil {
		t.Fatalf("create second stage: %v", err)
	}
	defer second.Cleanup()

	if first.stageName == second.stageName {
		t.Fatal("two operation-owned stages reused one supposedly random name")
	}
	for _, stage := range []*Stage{first, second} {
		if !strings.HasPrefix(stage.stageName, stageNamePrefix) {
			t.Fatalf("stage name %q lacks the private publication prefix", stage.stageName)
		}
		if filepath.Dir(stage.stagePath) != directory {
			t.Fatalf("stage is not a sibling of its destination: %q", stage.stagePath)
		}
		info, err := stage.File().Stat()
		if err != nil {
			t.Fatalf("inspect open stage: %v", err)
		}
		current, err := os.Lstat(stage.stagePath)
		if err != nil {
			t.Fatalf("inspect stage path: %v", err)
		}
		if !info.Mode().IsRegular() || !os.SameFile(info, current) {
			t.Fatal("stage path does not name the exclusively opened regular file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("stage mode = %04o; want 0600", info.Mode().Perm())
		}
	}
	if counts.atomic != 0 || counts.sync != 0 {
		t.Fatalf("stage creation invoked publication operations: atomic=%d sync=%d", counts.atomic, counts.sync)
	}
}

func TestNoReplacePreservesDestination(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "occupied.pcv")
	original := []byte("existing destination must survive")
	if err := os.WriteFile(target, original, 0o640); err != nil {
		t.Fatalf("write existing destination: %v", err)
	}
	before, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("inspect existing destination: %v", err)
	}
	operations, counts := realRenameOperations(t, directory)

	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if stage != nil {
		stage.Cleanup()
		t.Fatal("no-replace returned a stage for an occupied destination")
	}
	result := requireResultError(t, err)
	requireResult(
		t,
		result,
		StateNotPublished,
		pcv3.OutcomeOperationFailed,
		pcv3.StageOutputPublication,
		CodeDestinationExists,
	)
	if counts.atomic != 0 || counts.sync != 0 {
		t.Fatalf("occupied destination reached publication operations: atomic=%d sync=%d", counts.atomic, counts.sync)
	}
	after, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("inspect destination after refusal: %v", err)
	}
	if !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatal("no-replace changed destination identity or mode")
	}
	requireFileBytes(t, target, original)
	requireNoStageEntries(t, directory)
	if strings.Contains(fmt.Sprintf("%+v", err), target) {
		t.Fatal("no-replace refusal disclosed the destination path")
	}
}

func TestSafeReplaceFailsClosedWithoutIdentityPrimitive(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "existing.pcv")
	original := []byte("identity-pinned destination")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("write existing destination: %v", err)
	}
	operations, counts := realRenameOperations(t, directory)

	stage, err := createWithOperations(target, nil, PolicySafeReplace, operations)
	if stage != nil {
		stage.Cleanup()
		t.Fatal("unsupported safe-replace created staging")
	}
	result := requireResultError(t, err)
	requireResult(
		t,
		result,
		StateNotPublished,
		pcv3.OutcomeOperationFailed,
		pcv3.StageOutputPublication,
		CodePolicyUnsupported,
	)
	if counts.atomic != 0 || counts.sync != 0 {
		t.Fatalf("unsupported safe-replace reached publication operations: atomic=%d sync=%d", counts.atomic, counts.sync)
	}
	requireFileBytes(t, target, original)
	requireNoStageEntries(t, directory)
}

func TestProtectedOutputAliasFailsBeforeStage(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "source-and-output.pcv")
	operations, counts := realRenameOperations(t, directory)

	stage, err := createWithOperations(target, []string{target}, PolicyNoReplace, operations)
	if stage != nil {
		stage.Cleanup()
		t.Fatal("protected output alias created staging")
	}
	result := requireResultError(t, err)
	requireResult(
		t,
		result,
		StateNotPublished,
		pcv3.OutcomeOperationFailed,
		pcv3.StageOutputPublication,
		CodeInvalidRequest,
	)
	if counts.atomic != 0 || counts.sync != 0 {
		t.Fatalf("protected alias reached publication operations: atomic=%d sync=%d", counts.atomic, counts.sync)
	}
	requireNoStageEntries(t, directory)
}

func TestPublishCancellationBoundary(t *testing.T) {
	t.Run("before atomic call", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "cancelled.pcv")
		operations, counts := realRenameOperations(t, directory)
		stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
		if err != nil {
			t.Fatalf("create stage: %v", err)
		}
		if _, err := stage.File().Write([]byte("must never publish")); err != nil {
			stage.Cleanup()
			t.Fatalf("write stage: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result := stage.Publish(ctx)
		requireResult(
			t,
			result,
			StateNotPublished,
			pcv3.OutcomeOperationFailed,
			pcv3.StageCancellation,
			CodeCancelled,
		)
		if counts.atomic != 0 || counts.sync != 0 {
			t.Fatalf("pre-call cancellation reached publication operations: atomic=%d sync=%d", counts.atomic, counts.sync)
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup cancelled stage: %v", err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pre-call cancellation published a destination: %v", err)
		}
		requireNoStageEntries(t, directory)
	})

	t.Run("after proven commit", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "committed.pcv")
		payload := []byte("complete committed output")
		ctx, cancel := context.WithCancel(context.Background())
		counts := &operationCounts{}
		operations := platformOperations{
			atomicPublish: func(parent *os.File, stageName, targetName string, policy Policy) error {
				counts.atomic++
				if !sameDirectoryHandle(parent, directory) || policy != PolicyNoReplace {
					return errors.New("wrong test publication request")
				}
				if err := os.Rename(filepath.Join(directory, stageName), filepath.Join(directory, targetName)); err != nil {
					return err
				}
				cancel()
				return errors.New("atomic-call-error-after-commit-canary")
			},
			syncDirectory: func(parent *os.File) error {
				counts.sync++
				return parent.Sync()
			},
		}
		stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
		if err != nil {
			t.Fatalf("create stage: %v", err)
		}
		if _, err := stage.File().Write(payload); err != nil {
			stage.Cleanup()
			t.Fatalf("write stage: %v", err)
		}

		result := stage.Publish(ctx)
		requireResult(
			t,
			result,
			StatePublishedDurable,
			pcv3.OutcomeSuccess,
			pcv3.StageNone,
			CodePublishedDurable,
		)
		if counts.atomic != 1 || counts.sync != 1 {
			t.Fatalf("proven commit calls: atomic=%d sync=%d; want 1/1", counts.atomic, counts.sync)
		}
		if again := stage.Publish(context.Background()); again != result {
			t.Fatal("second Publish did not return the sealed terminal result")
		}
		if counts.atomic != 1 || counts.sync != 1 {
			t.Fatalf("second Publish repeated effects: atomic=%d sync=%d", counts.atomic, counts.sync)
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup committed stage: %v", err)
		}
		requireFileBytes(t, target, payload)
	})
}

func TestPublishIndeterminateRetainsUnprovenPaths(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "ambiguous.pcv")
	recovery := filepath.Join(directory, "operation-bytes-recovery")
	operationBytes := []byte("complete operation-owned output")
	foreignStageBytes := []byte("foreign bytes at remembered stage name")
	foreignTargetBytes := []byte("foreign bytes at target name")
	atomicCanary := "atomic-unprovable-error-canary"
	counts := &operationCounts{}
	operations := platformOperations{
		atomicPublish: func(parent *os.File, stageName, targetName string, policy Policy) error {
			counts.atomic++
			stagePath := filepath.Join(directory, stageName)
			if err := os.Rename(stagePath, recovery); err != nil {
				return err
			}
			if err := os.WriteFile(stagePath, foreignStageBytes, 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(directory, targetName), foreignTargetBytes, 0o600); err != nil {
				return err
			}
			return errors.New(atomicCanary)
		},
		syncDirectory: func(*os.File) error {
			counts.sync++
			return nil
		},
	}
	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	stagePath := stage.stagePath
	if _, err := stage.File().Write(operationBytes); err != nil {
		stage.Cleanup()
		t.Fatalf("write stage: %v", err)
	}

	result := stage.Publish(context.Background())
	requireResult(
		t,
		result,
		StatePublicationIndeterminate,
		pcv3.OutcomePublicationIndeterminate,
		pcv3.StageOutputPublication,
		CodePublicationIndeterminate,
	)
	if counts.atomic != 1 || counts.sync != 0 {
		t.Fatalf("indeterminate calls: atomic=%d sync=%d; want 1/0", counts.atomic, counts.sync)
	}
	for _, rendered := range []string{
		result.Error(),
		result.String(),
		result.GoString(),
		fmt.Sprintf("%v", result),
		fmt.Sprintf("%+v", result),
		fmt.Sprintf("%#v", result),
		fmt.Sprintf("%q", result),
		fmt.Sprintf("%x", result),
		fmt.Sprintf("%d", result),
	} {
		for _, canary := range []string{atomicCanary, target, stagePath, recovery} {
			if strings.Contains(rendered, canary) {
				t.Fatalf("indeterminate result disclosed %q in %q", canary, rendered)
			}
		}
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("non-destructive indeterminate cleanup: %v", err)
	}
	requireFileBytes(t, stagePath, foreignStageBytes)
	requireFileBytes(t, target, foreignTargetBytes)
	requireFileBytes(t, recovery, operationBytes)
}

func TestCleanupRemovesOnlyOwnedUnpublishedStage(t *testing.T) {
	t.Run("owned stage", func(t *testing.T) {
		directory := t.TempDir()
		operations, _ := realRenameOperations(t, directory)
		stage, err := createWithOperations(
			filepath.Join(directory, "output.pcv"),
			nil,
			PolicyNoReplace,
			operations,
		)
		if err != nil {
			t.Fatalf("create stage: %v", err)
		}
		stagePath := stage.stagePath
		if _, err := stage.File().Write([]byte("unpublished bytes")); err != nil {
			stage.Cleanup()
			t.Fatalf("write stage: %v", err)
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup owned stage: %v", err)
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("second cleanup changed terminal result: %v", err)
		}
		if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned unpublished stage remains: %v", err)
		}
	})

	t.Run("foreign replacement", func(t *testing.T) {
		directory := t.TempDir()
		operations, _ := realRenameOperations(t, directory)
		stage, err := createWithOperations(
			filepath.Join(directory, "output.pcv"),
			nil,
			PolicyNoReplace,
			operations,
		)
		if err != nil {
			t.Fatalf("create stage: %v", err)
		}
		stagePath := stage.stagePath
		if err := os.Remove(stagePath); err != nil {
			stage.Cleanup()
			t.Skipf("platform prevents replacing an open stage: %v", err)
		}
		foreign := []byte("must not be removed by cleanup")
		if err := os.WriteFile(stagePath, foreign, 0o640); err != nil {
			stage.Cleanup()
			t.Fatalf("write foreign stage replacement: %v", err)
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup after stage replacement: %v", err)
		}
		requireFileBytes(t, stagePath, foreign)
	})
}

func TestPublishDurabilityFailureRetainsCommittedDestination(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "durability-uncertain.pcv")
	payload := []byte("complete committed output")
	durabilityCanary := "directory-sync-error-canary"
	counts := &operationCounts{}
	operations := platformOperations{
		atomicPublish: func(parent *os.File, stageName, targetName string, policy Policy) error {
			counts.atomic++
			return os.Rename(filepath.Join(directory, stageName), filepath.Join(directory, targetName))
		},
		syncDirectory: func(*os.File) error {
			counts.sync++
			return errors.New(durabilityCanary)
		},
	}
	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	if _, err := stage.File().Write(payload); err != nil {
		stage.Cleanup()
		t.Fatalf("write stage: %v", err)
	}

	result := stage.Publish(context.Background())
	requireResult(
		t,
		result,
		StatePublishedDurabilityUncertain,
		pcv3.OutcomeCommittedDurabilityUncertain,
		pcv3.StageDirectorySync,
		CodeDurabilityUncertain,
	)
	if counts.atomic != 1 || counts.sync != 1 {
		t.Fatalf("durability failure calls: atomic=%d sync=%d; want 1/1", counts.atomic, counts.sync)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), durabilityCanary) {
		t.Fatal("durability result disclosed the raw sync error")
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup after committed durability failure: %v", err)
	}
	requireFileBytes(t, target, payload)
}
