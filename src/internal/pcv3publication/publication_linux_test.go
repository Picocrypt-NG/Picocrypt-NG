//go:build linux

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxNativeNoReplacePublishesDurably(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "native-output.pcv")
	payload := []byte("complete native PCV3 publication")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatalf("Create native stage: %v", err)
	}
	if _, err := stage.File().Write(payload); err != nil {
		stage.Cleanup()
		t.Fatalf("write native stage: %v", err)
	}

	result := stage.Publish(context.Background())
	requireResult(
		t,
		result,
		StatePublishedDurable,
		pcv3.OutcomeSuccess,
		pcv3.StageNone,
		CodePublishedDurable,
	)
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup native publication: %v", err)
	}
	requireFileBytes(t, target, payload)
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("inspect native destination: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("native destination mode = %v; want regular 0600", info.Mode())
	}
	requireNoStageEntries(t, directory)
}

func TestLinuxRenameat2RejectsLateCollision(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "late-collision.pcv")
	owned := []byte("operation-owned complete output")
	foreign := []byte("late foreign destination")
	operations := nativeOperations()
	nativeAtomic := operations.atomicPublish
	operations.atomicPublish = func(parent *os.File, stageName, targetName string, policy Policy) error {
		if err := os.WriteFile(filepath.Join(directory, targetName), foreign, 0o640); err != nil {
			return err
		}
		return nativeAtomic(parent, stageName, targetName, policy)
	}
	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatalf("create collision stage: %v", err)
	}
	stagePath := stage.stagePath
	if _, err := stage.File().Write(owned); err != nil {
		stage.Cleanup()
		t.Fatalf("write collision stage: %v", err)
	}

	result := stage.Publish(context.Background())
	requireResult(
		t,
		result,
		StateNotPublished,
		pcv3.OutcomeOperationFailed,
		pcv3.StageOutputPublication,
		CodeAtomicFailed,
	)
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup rejected collision stage: %v", err)
	}
	requireFileBytes(t, target, foreign)
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned stage remains after proven non-commit cleanup: %v", err)
	}
}

func TestLinuxSafeReplaceFailsBeforeStage(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "existing.pcv")
	original := []byte("existing destination")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("write existing destination: %v", err)
	}

	stage, err := Create(target, nil, PolicySafeReplace)
	if stage != nil {
		stage.Cleanup()
		t.Fatal("Linux safe-replace created staging without an identity-bound primitive")
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
	requireFileBytes(t, target, original)
	requireNoStageEntries(t, directory)
}
