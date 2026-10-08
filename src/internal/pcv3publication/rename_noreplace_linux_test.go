//go:build linux || android

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// forceRenameat2Error simulates a kernel whose renameat2 syscall always fails
// with the given error (ENOSYS on pre-3.15 kernels such as Android 7's 3.10).
func forceRenameat2Error(t *testing.T, err error) {
	t.Helper()
	native := unixRenameat2NoReplace
	unixRenameat2NoReplace = func(int, string, string) error {
		return err
	}
	t.Cleanup(func() {
		unixRenameat2NoReplace = native
	})
}

// TestRenameNoReplaceENOSYSFallbackPublishesDurably protects the production
// risk that PCV3 volume creation and read-output publication fail outright on
// Android 7 devices whose pre-3.15 kernel lacks renameat2 (ENOSYS): the whole
// native pipeline (stage publish and cleanup-journal install) must reach the
// proven durable state through the link(2)+unlink(2) fallback with the staged
// identity and exact bytes preserved.
func TestRenameNoReplaceENOSYSFallbackPublishesDurably(t *testing.T) {
	forceRenameat2Error(t, unix.ENOSYS)
	directory := t.TempDir()
	target := filepath.Join(directory, "enosys-output.pcv")
	payload := []byte("published through the link fallback\x00\x01")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	stagePath := stage.stagePath
	if count, err := stage.File().Write(payload); err != nil || count != len(payload) {
		stage.Cleanup()
		t.Fatalf("write stage = %d/%v; want %d/nil", count, err, len(payload))
	}
	stagedInfo, err := stage.File().Stat()
	if err != nil {
		stage.Cleanup()
		t.Fatalf("inspect staged identity: %v", err)
	}
	if err := stage.PersistCleanupJournal(); err != nil {
		stage.Cleanup()
		t.Fatalf("persist cleanup journal through fallback: %v", err)
	}

	result := stage.Publish(context.Background())
	requireResult(
		t,
		result,
		StatePublishedDurable,
		pcv3result.OutcomeSuccess,
		pcv3result.StageNone,
		CodePublishedDurable,
	)
	committedInfo, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("inspect committed destination: %v", err)
	}
	if !os.SameFile(stagedInfo, committedInfo) {
		t.Fatal("link-fallback commit changed the staged file identity")
	}
	requireFileBytes(t, target, payload)
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage pathname remains after fallback commit: %v", err)
	}
	requireAbsent(t, filepath.Join(directory, cleanupJournalName))
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup fallback commit: %v", err)
	}
	requireFileBytes(t, target, payload)
}

// TestRenameNoReplaceENOSYSFallbackRefusesLateCollision protects the
// production risk that the no-replace guarantee is lost on pre-3.15 kernels:
// a destination created after staging must never be overwritten by the
// link(2)+unlink(2) fallback, and the failed commit must stay fail-closed.
func TestRenameNoReplaceENOSYSFallbackRefusesLateCollision(t *testing.T) {
	forceRenameat2Error(t, unix.ENOSYS)
	directory := t.TempDir()
	target := filepath.Join(directory, "enosys-collision.pcv")
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
		pcv3result.OutcomeOperationFailed,
		pcv3result.StageOutputPublication,
		CodeAtomicFailed,
	)
	requireFileBytes(t, target, foreign)
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup rejected fallback collision: %v", err)
	}
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned stage remains after proven non-commit cleanup: %v", err)
	}
	requireFileBytes(t, target, foreign)
}

// TestRenameNoReplaceNonENOSYSNeverFallsBack protects the production risk that
// the link(2)+unlink(2) fallback masks a real renameat2 failure on modern
// kernels: any non-ENOSYS error must propagate through the existing
// identity-based classification without link(2) ever being attempted.
func TestRenameNoReplaceNonENOSYSNeverFallsBack(t *testing.T) {
	forceRenameat2Error(t, unix.EIO)
	directory := t.TempDir()
	target := filepath.Join(directory, "enosys-never.pcv")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	stagePath := stage.stagePath
	if _, err := stage.File().Write([]byte("operation-owned output")); err != nil {
		stage.Cleanup()
		t.Fatalf("write stage: %v", err)
	}

	result := stage.Publish(context.Background())
	requireResult(
		t,
		result,
		StateNotPublished,
		pcv3result.OutcomeOperationFailed,
		pcv3result.StageOutputPublication,
		CodeAtomicFailed,
	)
	// Had the fallback run, link(2) would have succeeded and created the target.
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-ENOSYS failure created the destination: %v", err)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup after non-ENOSYS failure: %v", err)
	}
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned stage remains after proven non-commit cleanup: %v", err)
	}
}

// TestRenameNoReplaceFallbackLinkSemantics protects the production risk that
// the ENOSYS fallback itself violates publication semantics: it must move the
// exact staged inode to the target, must refuse an existing target without
// touching either name, and must propagate non-ENOSYS renameat2 errors without
// attempting link(2).
func TestRenameNoReplaceFallbackLinkSemantics(t *testing.T) {
	openParent := func(t *testing.T, directory string) *os.File {
		t.Helper()
		parent, err := os.Open(directory)
		if err != nil {
			t.Fatalf("open pinned parent: %v", err)
		}
		t.Cleanup(func() {
			_ = parent.Close()
		})
		return parent
	}
	seed := func(t *testing.T, path string, data []byte) os.FileInfo {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("seed %s: %v", filepath.Base(path), err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("inspect %s: %v", filepath.Base(path), err)
		}
		return info
	}

	t.Run("fallback moves the exact staged identity", func(t *testing.T) {
		forceRenameat2Error(t, unix.ENOSYS)
		directory := t.TempDir()
		stageBytes := []byte("staged bytes moved by link fallback")
		stagedInfo := seed(t, filepath.Join(directory, "stage"), stageBytes)
		parent := openParent(t, directory)

		if err := renameNoReplace(int(parent.Fd()), "stage", "target"); err != nil {
			t.Fatalf("fallback rename: %v", err)
		}
		committedInfo, err := os.Lstat(filepath.Join(directory, "target"))
		if err != nil {
			t.Fatalf("inspect fallback target: %v", err)
		}
		if !os.SameFile(stagedInfo, committedInfo) {
			t.Fatal("fallback changed the staged file identity")
		}
		requireFileBytes(t, filepath.Join(directory, "target"), stageBytes)
		if _, err := os.Lstat(filepath.Join(directory, "stage")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source name remains after fallback: %v", err)
		}
	})

	t.Run("fallback refuses an existing target and preserves both names", func(t *testing.T) {
		forceRenameat2Error(t, unix.ENOSYS)
		directory := t.TempDir()
		stageBytes := []byte("staged bytes that must survive a refused fallback")
		foreign := []byte("foreign destination that must survive a refused fallback")
		seed(t, filepath.Join(directory, "stage"), stageBytes)
		seed(t, filepath.Join(directory, "target"), foreign)
		parent := openParent(t, directory)

		err := renameNoReplace(int(parent.Fd()), "stage", "target")
		if !errors.Is(err, unix.EEXIST) {
			t.Fatalf("fallback collision error = %v; want EEXIST", err)
		}
		requireFileBytes(t, filepath.Join(directory, "target"), foreign)
		requireFileBytes(t, filepath.Join(directory, "stage"), stageBytes)
	})

	t.Run("non-ENOSYS errors propagate without attempting link", func(t *testing.T) {
		forceRenameat2Error(t, unix.EPERM)
		directory := t.TempDir()
		stageBytes := []byte("staged bytes that must survive a non-ENOSYS failure")
		seed(t, filepath.Join(directory, "stage"), stageBytes)
		parent := openParent(t, directory)

		err := renameNoReplace(int(parent.Fd()), "stage", "target")
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("non-ENOSYS rename error = %v; want EPERM", err)
		}
		if _, statErr := os.Lstat(filepath.Join(directory, "target")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("non-ENOSYS failure created the destination: %v", statErr)
		}
		requireFileBytes(t, filepath.Join(directory, "stage"), stageBytes)
	})
}

// A kernel without renameat2 is supported only if the filesystem's hard-link
// fallback actually enforces no-replace on the pinned output directory.
func TestCapabilityProbeENOSYSFallback(t *testing.T) {
	forceRenameat2Error(t, unix.ENOSYS)
	stage, err := Create(filepath.Join(t.TempDir(), "output"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if err := stage.CheckCapability(); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilityProbePermissionRefusal(t *testing.T) {
	forceRenameat2Error(t, unix.EPERM)
	directory := t.TempDir()
	stage, err := Create(filepath.Join(directory, "output"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if err := stage.CheckCapability(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("probe = %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("probe residue: %v %v", entries, err)
	}
}
