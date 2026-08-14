package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

func TestPublishBlocksProtectedHardlinkToOwnedStage(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "output.pcv")
	source := filepath.Join(directory, "source.pcv")
	keyfile := filepath.Join(directory, "keyfile.bin")
	retainedKeyfile := filepath.Join(directory, "retained-keyfile.bin")
	sourceBytes := []byte("legacy source must remain unchanged")
	keyfileBytes := []byte("credential factor must remain unchanged")
	payload := []byte("complete operation-owned ciphertext")
	if err := os.WriteFile(source, sourceBytes, 0o640); err != nil {
		t.Fatalf("write protected source: %v", err)
	}
	if err := os.WriteFile(keyfile, keyfileBytes, 0o600); err != nil {
		t.Fatalf("write protected keyfile: %v", err)
	}
	sourceBefore, err := os.Lstat(source)
	if err != nil {
		t.Fatalf("inspect protected source: %v", err)
	}
	keyfileBefore, err := os.Lstat(keyfile)
	if err != nil {
		t.Fatalf("inspect protected keyfile: %v", err)
	}

	operations, counts := realRenameOperations(t, directory)
	stage, err := createWithOperations(
		target,
		[]string{source, keyfile},
		PolicyNoReplace,
		operations,
	)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	if _, err := stage.File().Write(payload); err != nil {
		stage.Cleanup()
		t.Fatalf("write stage: %v", err)
	}
	stagePath := stage.stagePath
	if err := os.Rename(keyfile, retainedKeyfile); err != nil {
		stage.Cleanup()
		t.Fatalf("retain original protected keyfile: %v", err)
	}
	if err := os.Link(stagePath, keyfile); err != nil {
		stage.Cleanup()
		if runtime.GOOS == "windows" {
			t.Skipf("filesystem does not permit an unprivileged hardlink: %v", err)
		}
		t.Fatalf("replace protected keyfile path with stage hardlink: %v", err)
	}
	aliasBefore, err := os.Lstat(keyfile)
	if err != nil {
		stage.Cleanup()
		t.Fatalf("inspect protected hardlink: %v", err)
	}
	stageBefore, err := os.Lstat(stagePath)
	if err != nil || !os.SameFile(aliasBefore, stageBefore) {
		stage.Cleanup()
		t.Fatalf("test precondition did not alias stage: %v", err)
	}

	result := stage.Publish(context.Background())
	requireResult(
		t,
		result,
		StateNotPublished,
		pcv3result.OutcomeOperationFailed,
		pcv3result.StageOutputPublication,
		CodeIdentityChanged,
	)
	if counts.atomic != 0 || counts.sync != 0 {
		t.Fatalf("protected-stage alias reached publication operations: atomic=%d sync=%d", counts.atomic, counts.sync)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("protected-stage alias created destination: %v", err)
	}
	requireFileBytes(t, source, sourceBytes)
	sourceAfter, err := os.Lstat(source)
	if err != nil || !os.SameFile(sourceBefore, sourceAfter) || sourceBefore.Mode() != sourceAfter.Mode() {
		t.Fatalf("protected source identity or mode changed: %v", err)
	}
	requireFileBytes(t, retainedKeyfile, keyfileBytes)
	keyfileAfter, err := os.Lstat(retainedKeyfile)
	if err != nil || !os.SameFile(keyfileBefore, keyfileAfter) || keyfileBefore.Mode() != keyfileAfter.Mode() {
		t.Fatalf("retained keyfile identity or mode changed: %v", err)
	}

	if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("cleanup with an external stage hardlink = %v; want ErrCleanupIncomplete", err)
	}
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup did not remove the exact owned stage name: %v", err)
	}
	requireFileBytes(t, keyfile, payload)
	aliasAfter, err := os.Lstat(keyfile)
	if err != nil || !os.SameFile(aliasBefore, aliasAfter) || aliasBefore.Mode() != aliasAfter.Mode() {
		t.Fatalf("cleanup touched external hardlink identity or mode: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read publication directory: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wantNames := []string{"keyfile.bin", "retained-keyfile.bin", "source.pcv"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("publication directory entries = %v; want %v", names, wantNames)
	}

	t.Run("sync failure before precommit", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "output.pcv")
		protected := filepath.Join(directory, "keyfile.bin")
		retained := filepath.Join(directory, "retained-keyfile.bin")
		original := []byte("original keyfile bytes")
		payload := []byte("operation ciphertext after early failure")
		if err := os.WriteFile(protected, original, 0o600); err != nil {
			t.Fatalf("write protected keyfile: %v", err)
		}
		protectedBefore, err := os.Lstat(protected)
		if err != nil {
			t.Fatalf("inspect protected keyfile: %v", err)
		}
		operations, counts := realRenameOperations(t, directory)
		syncCalls := 0
		operations.syncStage = func(*os.File) error {
			syncCalls++
			return errors.New("TEST ONLY injected stage sync failure")
		}
		stage, err := createWithOperations(target, []string{protected}, PolicyNoReplace, operations)
		if err != nil {
			t.Fatalf("create stage: %v", err)
		}
		if _, err := stage.File().Write(payload); err != nil {
			stage.Cleanup()
			t.Fatalf("write stage: %v", err)
		}
		stagePath := stage.stagePath
		if err := os.Rename(protected, retained); err != nil {
			stage.Cleanup()
			t.Fatalf("retain protected keyfile: %v", err)
		}
		if err := os.Link(stagePath, protected); err != nil {
			stage.Cleanup()
			if runtime.GOOS == "windows" {
				t.Skipf("filesystem does not permit an unprivileged hardlink: %v", err)
			}
			t.Fatalf("replace protected path with stage hardlink: %v", err)
		}
		aliasBefore, err := os.Lstat(protected)
		if err != nil {
			stage.Cleanup()
			t.Fatalf("inspect stage hardlink: %v", err)
		}

		result := stage.Publish(context.Background())
		requireResult(
			t,
			result,
			StateNotPublished,
			pcv3result.OutcomeOperationFailed,
			pcv3result.StageOutputPublication,
			CodeStageFailure,
		)
		if syncCalls != 1 || counts.atomic != 0 || counts.sync != 0 {
			t.Fatalf(
				"early failure calls: stage-sync=%d atomic=%d directory-sync=%d; want 1/0/0",
				syncCalls,
				counts.atomic,
				counts.sync,
			)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("early stage failure created destination: %v", err)
		}

		if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
			t.Fatalf("cleanup after early failure with external hardlink = %v; want ErrCleanupIncomplete", err)
		}
		if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cleanup did not remove the exact owned stage name: %v", err)
		}
		requireFileBytes(t, protected, payload)
		aliasAfter, err := os.Lstat(protected)
		if err != nil || !os.SameFile(aliasBefore, aliasAfter) || aliasBefore.Mode() != aliasAfter.Mode() {
			t.Fatalf("cleanup touched external hardlink identity or mode: %v", err)
		}
		requireFileBytes(t, retained, original)
		retainedAfter, err := os.Lstat(retained)
		if err != nil || !os.SameFile(protectedBefore, retainedAfter) || protectedBefore.Mode() != retainedAfter.Mode() {
			t.Fatalf("cleanup changed retained keyfile identity or mode: %v", err)
		}
	})
}

func TestPublishFailsClosedAtProtectedSymlinkBoundary(t *testing.T) {
	for _, test := range []struct {
		name       string
		linkTarget func(stagePath, protected string) string
	}{
		{
			name: "alias to owned stage",
			linkTarget: func(stagePath, _ string) string {
				return stagePath
			},
		},
		{
			name: "uninspectable symlink loop",
			linkTarget: func(_, protected string) string {
				return filepath.Base(protected)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "output.pcv")
			protected := filepath.Join(directory, "protected.bin")
			if err := os.WriteFile(protected, []byte("initial protected input"), 0o600); err != nil {
				t.Fatalf("write protected input: %v", err)
			}
			operations, counts := realRenameOperations(t, directory)
			stage, err := createWithOperations(target, []string{protected}, PolicyNoReplace, operations)
			if err != nil {
				t.Fatalf("create stage: %v", err)
			}
			if _, err := stage.File().Write([]byte("operation ciphertext")); err != nil {
				stage.Cleanup()
				t.Fatalf("write stage: %v", err)
			}
			stagePath := stage.stagePath
			if err := os.Remove(protected); err != nil {
				stage.Cleanup()
				t.Fatalf("remove protected input before namespace change: %v", err)
			}
			linkTarget := test.linkTarget(stagePath, protected)
			if err := os.Symlink(linkTarget, protected); err != nil {
				stage.Cleanup()
				t.Skipf("filesystem does not permit an unprivileged symlink: %v", err)
			}
			linkBefore, err := os.Lstat(protected)
			if err != nil || linkBefore.Mode()&os.ModeSymlink == 0 {
				stage.Cleanup()
				t.Fatalf("test precondition did not create symlink: %v", err)
			}

			result := stage.Publish(context.Background())
			requireResult(
				t,
				result,
				StateNotPublished,
				pcv3result.OutcomeOperationFailed,
				pcv3result.StageOutputPublication,
				CodeIdentityChanged,
			)
			if counts.atomic != 0 || counts.sync != 0 {
				t.Fatalf("protected symlink reached publication operations: atomic=%d sync=%d", counts.atomic, counts.sync)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("protected symlink created destination: %v", err)
			}
			if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("cleanup after protected symlink = %v; want ErrCleanupIncomplete", err)
			}
			if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("cleanup did not remove exact owned stage name: %v", err)
			}
			linkAfter, err := os.Lstat(protected)
			if err != nil || !os.SameFile(linkBefore, linkAfter) || linkBefore.Mode() != linkAfter.Mode() {
				t.Fatalf("cleanup touched protected symlink identity or mode: %v", err)
			}
			if got, err := os.Readlink(protected); err != nil || got != linkTarget {
				t.Fatalf("protected symlink target = %q/%v; want %q", got, err, linkTarget)
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatalf("read publication directory: %v", err)
			}
			if len(entries) != 1 || entries[0].Name() != filepath.Base(protected) {
				t.Fatalf("publication directory entries = %v; want only protected symlink", entries)
			}
		})
	}
}
