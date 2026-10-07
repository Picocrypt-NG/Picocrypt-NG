package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
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

// pcv3FaultSource is the simulated operation input whose identity, mode, and
// exact bytes must survive every publication fault untouched.
type pcv3FaultSource struct {
	path  string
	info  os.FileInfo
	bytes []byte
}

func pcv3SeedFaultSource(t *testing.T, directory string) *pcv3FaultSource {
	t.Helper()
	source := &pcv3FaultSource{
		path:  filepath.Join(directory, "source.pcv"),
		bytes: []byte("publication fault protected source bytes\x00\x01"),
	}
	if err := os.WriteFile(source.path, source.bytes, 0o640); err != nil {
		t.Fatalf("seed protected source: %v", err)
	}
	info, err := os.Lstat(source.path)
	if err != nil {
		t.Fatalf("inspect protected source: %v", err)
	}
	source.info = info
	return source
}

func (source *pcv3FaultSource) requireRetained(t *testing.T) {
	t.Helper()
	current, err := os.Lstat(source.path)
	if err != nil {
		t.Fatalf("protected source vanished: %v", err)
	}
	if !os.SameFile(source.info, current) || current.Mode() != source.info.Mode() {
		t.Fatalf("protected source identity/mode changed: %v/%v; want %v", current.Mode(), err, source.info.Mode())
	}
	requireFileBytes(t, source.path, source.bytes)
}

// pcv3RequireNoDisclosure proves that no fault rendering exposes the canary
// error text, a filesystem path, or the staged payload.
func pcv3RequireNoDisclosure(t *testing.T, rendered any, canaries ...string) {
	t.Helper()
	formatted := fmt.Sprintf("%v|%+v|%#v|%q", rendered, rendered, rendered, rendered)
	for _, canary := range canaries {
		if canary == "" {
			t.Fatal("empty disclosure canary")
		}
		if strings.Contains(formatted, canary) {
			t.Fatalf("fault rendering disclosed canary material: %q", formatted)
		}
	}
}

// pcv3NativeFaultOperations binds the real native platform operations and
// records commit/sync counts so a fault case can prove exactly which native
// boundary ran. The caller must have established native availability with
// pcv3RequireNativeFaultPlatform.
func pcv3NativeFaultOperations(t *testing.T) (platformOperations, *operationCounts) {
	t.Helper()
	counts := &operationCounts{}
	operations := nativeOperations()
	if operations.atomicPublish == nil || operations.syncDirectory == nil {
		t.Fatal("native publication operations became unavailable mid-test")
	}
	atomic := operations.atomicPublish
	operations.atomicPublish = func(parent *os.File, stageName, targetName string, policy Policy) error {
		counts.atomic++
		return atomic(parent, stageName, targetName, policy)
	}
	syncDirectory := operations.syncDirectory
	operations.syncDirectory = func(parent *os.File) error {
		counts.sync++
		return syncDirectory(parent)
	}
	return operations, counts
}

// pcv3RequireNativeFaultPlatform skips the whole matrix on platforms without
// a native atomic-publish and directory-sync primitive; the terminal gate runs
// on a native platform where this skip cannot fire.
func pcv3RequireNativeFaultPlatform(t *testing.T) {
	t.Helper()
	operations := nativeOperations()
	if operations.atomicPublish == nil || operations.syncDirectory == nil {
		t.Skip("native publication operations unavailable on this platform")
	}
}

func pcv3RequireNativeCommit(t *testing.T, result Result) {
	t.Helper()
	if runtime.GOOS == "windows" {
		requireResult(t, result, StatePublishedDurabilityUncertain, pcv3result.OutcomeCommittedDurabilityUncertain, pcv3result.StageDirectorySync, CodeDurabilityUncertain)
		return
	}
	requireResult(t, result, StatePublishedDurable, pcv3result.OutcomeSuccess, pcv3result.StageNone, CodePublishedDurable)
}

// TestPCV3PublicationFaultMatrix runs the integrated native filesystem fault
// matrix at the real stage/commit boundary: every case compares source,
// destination, and staging identities and exact bytes, preserves foreign data,
// and requires the exact closed publication and cleanup classification.
func TestPCV3PublicationFaultMatrix(t *testing.T) {
	pcv3RequireNativeFaultPlatform(t)
	t.Run("durable commit preserves the staged identity and exact bytes", func(t *testing.T) {
		directory := t.TempDir()
		source := pcv3SeedFaultSource(t, directory)
		foreign := []byte("foreign neighbor must survive commit")
		foreignPath := filepath.Join(directory, "foreign.txt")
		if err := os.WriteFile(foreignPath, foreign, 0o640); err != nil {
			t.Fatalf("seed foreign neighbor: %v", err)
		}
		target := filepath.Join(directory, "output.bin")
		payload := []byte("complete staged plaintext payload\x00")
		stage, err := Create(target, []string{source.path}, PolicyNoReplace)
		if err != nil {
			t.Fatalf("create native stage: %v", err)
		}
		stagePath := stage.stagePath
		if count, err := stage.File().Write(payload); err != nil || count != len(payload) {
			stage.Cleanup()
			t.Fatalf("write stage = %d/%v; want %d/nil", count, err, len(payload))
		}
		stagedInfo, err := stage.File().Stat()
		if err != nil {
			stage.Cleanup()
			t.Fatalf("inspect staged identity before commit: %v", err)
		}

		result := stage.Publish(context.Background())
		pcv3RequireNativeCommit(t, result)
		committedInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("inspect committed destination: %v", err)
		}
		if !os.SameFile(stagedInfo, committedInfo) {
			t.Fatal("durable commit changed the staged file identity")
		}
		if runtime.GOOS != "windows" && committedInfo.Mode().Perm() != 0o600 {
			t.Fatalf("committed destination mode = %04o; want 0600", committedInfo.Mode().Perm())
		}
		requireFileBytes(t, target, payload)
		if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("committed stage pathname remains: %v", err)
		}
		if again := stage.Publish(context.Background()); again != result {
			t.Fatal("second Publish did not return the sealed terminal result")
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup durable commit: %v", err)
		}
		requireFileBytes(t, foreignPath, foreign)
		source.requireRetained(t)
	})

	t.Run("short staged payload publishes byte exact", func(t *testing.T) {
		directory := t.TempDir()
		source := pcv3SeedFaultSource(t, directory)
		target := filepath.Join(directory, "short.bin")
		payload := []byte{0x5a}
		stage, err := Create(target, []string{source.path}, PolicyNoReplace)
		if err != nil {
			t.Fatalf("create short stage: %v", err)
		}
		stagePath := stage.stagePath
		if count, err := stage.File().Write(payload); err != nil || count != 1 {
			stage.Cleanup()
			t.Fatalf("write short stage = %d/%v; want 1/nil", count, err)
		}
		stagedInfo, err := stage.File().Stat()
		if err != nil {
			stage.Cleanup()
			t.Fatalf("inspect short staged identity: %v", err)
		}

		result := stage.Publish(context.Background())
		pcv3RequireNativeCommit(t, result)
		committedInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("inspect short destination: %v", err)
		}
		if !os.SameFile(stagedInfo, committedInfo) || committedInfo.Size() != 1 {
			t.Fatalf("short destination identity/size = %v/%d; want staged identity and 1 byte", committedInfo, committedInfo.Size())
		}
		requireFileBytes(t, target, payload)
		if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("short stage pathname remains: %v", err)
		}
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup short commit: %v", err)
		}
		source.requireRetained(t)
	})

	t.Run("missing pinned parent is never created", func(t *testing.T) {
		base := t.TempDir()
		source := pcv3SeedFaultSource(t, base)
		missingParent := filepath.Join(base, "missing-root")
		target := filepath.Join(missingParent, "output.bin")

		stage, err := Create(target, []string{source.path}, PolicyNoReplace)
		if stage != nil {
			stage.Cleanup()
			t.Fatal("missing pinned parent produced a stage")
		}
		result := requireResultError(t, err)
		requireResult(
			t,
			result,
			StateNotPublished,
			pcv3result.OutcomeOperationFailed,
			pcv3result.StageOutputPublication,
			CodeStageFailure,
		)
		if _, err := os.Lstat(missingParent); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("publication created the missing pinned parent: %v", err)
		}
		entries, err := os.ReadDir(base)
		if err != nil || len(entries) != 1 || entries[0].Name() != "source.pcv" {
			t.Fatalf("missing-parent failure left entries = %v, error %v; want only the source", entries, err)
		}
		source.requireRetained(t)
		pcv3RequireNoDisclosure(t, err, missingParent, target)
	})

	t.Run("no-replace collision at commit retains the exact foreign destination", func(t *testing.T) {
		directory := t.TempDir()
		source := pcv3SeedFaultSource(t, directory)
		target := filepath.Join(directory, "occupied.bin")
		payload := []byte("operation-owned complete output")
		foreign := []byte("late foreign destination bytes")
		operations, counts := pcv3NativeFaultOperations(t)
		operations.atomicPublish = func(parent *os.File, stageName, targetName string, policy Policy) error {
			counts.atomic++
			if err := os.WriteFile(filepath.Join(directory, targetName), foreign, 0o640); err != nil {
				return err
			}
			return nativeOperations().atomicPublish(parent, stageName, targetName, policy)
		}
		stage, err := createWithOperations(target, []string{source.path}, PolicyNoReplace, operations)
		if err != nil {
			t.Fatalf("create collision stage: %v", err)
		}
		stagePath := stage.stagePath
		if _, err := stage.File().Write(payload); err != nil {
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
		if counts.atomic != 1 || counts.sync != 0 {
			t.Fatalf("collision calls: atomic=%d sync=%d; want 1/0", counts.atomic, counts.sync)
		}
		foreignInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("inspect foreign destination: %v", err)
		}
		if !foreignInfo.Mode().IsRegular() || (runtime.GOOS != "windows" && foreignInfo.Mode().Perm() != 0o640) {
			t.Fatalf("foreign destination mode = %v; want regular 0640", foreignInfo.Mode())
		}
		requireFileBytes(t, target, foreign)
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup rejected collision stage: %v", err)
		}
		if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned collision stage remains: %v", err)
		}
		requireFileBytes(t, target, foreign)
		source.requireRetained(t)
		pcv3RequireNoDisclosure(t, result, target, stagePath, string(payload))
	})

	t.Run("directory sync failure retains the committed destination with uncertain durability", func(t *testing.T) {
		directory := t.TempDir()
		source := pcv3SeedFaultSource(t, directory)
		target := filepath.Join(directory, "uncertain.bin")
		payload := []byte("complete committed output with unproven durability")
		syncCanary := "pcv3-fault-directory-sync-canary"
		operations, counts := pcv3NativeFaultOperations(t)
		operations.syncDirectory = func(*os.File) error {
			counts.sync++
			return errors.New(syncCanary)
		}
		stage, err := createWithOperations(target, []string{source.path}, PolicyNoReplace, operations)
		if err != nil {
			t.Fatalf("create durability stage: %v", err)
		}
		if _, err := stage.File().Write(payload); err != nil {
			stage.Cleanup()
			t.Fatalf("write durability stage: %v", err)
		}
		stagedInfo, err := stage.File().Stat()
		if err != nil {
			stage.Cleanup()
			t.Fatalf("inspect durability staged identity: %v", err)
		}

		result := stage.Publish(context.Background())
		requireResult(
			t,
			result,
			StatePublishedDurabilityUncertain,
			pcv3result.OutcomeCommittedDurabilityUncertain,
			pcv3result.StageDirectorySync,
			CodeDurabilityUncertain,
		)
		if counts.atomic != 1 || counts.sync != 1 {
			t.Fatalf("durability failure calls: atomic=%d sync=%d; want 1/1", counts.atomic, counts.sync)
		}
		committedInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("inspect uncertain destination: %v", err)
		}
		if !os.SameFile(stagedInfo, committedInfo) {
			t.Fatal("uncertain commit changed the staged file identity")
		}
		requireFileBytes(t, target, payload)
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup after uncertain durability: %v", err)
		}
		requireFileBytes(t, target, payload)
		source.requireRetained(t)
		pcv3RequireNoDisclosure(t, result, syncCanary, target, directory)
	})

	t.Run("indeterminate commit retains every byte and reports cleanup uncertainty", func(t *testing.T) {
		directory := t.TempDir()
		source := pcv3SeedFaultSource(t, directory)
		target := filepath.Join(directory, "ambiguous.bin")
		recovery := filepath.Join(directory, "owned-bytes.recovery")
		payload := []byte("operation-owned committed bytes under an unproven atomic")
		foreignStage := []byte("foreign bytes at the remembered stage name")
		foreignTarget := []byte("foreign bytes at the target name")
		atomicCanary := "pcv3-fault-atomic-canary"
		operations, counts := pcv3NativeFaultOperations(t)
		operations.atomicPublish = func(parent *os.File, stageName, targetName string, policy Policy) error {
			counts.atomic++
			if err := nativeOperations().atomicPublish(parent, stageName, targetName, policy); err != nil {
				return err
			}
			if err := os.Rename(target, recovery); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(directory, stageName), foreignStage, 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(target, foreignTarget, 0o600); err != nil {
				return err
			}
			return errors.New(atomicCanary)
		}
		stage, err := createWithOperations(target, []string{source.path}, PolicyNoReplace, operations)
		if err != nil {
			t.Fatalf("create indeterminate stage: %v", err)
		}
		stagePath := stage.stagePath
		if _, err := stage.File().Write(payload); err != nil {
			stage.Cleanup()
			t.Fatalf("write indeterminate stage: %v", err)
		}

		result := stage.Publish(context.Background())
		requireResult(
			t,
			result,
			StatePublicationIndeterminate,
			pcv3result.OutcomePublicationIndeterminate,
			pcv3result.StageOutputPublication,
			CodePublicationIndeterminate,
		)
		if counts.atomic != 1 || counts.sync != 0 {
			t.Fatalf("indeterminate calls: atomic=%d sync=%d; want 1/0", counts.atomic, counts.sync)
		}
		if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
			t.Fatalf("indeterminate cleanup = %v; want ErrCleanupIncomplete", err)
		}
		requireFileBytes(t, recovery, payload)
		requireFileBytes(t, stagePath, foreignStage)
		requireFileBytes(t, target, foreignTarget)
		source.requireRetained(t)
		pcv3RequireNoDisclosure(t, result, atomicCanary, target, stagePath, recovery, string(payload))
	})

	t.Run("finalization failure with foreign occupation stays unproven and retains foreign bytes", func(t *testing.T) {
		directory := t.TempDir()
		source := pcv3SeedFaultSource(t, directory)
		target := filepath.Join(directory, "must-not-exist.bin")
		payload := []byte("staged bytes whose close report failed")
		foreign := []byte("foreign occupation at the failed stage name")
		closeCanary := "pcv3-fault-close-canary"
		operations, counts := pcv3NativeFaultOperations(t)
		operations.closeStage = func(file *os.File) error {
			if err := file.Close(); err != nil {
				t.Fatalf("close real stage before forced close report: %v", err)
			}
			return errors.New(closeCanary)
		}
		stage, err := createWithOperations(target, []string{source.path}, PolicyNoReplace, operations)
		if err != nil {
			t.Fatalf("create finalization stage: %v", err)
		}
		stagePath := stage.stagePath
		if _, err := stage.File().Write(payload); err != nil {
			stage.Cleanup()
			t.Fatalf("write finalization stage: %v", err)
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
		if counts.atomic != 0 || counts.sync != 0 {
			t.Fatalf("failed finalization reached commit = atomic %d sync %d", counts.atomic, counts.sync)
		}
		// Retain the original inode under another name so the foreign object
		// cannot accidentally reuse its identity after finalization closes it.
		escapedPath := filepath.Join(directory, "failed-owned-stage")
		if err := os.Rename(stagePath, escapedPath); err != nil {
			t.Fatalf("retain original stage before foreign occupation: %v", err)
		}
		if err := os.WriteFile(stagePath, foreign, 0o640); err != nil {
			t.Fatalf("plant foreign occupation: %v", err)
		}
		foreignInfo, err := os.Lstat(stagePath)
		if err != nil || os.SameFile(stage.stageInfo, foreignInfo) {
			t.Fatalf("foreign fixture did not establish distinct identity: %v", err)
		}
		if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
			t.Fatalf("cleanup foreign-occupied failed stage = %v; want ErrCleanupIncomplete", err)
		}
		if repeated := stage.Cleanup(); !errors.Is(repeated, ErrCleanupIncomplete) {
			t.Fatalf("repeated cleanup = %v; want stable ErrCleanupIncomplete", repeated)
		}
		requireFileBytes(t, stagePath, foreign)
		requireFileBytes(t, escapedPath, payload)
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed finalization created destination: %v", err)
		}
		source.requireRetained(t)
		pcv3RequireNoDisclosure(t, result, closeCanary, target, stagePath, string(payload))
	})

	t.Run("stage write bytes are published exactly with no extension or truncation", func(t *testing.T) {
		directory := t.TempDir()
		source := pcv3SeedFaultSource(t, directory)
		target := filepath.Join(directory, "exact.bin")
		payload := bytes.Repeat([]byte{0xa5, 0x3c, 0x00, 0x7e}, 4097)
		stage, err := Create(target, []string{source.path}, PolicyNoReplace)
		if err != nil {
			t.Fatalf("create exact stage: %v", err)
		}
		if count, err := stage.File().Write(payload); err != nil || count != len(payload) {
			stage.Cleanup()
			t.Fatalf("write exact stage = %d/%v; want %d/nil", count, err, len(payload))
		}
		stagedInfo, err := stage.File().Stat()
		if err != nil || stagedInfo.Size() != int64(len(payload)) {
			stage.Cleanup()
			t.Fatalf("staged size = %d, %v; want %d", stagedInfo.Size(), err, len(payload))
		}

		result := stage.Publish(context.Background())
		pcv3RequireNativeCommit(t, result)
		requireFileBytes(t, target, payload)
		if err := stage.Cleanup(); err != nil {
			t.Fatalf("cleanup exact commit: %v", err)
		}
		source.requireRetained(t)
	})
}
