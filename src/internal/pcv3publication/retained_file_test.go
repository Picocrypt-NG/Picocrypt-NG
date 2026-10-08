package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitRetainedConsumesExactSourceAfterDurableChunks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "encrypted.pcv")
	payload := []byte(strings.Repeat("authenticated encrypted bytes", 100))
	retained := publishRetainedTestFile(t, target, payload)

	decoy := filepath.Join(directory, "caller-selected.bin")
	decoyBytes := []byte("caller input path must not redirect retained authority")
	if err := os.WriteFile(decoy, decoyBytes, 0o600); err != nil {
		t.Fatalf("create caller-selected decoy: %v", err)
	}
	decoyInfo, err := os.Stat(decoy)
	if err != nil {
		t.Fatalf("stat caller-selected decoy: %v", err)
	}

	// This custody test uses the retained owner's injected successful barrier;
	// native Windows directory-durability refusal has its own contract test.
	completion, err := SplitRetainedWithResult(retained, fileops.SplitOptions{
		InputPath:     decoy,
		ExpectedInput: decoyInfo,
		ChunkSize:     1,
		Unit:          fileops.SplitUnitKiB,
	})
	if err != nil || completion != fileops.SplitCompleteDurable {
		t.Fatalf("split retained file: state=%v err=%v", completion, err)
	}
	if retained.Live() {
		t.Fatal("successful split left retained authority live")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful split left full retained source: %v", err)
	}
	requireFileBytes(t, decoy, decoyBytes)

	recombined := filepath.Join(directory, "recombined.pcv")
	if err := fileops.Recombine(fileops.RecombineOptions{
		InputBase:  target,
		OutputPath: recombined,
	}); err != nil {
		t.Fatalf("recombine retained chunks: %v", err)
	}
	requireFileBytes(t, recombined, payload)
}

func TestSplitRetainedFailurePreservesFullSourceAndConsumesAuthority(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "encrypted.pcv")
	payload := []byte(strings.Repeat("recoverable encrypted bytes", 100))
	retained := publishRetainedTestFile(t, target, payload)
	occupied := target + ".0"
	foreign := []byte("pre-existing chunk must survive")
	if err := os.WriteFile(occupied, foreign, 0o640); err != nil {
		t.Fatalf("create occupied chunk: %v", err)
	}

	_, err := SplitRetainedWithResult(retained, fileops.SplitOptions{
		ChunkSize: 1,
		Unit:      fileops.SplitUnitKiB,
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("occupied retained split = %v; want os.ErrExist", err)
	}
	if retained.Live() {
		t.Fatal("failed split left retained authority live")
	}
	requireFileBytes(t, target, payload)
	requireFileBytes(t, occupied, foreign)

	destination, err := os.OpenFile(
		filepath.Join(directory, "unavailable-copy.bin"),
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		0o600,
	)
	if err != nil {
		t.Fatalf("create post-consumption destination: %v", err)
	}
	copyResult := retained.CopyTo(destination)
	if copyResult.Copied() || copyResult.CleanupIncomplete() {
		t.Fatalf(
			"post-consumption copy = copied=%v cleanup=%v; want refused/clean",
			copyResult.Copied(), copyResult.CleanupIncomplete(),
		)
	}
	if _, err := destination.Stat(); err == nil {
		t.Fatal("post-consumption CopyTo left destination handle open")
	}
}

func TestSplitRetainedNeverRemovesSourceReplacement(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "encrypted.pcv")
	moved := filepath.Join(directory, "moved-owned-source.pcv")
	payload := []byte(strings.Repeat("identity-bound encrypted bytes", 100))
	foreign := []byte("foreign replacement must survive")
	retained := publishRetainedTestFile(t, target, payload)
	replaced := false

	_, err := SplitRetainedWithResult(retained, fileops.SplitOptions{
		ChunkSize: 1,
		Unit:      fileops.SplitUnitKiB,
		Progress: func(_ float32, info string) {
			if replaced || info != "3/3" {
				return
			}
			if err := os.Rename(target, moved); err != nil {
				t.Fatalf("move exact retained source: %v", err)
			}
			if err := os.WriteFile(target, foreign, 0o640); err != nil {
				t.Fatalf("install foreign source replacement: %v", err)
			}
			replaced = true
		},
	})
	if err == nil {
		t.Fatal("split accepted a replacement for its exact retained source")
	}
	if !replaced {
		t.Fatal("test did not replace the retained source")
	}
	if retained.Live() {
		t.Fatal("source replacement left retained authority live")
	}
	requireFileBytes(t, target, foreign)
	requireFileBytes(t, moved, payload)

	if chunks, err := filepath.Glob(target + ".*"); err != nil || len(chunks) != 0 {
		t.Fatalf("identity-refused split retained chunks: %v, %v", chunks, err)
	}
}

func TestSplitRetainedRejectsContentChangedAfterPrepublicationDigest(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "encrypted.pcv")
	payload := []byte(strings.Repeat("prepublication digest binding", 100))
	retained := publishRetainedTestFile(t, target, payload)

	mutated := append([]byte(nil), payload...)
	mutated[len(mutated)/2] ^= 0xff
	if err := os.WriteFile(target, mutated, 0o600); err != nil {
		t.Fatalf("mutate retained source in place: %v", err)
	}
	_, err := SplitRetainedWithResult(retained, fileops.SplitOptions{
		ChunkSize: 1,
		Unit:      fileops.SplitUnitKiB,
	})
	if err == nil {
		t.Fatal("split accepted content changed after its prepublication digest")
	}
	if retained.Live() {
		t.Fatal("rejected split left retained authority live")
	}
	requireFileBytes(t, target, mutated)
	if matches, globErr := filepath.Glob(target + ".*"); globErr != nil || len(matches) != 0 {
		t.Fatalf("rejected split left chunks: %v err=%v", matches, globErr)
	}
}

func TestPublishRetainedGrantsOnlyExactDurableIdentity(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	payload := []byte("authenticated plaintext retained by the Go owner")
	stage, err := createRetainedTestStage(t, target, payload)
	if err != nil {
		t.Fatalf("create retained publication stage: %v", err)
	}

	publication, retained := stage.PublishRetained(context.Background())
	if publication == nil || publication.State() != StatePublishedDurable || retained == nil ||
		!retained.Live() {
		t.Fatalf(
			"retained publication = %v capability=%v live=%v; want durable live exact owner",
			publication, retained, retained != nil && retained.Live(),
		)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("transferred stage cleanup = %v; want no second owner", err)
	}
	repeatedPublication, repeatedRetained := stage.PublishRetained(context.Background())
	if repeatedPublication == nil ||
		repeatedPublication.State() != StatePublishedDurable || repeatedRetained != nil {
		t.Fatalf(
			"repeated retained publication = %v capability=%v; want durable truth without second owner",
			repeatedPublication, repeatedRetained,
		)
	}
	requireFileBytes(t, target, payload)

	destinationPath := filepath.Join(directory, "saved.bin")
	destination, err := os.OpenFile(
		destinationPath,
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		0o600,
	)
	if err != nil {
		t.Fatalf("create owned destination: %v", err)
	}
	copyResult := retained.CopyTo(destination)
	if !copyResult.Copied() || copyResult.CleanupIncomplete() {
		t.Fatalf("copy result = copied=%v cleanup=%v; want copied/clean", copyResult.Copied(), copyResult.CleanupIncomplete())
	}
	if _, err := destination.Stat(); err == nil {
		t.Fatal("CopyTo returned with the transferred destination open")
	}
	requireFileBytes(t, destinationPath, payload)
	requireFileBytes(t, target, payload)
	if !retained.Live() {
		t.Fatal("transport copy consumed the retained source before exact discard")
	}

	if err := retained.RemoveExact(); err != nil {
		t.Fatalf("remove exact retained source: %v", err)
	}
	if retained.Live() {
		t.Fatal("exact removal left retained authority live")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact retained target still exists: %v", err)
	}
	requireFileBytes(t, destinationPath, payload)
}

func TestRetainedFileCopyFailureKeepsSource(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	payload := []byte("source remains available after destination refusal")
	retained := publishRetainedTestFile(t, target, payload)

	destinationPath := filepath.Join(directory, "read-only-destination.bin")
	if err := os.WriteFile(destinationPath, nil, 0o600); err != nil {
		t.Fatalf("seed destination: %v", err)
	}
	destination, err := os.Open(destinationPath)
	if err != nil {
		t.Fatalf("open read-only destination: %v", err)
	}
	copyResult := retained.CopyTo(destination)
	if copyResult.Copied() || copyResult.CleanupIncomplete() {
		t.Fatalf(
			"read-only copy = copied=%v cleanup=%v; want refused with no plaintext residue",
			copyResult.Copied(), copyResult.CleanupIncomplete(),
		)
	}
	if _, err := destination.Stat(); err == nil {
		t.Fatal("failed CopyTo returned with the transferred destination open")
	}
	if !retained.Live() {
		t.Fatal("failed transport copy consumed the retained source")
	}
	requireFileBytes(t, target, payload)
	requireFileBytes(t, destinationPath, nil)

	if err := retained.RemoveExact(); err != nil {
		t.Fatalf("discard retained source after failed copy: %v", err)
	}
}

func TestRetainedFileCopyRefusesSameIdentityWithoutTruncation(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	alias := filepath.Join(directory, "caller-destination.bin")
	payload := []byte("same-file refusal must preserve every byte")
	retained := publishRetainedTestFile(t, target, payload)
	if err := os.Link(target, alias); err != nil {
		_ = retained.RemoveExact()
		t.Skipf("filesystem does not permit a test hardlink: %v", err)
	}
	destination, err := os.OpenFile(alias, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open same-identity destination: %v", err)
	}
	copyResult := retained.CopyTo(destination)
	if copyResult.Copied() || !copyResult.CleanupIncomplete() {
		t.Fatalf(
			"same-identity copy = copied=%v cleanup=%v; want refusal with alias uncertainty",
			copyResult.Copied(), copyResult.CleanupIncomplete(),
		)
	}
	requireFileBytes(t, target, payload)
	requireFileBytes(t, alias, payload)
	if !retained.Live() {
		t.Fatal("same-identity refusal consumed the retained source")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatalf("remove test hardlink: %v", err)
	}
	if err := retained.RemoveExact(); err != nil {
		t.Fatalf("remove retained source: %v", err)
	}
}

func TestRetainedFileRemoveRefusesReplacement(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	moved := filepath.Join(directory, "moved-owned-output.bin")
	payload := []byte("owned bytes moved outside the retained name")
	foreign := []byte("foreign replacement must survive")
	retained := publishRetainedTestFile(t, target, payload)
	if err := os.Rename(target, moved); err != nil {
		t.Fatalf("move exact retained target: %v", err)
	}
	if err := os.WriteFile(target, foreign, 0o640); err != nil {
		t.Fatalf("write foreign replacement: %v", err)
	}

	err := retained.RemoveExact()
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("replacement-safe removal = %v; want ErrCleanupIncomplete", err)
	}
	if retained.Live() {
		t.Fatal("identity loss left a deletion capability live")
	}
	requireFileBytes(t, target, foreign)
	requireFileBytes(t, moved, payload)
	formatted := fmt.Sprintf("%v|%+v|%q", err, err, err)
	if strings.Contains(formatted, directory) {
		t.Fatalf("retained cleanup diagnostic disclosed a path: %q", formatted)
	}
}

func TestRetainedFileReportsPostRemoveDirectorySyncUncertainty(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	operations, _ := realRenameOperations(t, directory)
	syncCalls := 0
	operations.syncDirectory = func(parent *os.File) error {
		syncCalls++
		if syncCalls == 1 {
			return classifierTestDirectorySync(parent)
		}
		return errors.New("TEST ONLY post-remove directory sync failure")
	}
	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatalf("create retained stage: %v", err)
	}
	if _, err := stage.File().Write([]byte("durable before removal")); err != nil {
		_ = stage.Cleanup()
		t.Fatalf("write retained stage: %v", err)
	}
	publication, retained := stage.PublishRetained(context.Background())
	if publication == nil || publication.State() != StatePublishedDurable || retained == nil {
		_ = stage.Cleanup()
		t.Fatalf("retained publication = %v/%v; want durable capability", publication, retained)
	}

	err = retained.RemoveExact()
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("post-remove sync result = %v; want ErrCleanupIncomplete", err)
	}
	if syncCalls != 2 {
		t.Fatalf("directory sync calls = %d; want publication plus removal", syncCalls)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-remove sync failure left target name: %v", err)
	}
	if retained.Live() {
		t.Fatal("post-remove sync uncertainty left removal authority live")
	}
}

func TestPublishRetainedNeverGrantsForUncertainOrIndeterminate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*platformOperations)
		wantState State
	}{
		{
			name: "directory durability uncertain",
			mutate: func(operations *platformOperations) {
				operations.syncDirectory = func(*os.File) error {
					return errors.New("TEST ONLY directory sync failure")
				}
			},
			wantState: StatePublishedDurabilityUncertain,
		},
		{
			name: "atomic outcome indeterminate",
			mutate: func(operations *platformOperations) {
				operations.atomicPublish = func(*os.File, string, string, Policy) error {
					return nil
				}
			},
			wantState: StatePublicationIndeterminate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "private-output.bin")
			operations, _ := realRenameOperations(t, directory)
			test.mutate(&operations)
			stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
			if err != nil {
				t.Fatalf("create stage: %v", err)
			}
			if _, err := stage.File().Write([]byte("complete output")); err != nil {
				_ = stage.Cleanup()
				t.Fatalf("write stage: %v", err)
			}

			publication, retained := stage.PublishRetained(context.Background())
			if publication == nil || publication.State() != test.wantState || retained != nil {
				t.Fatalf(
					"non-durable publication = %v retained=%v; want %v and no authority",
					publication, retained, test.wantState,
				)
			}
			_ = stage.Cleanup()
		})
	}
}

func TestPublishRetainedCleansDurableTargetWhenExactOwnerCannotBeMinted(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	operations, _ := realRenameOperations(t, directory)
	operations.openRetained = func(*os.Root, string) (*os.File, error) {
		return nil, errors.New("TEST ONLY retained descriptor failure")
	}
	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	if _, err := stage.File().Write([]byte("must not be orphaned")); err != nil {
		_ = stage.Cleanup()
		t.Fatalf("write stage: %v", err)
	}

	publication, retained := stage.PublishRetained(context.Background())
	if publication == nil || publication.State() != StateNotPublished || retained != nil {
		t.Fatalf(
			"retained-owner failure = %v retained=%v; want proven no-output",
			publication, retained,
		)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("idempotent cleanup after retained-owner failure: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained-owner failure orphaned durable plaintext: %v", err)
	}
}

func TestPublishRetainedReportsIndeterminateWhenMintAndCleanupBothFail(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	operations, _ := realRenameOperations(t, directory)
	operations.openRetained = func(*os.Root, string) (*os.File, error) {
		return nil, errors.New("TEST ONLY retained descriptor failure")
	}
	operations.removeStage = func(*os.Root, string) error {
		return errors.New("TEST ONLY exact cleanup failure")
	}
	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	if _, err := stage.File().Write([]byte("cleanup state is uncertain")); err != nil {
		_ = stage.Cleanup()
		t.Fatalf("write stage: %v", err)
	}

	publication, retained := stage.PublishRetained(context.Background())
	if publication == nil || publication.State() != StatePublicationIndeterminate || retained != nil {
		t.Fatalf(
			"mint and cleanup failure = %v retained=%v; want indeterminate/no authority",
			publication, retained,
		)
	}
	if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("retained cleanup result = %v; want ErrCleanupIncomplete", err)
	}
	requireFileBytes(t, target, []byte("cleanup state is uncertain"))
}

func createRetainedTestStage(
	t *testing.T,
	target string,
	payload []byte,
) (*Stage, error) {
	t.Helper()
	operations, _ := realRenameOperations(t, filepath.Dir(target))
	stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
	if err != nil {
		return nil, err
	}
	if _, err := stage.File().Write(payload); err != nil {
		_ = stage.Cleanup()
		return nil, err
	}
	return stage, nil
}

func publishRetainedTestFile(t *testing.T, target string, payload []byte) *RetainedFile {
	t.Helper()
	stage, err := createRetainedTestStage(t, target, payload)
	if err != nil {
		t.Fatalf("create retained test stage: %v", err)
	}
	publication, retained := stage.PublishRetained(context.Background())
	if publication == nil || publication.State() != StatePublishedDurable || retained == nil {
		_ = stage.Cleanup()
		t.Fatalf("publish retained test file = %v/%v; want durable capability", publication, retained)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatalf("cleanup transferred stage: %v", err)
	}
	return retained
}

func TestSplitRetainedDirectoryBarrierFailurePreservesCompleteContainer(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "encrypted.pcv")
	payload := []byte(strings.Repeat("complete ciphertext retained until chunks are durable", 100))
	retained := publishRetainedTestFile(t, target, payload)
	closed := false
	_, err := SplitRetainedWithResult(retained, fileops.SplitOptions{
		ChunkSize: 1,
		Unit:      fileops.SplitUnitKiB,
		Progress: func(_ float32, _ string) {
			if !closed {
				// Invalidate the actual borrowed directory descriptor after split
				// preflight. Chunk writes still use the independent pinned root;
				// their final durability barrier must fail before source removal.
				if err := retained.parent.Close(); err != nil {
					t.Fatal(err)
				}
				closed = true
			}
		},
	})
	if !closed || err == nil {
		t.Fatalf("split with lost directory barrier returned %v (closed=%v)", err, closed)
	}
	if retained.Live() {
		t.Fatal("failed split retained follow-up authority")
	}
	requireFileBytes(t, target, payload)
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("failed split residue = %v/%v; want complete container only", entries, readErr)
	}
}

func TestSplitRetainedCompleteUncertaintyPreservesFullIdentityAndChunks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "encrypted.pcv")
	payload := []byte(strings.Repeat("complete uncertain encrypted bytes", 100))
	retained := publishRetainedTestFile(t, target, payload)
	original, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	file, parent, root := retained.file, retained.parent, retained.root
	calls := 0
	retained.syncDirectory = func(*os.File) error { calls++; return errors.ErrUnsupported }
	state, err := SplitRetainedWithResult(retained, fileops.SplitOptions{ChunkSize: 1, Unit: fileops.SplitUnitKiB})
	if err != nil || state != fileops.SplitCompleteDurabilityUncertain || calls != 1 {
		t.Fatalf("split completion = %v, %v; barrier calls=%d", state, err, calls)
	}
	if retained.Live() {
		t.Fatal("uncertain split left retained authority live")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("source handle not closed")
	}
	if _, err := parent.Stat(); err == nil {
		t.Fatal("parent handle not closed")
	}
	if _, err := root.Stat("."); err == nil {
		t.Fatal("root handle not closed")
	}
	current, err := os.Stat(target)
	if err != nil || !os.SameFile(original, current) {
		t.Fatalf("full ciphertext inode changed: %v", err)
	}
	requireFileBytes(t, target, payload)
	recombined := filepath.Join(directory, "recombined.pcv")
	if err := fileops.Recombine(fileops.RecombineOptions{InputBase: target, OutputPath: recombined}); err != nil {
		t.Fatal(err)
	}
	requireFileBytes(t, recombined, payload)
}

// Real pipe failure and pre-cancelled streaming must consume the same retained
// source as a successful stream, without publishing bytes after cancellation.
func TestRetainedStreamFailureAndCancellationConsumeSource(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "broken-pipe"
		if cancelled {
			name = "cancelled-before-stream"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "retained")
			retained := publishRetainedTestFile(t, path, []byte("owned plaintext must not survive failed streaming"))
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelled {
				cancel()
			} else if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			result := retained.StreamTo(ctx, writer)
			if result.Copied() || result.CleanupIncomplete() || retained.Live() {
				t.Fatalf("stream retained custody or reported success: copied=%v cleanup=%v live=%v", result.Copied(), result.CleanupIncomplete(), retained.Live())
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("failed stream retained internal plaintext: %v", err)
			}
			if cancelled {
				if count, err := writer.Write([]byte{0}); count != 0 || err == nil {
					t.Fatalf("cancelled stream left destination writable: count=%d err=%v", count, err)
				}
				var probe [1]byte
				count, err := reader.Read(probe[:])
				if count != 0 || err != io.EOF {
					t.Errorf("cancelled stream published bytes or left writer open: count=%d err=%v", count, err)
				}
			}
		})
	}
}
