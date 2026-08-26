package pcv3publication

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
			return parent.Sync()
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
