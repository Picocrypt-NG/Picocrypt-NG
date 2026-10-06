package fileops

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUnpackCancellationLeavesNoPartialDestination(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "cancel.zip")
	replacement := []byte("replacement payload")
	createStoredZipForUnpackStagingTest(t, zipPath, "victim.txt", replacement)

	extractDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		t.Fatalf("Create extraction directory: %v", err)
	}
	victimPath := filepath.Join(extractDir, "victim.txt")

	cancelCalls := 0
	err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
		Cancel: func() bool {
			cancelCalls++
			return cancelCalls == 2
		},
	})
	if err == nil || err.Error() != "operation cancelled" {
		t.Fatalf("Unpack cancellation error = %v, want operation cancelled", err)
	}
	if _, err := os.Lstat(victimPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Partial destination exists after cancellation: %v", err)
	}
	requireEmptyExtractionDir(t, extractDir)
}

// TestUnpackCancellationAfterStagingPreventsPublication protects the final
// cancellation boundary: a signal delivered after plaintext staging and sync
// but before publication must remove every stage and publish no destination.
func TestUnpackCancellationAfterStagingPreventsPublication(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "cancel-before-publish.zip")
	createStoredZipForUnpackStagingTest(t, zipPath, "victim.txt", []byte("staged plaintext"))
	extractDir := filepath.Join(tmpDir, "out")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("create extraction directory: %v", err)
	}

	stageSyncEntered := make(chan struct{})
	releaseStageSync := make(chan struct{})
	originalStageSync := unpackStageSyncFn
	unpackStageSyncFn = func(file *os.File) error {
		close(stageSyncEntered)
		<-releaseStageSync
		return originalStageSync(file)
	}
	t.Cleanup(func() { unpackStageSyncFn = originalStageSync })

	var cancelled atomic.Bool
	resultReady := make(chan UnpackResult, 1)
	go func() {
		resultReady <- UnpackWithResult(UnpackOptions{
			ZipPath:    zipPath,
			ExtractDir: extractDir,
			Cancel:     cancelled.Load,
		})
	}()
	<-stageSyncEntered
	cancelled.Store(true)
	close(releaseStageSync)
	result := <-resultReady

	if result == nil || result.State() != UnpackStateNotPublished {
		t.Fatalf("post-stage cancellation result = %#v; want not-published", result)
	}
	cause := errors.Unwrap(result)
	if cause == nil || !strings.Contains(cause.Error(), "operation cancelled") {
		t.Fatalf("post-stage cancellation cause = %v; want operation cancelled", cause)
	}
	if _, err := os.Lstat(filepath.Join(extractDir, "victim.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-stage cancellation published destination: %v", err)
	}
	requireNoUnpackStages(t, extractDir)
	requireEmptyExtractionDir(t, extractDir)
}

func TestUnpackCorruptEntryLeavesNoPartialDestination(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "corrupt.zip")
	replacement := []byte("replacement payload with a deliberately invalid checksum")
	createStoredZipForUnpackStagingTest(t, zipPath, "victim.txt", replacement)
	corruptStoredZipPayload(t, zipPath, replacement)

	extractDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		t.Fatalf("Create extraction directory: %v", err)
	}
	victimPath := filepath.Join(extractDir, "victim.txt")

	err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "checksum") {
		t.Fatalf("Unpack corrupt-entry error = %v, want checksum error", err)
	}
	if _, err := os.Lstat(victimPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Partial destination exists after corrupt entry: %v", err)
	}
	requireEmptyExtractionDir(t, extractDir)
}

func TestUnpackCorruptNestedEntryRemovesOwnedDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "corrupt-nested.zip")
	payload := []byte("nested replacement with a deliberately invalid checksum")
	createStoredZipForUnpackStagingTest(t, zipPath, "nested/deeper/victim.txt", payload)
	corruptStoredZipPayload(t, zipPath, payload)

	extractDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		t.Fatalf("Create extraction directory: %v", err)
	}

	err := Unpack(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "checksum") {
		t.Fatalf("Unpack corrupt nested-entry error = %v, want checksum error", err)
	}
	if _, err := os.Lstat(filepath.Join(extractDir, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Operation-owned nested directories remain after failure: %v", err)
	}
	requireEmptyExtractionDir(t, extractDir)
}

func TestUnpackRollbackPreservesForeignFileAddedToOwnedDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "cancel-nested.zip")
	payload := bytes.Repeat([]byte("nested plaintext payload"), 128*1024)
	createStoredZipForUnpackStagingTest(t, zipPath, "nested/deeper/victim.txt", payload)

	extractDir := filepath.Join(tmpDir, "out")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("create extraction directory: %v", err)
	}
	foreignPath := filepath.Join(extractDir, "nested", "deeper", "foreign.txt")
	foreignBytes := []byte("concurrent foreign data must prevent directory rollback")
	foreignCreated := false

	err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
		Progress: func(float32, string) {
			if foreignCreated {
				return
			}
			if err := os.WriteFile(foreignPath, foreignBytes, 0o600); err != nil {
				t.Fatalf("write concurrent foreign file: %v", err)
			}
			foreignCreated = true
		},
		Cancel: func() bool {
			return foreignCreated
		},
	})
	if err == nil || !strings.Contains(err.Error(), "operation cancelled") {
		t.Fatalf("Unpack cancellation error = %v, want operation cancelled", err)
	}
	if !strings.Contains(err.Error(), "remove extraction directory") {
		t.Fatalf("Unpack hid the directory rollback failure: %v", err)
	}
	if !foreignCreated {
		t.Fatal("real extraction made no progress before cancellation")
	}
	gotForeign, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatalf("read preserved foreign file: %v", err)
	}
	if !bytes.Equal(gotForeign, foreignBytes) {
		t.Fatalf("foreign file = %q, want %q", gotForeign, foreignBytes)
	}
	if _, err := os.Lstat(filepath.Join(extractDir, "nested", "deeper", "victim.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled archive destination was published: %v", err)
	}
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		t.Fatalf("read extraction directory after cancellation: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-unpack-") {
			t.Fatalf("operation-owned stage remained after cancellation: %s", entry.Name())
		}
	}
}

func TestUnpackLaterCorruptEntryPublishesNoEarlierDestination(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "later-corrupt.zip")
	firstReplacement := []byte("complete first replacement")
	secondReplacement := []byte("second replacement with a deliberately invalid checksum")
	createStoredZipEntriesForUnpackStagingTest(t, zipPath, map[string][]byte{
		"first.txt":  firstReplacement,
		"second.txt": secondReplacement,
	})
	corruptStoredZipPayload(t, zipPath, secondReplacement)

	extractDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		t.Fatalf("Create extraction directory: %v", err)
	}
	firstPath := filepath.Join(extractDir, "first.txt")
	secondPath := filepath.Join(extractDir, "second.txt")

	err := Unpack(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "checksum") {
		t.Fatalf("Unpack later corrupt-entry error = %v, want checksum error", err)
	}
	if _, err := os.Lstat(firstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Earlier destination was published before later checksum failure: %v", err)
	}
	if _, err := os.Lstat(secondPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Corrupt destination was published: %v", err)
	}
	requireEmptyExtractionDir(t, extractDir)
}

func TestUnpackRefusesToReplaceExistingDestination(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "success.zip")
	replacement := []byte("complete replacement payload")
	createStoredZipForUnpackStagingTest(t, zipPath, "victim.txt", replacement)

	extractDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		t.Fatalf("Create extraction directory: %v", err)
	}
	victimPath := filepath.Join(extractDir, "victim.txt")
	original := []byte("old destination data")
	if err := os.WriteFile(victimPath, original, 0o600); err != nil {
		t.Fatalf("Create existing destination: %v", err)
	}

	err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("Unpack collision error = %v, want os.ErrExist", err)
	}

	got, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("Read preserved destination: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("Existing destination changed: got %q, want %q", got, original)
	}
	requireOnlyExtractionEntry(t, extractDir, "victim.txt")
}

func TestUnpackRefusesReplacementAtRandomStagePath(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "stage-race.zip")
	replacement := bytes.Repeat([]byte("archive payload"), 128*1024)
	createStoredZipForUnpackStagingTest(t, zipPath, "victim.txt", replacement)

	extractDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(extractDir, 0o700); err != nil {
		t.Fatalf("Create extraction directory: %v", err)
	}
	victimPath := filepath.Join(extractDir, "victim.txt")

	foreign := []byte("foreign file at random stage pathname")
	foreignPath := ""
	err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
		Progress: func(float32, string) {
			if foreignPath != "" {
				return
			}
			entries, err := os.ReadDir(extractDir)
			if err != nil {
				t.Fatalf("Read extraction directory during replacement: %v", err)
			}
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), ".picocrypt-unpack-") {
					continue
				}
				foreignPath = filepath.Join(extractDir, entry.Name())
				if err := os.Remove(foreignPath); err != nil {
					t.Skipf("platform prevents replacing an open unpack stage: %v", err)
				}
				if err := os.WriteFile(foreignPath, foreign, 0o640); err != nil {
					t.Fatalf("Write foreign stage replacement: %v", err)
				}
				return
			}
			t.Fatal("Unpack progress ran without an operation-owned stage")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "stage path changed") {
		t.Fatalf("Unpack error = %v, want changed-stage refusal", err)
	}
	if foreignPath == "" {
		t.Fatal("test did not replace the random unpack stage")
	}

	if _, err := os.Lstat(victimPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Destination was published after stage replacement: %v", err)
	}
	gotForeign, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatalf("Read foreign stage replacement: %v", err)
	}
	if !bytes.Equal(gotForeign, foreign) {
		t.Fatalf("foreign stage replacement = %q, want %q", gotForeign, foreign)
	}
}

func TestUnpackRejectsOrPreventsChangedExtractionDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "root-change.zip")
	payload := []byte("payload must not be published into either directory")
	createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)

	extractDir := filepath.Join(tmpDir, "out")
	movedDir := filepath.Join(tmpDir, "moved")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("Create extraction directory: %v", err)
	}
	foreign := []byte("new directory contents")
	var renameErr error
	err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
		AvailableSpace: func(string) (int64, error) {
			renameErr = os.Rename(extractDir, movedDir)
			if renameErr != nil {
				return 0, renameErr
			}
			if err := os.Mkdir(extractDir, 0o700); err != nil {
				t.Fatalf("Replace extraction directory: %v", err)
			}
			if err := os.WriteFile(filepath.Join(extractDir, "foreign.txt"), foreign, 0o600); err != nil {
				t.Fatalf("Write foreign replacement directory entry: %v", err)
			}
			return int64(len(payload)), nil
		},
	})
	if renameErr != nil {
		if !windowsPreventedOpenHandleRename(renameErr) {
			t.Fatalf("move extraction directory during preflight: %v", renameErr)
		}
		if err != nil {
			t.Fatalf("Unpack after the OS prevented root replacement: %v", err)
		}
		got, readErr := os.ReadFile(filepath.Join(extractDir, "payload.txt"))
		if readErr != nil {
			t.Fatalf("read payload after prevented root replacement: %v", readErr)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload after prevented root replacement = %q, want %q", got, payload)
		}
		if _, statErr := os.Lstat(movedDir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("blocked replacement still created the moved root: %v", statErr)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "extraction directory changed") {
		t.Fatalf("Unpack changed-root error = %v, want explicit refusal", err)
	}
	if _, err := os.Lstat(filepath.Join(movedDir, "payload.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Payload was published into moved original directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(extractDir, "payload.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Payload was published into replacement directory: %v", err)
	}
	gotForeign, err := os.ReadFile(filepath.Join(extractDir, "foreign.txt"))
	if err != nil {
		t.Fatalf("Read replacement directory contents: %v", err)
	}
	if !bytes.Equal(gotForeign, foreign) {
		t.Fatalf("Replacement directory contents changed: got %q, want %q", gotForeign, foreign)
	}
	requireEmptyExtractionDir(t, movedDir)
}

func TestUnpackExpectedRootRejectsOrdinaryDirectoryReplacement(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "expected-root.zip")
	payload := []byte("plaintext must not enter a replacement root")
	createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)

	extractDir := filepath.Join(tmpDir, "out")
	movedDir := filepath.Join(tmpDir, "moved")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("create expected extraction root: %v", err)
	}
	expectedRoot, err := os.OpenRoot(extractDir)
	if err != nil {
		t.Fatalf("open expected extraction root: %v", err)
	}
	expected, err := expectedRoot.Stat(".")
	if err != nil {
		_ = expectedRoot.Close()
		t.Fatalf("inspect expected extraction root: %v", err)
	}
	if err := expectedRoot.Close(); err != nil {
		t.Fatalf("close expected extraction root: %v", err)
	}
	if err := os.Rename(extractDir, movedDir); err != nil {
		t.Fatalf("move expected extraction root: %v", err)
	}
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("create replacement extraction root: %v", err)
	}

	err = Unpack(UnpackOptions{
		ZipPath:             zipPath,
		ExtractDir:          extractDir,
		ExpectedExtractRoot: expected,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Unpack replacement-root error = %v, want identity mismatch", err)
	}
	requireEmptyExtractionDir(t, extractDir)
	requireEmptyExtractionDir(t, movedDir)
}

func TestUnpackExpectedRootDoesNotRecreateMissingDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "missing-root.zip")
	createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", []byte("plaintext"))

	extractDir := filepath.Join(tmpDir, "out")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("create expected extraction root: %v", err)
	}
	expected, err := os.Lstat(extractDir)
	if err != nil {
		t.Fatalf("inspect expected extraction root: %v", err)
	}
	if err := os.Remove(extractDir); err != nil {
		t.Fatalf("remove expected extraction root: %v", err)
	}

	err = Unpack(UnpackOptions{
		ZipPath:             zipPath,
		ExtractDir:          extractDir,
		ExpectedExtractRoot: expected,
	})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("Unpack missing-root error = %v, want no-create refusal", err)
	}
	if _, err := os.Lstat(extractDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Unpack recreated the missing expected root: %v", err)
	}
}

func TestUnpackPublishesThroughExclusiveCopyWhenHardLinksUnsupported(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "fallback.zip")
	payload := bytes.Repeat([]byte("fallback payload"), 1024)
	createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)
	extractDir := filepath.Join(tmpDir, "out")

	originalLink := unpackLinkFn
	unpackLinkFn = func(*os.Root, string, string) error {
		return errors.ErrUnsupported
	}
	t.Cleanup(func() {
		unpackLinkFn = originalLink
	})

	if err := Unpack(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir}); err != nil {
		t.Fatalf("Unpack through exclusive-copy fallback: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(extractDir, "payload.txt"))
	if err != nil {
		t.Fatalf("Read fallback output: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fallback output content mismatch")
	}
	requireOnlyExtractionEntry(t, extractDir, "payload.txt")
}

func TestUnpackDoesNotPublishAStageThatCouldNotBeSynced(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "stage-sync-failure.zip")
	payload := bytes.Repeat([]byte("plaintext"), 1024)
	createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)
	extractDir := filepath.Join(tmpDir, "out")
	syncFailure := errors.New("injected staged plaintext sync failure")

	originalSync := unpackStageSyncFn
	unpackStageSyncFn = func(*os.File) error {
		return syncFailure
	}
	t.Cleanup(func() {
		unpackStageSyncFn = originalSync
	})

	err := Unpack(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
	if !errors.Is(err, syncFailure) {
		t.Fatalf("Unpack sync error = %v, want injected failure", err)
	}
	if _, err := os.Lstat(filepath.Join(extractDir, "payload.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Unsynced plaintext was published: %v", err)
	}
	requireEmptyExtractionDir(t, extractDir)
}

func TestUnpackExclusiveCopyFallbackReportsRollbackFailure(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "fallback-rollback-failure.zip")
	payload := bytes.Repeat([]byte("archive payload"), 1024)
	createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)
	extractDir := filepath.Join(tmpDir, "out")
	copyFailure := errors.New("injected fallback copy failure")
	removeFailure := errors.New("injected fallback rollback failure")

	originalLink := unpackLinkFn
	originalCopy := unpackCopyFn
	originalRemove := unpackRemoveOwnedFn
	unpackLinkFn = func(*os.Root, string, string) error {
		return errors.ErrUnsupported
	}
	unpackCopyFn = func(dst io.Writer, src io.Reader) (int64, error) {
		n, err := io.CopyN(dst, src, 1)
		if err != nil {
			return n, err
		}
		return n, copyFailure
	}
	unpackRemoveOwnedFn = func(owned ownedUnpackFile, root *os.Root) error {
		if _, err := root.Lstat(owned.targetName); err != nil {
			t.Fatalf("Fallback target was not really created before rollback: %v", err)
		}
		return removeFailure
	}
	t.Cleanup(func() {
		unpackLinkFn = originalLink
		unpackCopyFn = originalCopy
		unpackRemoveOwnedFn = originalRemove
	})

	err := Unpack(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
	if !errors.Is(err, copyFailure) {
		t.Fatalf("Unpack error = %v, want original copy failure", err)
	}
	if !errors.Is(err, removeFailure) {
		t.Fatalf("Unpack error = %v, want rollback failure to remain visible", err)
	}
	got, readErr := os.ReadFile(filepath.Join(extractDir, "payload.txt"))
	if readErr != nil {
		t.Fatalf("Read retained fallback output: %v", readErr)
	}
	if !bytes.Equal(got, payload[:1]) {
		t.Fatalf("Retained fallback output = %q, want one copied byte", got)
	}
	requireOnlyExtractionEntry(t, extractDir, "payload.txt")
}

func TestUnpackExclusiveCopyFallbackPreservesLateCollision(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "fallback-collision.zip")
	payload := bytes.Repeat([]byte("archive payload"), 128*1024)
	createStoredZipForUnpackStagingTest(t, zipPath, "victim.txt", payload)
	extractDir := filepath.Join(tmpDir, "out")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("Create extraction directory: %v", err)
	}

	originalLink := unpackLinkFn
	unpackLinkFn = func(*os.Root, string, string) error {
		return errors.ErrUnsupported
	}
	t.Cleanup(func() {
		unpackLinkFn = originalLink
	})

	victimPath := filepath.Join(extractDir, "victim.txt")
	foreign := []byte("late destination must survive")
	createdCollision := false
	err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
		Progress: func(float32, string) {
			if createdCollision {
				return
			}
			createdCollision = true
			if err := os.WriteFile(victimPath, foreign, 0o600); err != nil {
				t.Fatalf("Create late destination collision: %v", err)
			}
		},
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("Unpack late-collision error = %v, want os.ErrExist", err)
	}
	if !createdCollision {
		t.Fatal("test did not create the late destination collision")
	}
	got, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("Read late destination: %v", err)
	}
	if !bytes.Equal(got, foreign) {
		t.Fatalf("Late destination changed: got %q, want %q", got, foreign)
	}
	requireOnlyExtractionEntry(t, extractDir, "victim.txt")
}

func TestUnpackResultClassifiesPublicationTruth(t *testing.T) {
	t.Run("missing extraction root is not created or published", func(t *testing.T) {
		tmpDir := t.TempDir()
		zipPath := filepath.Join(tmpDir, "missing-root.zip")
		payload := []byte("must not be published without a pinned extraction root")
		createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)
		extractDir := filepath.Join(tmpDir, "missing")

		result := UnpackWithResult(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
		requireUnpackState(t, result, UnpackStateNotPublished)
		if _, err := os.Lstat(extractDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("typed extraction created an unpinned root: %v", err)
		}
	})

	t.Run("published durable after unique containing directories sync bottom-up", func(t *testing.T) {
		extractDir := filepath.Join(t.TempDir(), "out")
		if err := os.Mkdir(extractDir, 0o700); err != nil {
			t.Fatalf("create pinned extraction root: %v", err)
		}
		archivePath := filepath.Join(
			"..",
			"pcv3operation",
			"internal",
			"pcv3",
			"testdata",
			"normal",
			"plaintext",
			"normal-standard-combined-ordered-archive-small.zip",
		)
		if _, err := os.Stat(archivePath); err != nil {
			t.Fatalf("required archive fixture unavailable: %v", err)
		}
		var synced []string
		originalSyncDirectory := unpackDirectorySyncFn
		unpackDirectorySyncFn = func(directory *os.File) error {
			info, err := directory.Stat()
			if err != nil {
				t.Fatalf("stat synced directory: %v", err)
			}
			docsInfo, docsErr := os.Stat(filepath.Join(extractDir, "docs"))
			rootInfo, rootErr := os.Stat(extractDir)
			switch {
			case docsErr == nil && os.SameFile(info, docsInfo):
				synced = append(synced, "docs")
			case rootErr == nil && os.SameFile(info, rootInfo):
				synced = append(synced, ".")
			default:
				t.Fatalf("unexpected directory identity reached durability sync: %v", info)
			}
			return directory.Sync()
		}
		t.Cleanup(func() {
			unpackDirectorySyncFn = originalSyncDirectory
		})

		result := UnpackWithResult(UnpackOptions{ZipPath: archivePath, ExtractDir: extractDir})
		requireUnpackState(t, result, UnpackStatePublishedDurable)
		if errors.Is(result, ErrUnpackCleanupIncomplete) {
			t.Fatalf("durable extraction reported cleanup uncertainty: %v", result)
		}
		if !slices.Equal(synced, []string{"docs", "."}) {
			t.Fatalf("synced directories = %q; want bottom-up unique [docs .]", synced)
		}
		requireUnpackFileBytes(t, filepath.Join(extractDir, "root.txt"), []byte("PCV3 authenticated archive fixture\n"))
		requireUnpackFileBytes(
			t,
			filepath.Join(extractDir, "docs", "readme.txt"),
			[]byte("Extraction is admitted only after whole-volume authentication.\n"),
		)
		requireNoUnpackStages(t, extractDir)
	})

	t.Run("late second entry collision rolls back to proven not published", func(t *testing.T) {
		tmpDir := t.TempDir()
		zipPath := filepath.Join(tmpDir, "late-collision.zip")
		firstBytes := []byte("first operation-owned plaintext")
		foreignBytes := []byte("late foreign second destination")
		createStoredZipEntriesForUnpackStagingTest(t, zipPath, map[string][]byte{
			"first.txt":  firstBytes,
			"second.txt": []byte("second operation-owned plaintext"),
		})
		extractDir := filepath.Join(tmpDir, "out")
		if err := os.Mkdir(extractDir, 0o700); err != nil {
			t.Fatalf("create extraction root: %v", err)
		}
		collisionPath := filepath.Join(extractDir, "second.txt")
		collisionCreated := false
		originalSyncDirectory := unpackDirectorySyncFn
		unpackDirectorySyncFn = func(*os.File) error {
			t.Fatal("rollback case attempted directory durability sync")
			return nil
		}
		t.Cleanup(func() {
			unpackDirectorySyncFn = originalSyncDirectory
		})

		result := UnpackWithResult(UnpackOptions{
			ZipPath:    zipPath,
			ExtractDir: extractDir,
			Progress: func(float32, string) {
				if collisionCreated {
					return
				}
				if err := os.WriteFile(collisionPath, foreignBytes, 0o640); err != nil {
					t.Fatalf("create late second-entry collision: %v", err)
				}
				collisionCreated = true
			},
		})
		requireUnpackState(t, result, UnpackStateNotPublished)
		if !errors.Is(result, os.ErrExist) {
			t.Fatalf("late collision result = %v; want os.ErrExist", result)
		}
		if errors.Is(result, ErrUnpackCleanupIncomplete) {
			t.Fatalf("successful rollback reported cleanup uncertainty: %v", result)
		}
		if !collisionCreated {
			t.Fatal("test did not create the late second-entry collision")
		}
		if _, err := os.Lstat(filepath.Join(extractDir, "first.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("first published output survived rollback: %v", err)
		}
		requireUnpackFileBytes(t, collisionPath, foreignBytes)
		requireNoUnpackStages(t, extractDir)
		requireOnlyExtractionEntry(t, extractDir, "second.txt")
	})

	t.Run("unproven partial-output rollback is publication indeterminate", func(t *testing.T) {
		tmpDir := t.TempDir()
		zipPath := filepath.Join(tmpDir, "rollback-failure.zip")
		payload := []byte("archive plaintext")
		createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)
		extractDir := filepath.Join(tmpDir, "out")
		if err := os.Mkdir(extractDir, 0o700); err != nil {
			t.Fatalf("create pinned extraction root: %v", err)
		}
		copyFailure := errors.New("TEST ONLY typed copy failure")
		removeFailure := errors.New("TEST ONLY typed rollback failure")

		originalLink := unpackLinkFn
		originalCopy := unpackCopyFn
		originalRemove := unpackRemoveOwnedFn
		unpackLinkFn = func(*os.Root, string, string) error { return errors.ErrUnsupported }
		unpackCopyFn = func(destination io.Writer, source io.Reader) (int64, error) {
			written, err := io.CopyN(destination, source, 1)
			if err != nil {
				return written, err
			}
			return written, copyFailure
		}
		unpackRemoveOwnedFn = func(owned ownedUnpackFile, root *os.Root) error {
			if _, err := root.Lstat(owned.targetName); err != nil {
				t.Fatalf("partial output was not created before rollback: %v", err)
			}
			return removeFailure
		}
		t.Cleanup(func() {
			unpackLinkFn = originalLink
			unpackCopyFn = originalCopy
			unpackRemoveOwnedFn = originalRemove
		})

		result := UnpackWithResult(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
		requireUnpackState(t, result, UnpackStatePublicationIndeterminate)
		if !errors.Is(result, copyFailure) || !errors.Is(result, removeFailure) {
			t.Fatalf("indeterminate result lost primary/rollback errors: %v", result)
		}
		if !errors.Is(result, ErrUnpackCleanupIncomplete) {
			t.Fatalf("indeterminate result hid cleanup uncertainty: %v", result)
		}
		requireUnpackFileBytes(t, filepath.Join(extractDir, "payload.txt"), payload[:1])
		requireNoUnpackStages(t, extractDir)
		requireOnlyExtractionEntry(t, extractDir, "payload.txt")
	})

	t.Run("post-publication directory sync failure is durability uncertain", func(t *testing.T) {
		tmpDir := t.TempDir()
		zipPath := filepath.Join(tmpDir, "sync-failure.zip")
		payload := []byte("fully published plaintext")
		createStoredZipForUnpackStagingTest(t, zipPath, "nested/payload.txt", payload)
		extractDir := filepath.Join(tmpDir, "out")
		if err := os.Mkdir(extractDir, 0o700); err != nil {
			t.Fatalf("create pinned extraction root: %v", err)
		}
		syncFailure := errors.New("TEST ONLY containing-directory sync failure")
		originalSyncDirectory := unpackDirectorySyncFn
		unpackDirectorySyncFn = func(*os.File) error { return syncFailure }
		t.Cleanup(func() {
			unpackDirectorySyncFn = originalSyncDirectory
		})

		result := UnpackWithResult(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
		requireUnpackState(t, result, UnpackStatePublishedDurabilityUncertain)
		if !errors.Is(result, syncFailure) {
			t.Fatalf("durability-uncertain result lost sync failure: %v", result)
		}
		if errors.Is(result, ErrUnpackCleanupIncomplete) {
			t.Fatalf("directory sync failure was mislabeled cleanup uncertainty: %v", result)
		}
		requireUnpackFileBytes(t, filepath.Join(extractDir, "nested", "payload.txt"), payload)
		requireNoUnpackStages(t, extractDir)
	})

	t.Run("post-publication root close warning preserves durable truth", func(t *testing.T) {
		tmpDir := t.TempDir()
		zipPath := filepath.Join(tmpDir, "root-close-failure.zip")
		payload := []byte("durable output survives handle cleanup warning")
		createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)
		extractDir := filepath.Join(tmpDir, "out")
		if err := os.Mkdir(extractDir, 0o700); err != nil {
			t.Fatalf("create pinned extraction root: %v", err)
		}
		closeFailure := errors.New("TEST ONLY extraction-root close failure")
		originalCloseRoot := unpackCloseRootFn
		unpackCloseRootFn = func(root *os.Root) error {
			if err := root.Close(); err != nil {
				return err
			}
			return closeFailure
		}
		t.Cleanup(func() {
			unpackCloseRootFn = originalCloseRoot
		})

		result := UnpackWithResult(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir})
		requireUnpackState(t, result, UnpackStatePublishedDurable)
		if !errors.Is(result, closeFailure) || !errors.Is(result, ErrUnpackCleanupIncomplete) {
			t.Fatalf("durable result lost root-close cleanup warning: %v", result)
		}
		requireUnpackFileBytes(t, filepath.Join(extractDir, "payload.txt"), payload)
		requireNoUnpackStages(t, extractDir)
	})

	t.Run("legacy compatibility does not request directory durability", func(t *testing.T) {
		tmpDir := t.TempDir()
		zipPath := filepath.Join(tmpDir, "legacy.zip")
		payload := []byte("legacy extraction payload")
		createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", payload)
		extractDir := filepath.Join(tmpDir, "out")
		originalSyncDirectory := unpackDirectorySyncFn
		unpackDirectorySyncFn = func(*os.File) error {
			t.Fatal("legacy Unpack requested new directory durability behavior")
			return nil
		}
		t.Cleanup(func() {
			unpackDirectorySyncFn = originalSyncDirectory
		})

		if err := Unpack(UnpackOptions{ZipPath: zipPath, ExtractDir: extractDir}); err != nil {
			t.Fatalf("legacy Unpack gained a user-visible durability failure: %v", err)
		}
		requireUnpackFileBytes(t, filepath.Join(extractDir, "payload.txt"), payload)
		requireNoUnpackStages(t, extractDir)
	})
}

func requireUnpackState(t *testing.T, result UnpackResult, want UnpackState) {
	t.Helper()
	if result == nil {
		t.Fatal("typed unpack returned nil result")
	}
	if got := result.State(); got != want {
		t.Fatalf("typed unpack state = %s; want %s (result: %v)", got, want, result)
	}
}

func requireUnpackFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read unpack output %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unpack output %s = %q; want %q", path, got, want)
	}
}

func requireNoUnpackStages(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.HasPrefix(entry.Name(), ".picocrypt-unpack-") {
			t.Fatalf("operation-owned unpack stage remained at %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect extraction tree for retained stages: %v", err)
	}
}

func createStoredZipForUnpackStagingTest(t *testing.T, zipPath, name string, data []byte) {
	t.Helper()

	createStoredZipEntriesForUnpackStagingTest(t, zipPath, map[string][]byte{name: data})
}

func createStoredZipEntriesForUnpackStagingTest(t *testing.T, zipPath string, entries map[string][]byte) {
	t.Helper()

	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create ZIP archive: %v", err)
	}
	writer := zip.NewWriter(file)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		entry, createErr := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if createErr != nil {
			t.Fatalf("Create ZIP entry %q: %v", name, createErr)
		}
		if _, writeErr := entry.Write(entries[name]); writeErr != nil {
			t.Fatalf("Write ZIP entry %q: %v", name, writeErr)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close ZIP writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close ZIP archive: %v", err)
	}
}

func corruptStoredZipPayload(t *testing.T, zipPath string, payload []byte) {
	t.Helper()

	archive, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("Read ZIP archive for corruption: %v", err)
	}
	offset := bytes.Index(archive, payload)
	if offset < 0 {
		t.Fatal("Stored ZIP payload not found in archive")
	}
	if bytes.Contains(archive[offset+len(payload):], payload) {
		t.Fatal("Stored ZIP payload appears more than once in archive")
	}
	archive[offset+len(payload)/2] ^= 0xff
	if err := os.WriteFile(zipPath, archive, 0o600); err != nil {
		t.Fatalf("Write corrupted ZIP archive: %v", err)
	}
}

func requireOnlyExtractionEntry(t *testing.T, extractDir, wantName string) {
	t.Helper()

	entries, err := os.ReadDir(extractDir)
	if err != nil {
		t.Fatalf("Read extraction directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != wantName {
		t.Fatalf("Extraction directory entries = %v, want only %q", entries, wantName)
	}
}

func requireEmptyExtractionDir(t *testing.T, extractDir string) {
	t.Helper()

	entries, err := os.ReadDir(extractDir)
	if err != nil {
		t.Fatalf("Read extraction directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("Extraction directory entries = %v, want none", entries)
	}
}
