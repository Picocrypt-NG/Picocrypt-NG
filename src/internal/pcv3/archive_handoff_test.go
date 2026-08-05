package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const normalArchiveFixtureID = "normal-standard-combined-ordered-archive-small"

func TestAuthenticatedArchiveHandoffExtractsContainedPayload(t *testing.T) {
	fixture, archive, result, completion := readArchiveHandoffFixture(
		t,
		context.Background(),
		normalArchiveFixtureID,
	)
	if fixture.PayloadKind != "archive" {
		t.Fatalf("TEST ONLY payload kind = %q; want archive", fixture.PayloadKind)
	}
	if result.Outcome() != OutcomeSuccess || result.Stage() != StageNone {
		t.Fatalf("archive reader result = %v/%v; want success/none", result.Outcome(), result.Stage())
	}
	kind, authenticated := completion.authenticatedPayloadKind()
	if !authenticated || kind != PayloadKindArchive {
		t.Fatalf("archive completion = %v/%v; want authenticated/archive", authenticated, kind)
	}

	archiveFile := writeArchiveHandoffInput(t, archive)
	extractDir := filepath.Join(t.TempDir(), "extracted")
	if err := unpackAuthenticatedArchive(completion, archiveFile, fileops.UnpackOptions{
		ExtractDir: extractDir,
		AvailableSpace: func(string) (int64, error) {
			return math.MaxInt64, nil
		},
	}); err != nil {
		t.Fatalf("authenticated archive handoff: %v", err)
	}

	assertArchiveHandoffFile(t, filepath.Join(extractDir, "root.txt"), "PCV3 authenticated archive fixture\n")
	assertArchiveHandoffFile(
		t,
		filepath.Join(extractDir, "docs", "readme.txt"),
		"Extraction is admitted only after whole-volume authentication.\n",
	)
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		t.Fatalf("read extraction root: %v", err)
	}
	got := make([]string, len(entries))
	for index := range entries {
		got[index] = entries[index].Name()
	}
	if !slices.Equal(got, []string{"docs", "root.txt"}) {
		t.Fatalf("extraction root entries = %q; want only docs and root.txt", got)
	}
}

func TestArchiveHandoffRejectsWithoutWholeVolumeAuthentication(t *testing.T) {
	_, archive, _, _ := readArchiveHandoffFixture(t, context.Background(), normalArchiveFixtureID)

	t.Run("nil completion", func(t *testing.T) {
		assertArchiveHandoffRejectedWithoutSideEffects(t, nil, archive)
	})
	t.Run("zero-value completion", func(t *testing.T) {
		assertArchiveHandoffRejectedWithoutSideEffects(t, &normalCompletion{}, archive)
	})
	t.Run("authentication failure", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			"normal-negative-final",
		)
		if result.Outcome() != OutcomeAuthenticationFailed || completion != nil {
			t.Fatalf("failed reader result/completion = %v/%v; want authentication-failed/nil", result.Outcome(), completion)
		}
		assertArchiveHandoffRejectedWithoutSideEffects(t, completion, archive)
	})
}

func TestArchiveHandoffRejectsUnsealedArchiveCompletionWithoutSideEffects(t *testing.T) {
	_, archive, _, _ := readArchiveHandoffFixture(t, context.Background(), normalArchiveFixtureID)
	completion := newNormalCompletion(PayloadKindArchive, false)
	if kind, authenticated := completion.authenticatedPayloadKind(); authenticated || kind != 0 {
		t.Fatalf("unsealed archive completion = %v/%v; want no authenticated payload capability", authenticated, kind)
	}
	assertArchiveHandoffRejectedWithoutSideEffects(t, completion, archive)
}

func TestArchiveHandoffRejectsRawDamagedAndCancelledResults(t *testing.T) {
	_, archive, _, _ := readArchiveHandoffFixture(t, context.Background(), normalArchiveFixtureID)

	t.Run("authenticated raw payload", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			"normal-standard-combined-ordered-one",
		)
		kind, authenticated := completion.authenticatedPayloadKind()
		if result.Outcome() != OutcomeSuccess || !authenticated || kind != PayloadKindRaw {
			t.Fatalf("raw reader result/completion = %v/%v/%v; want success/authenticated/raw", result.Outcome(), authenticated, kind)
		}
		assertArchiveHandoffRejectedWithoutSideEffects(t, completion, archive)
	})

	t.Run("authenticated degraded payload", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			"normal-degraded-capsule",
		)
		if result.Outcome() != OutcomeAuthenticatedDegraded || completion == nil {
			t.Fatalf("degraded reader result/completion = %v/%v; want authenticated-degraded/non-nil", result.Outcome(), completion)
		}
		if _, authenticated := completion.authenticatedPayloadKind(); authenticated {
			t.Fatal("degraded reader minted a whole-volume authentication capability")
		}
		assertArchiveHandoffRejectedWithoutSideEffects(t, completion, archive)
	})

	t.Run("cancelled operation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, result, completion := readArchiveHandoffFixture(t, ctx, normalArchiveFixtureID)
		if result.Outcome() != OutcomeOperationFailed || result.Stage() != StageCancellation || completion != nil {
			t.Fatalf("cancelled reader result/completion = %v/%v/%v; want operation-failed/cancellation/nil", result.Outcome(), result.Stage(), completion)
		}
		assertArchiveHandoffRejectedWithoutSideEffects(t, completion, archive)
	})
}

func TestNormalReaderCompletionRequiresAuthenticatedTail(t *testing.T) {
	t.Run("fully authenticated archive", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			normalArchiveFixtureID,
		)
		kind, authenticated := completion.authenticatedPayloadKind()
		if result.Outcome() != OutcomeSuccess || !authenticated || kind != PayloadKindArchive {
			t.Fatalf("healthy tail result/completion = %v/%v/%v; want success/authenticated/archive", result.Outcome(), authenticated, kind)
		}
	})

	t.Run("damaged trailer", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			"normal-degraded-trailer",
		)
		if result.Outcome() != OutcomeAuthenticatedDegraded || completion == nil {
			t.Fatalf("damaged trailer result/completion = %v/%v; want authenticated-degraded/non-nil", result.Outcome(), completion)
		}
		if _, authenticated := completion.authenticatedPayloadKind(); authenticated {
			t.Fatal("damaged trailer minted a whole-volume authentication capability")
		}
	})

	t.Run("invalid final record", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			"normal-negative-final",
		)
		if result.Outcome() != OutcomeAuthenticationFailed || result.Stage() != StageFinalRecord || completion != nil {
			t.Fatalf("invalid final result/completion = %v/%v/%v; want authentication-failed/final-record/nil", result.Outcome(), result.Stage(), completion)
		}
	})
}

func readArchiveHandoffFixture(
	t *testing.T,
	ctx context.Context,
	fixtureID string,
) (normalFixture, []byte, *normalReadResult, *normalCompletion) {
	t.Helper()
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	fixture := requireNormalFixture(t, fixtures, fixtureID)
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
	source := newNormalFixtureSource(t, fixture, volume)
	sink := &normalFixtureSink{}
	result, completion, _ := runNormalBehaviorRead(t, ctx, fixture, source, int64(len(volume)), sink)
	if result == nil {
		t.Fatal("normal reader returned a nil result")
	}
	t.Cleanup(result.Close)
	if completion != nil && !bytes.Equal(sink.plaintext(), plaintext) {
		t.Fatalf("reader staged %d bytes; want exact %d-byte fixture", len(sink.plaintext()), len(plaintext))
	}
	return fixture, plaintext, result, completion
}

func writeArchiveHandoffInput(t *testing.T, archive []byte) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "authenticated-archive-*.zip")
	if err != nil {
		t.Fatalf("create archive staging file: %v", err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrInvalid) {
			t.Errorf("close archive staging file: %v", err)
		}
	})
	if _, err := file.Write(archive); err != nil {
		t.Fatalf("write archive staging file: %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("sync archive staging file: %v", err)
	}
	return file
}

func assertArchiveHandoffRejectedWithoutSideEffects(
	t *testing.T,
	completion *normalCompletion,
	archive []byte,
) {
	t.Helper()
	archiveFile := writeArchiveHandoffInput(t, archive)
	extractDir := filepath.Join(t.TempDir(), "reserved-output")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		t.Fatalf("reserve extraction directory: %v", err)
	}
	sentinelPath := filepath.Join(extractDir, "keep.txt")
	const sentinel = "foreign bytes must survive\n"
	if err := os.WriteFile(sentinelPath, []byte(sentinel), 0o600); err != nil {
		t.Fatalf("write extraction sentinel: %v", err)
	}
	sentinelInfo, err := os.Stat(sentinelPath)
	if err != nil {
		t.Fatalf("stat extraction sentinel before rejected handoff: %v", err)
	}

	err = unpackAuthenticatedArchive(completion, archiveFile, fileops.UnpackOptions{
		ExtractDir: extractDir,
		AvailableSpace: func(string) (int64, error) {
			return math.MaxInt64, nil
		},
	})
	if !errors.Is(err, errArchiveHandoffDenied) {
		t.Fatalf("archive handoff error = %v; want authenticated-admission denial", err)
	}
	assertArchiveHandoffFile(t, sentinelPath, sentinel)
	retainedInfo, statErr := os.Stat(sentinelPath)
	if statErr != nil {
		t.Fatalf("stat extraction sentinel after rejected handoff: %v", statErr)
	}
	if retainedInfo.Mode() != sentinelInfo.Mode() {
		t.Fatalf("rejected extraction changed sentinel mode from %v to %v", sentinelInfo.Mode(), retainedInfo.Mode())
	}
	entries, readErr := os.ReadDir(extractDir)
	if readErr != nil {
		t.Fatalf("read rejected extraction root: %v", readErr)
	}
	if len(entries) != 1 || entries[0].Name() != "keep.txt" {
		t.Fatalf("rejected extraction changed destination entries: %v", entries)
	}
}

func assertArchiveHandoffFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read extracted file %q: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("extracted file %q = %q; want %q", path, got, want)
	}
}
